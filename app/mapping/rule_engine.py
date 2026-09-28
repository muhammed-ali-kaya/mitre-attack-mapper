"""Deterministik ATT&CK eslestirme motoru.

MIMARI KARARI: teknik secimi RAG'den ALINDI. Vektor benzerligi bir teknigi
SECEMEZ; yalnizca teknik burada deterministik olarak belirlendikten SONRA o
teknigin aciklama metnini getirmek icin kullanilir (bkz. app/mapping/
enrichment.py).

Gerekce, gercek bir kosudan: 51 satirlik bir Windows guvenlik logu setinde
benzerlik tabanli secim 44 teknik uretti ve "Kritik/85" bir olay ilan etti.
Veri setinde guvenlik duvari degisikligi olayi (4946-4954, 5025) HIC yoktu;
buna ragmen T1686.003 'Windows Host Firewall' 14 kez uretilmisti -- kaynak,
guvenlik duvarinin CALISTIGINI gosteren 5156 "permitted a connection"
satirlariydi. Benzerlik skoru "firewall" kelimesini gordu ve yeterli buldu.
Boolean kanit kosulu bu hatayi yapisal olarak imkansiz kilar.

Motor SADECE rules/attack_mappings.yaml'i okur. YAML'da karsiligi olmayan
hicbir teknik ciktiya giremez."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.mapping.polarity import Polarity, classify, evidence_allowed

RULES_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "attack_mappings.yaml"

CONFIDENCE_LEVELS = ("high", "medium", "low")


class RuleValidationError(ValueError):
    """YAML semasi bozuk. Sessizce yok saymiyoruz: kural dosyasindaki bir
    yazim hatasi, o teknigin sessizce hic uretilmemesi demek olurdu."""


def _lehce_varyantlari(text: str) -> tuple[str, ...]:
    """Degerin ESLESTIRILEBILIR bicimleri: ham hali + registry NORMALIZE hali.

    NEDEN VAR: log ile ATT&CK/kural dili ayni seyi FARKLI YAZIYOR.
    4656 Object Access olaylari cekirdek ad-uzayini yaziyor --
    "\\REGISTRY\\MACHINE\\SAM" -- kural ise Win32 gosterimini ariyor:
    "HKLM\\SAM". Ikisi ayni anahtar, eslesme sifir.

    Bu, known_regression T1-T1003.002-gate-notation'in 2B yarisiydi:
    "kural object.name'e baksin VE cekirdek ad-uzayi gosterimini TANISIN".
    Kosulu object.name'e tasimak birinci yariydi; ikincisi bu.

    KURALA OZEL DEGIL: alan ADINA bakilmiyor, DEGERIN BICIMINE bakiliyor.
    Yarin baska bir alan registry yolu tasirsa da calisir, ve tablo
    buyudugunde bu kod degismez. Tablonun kendisi
    config/path_normalization.yaml'da veri olarak duruyor.

    Ham hali de listede KALIYOR: normalizasyon bir IKAME degil EKLEME.
    Zaten Win32 gosterimi yazan loglar bozulmamali."""
    from app.normalization.path_normalizer import (
        looks_like_registry_path,
        normalize_registry_path,
    )

    if not text or not looks_like_registry_path(text):
        return (text,)
    normalize = normalize_registry_path(text)
    if not normalize or normalize == text:
        return (text,)
    return (text, normalize)


@dataclass(frozen=True)
class FieldCondition:
    field: str
    must_match: re.Pattern | None = None
    must_not_match: re.Pattern | None = None

    def matches(self, row: dict[str, Any]) -> bool:
        value = row.get(self.field)
        text = "" if value is None else str(value)
        adaylar = _lehce_varyantlari(text)
        if self.must_match is not None and not any(
            self.must_match.search(a) for a in adaylar
        ):
            return False
        if self.must_not_match is not None and any(
            self.must_not_match.search(a) for a in adaylar
        ):
            return False
        return True

    def describe(self) -> str:
        if self.must_match is not None:
            return f"{self.field} ~ /{self.must_match.pattern}/"
        return f"{self.field} !~ /{self.must_not_match.pattern}/"

    def diagnose(self, row: dict[str, Any]) -> str:
        """Bu kosul NEDEN dustu -- ve normalizasyon DENENDI MI.

        NEDEN VAR: "kanit kosullari saglanmiyor" mesaji analisti yanlis
        katmana baktiriyordu. Ama hangi kosulun dustugunu soylemek de
        yetmiyor: lehce normalizasyonu SESSIZCE calismazsa kimse fark
        etmez ve ayni hata ayiklama korlugu baska bir alanda tekrar eder.
        O yuzden DENENEN BICIMLER de yaziliyor."""
        if self.field not in row or row.get(self.field) in (None, ""):
            return f"{self.field} alanı girdide YOK"
        text = str(row[self.field])
        adaylar = _lehce_varyantlari(text)
        denenen = ", ".join(repr(a) for a in adaylar)
        ek = "" if len(adaylar) > 1 else " (registry yolu değil, normalizasyon uygulanmadı)"
        if self.must_match is not None:
            return (f"{self.field} deseni /{self.must_match.pattern}/ ile eşleşmedi "
                    f"— denenen biçimler: {denenen}{ek}")
        return (f"{self.field} YASAKLI desen /{self.must_not_match.pattern}/ ile eşleşti "
                f"— denenen biçimler: {denenen}{ek}")


@dataclass(frozen=True)
class AnyOf:
    """Alt kosullardan HERHANGI BIRI saglanirsa gecer (VEYA).

    NEDEN VAR: bazi kosullar tek desende IKI FARKLI SEYI ariyor ve bu iki
    sey ayri alanlara ait. Ornek T1105:

        (certutil.*-urlcache|bitsadmin.*/transfer|\\curl\\.exe|invoke-webrequest)

    curl.exe bir SUREC ADI; "certutil -urlcache" bir KOMUT SATIRI desenidir.
    Ikisini tek alana tasimak mumkun degil, ama iki AYRI kosula bolmek de
    yanlis olurdu: motor kosullari VE'liyor, yani "hem curl.exe hem certutil"
    sarti cikardi -- kural hicbir zaman atesleMEZdi.

    Dogru ifade VEYA'dir ve dile bir yapi olarak eklenir; kural basina ozel
    kod yazilmaz. `bolme` alanlari config/rule_field_map.yaml'da gerekceleriyle
    duruyor."""

    conditions: tuple[FieldCondition, ...]

    def matches(self, row: dict[str, Any]) -> bool:
        return any(c.matches(row) for c in self.conditions)

    def describe(self) -> str:
        return "(" + " VEYA ".join(c.describe() for c in self.conditions) + ")"

    def diagnose(self, row: dict[str, Any]) -> str:
        return "hiçbir kol tutmadı: " + " | ".join(
            c.diagnose(row) for c in self.conditions
        )


@dataclass(frozen=True)
class Rule:
    technique_id: str
    tactic: str
    confidence: str
    required_event_ids: frozenset[str] = frozenset()
    forbidden_event_ids: frozenset[str] = frozenset()
    field_conditions: tuple[FieldCondition | AnyOf, ...] = ()
    min_events: int = 1
    name: str | None = None
    note: str | None = None

    def row_matches(self, row: dict[str, Any]) -> bool:
        event_id = str(row.get("EventID") or "").strip()

        # forbidden ONCE bakilir: "bu olay bu teknigin kaniti OLAMAZ" ifadesi,
        # required listesiyle celisirse yasak kazanmali.
        if event_id and event_id in self.forbidden_event_ids:
            return False
        if self.required_event_ids and event_id not in self.required_event_ids:
            return False
        return all(cond.matches(row) for cond in self.field_conditions)

    def diagnose_failure(self, row: dict[str, Any]) -> str:
        """Bu kural bu satirda NEDEN atesleMEDI -- katman katman.

        Onceki mesaj yalnizca beklenen olay ID'lerini yaziyordu ve olay ID
        ESLESSE BILE ayni cumleyi kuruyordu; analist yanlis yere bakiyordu.
        Bu, T1003.002 vakasinda aylarca yanlis katmanin suclanmasina yol
        acti (bkz. kapanmis_gerileme T1-T1003.002-gate-notation)."""
        event_id = str(row.get("EventID") or "").strip()
        if event_id and event_id in self.forbidden_event_ids:
            return f"olay ID {event_id} bu teknik için YASAKLI listede"
        if self.required_event_ids and event_id not in self.required_event_ids:
            gerekli = ", ".join(sorted(self.required_event_ids))
            return (f"olay ID eşleşmedi (girdi: {event_id or 'YOK'}, gerekli: {gerekli})")
        dusenler = [c.diagnose(row) for c in self.field_conditions if not c.matches(row)]
        if not dusenler:
            return "tüm koşullar sağlandı"
        onek = f"olay ID eşleşti ({event_id})" if event_id else "olay ID koşulu yok"
        return onek + ", koşul düştü: " + " ; ".join(dusenler)

    def explain(self, row: dict[str, Any]) -> list[str]:
        """Bu satirda kuralin HANGI kosullarinin saglandigini yazar.

        Toplu analizde 'kanit: satir 12' yeterli bir izdir; ama tek bir
        serbest metin analiz edildiginde tum kanit 'satir 0'dir ve hicbir sey
        anlatmaz. Asil izlenebilirlik, tetigi ceken boolean kosulun kendisidir:
        'EventID=4104 eslesti' + 'Message ~ /scriptblock/'."""
        reasons: list[str] = []
        event_id = str(row.get("EventID") or "").strip()
        if self.required_event_ids and event_id:
            reasons.append(f"EventID={event_id} (gerekli listede)")
        for cond in self.field_conditions:
            reasons.append(cond.describe())
        return reasons


@dataclass
class Finding:
    """Kural motorunun urettigi tek bulgu.

    evidence_row_ids BOS OLAMAZ -- motor bos kanitli bulguyu uretmeden atar
    (kanit kapisi). Alan, ozet ve rapor katmanlarinin her cumleyi ham satira
    baglamasi icin tasiniyor."""
    technique_id: str
    tactic: str
    confidence: str
    evidence_row_ids: list[int] = field(default_factory=list)
    name: str | None = None
    note: str | None = None
    # Tetigi ceken boolean kosullar -- bkz. Rule.explain.
    matched_conditions: list[str] = field(default_factory=list)

    @property
    def occurrence_count(self) -> int:
        """Tekillestirilmis satir sayisi -- ayni satir iki kez sayilmaz."""
        return len(set(self.evidence_row_ids))


def _compile(pattern: str | None, where: str) -> re.Pattern | None:
    if pattern is None:
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RuleValidationError(f"{where}: gecersiz regex {pattern!r} ({exc})") from exc


def _parse_field_condition(raw: dict[str, Any], where: str) -> FieldCondition | AnyOf:
    if "any_of" in raw:
        alt = raw["any_of"]
        if not isinstance(alt, list) or len(alt) < 2:
            raise RuleValidationError(
                f"{where}: any_of en az IKI alt kosul icermeli "
                f"-- tek alt kosullu VEYA anlamsizdir"
            )
        return AnyOf(tuple(_parse_field_condition(a, where) for a in alt))
    if "field" not in raw:
        raise RuleValidationError(f"{where}: field_conditions girisinde 'field' yok")
    if "must_match" not in raw and "must_not_match" not in raw:
        raise RuleValidationError(
            f"{where}: field_conditions girisinde must_match ya da must_not_match olmali"
        )
    return FieldCondition(
        field=str(raw["field"]),
        must_match=_compile(raw.get("must_match"), where),
        must_not_match=_compile(raw.get("must_not_match"), where),
    )


def _as_id_set(values: Any) -> frozenset[str]:
    if not values:
        return frozenset()
    return frozenset(str(v).strip() for v in values)


def parse_rule(raw: dict[str, Any]) -> Rule:
    technique_id = raw.get("technique_id")
    if not technique_id:
        raise RuleValidationError(f"technique_id yok: {raw!r}")
    where = f"kural {technique_id}"

    confidence = str(raw.get("confidence") or "").lower()
    if confidence not in CONFIDENCE_LEVELS:
        raise RuleValidationError(
            f"{where}: confidence {confidence!r} gecersiz, {CONFIDENCE_LEVELS} bekleniyor"
        )

    required = raw.get("required") or {}
    forbidden = raw.get("forbidden") or {}
    conditions = tuple(
        _parse_field_condition(c, where) for c in (raw.get("field_conditions") or [])
    )

    required_ids = _as_id_set(required.get("event_ids"))
    if not required_ids and not conditions:
        # Kosulsuz kural, her satiri kanit sayar -- tam da kacindigimiz sey.
        raise RuleValidationError(
            f"{where}: en az bir required.event_ids ya da field_conditions gerekli"
        )

    return Rule(
        technique_id=str(technique_id),
        tactic=str(raw.get("tactic") or ""),
        confidence=confidence,
        required_event_ids=required_ids,
        forbidden_event_ids=_as_id_set(forbidden.get("event_ids")),
        field_conditions=conditions,
        min_events=int(raw.get("min_events") or 1),
        name=raw.get("name"),
        note=raw.get("note"),
    )


@dataclass(frozen=True)
class ReviewRule:
    """ATT&CK teknigi IDDIA ETMEYEN, 'bir analist baksin' kurali.

    Tekniklerden ayri tutulmasi bilincli: bir teknik iddiasi kanit ister,
    bir inceleme talebi istemez. Ikisini ayni listede toplamak, raporu
    okuyanin 'sistem burada su teknigi tespit etti' diye anlamasina yol
    acardi."""
    id: str
    title: str
    field_conditions: tuple[FieldCondition, ...]
    min_events: int = 1
    note: str | None = None

    def row_matches(self, row: dict[str, Any]) -> bool:
        return all(cond.matches(row) for cond in self.field_conditions)


@dataclass
class ReviewFinding:
    id: str
    title: str
    evidence_row_ids: list[int] = field(default_factory=list)
    note: str | None = None

    @property
    def occurrence_count(self) -> int:
        return len(set(self.evidence_row_ids))


def parse_review_rule(raw: dict[str, Any]) -> ReviewRule:
    rule_id = raw.get("id")
    if not rule_id:
        raise RuleValidationError(f"review_findings girisinde 'id' yok: {raw!r}")
    where = f"inceleme kurali {rule_id}"

    conditions = tuple(
        _parse_field_condition(c, where) for c in (raw.get("field_conditions") or [])
    )
    if not conditions:
        raise RuleValidationError(f"{where}: en az bir field_conditions gerekli")

    return ReviewRule(
        id=str(rule_id),
        title=str(raw.get("title") or rule_id),
        field_conditions=conditions,
        min_events=int(raw.get("min_events") or 1),
        note=raw.get("note"),
    )


def load_rules(path: Path = RULES_PATH) -> list[Rule]:
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_rules = document.get("techniques")
    if raw_rules is None:
        raise RuleValidationError(f"{path}: 'techniques' anahtari yok")
    return [parse_rule(r) for r in raw_rules]


def load_review_rules(path: Path = RULES_PATH) -> list[ReviewRule]:
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [parse_review_rule(r) for r in (document.get("review_findings") or [])]


def evaluate_review_rules(
    rows: list[dict[str, Any]], rules: list[ReviewRule] | None = None
) -> list[ReviewFinding]:
    if rules is None:
        rules = load_review_rules()

    findings: list[ReviewFinding] = []
    for rule in rules:
        evidence_row_ids = [i for i, row in enumerate(rows) if rule.row_matches(row)]
        if len(evidence_row_ids) < rule.min_events or not evidence_row_ids:
            continue
        findings.append(
            ReviewFinding(
                id=rule.id,
                title=rule.title,
                evidence_row_ids=evidence_row_ids,
                note=rule.note,
            )
        )
    return findings


def _polarity_of(row: dict[str, Any]) -> Polarity:
    """Kutupsallik Message alanindan okunur; yoksa satirin tamami taranir."""
    message = row.get("Message")
    if message:
        return classify(str(message))
    return classify(" ".join(str(v) for v in row.values() if v))


def evaluate_rules(rows: list[dict[str, Any]], rules: list[Rule] | None = None) -> list[Finding]:
    """Satirlari kurallara karsi degerlendirir.

    rows: normalize edilmis satirlar (bkz. app/batch/qradar_adapter.py). Sira
    onemli: evidence_row_ids bu listedeki indekslerdir.

    Hicbir teknik benzerlik skoruyla uretilmez; bir kuralin TUM kosullari
    saglanmadan bulgu olusmaz."""
    if rules is None:
        rules = load_rules()

    polarities = [_polarity_of(row) for row in rows]

    findings: list[Finding] = []
    for rule in rules:
        evidence_row_ids = [
            index
            for index, row in enumerate(rows)
            if rule.row_matches(row)
            and evidence_allowed(rule.technique_id, polarities[index])
        ]

        if len(evidence_row_ids) < rule.min_events:
            continue

        # Kanit kapisi: bos kanitli bulgu asla uretilmez.
        if not evidence_row_ids:
            continue

        matched_conditions: list[str] = []
        for index in evidence_row_ids:
            for reason in rule.explain(rows[index]):
                if reason not in matched_conditions:
                    matched_conditions.append(reason)

        findings.append(
            Finding(
                technique_id=rule.technique_id,
                tactic=rule.tactic,
                confidence=rule.confidence,
                evidence_row_ids=evidence_row_ids,
                name=rule.name,
                note=rule.note,
                matched_conditions=matched_conditions,
            )
        )

    return sorted(merge_findings(findings), key=lambda f: f.technique_id)


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Ayni teknigi ureten birden fazla kurali TEK bulguda birlestirir.

    Bir teknigin birden fazla kanit yolu olmasi normaldir (orn. T1059.001 hem
    4104 script block'tan hem de 4688 + supheli PowerShell argumanlarindan
    gorulebilir). Bunlari ayri bulgular olarak birakmak ayni teknigi listede
    iki kez gosterirdi.

    Birlesimde: kanit satirlari ve kosullar birlestirilir, guven seviyesi EN
    YUKSEK olan kazanir -- bir yol zayif digeri gucluyse, teknik guclu kanitla
    gorulmus demektir."""
    order = {level: i for i, level in enumerate(CONFIDENCE_LEVELS)}
    merged: dict[str, Finding] = {}

    for finding in findings:
        existing = merged.get(finding.technique_id)
        if existing is None:
            merged[finding.technique_id] = finding
            continue

        for row_id in finding.evidence_row_ids:
            if row_id not in existing.evidence_row_ids:
                existing.evidence_row_ids.append(row_id)
        for reason in finding.matched_conditions:
            if reason not in existing.matched_conditions:
                existing.matched_conditions.append(reason)

        if order.get(finding.confidence, 99) < order.get(existing.confidence, 99):
            existing.confidence = finding.confidence
        existing.name = existing.name or finding.name

    for finding in merged.values():
        finding.evidence_row_ids.sort()
    return list(merged.values())
