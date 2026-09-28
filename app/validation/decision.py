"""Karar katmani -- "bu is dusmanca mi" sorusuna KOD tarafinda cevap.

Beklenti (kod yazilmadan once): docs/beklenti_5_karar_katmani.md

NEDEN KODA TASINDI (olculdu 2026-08-16)
    Karar `activity_verdict` alanindaydi, yani LLM'in BEYANIYDI. Ayni girdi
    (T1, SAM hive erisimi), ayni prompt, temperature=0, sabit seed; tek fark
    modelin VRAM'de yuklu olup olmamasi:

        model soguk (6/6 kosu) -> malicious_or_suspicious
        model sicak (6/6 kosu) -> insufficient_evidence

    Retrieval iki kolda birebir ayni, teknik listesi ayni. Degisen tek sey
    bu alandi. Bir SOC icin iki cikti taban tabana zit: biri "bakma",
    digeri "incele".

KOMPOZIT SKOR OKUNMAZ
    Bilesenler DOGRUDAN okunur. Harmanlanmis tek sayi denetlenemez:
    analiste "0.82" demek itiraz edilebilir bir sey soylememektir,
    "kritik varlik + yazma erisimi + 1 dogrulanmis kanit" itiraz
    edilebilir. Ayrica bilesenler FARKLI sorulara cevap veriyor --
    "elimizde kanit var mi" ile "bu onemli mi" ortalanamaz.

IKI BAGIMSIZ YOL, VE'LENMEZ (bolum 3)
    Bes girdinin hepsini sart kosmak sistemi susturur: varlik kritikligi
    60 senaryonun HICBIRINDE mevcut degil (0/60). Kritikligi zorunlu girdi
    yapmak 60/60 INSUFFICIENT_DATA uretirdi.

        Yol A: teknik seti + dogrulanmis kanit  -> tek basina yeter
        Yol B: varlik kritikligi + erisim sinifi -> tek basina yeter

    Bir logda hangi girdiler mevcutsa o yol calisir.

BASTIRMA TEK YONLU VE TEK YOLLU (bolum 5)
    Aktor baseline yalnizca Yol B'yi bastirabilir; Yol A'ya dokunamaz.
    Aktor alani TAKLIT EDILEBILIR -- SYSTEM'e gecmek ele gecirmenin
    basarisizligi degil AMACIDIR. Dogrulanmis kaniti taklit edilebilir bir
    alanla sildirmek, kanit kapisini aktor alanina devretmek olurdu.

    Baseline YAPISAL alandan okunur (account.name / process.name), ham
    metinden degil. Olculdu: T3'e aktor OLMAYAN bir alana
    "trustedinstaller.exe" dizesi konunca ham metin taramasi mesru diyordu,
    process.name hala powershell.exe idi.

YOKLUKTAN BENIGN URETILMEZ (bolum 4)
    SUFFICIENT_BENIGN POZITIF bir iddiadir: "baktim, zararsiz". Iki yolu
    var, ikisi de bir ESLESMEYE dayanir:
        1. siniflanmis 'noise' varlik + salt okuma + dogrulanmis kanit yok
        2. Yol B'nin (varlik ailesi, aktor) cifti beklenen listede
    "Bilmiyorum" bunlarin hicbiri degildir ve INSUFFICIENT_DATA'dir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.normalization.asset_criticality import siniflandir
from app.normalization.command_line_paths import extract_registry_paths
from app.normalization.event_semantics import describe

BASELINE_CONFIG = Path(__file__).resolve().parents[2] / "config" / "actor_baseline.yaml"

#: Windows yol ayraci. chr(92): kaynakta kacisli ters bolu tasimamak icin.
BOLU = chr(92)

INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
SUFFICIENT_BENIGN = "SUFFICIENT_BENIGN"
SUFFICIENT_SUSPICIOUS = "SUFFICIENT_SUSPICIOUS"

DECISION_LABELS = {
    INSUFFICIENT_DATA: "Karar için yetersiz veri",
    SUFFICIENT_BENIGN: "Meşru aktivite",
    SUFFICIENT_SUSPICIOUS: "Şüpheli aktivite",
}

#: Yol B'yi tetikleyen kritiklik seviyeleri.
_AGIR_SEVIYELER = ("critical", "high")
#: Kritikligin UC DURUMUNDAN biri: yol hic yok.
KRITIKLIK_YOK = "YOK"


class MultiEventDecisionError(ValueError):
    """`decide` cok olayli bir girdiyle cagrildi.

    KARAR EVENT SEVIYESINDEDIR (Gorev 14 §2). Bastirma bir UCLU hakkinda
    iddiadir -- belirli aktor, belirli varlik, belirli erisim -- ve bu uclu
    yalnizca tek bir event icinde anlamlidir. Cok olayli metinde alanlar
    olaylar arasi DERLENIR; olculdu: bastiran (TrustedInstaller.exe, SYSTEM)
    cifti hicbir event'te birlikte YOKTU, yalnizca birlestirmeden dogmustu ve
    gercek bir alarmi susturuyordu.

    Bu yuzden cok olayli girdi burada sessizce islenmez. Dogru giris noktasi
    `decide_alarm` (ya da hattin kendisi): girdi once olaylara bolunur, her
    olay kendi kararini alir, kararlar EN SERT KAZANIR ile birlestirilir."""


@dataclass
class Decision:
    """Karar + GEREKCE ZINCIRI.

    reason_chain zorunlu: sinif dogru cikip gerekce yanlis olabilir ve bu
    projede tam olarak bu desen defalarca olcum kirletti. Analiste
    "SUFFICIENT_SUSPICIOUS" demek yetmez -- hangi girdinin bu sonucu
    verdigi yazili olmali."""

    decision: str
    label: str
    reason: str
    reason_chain: list[str] = field(default_factory=list)
    inputs: dict[str, Any] = field(default_factory=dict)
    paths: dict[str, bool] = field(default_factory=dict)
    suppression: dict[str, Any] | None = None

    @property
    def alerts(self) -> bool:
        return self.decision == SUFFICIENT_SUSPICIOUS

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "label": self.label,
            "reason": self.reason,
            "reason_chain": list(self.reason_chain),
            "inputs": dict(self.inputs),
            "paths": dict(self.paths),
            "suppression": self.suppression,
        }


# --------------------------------------------------------------- girdiler

def _alan(parsed: dict[str, Any], *adlar: str) -> Any:
    """parsed_fields'ten ilk dolu alanin degeri. N/A yokluk sayilir."""
    for ad in adlar:
        ham = parsed.get(ad)
        deger = getattr(ham, "value", ham)
        if deger is None:
            continue
        if isinstance(deger, list):
            if deger:
                return deger
            continue
        metin = str(deger).strip()
        if metin and metin.upper() != "N/A":
            return metin
    return None


def varlik_kritikligi(normalized: dict[str, Any]) -> tuple[str, str | None, str | None]:
    """(seviye, aile, yol) -- seviye 'YOK' | 'unknown' | critical/high/...

    KAYNAK SIRASI (Gorev 5 bolum 6 karari): yapisal yol alani -> komut
    satiri -> HICBIR SEY. Duzyazidan OKUNMAZ: komut satiri olayin
    ARTEFAKTI, duzyazi olayin IDDIASIDIR. "Bir PowerShell sureci kod
    indirdi" bir iddiadir, kanit degildir.

    Komut satiri cikarimi Gorev 6'da duzeltildikten SONRA baglandi
    (app/normalization/command_line_paths.py): oncesinde
    `reg.exe save HKLM\\SAM C:\\...` girdisinden "HKLM\\SAM C" cikiyor ve
    kritiklik 'unknown'a dusuyordu."""
    parsed = normalized.get("parsed_fields") or {}

    yol = _alan(parsed, "object.name", "registry.path", "file.path")
    if not yol:
        komut = _alan(parsed, "process.command_line", "command_line", "process.args")
        for aday in extract_registry_paths(komut):
            yol = aday
            break

    if not yol:
        return KRITIKLIK_YOK, None, None

    k = siniflandir(yol)
    return ("unknown" if k.bilinmiyor else k.seviye), k.aile, yol


def _erisim_ozeti(normalized: dict[str, Any]) -> dict[str, Any]:
    parsed = normalized.get("parsed_fields") or {}
    return describe(
        _alan(parsed, "event.id") or normalized.get("event_id"),
        _alan(parsed, "access.mask"),
        _alan(parsed, "object.type"),
        _alan(parsed, "access.list"),
    )


def erisim_sinifi(normalized: dict[str, Any]) -> str | None:
    return _erisim_ozeti(normalized).get("access_class")


def talep_sinifi(normalized: dict[str, Any]) -> str | None:
    """TALEP EDILEN erisim sinifi -- yalnizca `erisim_gerceklesti: false`
    olan olaylarda (4656) doludur.

    Gorev 19: bu deger karara GIRMEZ (Gorev 18 orada duruyor), ama gerekce
    metnine girer. "Erisim sinifi: salt okuma" demek, maskesinde iki yazma
    biti olan bir handle talebi icin analiste yanlis sey soylemektir --
    dogru cumle "yazma talep edildi, gerceklesme kaniti yok"."""
    return _erisim_ozeti(normalized).get("requested_class")


def aktor(normalized: dict[str, Any]) -> dict[str, str | None]:
    """Aktor YAPISAL alandan. Ham metin taramasi karar girdisi DEGILDIR."""
    parsed = normalized.get("parsed_fields") or {}
    return {
        "account": _alan(parsed, "account.name", "user.name", "subject.user"),
        "process": _alan(parsed, "process.name"),
    }


def dogrulanmis_kanit_sayisi(verification: Any) -> int:
    """Kanit kapisi + ajanlarin CONFIRM kararlarinin sayisi.

    ABSTAIN sayilmaz: "sinanamadi" ile "dogrulandi" ayni sey degil -- bu
    ayrimi karistirmak T1003.002'de bir kez 'dogru cevap, yanlis sebep'
    uretti (bkz. HANDOFF)."""
    if verification is None:
        return 0
    kabul = {m.get("attack_id") for m in getattr(verification, "accepted", [])}
    return sum(
        1
        for d in getattr(verification, "decisions", [])
        if getattr(d.verdict, "value", d.verdict) == "confirm"
        and d.technique_id in kabul
    )


# ------------------------------------------------------------- baseline

@lru_cache(maxsize=1)
def _baseline_ham() -> dict[str, Any]:
    return yaml.safe_load(BASELINE_CONFIG.read_text(encoding="utf-8")) or {}


def _baseline_tablosu() -> list[dict[str, Any]]:
    return _baseline_ham().get("beklenen_ciftler") or []


def _guvenilir_dizinler() -> list[str]:
    return _baseline_ham().get("guvenilir_dizinler") or []


def _ad(value: str | None) -> str:
    return (value or "").strip().casefold()


def _surec_parcala(value: str | None) -> tuple[str, str]:
    """Surec degerini (dizin, taban ad) olarak ayir. Ikisi de casefold.

    Gorev 17: `process.name` gercek veride TAM YOL tasiyor (77 tam yol / 4
    taban ad), fixture ise taban ad tasiyordu -- bastirma tam esitlikle
    karsilastirdigi icin gercek veride hic ateslemiyordu. Ayrim burada
    yapilir ki tablo taban adi, dizin kontrolu ise deseni okusun.

    Surucu harfi ATILIR: `Program Files` bir D: bolumunde olabilir; anlamli
    olan surucu degil, dizinin Windows kurulum agacindaki yeridir."""
    ham = (value or "").strip().strip('"').replace("/", BOLU)
    if not ham:
        return "", ""
    dizin, ayrac, taban = ham.rpartition(BOLU)
    if not ayrac:
        return "", ham.casefold()
    if len(dizin) >= 2 and dizin[1] == ":":  # surucu harfi
        dizin = dizin[2:]
    return dizin.casefold(), taban.casefold()


def _dizin_guvenilir_mi(dizin: str) -> bool:
    r"""Dizin, beklenen desenlerden biriyle AYRAC SINIRINDA basliyor mu?

    Onek degil sinir esleme: `\Temp\Windows\System32` bir System32
    DEGILDIR, cunku desen dizinin basindan itibaren tutmak zorundadir.
    Alt dizinler kabul edilir (`\Windows\WinSxS\amd64_...`).

    Dizinsiz deger (bos dizin) HICBIR desenle eslesmez: surecin nereden
    calistigi bilinmiyorsa bastirma yapilmaz -- guvenli yonde hata."""
    if not dizin:
        return False
    for desen in _guvenilir_dizinler():
        d = _ad(desen).rstrip(BOLU)
        if d and (dizin == d or dizin.startswith(d + BOLU)):
            return True
    return False


def baseline_bastirir_mi(aile: str | None, aktor_bilgisi: dict[str, str | None]) -> dict[str, Any] | None:
    r"""(varlik ailesi, aktor) cifti beklenen listede mi?

    Surec VE hesap birlikte eslesmek zorunda. Ikisini birden istemek
    bastirmayi DARALTIR, yani guvenli yonde hata yapar.

    SUREC IKI PARCADAN ESLESIR (Gorev 17): taban ad `surecler` listesinde
    olacak VE dizin `guvenilir_dizinler` desenlerinden biriyle eslesecek.
    Yalnizca taban ada bakmak C:\Temp\msiexec.exe'yi de bastirirdi -- yani
    saldirganin mesru bir ikili adini kopyalayacagi yerde kor nokta acardi.
    Dizinsiz gelen deger bastirilmaz: nereden calistigi bilinmiyor demektir
    ve bilinmeyen dogrulanmis sayilmaz."""
    if not aile:
        return None
    dizin, taban = _surec_parcala(aktor_bilgisi.get("process"))
    hesap = _ad(aktor_bilgisi.get("account"))
    if not taban or not hesap:
        return None
    if not _dizin_guvenilir_mi(dizin):
        return None

    for kayit in _baseline_tablosu():
        if _ad(kayit.get("aile")) != _ad(aile):
            continue
        if taban not in {_surec_parcala(s)[1] for s in kayit.get("surecler") or []}:
            continue
        if hesap not in {_ad(h) for h in kayit.get("hesaplar") or []}:
            continue
        return {
            "aile": kayit.get("aile"),
            "surec": aktor_bilgisi.get("process"),
            "hesap": aktor_bilgisi.get("account"),
            "gerekce": (kayit.get("gerekce") or "").strip(),
        }
    return None


# ---------------------------------------------------------------- karar

def decide(
    normalized: dict[str, Any],
    mappings: list[dict[str, Any]],
    verification: Any = None,
) -> Decision:
    """Uc sinifin biri + gerekce zinciri.

    Sira onemli ve bolum 5.2'de baglandi: Yol A once sorulur ve Yol A
    tetiklendiyse bastirma UYGULANMAZ. Iki yol da tetiklendiyse sonuc
    yine SUSPICIOUS'tur.

    TEK OLAY SARTI: girdi birden fazla olay tasiyorsa bu fonksiyon
    calismaz (bkz. MultiEventDecisionError). Alarm seviyesi karar
    `combine_event_decisions`/`decide_alarm` uzerinden verilir."""
    olay_sayisi = (normalized.get("split") or {}).get("event_count", 1)
    if olay_sayisi and olay_sayisi > 1:
        raise MultiEventDecisionError(
            f"decide() {olay_sayisi} olayli girdiyle cagrildi. Karar EVENT "
            "seviyesindedir; alarm karari icin decide_alarm() kullanin."
        )

    seviye, aile, yol = varlik_kritikligi(normalized)
    ozet = _erisim_ozeti(normalized)
    erisim = ozet.get("access_class")
    talep = ozet.get("requested_class")
    aktor_bilgisi = aktor(normalized)
    kanit = dogrulanmis_kanit_sayisi(verification)
    teknikler = [m.get("attack_id") for m in mappings or []]

    girdiler = {
        "teknik_sayisi": len(teknikler),
        "teknikler": teknikler,
        "dogrulanmis_kanit": kanit,
        "kritiklik": seviye,
        "kritiklik_ailesi": aile,
        "varlik_yolu": yol,
        "erisim_sinifi": erisim,
        "talep_edilen_erisim": talep,
        "erisim_kaynagi": ozet.get("access_class_source"),
        "aktor": aktor_bilgisi,
    }

    # Gorev 19: talep edilen yazma, gerekce metninde ACIKCA soylenir.
    # Karara GIRMEZ -- Gorev 18 4656'yi talep saymaya devam eder. Ama
    # "salt okuma" demek, maskesinde iki yazma biti olan bir kayit icin
    # analiste yanlis sey soylemektir.
    talep_notu = (
        f"{talep} talep edildi, gerçekleşme kanıtı yok "
        f"(olay gerçekleşen erişimi göstermiyor; gerçekleşen erişim 4663'tür)"
        if talep else None
    )

    yol_a = bool(teknikler) and kanit >= 1
    yol_b = seviye in _AGIR_SEVIYELER and erisim == "write"
    yollar = {"A": yol_a, "B": yol_b}

    zincir: list[str] = []

    # Gorev 20: cozulemeyen erisim adi SESSIZ kalmaz. Eskiden sinif olayin
    # varsayilanina (4663 -> read) dusuyordu; karar dogru cikip sebebi
    # yanlis oluyordu. Ad artik zincirde yazili ve sinif 'unknown'.
    for _ad in (ozet.get("unresolved_access_names") or []):
        zincir.append(
            f"Erişim adı çözülemedi: '{_ad}' — bit tablosunda karşılığı yok, "
            "erişim sınıfı 'unknown'. Bilinmeyen okuma sayılmaz "
            "(Görev 4: unknown ≠ noise)."
        )

    if yol_a:
        zincir.append(
            f"Yol A: {len(teknikler)} teknik ({', '.join(teknikler)}) "
            f"+ {kanit} doğrulanmış kanıt"
        )
        if yol_b:
            zincir.append(f"Yol B de tetiklendi: {seviye} varlık ({aile}) + yazma erişimi")
        zincir.append("Bastırma uygulanmadı: aktör baseline Yol A'yı bastıramaz (§5.2)")
        ozet = f"{len(teknikler)} doğrulanmış teknik"
        if yol_b:
            ozet = f"{seviye} varlık + yazma erişimi + " + ozet
        return _sonuc(SUFFICIENT_SUSPICIOUS, ozet, zincir, girdiler, yollar)

    if yol_b:
        zincir.append(f"Yol B: {seviye} varlık ({aile}) + yazma erişimi")
        zincir.append(
            f"Yol A kurulamadı: {len(teknikler)} teknik, {kanit} doğrulanmış kanıt"
        )
        bastirma = baseline_bastirir_mi(aile, aktor_bilgisi)
        if bastirma:
            zincir.append(
                f"Baseline bastırdı: ({bastirma['aile']}, {bastirma['surec']}) "
                f"çifti beklenen listede — {bastirma['gerekce']}"
            )
            return _sonuc(
                SUFFICIENT_BENIGN,
                f"beklenen aktör/varlık çifti: {bastirma['surec']} → {bastirma['aile']}",
                zincir, girdiler, yollar, bastirma,
            )
        zincir.append(
            f"Baseline bastırmadı: ({aile}, {aktor_bilgisi.get('process')}) "
            "çifti beklenen listede yok"
        )
        return _sonuc(
            SUFFICIENT_SUSPICIOUS,
            f"{seviye} varlık ({aile}) + yazma erişimi, doğrulanmış teknik olmadan",
            zincir, girdiler, yollar,
        )

    # --- iki yol da kurulmadi: BENIGN yalnizca POZITIF eslesmeyle
    if seviye == "noise" and erisim == "read" and kanit == 0:
        zincir.append(f"Sınıflanmış 'noise' varlık: {yol}")
        zincir.append(
            f"Erişim sınıfı: salt okuma — {talep_notu}" if talep_notu
            else "Erişim sınıfı: salt okuma"
        )
        zincir.append("Doğrulanmış kanıt yok")
        zincir.append("Üçü birden gerekli — biri eksik olsaydı INSUFFICIENT_DATA olurdu")
        return _sonuc(
            SUFFICIENT_BENIGN,
            # Gorev 19: baslik da talebi soyler. "Salt okuma" demek,
            # maskesinde iki yazma biti olan bir handle talebi icin
            # analiste yanlis sey soylemektir -- ozet satiri gerekce
            # zincirinden once okunuyor.
            (
                "gürültü seviyesindeki varlığa salt okuma "
                f"({talep} talep edildi, gerçekleşmedi), doğrulanmış kanıt yok"
                if talep else
                "gürültü seviyesindeki varlığa salt okuma, doğrulanmış kanıt yok"
            ),
            zincir, girdiler, yollar,
        )

    zincir.append(
        f"Yol A kurulamadı: {len(teknikler)} teknik, {kanit} doğrulanmış kanıt"
    )
    if seviye == KRITIKLIK_YOK:
        zincir.append("Yol B kurulamadı: girdide varlık yolu YOK — kritiklik bu kararda girdi değil")
    elif seviye == "unknown":
        zincir.append(
            f"Yol B kurulamadı: varlık görüldü ({yol}) ama tablo tanımıyor — "
            "'unknown' BENIGN üretemez (§1)"
        )
    else:
        zincir.append(
            f"Yol B kurulamadı: kritiklik {seviye}, erişim {erisim}"
            + (f" — {talep_notu}" if talep_notu else "")
        )
    zincir.append("BENIGN üretilmedi: yokluktan BENIGN çıkarılmaz (§4)")
    return _sonuc(
        INSUFFICIENT_DATA,
        "karar için yeterli girdi yok",
        zincir, girdiler, yollar,
    )


def _sonuc(
    karar: str,
    ozet: str,
    zincir: list[str],
    girdiler: dict[str, Any],
    yollar: dict[str, bool],
    bastirma: dict[str, Any] | None = None,
) -> Decision:
    return Decision(
        decision=karar,
        label=DECISION_LABELS[karar],
        reason=ozet,
        reason_chain=zincir,
        inputs=girdiler,
        paths=yollar,
        suppression=bastirma,
    )


# ---------------------------------------------------------- alarm karari
#
# GOREV 14 -- docs/beklenti_14_girdi_bolme_alarm_karari.md
#
# EN SERT KAZANIR. Zincir degerlendirmesi YAPILMAZ ve bu acikca yazilidir.
#
#     SUFFICIENT_SUSPICIOUS  >  INSUFFICIENT_DATA  >  SUFFICIENT_BENIGN
#
# INSUFFICIENT_DATA'nin BENIGN'den SERT olmasi kasitli: bir alarm ancak HER
# event'i BENIGN ise BENIGN okur. Tek bir "bilmiyorum" alarmi mesru ilan
# etmeye yetmez -- yokluktan BENIGN uretilmez kuralinin (bolum 4) alarm
# seviyesindeki karsiligi.
#
# BASTIRMA YUKARI YAYILMAZ (bolum 2). Bastirma bir UCLU hakkinda iddiadir:
# belirli aktor, belirli varlik, belirli erisim. Bu uclu yalnizca TEK BIR
# EVENT icinde anlamlidir; bir alarmin tek bir aktoru yoktur, yani alarm
# seviyesinde bu iddia iyi tanimli bile degildir. Acigin mekanizmasi tam
# olarak buydu: bastiran (TrustedInstaller.exe, SYSTEM) cifti iki AYRI
# event'ten derlenmisti. Burada bastirilmis bir event yalnizca KENDINI
# BENIGN yapar; yanindaki supheli event alarmi SUSPICIOUS tutar.
#
# Sonuc olarak saldirgan zararsiz event ekleyerek alarma en fazla
# INSUFFICIENT_DATA'lik gurultu ekleyebilir; supheli event'i susturamaz.
#
# BILINEN SINIR -- rapora yazilacak: yalniz basina zararsiz ama BIRLIKTE
# saldiri olan event dizileri bu kuralla yakalanmaz. Bugun de yakalanmiyor;
# yakalamak gercek alarm verisi olmadan tasarlanamaz (Gorev 13 sonrasi).

#: Sertlik sirasi. Sayi buyudukce sert. Tek kaynak: karsilastirma da,
#: dagilim anahtarlari da buradan okunur -- ikinci bir sozluk yok.
ALARM_SERTLIGI = {
    SUFFICIENT_BENIGN: 0,
    INSUFFICIENT_DATA: 1,
    SUFFICIENT_SUSPICIOUS: 2,
}


@dataclass
class AlarmDecision:
    """Alarm seviyesi karar + HANGI event'in verdigi.

    Ozet tek basina yetmez (beklenti bolum 1): "SUSPICIOUS" demek analiste
    itiraz edilebilir bir sey soylememektir. `belirleyen_event` ve
    `event_kararlari` zorunlu -- "alarm supheli, cunku event #4 supheli"
    tek cumlede gosterilebilmeli.

    Decision ile AYNI alanlari tasir (decision/label/reason/reason_chain/
    inputs/paths/suppression), cunku hat ciktisindaki "decision" anahtarini
    okuyan alti tuketici var (metrics, render, probe, measure_decision_shift).
    Tekli girdide bu alanlar tek event'in kararinin AYNISIDIR."""

    decision: str
    label: str
    reason: str
    reason_chain: list[str] = field(default_factory=list)
    inputs: dict[str, Any] = field(default_factory=dict)
    paths: dict[str, bool] = field(default_factory=dict)
    suppression: dict[str, Any] | None = None
    belirleyen_event: int = 0
    event_kararlari: list[dict[str, Any]] = field(default_factory=list)
    dagilim: dict[str, int] = field(default_factory=dict)
    split: dict[str, Any] | None = None

    @property
    def alerts(self) -> bool:
        return self.decision == SUFFICIENT_SUSPICIOUS

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "label": self.label,
            "reason": self.reason,
            "reason_chain": list(self.reason_chain),
            "inputs": dict(self.inputs),
            "paths": dict(self.paths),
            "suppression": self.suppression,
            "belirleyen_event": self.belirleyen_event,
            "event_kararlari": list(self.event_kararlari),
            "dagilim": dict(self.dagilim),
            "split": self.split,
        }


def combine_event_decisions(
    kararlar: list[Decision],
    *,
    split: dict[str, Any] | None = None,
) -> AlarmDecision:
    """Event kararlarini alarm karariyla birlestirir -- EN SERT KAZANIR.

    TEK BIRLESTIRICI. Hat da (her event kendi run_improved_query cagrisindan
    gecer) karar katmaninin kendi sozlesme testi de bu fonksiyonu cagirir.
    Ikinci bir birlestirme yolu yazmak, bu oturumda uc kez isiran desendir
    (space_kv, to_legacy_facts, text_to_row): duzeltme bir yola iner, obur
    yol eski davranisi saklar.

    Beraberlik kurali: ayni sertlikte birden fazla event varsa ILKI
    belirleyicidir. Deterministik olmasi denetim icin sart -- "hangi event
    bu karari verdi" sorusunun tek cevabi olmali."""
    if not kararlar:
        raise ValueError("alarm karari icin en az bir event karari gerekli")

    dagilim = {ad: 0 for ad in ALARM_SERTLIGI}
    for k in kararlar:
        dagilim[k.decision] = dagilim.get(k.decision, 0) + 1

    belirleyen_index = max(
        range(len(kararlar)),
        key=lambda i: (ALARM_SERTLIGI.get(kararlar[i].decision, 1), -i),
    )
    belirleyen = kararlar[belirleyen_index]

    event_kararlari = [
        {
            "index": i,
            "decision": k.decision,
            "reason": k.reason,
            "reason_chain": list(k.reason_chain),
            "suppression": k.suppression,
        }
        for i, k in enumerate(kararlar)
    ]

    if len(kararlar) == 1:
        # Tekli girdi: zincir AYNEN korunur. Alarm katmani tek olayli girdide
        # hicbir sey EKLEMEMELI, yoksa gecmis olcumlerle karsilastirilamaz.
        zincir = list(belirleyen.reason_chain)
        ozet = belirleyen.reason
    else:
        zincir = [
            f"Alarm {len(kararlar)} event'e bölündü"
            + (f" (sınır kuralı: {split.get('rule')})" if split else ""),
            "Alarm kararı EN SERT event'ten: "
            + f"#{belirleyen_index} → {belirleyen.decision}",
            "Dağılım: "
            + ", ".join(f"{ad}={dagilim[ad]}" for ad in ALARM_SERTLIGI if dagilim.get(ad)),
        ]
        bastirilan = [e["index"] for e in event_kararlari if e["suppression"]]
        if bastirilan:
            zincir.append(
                f"Bastırılan event(ler): {bastirilan} — bastırma event "
                "seviyesinde kaldı, alarma yayılmadı (§2)"
            )
        zincir += [f"event #{belirleyen_index} · {adim}" for adim in belirleyen.reason_chain]
        ozet = f"event #{belirleyen_index}: {belirleyen.reason}"

    if split and split.get("warning"):
        zincir.append(f"⚠ {split['warning']}")

    return AlarmDecision(
        decision=belirleyen.decision,
        label=DECISION_LABELS[belirleyen.decision],
        reason=ozet,
        reason_chain=zincir,
        inputs=dict(belirleyen.inputs),
        paths=dict(belirleyen.paths),
        suppression=belirleyen.suppression,
        belirleyen_event=belirleyen_index,
        event_kararlari=event_kararlari,
        dagilim=dagilim,
        split=split,
    )


def decide_alarm(raw_text: str) -> AlarmDecision:
    """Ham metni olaylara bolup her olayi decide()'dan gecirir, sonra §1 ile
    birlestirir.

    ESLESTIRME/DOGRULAMA GIRDISI YOK. Bu bicim karar katmaninin kendi
    sozlesmesini olcmek icindir: "zararsiz bir event eklemek supheli bir
    event'i susturabiliyor mu?" sorusu LLM'siz cevaplanabilir olmali.

    Uretim yolu ayni birlestiriciyi kullanir ama event kararlarini kendi
    run_improved_query cagrilarindan alir (app/retrieval/improved_pipeline.py).
    Iki yol da combine_event_decisions'dan gecer."""
    from app.normalization.formats import split_events
    from app.normalization.input_parser import normalize_input

    bolme = split_events(raw_text)
    kararlar = [decide(normalize_input(olay), [], None) for olay in bolme.events]
    return combine_event_decisions(kararlar, split=bolme.to_dict())
