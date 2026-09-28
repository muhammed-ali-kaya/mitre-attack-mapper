"""Formata duyarli log ayristirma katmani (Gorev 1).

NEDEN AYRI BIR KATMAN
    Eski ayristirici tek bir regex'ti ve tek bir bicim varsayiyordu:
    boslukla ayrilmis Key=Value. Baska bicimdeki bir log ona TAMAMEN BOS
    gorunmuyordu -- daha kotusu, YANLIS gorunuyordu: anahtar adlari son
    kelimeye iniyor, degerler ilk bosluktan kesiliyordu. Bir log "ayristirildi"
    damgasi yiyip icerigi bozulmus halde asagi akiyordu.

DESTEKLENEN BICIMLER -- her birinin fixture'i VAR
    brace_kv        {Alan=Deger, Alan=Deger}      tests/fixtures/registry_object_access_logs.json
    windows_message "Etiket:  Deger" cok satirli   tests/fixtures/qradar_2026-08-06_51rows.csv
    json            {"alan": "deger"}             toplu mod JSON girdisi
    space_kv        Alan=Deger Alan=Deger         evaluation/test_scenarios.json (eski varsayilan)

    LEEF ve CEF BILEREK YOK. Elde gercek ornek olmadan yazilan bir ayristirici
    test edilemez, ve test edilmemis bir ayristirici olmayanindan kotudur:
    olmayan sessiz kalir, test edilmemis olan sessizce YANLIS ayristirir.
    Gercek ornek geldiginde LogFormat'i uygulayan bir sinif eklemek yeterli.

DORT DUZELTILEN HATA (olculdu, bkz. tests/test_parser_contract.py)
    A  anahtar son kelimeye iniyor + dedup: 'Pipe Name', 'Process Name',
       'Account Name', 'Object Name' hepsi 'Name' oluyor, ilki (N/A) tutulup
       gerisi siliniyordu. T3'te bunun sonucu 'Value: 0' idi -- yani
       "Defender acik", logun tam tersi.
    B  deger ilk boslukta kesiliyor: 'NT AUTHORITY' -> 'NT',
       'Query key value|...' -> 'Query', 'Access Mask' -> anahtar 'Mask'.
    C  kapanis '}' strip edilmiyor: son alan '0}' kaliyordu.
    D  'Event ID=' bosluklu yazim hic goruilmuyordu: dort probe logunda da
       event_id None cikiyor, event_id_relevance bileseni ve olay
       anlambilimi tamamen olu kaliyordu.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol

import yaml

SCHEMA_FILE = Path(__file__).resolve().parents[2] / "config" / "field_schema.yaml"


@dataclass(frozen=True)
class Field:
    """Tek bir ayristirilmis alan.

    Uc tuketici ayni alandan UC FARKLI sey istiyor, o yuzden deger tek
    basina yetmiyor:
      - Gorev 12 on kapisi  : kac alan BILGI TASIYOR (informative)
      - retrieval sorgusu   : bilgi tasimayan ve sema disi alanlar GIRMEMELI
      - kanit tablosu       : hepsi GORUNMELI, 'bu alan bos' da bir bilgidir
    """
    value: str | list[str]
    informative: bool
    in_schema: bool

    @property
    def text(self) -> str:
        """Metin gosterimi -- liste degerler icin ogeleri birlestirir."""
        if isinstance(self.value, list):
            return " | ".join(self.value)
        return self.value


class LogFormat(Protocol):
    name: str

    def matches(self, raw: str) -> bool: ...

    def extract_pairs(self, raw: str) -> Iterable[tuple[str, str]]: ...


# --------------------------------------------------------------------------
# Sema
# --------------------------------------------------------------------------

_SCHEMA_CACHE: dict[str, Any] | None = None


def _normalise_key(name: str) -> str:
    """Alias eslesmesi icin anahtar: buyuk/kucuk harf, bosluk ve alt cizgi
    duyarsiz. 'Object Value Name' == 'objectvaluename' == 'OBJECT_VALUE_NAME'."""
    return re.sub(r"[\s_]+", "", name).strip().lower()


def load_schema(path: Path | None = None) -> dict[str, Any]:
    """Sema dosyasini okur ve alias -> canonical tersine haritasini kurar."""
    global _SCHEMA_CACHE
    if path is None and _SCHEMA_CACHE is not None:
        return _SCHEMA_CACHE

    raw = yaml.safe_load((path or SCHEMA_FILE).read_text(encoding="utf-8"))
    alias_to_canonical: dict[str, str] = {}
    for canonical, spec in (raw.get("fields") or {}).items():
        for alias in (spec.get("aliases") or []):
            alias_to_canonical[_normalise_key(alias)] = canonical
        # Canonical adin kendisi de bir aliastir.
        alias_to_canonical[_normalise_key(canonical)] = canonical

    schema = {
        "fields": raw.get("fields") or {},
        "alias_to_canonical": alias_to_canonical,
        "non_informative": {
            str(v).strip().lower() for v in (raw.get("non_informative_values") or [])
        },
    }
    if path is None:
        _SCHEMA_CACHE = schema
    return schema


# --------------------------------------------------------------------------
# Bicimler
# --------------------------------------------------------------------------

# Deger bir sonraki ", " ayracina kadar okunur -- ilk BOSLUGA kadar degil.
# Anahtar bosluk icerebilir ('Object Value Name'), bu yuzden [^=]+ kullanilir.
_BRACE_PAIR_RE = re.compile(r"([^=,]+?)\s*=\s*([^=]*?)(?=,\s*[^=,]+?\s*=|$)")

# Boslukla ayrilmis Key=Value. Anahtar bosluk ICERMEZ ama DEGER icerebilir:
#     CommandLine=certutil.exe -urlcache -split -f http://...
#     SubjectDomainName=NT AUTHORITY
#
# Eski hali degeri \S+ ile okuyordu, yani ILK BOSLUKTA kesiyordu -- brace_kv
# icin duzeltilen B bug'inin space_kv'de duran hali. Olculdu: 60 senaryonun
# 16'si bu bicimde ve raw_log kategorisinin 9/10'u; kirpilmis komut satiri
# IKI ayri 60 senaryoluk olcumu kirletti (D kolu ve dedup).
#
# DEGER NEREDE BITER? Bir sonraki "Anahtar=" ciftinde. Ama sinir belirsiz:
#     CommandLine=cmd /c set X=1 SubjectUserName=jdoe
# burada "X=" bir alan degil, komutun parcasi. Bu yuzden sinir SEMADAN
# turetiliyor: yalnizca config/field_schema.yaml'da TANIMLI bir alan adi
# degeri bitirir. Sema zaten ad sozlugunun tek kaynagi; "hangi kelime alan
# adidir" sorusunu ikinci kez cevaplamiyoruz.
_SPACE_KV_KEY_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\s*=")


def _space_kv_boundary_pattern(schema: dict[str, Any]) -> re.Pattern:
    """Semada tanimli alan adlarindan deger-bitis sinirini kurar."""
    adlar = sorted(
        {re.sub(r"[\s_]+", "", a) for a in schema["alias_to_canonical"]},
        key=len, reverse=True,
    )
    return re.compile(
        r"\s+(?:" + "|".join(re.escape(a) for a in adlar) + r")\s*=",
        re.IGNORECASE,
    )

# Windows Message govdesi: "Etiket:  Deger", aralarinda 2+ bosluk.
#
# ETIKETIN SINIRI UZUNLUK DEGIL, BICIMIN KENDI DEGISMEZIDIR (Gorev 15).
# Eski hali `[A-Z][A-Za-z ]{2,28}?` idi ve 28 keyfi bir sayiydi. Iki yonde
# de yanlisti:
#   - 32 karakterlik gercek etiket ('Privileges Used for Access Check')
#     TANINMIYOR, metni bir onceki alanin degerine yapisiyordu:
#     access.mask = '0x2001F  Privileges Used for Access Check: -'
#     -> decode_access_mask None donuyor -> Yol B hic ateslenemiyor.
#   - Siniri buyutmek (60/sinirsiz olculdu) bu kez DEGERI etiket sandiriyor:
#     'Notify about changes to keys       Access Reasons' etiket olarak
#     okunuyor, access.list bozuluyor.
#
# Asil kural: 2+ ardisik bosluk bu bicimde ETIKET/DEGER AYRACIDIR, o yuzden
# etiketin ICINDE olamaz. Etiket = tek bosluklu kelime dizisi. Uzunluk
# sinirina gerek yok; sinir zaten ayracin kendisi.
#
# OLCULDU (166 girdi: 51 QRadar KV + 51 ham Message + 60 senaryo + 4 probe):
# hicbir girdide BICIM SECIMI degismedi (bu regex matches() icinde de
# kullaniliyor), hicbir girdide sema ici alan KAYBEDILMEDI, 41 ham Message
# girdisinde alan kumesi duzeldi (object.name +5, source.ip +23,
# user.domain +18, account.name +15, logon.id +7). Silinen adlarin hepsi
# 'unknown.Key  Object Name' gibi BOZUK isimlerdi.
_MESSAGE_LABEL_RE = re.compile(
    r"(?:^|(?<=\s\s)|(?<=\n))([A-Z][A-Za-z]+(?: [A-Za-z]+)*):[ \t]+"
)


class BraceKeyValueFormat:
    """{Alan=Deger, Alan=Deger} -- virgul ayracli, anahtarlarda bosluk var."""

    name = "brace_kv"

    def matches(self, raw: str) -> bool:
        stripped = raw.strip()
        return stripped.startswith("{") and "=" in stripped and not _looks_like_json(stripped)

    def extract_pairs(self, raw: str) -> Iterable[tuple[str, str]]:
        # BUG C: bastaki '{' ve sondaki '}' atilir; aksi halde son degerde
        # kapanis parantezi kaliyordu ('0}').
        body = raw.strip().lstrip("{").rstrip("}")
        for key, value in _BRACE_PAIR_RE.findall(body):
            yield key.strip(), value.strip().rstrip(",").strip()


class JsonFormat:
    name = "json"

    def matches(self, raw: str) -> bool:
        return _looks_like_json(raw.strip())

    def extract_pairs(self, raw: str) -> Iterable[tuple[str, str]]:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                yield str(key), json.dumps(value, ensure_ascii=False)
            else:
                yield str(key), "" if value is None else str(value)


class WindowsMessageFormat:
    """Gercek Windows Event Log export'u: govdede "Etiket:  Deger"."""

    name = "windows_message"

    def matches(self, raw: str) -> bool:
        return len(_MESSAGE_LABEL_RE.findall(raw)) >= 2

    def extract_pairs(self, raw: str) -> Iterable[tuple[str, str]]:
        matches = list(_MESSAGE_LABEL_RE.finditer(raw))
        for i, match in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
            value = raw[match.end():end].strip()
            # Bos deger bir BOLUM BASLIGIDIR ("Process Information:"), alan degil.
            if value:
                yield match.group(1).strip(), value


class SpaceKeyValueFormat:
    """Alan=Deger Alan=Deger -- eski varsayilan bicim.

    Deger, bir SONRAKI sema alanina kadar okunur (bkz. _space_kv_boundary_pattern).
    Tirnakli degerler oldugu gibi alinir."""

    name = "space_kv"

    def matches(self, raw: str) -> bool:
        return bool(_SPACE_KV_KEY_RE.search(raw))

    def extract_pairs(self, raw: str) -> Iterable[tuple[str, str]]:
        schema = load_schema()
        sinir = _space_kv_boundary_pattern(schema)

        # Bir onceki degerin bittigi konum. Icinde "X=" gecen bir komut
        # satiri ("cmd /c set X=1") ayrica alan uretmesin: o "X=" zaten
        # baska bir alanin DEGERININ icinde.
        tuketilen = 0

        for match in _SPACE_KV_KEY_RE.finditer(raw):
            if match.start() < tuketilen:
                continue
            key = match.group(1)
            kalan = raw[match.end():]

            tirnakli = re.match(r'\s*"((?:[^"\\]|\\.)*)"', kalan)
            if tirnakli:
                tuketilen = match.end() + tirnakli.end()
                # Regex kacisli cifti ZATEN taniyor (`\\.`) ama grubu ham
                # dondururdu -- yani tirnaklamayi cozup kacisi birakiyordu.
                # Asimetri buradaydi.
                yield key, unescape_serialized(tirnakli.group(1))
                continue

            son = sinir.search(kalan)
            ham = kalan[: son.start()] if son else kalan
            # Satir sonu da bir sinirdir: cok satirli girdide bir sonraki
            # satirin basi onceki degerin devami degildir.
            ham = ham.split("\n", 1)[0]
            tuketilen = match.end() + len(ham)
            deger = ham.strip()
            if deger:
                yield key, _unquote(deger)


# Sira ONEMLI: en spesifik bicim once denenir. brace_kv ve json ikisi de '{'
# ile basliyor, bu yuzden json once kontrol edilir.
FORMATS: list[LogFormat] = [
    JsonFormat(),
    BraceKeyValueFormat(),
    SpaceKeyValueFormat(),
    WindowsMessageFormat(),
]


def _looks_like_json(text: str) -> bool:
    if not text.startswith("{"):
        return False
    try:
        return isinstance(json.loads(text), dict)
    except Exception:
        return False


# Serilestirmenin URETTIGI kacis dizileri, TAM OLARAK bunlar:
# app/batch/serialize.py:_format_kv_value tirnaklarken `\` -> `\\` ve
# `"` -> `\"` yaziyor. Geri alma DAR tutuluyor -- yalnizca bu iki dizi.
#
# NEDEN GENEL BIR `\\(.)` DEGIL: ucuncu taraf loglarinda tirnak icinde
# 'C:\Users\...' gibi TEK ters bolulu yollar var; genel kural onlardan
# ters boluyu SILERDI. Dar kural onlara dokunmuyor (ne `\\` ne `\"`).
# Geriye kalan tek belirsizlik: bizim uretmedigimiz, tirnakli, icinde
# gercek `\\` tasiyan bir deger (tirnak icinde UNC yolu). 166 girdilik
# korpusta OLCULDU: boyle deger 0 tane.
_ESCAPE_UNDO_RE = re.compile(r"\\([\\\"])")


def unescape_serialized(value: str) -> str:
    """Serilestirmenin kacisini geri alir. TIRNAKLI degerlere ozgudur.

    Tirnaksiz bir degere UYGULANMAZ: tirnaklanmayan deger kacislanmamistir
    da, ve orada `\\\\` gercek bir cift ters bolu (UNC yolu) olabilir."""
    return _ESCAPE_UNDO_RE.sub(r"\1", value)


def _unquote(value: str) -> str:
    """Tirnaklari siler VE kacisi geri alir.

    Ikisi ayrilamaz: tirnak eklemek ile kacis eklemek serilestirmede TEK
    islemdir (bkz. _format_kv_value), o yuzden geri alma da tek islem.
    Ayri birakildiginda olan sey olculdu -- 'reg.exe save HKLM\\SAM ...'
    toplu yoldan 'HKLM\\\\SAM' olarak cikiyor ve varlik kritikligi
    critical yerine unknown donuyor."""
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return unescape_serialized(value[1:-1])
    return value


def detect_format(raw: str) -> LogFormat | None:
    for fmt in FORMATS:
        try:
            if fmt.matches(raw):
                return fmt
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------
# Ayristirma
# --------------------------------------------------------------------------

def parse_fields(
    raw: str,
    schema: dict[str, Any] | None = None,
    *,
    _nested: bool = False,
) -> tuple[dict[str, Field], str | None]:
    """Ham logu {canonical_ad: Field} sozlugune cevirir.

    Donen ikinci deger kullanilan bicimin adi (bilinmiyorsa None).

    ANAHTAR CAKISMASINDA DEDUP YOK: her alan kendi canonical adiyla durur.
    Ayni canonical ad iki kez gelirse ILKI korunur -- ama bu artik 'Pipe Name'
    ile 'Object Name'in carpismasi degil, gercekten ayni alanin tekrari.

    YUVALANMIS GOVDE (Gorev 15): semada `nested: true` isaretli bir alanin
    DEGERI kendi basina bir logdur ve ayrica ayristirilir. Donen bicim adi
    her zaman DIS bicimdir; ic ayristirma bir alt yapi degil, bir kurtarma
    adimidir. `_nested` yalnizca tek seviye inilmesini garanti eder."""
    schema = schema or load_schema()
    alias_map = schema["alias_to_canonical"]
    specs = schema["fields"]
    non_informative = schema["non_informative"]

    fmt = detect_format(raw)
    if fmt is None:
        return {}, None

    fields: dict[str, Field] = {}
    for raw_key, raw_value in fmt.extract_pairs(raw):
        key = raw_key.strip()
        if not key:
            continue

        canonical = alias_map.get(_normalise_key(key))
        in_schema = canonical is not None
        # Sema disi alan SILINMEZ: kanit tablosunda gorunur, retrieval
        # sorgusuna girmez. Ad kirliligi olmasin diye namespace'lenir.
        name = canonical or f"unknown.{key}"
        if name in fields:
            continue

        value: str | list[str] = raw_value
        separator = (specs.get(canonical) or {}).get("list_separator") if canonical else None
        if separator:
            # Liste alani HER ZAMAN listedir -- tek ogeli olsa bile.
            # Ayraca gore sartli davranmak, T2'deki 'Accesses=Query key value'
            # gibi tek erisimli kayitlarda tipi sessizce degistiriyordu ve
            # tuketici bir gun str, bir gun list gormek zorunda kaliyordu.
            value = [part.strip() for part in raw_value.split(separator) if part.strip()]

        # Ayrac KORUNUR: " ".join uc ayri erisimi ("Query key value",
        # "Enumerate sub-keys", "Read Control") tek bulanik ifadeye
        # cevirirdi. Bu metin retrieval sorgusuna ve kanit tablosuna akiyor,
        # ve access.list Gorev 2'de birincil agirlikli alanlardan biri olacak.
        text = value if isinstance(value, str) else " | ".join(value)
        informative = (
            in_schema and bool(text.strip()) and text.strip().lower() not in non_informative
        )
        fields[name] = Field(value=value, informative=informative, in_schema=in_schema)

    if not _nested:
        fields = _yuvalanmis_govdeleri_coz(fields, schema)
        fields = _turetilmis_alanlari_doldur(fields, schema)

    return fields, fmt.name


#: Turetim kurallari. Tablo semada (`derive:`), UYGULAMA burada -- yeni bir
#: turetilmis alan eklemek sema satiri yazmaktir, kod degistirmek degil.
def _taban_ad(deger: str) -> str:
    """Yolun son bileseni. Iki ayrac da kabul edilir; QRadar kayitlarinda
    ters bolu, Sysmon/normalize edilmis kayitlarda duz bolu gorulebiliyor."""
    return re.split(r"[\\/]", deger.strip().rstrip("\\/"))[-1]


_TURETME_KURALLARI = {"basename": _taban_ad}


def _turetilmis_alanlari_doldur(
    fields: dict[str, Field], schema: dict[str, Any]
) -> dict[str, Field]:
    """Semada `derive:` isaretli alanlari KAYNAK alandan doldurur.

    NEDEN VAR (Gorev 24): gercek bir QRadar kaynagi ebeveyn surec icin
    YALNIZCA `Parent Process Path` yaziyor, `Parent Process Name` YAZMIYOR --
    ama iki kural kosulu (T1204.002, T1566.001) `parent.process.name` okuyor.
    Yeni kanonik alani turetimsiz eklemek olculdu: **0 kosul** aciyor, yani
    alan olu dogardi (docs/beklenti_24_sema_alan_boslugu.md §4a).

    UC SINIR -- ucu de kabul olcutu olarak kod yazilmadan ONCE baglandi:

      1. ACIK DEGER KAZANIR. Alan zaten varsa turetim CALISMAZ. Kaynak hem
         adi hem yolu yazdiginda kaynagin kendi beyani yetkilidir; turetim
         yalnizca BOSLUK DOLDURUR (`_yuvalanmis_govdeleri_coz` ile ayni
         yetki sirasi).
      2. BILGI TASIMAYAN KAYNAKTAN TURETILMEZ. 'N/A' / '-' bir yol degildir;
         ondan uretilen 'taban ad' da bir ad degildir. Bosluğu bos bir
         degerle doldurmak bosluktan kotudur -- ayni gerekce, ayni cumle.
      3. YON TEK TARAFLI. Tablo yalnizca yol -> ad tasiyor. Ters yon
         (ad -> yol) YASAK: taban addan dizin URETILEMEZ, ve Gorev 17
         'dizinsiz deger dogrulanmis sayilmaz' kuralini tam bu noktada
         koydu. Bu bir tablo kisiti degil, kasitli bir bosluk."""
    specs = schema["fields"]
    birlesik = dict(fields)
    for ad, spec in specs.items():
        kural = (spec or {}).get("derive") or {}
        kaynak_ad, kural_adi = kural.get("from"), kural.get("rule")
        if not kaynak_ad or kural_adi not in _TURETME_KURALLARI:
            continue
        if ad in birlesik:
            continue  # SINIR 1
        kaynak = birlesik.get(kaynak_ad)
        if kaynak is None or not kaynak.informative:
            continue  # SINIR 2
        turetilen = _TURETME_KURALLARI[kural_adi](kaynak.text)
        if not turetilen.strip():
            continue
        birlesik[ad] = Field(value=turetilen, informative=True, in_schema=True)
    return birlesik


def _yuvalanmis_govdeleri_coz(
    fields: dict[str, Field], schema: dict[str, Any]
) -> dict[str, Field]:
    """Semada `nested: true` isaretli alanlarin govdesini ayrica ayristirir.

    YETKI SIRASI -- DIS ALAN KAZANIR, ic govde YALNIZCA BOSLUK DOLDURUR.

    Varsayim ACIKCA yaziliyor (HANDOFF dersi 8: sessiz oncelik sirasi bir
    gerekceyi dondurur): dis alanlar kaynagin ACIK kolonlarindan gelir
    (QRadar adaptorunun EventID/SubjectUserName/FilePath kolonlari), ic
    govde ise 'Etiket: Deger' ayristirmasinin best-effort urunudur.
    Olculdu -- cakisan iki alanda da dis deger daha temiz:
        process.name  12/51  dis 'C:\\Windows\\...svchost.exe'  ic ayni ama kacisli
        host.name      1/51  dis 'WINHOST-01'   ic 'ConsoleHost  HostVersion=...'
    Adaptor kolonlari bir gun best-effort hale gelirse bu sira yeniden
    degerlendirilmelidir.

    Bicim adi DEGISMEZ: cagiran taraf hala dis bicimi gorur. Ic govdenin
    kendi bicimi (windows_message) bir uygulama detayidir; disari sizsaydi
    'bu log hangi bicimde' sorusunun iki cevabi olurdu."""
    specs = schema["fields"]
    nested_adlar = [ad for ad in fields if (specs.get(ad) or {}).get("nested")]
    if not nested_adlar:
        return fields

    birlesik = dict(fields)
    for ad in nested_adlar:
        govde = fields[ad].text
        if not govde.strip():
            continue
        try:
            ic_alanlar, _ = parse_fields(govde, schema, _nested=True)
        except Exception:
            # Ic govde ayristirilamazsa dis sonuc AYNEN durur. Kurtarma
            # adimi, dis ayristirmayi riske atamaz.
            continue
        for ic_ad, ic_alan in ic_alanlar.items():
            if ic_ad == ad:
                continue  # govde kendini tekrar uretmesin
            # BILGI TASIMAYAN DEGER KURTARILMAZ ('-', 'N/A', 'NULL SID'...).
            #
            # Dis yolda bu degerler SAKLANIR ve informative=False ile
            # isaretlenir -- cunku orada kaynak o kolonu ACIKCA bos ilan
            # etmistir ve analist "bu alan bos" bilgisini gormelidir.
            # Ic govde bir KURTARMA adimidir ve setdefault ile yalnizca
            # BOSLUK DOLDURUR: bosluğu bos bir degerle doldurmak bosluktan
            # kotudur.
            #
            # Somut zarar olculdu: decision._alan yalnizca 'N/A'yi yokluk
            # sayiyor, '-' yokluk saymiyor. Ic govdeden gelen
            # object.name='-' varlik_kritikligi'nde iyi olan file.path
            # degerini GOLGELERDI -- yani kurtarma, karari bozardi.
            if ic_alan.in_schema and not ic_alan.informative:
                continue
            birlesik.setdefault(ic_ad, ic_alan)
    return birlesik


def to_legacy_facts(fields: dict[str, Field], schema: dict[str, Any] | None = None) -> dict[str, str]:
    """Eski tuketiciler icin duz {ad: deger} izdusumu.

    Kural motoru, QRadar yolu ve korelasyon 'EventID', 'CommandLine' gibi
    ESKI adlara bagli. Yeni canonical adlara toptan gecmek Gorev 1'i bir ad
    gocune cevirirdi; bu izdusum kopruyu tek yerde tutuyor.

    Yetkili yapi parse_fields()'in dondurdugudur; burasi yalnizca bir
    goruntudur."""
    schema = schema or load_schema()
    specs = schema["fields"]
    out: dict[str, str] = {}
    for name, field in fields.items():
        legacy = (specs.get(name) or {}).get("legacy")
        out[legacy or name] = field.text
    return out


# --------------------------------------------------------------------------
# Olay bolme (Gorev 14) -- docs/beklenti_14_girdi_bolme_alarm_karari.md
# --------------------------------------------------------------------------
#
# NEDEN BURADA: bicim algilama zaten bu modulde. Olay siniri BICIME OZGUDUR
# ("brace_comma_kv satir basina bir olay; duzyazi bolunmez"), yani sinir
# kuralini bicim algilayicidan ayri bir modulde tutmak ayni soruyu iki yerde
# cevaplamak olurdu.
#
# NEDEN GEREKLI: normalize_input cok olayli metni TEK KAYIT saniyordu ve
# cakismayi alanlar arasinda TUTARSIZ coziyordu (event.id/process.name ILK,
# account.name SON kazanir). Sonucu bir bug degil bir ACIK: saldirgan
# zararsiz bir olay ekleyerek gercek alarmi susturabiliyordu, cunku bastiran
# (surec, hesap) cifti HICBIR EVENT'TE birlikte yoktu -- yalnizca
# birlestirmeden doguyordu (tests/fixtures/merge_vulnerability_logs.json).
#
# YANLIS BOLMEK, BIRLESTIRMEK KADAR ZARARLI: bir event ikiye bolunurse
# kanitin yarisi bir tarafta, teknigin geldigi satir obur tarafta kalir ve
# kanit kapisi kendi bulgusunu curutur. Bu yuzden kurallarin hepsi
# BOLMEMEYE meyillidir: suphede kalan girdi TEK olay sayilir ve durum
# SESSIZ GECILMEZ (asagidaki isaret sayaci).
#
# SINIR KURALLARI -- sirayla, ilk uyan uygulanir
#
#   1. json_array         metnin tamami bir JSON dizisi -> oge basina bir olay
#   2. brace_blocks       >=2 DENGELI ust seviye {...} blogu ve bloklarin
#                         disinda yalnizca bosluk -> blok basina bir olay.
#                         Satir sonuna bagli DEGIL: "{a} {b}" de boluner.
#   3. cok_satirli_kayit  "{" ile baslayan satir YOK ve >=2 "Etiket:  Deger"
#                         isareti VAR -> Windows Event Log govdesi. Bu bicimde
#                         kayit sinirlari satir sonlari DEGILDIR; BOLUNMEZ.
#   4. lines              satir sonu sinirdir. IKI istisna:
#                         (a) ayrac dengesi bozukken satir sonu sinir DEGILDIR
#                             -- cok satirli bir blok ikiye bolunmez;
#                         (b) ardisik DUZYAZI satirlari TEK olayda birlesir
#                             ve bos satir duzyaziyi bolmez -- duzyazi
#                             bolunmez (beklenti dosyasi bolum 3).
#   5. single             hicbiri >1 olay uretmedi -> TEK olay.
#
# BOLUNEMEYEN DURUM -- sessiz geri donus YOK
#   Bagimsiz bir sayac girdideki olay isaretlerini ("Event ID=" / "Event ID:")
#   sayar. Isaret sayisi uretilen olay sayisindan BUYUKSE bolme eksik
#   kalmistir ve sonuc bir UYARI tasir. Elle sayilan beklentiyi bagimsiz bir
#   sayacla dogrulamak bu projede uc kez hata yakaladi; burada ayni desen
#   bolucunun kendi korlugune uygulaniyor.

#: Olay isareti. "EventIDCode=" BILEREK eslesmez -- QRadar payload'unda
#: EventID ile birlikte gecer ve tek olayi iki isaret gibi sayardi.
_EVENT_MARKER_RE = re.compile(r"\bEvent\s*ID\s*[=:]", re.IGNORECASE)


def _isaret_sayisi(metin: str) -> int:
    """Girdideki olay isaretlerini BOLGE BASINA sayar ve en buyugunu alir.

    NEDEN DUZ SAYIM DEGIL -- OLCULDU (51 gercek QRadar satiri): bir QRadar
    satiri ayni olayi IKI KODLAMADA tasiyor; yapisal alanda
    "{... Event ID=5156 ...}", ham payload'da "EventID=5156". Duz sayim
    51/51 satirda "2 isaret, 1 olay" deyip uyari basiyordu. Her satirda yanan
    bir uyari, uyari degil gurultudur ve okunmamayi ogretir.

    Ayni olayin iki kodlamasi TEK olaydir; iki AYRI olay ise ayni bolgede
    yan yana durur. Bu yuzden sayac blok ICI ve blok DISI olarak ayri sayar,
    buyugunu dondurur.

    Dogrulama (ayni olcum): 60 senaryodan yalnizca `multi-010` uyari veriyor
    ve o senaryo gercekten iki olay tasiyor ("EventID=4688 ... followed by
    EventID=4688 ..."), tek satirda, bolunemeyecek bicimde. Yani sayac
    gercek pozitifi koruyup yanlis pozitifi dusuruyor.

    BILINEN SINIR: ayni bolgede ayni olayin iki kez serilestirildigi bir
    girdi hala iki olay sayilir. Boyle bir ornek elde YOK; goruldugunde
    fixture'lanip burada cozulecek."""
    bloklar, disarida = _brace_blocks(metin)
    blok_ici = sum(len(_EVENT_MARKER_RE.findall(b)) for b in bloklar)
    blok_disi = len(_EVENT_MARKER_RE.findall(disarida))
    return max(blok_ici, blok_disi)


@dataclass(frozen=True)
class SplitResult:
    """Bolme sonucu + NASIL bolundugu.

    Kural adi ciktida tasinir: "iki olay bulundu" demek yetmez, hangi sinir
    kuralinin buldugu denetlenebilir olmali. Bir alarm yanlis bolunduyse
    once bu alan okunur."""

    events: tuple[str, ...]
    rule: str
    marker_count: int
    warning: str | None = None

    @property
    def split(self) -> bool:
        return len(self.events) > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "event_count": len(self.events),
            "marker_count": self.marker_count,
            "warning": self.warning,
        }


def _brace_blocks(text: str) -> tuple[list[str], str]:
    """Ust seviye dengeli {...} bloklari ve bloklarin DISINDA kalan metin.

    Disarida kalan metin bilerek donuyor: "{a} serbest metin {b}" girdisinde
    bloklara bakip serbest metni yok saymak, bir olayi sessizce dusurmek
    olurdu.

    TIRNAK YALNIZCA BLOK ICINDE izlenir. Blok disinda tirnak siradan bir
    karakterdir: gercek QRadar payload'unda tek basina duran tirnaklar var ve
    onlari dize baslangici saymak metnin GERI KALANINI yutuyordu -- 51
    satirin 51'inde disarida kalan metin bos cikiyordu."""
    blocks: list[str] = []
    disarida: list[str] = []
    depth = 0
    start: int | None = None
    in_str = False
    escape = False

    for i, ch in enumerate(text):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"' and depth:
            in_str = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth:
                depth -= 1
                if depth == 0 and start is not None:
                    blocks.append(text[start : i + 1])
                    start = None
        elif depth == 0:
            disarida.append(ch)

    if depth and start is not None:
        # Kapanmamis blok: bir olayi yarim bir bloga indirmektense bolme
        # basarisiz sayilir (cagiran tarafta >1 sarti tutmaz).
        disarida.append(text[start:])
    return blocks, "".join(disarida)


def _ayraclar_kapali_mi(text: str) -> bool:
    """Satir sonu SINIR SAYILABILIR mi -- ayraclar dengeli mi?

    Dengesizse satir bir sonrakinde devam ediyordur. Kapanmayan bir tirnak
    tum kalan satirlari tek olaya baglar; bu yon KASITLI: eksik bolme
    gorunur (isaret sayaci uyarir), yanlis bolme gorunmez."""
    depth = 0
    in_str = False
    escape = False
    for ch in text:
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth = max(0, depth - 1)
    return depth == 0 and not in_str


def _line_groups(text: str) -> list[str]:
    """Satirlari olay adaylarina gruplar (kural 4)."""
    gruplar: list[str] = []
    tampon: list[str] = []
    duzyazi_acik = False

    for satir in text.splitlines():
        if tampon:
            tampon.append(satir)
            if _ayraclar_kapali_mi("\n".join(tampon)):
                gruplar.append("\n".join(tampon))
                tampon = []
                duzyazi_acik = False
            continue

        if not satir.strip():
            continue  # bos satir duzyaziyi BOLMEZ

        if not _ayraclar_kapali_mi(satir):
            tampon = [satir]
            continue

        if detect_format(satir) is None:
            # Duzyazi bir IDDIA, artefakt degil. Bolunmez; ardisik duzyazi
            # satirlari ayni olayda kalir.
            if duzyazi_acik:
                gruplar[-1] = gruplar[-1] + "\n" + satir
            else:
                gruplar.append(satir)
                duzyazi_acik = True
            continue

        gruplar.append(satir)
        duzyazi_acik = False

    if tampon:
        gruplar.append("\n".join(tampon))
    return gruplar


def _split_sonucu(olaylar: list[str], kural: str, isaret: int) -> SplitResult:
    temiz = [o.strip() for o in olaylar if o.strip()]
    if not temiz:
        temiz = [""]
    uyari = None
    if isaret > len(temiz):
        uyari = (
            f"BÖLÜNEMEDİ: girdide {isaret} olay işareti (Event ID) var, sınır "
            f"kuralı '{kural}' {len(temiz)} olay üretti. Alanlar olaylar "
            "arasında BİRLEŞTİRİLMİŞ olabilir — bu girdide alarm kararı tek "
            "olaya dayanıyor ve bastırma/eleme olaylar arası derlemeye açıktır."
        )
    return SplitResult(tuple(temiz), kural, isaret, uyari)


def split_events(raw: str) -> SplitResult:
    """Cok olayli girdiyi olaylara boler. Kurallar modul basligindaki tabloda.

    Donen liste HER ZAMAN en az bir eleman tasir: tek olayli girdi de tek
    elemanli listedir. Cagiran taraf "bolundu mu" diye dallanmaz -- tekli ve
    coklu girdi AYNI koddan gecer (beklenti dosyasi bolum 3)."""
    metin = (raw or "").strip()
    isaret = _isaret_sayisi(metin)

    if not metin:
        return _split_sonucu([raw or ""], "bos", isaret)

    # 1. JSON dizisi
    try:
        veri = json.loads(metin)
    except Exception:
        veri = None
    if isinstance(veri, list) and len(veri) > 1 and all(isinstance(x, dict) for x in veri):
        return _split_sonucu(
            [json.dumps(x, ensure_ascii=False) for x in veri], "json_array", isaret
        )

    # 2. Ust seviye {...} bloklari
    bloklar, disarida = _brace_blocks(metin)
    if len(bloklar) > 1 and not disarida.strip():
        return _split_sonucu(bloklar, "brace_blocks", isaret)

    # 3. Cok satirli Windows kaydi -- satir sonu sinir DEGIL
    if len(_MESSAGE_LABEL_RE.findall(metin)) >= 2 and not any(
        s.lstrip().startswith(("{", "[")) for s in metin.splitlines()
    ):
        return _split_sonucu([metin], "cok_satirli_kayit", isaret)

    # 4. Satir siniri
    gruplar = _line_groups(metin)
    if len(gruplar) > 1:
        return _split_sonucu(gruplar, "lines", isaret)

    return _split_sonucu([metin], "single", isaret)
