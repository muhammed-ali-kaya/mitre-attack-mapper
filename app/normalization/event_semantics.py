"""Olay ID'si ve erisim maskesi anlambilimi (Gorev 3).

NE COZULUYOR
    Sistem olay ID'sini bir ETIKET gibi tasiyordu, anlamini hic cozmuyordu.
    Iki somut kayip:

    1. 4657 "registry degeri degistirildi" demektir -- TANIMI GEREGI bir
       yazma islemi. T3'te (Defender kapatma) bu tek basina T1112/T1685
       ailesine guclu bir sinyaldi ve hicbir yerde kullanilmadi.
    2. 4656 yalnizca bir HANDLE TALEBIDIR; erisimin gerceklestigini
       gostermez (o 4663'tur). Ikisini ayni saymak, "acmayi denedi" ile
       "okudu" arasindaki farki silmek demek.

    Erisim maskesi de string olarak tasiniyordu: '0x2000d' bir metin
    parcasiydi, icindeki yazma bitleri hicbir zaman gorulmedi.

NEDEN LLM DEGIL
    Bit maskesi cozmek deterministik bir lookup'tir. Cevabi kesin bilinen
    bir soruyu dil modeline sormak, onu olasiliksal hale getirmekten baska
    bir sey yapmaz. Tablolar config/ altinda VERI olarak durur; tablo
    buyudukce bu dosya degismez.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
EVENT_FILE = CONFIG_DIR / "event_semantics.yaml"
MASK_FILE = CONFIG_DIR / "access_mask.yaml"

# Yazma niyeti tasiyan islem siniflari. Salt okuma -> T1012/T1003 ailesi;
# yazma/silme -> T1112/T1562/T1685 ailesi.
WRITE_CLASSES = {"write", "create", "delete"}

_EVENTS: dict[str, Any] | None = None
_MASKS: dict[str, Any] | None = None


def _load(path: Path, cache_name: str) -> dict[str, Any]:
    global _EVENTS, _MASKS
    cached = _EVENTS if cache_name == "events" else _MASKS
    if cached is not None:
        return cached
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if cache_name == "events":
        _EVENTS = data
    else:
        _MASKS = data
    return data


def event_semantics(event_id: str | None) -> dict[str, Any] | None:
    """Olayin anlami, islem sinifi, veri bileseni ve anlamli alanlari."""
    if not event_id:
        return None
    return (_load(EVENT_FILE, "events").get("events") or {}).get(str(event_id).strip())


def meaningful_fields(event_id: str | None) -> list[str]:
    """BU OLAY TURUNDE anlam tasiyan alan adlari.

    Gorev 12'nin ucuz on kapisi bunu kullanir: tek bir genel "bilgilendirici
    alan sayisi"na bakmak, 4656 icin object.name eksikligini YAKALAYAMAZ --
    15 alanin 5'i dolu olabilir ama kritik olan bos olabilir."""
    semantics = event_semantics(event_id)
    return list((semantics or {}).get("anlamli_alanlar") or [])


def missing_critical_fields(event_id: str | None, present: set[str]) -> list[str]:
    """Bu olay icin beklenen ama girdide BULUNMAYAN anlamli alanlar."""
    return [f for f in meaningful_fields(event_id) if f not in present]


@dataclass
class DecodedMask:
    """Cozulmus erisim maskesi.

    inconsistent_with_text: maske ile Accesses metni CELISIYOR mu. Gercek
    loglarda oluyor -- ornek: Accesses uc erisim listeliyor ama maskede
    dorduncu bir yazma biti var. Sessizce birini secmiyoruz; ikisini de
    raporlayip celiskiyi isaretliyoruz."""
    raw: str | None
    bits: list[str] = field(default_factory=list)
    classes: set[str] = field(default_factory=set)
    inconsistent_with_text: bool = False
    text_only: list[str] = field(default_factory=list)
    mask_only: list[str] = field(default_factory=list)
    #: Sinif NEREDEN geldi: "mask" | "text" | "mask+text".
    #: Gorev 19: sessizce turetilmis bir sinif, denetlenemez bir siniftir.
    #: Analist "write" gordugunde bunun hex maskeden mi yoksa Accesses
    #: metninden mi geldigini bilmek zorunda -- ikisinin guvenilirligi ayni
    #: degil (metin lehceye gore degisir, maske bit tablosudur).
    source: str = "mask"
    #: Metinde gecen ama bit tablosuna baglanamayan adlar (Gorev 20).
    #: Bos degilse ve baska sinif kaniti yoksa sinif "unknown"dir.
    unresolved: list[str] = field(default_factory=list)

    @property
    def access_class(self) -> str | None:
        """Tek bir etiket: yazma biti VARSA write, yoksa read.

        Yazma bir yukselme: 'okudu ve yazdi' bir yazma olayidir."""
        if not self.classes:
            # Gorev 20: cozulemeyen ad varken None donmek, cagirani olayin
            # varsayilanina dusuruyordu (4663 -> read) ve bu SESSIZ bir
            # yanlistir. "unknown" gurultulu ama dogru.
            return "unknown" if self.unresolved else None
        return "write" if self.classes & WRITE_CLASSES else "read"


def _table_for(object_type: str | None) -> dict[str, dict[str, str]]:
    """Object Type'a gore bit tablosu. 'Key' KRIPTOGRAFIK anahtar degil,
    Windows registry anahtaridir -- bu ayrim yapilmadigi icin T0'da
    T1552.004 (Private Keys) aday olarak gelmisti."""
    masks = _load(MASK_FILE, "masks")
    family = (masks.get("object_type_map") or {}).get(
        (object_type or "").strip().lower(), "registry"
    )
    table = dict(masks.get(family) or {})
    table.update(masks.get("standard") or {})
    return table


def decode_access_mask(
    mask: str | None,
    object_type: str | None = None,
    access_text: list[str] | str | None = None,
) -> DecodedMask | None:
    """Ham maskeyi -- ya da maske yoksa `Accesses` METNINI -- bit adlarina
    ve read/write sinifina cevirir.

    GOREV 19: eskiden ilk satir `if not mask: return None` idi ve
    `access_text` YALNIZCA maskeyle capraz kontrol icin kullaniliyordu;
    hicbir zaman sinifin KAYNAGI degildi. Gercek QRadar verisinde 4663
    satirlari maskesiz gelip yalnizca `Accesses: Set key value` tasiyor ve
    o kayitlar `read` sayiliyordu. Olculdu: SAM + 4663 + Accesses (maskesiz)
    -> erisim read -> Yol B ateslenmiyor -> GERCEK ALARM KACIYOR
    (docs/beklenti_19_accesses_metni.md §1.3).

    Bilgi kayip degildi -- parser `access.list`'i tasiyordu. Gorev 15'in
    kardesi: orada alan parser'a ulasmiyordu, burada parser'dan karara."""
    table = _table_for(object_type)
    metin_bitleri, metin_siniflari, cozulemeyen = _classes_from_text(access_text, table)

    if not mask:
        # Maske yok: sinif YALNIZCA metinden gelebilir. Metin de yoksa
        # soylenecek bir sey yoktur -- eski davranis (None) korunur, cunku
        # "bilgi yok" ile "okuma" ayni sey degildir.
        if not metin_siniflari:
            # Metin VARDI ama hicbir adi cozulemedi: bu "bilgi yok" degil,
            # "bilgi var, okuyamadim" demektir. Ikisi ayni sey degil ve
            # ayni sonuca goturulemez (Gorev 20 §2.3).
            if cozulemeyen:
                return DecodedMask(
                    raw=None, bits=[], classes=set(),
                    source="text", unresolved=cozulemeyen,
                )
            return None
        return DecodedMask(
            raw=None,
            bits=sorted(metin_bitleri),
            classes=metin_siniflari,
            source="text",
            unresolved=cozulemeyen,
        )

    text = str(mask).strip()
    try:
        value = int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None

    bits: list[str] = []
    classes: set[str] = set()
    for hex_key, spec in table.items():
        bit = int(hex_key, 16)
        if bit and value & bit == bit:
            bits.append(spec["ad"])
            classes.add(spec["sinif"])

    decoded = DecodedMask(
        raw=text,
        bits=sorted(bits),
        classes=classes,
        source="mask+text" if metin_siniflari else "mask",
        unresolved=cozulemeyen,
    )

    if access_text:
        items = [access_text] if isinstance(access_text, str) else list(access_text)
        normalised = {_normalise_access(i) for i in items}
        mask_names = {_normalise_access(b) for b in bits}
        decoded.mask_only = sorted(mask_names - normalised)
        decoded.text_only = sorted(normalised - mask_names)
        decoded.inconsistent_with_text = bool(decoded.mask_only or decoded.text_only)

    return decoded


#: ELLE takma ad -- YALNIZCA mekanik eslesmenin cozemedigi adlar (Gorev 20).
#:
#: Eskiden burasi dokuz girdiydi ve hepsi registry/standart adlardan
#: secilmisti (ilk vaka registry'ydi). Olculdu: 22 Windows goruntu adinin
#: 9'u cozuluyordu (%40) ve KACANLARIN 7'SI YAZMA idi -- dosya ailesi 0/7,
#: surec ailesi 0/4. Tabloyu elle yirmi ikiye cikarmak ayni kusuru bir
#: sonraki ada ertelerdi; bag artik `_bit_for_text` ile TURETILIYOR.
#:
#: Burada kalanlar, jeton kumesi kuralinin cozemedigi adlar. Bir ad buraya
#: ancak mekanik kural onu cozemedigi GOSTERILEREK girer.
_ACCESS_ALIASES = {
    # {notify, about, changes, to, keys} ile KEY_NOTIFY {key, notify}
    # arasinda ne esitlik ne alt kume iliskisi var.
    "notifyaboutchangestokeys": "keynotify",
}


def _normalise_access(name: str) -> str:
    key = re.sub(r"[\s_-]+", "", str(name)).strip().lower()
    return _ACCESS_ALIASES.get(key, key)


#: `Accesses` degerini ogelere bolen ayraclar (Gorev 20).
#: TEK BOSLUKTAN BOLUNMEZ -- adlarin kendisi tek bosluk iceriyor
#: ("Set key value"). Gercek QRadar satirlari ogeleri COKLU BOSLUKLA
#: paketliyor; ayni degismez Gorev 15'te de kullanilmisti (K-C):
#: "2+ ardisik bosluk ayractir, o yuzden adin icinde olamaz".
_ACCESS_SPLIT = re.compile(r"\||,|;|\r|\n|[ \t]{2,}")


def _access_items(access_text: list[str] | str | None) -> list[str]:
    if not access_text:
        return []
    ham = [access_text] if isinstance(access_text, str) else list(access_text)
    ogeler: list[str] = []
    for parca in ham:
        for oge in _ACCESS_SPLIT.split(str(parca)):
            oge = oge.strip()
            if oge:
                ogeler.append(oge)
    return ogeler


def _tokens(name: str) -> frozenset[str]:
    """Adi jeton kumesine cevirir.

    - Parantezli ve egik cizgili ALTERNATIFLER ilk secenege indirgenir:
      Windows "ReadData (or ListDirectory)" ve "Execute/Traverse" yazar --
      ayni bit, farkli nesne turunde farkli ad.
    - camelCase bolunur ("DeleteChild" -> delete, child).
    """
    metin = str(name)
    metin = re.sub(r"\(.*?\)", " ", metin)      # "(or ListDirectory)"
    metin = metin.split("/")[0]                  # "Execute/Traverse"
    metin = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", metin)   # camelCase
    parcalar = re.split(r"[\s_\-]+", metin)
    return frozenset(p.lower() for p in parcalar if p)


def _bit_for_text(ad: str, table: dict[str, dict[str, str]]) -> dict[str, str] | None:
    """Goruntu adini bit tablosundaki girdiye baglar -- TURETEREK (Gorev 20).

    Kural, ve SIRASI zorunlu:
      1. tam jeton kumesi esitligi; tek aday varsa o
      2. yoksa alt kume; tek aday varsa o
      3. birden fazla aday varsa COZULMEZ

    1'in 2'den once gelmesi sart: "DELETE" hem DELETE ile (esitlik) hem
    FILE_DELETE_CHILD ile (alt kume) eslesir. Esitlik once sorulmazsa
    belirsiz kalir.

    3 numarali kural bilerek boyle: belirsizken bir sinif SECMEK, uydurmak
    demektir. Uydurulmus bir sinif, olmayan bir siniftan kotudur -- cunku
    sessizce dogru gorunur."""
    elle = _ACCESS_ALIASES.get(re.sub(r"[\s_-]+", "", str(ad)).strip().lower())
    if elle:
        for spec in table.values():
            if _normalise_access(spec["ad"]) == elle:
                return spec

    jetonlar = _tokens(ad)
    if not jetonlar:
        return None

    esit = [spec for spec in table.values() if _tokens(spec["ad"]) == jetonlar]
    if len(esit) == 1:
        return esit[0]

    alt = [spec for spec in table.values() if jetonlar < _tokens(spec["ad"])]
    if len(alt) == 1:
        return alt[0]
    return None


def _classes_from_text(
    access_text: list[str] | str | None,
    table: dict[str, dict[str, str]],
) -> tuple[list[str], set[str], list[str]]:
    """`Accesses` metnindeki adlari BIT TABLOSUNDAN siniflandirir.

    Dondurur: (bit adlari, siniflar, COZULEMEYEN adlar).

    Ucuncu deger Gorev 20'de eklendi ve sessizligi bitiriyor: taninmayan bir
    ad eskiden atlaniyordu ve sinif olayin varsayilanina (4663 icin `read`)
    dusuyordu. Olculdu: kritik anahtara "Create link" yazan bir kayit
    INSUFFICIENT_DATA aliyordu -- Gorev 19'un kapattigi kacan alarm, baska
    bir yazimla. Artik cozulemeyen ad RAPORLANIR ve karar katmani onu
    `unknown` olarak gorur (Gorev 4: unknown != noise)."""
    bitler: list[str] = []
    siniflar: set[str] = set()
    cozulemeyen: list[str] = []
    for oge in _access_items(access_text):
        spec = _bit_for_text(oge, table)
        if spec:
            bitler.append(spec["ad"])
            siniflar.add(spec["sinif"])
        else:
            cozulemeyen.append(oge)
    return sorted(set(bitler)), siniflar, cozulemeyen


def describe(event_id: str | None, mask: str | None, object_type: str | None = None,
             access_text: list[str] | str | None = None) -> dict[str, Any]:
    """Olay + maske anlambiliminin birlesik ozeti.

    Islem sinifi celisirse MASKE kazanir: olay turu genel bir beyandir,
    maske ise o KAYDA ozel gercek haktir.

    AMA YALNIZCA GERCEKLESMIS OLAYLARDA (Gorev 18). `erisim_gerceklesti:
    false` tasiyan bir olayda -- katalogda tek ornek 4656 -- maske
    gerceklesen erisimi degil TALEP EDILEN hakki anlatir. 0x2001F "yazma
    hakki ISTEDI" der, "yazdi" demez; gerceklesen erisim 4663'tur. Orada
    maske sinifi YUKSELTMEZ, `requested_class` olarak ayrica raporlanir --
    bilgi kaybolmuyor, yalnizca karara girdigi sifat degisiyor.

    Bu ayrim olmadan Yol B (kritiklik + yazma erisimi) her handle
    TALEBINDE atesliyordu; olculdu: docs/sonuc_13_s_kolu.md §3, uc ayri
    kritik anahtarda tutarli."""
    semantics = event_semantics(event_id) or {}
    decoded = decode_access_mask(mask, object_type, access_text)

    event_class = semantics.get("islem_sinifi")
    mask_class = decoded.access_class if decoded else None
    gerceklesti = semantics.get("erisim_gerceklesti", True)

    access_class = (mask_class or event_class) if gerceklesti else event_class
    requested_class = None if gerceklesti else mask_class

    return {
        "event_id": event_id,
        "meaning": semantics.get("anlam"),
        "event_class": event_class,
        "mask_class": mask_class,
        "access_realized": bool(gerceklesti),
        "requested_class": requested_class,
        "access_class": access_class,
        "class_conflict": bool(gerceklesti and mask_class and event_class
                               and mask_class != event_class),
        "data_components": semantics.get("veri_bileseni") or [],
        "meaningful_fields": semantics.get("anlamli_alanlar") or [],
        "access_class_source": (decoded.source if decoded else None),
        "unresolved_access_names": (decoded.unresolved if decoded else []),
        "mask_bits": decoded.bits if decoded else [],
        "mask_inconsistent_with_text": bool(decoded and decoded.inconsistent_with_text),
        "mask_only_bits": decoded.mask_only if decoded else [],
        "note": semantics.get("not"),
    }
