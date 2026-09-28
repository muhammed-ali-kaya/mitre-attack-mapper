"""Varlik kritikligi: bir registry yolu ne kadar kritik? (Gorev 4)

MOTOR TABLOYU OKUR, TABLOYU ICERMEZ. Bu dosyada tek bir registry yolu
yazili degil; hepsi config/asset_criticality.yaml'da veri. Tablo
buyudugunde bu dosya degismez.

LEHCE BAGIMSIZ: eslestirmeden once path_normalizer calisir, yani
    HKLM\\SAM · HKEY_LOCAL_MACHINE\\SAM · \\REGISTRY\\MACHINE\\SAM
ayni sonucu verir. Normalizasyon 2B'de kural motoruna baglandi; burada
YENIDEN YAZILMIYOR, ayni fonksiyon cagriliyor.

ESLESMEYEN YOL -> `unknown`, `noise` DEGIL. Bilinmeyeni zararsiz saymak,
tablonun kapsamadigi her saldiriyi gorunmez yapar; kapsama boslugu sessiz
bir kor noktaya donusur. Gorev 5'e baglayici sonuc: `unknown` tek basina
SUFFICIENT_BENIGN uretemez -- baska kanit yoksa cikti INSUFFICIENT_DATA
olur, yani "zararsiz" degil "bilmiyorum".
"""
from __future__ import annotations

import functools
import pathlib
import re
from dataclasses import dataclass
from typing import Any

import yaml

from app.normalization.path_normalizer import (
    looks_like_registry_path,
    normalize_registry_path,
)

CONFIG_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "config"
    / "asset_criticality.yaml"
)

SEVIYELER = ("critical", "high", "medium", "noise", "unknown")


class CriticalityConfigError(ValueError):
    """Tablo bozuk. Sessizce yok saymiyoruz: eksik bir seviye ya da
    kaynaksiz bir satir, o yolun sessizce yanlis siniflanmasi demek."""


@dataclass(frozen=True)
class Kritiklik:
    seviye: str
    aile: str | None = None
    kaynak: tuple[str, ...] = ()
    eslesen_desen: str | None = None
    #: Yol HIVE ONEKI OLMADAN yazilmisti ve eslesme hive denenerek bulundu.
    #: Gevsek bir eslesmedir; karar katmani (Gorev 5) bunu bilmeli.
    hive_varsayildi: bool = False
    #: Hive'siz eslesmede farkli hive'lar FARKLI seviye verdi. En sert olan
    #: secildi -- eksik cagirmak, fazla cagirmaktan tehlikelidir (unknown !=
    #: noise mantiginin aynisi).
    hive_belirsiz: bool = False

    @property
    def bilinmiyor(self) -> bool:
        return self.seviye == "unknown"


BILINMIYOR = Kritiklik(seviye="unknown")


@functools.lru_cache(maxsize=1)
def _tablo() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ham = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    desenler = ham.get("desenler") or []
    for i, d in enumerate(desenler):
        if d.get("seviye") not in SEVIYELER[:-1]:
            raise CriticalityConfigError(
                f"desen {i}: gecersiz seviye {d.get('seviye')!r} "
                f"(unknown TABLOYA yazilmaz, eslesmeyenin varsayilanidir)"
            )
        if not d.get("kaynak"):
            raise CriticalityConfigError(
                f"desen {i} ({d.get('desen')!r}): kaynak beyan edilmemis. "
                f"Kaynagi 'fixture'da vardi' olan satir kabul edilmez."
            )
    # En UZUN desen once: Services\EventLog, Services'ten spesifiktir.
    desenler = sorted(desenler, key=lambda d: len(d["desen"]), reverse=True)
    return desenler, (ham.get("kapsam_disi") or [])


def _kanonik(value: str) -> str:
    n = normalize_registry_path(value)
    metin = (n or value).replace("/", "\\").rstrip("\\")
    seg = [s for s in metin.split("\\") if s]
    if seg:
        # HKU -> HKCU, ve varsa aradaki SID atilir: HKU\S-1-5-21-...\Software
        # ile HKCU\Software ayni varliktir.
        seg[0] = _HIVE_ESDEGERI.get(seg[0].upper(), seg[0])
        if len(seg) > 1 and _SID_RE.match(seg[1]):
            del seg[1]
    return "\\".join(seg).casefold()


_HIVE_ONEKI = ("hklm\\", "hkcu\\", "hkcr\\", "hku\\", "hkey_", "\\registry\\")
#: Hive'siz yolda denenecek hive'lar. Sirali DEGIL -- hepsi denenir, sonra
#: en sert seviye secilir.
_DENENECEK_HIVELAR = ("HKLM", "HKCU")
#: HKU (HKEY_USERS) ile HKCU AYNI VARLIK SINIFIDIR -- HKU\<SID>\Software\...
#: ile HKCU\Software\... ayni kullanici anahtarina isaret eder, yalnizca
#: hangi kullanici oldugu farkli. VARLIK KRITIKLIGI acisindan fark yok:
#: bir kullanicinin autorun anahtari, hangi kullanici olursa olsun autorun
#: anahtaridir. Bu esdegerlik path_normalizer'a KONMADI -- orada HKU ve HKCU
#: gercekten farkli kovanlardir; ayrim yalnizca KRITIKLIK sorusunda erir.
_HIVE_ESDEGERI = {"HKU": "HKCU"}
_SID_RE = re.compile(r"^S-\d-\d+(-\d+)*$|^\.DEFAULT$", re.IGNORECASE)
_SERTLIK = {"critical": 3, "high": 2, "medium": 1, "noise": 0}


def _duz_eslesme(hedef: str) -> dict | None:
    desenler, _ = _tablo()
    for d in desenler:
        desen = _kanonik(d["desen"])
        if hedef == desen or hedef.startswith(desen + "\\"):
            return d
    return None


def siniflandir(path: str | None) -> Kritiklik:
    """Yolun kritikligi. Eslesme SEGMENT SINIRINDA onek olarak yapilir.

    Segment siniri sart: "HKLM\\SAMPLE" ile "HKLM\\SAM" ayni sey degildir.
    Duz onek karsilastirmasi ikisini esitlerdi.

    HIVE'SIZ YOLLAR (olculdu: ATT&CK metinlerindeki 283 yolun 38'i):
    ATT&CK ayni anahtari iki turlu yaziyor --
        HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
             SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
    Ikincisi hive tasimadigi icin siniflandirilamiyordu. Cozum tabloya
    hive'siz satir eklemek DEGIL -- o tabloyu ikiye katlardi ve her yeni
    satirda tekrarlanirdi. Bunun yerine bilinen hive'lar DENENIR.

    GEVSEME KONTROLLU: yalnizca bilinen bir hive ONEKLENIR, desen
    eslestirmesi aynen kalir. "SOFTWARE\\AcmeCorp\\Run" hicbir hive ile
    eslesmez, cunku eslesen sey son segment degil TAM YOLDUR.

    HKLM vs HKCU AYRIMI dusunulmeden gecilmedi: ayni anahtar makine
    genelinde ve kullanici altinda farkli SEYLERDIR. Tabloda ikisi de
    'autorun-run/high' -- ama bu VARSAYILMIYOR, olculuyor: hive'lar farkli
    seviye verirse `hive_belirsiz` isaretlenir ve EN SERT olan secilir.
    Eksik cagirmak fazla cagirmaktan tehlikelidir (unknown != noise)."""
    if not path:
        return BILINMIYOR

    metin = str(path).strip()
    dusuk = metin.casefold()
    hive_var = dusuk.startswith(_HIVE_ONEKI)

    if hive_var:
        if not looks_like_registry_path(metin):
            return BILINMIYOR
        d = _duz_eslesme(_kanonik(metin))
        if d is None:
            return BILINMIYOR
        return Kritiklik(
            seviye=d["seviye"], aile=d.get("aile"),
            kaynak=tuple(d.get("kaynak") or ()), eslesen_desen=d["desen"],
        )

    # --- hive yok: bilinen hive'lari dene
    if "\\" not in metin:
        return BILINMIYOR
    bulunanlar = []
    for h in _DENENECEK_HIVELAR:
        aday = f"{h}\\{metin.lstrip(chr(92))}"
        if not looks_like_registry_path(aday):
            continue
        d = _duz_eslesme(_kanonik(aday))
        if d is not None:
            bulunanlar.append(d)
    if not bulunanlar:
        return BILINMIYOR

    en_sert = max(bulunanlar, key=lambda d: _SERTLIK[d["seviye"]])
    belirsiz = len({d["seviye"] for d in bulunanlar}) > 1
    return Kritiklik(
        seviye=en_sert["seviye"], aile=en_sert.get("aile"),
        kaynak=tuple(en_sert.get("kaynak") or ()), eslesen_desen=en_sert["desen"],
        hive_varsayildi=True, hive_belirsiz=belirsiz,
    )


def kapsam_disi_mi(path: str | None) -> str | None:
    """Bu yol BILEREK kapsam disi mi? Ise gerekcesini dondurur.

    'Tabloda yok' ile 'tabloya bilerek alinmadi' farkli seylerdir. Ikincisi
    bir KARARDIR ve gerekcesi yazilidir; kapsama raporunda 'gerekcesiz
    unknown' sayilmaz."""
    if not path:
        return None
    hedef = str(path).casefold()
    _, disi = _tablo()
    for k in disi:
        if str(k["desen_izi"]).casefold() in hedef:
            return k["gerekce"]
    return None
