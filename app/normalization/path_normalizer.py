"""Registry yolu normalizasyonu -- log dili ile ATT&CK dilini bulusturur.

NEDEN VAR (olculdu 2026-08-16, 697 canli teknik)
    ATT&CK metinleri : HKLM/HKCU 247 gecis · HKEY_ 121 · \\REGISTRY\\ = 1
    Windows loglari  : \\REGISTRY\\MACHINE\\...  (4656/4657'nin tek bicimi)

    Iki taraf neredeyse hic ayni gosterimi kullanmiyor; ham string
    karsilastirmasi bu yuzden calisamaz.

ZATEN BIR KEZ ISIRDI
    T1003.002 kurali 'HKLM\\SAM' ariyor, log '\\REGISTRY\\MACHINE\\SAM'
    yaziyor. Kural, kapsadigini beyan ettigi 4656 olayinda hicbir zaman
    eslesemiyor -- known_regression'da kayitli.

KAPSAM: bu modul T3/T1685'i COZMEZ. T1685'in metninde HKLM yalin geciyor,
ardinda yol yok. Bayrak vakasi T1003.002'dir.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CONFIG_FILE = Path(__file__).resolve().parents[2] / "config" / "path_normalization.yaml"


@lru_cache(maxsize=1)
def _config() -> dict[str, Any]:
    return yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _alias_table() -> list[tuple[re.Pattern, str]]:
    """(desen, canonical) ciftleri -- UZUN alias once.

    Sira onemli: 'HKEY_LOCAL_MACHINE' once denenmezse 'HKLM' zaten
    canonical oldugu icin eslesme kacabilir; ayrica '\\REGISTRY\\MACHINE'
    ile 'REGISTRY\\MACHINE' ic ice gecer."""
    pairs: list[tuple[str, str]] = []
    for entry in _config().get("hive_aliases", []):
        canonical = entry["canonical"]
        for alias in entry.get("aliases", []):
            pairs.append((alias, canonical))
        pairs.append((canonical, canonical))

    pairs.sort(key=lambda p: -len(p[0]))
    return [
        (re.compile(r"(?<![\w\\])" + re.escape(alias), re.IGNORECASE), canonical)
        for alias, canonical in pairs
    ]


def normalize_registry_path(value: str | None) -> str | None:
    """Bir registry yolunu karsilastirilabilir tek bicime cevirir.

        \\REGISTRY\\MACHINE\\SAM            -> HKLM\\SAM
        HKEY_LOCAL_MACHINE\\Software\\Foo   -> HKLM\\SOFTWARE\\FOO
        HKLM/Software/Foo                  -> HKLM\\SOFTWARE\\FOO

    None/bos girdi None doner -- 'bilinmiyor' ile 'bos yol' ayni sey degil."""
    if not value or not str(value).strip():
        return None

    cfg = _config()
    text = str(value).strip()

    if cfg.get("separators", {}).get("slash_to_backslash", True):
        text = text.replace("/", "\\")
    if cfg.get("separators", {}).get("collapse_backslashes", True):
        text = re.sub(r"\\{2,}", "\\\\", text)

    for pattern, canonical in _alias_table():
        new_text, n = pattern.subn(canonical, text, count=1)
        if n:
            text = new_text
            break

    if cfg.get("separators", {}).get("strip_edges", True):
        text = text.strip("\\ ")

    # SEGMENT esdegerlikleri ve GURULTU segmentleri -- ikisi de config'ten.
    # Kod hangi segmentin gurultu oldugunu BILMEZ; tabloyu okur.
    segmentler = [s for s in text.split("\\") if s]
    for kural in cfg.get("segment_aliases") or []:
        desen = re.compile(rf"^{kural['pattern']}$", re.IGNORECASE)
        segmentler = [
            kural["canonical"] if desen.match(s) else s for s in segmentler
        ]
    gurultu = {str(s).casefold() for s in (cfg.get("noise_segments") or [])}
    if gurultu:
        segmentler = [s for s in segmentler if s.casefold() not in gurultu]
    text = "\\".join(segmentler)

    if cfg.get("case_insensitive", True):
        text = text.upper()

    return text or None


def _is_bare_hive(normalized: str) -> bool:
    """Normalize edilmis deger yalnizca kovan koku mu ('HKLM', 'HKCU')?"""
    return "\\" not in normalized


def paths_match(left: str | None, right: str | None) -> bool:
    """Iki yol AYNI registry konumunu mu gosteriyor?

    Bir taraf digerinin ONEKI ise de eslesir: ATT&CK metinleri cogu zaman
    kovan + birkac segment yazar ('HKLM\\SAM'), log ise tam yolu
    ('\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains'). Daha genel olan yolun daha
    ozel olani kapsamasi dogru davranistir.

    Onek karsilastirmasi SEGMENT sinirinda yapilir: 'HKLM\\SAMPLE' yolu
    'HKLM\\SAM' ile eslesmemeli."""
    a, b = normalize_registry_path(left), normalize_registry_path(right)
    if not a or not b:
        return False

    # YALIN KOVAN KOKU ESLESME URETMEZ.
    #
    # "HKLM" tek basina butun yerel makine kovanidir; her HKLM yoluyla
    # eslesir. Teknik olarak dogru, pratikte kullanissiz -- ayirt edici
    # hicbir bilgi tasimaz ve kabul edilirse T1685 gibi metninde yalnizca
    # yalin "HKLM" gecen bir teknik HER registry loguyla eslesir. Hic
    # eslesmemekten kotudur.
    if _is_bare_hive(a) or _is_bare_hive(b):
        return False

    if a == b:
        return True

    shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
    return longer.startswith(shorter + "\\")


def looks_like_registry_path(value: str | None) -> bool:
    """Bu deger bir registry yolu mu? (yol olmayan alanlari normalize
    etmeye calismamak icin)"""
    if not value:
        return False
    text = str(value).strip().upper().replace("/", "\\")
    return bool(re.match(r"^(\\*REGISTRY\\|HK(LM|CU|CR|U|CC)\b|HKEY_)", text))
