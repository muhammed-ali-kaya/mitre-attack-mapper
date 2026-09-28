"""Uretilen ATT&CK verisi: repoda dagitilmaz, veri hattiyla kurulur.

`data/processed/` ve `data/stix/*.json` `.gitignore`dadir -- STIX bundle'i
indirilip parse edilerek uretilir (README "Veri hattini kurma"). Bu yuzden
TAZE BIR KLONDA yoktur ve ona bagli testler dosya bulunamadi diye duserdi.

Dusmek yerine ATLANIYOR, cunku bu bir kusur degil bir ONKOSUL: veri hattini
kosmamis bir klonun "858 teknik gorunuyor mu" sorusuna verecek cevabi yok.
Atlama sessiz degil -- sebebi skip mesajinda, ne yapilacagi da yazili; yani
yayin kopyasinda "gecti" diyen sayi, olcmedigi seyi olctu sanmiyor.

Ayri modul: [[private_data]] YAYINLANMAYAN veriyi, bu modul URETILEN veriyi
kapsar. Ikisi ayri sebeptir ve ayri kalmalari gerekir -- biri gizlilik, digeri
kurulum.
"""

from __future__ import annotations

from pathlib import Path

import pytest

KOK = Path(__file__).resolve().parent.parent
TEKNIKLER = KOK / "data" / "processed" / "techniques.json"

requires_attack_data = pytest.mark.skipif(
    not TEKNIKLER.exists(),
    reason=(
        "uretilen ATT&CK verisi yok (data/processed/techniques.json); "
        "once `python scripts/download_attack_data.py && "
        "python scripts/parse_stix.py` -- bkz. tests/generated_data.py"
    ),
)
