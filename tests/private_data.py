"""Yayina kapali veri: gercek QRadar export'u repoda dagitilmaz.

51 satirlik `qradar_2026-08-06_51rows.csv` ve ondan uretilen
`evaluation/g_arm_qradar_labels.json` GERCEK bir ortamin telemetrisidir
(makine adi, ic ag adresleri, ham Windows Security govdeleri). Kamuya acik
kopyaya hic girmez; ozel calisma kopyasinda durur.

Bu yuzden ona bagli testler veri yoksa ATLANIR, basarisiz OLMAZ -- ve atlama
sessiz degil: sebebi skip mesajinda yazili, yani kamuya acik kopyada
"gecti" diyen bir sayi, olcmedigi seyi olctu sanmiyor.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"
QRADAR_CSV = FIXTURES / "qradar_2026-08-06_51rows.csv"
G_ARM_LABELS = FIXTURES.parent.parent / "evaluation" / "g_arm_qradar_labels.json"

requires_qradar_export = pytest.mark.skipif(
    not QRADAR_CSV.exists(),
    reason=(
        f"gercek QRadar export'u yok ({QRADAR_CSV.name}); "
        "yayin kopyasinda dagitilmaz -- bkz. tests/private_data.py"
    ),
)
