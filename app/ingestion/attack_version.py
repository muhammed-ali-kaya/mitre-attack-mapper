"""ATT&CK surumu: KODDA SABIT DEGIL, veri kaynaginin ust verisinden okunur.

Neden: pipeline'lar ciktiya `attack_version` yaziyordu ama degeri elle
yazilmis bir sabitti ("19.1"). Veri 19.2'ye tasindiginda sabit ayni kaldi ve
19.2 verisiyle uretilen her kayit "19.1" etiketi tasidi -- etiket, verinin
kendisinden ayrisabiliyordu.

Kaynak `data/metadata/attack_source_metadata.json`: `download_attack_data.py`
yazar, `parse_stix.py` islenen veriye aynen bu alani kopyalar. Dosya repoda
izlenir, dolayisiyla veri hatti kurulmamis bir klonda da mevcuttur.

Sinir: ust veri yeni bir surum icin indirilip `parse_stix.py` henuz
calistirilmadiysa, etiket indirilen surumu gosterir, islenen veriyi degil.
Veri hattinin sirasi (README) bu durumu kisa tutar.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

METADATA_FILE = Path(__file__).resolve().parents[2] / "data" / "metadata" / "attack_source_metadata.json"


@lru_cache(maxsize=1)
def attack_version() -> str:
    """Yerel ATT&CK verisinin surumu (orn. "19.2")."""
    metadata = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
    version = metadata.get("attack_version")
    if not version:
        raise ValueError(f"{METADATA_FILE} icinde attack_version yok")
    return version
