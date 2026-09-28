"""Toplu analiz sonucunu diske yazar.

Neden gerekli: toplu analiz, satir basina ~25 saniye suren yerel LLM cagrilari
yapiyor. Sonuc yalnizca st.session_state'e konursa, tarayici websocket
baglantisi kopan bir kosuda dakikalarca suren butun is cope gidiyor (bkz.
.streamlit/config.toml -> disconnectedSessionTTL). Sonucu hesaplanir
hesaplanmaz diske yazmak bu bagimliligi kaldiriyor: baglanti olse bile dosya
duruyor ve arayuzdeki "onceden hesaplanmis sonucu yukle" akisiyla geri
alinabiliyor.

Bicim, scripts/run_bulk_analysis.py'nin urettigi dosyayla AYNI (json.dumps
default=str) -- boylece iki yoldan uretilen sonuclar ayni yukleyiciyle
okunabiliyor (bkz. app/ui/bulk_view.py -> _parse_precomputed_result).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "bulk_results"


def save_bulk_result(result: dict[str, Any], directory: Path = RESULTS_DIR) -> Path:
    """Sonucu zaman damgali bir dosyaya yazip yolunu dondurur."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"bulk_{datetime.now():%Y%m%d_%H%M%S}.json"
    path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return path
