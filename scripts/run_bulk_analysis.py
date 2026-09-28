"""Toplu (CSV/JSON) analizi Streamlit disinda, terminalden calistirmak icin.

Neden: app/ui/bulk_view.py uzerinden calistirilan toplu analiz, tum satirlar
bitene kadar tek bir Streamlit tarayici oturumuna bagli kalıyor. Cok satirli
dosyalarda (satir basina LLM cagrisi + olasi retry'lar) toplam sure kolayca
onlarca dakikayi/saatleri bulabiliyor; bu sure boyunca WebSocket baglantisi
herhangi bir nedenle kesilirse (ag, guvenlik yazilimi, uzun bosta kalma...)
Streamlit "baglanti koptu" uyarisi verip calismayi yarida birakiyor ve o ana
kadarki sonuclar da kayboluyor (sonuc ancak islem TAMAMEN bitince
st.session_state'e yaziliyor).

Bu script ayni app/batch/orchestrator.py::run_bulk_analysis fonksiyonunu
dogrudan, tarayiciya bagli olmadan calistirir; ilerlemeyi terminale basar ve
sonucu (Streamlit'ten bagimsiz sekilde) bir JSON dosyasina yazar. Boylece uzun
toplu analizler tarayici/ag durumundan etkilenmez."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.batch.orchestrator import run_bulk_analysis
from app.batch.qradar_adapter import try_convert_qradar_export
from app.batch.serialize import parse_csv_rows, parse_json_rows


def _load_rows(path: Path) -> list[dict]:
    file_bytes = path.read_bytes()
    if path.suffix.lower() == ".csv":
        qradar_rows = try_convert_qradar_export(file_bytes)
        if qradar_rows is not None:
            print(f"QRadar ham export formati algilandi ({len(qradar_rows)} satir)")
            return qradar_rows
        return parse_csv_rows(file_bytes)
    return parse_json_rows(file_bytes)


def _on_progress(i: int, n: int, phase: str) -> None:
    label = "yeniden deneme" if phase == "yeniden_deneme" else "analiz"
    print(f"[{label}] {i}/{n}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="CSV veya JSON dosya yolu")
    parser.add_argument(
        "--system", choices=["baseline", "improved"], default="improved",
        help="Kullanilacak pipeline (varsayilan: improved)",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Sonuc JSON dosyasi (varsayilan: <input>.result.json)",
    )
    args = parser.parse_args()

    system_choice = "Gelistirilmis" if args.system == "improved" else "Baseline"
    out_path = args.out or args.input.with_suffix(".result.json")

    rows = _load_rows(args.input)
    print(f"{len(rows)} satir okundu, sistem={system_choice}")

    result = run_bulk_analysis(rows, system_choice, on_progress=_on_progress)

    out_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print(f"\n{len(result['items'])} satir islendi, {len(result['incidents'])} incident bulundu.")
    print(f"Sonuc yazildi: {out_path}")


if __name__ == "__main__":
    main()
