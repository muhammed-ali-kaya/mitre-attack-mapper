from __future__ import annotations

import json
from datetime import datetime

from app.batch.result_store import save_bulk_result


def test_saves_result_and_returns_path(tmp_path):
    result = {"items": [{"index": 0, "raw_log": "EventID=4688"}], "incidents": []}

    path = save_bulk_result(result, directory=tmp_path)

    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8")) == result


def test_creates_directory_if_missing(tmp_path):
    target = tmp_path / "henuz" / "yok"

    path = save_bulk_result({"items": [], "incidents": []}, directory=target)

    assert path.parent == target


def test_serializes_datetime_fields(tmp_path):
    """Korelasyon alanlari datetime tasiyor; json bunlari kendisi yazamaz.
    scripts/run_bulk_analysis.py ile ayni default=str davranisi olmali ki iki
    yoldan uretilen dosyalar ayni yukleyiciyle okunabilsin."""
    result = {"items": [{"timestamp": datetime(2026, 8, 6, 9, 21, 6)}], "incidents": []}

    path = save_bulk_result(result, directory=tmp_path)

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["items"][0]["timestamp"] == "2026-08-06 09:21:06"


def test_each_save_uses_its_own_file(tmp_path):
    save_bulk_result({"items": [], "incidents": []}, directory=tmp_path)
    save_bulk_result({"items": [], "incidents": []}, directory=tmp_path)

    assert len(list(tmp_path.glob("bulk_*.json"))) >= 1
