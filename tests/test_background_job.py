from __future__ import annotations

import time

from app.batch import background_job


def _wait_for(job, status, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if job.status == status:
            return True
        time.sleep(0.02)
    return False


def test_job_runs_in_background_and_reports_result(monkeypatch, tmp_path):
    monkeypatch.setattr(
        background_job, "run_bulk_analysis",
        lambda rows, system_choice, on_progress=None: {"items": rows, "incidents": []},
    )
    monkeypatch.setattr(background_job, "save_bulk_result", lambda result: tmp_path / "bulk.json")

    job_id = background_job.start_bulk_job([{"a": 1}], "Gelistirilmis", total=1)
    job = background_job.get_job(job_id)

    assert _wait_for(job, "done")
    assert job.result == {"items": [{"a": 1}], "incidents": []}
    assert job.saved_path.endswith("bulk.json")


def test_start_returns_immediately_without_waiting_for_work(monkeypatch, tmp_path):
    """Asil kazanc bu: baslatan taraf (Streamlit script kosumu) bloke olmuyor,
    dolayisiyla analiz artik tarayici baglantisinin yasamasina bagli degil."""
    def slow_run(rows, system_choice, on_progress=None):
        time.sleep(0.5)
        return {"items": [], "incidents": []}

    monkeypatch.setattr(background_job, "run_bulk_analysis", slow_run)
    monkeypatch.setattr(background_job, "save_bulk_result", lambda result: tmp_path / "bulk.json")

    started = time.time()
    job_id = background_job.start_bulk_job([], "Gelistirilmis", total=0)
    elapsed = time.time() - started

    assert elapsed < 0.2
    assert background_job.get_job(job_id).status == "running"


def test_progress_is_readable_while_running(monkeypatch, tmp_path):
    release = {"go": False}

    def run_with_progress(rows, system_choice, on_progress=None):
        on_progress(3, 10, "analiz")
        while not release["go"]:
            time.sleep(0.01)
        return {"items": [], "incidents": []}

    monkeypatch.setattr(background_job, "run_bulk_analysis", run_with_progress)
    monkeypatch.setattr(background_job, "save_bulk_result", lambda result: tmp_path / "bulk.json")

    job = background_job.get_job(background_job.start_bulk_job([], "Gelistirilmis", total=10))

    deadline = time.time() + 5
    while job.current == 0 and time.time() < deadline:
        time.sleep(0.02)

    assert (job.current, job.total, job.phase) == (3, 10, "analiz")
    release["go"] = True
    assert _wait_for(job, "done")


def test_unexpected_failure_is_reported_not_swallowed(monkeypatch):
    def boom(rows, system_choice, on_progress=None):
        raise RuntimeError("dosya bozuk")

    monkeypatch.setattr(background_job, "run_bulk_analysis", boom)

    job = background_job.get_job(background_job.start_bulk_job([], "Gelistirilmis", total=0))

    assert _wait_for(job, "error")
    assert job.error == "dosya bozuk"
    assert job.result is None


def test_save_failure_does_not_lose_the_result(monkeypatch):
    """Diske yazamamak analizi gecersiz kilmaz -- sonuc yine de teslim edilir."""
    monkeypatch.setattr(
        background_job, "run_bulk_analysis",
        lambda rows, system_choice, on_progress=None: {"items": [], "incidents": []},
    )

    def failing_save(result):
        raise OSError("disk dolu")

    monkeypatch.setattr(background_job, "save_bulk_result", failing_save)

    job = background_job.get_job(background_job.start_bulk_job([], "Gelistirilmis", total=0))

    assert _wait_for(job, "done")
    assert job.result == {"items": [], "incidents": []}
    assert job.save_error == "disk dolu"
    assert job.saved_path is None


def test_status_becomes_done_only_after_result_is_set(monkeypatch, tmp_path):
    """Arayuz 'done' gorunce sonucu okuyor; sonuc yazilmadan status
    degisirse arayuz None sonucu devralirdi."""
    monkeypatch.setattr(
        background_job, "run_bulk_analysis",
        lambda rows, system_choice, on_progress=None: {"items": [], "incidents": []},
    )
    monkeypatch.setattr(background_job, "save_bulk_result", lambda result: tmp_path / "bulk.json")

    job = background_job.get_job(background_job.start_bulk_job([], "Gelistirilmis", total=0))
    assert _wait_for(job, "done")
    assert job.result is not None


def test_get_job_returns_none_for_unknown_id():
    assert background_job.get_job(None) is None
    assert background_job.get_job("yok-boyle-bir-is") is None
