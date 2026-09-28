"""Toplu analizi tarayici oturumundan BAGIMSIZ bir arka plan is'i olarak calistirir.

Cozdugu sorun: toplu analiz eskiden dogrudan Streamlit'in script kosumu icinde
calisiyordu. Streamlit bir script kosumunu tarayici baglantisina bagli tutar --
kullanici sekmeyi arka plana alinca, makine uyuyunca ya da websocket koptugunda
kosum iptal ediliyor ve dakikalarca suren is cope gidiyordu. Terminaldeki
"Error sending websocket payload / Unexpected ASGI message 'websocket.send'"
hatasi bunun gorunen yuzuydu.

Cozum: isi ayri bir thread'e almak. Thread, Streamlit'in oturum yasam
dongusune bagli degil -- baglanti kopsa da, kullanici baska sekmeye gecse de
calismaya devam eder. Arayuz yalnizca ilerlemeyi OKUR (bkz. app/ui/bulk_view.py,
st.fragment(run_every=...) ile periyodik yenilenen ilerleme cubugu).

Iki kural:
  1. Thread icinde st.* CAGRILMAZ. Streamlit API'leri kosum baglamina (script
     run context) bagli; arka plan thread'inde cagirmak ya uyari uretir ya da
     sessizce hicbir sey yapmaz. Thread sadece duz veri yapisi gunceller.
  2. Is kaydi (registry) modul duzeyinde tutulur, st.session_state'te DEGIL.
     Oturum, baglanti koptuktan bir sure sonra temizlenebiliyor (bkz.
     .streamlit/config.toml -> disconnectedSessionTTL); modul duzeyi kayit
     sunucu sureci yasadigi surece durur, dolayisiyla kullanici geri
     dondugunde is hala oradadir.

Sinir: is, Streamlit sunucu SURECINE bagli. Sunucu yeniden baslarsa (Ctrl+C,
kod degisikligiyle otomatik reload) is de olur. Bunu tolere edilemez buldugun
durumda tamamen ayri bir surec olan scripts/run_bulk_analysis.py kullanilmali.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.batch.orchestrator import run_bulk_analysis
from app.batch.result_store import save_bulk_result


@dataclass
class BulkJob:
    """Arka plan isinin disaridan okunabilir durumu.

    Alanlar thread tarafindan yazilip arayuz tarafindan okunuyor. Python'da
    tekil alan atamalari zaten atomik oldugu icin okuma tarafi kilit
    gerektirmiyor; kilit yalnizca kaydin kendisini (sozluk) korumak icin var.
    """

    id: str
    total: int
    current: int = 0
    phase: str = "analiz"
    status: str = "running"  # running | done | error
    result: dict[str, Any] | None = None
    error: str | None = None
    saved_path: str | None = None
    save_error: str | None = None


_jobs: dict[str, BulkJob] = {}
_lock = threading.Lock()


def start_bulk_job(rows: list[dict[str, Any]], system_choice: str, total: int) -> str:
    """Isi baslatir ve is kimligini dondurur. Cagiran taraf bloke olmaz."""
    job = BulkJob(id=uuid.uuid4().hex[:8], total=total)
    with _lock:
        _jobs[job.id] = job

    thread = threading.Thread(target=_run, args=(job, rows, system_choice), daemon=True)
    thread.start()
    return job.id


def get_job(job_id: str | None) -> BulkJob | None:
    if not job_id:
        return None
    with _lock:
        return _jobs.get(job_id)


def _run(job: BulkJob, rows: list[dict[str, Any]], system_choice: str) -> None:
    def on_progress(current: int, total: int, phase: str) -> None:
        job.current = current
        job.total = total
        job.phase = phase

    try:
        result = run_bulk_analysis(rows, system_choice, on_progress=on_progress)
    except Exception as e:
        # orchestrator satir bazinda hatalari zaten izole ediyor; buraya gelen
        # bir hata beklenmedik bir seydir. Thread'in sessizce olmesi yerine
        # durumu isaretliyoruz ki arayuz kullaniciya soyleyebilsin.
        job.error = str(e)
        job.status = "error"
        return

    # Diske yazma, session'a koymadan once: is bitiminde tarayici baglantisi
    # kopmus olabilir, ama dosya baglantidan bagimsiz olarak durur.
    try:
        job.saved_path = str(save_bulk_result(result))
    except OSError as e:
        job.save_error = str(e)

    job.result = result
    job.status = "done"  # en son: arayuz bunu gorunce sonucu okumaya baslar
