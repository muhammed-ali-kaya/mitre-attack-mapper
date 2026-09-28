"""Baseline RAG pipeline'ini komut satirindan test etmek icin."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.retrieval.baseline_pipeline import run_baseline_query


def main() -> None:
    query = " ".join(sys.argv[1:]) or (
        "EventID=4688 NewProcessName=C:\\Windows\\System32\\schtasks.exe "
        "CommandLine=schtasks /create /s 10.10.20.15 /tn UpdateCheck /tr powershell.exe /sc onlogon "
        "SubjectUserName=service.admin"
    )
    print(f"Girdi: {query}\n")
    result = run_baseline_query(query)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
