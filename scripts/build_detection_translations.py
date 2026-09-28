"""data/translations/detection_tr.json dosyasini olusturur/gunceller.

Bu dosya, MITRE'nin resmi detection metinlerinin elle hazirlanmis Turkce
karsiliklarini tutar (gerekce icin bkz. app/llm/detection_translations.py).
Script cevirinin KENDISINI yapmaz -- cevrilecek metinleri "tr": "" olarak
iskelete ekler, ceviri elle doldurulur. Mevcut ceviriler korunur.

Neden hepsini birden degil: 697 teknigin detection metni toplam ~437 bin
karakter. Demoda ve test setinde gercekten ekrana gelen teknikler bunun kucuk
bir alt kumesi, o yuzden varsayilan mod yalnizca onlari hedefler. Dosyada
olmayan teknikler icin sistem LLM cevirisine geri duser, yani eksik kayit
bozulma degil sadece daha yavas/degisken ceviri demek.

Kullanim:
    python scripts/build_detection_translations.py            # test seti + eval ciktisi
    python scripts/build_detection_translations.py --all      # butun teknikler
    python scripts/build_detection_translations.py --ids T1053.005 T1078
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.ingestion.attack_version import attack_version  # noqa: E402
from app.llm.detection_translations import TRANSLATIONS_PATH  # noqa: E402
from app.validation.validator import AttackKnowledgeBase  # noqa: E402

ATTACK_VERSION = attack_version()  # data/metadata'dan; sabit degil
SCENARIOS_PATH = PROJECT_ROOT / "evaluation" / "test_scenarios.json"
EVAL_RESULTS_PATH = PROJECT_ROOT / "evaluation" / "results" / "eval_improved.jsonl"


def demo_relevant_ids() -> set[str]:
    """Test setinin bekledigi + sistemin gercekten urettigi teknikler.

    Ikisinin birlesimi: beklenen teknikler demonun 'dogru cevap' tarafi,
    uretilen teknikler ise ekranda GERCEKTEN gorunen sey (sistem yanlis bir
    teknik dondurse bile onun detection metni render ediliyor)."""
    ids: set[str] = set()

    scenarios = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
    for scenario in scenarios:
        ids.update(scenario.get("expected_attack_ids") or [])
        ids.update(scenario.get("acceptable_alternatives") or [])

    if EVAL_RESULTS_PATH.exists():
        for line in EVAL_RESULTS_PATH.open(encoding="utf-8"):
            row = json.loads(line)
            ids.update(row.get("predicted_ids") or [])

    return {i for i in ids if i}


def load_existing(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("entries") or {}


def build(target_ids: set[str], path: Path) -> dict[str, int]:
    kb = AttackKnowledgeBase()
    entries = load_existing(path)
    stats = {"eklendi": 0, "korundu": 0, "bayat": 0, "metni_yok": 0}

    for attack_id in sorted(target_ids):
        technique = kb.by_id.get(attack_id)
        if not technique:
            continue
        english = (technique.get("detection") or "").strip()
        if not english:
            stats["metni_yok"] += 1
            continue

        existing = entries.get(attack_id)
        if existing and existing.get("tr"):
            if existing.get("en", "").strip() == english:
                stats["korundu"] += 1
                continue
            # ATT&CK verisi guncellenmis: kayitli ceviri artik baska bir metne
            # ait. Ceviriyi silmiyoruz (elle emek verilmis), ama yeni Ingilizce
            # metni yaziyoruz -- boylece calisma aninda eslesme kurulamaz ve
            # sistem LLM cevirisine duser; buradaki rapor da elle guncellenmesi
            # gerektigini gosterir.
            entries[attack_id] = {"en": english, "tr": existing["tr"], "bayat": True}
            stats["bayat"] += 1
            continue

        entries[attack_id] = {"en": english, "tr": ""}
        stats["eklendi"] += 1

    payload = {
        "attack_version": ATTACK_VERSION,
        "_aciklama": (
            "MITRE detection metinlerinin elle hazirlanmis Turkce cevirileri. "
            "'tr' bos olan kayitlar calisma aninda yok sayilir ve LLM cevirisine "
            "duser. 'bayat': true olan kayitlarda ATT&CK metni degismistir, ceviri "
            "yeniden gozden gecirilmelidir."
        ),
        "entries": dict(sorted(entries.items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="butun tekniklerin detection metinleri")
    parser.add_argument("--ids", nargs="*", help="yalnizca verilen attack_id'ler")
    args = parser.parse_args()

    if args.ids:
        target_ids = set(args.ids)
    elif args.all:
        target_ids = set(AttackKnowledgeBase().by_id.keys())
    else:
        target_ids = demo_relevant_ids()

    stats = build(target_ids, TRANSLATIONS_PATH)

    entries = load_existing(TRANSLATIONS_PATH)
    translated = sum(1 for e in entries.values() if e.get("tr"))
    print(f"Hedeflenen teknik: {len(target_ids)}")
    print(f"  yeni eklendi (ceviri bekliyor): {stats['eklendi']}")
    print(f"  mevcut ceviri korundu:          {stats['korundu']}")
    print(f"  bayat (ATT&CK metni degismis):  {stats['bayat']}")
    print(f"  detection metni olmayan:        {stats['metni_yok']}")
    print(f"Dosya: {TRANSLATIONS_PATH.relative_to(PROJECT_ROOT)}")
    print(f"  toplam kayit: {len(entries)}, cevrilmis: {translated}")


if __name__ == "__main__":
    main()
