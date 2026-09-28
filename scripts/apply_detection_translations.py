"""Elle yazilmis cevirileri data/translations/detection_tr.json icine isler.

Girdi, {attack_id: "<Turkce metin>"} seklinde bir JSON dosyasi. Ceviriler
partiler halinde yazildigi icin bu adim ayri: iskeleti build_detection_
translations.py uretir, ceviri elle doldurulur, bu script de dogrulayip yerine
koyar.

Dogrulama -- neden gerekli: MITRE'nin detection metinlerinin cogu TEK BIR ALAN
icinde satir satir farkli platformlari anlatiyor (Windows / Linux / macOS /
ESXi / ag cihazi). Ceviri sirasinda bir satiri atlamak ya da birlestirmek, o
platformun tespit onerisini sessizce yok etmek demek. Satir sayisi kontrolu bu
hatayi yakalar; ayni mantik LLM cevirisinde de var (bkz. app/llm/translator.py
-- uzunluk uyusmazsa ceviri tumden reddediliyor).

Kullanim:
    python scripts/apply_detection_translations.py <ceviri_dosyasi.json>
    python scripts/apply_detection_translations.py <dosya.json> --force
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.llm.detection_translations import TRANSLATIONS_PATH  # noqa: E402


def validate(attack_id: str, english: str, turkish: str) -> list[str]:
    problems = []

    en_lines = english.strip().count("\n") + 1
    tr_lines = turkish.strip().count("\n") + 1
    if en_lines != tr_lines:
        problems.append(f"{attack_id}: satir sayisi uyusmuyor (en={en_lines}, tr={tr_lines})")

    if not turkish.strip():
        problems.append(f"{attack_id}: ceviri bos")

    # Cevrilmemis birakilmis olmasi gereken ATT&CK/komut adlari icin kaba bir
    # uyari: Ingilizce metinde backtick icinde gecen komutlar ceviride de aynen
    # gecmeli. Sessiz bir "esxcli -> esxcli agi" bozulmasini yakalar.
    for token in _backtick_tokens(english):
        if token not in turkish:
            problems.append(f"{attack_id}: '{token}' ceviride bulunamadi (cevrilmis olabilir)")

    return problems


def _backtick_tokens(text: str) -> list[str]:
    parts = text.split("`")
    # tek indisliler backtick ICI: `show arp` -> ["...", "show arp", "..."]
    return [p for i, p in enumerate(parts) if i % 2 == 1 and p.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("translations_file", help="{attack_id: turkce_metin} JSON dosyasi")
    parser.add_argument("--force", action="store_true", help="uyarilara ragmen yaz")
    args = parser.parse_args()

    incoming = json.loads(Path(args.translations_file).read_text(encoding="utf-8"))
    document = json.loads(TRANSLATIONS_PATH.read_text(encoding="utf-8"))
    entries = document["entries"]

    problems: list[str] = []
    applied = 0
    for attack_id, turkish in incoming.items():
        entry = entries.get(attack_id)
        if entry is None:
            problems.append(f"{attack_id}: iskelette yok (once build_detection_translations.py calistirin)")
            continue
        problems.extend(validate(attack_id, entry["en"], turkish))
        entry["tr"] = turkish
        entry.pop("bayat", None)
        applied += 1

    if problems:
        print("UYARILAR:")
        for problem in problems:
            print(f"  - {problem}")
        if not args.force:
            print("\nHicbir sey yazilmadi. Duzeltip tekrar calistirin ya da --force kullanin.")
            sys.exit(1)

    document["entries"] = dict(sorted(entries.items()))
    TRANSLATIONS_PATH.write_text(
        json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    translated = sum(1 for e in entries.values() if e.get("tr"))
    print(f"Islenen: {applied}")
    print(f"Dosyadaki toplam kayit: {len(entries)}, cevrilmis: {translated}")


if __name__ == "__main__":
    main()
