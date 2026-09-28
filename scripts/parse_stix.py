"""STIX bundle'ini parse edip data/processed/techniques.json olarak kaydeder."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.parsers.stix_parser import (
    load_bundle,
    parse_all_mitigations,
    parse_all_tactics,
    parse_all_techniques,
)

STIX_FILE = PROJECT_ROOT / "data" / "stix" / "enterprise-attack.json"
SOURCE_METADATA_FILE = PROJECT_ROOT / "data" / "metadata" / "attack_source_metadata.json"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def main() -> None:
    source_metadata = json.loads(SOURCE_METADATA_FILE.read_text(encoding="utf-8"))
    attack_version = source_metadata["attack_version"]

    objects = load_bundle(STIX_FILE)
    techniques = parse_all_techniques(objects, attack_version)
    tactics = parse_all_tactics(objects, attack_version)
    mitigations = parse_all_mitigations(objects, attack_version)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    (PROCESSED_DIR / "techniques.json").write_text(
        json.dumps(techniques, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (PROCESSED_DIR / "tactics.json").write_text(
        json.dumps(tactics, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (PROCESSED_DIR / "mitigations.json").write_text(
        json.dumps(mitigations, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    n_sub = sum(1 for t in techniques if t["is_subtechnique"])
    n_deprecated = sum(1 for t in techniques if t["deprecated"])
    n_revoked = sum(1 for t in techniques if t["revoked"])
    print(f"Toplam teknik+alt teknik: {len(techniques)}")
    print(f"  Alt teknik: {n_sub}")
    print(f"  Ana teknik: {len(techniques) - n_sub}")
    print(f"  Deprecated: {n_deprecated}, Revoked: {n_revoked}")
    print(f"Taktik sayisi: {len(tactics)}")
    print(f"Mitigation sayisi: {len(mitigations)}")
    print(f"Kaydedildi: {PROCESSED_DIR}")


if __name__ == "__main__":
    main()
