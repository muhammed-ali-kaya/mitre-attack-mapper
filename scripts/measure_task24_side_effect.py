"""Gorev 24 -- sema degisikliginin 126 kayitlik yan etkisi. Gerilemede exit 1.

TABAN CIZGISI GIT'TEN OKUNUR (`git show HEAD:config/field_schema.yaml`), elle
kopyalanmis bir "onceki sema" tutulmaz: kopya bayatlar ve bayat bir taban
cizgisi, olculen farki degisikligin degil kopyanin yasina baglar.

OLCUTLER (docs/beklenti_24_sema_alan_boslugu.md §6c, §9c)
    Ö3   `CommandLine=` tasiyan mevcut girdilerde DEGERLER degismez.
    Ö15  126 kayitta (G+S+H) ayristirma cikti kumesi Ö3 disinda degismez.

LLM ve indeks GEREKMEZ.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.batch.qradar_adapter import try_convert_qradar_export  # noqa: E402
from app.batch.serialize import row_to_kv_string  # noqa: E402
from app.normalization import formats  # noqa: E402
from app.normalization.formats import load_schema, parse_fields  # noqa: E402

G_CSV = KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"
S_SET = KOK / "evaluation" / "s_arm_set.json"
H_SET = KOK / "evaluation" / "heldout_set.json"
CIKTI = KOK / "evaluation" / "results" / "task24_side_effect.json"


def _sema_kur(ham: dict[str, Any]) -> dict[str, Any]:
    alias: dict[str, str] = {}
    for kanonik, spec in (ham.get("fields") or {}).items():
        for a in (spec or {}).get("aliases") or []:
            alias[formats._normalise_key(a)] = kanonik
        alias[formats._normalise_key(kanonik)] = kanonik
    return {
        "fields": ham.get("fields") or {},
        "alias_to_canonical": alias,
        "non_informative": {
            str(v).strip().lower() for v in (ham.get("non_informative_values") or [])
        },
    }


def _taban_sema() -> dict[str, Any]:
    ham = subprocess.run(
        ["git", "show", "HEAD:config/field_schema.yaml"],
        cwd=KOK, capture_output=True, text=True, check=True,
    ).stdout
    return _sema_kur(yaml.safe_load(ham))


def _ayristir(metin: str, sema: dict[str, Any]) -> dict[str, str]:
    """ARAC KUSURU 9 (beklenti §5a): `parse_fields(raw, schema)` verilen semayi
    space_kv tokenizasyonuna UYGULAMIYOR -- `extract_pairs` kendi icinde
    `load_schema()` cagiriyor. Sema bu yuzden ONBELLEK degistirilerek
    uygulanir; parametre tek basina sessizce bos olcum uretir."""
    onceki = formats._SCHEMA_CACHE
    formats._SCHEMA_CACHE = sema
    try:
        alanlar, _ = parse_fields(metin, sema)
        return {k: v.text for k, v in alanlar.items()}
    finally:
        formats._SCHEMA_CACHE = onceki


def _set_loglari(yol: Path) -> list[str]:
    ham = json.loads(yol.read_text(encoding="utf-8"))
    kayitlar = ham["kayitlar"] if isinstance(ham, dict) else ham
    loglar = [k["input"] for k in kayitlar if isinstance(k, dict) and k.get("input")]
    beklenen = ham.get("kayit_sayisi") if isinstance(ham, dict) else len(kayitlar)
    if beklenen and len(loglar) != beklenen:
        raise SystemExit(f"{yol.name}: {beklenen} bekleniyordu, {len(loglar)} okundu")
    return loglar


def _korpuslar() -> dict[str, list[str]]:
    rows = try_convert_qradar_export(G_CSV.read_bytes())
    if rows is None:
        raise SystemExit("G korpusu okunamadi")
    return {
        "G": [row_to_kv_string(r) for r in rows],
        "S": _set_loglari(S_SET),
        "H": _set_loglari(H_SET),
    }


def main() -> int:
    taban, yeni = _taban_sema(), load_schema()
    korpuslar = _korpuslar()

    rapor: dict[str, Any] = {}
    ihlal = 0
    toplam = 0
    for ad, loglar in korpuslar.items():
        degisen = []
        for i, metin in enumerate(loglar):
            toplam += 1
            a = _ayristir(metin, taban)
            b = _ayristir(metin, yeni)
            if a == b:
                continue
            eklenen = {k: b[k] for k in b.keys() - a.keys()}
            dusen = {k: a[k] for k in a.keys() - b.keys()}
            oynayan = {
                k: {"onceki": a[k], "yeni": b[k]}
                for k in a.keys() & b.keys() if a[k] != b[k]
            }
            # Ö3/Ö15: EKLENEN alan kabul edilir (kazanc). DUSEN ya da DEGERI
            # OYNAYAN alan IHLALDIR -- mevcut bir okuma bozulmus demektir.
            if dusen or oynayan:
                ihlal += 1
            degisen.append({
                "kayit": i, "eklenen": eklenen,
                "dusen": dusen, "degeri_oynayan": oynayan,
            })
        rapor[ad] = {"kayit": len(loglar), "degisen": len(degisen), "ayrinti": degisen}

    CIKTI.parent.mkdir(parents=True, exist_ok=True)
    CIKTI.write_text(json.dumps(rapor, indent=2, ensure_ascii=False), encoding="utf-8")

    for ad, v in rapor.items():
        print(f"{ad}: {v['degisen']}/{v['kayit']} kayit degisti")
        for d in v["ayrinti"][:5]:
            print(f"   kayit {d['kayit']}: +{list(d['eklenen'])} "
                  f"-{list(d['dusen'])} ~{list(d['degeri_oynayan'])}")

    print(f"\ntoplam {toplam} kayit, IHLAL (dusen/oynayan alan): {ihlal}")
    print(f"Rapor: {CIKTI.relative_to(KOK)}")
    if ihlal:
        print("GERILEME: mevcut bir alan dustu ya da degeri oynadi (Ö3/Ö15).")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
