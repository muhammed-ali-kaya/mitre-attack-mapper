"""Enterprise ATT&CK STIX 2.1 verisini resmi kaynaktan indirir ve sürüm/hash kaydı tutar.

Doküman gereksinimi (bölüm 6, "ATT&CK Sürüm Yönetimi"):
kullanılan ATT&CK sürümü, indirilme tarihi, STIX dosyasının hash değeri ve kaynak
adresi kayıt altına alınmalıdır.

SÜRÜM AÇIKÇA SEÇİLİR, "EN SON" TAKİP EDİLMEZ
--------------------------------------------
Bu betik eskiden sürümsüz `enterprise-attack.json` adresini çekiyordu. O adres
MITRE'nin o anki en son sürümünü döndürür: 2026-08-05'te 19.2'ye geçti. Yani
veri hattını yeniden çalıştırmak, kimse istemeden bilgi tabanını başka bir
ATT&CK sürümüne taşıyabiliyordu -- üstelik `app/retrieval/*_pipeline.py`
içindeki sürüm sabitleri "19.1" demeye devam ettiği için çıktı YANLIŞ SÜRÜMLE
etiketlenirdi.

Artık sürüm `--version` ile seçilir, seçilmezse `DEFAULT_ATTACK_VERSION`
kullanılır. Varsayılan bilerek "en son" değil, bu deponun ÜRETİMDE ÇALIŞTIĞI
sürümdür: argümansız çalıştırmak mevcut veriyi yeniden üretir, sürüm atlatmaz.
Sürüm yükseltmek bu sabiti kasıtlı olarak değiştirmeyi gerektirir.

İNDİRİLEN DOĞRULANMADAN YAZILMAZ
---------------------------------
Bundle'ın içindeki gerçek `x_mitre_version`, istenen sürümle karşılaştırılır.
Tutmuyorsa hiçbir dosya yazılmaz ve çıkış kodu sıfırdan farklı olur. Eski
davranışta indirilen içerik doğrulamadan ÖNCE üretim dosyasının üzerine
yazılıyordu; yanlış bir indirme, üretim verisini geri dönüşsüz biçimde
değiştirebilirdi.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STIX_DIR = PROJECT_ROOT / "data" / "stix"
METADATA_DIR = PROJECT_ROOT / "data" / "metadata"
STIX_FILE = STIX_DIR / "enterprise-attack.json"
METADATA_FILE = METADATA_DIR / "attack_source_metadata.json"

# Bu deponun uretimde calistigi ATT&CK surumu. Dondurulmus 60 senaryoluk
# benchmark bu surumun bundle'indan uretilmis indekse baglidir; degistirmek
# indeksin yeniden kurulmasini ve benchmark'in yeniden olculmesini gerektirir.
DEFAULT_ATTACK_VERSION = "19.2"

SOURCE_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-{version}.json"
)

# MITRE surumleri "MAJOR.MINOR" bicimindedir (19.1, 19.2, 7.2 ...).
VERSION_PATTERN = re.compile(r"^\d+\.\d+$")


class VersionMismatch(RuntimeError):
    """Indirilen bundle'in surumu istenenle ayni degil."""


def build_source_url(version: str) -> str:
    """Surume gore resmi STIX adresini kurar.

    Surum bicimi burada dogrulanir: yol parcasina dogrudan girdigi icin
    serbest bir dize kabul etmek adresi baska bir dosyaya kaydirabilir.
    """
    if not VERSION_PATTERN.match(version or ""):
        raise ValueError(
            f"Gecersiz ATT&CK surumu: {version!r} -- beklenen bicim 'MAJOR.MINOR' (orn. 19.1)"
        )
    return SOURCE_URL_TEMPLATE.format(version=version)


def resolve_source_url(version: str, env: dict[str, str] | None = None) -> str:
    """Adresi belirler; `ATTACK_STIX_URL` tanimliysa o kazanir.

    Ortam degiskeni destegi korundu (yerel ayna, cevrimdisi kopya), ama
    ATLATMA DEGIL: nereden gelirse gelsin bundle'in surumu yine istenen
    surumle karsilastirilir. Sursuz adresi buraya koyan biri, artik sessizce
    baska bir surume gecmek yerine acik bir hata alir.
    """
    env = os.environ if env is None else env
    override = env.get("ATTACK_STIX_URL")
    if override:
        return override
    return build_source_url(version)


def download_stix(source_url: str) -> bytes:
    response = requests.get(source_url, timeout=60)
    response.raise_for_status()
    return response.content


def extract_attack_version(stix_bundle: dict) -> str | None:
    """STIX bundle icindeki x-mitre-collection nesnesinden ATT&CK surum numarasini cikarir."""
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version")
    return None


def verify_version(requested: str, actual: str | None, source_url: str) -> None:
    """Istenen surumle bundle'in kendi surumunu karsilastirir.

    Surum okunamiyorsa da hata verilir: surumsuz bir bundle'i kaydetmek,
    metadata'nin `attack_version` alanini None yapar ve parse_stix.py o alani
    teknik kayitlarina yaziyor -- sessiz bir bosluk yerine gurultulu bir hata.
    """
    if actual is None:
        raise VersionMismatch(
            f"Bundle icinde x-mitre-collection surumu bulunamadi.\n"
            f"  adres  : {source_url}\n"
            f"  istenen: {requested}\n"
            f"Hicbir dosya yazilmadi."
        )
    if actual != requested:
        raise VersionMismatch(
            f"Surum uyusmazligi -- indirilen bundle istenen surum degil.\n"
            f"  adres   : {source_url}\n"
            f"  istenen : {requested}\n"
            f"  bundle  : {actual}\n"
            f"Hicbir dosya yazilmadi. Surumsuz bir adres kullaniyorsaniz "
            f"(ATTACK_STIX_URL) ya adresi surume sabitleyin ya da "
            f"--version {actual} ile acikca o surumu isteyin."
        )


def build_metadata(
    *,
    requested_version: str,
    actual_version: str,
    source_url: str,
    content: bytes,
    object_count: int,
) -> dict[str, object]:
    """Metadata kaydini kurar.

    `attack_version` GERCEK bundle surumudur ve anahtar adi korunmustur --
    scripts/parse_stix.py bu alani okuyup teknik/taktik/mitigation kayitlarina
    yaziyor. `requested_version` yanina eklendi: ikisi esit olmadan buraya
    hic gelinmez, ama kayit hangi surumun ISTENDIGINI de tasir.
    """
    return {
        "source_url": source_url,
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "file_size_bytes": len(content),
        "requested_version": requested_version,
        "attack_version": actual_version,
        "object_count": object_count,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Enterprise ATT&CK STIX bundle'ini indirir. Surum acikca secilir; "
            "secilmezse deponun uretim surumu kullanilir, 'en son' takip edilmez."
        )
    )
    parser.add_argument(
        "--version",
        default=DEFAULT_ATTACK_VERSION,
        help=f"Indirilecek ATT&CK surumu (varsayilan: {DEFAULT_ATTACK_VERSION})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    requested = args.version
    source_url = resolve_source_url(requested)

    print(f"Istenen surum: {requested}")
    print(f"Indiriliyor  : {source_url}")
    content = download_stix(source_url)

    stix_bundle = json.loads(content)
    actual_version = extract_attack_version(stix_bundle)

    # DOGRULAMA YAZMADAN ONCE: tutmuyorsa uretim dosyasina dokunulmaz.
    verify_version(requested, actual_version, source_url)

    metadata = build_metadata(
        requested_version=requested,
        actual_version=actual_version,
        source_url=source_url,
        content=content,
        object_count=len(stix_bundle.get("objects", [])),
    )

    STIX_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    STIX_FILE.write_bytes(content)
    METADATA_FILE.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Kaydedildi: {STIX_FILE}")
    print(f"ATT&CK surumu: {actual_version}")
    print(f"SHA256: {metadata['sha256']}")
    print(f"Nesne sayisi: {metadata['object_count']}")
    print(f"Metadata: {METADATA_FILE}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VersionMismatch as hata:
        print(f"\nHATA: {hata}")
        raise SystemExit(1)
