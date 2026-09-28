"""Olcum kosularinin ortak hijyeni: isinma cagrisi + sirali yanlilik korumasi.

NEDEN VAR (olculdu, 2026-08-16)
    Ayni girdi, ayni prompt, temperature=0 ve sabit seed ile IKI FARKLI cevap
    verebiliyor -- ama rastgele degil: modelin VRAM'de yuklu olup olmamasina
    gore. Alti kosuluk iki kol:

        soguk (her kosudan once model bosaltildi) : 6/6 ayni cevap A
        sicak (tek oturum)                        : 6/6 ayni cevap B

    Her kol kendi icinde kararli, kollar birbirinden farkli. Yani hat
    deterministik; kayitsiz bir GIRDI vardi.

SONUCU NE OLUR
    Bir olcum kosusunun ILK sorgusu soguk modele gider, geri kalani sicaga.
    Sabit sirali bir sette bu, hep AYNI senaryonun farkli kosullarda
    olculmesi demektir -- rastgele gurultu degil, siraya bagli SISTEMATIK
    yanlilik. O senaryonun sayilari her kosuda bozuk cikar ve uzerine
    kurulan her metrik bundan etkilenir.

IKI KORUMA
    warmup_model()    : olcume girmeyen bir cagri; ilk gercek sorgu artik
                        sicak modele gider.
    shuffled()        : senaryo sirasini SABIT seed ile karistirir. Isinma
                        kacarsa bile artefakt hep ayni senaryoya yiginlmaz;
                        sabit seed sayesinde kosular birbiriyle
                        karsilastirilabilir kalir.
"""

from __future__ import annotations

import random
from typing import Any, Sequence

import requests

OLLAMA_HOST = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:8b"

# Karistirma seed'i SABIT: amac sirayi rastgelelestirmek degil, sabit sirali
# yanliligi kirmak. Kosudan kosuya degisen bir seed, iki kosuyu
# karsilastirilamaz hale getirirdi.
SHUFFLE_SEED = 20260816


def warmup_model(model: str = DEFAULT_MODEL, timeout: int = 300) -> bool:
    """Modeli VRAM'e yukler ve bir token urettirir. Sonuc KULLANILMAZ.

    Basarisizlik olcumu durdurmaz -- isinma bir kolaylik, on kosul degil --
    ama sessiz de gecmez: cagiran taraf False gorurse raporuna yazar."""
    try:
        requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": model,
                "prompt": "warmup",
                "stream": False,
                "options": {"num_predict": 1},
            },
            timeout=timeout,
        ).raise_for_status()
        return True
    except Exception:
        return False


def unload_model(model: str = DEFAULT_MODEL, timeout: int = 30) -> bool:
    """Modeli VRAM'den bosaltir (keep_alive=0) -- soguk kol olcumu icin."""
    try:
        requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": model, "prompt": "", "keep_alive": 0},
            timeout=timeout,
        ).raise_for_status()
        return True
    except Exception:
        return False


def shuffled(items: Sequence[Any], seed: int = SHUFFLE_SEED) -> list[Any]:
    """Sabit seed ile karistirilmis KOPYA dondurur.

    Girdiyi yerinde degistirmez: cagiran taraf orijinal sirayi (orn. rapor
    ciktisini kaynak dosyayla eslestirmek icin) hala kullanabilsin."""
    out = list(items)
    random.Random(seed).shuffle(out)
    return out


def prepare_run(model: str = DEFAULT_MODEL) -> dict[str, Any]:
    """Olcum kosusunun basinda cagrilir. Rapora yazilacak hijyen kaydini
    dondurur -- hangi korumalarin uygulandigi sonuctan ayrilamaz olmali."""
    warmed = warmup_model(model)
    return {
        "warmup_performed": warmed,
        "shuffle_seed": SHUFFLE_SEED,
        "model": model,
        "_not": (
            "Isinma cagrisi olcume dahil DEGILDIR. Sira sabit seed ile "
            "karistirildi; siraya bagli yanlilik tek senaryoya yiginlmasin diye."
        ),
    }
