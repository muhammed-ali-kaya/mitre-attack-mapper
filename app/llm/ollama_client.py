"""Ollama /api/chat istemcisi. Yapilandirilmis (JSON schema kisitli) cikti destekler.

Retry mantigi: uzun evaluation kosumlari sirasinda ara sira (yaklasik her ~5
sorguda bir) Ollama'nin 300s icinde cevap veremedigi gozlemlendi (VRAM
tikanikligindan degil -- surekli degil, aradaki sorgular sorunsuz gecti;
muhtemelen model'in gecici olarak VRAM'den atilip yeniden yuklenmesi gibi
periyodik bir gecikme). Kalici bir hata olmadigi icin retry ile cozuluyor.
"""

from __future__ import annotations

import time
from typing import Any

import requests

OLLAMA_HOST = "http://localhost:11434"

# Ollama'ya hicbir sampling ayari gonderilmedigi surece model kendi varsayilan
# sicakligiyla orneklem yapiyordu: AYNI girdi, kosudan kosuya farkli cikti.
# Olcumu bozan da buydu -- kodda tek satir degismeden 60 senaryonun ~%24'u
# yer degistiriyor, yani baseline/improved farki gurultunun altinda kaliyordu.
# temperature=0 + sabit seed ile eval tekrarlanabilir hale geliyor.
#
# num_ctx: qwen3:8b 40960 token baglam destekliyor ama Ollama onu kendi
# varsayilani olan 4096 ile yukluyordu (`/api/ps` -> context_length: 4096).
# Olculen prompt boyutlari 4205-7339 token araligindaydi, yani bazi promptlar
# TEK BASINA pencereyi asiyordu. Asinca Ollama context-shift yapip promptun
# basini -- sistem promptunu ve JSON semasini -- dusuruyor, model o noktadan
# sonra gecerli JSON uretemiyor: eval kosusunda 3 senaryo "Unterminated string",
# 5 senaryo da (shift sonrasi prompt yeniden hesaplandigi icin) 300s timeout
# ile dusmustu. Prompt boyu senaryodan senaryoya degistigi icin hata araliksiz
# degildi, bu yuzden uzun sure fark edilmedi.
#
# Neden 6144: 8GB VRAM'de qwen3 ve bge-m3'un AYNI ANDA yuklu kalabildigi en
# buyuk deger. Olcum (KV cache ~0.14 MB/token):
#     4096 -> qwen3 5.58GB + bge-m3 0.66GB, ikisi birden yuklu kaliyor
#     6144 -> qwen3 5.88GB + bge-m3 0.66GB, ikisi birden yuklu kaliyor
#     8192 -> qwen3 6.19GB, bge-m3 yuklenince qwen3 VRAM'den ATILIYOR
# 8192'deki tahliye her sorguda model yeniden yuklenmesi demek; zaten timeout
# yasadigimiz bir kosuda bunu goze alamayiz (ayni kisit icin bkz.
# app/retrieval/reranker.py -- reranker de bu yuzden CPU'da).
#
# 6144, 7339 tokenlik en kotu prompt'a yetmiyor; o yuzden asil cozum prompt'u
# bir butceye baglamak. Bkz. app/llm/prompts.py -> CONTEXT_CHAR_BUDGET.
DETERMINISTIC_OPTIONS: dict[str, Any] = {"temperature": 0, "seed": 42, "top_p": 1, "num_ctx": 6144}

# Modelin VRAM'de kalma suresi. Ollama'nin varsayilani 5 dakika ve bu,
# etkilesimli kullanimda YETMIYOR: analist arada bir log yapistirdiginda
# model her seferinde bosalmis oluyor.
#
# Bu bir hiz meselesi degil, DOGRULUK meselesi. Olculdu (2026-08-16, T1
# fixture'i, alti kosuluk iki kol):
#     model soguk -> activity_verdict = malicious_or_suspicious  (6/6)
#     model sicak -> activity_verdict = insufficient_evidence     (6/6)
# NOT (Gorev 5, 2026-08-19): activity_verdict semadan KALKTI ve karar koda
# tasindi (app/validation/decision.py). Yukaridaki olcum tarihsel kayittir
# -- kaldirmanin GEREKCESI oydu. Yukleme durumunun etiket/serbest metin
# alanlarindaki etkisi surebilir; o Gorev 7'nin konusu.
# Ayni girdi, ayni prompt, temperature=0, sabit seed. Retrieval iki kolda
# birebir ayni. Yani yukleme durumu, kayitsiz bir GIRDI gibi davraniyor ve
# bir SOC icin taban tabana zit iki sonuc uretebiliyor.
#
# Yukleme maliyeti de olculdu: soguk cagri 8.5sn (6.3sn'si model yukleme),
# sicak cagri 2.5sn.
#
# 30 dakika, bir analiz oturumunu kapsayacak kadar uzun; sinirsiz degil,
# cunku qwen3:8b ~5.9GB tutuyor ve bu makinede VRAM 8GB (ayni kisit icin
# bkz. app/retrieval/reranker.py -- reranker bu yuzden CPU'da).
KEEP_ALIVE = "30m"

# --- Token muhasebesi --------------------------------------------------------
# Ollama /api/chat yaniti kac token harcandigini zaten donduruyor:
#   prompt_eval_count -> modele GIDEN token sayisi (sistem promptu + baglam +
#                        kullanici girdisi + JSON semasi)
#   eval_count        -> modelin URETTIGI token sayisi
# Sayaci burada tutmamizin sebebi: tek bir kullanici girdisi birden fazla LLM
# cagrisi tetikleyebiliyor (pipeline'in eslestirme cagrisi + arayuzdeki ceviri
# cagrisi). Cagrilarin hepsi bu modulden gectigi icin toplami tek yerde,
# cagiran taraflari degistirmeden toplayabiliyoruz.
#
# Sayac kumulatif (islem boyunca artar); "bu girdi kac token harcadi" sorusu
# usage_snapshot() ile isin basinda bir foto cekip usage_since() ile farkini
# almaktan ibaret. Boylece es zamanli olmayan farkli olcum pencereleri
# (pipeline, render, toplu analizde her satir) birbirini sifirlamiyor.
_USAGE_TOTALS: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}


def usage_snapshot() -> dict[str, int]:
    """Kumulatif sayacin o anki kopyasi. usage_since() ile birlikte kullanilir."""
    return dict(_USAGE_TOTALS)


def usage_since(snapshot: dict[str, int]) -> dict[str, int]:
    """snapshot alindigindan bu yana harcanan token'lar."""
    delta = {key: _USAGE_TOTALS[key] - snapshot.get(key, 0) for key in _USAGE_TOTALS}
    delta["total_tokens"] = delta["prompt_tokens"] + delta["completion_tokens"]
    return delta


def _record_usage(response: dict[str, Any]) -> None:
    # Alanlar Ollama surumune/istegin turune gore eksik gelebilir; sayaci
    # patlatmak yerine 0 sayiyoruz -- token gosterimi bir raporlama detayi,
    # analizi dusurmeye degmez.
    _USAGE_TOTALS["prompt_tokens"] += int(response.get("prompt_eval_count") or 0)
    _USAGE_TOTALS["completion_tokens"] += int(response.get("eval_count") or 0)
    _USAGE_TOTALS["calls"] += 1


def chat(
    model: str,
    system: str,
    user: str,
    json_schema: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
    timeout: int = 300,
    max_retries: int = 2,
    retry_backoff_seconds: float = 5.0,
    think: bool = False,
) -> dict[str, Any]:
    """think=False: qwen3 gibi reasoning modellerinde gizli 'thinking' asamasini
    kapatir. Yapilandirilmis JSON ciktimiz zaten thinking metnini kullanmiyor,
    bu yuzden kapatmanin hiz kazandirmasi beklenir; dogruluk etkisini test
    ederek dogrulamak gerekir (asagida yapildi)."""
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "think": think,
        "keep_alive": KEEP_ALIVE,
    }
    if json_schema:
        payload["format"] = json_schema
    # Cagiran taraf acikca options verirse o kazanir; vermezse deterministik
    # varsayilan uygulanir (bkz. DETERMINISTIC_OPTIONS).
    payload["options"] = options if options is not None else DETERMINISTIC_OPTIONS

    return _post_with_retries(payload, timeout, max_retries, retry_backoff_seconds)


def chat_turn(
    model: str,
    system: str,
    history: list[dict[str, str]],
    timeout: int = 120,
    max_retries: int = 2,
    retry_backoff_seconds: float = 3.0,
    think: bool = False,
) -> str:
    """Coklu-tur (multi-turn) sohbet icin: chat()'in aksine JSON schema kisitlamasi
    yok, serbest metin yanit doner (dogrudan cevap metni, ham API yaniti degil).

    history: onceki {"role": "user"|"assistant", "content": str} turlerinin
    listesi -- en sonda kullanicinin yeni sorusu olmali."""
    payload: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "system", "content": system}, *history],
        "stream": False,
        "think": think,
        "keep_alive": KEEP_ALIVE,
        "options": DETERMINISTIC_OPTIONS,
    }
    response = _post_with_retries(payload, timeout, max_retries, retry_backoff_seconds)
    return response["message"]["content"]


def _post_with_retries(
    payload: dict[str, Any], timeout: int, max_retries: int, retry_backoff_seconds: float
) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            response = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, timeout=timeout)
            response.raise_for_status()
            body = response.json()
            # Basarisiz denemeler token uretmedigi icin sayim yalnizca burada.
            _record_usage(body)
            return body
        except requests.exceptions.HTTPError as e:
            # 5xx sunucu tarafinda gecici bir arizadir ve tam olarak retry'in
            # var olma sebebidir; eval kosusunda Ollama tek bir senaryoda 500
            # dondurup senaryoyu tamamen dusurmustu. 4xx ise istegin kendisi
            # bozuk demek -- tekrar gondermek ayni sonucu verir, hemen yukselt.
            status = e.response.status_code if e.response is not None else 0
            if status < 500:
                raise
            last_error = e
            if attempt < max_retries:
                time.sleep(retry_backoff_seconds * (attempt + 1))
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
            last_error = e
            if attempt < max_retries:
                time.sleep(retry_backoff_seconds * (attempt + 1))
    raise last_error
