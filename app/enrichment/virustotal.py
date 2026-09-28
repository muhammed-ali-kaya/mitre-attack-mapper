"""IP itibar sorgusu (VirusTotal API v3) -- yalnizca GOSTERIM amacli zenginlestirme.

Bu modul projenin ilk dis servis bagimliligi: geri kalan her sey (Ollama, ATT&CK
verisi, retrieval) yerel calisiyor. Bu yuzden uc kural kati tutuldu.

1. YALNIZCA PUBLIC IP sorgulanir. Loglar RFC1918/loopback/link-local adres dolu;
   bunlari VT'ye gondermek uc ayri hata olurdu: VT'de ozel adreslerin karsiligi
   yok (faydasiz), dakikada 4 isteklik ucretsiz kotayi bosa yakar, ve en onemlisi
   ic ag topolojisini ucuncu bir tarafa sizdirir.

2. Sonuc LLM PROMPTUNA GIRMEZ. VT yaniti serbest metin alanlari (etiketler,
   AS sahibi adi) iceriyor; bunlar prompt'a girse disaridan gelen metin model
   talimatina donusebilirdi -- projenin olctugu prompt_injection direncini
   dogrudan zayiflatirdi. Cikti sadece arayuzde ve indirilen raporda gorunur,
   eslestirme kararina hicbir sekilde katilmaz.

3. Ozellik SESSIZCE kapanir. Anahtar yoksa, ag yoksa, kota dolduysa veya servis
   hata dondurduyse analiz akisi etkilenmez; ilgili IP "sorgulanamadi" olarak
   isaretlenir. Demo sirasinda bir ag sorunu uygulamayi durdurmamali.

Anahtar .env icindeki VIRUSTOTAL_API_KEY'den okunur (.env git'e girmez).
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any

import requests
from dotenv import dotenv_values

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
REQUEST_TIMEOUT = 10

# Ucretsiz kota dakikada 4 istek. Kotayi proaktif beklemeyle (istekler arasi
# 15sn uyku) yonetmek arayuzu kilitlerdi; bunun yerine tek seferde sorgulanan
# IP sayisi sinirlaniyor ve 429 gelirse kalanlar "kota doldu" diye isaretlenip
# donuluyor. Kullaniciyi bekletmek yerine eksik bilgiyi durustce gostermek
# daha iyi: hangi IP'nin neden sorgulanmadigi ekranda yaziyor.
DEFAULT_MAX_LOOKUPS = 10

_cache: dict[str, "IpReputation"] = {}


@dataclass
class IpReputation:
    """Tek bir IP icin VT sonucu. status alani 'ok' disindaysa sayisal alanlar
    anlamsizdir -- cagiran taraf status'e bakmali."""

    ip: str
    status: str  # ok | rate_limited | not_found | error | disabled
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    reputation: int | None = None
    country: str | None = None
    as_owner: str | None = None
    detail: str | None = None

    @property
    def verdict(self) -> str:
        if self.status == "rate_limited":
            return "Kota doldu - sorgulanamadi"
        if self.status == "not_found":
            return "VirusTotal'de kayit yok"
        if self.status == "disabled":
            return "Ozellik kapali (API anahtari yok)"
        if self.status != "ok":
            return "Sorgulanamadi"
        if self.malicious > 0:
            return f"Zararli ({self.malicious} motor)"
        if self.suspicious > 0:
            return f"Supheli ({self.suspicious} motor)"
        return "Temiz"


@dataclass
class LookupResult:
    """Bir grup IP'nin sorgu sonucu ve NEDEN bazilarinin sorgulanmadigi.

    Atlanan IP'leri sessizce yutmak yaniltici olurdu: analist "bu IP temiz mi
    yoksa hic bakilmadi mi" ayrimini gorebilmeli."""

    reputations: list[IpReputation] = field(default_factory=list)
    skipped_private: list[str] = field(default_factory=list)
    skipped_over_limit: list[str] = field(default_factory=list)
    enabled: bool = True


def get_api_key() -> str | None:
    """Anahtari ortamdan ya da .env'den okur. Ortam degiskeni oncelikli --
    boylece anahtari .env'e yazmadan tek seferlik de verilebilir.

    .env icin load_dotenv yerine dotenv_values kullaniliyor. load_dotenv
    degerleri os.environ'a yaziyor ve override=False ile zaten var olani
    gecmiyor; .env'de bos bir "VIRUSTOTAL_API_KEY=" satiri varsa (ornek
    dosyadan kopyalanan hali boyle) ilk okumada ortama bos string yaziliyor
    ve kullanici anahtari sonradan doldurdugunda uygulama bunu ASLA
    gormuyordu -- yeniden baslatmak gerekiyordu. dotenv_values dosyayi her
    seferinde taze okur ve ortami kirletmez."""
    from_env = os.environ.get("VIRUSTOTAL_API_KEY")
    if from_env and from_env.strip():
        return from_env.strip()

    from_file = (dotenv_values() or {}).get("VIRUSTOTAL_API_KEY")
    return from_file.strip() if from_file and from_file.strip() else None


def is_enabled() -> bool:
    return bool(get_api_key())


def is_public_ip(value: str) -> bool:
    """Adresin internete acik (dolayisiyla VT'ye sorulabilir) olup olmadigi.

    ipaddress kutuphanesi RFC1918 (10/8, 172.16/12, 192.168/16), loopback,
    link-local (169.254/16), multicast ve ayrilmis bloklarin hepsini biliyor;
    bu listeyi elle tutmak yeni bir blok cikinca sessizce hatali olurdu."""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _parse_response(ip: str, payload: dict[str, Any]) -> IpReputation:
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    return IpReputation(
        ip=ip,
        status="ok",
        malicious=int(stats.get("malicious") or 0),
        suspicious=int(stats.get("suspicious") or 0),
        harmless=int(stats.get("harmless") or 0),
        reputation=attributes.get("reputation"),
        country=attributes.get("country"),
        as_owner=attributes.get("as_owner"),
    )


def lookup_ip(ip: str) -> IpReputation:
    """Tek IP sorgular. Hicbir durumda exception firlatmaz -- cagiran tarafin
    akisi bir ag hatasi yuzunden kesilmemeli (bkz. modul basligi, kural 3)."""
    if ip in _cache:
        return _cache[ip]

    api_key = get_api_key()
    if not api_key:
        return IpReputation(ip=ip, status="disabled")

    try:
        response = requests.get(
            API_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        return IpReputation(ip=ip, status="error", detail=str(e))

    if response.status_code == 429:
        return IpReputation(ip=ip, status="rate_limited")
    if response.status_code == 404:
        result = IpReputation(ip=ip, status="not_found")
        _cache[ip] = result
        return result
    if response.status_code != 200:
        return IpReputation(ip=ip, status="error", detail=f"HTTP {response.status_code}")

    try:
        result = _parse_response(ip, response.json())
    except (ValueError, KeyError, TypeError) as e:
        return IpReputation(ip=ip, status="error", detail=f"yanit ayristirilamadi: {e}")

    # Yalnizca basarili sonuc onbellege alinir; gecici hatalar (kota, ag)
    # onbellege girerse sonraki denemede de hatali gorunurdu.
    _cache[ip] = result
    return result


def lookup_ips(ips: list[str], max_lookups: int = DEFAULT_MAX_LOOKUPS) -> LookupResult:
    """Bir grup IP'yi tekillestirip sorgular; ozel adresleri hic gondermez."""
    result = LookupResult(enabled=is_enabled())

    unique: list[str] = []
    for ip in ips:
        value = (ip or "").strip()
        if not value or value in unique or value in result.skipped_private:
            continue
        if is_public_ip(value):
            unique.append(value)
        else:
            result.skipped_private.append(value)

    if not result.enabled:
        return result

    network_lookups = 0
    for position, ip in enumerate(unique):
        # Sinir yalnizca GERCEK istekleri sayar; onbellekten gelen cevap kota
        # harcamadigi icin sinira takilmamali.
        cached = ip in _cache
        if not cached and network_lookups >= max_lookups:
            result.skipped_over_limit.append(ip)
            continue
        if not cached:
            network_lookups += 1

        reputation = lookup_ip(ip)
        result.reputations.append(reputation)

        # Kota dolduysa kalan IP'ler icin denemeye devam etmek anlamsiz.
        if reputation.status == "rate_limited":
            result.skipped_over_limit.extend(unique[position + 1 :])
            break

    return result


def clear_cache() -> None:
    _cache.clear()
