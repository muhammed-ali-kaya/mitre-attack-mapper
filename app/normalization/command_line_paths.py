"""Komut satirindan registry yolu cikarir -- SINIRI dogru bulmak icin.

NEDEN VAR (olculdu 2026-08-19, bkz. docs/beklenti_6_komut_satiri_yol_siniri.md)
    reg.exe save HKLM\\SAM C:\\Users\\Public\\sam.hive

    Naif desen bundan "HKLM\\SAM C" cikariyordu; siniflandir buna 'unknown'
    diyor. Oysa HKLM\\SAM tek basina 'critical'. Yani SAM hirsizliginin
    komut satiri bicimi -- T1003.002, known_regression'daki teknik -- bir
    TOKENIZASYON ARTEFAKTI yuzunden kayboluyordu. Gorev 4'un kuralinca
    'unknown' BENIGN uretemez ama SUSPICIOUS de uretemez; vaka sessizce
    dusuyordu.

SORUN "BOSLUK KABUL EDILMESI" DEGIL
    Registry anahtar adlari gercekten bosluk tasir: "Windows Defender",
    "Windows NT", "Time Zones". Bosluk yasaklanirsa bu yollar KIRPILIR ve
    ayni vaka ters yonden kaybedilir. Sorun, bosluktan SONRASINA
    bakilmamasi: bir sonraki token segment devami mi, yoksa ikinci bir
    pozisyonel argüman mi?

BU MODUL DUZYAZIYA UYGULANMAZ
    Gorev 5 §6 karari: kritiklik yapisal alandan, yoksa komut satirindan
    okunur; duzyazidan OKUNMAZ. Komut satiri olayin artefaktidir, duzyazi
    olayin iddiasi. Bu kural burada degil, cagiran tarafta zorlanir.
"""

from __future__ import annotations

import re

from app.normalization.path_normalizer import looks_like_registry_path

#: Yolun BASLAYABILECEGI onekler. path_normalizer'daki alias tablosuyla ayni
#: aileden; burada yalnizca "yol burada basliyor" tespiti icin gerekli.
_HIVE_BASI = re.compile(
    r"(?<![\w\\])(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKCC|HKU)(?=[:\\])"
    r"|(?<![\w])\\REGISTRY\\",
    re.IGNORECASE,
)

#: K2 -- yeni bir kok baslatan token. Bunlar yolun DEVAMI olamaz.
_YENI_KOK = re.compile(
    r"^(?:[A-Za-z]:[\\/]"          # C:\ surucu yolu
    r"|\\\\"                       # \\sunucu\paylasim (UNC)
    r"|(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKCC|HKU)[:\\])",  # ikinci bir kovan
    re.IGNORECASE,
)

#: K2 -- bayrak/anahtar. '/v', '/s', '-Name', '--force'
_BAYRAK = re.compile(r"^[-/][A-Za-z-]")

#: K2 -- dosya adi bicimi: ad.uzanti (1-5 karakter uzanti)
_DOSYA_ADI = re.compile(r"^[\w.$-]+\.[A-Za-z0-9]{1,5}$")

#: K3 -- reg.exe fiil aritesi. Ikinci pozisyoneli DOSYA olan fiiller.
#: Arite 1 olanlarda anahtar adi tek pozisyoneldir ve ilk bayraga kadar
#: her sey yola aittir; arite 2'de son token dosyadir.
_REG_ARITE_2 = {"save", "restore", "load", "export", "copy", "compare"}
_REG_KOMUTU = re.compile(r"(?<![\w.])reg(?:\.exe)?\s+([a-z]+)", re.IGNORECASE)


def _reg_fiili(command_line: str) -> str | None:
    """Komut bir `reg`/`reg.exe` cagrisiysa fiilini dondurur."""
    match = _REG_KOMUTU.search(command_line)
    return match.group(1).casefold() if match else None


def _tirnakli_govde(command_line: str, start: int) -> str | None:
    """K1 -- yol bir tirnagin ICINDE basliyorsa kapanisa kadar olan govde.

    Tirnak, komut satirini yazanin ACIK sinir beyanidir; icindeki bosluk
    sorgulanmaz."""
    for quote in ('"', "'"):
        open_at = command_line.rfind(quote, 0, start)
        if open_at == -1:
            continue
        close_at = command_line.find(quote, start)
        if close_at == -1:
            continue
        # Aradaki metinde baska bir tirnak varsa bu cift bizi kapsamiyor.
        if quote in command_line[open_at + 1:start]:
            continue
        return command_line[start:close_at]
    return None


def _ham_govde(command_line: str, start: int) -> str:
    """Tirnaksiz govde: bosluklar DAHIL, ham hâliyle satir sonuna kadar."""
    kuyruk = command_line[start:]
    for quote in ('"', "'"):
        kesim = kuyruk.find(quote)
        if kesim != -1:
            kuyruk = kuyruk[:kesim]
    return kuyruk


def _bosluktan_sonrasina_bak(govde: str, arite_2: bool) -> str:
    """K2 + K3 -- govdeyi bosluk sinirinda nerede kesecegimize karar verir.

    Token token ilerler; her boslukta sonraki token'in yolun DEVAMI mi
    yoksa yeni bir argüman mi oldugunu sorar."""
    tokens = govde.split(" ")
    kabul = [tokens[0]]
    kesildi = False
    for token in tokens[1:]:
        if not token:
            break
        if _YENI_KOK.match(token) or _BAYRAK.match(token) or _DOSYA_ADI.match(token):
            kesildi = True
            break
        kabul.append(token)

    # K3 -- arite 2 fiillerinde ikinci pozisyonel bir DOSYADIR. K2 zaten
    # kestiyse dokunma; kesmediyse son token o dosyadir.
    if arite_2 and not kesildi and len(kabul) > 1:
        kabul.pop()

    return " ".join(kabul)


def _temizle(value: str) -> str:
    """K4 -- PowerShell surucu gosterimi ve kuyruk noktalama.

    HKLM:\\SOFTWARE\\... -> HKLM\\SOFTWARE\\...
    _kanonik ilk segmenti 'hklm:' olarak goruyor ve hicbir desenle
    eslesmiyor; V7'nin None donmesinin sebebi buydu."""
    value = re.sub(r"^(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKCC|HKU):", r"\1", value,
                   flags=re.IGNORECASE)
    return value.strip().rstrip(",;)").rstrip("\\ ")


def extract_registry_paths(command_line: str | None) -> list[str]:
    """Komut satirindaki registry yollari -- gecis sirasinda, tekrarsiz.

        reg.exe save HKLM\\SAM C:\\Users\\Public\\sam.hive  -> ['HKLM\\SAM']
        reg add HKLM\\...\\Windows Defender /v Disable...   -> ['HKLM\\...\\Windows Defender']

    Yalin kovan ('HKLM', ardinda segment yok) YOL DEGILDIR ve donmez --
    path_normalizer'daki karar ile ayni (K5): ayirt edici bilgi tasimaz."""
    if not command_line or not str(command_line).strip():
        return []

    text = str(command_line)
    arite_2 = _reg_fiili(text) in _REG_ARITE_2

    bulunanlar: list[str] = []
    son_bitis = -1
    for match in _HIVE_BASI.finditer(text):
        start = match.start()
        # Onceki bir yolun ICINDE kaldiysak atla: "HKLM\\...\\HKCU-benzeri"
        # gibi ic ice eslesmeler ayni yolu ikinci kez uretmemeli.
        if start < son_bitis:
            continue

        govde = _tirnakli_govde(text, start)
        if govde is None:
            govde = _bosluktan_sonrasina_bak(_ham_govde(text, start), arite_2)

        son_bitis = start + len(govde)
        aday = _temizle(govde)

        # K5 -- yalin kovan yol degildir.
        if "\\" not in aday.strip("\\"):
            continue
        if not looks_like_registry_path(aday):
            continue
        if aday not in bulunanlar:
            bulunanlar.append(aday)

    return bulunanlar
