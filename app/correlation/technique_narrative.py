"""Teknik basina tek satirlik "NE OLDU" cumlesi (Gorev 25).

SORUN: matris tablosu "Socket Filters (T1205.002, 5 kayit)" yaziyordu.
Analist rakami goruyor ama olayi cikaramiyor -- hangi log, ne yapildi?
Veri zaten elde: source_row_indices, first_seen_timestamp ve satirin
kanonik alanlari.

ALAN SECIMI YENIDEN YAZILMADI (madde 7: "ayni isi yapan baska kac yol
var?"). `config/event_semantics.yaml`in `anlamli_alanlar` listesi zaten
OLAY BASINA anlam tasiyan kanonik alanlari tutuyor -- 5156 icin
source.ip / destination.ip / destination.port / process.name. Cumle o
listeden kuruluyor, ikinci bir tablo acilmiyor.

K2 ILE KARISTIRILMAMALI: K2 (teknik, olay) -> alan sorusunu kural
ESLESTIRMESI icin soruyor ve cozulmedi. Burada anahtar TEK BASINA olaydir
ve sonuc yalnizca GOSTERIME gidiyor; hicbir eslesme, skor veya kapsam
hesabi bu modulden etkilenmez.

LLM KULLANILMAZ. Cumle sablondan kurulur; uretilemiyorsa None doner ve
cagiran taraf bugunku gorunume duser -- eksik veriyle cumle UYDURULMAZ.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.normalization.event_semantics import event_semantics

#: Cumlenin OZNESI olabilecek alanlar, oncelik sirasiyla.
ACTOR_FIELDS: tuple[str, ...] = ("process.name", "account.name", "service.name")

#: Cumlenin NESNESI olabilecek alanlar: (alan, on ek etiketi).
#:
#: HER SATIR en az bir olayin `anlamli_alanlar` listesinde gecmek ZORUNDA
#: (tests/test_technique_narrative.py). Ilk yazimda `target.user.name`
#: buradaydi ve hicbir olay onu anlamli saymiyordu -- test yakaladi,
#: satir silindi. Boyle bir satir hicbir zaman ateslenmez ama tabloyu
#: buyutur ve bakan kisiye desteklendigi izlenimini verir.
#: Hedef adresi ciplak yazilir -- ok zaten "-> hedef" anlamini tasiyor.
#: Digerleri on ek alir, cunku "chrome.exe -> Administrator" tek basina
#: hangi tur nesne oldugunu soylemez.
TARGET_FIELDS: tuple[tuple[str, str], ...] = (
    ("destination.ip", ""),
    ("object.name", ""),
    ("file.path", ""),
    ("file.name", ""),
    ("target.image", ""),
    ("service.image_path", ""),
    ("share.name", "paylaşım "),
    ("value.new", "yeni değer "),
    ("script.block_text", "betik "),
    ("process.command_line", ""),
    ("source.ip", "yerel "),
)

#: Hedef alanina bitisik yazilacak port alanlari.
PORT_OF: dict[str, str] = {
    "destination.ip": "destination.port",
    "source.ip": "source.port",
}

#: Bu uzunlugun ustundeki deger tek satira sigmaz (komut satiri, betik
#: govdesi). Kesilen deger "..." ile isaretlenir -- sessizce kirpmak,
#: analiste TAM deger gosterildigi izlenimini verirdi.
VALUE_LENGTH_LIMIT = 70


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    if not text or text.casefold() in {"nan", "n/a", "-", "null", "none"}:
        return None
    return text


def _shorten(text: str) -> str:
    if len(text) <= VALUE_LENGTH_LIMIT:
        return text
    return text[: VALUE_LENGTH_LIMIT - 1].rstrip() + "…"


def base_name(path_or_name: str) -> str:
    r"""Tam yoldan taban adi ayirir (`...\chrome.exe` -> `chrome.exe`).

    YON TEK TARAFLI -- Gorev 24'un turetim kurali ile ayni: yol -> ad
    turetilir, ad yol sayilmaz. Burada yalnizca GOSTERIM icin yapiliyor;
    tam yol cagiran tarafta duruyor ve hicbir kosul bu degeri okumuyor."""
    parts = path_or_name.replace("/", "\\").split("\\")
    tail = parts[-1].strip()
    return tail or path_or_name


def _clock(timestamp: Any) -> str | None:
    """`first_seen_timestamp` iki bicimde gelebilir: canli kosuda datetime,
    diske kaydedilmis sonucta STRING (result_store json.dumps default=str).
    Demo kaydedilmis dosyadan aciliyor -- ikisi de desteklenmek zorunda."""
    if timestamp is None:
        return None
    if isinstance(timestamp, datetime):
        return timestamp.strftime("%H:%M")
    text = _text(timestamp)
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).strftime("%H:%M")
        except ValueError:
            continue
    return None


def row_event_id(row: dict[str, Any]) -> str | None:
    """Kanonik ad once, legacy izdusumu sonra.

    Gorev 24'un dersi: `text_to_row` IKI namespace'i birden yaziyor;
    yalnizca birine bakan olcum iki kez yanlis sayi uretti."""
    return _text(row.get("event.id")) or _text(row.get("EventID"))


def _actor(row: dict[str, Any], meaningful: list[str]) -> str | None:
    for field in ACTOR_FIELDS:
        if field not in meaningful:
            continue
        value = _text(row.get(field))
        if value:
            return base_name(value) if field != "account.name" else value
    return None


def _target(row: dict[str, Any], meaningful: list[str], actor_field_used: bool) -> str | None:
    for field, prefix in TARGET_FIELDS:
        if field not in meaningful:
            continue
        value = _text(row.get(field))
        if not value:
            continue
        port = _text(row.get(PORT_OF.get(field, ""))) if PORT_OF.get(field) else None
        if port and PORT_OF.get(field) in meaningful:
            value = _join_host_port(value, port)
        return prefix + _shorten(value)
    return None


def _join_host_port(host: str, port: str) -> str:
    """IPv6 adresi kendi icinde ':' tasiyor -- duz birlestirme `:::54770`
    gibi okunamayan bir dize uretiyordu (gercek 5158 kaydinda olcuIdu).
    Koseli ayrac IPv6 icin standart gosterimdir."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def technique_sentence(technique: dict[str, Any], rows_by_index: dict[int, dict[str, Any]]) -> str | None:
    """Teknigin ILK goruldugu satirdan tek cumlelik ozet.

    None doner: olayin ID'si okunamiyorsa, olay `event_semantics.yaml`de
    yoksa, ya da o olayin anlamli alanlarinin hicbiri satirda dolu
    degilse. Cagiran taraf o zaman bugunku gorunumu basar -- eksik
    veriyle cumle uydurmak, analistin guvenmemesi gereken bir satiri
    guvenilir gostermek olurdu."""
    indices = technique.get("source_row_indices") or []
    row = next((rows_by_index[i] for i in indices if i in rows_by_index), None)
    if not row:
        return None

    event_id = row_event_id(row)
    semantics = event_semantics(event_id)
    if semantics is None:
        return None

    meaningful = list(semantics.get("anlamli_alanlar") or [])
    actor = _actor(row, meaningful)
    target = _target(row, meaningful, actor is not None)
    if actor is None and target is None:
        return None

    # Dolu olmayan parca DUSER, yer tutucu basilmaz (Gorev 24'un "- -" dersi).
    who = " → ".join(p for p in (actor, target) if p)
    clock = _clock(technique.get("first_seen_timestamp"))

    parts = [f"{clock} · {who}" if clock else who]
    anlam = _text(semantics.get("anlam"))
    if anlam:
        parts.append(anlam)
    sentence = ", ".join(parts)
    return f"{sentence} ({event_id})"


def technique_sentences(
    techniques: list[dict[str, Any]], rows_by_index: dict[int, dict[str, Any]]
) -> dict[str, str]:
    """attack_id -> cumle. Cumle kurulamayan teknik SOZLUKTE YER ALMAZ."""
    out: dict[str, str] = {}
    for technique in techniques:
        attack_id = technique.get("attack_id")
        if not attack_id:
            continue
        sentence = technique_sentence(technique, rows_by_index)
        if sentence:
            out[attack_id] = sentence
    return out
