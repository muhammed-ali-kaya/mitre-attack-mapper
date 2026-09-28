"""Incident timeline'ini ve MITRE attack chain'ini Mermaid diyagram metnine
ceviren yardimcilar (Streamlit 1.60+ `st.mermaid_chart` ile render eder).

Metin listeleri cok satirli incident'lerde okunaksizlasiyordu: hangi olayin
hangisini izledigi ve hangi teknigin hangi taktik fazina dustugu ancak
satirlar tek tek okununca cikiyordu. Diyagramlar bunu tek bakista gorunur
kiliyor; kisaltilmamis kanit metinleri app/ui/bulk_view.py'deki expander'larda
oldugu gibi korunuyor."""

from __future__ import annotations

import re
from typing import Any

from app.correlation.tactic_labels import tactic_label

EVIDENCE_CHAR_LIMIT = 130
TECHNIQUE_NAME_CHAR_LIMIT = 46

# Mermaid dugumu icerigine gore boyutlaniyor: en uzun satir ne kadarsa kutu o
# kadar genis oluyor. padding dugum ici boslugu, EVIDENCE_CHAR_LIMIT ise
# satiri uzatarak kutuyu esnetiyor.
_INIT_DIRECTIVE = '%%{init: {"flowchart": {"padding": 22, "nodeSpacing": 30, "rankSpacing": 48}}}%%'

# Kanit metni tek satirda cok uzarsa kutu ekrana sigmiyor; bu genislikte
# sarmalanip birden fazla satira bolunuyor. Deger EVIDENCE_CHAR_LIMIT'ten
# kucuk olmali, yoksa sarmalama hic devreye girmez.
EVIDENCE_WRAP_WIDTH = 68

# NOT: Bir zamanlar burada MIN_LABEL_WIDTH vardi -- kisa etiketli dugumleri
# bolunmez bosluklarla genisletiyordu. Kaldirildi; gerekcesi _label()'da.

_ENTITY_PATTERN = re.compile(r"#(?:\d+|[a-z]+);")

# Mermaid etiketleri cift tirnak icinde uretiliyor; asagidaki karakterler
# etiketi bozdugu icin Mermaid'in entity kodlarina cevriliyor. '#' ilk sirada
# olmali -- yoksa sonraki entity'lerin urettigi '#' bir kez daha kacilir.
_LABEL_ENTITIES = (("#", "#35;"), ('"', "#quot;"), ("<", "#lt;"), (">", "#gt;"))


def format_timestamp(ts: Any) -> str:
    """Zaman damgasi olmayan satirlar korelasyon motorunda eleniyor degil, sona
    ekleniyor (bkz. app/correlation/timeline.py) -- onlar icin '-' donuyor."""
    return ts.strftime("%H:%M:%S") if ts is not None else "-"


def _escape(text: Any) -> str:
    escaped = " ".join(str(text).split())
    for char, entity in _LABEL_ENTITIES:
        escaped = escaped.replace(char, entity)
    return escaped


def _truncate(text: Any, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _wrap(text: str, width: int) -> list[str]:
    """Metni kelime sinirlarindan width karakterlik satirlara boler.

    Escape'ten ONCE cagrilmali: escape sonrasi bolmek '#quot;' gibi bir entity
    kodunu ortasindan kesebilir (ayni gerekce icin bkz. _label)."""
    words = text.split()
    if not words:
        return []

    lines = []
    current = words[0]
    for word in words[1:]:
        if len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _label(*parts: str) -> str:
    """Bos parcalari atarak Mermaid'in cok satirli etiketini kurar. Kisaltma
    escape'ten ONCE yapilmali -- tersi bir entity kodunu ortasindan boler.

    TABAN GENISLIK DOLGUSU KALDIRILDI. Kisa kanitli dugumler komsularindan
    dar kaldigi icin ilk satir bolunmez bosluklarla doldurulyordu; ama bu
    dolgu tarayicida HARFI HARFINE "&nbsp;&nbsp;&nbsp;..." olarak
    goruntuleniyordu. Sirasiyla '#nbsp;', sayisal '#160;' ve gercek U+00A0
    karakteri denendi -- ucu de ayni bozuk ciktiyi verdi, yani Streamlit'in
    mermaid kanali bu boslugu her halukarda entity METNINE ceviriyor.
    Degisken genislikte dugumler tamamen okunabilir; ekranda "&nbsp;" yigini
    ise degil. Yeniden denenecekse once app/ui/diagrams.py testlerine
    tarayicida DOGRULANMIS bir ornek eklenmeli."""
    kept = [part for part in parts if part]
    if not kept:
        return ""
    return "<br/>".join(kept)


def build_timeline_diagram(timeline: list[dict[str, Any]]) -> str:
    """Kronolojik olay akisi: her satir bir dugum, oklar zaman sirasini izler."""
    if not timeline:
        return ""

    lines = [_INIT_DIRECTIVE, "graph TD"]
    unmapped: list[str] = []

    for i, entry in enumerate(timeline):
        node_id = f"n{i}"
        header = f"{format_timestamp(entry.get('timestamp'))} · EventID {entry.get('event_id') or '-'}"

        technique = ""
        if entry.get("attack_id"):
            name = entry.get("technique_name") or ""
            heading = f"{entry['attack_id']} — {name}" if name else str(entry["attack_id"])
            technique = _escape(_truncate(heading, TECHNIQUE_NAME_CHAR_LIMIT + 14))
        else:
            unmapped.append(node_id)

        evidence = _truncate(entry.get("evidence") or "-", EVIDENCE_CHAR_LIMIT)
        evidence_lines = [_escape(seg) for seg in _wrap(evidence, EVIDENCE_WRAP_WIDTH)]
        lines.append(f'    {node_id}["{_label(_escape(header), technique, *evidence_lines)}"]')
        if i:
            lines.append(f"    n{i - 1} --> {node_id}")

    # Guvenilir eslesmesi olmayan satirlar zincirden dusurulmuyor (olay sirasi
    # bozulmasin), sadece kesik cerceveyle ayirt ediliyor.
    if unmapped:
        lines.append("    classDef unmapped stroke-dasharray: 4 3")
        lines.append(f"    class {','.join(unmapped)} unmapped")

    return "\n".join(lines)


def build_attack_chain_diagram(chain: list[dict[str, Any]]) -> str:
    """Kill chain: her taktik fazi bir subgraph, icinde o faza dusen teknikler.

    Faz basliklari Turkce (Ingilizce karsiligi parantez icinde) -- teknik
    adlari ve ATT&CK ID'leri cevrilmez, bkz. app/correlation/tactic_labels.py.

    Dugum id'leri faz basina uretiliyor: varsayilan yerlestirmede bir teknik
    yalnizca birincil taktiginde cizilse de, primary_tactic_only=False ile
    cagrilan bir zincirde ayni ATT&CK ID birden cok fazda gorunebilir.

    Yon TD (yukaridan asagi): kill chain soldan saga daha dogal okunsa da LR'de
    subgraph'lar kapsayici genisligine sigmayip basliklari kirpiliyordu."""
    if not chain:
        return ""

    lines = [_INIT_DIRECTIVE, "graph TD"]

    for i, phase in enumerate(chain):
        tactic = _escape(tactic_label(phase.get("tactic")))
        lines.append(f'    subgraph p{i}["{tactic}"]')
        for j, technique in enumerate(phase.get("techniques") or []):
            attack_id = _escape(technique.get("attack_id") or "-")
            count = technique.get("occurrence_count")
            name = _escape(_truncate(technique.get("name") or "", TECHNIQUE_NAME_CHAR_LIMIT))
            heading = f"{attack_id} ({count})" if count else attack_id
            lines.append(f'        p{i}t{j}["{_label(heading, name)}"]')
        lines.append("    end")
        if i:
            lines.append(f"    p{i - 1} --> p{i}")

    return "\n".join(lines)
