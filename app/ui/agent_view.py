"""Ajan katmaninin karar izini ekrana cizer (sartname Bolum 27 + 28).

Neden ayri bir bolum: dogrulama katmaninin DEGERI, ne kabul ettiginde degil
NE ELEDIGINDE ve NEDEN eledigende gorunur. Elenen teknikler gizlenirse
kullanici yalnizca "sistem az teknik buldu" gorur; gerekcelerle birlikte
gosterilirse "sistem sunu degerlendirdi ve su kanit eksikligi nedeniyle
disarida birakti" gorur. Ikincisi bir analiste is verir.

Tekli modda sonuc ekraninin "Dogrulama" sekmesinde cizilir
(bkz. app/ui/render.py::render_result)."""

from __future__ import annotations

from typing import Any

import streamlit as st

from app.ui.theme import VERDICT_COLOR, md_badge, section

_VERDICT_LABEL_TR = {
    "confirm": "onaylandı",
    "downgrade": "güven düşürüldü",
    "reject": "elendi",
    "abstain": "karar verilmedi",
}


def render_agent_loop(result: dict[str, Any]) -> None:
    """Agentic dongunun izi: kac tur donuldu, NEDEN donuldu, ne degisti.

    Dongu sessiz calisirsa kullanicinin gordugu tek sey "analiz uzun surdu"
    olur. Gerekcesiyle gosterilince, sistemin kendi sonucundan memnun
    kalmayip ikinci kez aradigi -- ve neye gore aradigi -- goruluyor."""
    trace = result.get("loop_trace") or []
    if not trace:
        return

    section(
        f"Agentic döngü — {len(trace)} ek tur",
        "Doğrulama katmanı sonucundan memnun kalmadığında hat, retrieval'ı **yeniden** "
        "çalıştırır: kanıtı çürütülen teknikler aday havuzundan düşürülür, böylece ilk "
        "turda eşik altında kalmış teknikler yükselir. Turlar **birikimlidir** — ikinci "
        "tur birincinin bulgularını silemez, yalnızca üzerine ekler "
        "(`app/agents/graph.py`).",
    )

    for entry in trace:
        tur = entry.get("pass")
        with st.container(border=True):
            st.markdown(f"{md_badge(f'{tur}. ek tur', 'blue')}&nbsp; {entry.get('reason') or '-'}")
            excluded = entry.get("excluded_attack_ids") or []
            if excluded:
                st.write(
                    "Aday havuzundan düşürülenler: "
                    + ", ".join(f"`{a}`" for a in excluded)
                )
            for reason in entry.get("agent_reasons") or []:
                st.caption(reason)


def render_agent_verification(result: dict[str, Any]) -> None:
    decisions = result.get("agent_decisions") or []
    rejected = result.get("agent_rejected_mappings") or []

    if not decisions and not rejected:
        return

    section(
        "Kontrol ajanları",
        "Dil modelinin seçtiği her teknik, tekniğe özel bir kontrol ajanından geçer. "
        "Ajanlar bir tekniği **onaylayabilir, güvenini düşürebilir veya eleyebilir** — "
        "ama yeni teknik ekleyemez ve güven yükseltemez. Bu sınır kodda zorlanır "
        "(`app/agents/runner.py`).",
    )

    accepted = result.get("mappings") or []
    col1, col2, col3 = st.columns(3)
    col1.metric("Kabul edilen", len(accepted), border=True)
    col2.metric("Elenen", len(rejected), border=True)
    col3.metric("Ajan kararı", len(decisions), border=True)

    if rejected:
        st.markdown("**Elenen teknikler**")
        for mapping in rejected:
            with st.container(border=True):
                st.markdown(
                    f"{md_badge('elendi', 'red')}&nbsp; "
                    f"**{mapping.get('attack_id')} — {mapping.get('name') or '-'}**"
                )
                st.write(mapping.get("agent_reason") or "-")
                st.caption(f"Karar veren: `{mapping.get('agent_id')}`")

    with st.expander(f"Tüm ajan kararları — denetim izi ({len(decisions)})"):
        st.caption(
            "Her karar gerekçesiyle birlikte saklanır — 'sistem bunu eledi ama neden "
            "bilmiyoruz' bir olay raporunda savunulamaz."
        )
        for decision in decisions:
            verdict = decision.get("verdict")
            st.markdown(
                f"{md_badge(_VERDICT_LABEL_TR.get(verdict, str(verdict)), VERDICT_COLOR.get(verdict, 'gray'))}"
                f"&nbsp; **{decision.get('attack_id')}** · `{decision.get('agent_id')}`"
            )
            st.caption(decision.get("reason") or "-")
