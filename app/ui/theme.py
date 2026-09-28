"""Arayuzun gorsel dili: tek yerde duran CSS katmani ve durum rozetleri.

Renk sozlesmesi (bkz. .streamlit/config.toml):
    mavi      YALNIZCA kontrol vurgusu -- dugme, secim, baglanti
    kirmizi / turuncu / sari / yesil
              YALNIZCA durum anlami -- karar, siddet, guven, ajan hukmu
Iki rol karisirsa her dugme alarm gibi gorunur; eski temada birincil renk
kirmiziydi ve tam olarak bu oluyordu.

Yazi tipi sistem yigini: dis kaynaktan yazi tipi YUKLENMEZ, arayuz
cevrimdisi / hava bosluklu ortamda da ayni gorunur.

Rozet eslemeleri yalnizca GOSTERIMDIR: hangi degerin hangi renge dustugu
analiz sonucunu degistirmez."""

from __future__ import annotations

import streamlit as st

FONT_STACK = "'Segoe UI', system-ui, -apple-system, 'Helvetica Neue', Arial, sans-serif"
MONO_STACK = "'Cascadia Mono', 'Consolas', ui-monospace, 'SFMono-Regular', monospace"

_CSS = f"""
<style>
html, body, [class*="css"], .stMarkdown, .stText, button, input, textarea, select {{
    font-family: {FONT_STACK} !important;
}}
code, pre, .stCode, [data-testid="stCode"] * {{
    font-family: {MONO_STACK} !important;
}}
[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1400px; }}

h1, h2, h3, h4 {{ font-weight: 600 !important; letter-spacing: -0.01em; border: none !important; }}
h2 {{ font-size: 1.45rem !important; }}
h4 {{ font-size: 1.02rem !important; margin-top: 0.2rem !important; }}

[data-testid="stCaptionContainer"], .stCaption {{ color: #a1a1aa !important; }}
[data-testid="stMetricLabel"] {{ color: #a1a1aa !important; }}
[data-testid="stMetricValue"] {{ font-size: 1.5rem !important; font-weight: 600 !important; }}

button, [data-testid="stBaseButton-primary"] {{ box-shadow: none !important; }}
[data-testid="stExpander"] details {{ border-radius: 8px; }}
[data-testid="stExpander"] summary p {{ font-weight: 500; }}
[data-testid="stTabs"] [data-baseweb="tab"] p {{ font-weight: 500; }}

.st-key-app_header {{ margin-bottom: 0.4rem; }}
.st-key-empty_state p {{ color: #a1a1aa; }}
</style>
"""


def apply_theme() -> None:
    """CSS katmanini sayfaya ekler. Her yeniden calistirmada cagrilmali."""
    st.markdown(_CSS, unsafe_allow_html=True)


# --- durum rozetleri --------------------------------------------------------

CONFIDENCE_COLOR = {"high": "green", "medium": "yellow", "low": "orange", "insufficient": "red"}
CONFIDENCE_LABEL = {"high": "yüksek", "medium": "orta", "low": "düşük", "insufficient": "yetersiz"}

SEVERITY_COLOR = {"Low": "green", "Medium": "yellow", "High": "orange", "Critical": "red"}

DECISION_COLOR = {
    "SUFFICIENT_SUSPICIOUS": "red",
    "INSUFFICIENT_DATA": "orange",
    "SUFFICIENT_BENIGN": "green",
}

VERDICT_COLOR = {"confirm": "green", "downgrade": "orange", "reject": "red", "abstain": "gray"}


def _rozet_metni(metin: str) -> str:
    """Markdown rozet yonergesini bozan koseli parantezleri yumusatir."""
    return str(metin).replace("[", "(").replace("]", ")")


def md_badge(label: str, color: str = "gray") -> str:
    """Satir ici markdown rozeti (`:renk-badge[metin]`)."""
    return f":{color}-badge[{_rozet_metni(label)}]"


def confidence_badge(level: str | None) -> str:
    level = (level or "").lower()
    return md_badge(f"güven: {CONFIDENCE_LABEL.get(level, level or '—')}", CONFIDENCE_COLOR.get(level, "gray"))


def section(title: str, caption: str | None = None) -> None:
    """Bolum basligi: kucuk, tutarli, cizgisiz."""
    st.markdown(f"#### {title}")
    if caption:
        st.caption(caption)
