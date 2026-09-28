"""MITRE ATT&CK Teknik Eslestirme Platformu - Streamlit arayuzu (dokuman bolum 28)."""

from __future__ import annotations

import sys
import time
import traceback
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.ingestion.attack_version import attack_version
from app.llm.chat_assistant import CHAT_MODEL, build_chat_system_prompt
from app.llm.ollama_client import chat_turn
from app.retrieval.baseline_pipeline import run_baseline_query
from app.retrieval.improved_pipeline import run_improved_query
from app.ui.bulk_view import render_bulk_mode
from app.ui.render import render_result
from app.ui.theme import apply_theme

st.set_page_config(page_title="MITRE ATT&CK Eşleştirme Platformu", layout="wide")
apply_theme()

# Arka uca giden DEGERLER. Degistirilmemeli: app/batch/orchestrator.py ve
# asagidaki tekli akis `startswith("Gelistirilmis")` ile sistem seciyor.
# Ekranda gorunen etiketler SYSTEM_LABELS'tan gelir.
SYSTEM_IMPROVED = "Gelistirilmis Sistem (hybrid retrieval + reranking + dogrulama)"
SYSTEM_BASELINE = "Baseline Sistem (yalnizca semantic search, dogrulama yok)"
SYSTEM_LABELS = {SYSTEM_IMPROVED: "Geliştirilmiş", SYSTEM_BASELINE: "Baseline"}

MODE_SINGLE = "Tekli analiz"
MODE_BULK = "Toplu analiz"


@st.cache_resource
def _warm_model() -> bool:
    """Uygulama acilirken modeli VRAM'e yukler -- sonucu KULLANILMAZ.

    Neden: olculdu (2026-08-16) ki modelin yuklu olup olmamasi ciktiyi
    DEGISTIRIYOR, yalnizca yavaslatmiyor. Ayni girdide soguk model
    'malicious_or_suspicious', sicak model 'insufficient_evidence' dedi
    (alti kosuluk iki kol, her kol kendi icinde 6/6 kararli).

    Isinma cagrisi olcum betiklerine eklenmisti ama UYGULAMAYA
    eklenmemisti; yani olculen sistem sicak, calistirilan sistem ilk
    istekte soguktu. Ollama'nin keep_alive varsayilani 5 dakika oldugu
    icin bu istisna degil, etkilesimli kullanimin normaliydi.

    st.cache_resource: oturum basina bir kez calisir, her yeniden
    calistirmada degil."""
    from app.evaluation.run_hygiene import warmup_model

    return warmup_model()


_MODEL_WARM = _warm_model()

# --- ust bilgi -------------------------------------------------------------
with st.container(key="app_header"):
    sol, sag = st.columns([3, 2], vertical_alignment="center")
    with sol:
        st.markdown("## MITRE ATT&CK Teknik Eşleştirme")
        st.caption(
            "Retrieval aday üretir, yerel LLM seçer, doğrulama katmanı neyin kalacağına "
            "karar verir. Kontrol ajanları bir tekniği eleyebilir ya da güvenini "
            "düşürebilir, ama yeni teknik ekleyemez."
        )
    with sag:
        with st.container(horizontal=True, horizontal_alignment="right", gap="small"):
            st.badge(f"ATT&CK {attack_version()}", color="blue")
            # Model yukleme durumu ciktiyi degistirdigi icin gorunur olmali.
            if _MODEL_WARM:
                st.badge("Model hazır", icon=":material/check:", color="green")
            else:
                st.badge(
                    "Model ısıtılamadı",
                    icon=":material/warning:",
                    color="orange",
                    help="İlk analiz soğuk modelle çalışır; sonuç sıcak modelden farklı olabilir.",
                )
            st.badge("Doğrulama açık", color="gray", help="Kanıt kapısı + teknik bazlı kontrol ajanları")

# --- kenar cubugu ----------------------------------------------------------
with st.sidebar:
    st.markdown("#### Ayarlar")
    mode = st.segmented_control(
        "Mod", [MODE_SINGLE, MODE_BULK], default=MODE_SINGLE, required=True, width="stretch"
    )
    system_choice = st.segmented_control(
        "Analiz sistemi",
        [SYSTEM_IMPROVED, SYSTEM_BASELINE],
        default=SYSTEM_IMPROVED,
        required=True,
        format_func=SYSTEM_LABELS.get,
        width="stretch",
        help=(
            "Geliştirilmiş: hybrid retrieval + reranking + doğrulama.  \n"
            "Baseline: yalnızca semantic search, doğrulama yok."
        ),
    )
    # Sartname Bolum 28: girdi turu ve platform secimi arayuzde ZORUNLU.
    if mode == MODE_SINGLE:
        input_type = st.selectbox(
            "Girdi türü",
            ["Doğal dil olay açıklaması", "Ham log / yapılandırılmış olay",
             "Detection kuralı / alarm açıklaması"],
        )
        platform_choice = st.selectbox("Platform", ["Otomatik tespit", "Windows", "Linux", "macOS"])
    st.divider()
    st.caption(f"ATT&CK sürümü: {attack_version()}")
    st.caption("Doğrulama: kanıt kapısı + teknik bazlı kontrol ajanları")
    st.caption(
        "Model: hazır (ısıtıldı)" if _MODEL_WARM else "Model: ısıtılamadı — ilk analiz soğuk çalışır"
    )
    st.caption("Çıkarım yerelde çalışır (Ollama); olay içeriği dışarı gönderilmez.")

if mode == MODE_BULK:
    render_bulk_mode(system_choice)
else:
    EXAMPLE_INPUTS = {
        "Örnek 1 — Ham log (zamanlanmış görev)": (
            "EventID=4688 NewProcessName=C:\\Windows\\System32\\schtasks.exe "
            "CommandLine=schtasks /create /s 10.10.20.15 /tn UpdateCheck /tr powershell.exe /sc onlogon "
            "SubjectUserName=service.admin"
        ),
        "Örnek 2 — Doğal dil (PowerShell)": "Bir PowerShell sureci internetten kod indirerek bellekte calistirdi.",
        "Örnek 3 — Tehdit istihbaratı (LSASS + lateral movement)": (
            "The actor dumped credentials from LSASS and later authenticated to remote systems "
            "using stolen administrative credentials."
        ),
        # Asagidaki ikisi MESRU aktivite -- sistemin alarm URETMEMESI gereken
        # durumlar. Ornek listesinde yalnizca saldirilar vardi; oysa bir SOC
        # ekibinin gordugu loglarin buyuk cogunlugu normal is ve sistemin asil
        # sinavi bunlarda sessiz kalabilmek (bkz. app/validation/benign_signals.py).
        # Ornek METINLERI degistirilmedi -- analize giden girdidir.
        "Örnek 4 — Meşru: onaylı değişiklik talebi": (
            "BT departmani, onayli bir degisiklik talebi (ticket #4521) kapsaminda her gece "
            "02:00'de calisan bir yedekleme gorevi olusturdu."
        ),
        "Örnek 5 — Meşru: Windows Update": (
            "EventID=4688 NewProcessName=C:\\Windows\\System32\\wuauclt.exe "
            "CommandLine=wuauclt.exe /detectnow SubjectUserName=SYSTEM"
        ),
    }

    with st.container(border=True):
        st.markdown("#### Girdi")
        selected_example = st.selectbox(
            "Örnek girdi (isteğe bağlı)", ["(Boş)"] + list(EXAMPLE_INPUTS.keys())
        )
        default_text = EXAMPLE_INPUTS.get(selected_example, "")
        user_input = st.text_area(
            "Güvenlik olayı açıklaması, ham log veya detection kuralı",
            value=default_text,
            height=140,
            placeholder="Örn. EventID=4688 NewProcessName=C:\\Windows\\System32\\schtasks.exe CommandLine=…",
        )
        with st.container(horizontal=True, horizontal_alignment="right"):
            analyze_clicked = st.button("Analiz et", type="primary", icon=":material/search:")

    if analyze_clicked and user_input.strip():
        platform_arg = None if platform_choice == "Otomatik tespit" else platform_choice

        try:
            with st.spinner(
                "Analiz ediliyor — yerel model yanıtı birkaç dakika sürebilir "
                "(ilk sorguda model yüklemesi nedeniyle daha uzun)…",
                show_time=True,
            ):
                t0 = time.time()
                if system_choice.startswith("Gelistirilmis"):
                    result = run_improved_query(user_input, platform=platform_arg)
                else:
                    result = run_baseline_query(user_input)
                elapsed = time.time() - t0
        except Exception as e:
            st.error(f"Analiz tamamlanamadı: {e}")
            with st.expander("Hata ayrıntısı"):
                st.code(traceback.format_exc(), language=None)
        else:
            st.session_state["last_result"] = result
            st.session_state["last_result_elapsed"] = elapsed
            st.session_state["last_analysis_input"] = user_input
            st.session_state["chat_history"] = []  # yeni analizde sohbet gecmisi sifirlanir
    elif analyze_clicked:
        st.warning("Lütfen analiz edilecek bir girdi metni girin.")

    if st.session_state.get("last_result"):
        result = st.session_state["last_result"]
        render_result(result, elapsed=st.session_state["last_result_elapsed"], include_agent_views=True)

        st.divider()
        st.markdown("#### Bu analiz hakkında soru sorun")
        st.caption(
            "Bu sohbet yalnızca yukarıdaki analiz sonucuna dayanır — yeni bir ATT&CK "
            "eşleştirmesi yapmaz, sadece mevcut sonucu açıklar."
        )

        for msg in st.session_state.get("chat_history", []):
            with st.chat_message(msg["role"]):
                st.write(msg["content"])

        user_question = st.chat_input(
            "Örnek: Bu eşleştirme neden T1053 oldu? / QRadar kural taslağını nasıl kullanırım?"
        )
        if user_question:
            st.session_state["chat_history"].append({"role": "user", "content": user_question})
            with st.chat_message("user"):
                st.write(user_question)

            with st.chat_message("assistant"):
                with st.spinner("Yanıt hazırlanıyor…"):
                    system_prompt = build_chat_system_prompt(result)
                    reply = chat_turn(CHAT_MODEL, system_prompt, st.session_state["chat_history"])
                st.write(reply)

            st.session_state["chat_history"].append({"role": "assistant", "content": reply})
    elif not analyze_clicked:
        with st.container(border=True, key="empty_state"):
            st.markdown("**Henüz analiz yok**")
            st.caption(
                "Bir örnek seçin ya da kendi girdinizi yapıştırın. Sonuçta şunlar görünür: "
                "karar ve gerekçe zinciri · kanıtıyla eşleşen ATT&CK teknikleri · "
                "doğrulama katmanının elediği adaylar · resmî MITRE tespit ve önleme verisi."
            )
