"""Bir analiz sonucunu (run_improved_query/run_baseline_query'nin dondurdugu
result dict'i) Streamlit'te render eden paylasilan fonksiyon.

Hem tekli analiz akisi hem de toplu (CSV/JSON) analiz akisi ayni sonuc
seklini uretiyor -- render mantigini burada tek yerde tutmak ~100 satirlik
kodun iki yerde tekrarlanmasini onluyor.

YERLESIM: en ustte karar karti (analiste once "bakmali miyim" cevabi), altinda
dort sekme -- Eslestirmeler / Kanit ve gerekce / Dogrulama / Teknik detay.
Eskiden butun bolumler alt alta ve dordu acik geliyordu; hicbir bilgi
kaldirilmadi, yalnizca gruplandi."""

from __future__ import annotations

from typing import Any

import streamlit as st

from app.llm.ollama_client import usage_since, usage_snapshot
from app.llm.translator import lookup_reference_translation, translate_reference_texts
from app.ui.theme import DECISION_COLOR, confidence_badge, md_badge, section


#: Markdown'da anlam tasiyan ve kanit metinlerinde GERCEKTEN gecen isaretler.
#: `*.evtx deletion` (EVIDENCE_REQUIREMENTS'ta duruyor) bunun canli ornegi.
_MARKDOWN_ISARETLERI = "\\`*_{}[]()#+-.!|"


def _duz_metin(deger: Any) -> str:
    """Veriyi markdown olarak DEGIL, metin olarak basar.

    NEDEN: `st.write(f"- {item}")` item'i markdown'a sokuyor. Kanit terimleri
    veri, bicimlendirme degil -- `*.evtx deletion` icindeki yildiz vurgu
    acmaya calisiyor ve terim ekranda oldugu gibi gorunmuyor."""
    metin = str(deger)
    return "".join("\\" + ch if ch in _MARKDOWN_ISARETLERI else ch for ch in metin)


def _madde_listesi(ogeler: Any, bos_metin: str) -> None:
    """Madde listesi cizer; BOS madde CIZMEZ.

    Iki ayri kusuru birden kapatiyor:
      1. Bos/yalnizca-bosluk oge `st.write("- ")` uretiyordu -- ekranda
         icerigi olmayan bir madde isareti.
      2. Liste bosken yer tutucu `["-"]` idi ve `- -` olarak basiliyordu;
         bu da bos bir madde gibi goruluyor. Yer tutucu artik madde degil,
         acikca yazilmis bir not."""
    dolu = [o for o in (ogeler or []) if str(o).strip()]
    if not dolu:
        st.caption(bos_metin)
        return
    for oge in dolu:
        st.write(f"- {_duz_metin(oge)}")


def _render_detection_recommendation(mapping: dict[str, Any]) -> None:
    """MITRE'nin resmi tespit onerisini gosterir; Turkcesi hazirsa onu kullanir.

    Ceviri CIZIM SIRASINDA yapilmaz. Olculdu: elle cevrilmemis bir teknigin
    LLM cevirisi 190 saniyeye kadar cikabiliyor. Eskiden bu cagri her mapping
    icin cizim sirasinda yapiliyordu ve toplu analizde (51 satir) sayfa
    pratikte hic tamamlanmiyordu: satirlar tek tek dusuyor, arkadaki incident
    sekmesine sira gelmiyordu. Streamlit expander'larinin ICERIGI kapaliyken
    de calistigi icin kullanici hicbir detayi acmasa bile bu bedel odeniyordu.

    Simdi: hazir ceviri (elle hazirlanmis dosya ya da bu oturumda cevrilmis)
    aninda gosteriliyor; yoksa orijinal Ingilizce metin gosterilip ceviri
    kullanicinin acik istegine birakiliyor."""
    original = mapping["detection_recommendation"]
    attack_id = mapping.get("attack_id", "?")
    translated = lookup_reference_translation(original)

    if translated:
        st.caption("Resmî MITRE verisi — Türkçeye çevrildi")
        st.info(translated)
        with st.expander("Orijinal MITRE metni (İngilizce)"):
            st.write(original)
        return

    st.caption("Resmî MITRE verisi — LLM tarafından üretilmedi")
    st.info(original)
    if st.button("Türkçeye çevir", key=f"translate_detection_{attack_id}"):
        with st.spinner("Yerel LLM ile çevriliyor… (bir dakikadan uzun sürebilir)"):
            translate_reference_texts([original])
        # Sonuc onbellege girdi; yeniden cizimde ustteki daldan Turkce gelecek.
        st.rerun()


def _render_decision(
    decision: dict[str, Any] | None,
    benign_signals: list[str],
    result: dict[str, Any],
    elapsed: float | None,
) -> None:
    """Sonucun EN USTUNDE karar karti + GEREKCE ZINCIRI (Gorev 5).

    Konumu bilincli: eskiden ekranin ilk gordugu sey ATT&CK eslestirmeleriydi,
    yani mesru bir yonetim faaliyeti bile once "saldiri teknigi" olarak
    goruntuye giriyordu. Karari basa almak, analiste once "bakmali miyim"
    sorusunun cevabini veriyor.

    ZINCIR GOSTERILMEK ZORUNDA. Karar artik LLM'in bir cumlesi degil, bes
    girdiden uretilen bir sonuc; hangi girdinin ne yaptigi gorulmezse
    denetlenemez bir kutu olur. Analistin itiraz edebilmesi Gorev 5'in
    gerekcesiydi. Bu yuzden zincir kartin icinde ACIK gelir."""
    # Anahtar (key) BILEREK yok: toplu modda ayni fonksiyon birden fazla
    # satir icin ayni sayfada cizilir ve sabit anahtar cakisirdi.
    with st.container(border=True):
        if decision:
            karar = decision.get("decision")
            label = decision.get("label") or karar
            reason = decision.get("reason") or ""
            st.markdown(
                f"{md_badge(label, DECISION_COLOR.get(karar, 'gray'))}&nbsp;&nbsp;{_duz_metin(reason)}"
            )
        else:
            karar = None
            # Karar yoksa sebep iki olabilir: baseline sistemin karar katmani
            # yoktur, ya da gelistirilmis hat bu girdide hata verdi. Hangisi
            # oldugu burada bilinmiyor; biri varsayilip yazilmaz.
            st.markdown(md_badge("Karar üretilmedi", "gray"))
            st.caption("Baseline sistemin karar katmanı yoktur; geliştirilmiş hatta bu, analizin tamamlanamadığı anlamına gelir.")

        kabul = len(result.get("mappings") or [])
        elenen = len(result.get("agent_rejected_mappings") or [])
        cols = st.columns(4)
        cols[0].metric("Kabul edilen teknik", kabul)
        cols[1].metric("Ajanlarca elenen", elenen)
        cols[2].metric("Süre", f"{elapsed:.1f} sn" if elapsed is not None else "—")
        cols[3].metric("ATT&CK sürümü", result.get("attack_version") or "—")

        if not decision:
            return

        zincir = decision.get("reason_chain") or []
        if zincir:
            with st.expander("Gerekçe zinciri — hangi girdi bu sonucu verdi", expanded=True):
                for adim in zincir:
                    st.write(f"- {adim}")
                girdiler = decision.get("inputs") or {}
                st.caption(
                    "Girdiler: "
                    f"kritiklik={girdiler.get('kritiklik')} "
                    f"({girdiler.get('kritiklik_ailesi') or '—'}) · "
                    f"erişim={girdiler.get('erisim_sinifi') or '—'} · "
                    f"doğrulanmış kanıt={girdiler.get('dogrulanmis_kanit')} · "
                    f"aktör={(girdiler.get('aktor') or {}).get('process') or '—'}"
                    f"/{(girdiler.get('aktor') or {}).get('account') or '—'}"
                )

        # ALARM SEVIYESI (Gorev 14): girdi birden fazla olay tasiyorsa karar
        # "en sert kazanir" ile verilir ve HANGI event'in verdigi gosterilmek
        # ZORUNDA. "SUSPICIOUS" demek analiste itiraz edilebilir bir sey
        # soylememektir; "alarm supheli, cunku event #1 supheli" itiraz
        # edilebilir bir cumledir.
        event_kararlari = decision.get("event_kararlari") or []
        if len(event_kararlari) > 1:
            dagilim = decision.get("dagilim") or {}
            with st.expander(
                f"Alarm {len(event_kararlari)} olaya bölündü — "
                f"kararı event #{decision.get('belirleyen_event')} verdi",
                expanded=True,
            ):
                for olay in event_kararlari:
                    isaret = "◀" if olay["index"] == decision.get("belirleyen_event") else " "
                    bastirma = " · bastırıldı" if olay.get("suppression") else ""
                    st.write(
                        f"{isaret} **event #{olay['index']}** — {olay['decision']}"
                        f"{bastirma}: {olay.get('reason') or ''}"
                    )
                st.caption(
                    "Sıralama: ŞÜPHELİ > YETERSİZ VERİ > MEŞRU. Bir alarm ancak "
                    "**her** event'i meşruysa meşru okur; bastırma event "
                    "seviyesinde kalır ve alarma yayılmaz. Dağılım: "
                    + ", ".join(f"{k}={v}" for k, v in dagilim.items() if v)
                )

        bolme = decision.get("split") or {}
        if bolme.get("warning"):
            st.warning(bolme["warning"])

        if decision.get("suppression"):
            st.caption(
                "Bu karar **aktör baseline'ı** tarafından bastırıldı — yalnızca "
                "kritiklik+erişim yolu bastırılabilir; doğrulanmış kanıta dayanan "
                "bulgular bastırılamaz."
            )

        if benign_signals:
            with st.expander("Meşruiyet belirtileri (yalnızca bilgi — karara girmez)"):
                for signal in benign_signals:
                    st.write(f"- {signal}")
                st.caption(
                    "Bu belirtiler ham metinden çıkarılır ve **karar girdisi değildir**: "
                    "taklit edilebilirler (ölçüldü — aktör olmayan bir alana konan "
                    "dize sinyali tersine çeviriyordu). Karar yapısal alanlardan verilir."
                )

        if karar != "SUFFICIENT_SUSPICIOUS":
            st.caption(
                "Eşleştirmeler **bilgi amaçlı** gösteriliyor — "
                "bu karara göre alarm üretilmemeli."
            )


def _render_token_usage(result: dict[str, Any], usage_before_render: dict[str, int]) -> None:
    """Bu girdi için harcanan toplam token'ı küçük bir satır olarak yazar.

    İki kaynağı toplar: pipeline'ın kendi ölçtüğü eşleştirme çağrısı
    (result["token_usage"]) ve render sırasında yapılan çeviri çağrıları
    (bkz. _translate_for_display) — çeviri pipeline'ın dışında kaldığı için
    pipeline'ın döndürdüğü sayıya dahil değil.

    Toplam, result dict'inin içine geri yazılıyor: çeviri sonuçları önbelleğe
    alındığı için aynı sonuç ikinci kez çizildiğinde (kullanıcı soru sorunca,
    bir widget değişince) render deltası 0 olur; geri yazmasak ekrandaki sayı
    kendiliğinden küçülürdü."""
    usage = dict(result.get("token_usage") or {})
    render_usage = usage_since(usage_before_render)

    for key in ("prompt_tokens", "completion_tokens", "calls"):
        usage[key] = usage.get(key, 0) + render_usage.get(key, 0)
    usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
    result["token_usage"] = usage

    # Binlik ayraci nokta: Python'un varsayilan virgulu Turkce bir arayuzde
    # ondalik ayraci gibi okunuyor ("4,443 token" -> 4.4 token).
    def tr(n: int) -> str:
        return f"{n:,}".replace(",", ".")

    cols = st.columns(3)
    cols[0].metric("Toplam token", tr(usage["total_tokens"]))
    cols[1].metric("Girdi / üretim", f"{tr(usage['prompt_tokens'])} / {tr(usage['completion_tokens'])}")
    cols[2].metric("LLM çağrısı", usage["calls"])


def _render_mapping_card(m: dict[str, Any]) -> None:
    """Tek bir ATT&CK eslestirmesi: baslik satiri, iki sutunlu govde, alt sekmeler."""
    confidence = m.get("confidence_level", "?")
    with st.container(border=True):
        head_l, head_r = st.columns([3, 2], vertical_alignment="center")
        head_l.markdown(
            f"**`{m.get('attack_id')}`**&nbsp; **{_duz_metin(m.get('name') or '')}**"
            f"&nbsp;&nbsp;{md_badge(m.get('object_type') or 'technique', 'gray')}"
        )
        # Ham reranker skoru BILEREK gosterilmiyor. Normalize edilmemis
        # cross-encoder ciktisi sorgular arasi karsilastirilamaz: bir
        # logda 0.236 en iyi adayin skoruyken baska bir logda 0.047 en
        # iyi adayin skoru olabiliyor. Analist iki sayiyi yan yana
        # gorunce buyugunu "daha guvenilir" sanar; oysa farkli
        # dagilimlardan geliyorlar. Ayni sorgu icindeki siralamayi zaten
        # listenin sirasi anlatiyor.
        skor = ""
        if m.get("confidence_score") is not None:
            skor = (
                f"&nbsp;&nbsp;kompozit skor **{m['confidence_score']:.2f}** · "
                f"LLM'in bildirdiği: {m.get('llm_reported_confidence')}"
            )
        head_r.markdown(f"{confidence_badge(confidence)}{skor}")

        sol, sag = st.columns([3, 2], gap="large")
        with sol:
            st.markdown("**Gerekçe**")
            st.write(m.get("reasoning_summary", "-"))
            if m.get("evidence"):
                st.markdown("**Kanıtlar**")
                for e in m["evidence"]:
                    st.write(f"- {e}")
            evidence_check = m.get("evidence_check") or {}
            if evidence_check.get("applicable"):
                st.markdown("**Zorunlu kanıt kontrolü**")
                for t in evidence_check.get("found", []):
                    st.write(f"- Bulundu: {_duz_metin(t)}")
                for t in evidence_check.get("missing", []):
                    st.write(f"- Eksik: {_duz_metin(t)}")
        with sag:
            st.markdown("**Taktikler**")
            st.markdown(" ".join(md_badge(t, "blue") for t in m.get("tactics", [])) or "—")
            if m.get("data_components"):
                st.markdown("**İlgili veri bileşenleri**")
                st.write(", ".join(m["data_components"]))
            if m.get("source_url"):
                st.markdown(f"[Resmî ATT&CK sayfası ↗]({m['source_url']})")
            if m.get("validation_notes"):
                st.caption("Doğrulama katmanı düzeltmeleri: " + "; ".join(m["validation_notes"]))

        alt_basliklar = []
        if m.get("detection_recommendation"):
            alt_basliklar.append("Tespit önerisi")
        if m.get("mitigation_recommendations"):
            alt_basliklar.append("Önleme ve azaltma")
        if m.get("confidence_score") is not None:
            alt_basliklar.append("Güven bileşenleri")
        qradar_draft = m.get("qradar_rule_draft")
        if qradar_draft:
            alt_basliklar.append("QRadar kural taslağı")
        if not alt_basliklar:
            return

        sekmeler = dict(zip(alt_basliklar, st.tabs(alt_basliklar)))
        if "Tespit önerisi" in sekmeler:
            with sekmeler["Tespit önerisi"]:
                _render_detection_recommendation(m)
        if "Önleme ve azaltma" in sekmeler:
            with sekmeler["Önleme ve azaltma"]:
                st.caption("Resmî MITRE mitigation verisi")
                for mit in m["mitigation_recommendations"]:
                    st.write(f"- {mit.get('attack_id')}: {mit.get('name')}")
        if "Güven bileşenleri" in sekmeler:
            with sekmeler["Güven bileşenleri"]:
                bilesenler = m.get("confidence_components", {}) or {}
                st.dataframe(
                    [
                        {"Bileşen": ad, "Değer": round(float(v), 3) if isinstance(v, (int, float)) else v}
                        for ad, v in bilesenler.items()
                    ],
                    hide_index=True,
                )
        if "QRadar kural taslağı" in sekmeler:
            with sekmeler["QRadar kural taslağı"]:
                st.caption("Taslak — production öncesi doğrulanmalıdır.")
                st.code(qradar_draft["rule_text"], language=None)
                for note in qradar_draft["notes"]:
                    st.caption("Not: " + note)


def render_result(
    result: dict[str, Any],
    elapsed: float | None = None,
    include_agent_views: bool = False,
) -> None:
    """Sonuc ekrani. `include_agent_views` tekli modda ajan izini Dogrulama
    sekmesine koyar; toplu moddaki satir detayi eskisi gibi onsuz cizilir."""
    usage_before_render = usage_snapshot()

    _render_decision(
        result.get("decision"), result.get("benign_signals_display") or [], result, elapsed
    )

    mappings = result.get("mappings", [])
    tab_map, tab_kanit, tab_dogrulama, tab_teknik = st.tabs(
        [f"Eşleştirmeler ({len(mappings)})", "Kanıt ve gerekçe", "Doğrulama", "Teknik detay"]
    )

    with tab_map:
        if not mappings:
            with st.container(border=True):
                st.markdown("**Güvenilir bir eşleştirme yok**")
                st.caption(
                    "Yeterli kanıt bulunamadı veya güvenilir bir eşleştirme yapılamadı. "
                    "Bu geçerli bir sonuçtur — sistem kanıtı olmayan bir teknik üretmez. "
                    "Elenen adaylar ve gerekçeleri Doğrulama sekmesinde."
                )
        for m in mappings:
            _render_mapping_card(m)

    with tab_kanit:
        input_summary = result.get("input_summary", {})
        if input_summary.get("detected_platform") or input_summary.get("detected_tools"):
            section("Girdi normalizasyonu — çıkarılan gözlemler")
            with st.container(border=True):
                c1, c2, c3 = st.columns(3)
                c1.markdown(f"**Platform**  \n{input_summary.get('detected_platform') or '—'}")
                c2.markdown(f"**Araçlar**  \n{', '.join(input_summary.get('detected_tools') or []) or '—'}")
                c3.markdown(f"**Uzak sistem ilişkisi**  \n{'Evet' if input_summary.get('is_remote') else 'Hayır'}")
                if input_summary.get("observed_actions_heuristic"):
                    st.markdown("**Heuristik gözlemler**")
                    for a in input_summary["observed_actions_heuristic"]:
                        st.write(f"- {a}")

        if result.get("evidence_summary"):
            es = result["evidence_summary"]
            section(
                "Loglardan çıkarılan kanıt",
                "Bu bölüm tamamen kod tarafında üretilir; LLM çıktısı kullanılmaz. "
                "Bu yüzden 'varsayılan' listesi her zaman boştur — sistem logda "
                "olmayan hiçbir şeyi buraya eklemez.",
            )
            with st.container(border=True):
                st.write("**Tespit edilenler:**")
                _madde_listesi(es.get("detected"), "Girdiden hiçbir alan çıkarılamadı.")

                st.write("**Tespit edilmeyenler:**")
                _madde_listesi(
                    es.get("not_detected"),
                    "Eksik kanıt yok — hiçbir teknik zorunlu kanıt kontrolüne girmedi.",
                )

                st.write("**Varsayılanlar:** Yok")

        if result.get("observed_behaviors"):
            section("Gözlemlenen davranışlar (LLM analizi)")
            for b in result["observed_behaviors"]:
                st.write(f"- {b}")

        if result.get("filtered_observed_behaviors"):
            with st.expander(
                f"Filtrelenen davranışlar ({len(result['filtered_observed_behaviors'])}) — girdiden doğrulanamadı"
            ):
                for b in result["filtered_observed_behaviors"]:
                    st.write(f"- {b}")

        if result.get("additional_data_needed"):
            with st.expander("Önerilen ek veri"):
                for d in result["additional_data_needed"]:
                    st.write(f"- {d}")

    with tab_dogrulama:
        if include_agent_views:
            from app.ui.agent_view import render_agent_loop, render_agent_verification

            render_agent_verification(result)
            render_agent_loop(result)

        if result.get("rejected_mappings"):
            section(
                f"Doğrulama katmanının reddettikleri ({len(result['rejected_mappings'])})",
                "Şeffaflık için gösterilir: ID/isim/revoked/platform kontrolünden geçemeyen öneriler.",
            )
            for m in result["rejected_mappings"]:
                with st.container(border=True):
                    st.markdown(f"{md_badge('reddedildi', 'red')}&nbsp; **{m.get('attack_id')}** ({m.get('name')})")
                    for issue in m.get("validation_issues", []):
                        st.write(f"- {issue}")

        if result.get("alternative_candidates"):
            section("Alternatif adaylar")
            for alt in result["alternative_candidates"]:
                st.write(f"**{alt.get('attack_id')}** ({alt.get('name')}) — {alt.get('reason_not_selected')}")

        if not (
            (include_agent_views and (result.get("agent_decisions") or result.get("agent_rejected_mappings")))
            or result.get("rejected_mappings")
            or result.get("alternative_candidates")
        ):
            st.caption("Bu sonuç için doğrulama kaydı yok.")

    with tab_teknik:
        section("Token kullanımı (bu girdi için)")
        _render_token_usage(result, usage_before_render)
        with st.expander("Retrieval sonuçları (chunk kimlikleri)"):
            st.write(result.get("retrieved_chunk_ids", []))
        with st.expander("Performans metrikleri"):
            st.json(result.get("timings", {}))
