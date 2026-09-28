"""Toplu mod (incident) sohbeti: VERI SORGUSU, aciklama degil.

Tekli moddaki asistan (app/llm/chat_assistant.py) "bu teknik neden
secildi" sorusunu cevapliyor. Buradaki sorular baska: "hangi satirlardan
geldi", "11:28'de ne oldu", "risk neden 26", "neden 22 sinyal zayif".
CEVAPLAR ZATEN VERIDE -- modelin isi hesaplamak degil, bulmak.

NEDEN AYRI MODUL: `build_chat_context` tek satir analizinin sekline
bagli (`mappings`, `rejected_mappings`, `input_summary`). Incident
dict'inin anahtarlari bambaska (`row_indices`, `timeline`, `techniques`,
`weak_techniques`, `attack_chain`, `risk`, `ioc_summary`). Yeniden
kullanilan: `chat_turn` (tasima) ve arayuz dongusu deseni.

MODEL HESAPLAMAZ, ALINTILAR. Baglamdaki risk bolumu
`risk_score.breakdown_sentences` ciktisidir, esik cumlesi
`dedup.confidence_threshold_sentence`ten gelir -- yani sayilar baglama
ZATEN HESAPLANMIS girer. Prompt'taki yasak tek savunma degil; asil
savunma modelin sayiyi uretmek zorunda olmamasi.

BAGLAM BUTCESI OLCULDU (scripts/measure_bulk_chat_context.py, gercek
`prompt_eval_count`): kesintisiz baglam 7.169 token, butce 4.724.
Secilen P2 paketi: timeline gruplu, kapsam ciplak, zayiflar kompakt,
IOC baglam disi. Ayrintili olcum
`docs/beklenti_26_toplu_mod_sohbeti.md`.

Bu modul LLM CAGIRMAZ -- yalnizca baglam/prompt kurar ve butce hesabi
yapar, boylece agdan bagimsiz test edilebilir (tekli moddaki modulun
ayni deseni). Gercek cagri app/ui/bulk_view.py'de `chat_turn` ile.
"""

from __future__ import annotations

from typing import Any

from app.correlation.dedup import confidence_threshold_sentence
from app.correlation.risk_score import THRESHOLD_SENTENCE, breakdown_sentences
from app.correlation.tactic_labels import tactic_label
from app.correlation.technique_narrative import technique_sentence
from app.mapping.event_labels import event_label

CHAT_MODEL = "qwen3:8b"

# --- Butce -------------------------------------------------------------------
# app/llm/ollama_client.py::DETERMINISTIC_OPTIONS ile AYNI olmali. num_ctx
# BUYUTULMEYECEK: analiz hattiyla paylasiliyor ve VRAM 8GB (ayni kisit icin
# bkz. app/retrieval/reranker.py). Buyutmek Ollama'nin modeli tahliye
# etmesine ve timeout'a yol acar.
NUM_CTX = 6144
RESERVE_HISTORY = 720
RESERVE_ANSWER = 700

#: TASARIM butcesi: BAGLAM tek basina bunu asmamali. Gecmis ve yanit icin
#: yer birakmasi gerektigi varsayimiyla kuruldu; Ö1'in kapanis olcutu bu.
TOKEN_BUDGET = NUM_CTX - RESERVE_HISTORY - RESERVE_ANSWER  # 4724

#: CALISMA ZAMANI siniri: baglam + gecmis bunu asamaz.
#:
#: TOKEN_BUDGET ile karistirilmamali. Ilk yazimda calisma zamani kontrolu
#: TOKEN_BUDGET'a bakiyordu ve GECMISI IKI KEZ sayiyordu -- bir kez
#: RESERVE_HISTORY dusulerek, bir kez de uzerine eklenerek. Sonucu: ilk
#: mesajda bile "gecmis doldu" uyarisi. Yanlis alarm veren bir uyari,
#: uyari degil GURULTUDUR (madde 11).
INPUT_LIMIT = NUM_CTX - RESERVE_ANSWER  # 5444

#: Kaba token tahmincisinin bolen katsayisi.
#:
#: Gercek olcumde (7 bolum, qwen3:8b) karakter/token orani 1.94 ile 2.69
#: arasinda degisti. Tahminci ASLA AZ SAYMAMALI -- az sayan bir tahminci
#: tasmayi kacirir, cok sayan yalnizca erken uyarir. Bu yuzden bolen
#: olculen EN DUSUK orandan da kucuk secildi.
#: Sozlesme: tests/test_bulk_chat_assistant.py, olculen gercek sayilara
#: karsi (evaluation/results/bulk_chat_context.json).
CHARS_PER_TOKEN = 1.9

BULK_CHAT_SYSTEM_PROMPT_TEMPLATE = """Sen, asagida verilen TOPLU LOG ANALIZI \
sonucunu okuyan bir SOC asistanisin. Kullanici SIEM log okumayi yeni ogreniyor.

BU BIR VERI SORGUSUDUR, YENI BIR ANALIZ DEGIL. Sorularin cevaplari asagidaki
INCIDENT VERISI'nde ZATEN VAR. Senin isin hesaplamak degil, veride bulmak ve
sade bir Turkce ile soylemek.

KESIN YASAKLAR:
- Asagida GECMEYEN bir ATT&CK teknigi veya ID'si ONERME, ima etme, uydurma.
- Yeni bir eslestirme YAPMA. Hangi teknigin dogru oldugu zaten karara baglandi.
- Risk skorunu YENIDEN HESAPLAMA. Skor ve her bileseni asagida yazili --
  bir sayi sorulursa asagidakini AYNEN aktar, kendin toplama/carpma yapma.
- Asagida olmayan bir sayi, saat, satir numarasi veya IP URETME.
- Bir bilgi asagida yoksa "bu bilgi analiz sonucunda yok" de. TAHMIN ETME.

NASIL CEVAPLA:
- Kisa ve net. Turkce yaz.
- Bir teknikten bahsederken ATT&CK ID'sini ve adini birlikte ver.
- Cevabini hangi satirlardan/kayitlardan cikardigini soyle (satir numaralari
  asagida yazili).
- ATT&CK ID'lerini, teknik adlarini ve MITRE terminolojisini CEVIRME.
- BIR LISTE SORULURSA LISTENIN TAMAMINI VER. Kendi kendine eleme yapma,
  kisaltma, "vb." deme. Asagida 10 madde varsa 10'unu da yaz.

ZAYIF SINYALLER HAKKINDA -- BU AYRIM KRITIK:
Zayif sinyaller ELENMEDI. Sadece risk skoruna ve saldiri zincirine
GIRMEDILER; hepsi ekranda duruyor ve bir analistin dogrulamasini bekliyor.
"elendi", "elenmis", "cikarildi", "dogrulanmadi" DEME -- bunlarin hepsi
yanlis. Dogrusu: "kanit duzeyi esigin altinda kaldigi icin ana anlatiya
alinmadi". Neden zayif sayildiklari sorulursa ESIGI aktar (asagida
"Kanit duzeyi esigi" satirinda yazili), tahmin yurutme.

DEGERLENDIRILEMEYEN TAKTIK, "BULGU YOK" DEMEK DEGIL:
Bir taktik hem saldiri zincirinde gorulmus hem de "degerlendirilemeyen"
listesinde olabilir -- celiski degildir. Zincir, olay ID'si sart kosmayan
kurallardan da beslenir; kapsam ise o taktigi GORECEK olay ID'lerinin
veri setinde olup olmadigini soyler. Ikisi ayri sorudur; kapsam sorulursa
asagidaki kapsam listesini AYNEN kullan.

INCIDENT VERISI:
{context}
"""

#: Arayuzdeki hazir soru butonlari. Hepsinin cevabi baglamda VAR --
#: analist ne sorabilecegini bilsin diye.
SUGGESTED_QUESTIONS: tuple[str, ...] = (
    "Bu incident'te ne oldu?",
    "Risk neden Medium?",
    "Neden bu kadar çok sinyal zayıf sayıldı?",
    "Hangi taktikler değerlendirilemedi?",
)

#: Soruda bunlardan biri geciyorsa IOC ozeti baglama eklenir ve YER ACMAK
#: ICIN timeline cikarilir. Deterministik -- ikinci bir LLM turu YOK,
#: cunku ikinci tur sureyi ikiye katlar (kullanici siniri).
IOC_KEYWORDS: tuple[str, ...] = (
    "ioc", "artefakt", "artifact", "gosterge", "gösterge",
    "ip adres", "ip'ler", "ipler", "hash", "domain", "alan adi", "alan adı",
    "url", "dosya adi", "dosya adı", "zararli", "zararlı",
)


#: Kalibrasyonun cikabilecegi en yuksek oran. Olculen en yuksek oran 2.69
#: idi; tavan biraz uzerinde. Tavan OLMAZSA bozuk bir olcum (orn. Ollama
#: alani hic dondurmezse 0) tahminciyi KOR eder ve tasma sessizlesir --
#: yani tam da onlemeye calistigimiz sey olur.
MAX_CALIBRATED_RATIO = 3.0


def estimate_tokens(text: str, chars_per_token: float | None = None) -> int:
    """Kaba token tahmini -- gonderimden ONCE, cagriyi bosa harcamamak icin.

    Gercek sayim degildir; gercegi Ollama `prompt_eval_count` ile doner
    (bkz. ollama_client.usage_since). Kalibrasyonsuz hali bilerek FAZLA
    sayar."""
    ratio = CHARS_PER_TOKEN if chars_per_token is None else chars_per_token
    ratio = min(max(ratio, CHARS_PER_TOKEN), MAX_CALIBRATED_RATIO)
    return int(len(text) / ratio) + 1


def calibration_ratio(sent_text: str, actual_prompt_tokens: int) -> float | None:
    """Bir cagridan SONRA: gercekten gonderilen metnin olculmus oranı.

    NEDEN GEREKLI: sabit oranli tahminci gercek 4.558 token'lik baglami
    5.156 sanmisti (%13 fazla). Bu kadar fazla saymak, ikinci turda
    "gecmis doldu" YANLIS ALARMI verirdi -- her girdide yanan bir uyari,
    uyari degil gurultudur (madde 11).

    Ollama her cagrida gercek `prompt_eval_count`u donduruyor; onu bir
    dahaki tura tasimak bedava ve kendini duzelten bir olcumdur. Bozuk
    deger (0 veya negatif) gelirse None doner ve sabit oran korunur."""
    if actual_prompt_tokens <= 0 or not sent_text:
        return None
    return len(sent_text) / actual_prompt_tokens


def wants_ioc(question: str) -> bool:
    """Soru IOC/artefakt hakkinda mi? Deterministik, LLM turu harcamaz."""
    lowered = (question or "").casefold()
    return any(keyword in lowered for keyword in IOC_KEYWORDS)


# --- Baglam bolumleri (P2) ---------------------------------------------------


def _ozet(incident: dict[str, Any], techniques: list, weak: list) -> str:
    return "\n".join([
        f"INCIDENT {incident['id']} — sunucu: {incident.get('hostname') or '-'}, "
        f"kullanici: {incident.get('primary_user') or '-'}",
        f"{len(incident.get('row_indices') or [])} log kaydi, {len(techniques)} "
        f"dogrulanmis teknik, {len(weak)} zayif sinyal, "
        f"{len(incident.get('attack_chain') or [])} taktik asamasi",
        f"Analist ozeti: {incident.get('attack_summary') or '-'}",
    ])


def _teknikler(techniques: list, weak: list, sentences: dict[str, str]) -> str:
    """Guclu teknikler TAM, zayiflar KOMPAKT.

    Zayiflarin tamami zaten ekrandaki tabloda. "Neden zayif" sorusunun
    cevabi liste degil ESIK cumlesidir; o da asagida risk bolumunde."""
    lines = ["DOGRULANMIS TEKNIKLER (kanit duzeyi yeterli, zincire ve skora girdi):"]
    for t in techniques:
        lines.append(
            f"- {t['attack_id']} {t.get('name')} | taktikler: "
            f"{', '.join(tactic_label(x, with_english=False) for x in (t.get('tactics') or []))} "
            f"| guven: {t.get('confidence_level') or '-'} "
            f"| {t.get('occurrence_count')} kayit | satirlar: {t.get('source_row_indices')}"
        )
        if sentences.get(t["attack_id"]):
            lines.append(f"  Ne oldu: {sentences[t['attack_id']]}")
    if weak:
        lines.append(
            f"ZAYIF SINYALLER ({len(weak)} adet — ELENMEDILER, yalnizca skora ve "
            "zincire girmediler; tamami ekrandaki tabloda): "
            + ", ".join(f"{t['attack_id']} ({t.get('occurrence_count')} kayit)" for t in weak)
        )
    return "\n".join(lines)


def _timeline_gruplu(incident: dict[str, Any], parsed_rows: dict[int, dict]) -> str:
    """Ayni olayi anlatan satirlar TEK satirda toplanir.

    Gorev 25'in bulgusu: 5156/5158 kayitlari birbirinin tekrari ve bes
    ayri teknik ayni kaydi gerekce gosteriyor. Ayni cumleyi baglamda 51
    kez yazmak token yakmaktan baska bir sey yapmiyor -- olcum: 3.141 ->
    1.682 token (%46 dusus). Satir numaralari KORUNUYOR, cunku "hangi
    satirlardan geldi" bu sohbetin ana sorularindan biri."""
    gruplar: dict[str, list[int]] = {}
    saatler: dict[str, list[str]] = {}
    teknikler: dict[str, set[str]] = {}

    for entry in incident.get("timeline") or []:
        sahte = {
            "source_row_indices": [entry["row_index"]],
            "first_seen_timestamp": entry.get("timestamp"),
        }
        cumle = technique_sentence(sahte, parsed_rows) or event_label(entry.get("event_id")) or "-"
        govde = cumle.split(" · ", 1)[-1]
        saat = cumle.split(" · ", 1)[0] if " · " in cumle else None

        gruplar.setdefault(govde, []).append(entry["row_index"])
        if saat:
            saatler.setdefault(govde, []).append(saat)
        if entry.get("attack_id"):
            teknikler.setdefault(govde, set()).add(entry["attack_id"])

    lines = ["ZAMAN CIZELGESI (ayni olayi anlatan satirlar tek satirda toplandi):"]
    for govde, satirlar in gruplar.items():
        s = sorted(saatler.get(govde) or [])
        if not s:
            aralik = "saat yok"
        elif s[0] == s[-1]:
            aralik = s[0]
        else:
            aralik = f"{s[0]}-{s[-1]}"
        etiket = ""
        if teknikler.get(govde):
            etiket = " [" + ", ".join(sorted(teknikler[govde])) + "]"
        lines.append(
            f"- {aralik} | {govde} | {len(satirlar)} kayit, satirlar: {sorted(satirlar)}{etiket}"
        )
    return "\n".join(lines)


def _risk(incident: dict[str, Any], techniques: list) -> str:
    """Sayilar baglama ZATEN HESAPLANMIS girer -- modelin isi alintilamak.

    Bu bolum `risk_score.breakdown_sentences` ciktisidir; ekranda gorunen
    tablonun ta kendisi. Model toplama yapmak zorunda olmadigi icin
    yanlis toplayamaz."""
    risk = incident.get("risk") or {}
    lines = [f"RISK SKORU: {risk.get('score')}/100 ({risk.get('severity')})"]
    for ad, gerekce, katki in breakdown_sentences(risk, technique_count=len(techniques)):
        lines.append(f"- {ad}: {gerekce} -> {katki}")
    lines.append(THRESHOLD_SENTENCE)
    lines.append("Kanit duzeyi esigi: " + confidence_threshold_sentence().replace("**", ""))
    return "\n".join(lines)


def _kapsam(coverage_report: Any) -> str:
    """Olay ADLARI ve log kaynagi cumleleri EKRANDA duruyor; baglamda
    taktik + eksik ID yeterli (olcum: 1.594 -> 449 token)."""
    if coverage_report is None:
        return ""
    lines = [
        "TESPIT KAPSAMI — veri setinde bulunan olay ID'leri: "
        + ", ".join(coverage_report.dataset_event_ids),
        "Degerlendirilemeyen taktikler (veri olmadigi icin; bulgu yok DEMEK DEGIL) "
        "ve eksik olay ID'leri:",
    ]
    for tactic in coverage_report.unassessable:
        lines.append(
            f"- {tactic.tactic_name or tactic.tactic}: {', '.join(tactic.missing_event_ids)}"
        )
    lines.append(
        "Degerlendirilebilen taktikler: "
        + ", ".join((t.tactic_name or t.tactic) for t in coverage_report.assessable)
    )
    return "\n".join(lines)


def _ioc(incident: dict[str, Any]) -> str:
    ioc = incident.get("ioc_summary") or {}
    liste = ioc.get("ioc_list") or []
    if not liste:
        return "IOC OZETI: kayitlardan gosterge cikarilamadi."
    return "IOC OZETI: " + ", ".join(f"{i.get('type')}:{i.get('value')}" for i in liste)


def build_bulk_chat_context(
    incident: dict[str, Any],
    parsed_rows: dict[int, dict],
    coverage_report: Any = None,
    *,
    include_ioc: bool = False,
) -> str:
    """P2 paketi.

    include_ioc=True verilirse IOC ozeti eklenir ve YER ACMAK ICIN
    timeline CIKARILIR -- ikinci bir LLM turu acmadan, ayni turda.
    Timeline'in cikmasi kayipsiz degil; bunu prompt kullaniciya
    soyleyebilsin diye baglamda acikca yaziyor."""
    techniques = incident.get("techniques") or incident.get("deduped_techniques") or []
    weak = incident.get("weak_techniques") or []

    from app.correlation.technique_narrative import technique_sentences

    sentences = technique_sentences(list(techniques) + list(weak), parsed_rows)

    parts = [
        _ozet(incident, techniques, weak),
        _teknikler(techniques, weak, sentences),
    ]

    if include_ioc:
        parts.append(_ioc(incident))
        parts.append(
            "(Bu turda zaman cizelgesi baglamdan CIKARILDI, yerine IOC ozeti kondu. "
            "Zaman cizelgesi sorulursa kullaniciya yeni bir soru sormasini soyle.)"
        )
    else:
        parts.append(_timeline_gruplu(incident, parsed_rows))

    parts.append(_risk(incident, techniques))
    kapsam = _kapsam(coverage_report)
    if kapsam:
        parts.append(kapsam)

    return "\n\n".join(parts)


def build_bulk_chat_system_prompt(
    incident: dict[str, Any],
    parsed_rows: dict[int, dict],
    coverage_report: Any = None,
    *,
    include_ioc: bool = False,
) -> str:
    return BULK_CHAT_SYSTEM_PROMPT_TEMPLATE.format(
        context=build_bulk_chat_context(
            incident, parsed_rows, coverage_report, include_ioc=include_ioc
        )
    )


def budget_status(
    system_prompt: str,
    history: list[dict[str, str]],
    *,
    chars_per_token: float | None = None,
) -> dict[str, Any]:
    """Gonderimden ONCE: bu istek butceyi asiyor mu?

    Ollama num_ctx'i asan prompt'u SESSIZCE KIRPAR. Sessizce bozuk calisan
    bir katman istemiyoruz (madde 16) -- bu yuzden cagri yapilmadan once
    bakiliyor ve asiyorsa hic gonderilmiyor: hem yanlis cevap onlenir hem
    bosa 30 saniye harcanmaz."""
    prompt_tokens = estimate_tokens(system_prompt, chars_per_token)
    history_tokens = sum(
        estimate_tokens(m.get("content") or "", chars_per_token) for m in history
    )
    total = prompt_tokens + history_tokens
    return {
        "prompt_tokens": prompt_tokens,
        "history_tokens": history_tokens,
        "total": total,
        "budget": INPUT_LIMIT,
        "fits": total <= INPUT_LIMIT,
        "overflow": max(0, total - INPUT_LIMIT),
        "calibrated": chars_per_token is not None,
    }


def overflow_message(status: dict[str, Any]) -> str:
    """Analistin ekranda gorecegi uyari. Sayilar yazili -- "doldu" demek
    tek basina, neyin doldugunu soylemiyor."""
    return (
        f"**Sohbet geçmişi doldu, yeni sohbet başlatın.** "
        f"Bu soru için gereken bağlam {status['total']} token, "
        f"sınır {status['budget']}. Devam edilseydi model bağlamın bir "
        f"kısmını **sessizce kaybedecek** ve eksik veriyle cevap verecekti. "
        f"'Sohbeti temizle' düğmesi geçmişi sıfırlar; incident verisi aynı kalır."
    )


def actual_usage_warning(prompt_tokens: int) -> str | None:
    """Gonderimden SONRA: Ollama'nin dondurdugu GERCEK sayi
    (`prompt_eval_count`, bkz. ollama_client.usage_since).

    Tahminci fazla saymak uzere ayarli; buna ragmen gercek sayi butceyi
    asiyorsa tahminci yanilmis demektir ve bunu bilmemiz gerekir."""
    if prompt_tokens <= NUM_CTX:
        return None
    return (
        f"Son soruda modele giden gerçek token sayısı **{prompt_tokens}**, "
        f"pencere sınırı {NUM_CTX}. Bağlamın bir kısmı kırpılmış olabilir — "
        "bu cevaba temkinli yaklaşın ve yeni bir sohbet başlatın."
    )


def trim_history(
    history: list[dict[str, str]],
    system_prompt: str,
    *,
    chars_per_token: float | None = None,
) -> tuple[list[dict[str, str]], int]:
    """Pencereye sigmayan ESKI turlari dusurur; (kalan, dusen) doner.

    NEDEN MESRU: bunlar bagimsiz VERI SORGULARI, bir muhabbet degil.
    "T1205.002 hangi satirlardan geldi" sorusunun cevabi icin bir onceki
    sorunun cevabina ihtiyac yok. Baglam 4.558 token ve pencere 6.144
    oldugu icin gecmise ~1.600 token kaliyor -- tum gecmisi tasimak,
    ucuncu turda sohbeti bitirmek demekti.

    DUSEN TUR SESSIZ DEGIL: kac turun dustugu geri donuyor ve arayuz
    bunu yaziyor. Sessizce kirpmak, tam da bu gorevde onlemeye
    calistigimiz seydi (madde 16).

    EN SON TUR HER ZAMAN KORUNUR: kullanicinin SU ANKI sorusu dusurulurse
    model bambaska bir soruya cevap verir. Tek basina bile sigmiyorsa
    liste oldugu gibi doner ve budget_status "sigmiyor" der -- karar
    cagirana kalir, burada sessizce kirpilmaz."""
    if not history:
        return [], 0

    kalan_butce = INPUT_LIMIT - estimate_tokens(system_prompt, chars_per_token)

    # Sondan basa dogru, tur tur ekle.
    tutulan: list[dict[str, str]] = []
    harcanan = 0
    for message in reversed(history):
        maliyet = estimate_tokens(message.get("content") or "", chars_per_token)
        if tutulan and harcanan + maliyet > kalan_butce:
            break
        tutulan.append(message)
        harcanan += maliyet

    tutulan.reverse()
    return tutulan, len(history) - len(tutulan)
