"""QRadar icin TASLAK tespit kurali uretir (QRadar Rule Wizard'in "Rule Summary"
formatina benzer duz metin -- AQL degil).

Felsefe: projedeki genel ilkeyle tutarli olarak (bkz. app/validation/validator.py),
LLM'e QRadar syntax'ini serbestce yazdirmiyoruz. Kural tamamen kod-tarafli,
normalize_input()'un (app/normalization/input_parser.py) girdiden cikardigi somut
alanlardan (event_id, process_name, command_line, user_account, remote_ips) ve
validator'in resmi MITRE verisiyle onayladigi mapping'den (attack_id, name,
detection_recommendation) insa edilir. Kanit yoksa None doner -- bos/uydurma bir
kural gosterilmez.

Onemli sinirlama: QRadar'daki custom property adlari ("Process Name",
"Command Line" gibi) musterinin DSM/log source uzantisina gore degisir.
Burada kullanilanlar en yaygin Windows Sysmon/Security-Auditing eslemeleridir;
gercek ortamda dogrulanmadan production kuralina alinmamalidir -- bu yuzden
sonuc hep 'notes' alaninda acikca TASLAK olarak isaretlenir.
"""

from __future__ import annotations

from typing import Any


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


# --------------------------------------------------------- incident seviyesi

# Korelasyon anahtari olarak tercih sirasi. Hostname once geliyor: bir
# saldirinin asamalari cogunlukla AYNI MAKINEDE gorunur, kullanici hesabi ise
# asama degistirebilir (hesap atfi -- saldirgan baska hesaba gecebilir).
_CORRELATION_KEYS = [
    ("Hostname", "Hostname"),
    ("SubjectUserName", "Username"),
]

# Zaman penceresi icin alt/ust sinir. Alt sinir: cok dar bir pencere
# gercek ortamdaki saat kaymasiyla kuralin hic tetiklenmemesine yol acar.
# Ust sinir: 24 saatten genis bir korelasyon penceresi QRadar'da pahalidir
# ve "ayni saldiri" iddiasini zayiflatir.
_MIN_WINDOW_MINUTES = 15
_MAX_WINDOW_MINUTES = 24 * 60


def _window_minutes(timeline: list[dict[str, Any]]) -> int:
    """Incident'in gercek zaman araligindan pencere turetir.

    Neden sabit 60 dakika degil: incident 6 saate yayildiysa 1 saatlik bir
    pencere ayni olay orgusunu bir daha yakalayamaz. Gercek araligi olcup
    uzerine pay birakiyoruz."""
    stamps = sorted(e["timestamp"] for e in timeline if e.get("timestamp"))
    if len(stamps) < 2:
        return _MIN_WINDOW_MINUTES

    span_seconds = (stamps[-1] - stamps[0]).total_seconds()
    # %50 pay: kural, gozlemlenen orgunun biraz daha yavas tekrarini da
    # yakalayabilmeli.
    minutes = int(span_seconds / 60 * 1.5) + 1
    return max(_MIN_WINDOW_MINUTES, min(minutes, _MAX_WINDOW_MINUTES))


def build_incident_qradar_rule(
    incident: dict[str, Any], rows_by_index: dict[int, dict[str, Any]]
) -> dict[str, Any] | None:
    """Bir incident'in TAMAMINDAN korelasyonlu taslak kural uretir.

    TEKLI KURALDAN FARKI VE ASIL DEGERI
        build_qradar_rule_draft tek bir olaydan tek bir kural cikarir; o kural
        production'da gurultu yapar, cunku "schtasks calisti" tek basina
        supheli degildir. Buradaki kural ise CAKISMA arar: ayni makinede,
        ayni zaman penceresinde, BIRDEN FAZLA asamaya ait olaylar. Yanlis
        pozitifi dusuren sey teknik listesi degil, bu esik.

    KAYNAK: yalnizca kod tarafi. Teknikler dogrulama katmanindan gecmis
    guclu bulgulardan (incident["techniques"]), artefactlar ise ham
    satirlardan geliyor. LLM'e QRadar syntax'i yazdirilmiyor -- projenin
    genel ilkesi (bkz. modul basligi).

    ZAYIF SINYALLER DISARIDA: incident["weak_techniques"] bilerek
    kullanilmiyor. Analist dogrulamasi bekleyen bir sinyalden production
    alarmi uretmek, zayifligi gorunmez kilardi.

    Donus: taslak kural, ya da korelasyonlu bir kurali hakli cikaracak
    kadar malzeme yoksa None."""
    techniques = incident.get("techniques") or []
    if len(techniques) < 2:
        # Tek teknikli bir incident icin korelasyon kurali kurmak yanlis
        # olurdu: "birden fazla asama" iddiasi yok. Tekli kural zaten var.
        return None

    row_indices = incident.get("row_indices") or []
    rows = [rows_by_index[i] for i in row_indices if i in rows_by_index]
    if not rows:
        return None

    event_ids = sorted({
        str(r.get("EventID")).strip() for r in rows if str(r.get("EventID") or "").strip()
    })
    processes = sorted({
        _basename(str(r["NewProcessName"])).lower()
        for r in rows
        if str(r.get("NewProcessName") or "").strip()
    })
    if not event_ids and not processes:
        return None

    # Korelasyon anahtari: incident'te gercekten sabit kalan alan.
    correlation_field = None
    correlation_value = None
    for row_key, qradar_property in _CORRELATION_KEYS:
        values = {
            str(r[row_key]).strip() for r in rows if str(r.get(row_key) or "").strip()
        }
        if len(values) == 1:
            correlation_field = qradar_property
            correlation_value = values.pop()
            break

    window = _window_minutes(incident.get("timeline") or [])
    # Esik: incident'teki asama sayisi kadar, en fazla 3. Ucten yukarisi
    # kurali fazla ozel yapar -- ayni saldirinin bir asamasi eksik
    # goruldugunde hic tetiklenmez.
    threshold = min(len(techniques), 3)

    host = incident.get("hostname") or "bilinmeyen host"
    rule_name = (
        f"[{incident.get('id', 'INC')}] Cok Asamali Supheli Aktivite - {host} (Taslak)"
    )

    tests: list[str] = []
    if correlation_field:
        tests.append(
            f"and when at least {threshold} events are seen with the same "
            f"{correlation_field} in {window} minutes"
        )
    else:
        # Sabit bir korelasyon alani yoksa bunu SAKLAMIYORUZ -- kural yine
        # uretiliyor ama analistin anahtari elle secmesi gerektigi notlarda
        # acikca yaziyor.
        tests.append(
            f"and when at least {threshold} events are seen in {window} minutes "
            "(korelasyon alanini elle secin -- bkz. notlar)"
        )

    if event_ids:
        tests.append(
            "and when the EventID is one of the following: " + ", ".join(event_ids)
        )
    if processes:
        tests.append(
            "and when the Process Name contains any of the following: "
            + ", ".join(f'"{p}"' for p in processes)
        )

    rule_lines = [
        f'Apply "{rule_name}" on events which are detected by the Local system',
        *tests,
    ]

    technique_lines = [
        f"- {t.get('attack_id')} {t.get('name') or ''}".rstrip()
        + f" ({t.get('occurrence_count', 0)} kayıt, güven: {t.get('confidence_level') or '-'})"
        for t in techniques
    ]

    notes = [
        "Bu bir TASLAKTIR -- production'a almadan önce QRadar ortamınızdaki gerçek custom "
        "property adlarını (EventID, Process Name, Hostname, Username) doğrulayın.",
        f"Zaman penceresi ({window} dk) bu incident'in gözlenen süresinden türetildi, "
        "sabit bir değer değil. Ortamınızdaki normal aktivite yoğunluğuna göre ayarlayın.",
        f"Eşik ({threshold} olay) incident'teki doğrulanmış teknik sayısından geliyor. "
        "Düşürmek yanlış pozitifi artırır, yükseltmek kuralı fazla özel yapar.",
    ]
    if not correlation_field:
        notes.append(
            "UYARI: Bu incident'te tüm satırlarda sabit kalan bir Hostname/Username "
            "bulunamadı, bu yüzden korelasyon anahtarı boş bırakıldı. Kuralı "
            "kullanmadan önce ortamınıza uygun bir anahtar (Hostname, Username, "
            "Source IP...) seçmelisiniz -- anahtarsız kural tüm ortamda sayım yapar."
        )
    if incident.get("weak_techniques"):
        notes.append(
            f"Bu incident'te {len(incident['weak_techniques'])} zayıf sinyal daha var; "
            "doğrulama beklediği için kurala DAHIL EDİLMEDİ."
        )

    return {
        "rule_name": rule_name,
        "rule_text": "\n".join(rule_lines),
        "techniques": technique_lines,
        "window_minutes": window,
        "threshold": threshold,
        "correlation_field": correlation_field,
        "correlation_value": correlation_value,
        "notes": notes,
    }


def build_qradar_rule_draft(mapping: dict[str, Any], normalized: dict[str, Any]) -> dict[str, Any] | None:
    """Donus: taslak kural bilgisi, ya da yeterli somut alan yoksa None."""
    process_name = normalized.get("process_name")
    command_line = normalized.get("command_line")
    event_id = normalized.get("event_id")
    user_account = normalized.get("user_account")
    remote_ips = normalized.get("remote_ips") or []
    detected_tools = normalized.get("detected_tools") or []
    platform = normalized.get("platform")
    is_remote = normalized.get("is_remote")

    tool_terms = [_basename(process_name)] if process_name else list(detected_tools)
    if not tool_terms and not command_line and not event_id:
        return None

    attack_id = mapping.get("attack_id", "?")
    name = mapping.get("name", "?")
    rule_name = f"[{attack_id}] {name} - Olasi Gozlem (Taslak)"

    tests: list[str] = []
    extra_notes: list[str] = []

    if platform:
        tests.append(f'and when the Log Source Type is one of the following: {platform}')

    if process_name:
        basename = _basename(process_name)
        tests.append(f'and when the Process Name contains "{basename}"')
    elif tool_terms:
        term_list = " or ".join(f'"{t}"' for t in tool_terms)
        tests.append(f"and when the Process Name contains one of the following: {term_list}")

    if command_line:
        snippet = command_line[:80]
        tests.append(f'and when the Command Line contains "{snippet}"')

    if remote_ips:
        ip_list = ", ".join(remote_ips)
        tests.append(f"and when the Destination IP is one of the following: {ip_list}")
    elif is_remote:
        tests.append(
            "and when the destination host/IP matches the remote target "
            "(metinden dogrudan cikarilamadi -- log kaynaginizdaki ilgili alani manuel ekleyin)"
        )

    if user_account:
        tests.append(f'and when the Username is one of the following: {user_account}  (opsiyonel baglam filtresi)')

    if event_id:
        extra_notes.append(
            f"Windows Event ID {event_id} de bu olaya ait olmali -- DSM'inizin bunu ayri bir "
            "custom property olarak (orn. \"EventID\") sunup sunmadigini kontrol edin."
        )

    rule_lines = [
        f'Apply "{rule_name}" on events which are detected by the Local system',
        "and when at least 1 events matched by the following rule in the last 1 hours:",
        *tests,
    ]
    rule_text = "\n".join(rule_lines)

    notes = [
        "Bu bir TASLAKTIR -- production'a almadan once QRadar ortaminizdaki gercek custom "
        "property adlarini (Process Name, Command Line, EventID vb.) dogrulayin.",
        "Degerler yalnizca bu tek girdiden cikarildi; genel bir kural icin process/komut "
        "satiri varyasyonlarini genisletmeniz gerekir.",
        f"Resmi MITRE tespit onerisi: {mapping.get('detection_recommendation') or '-'}",
        *extra_notes,
    ]
    if mapping.get("confidence_level") in {"low", "insufficient"}:
        notes.append(
            f"Bu eslestirmenin guven seviyesi '{mapping.get('confidence_level')}' -- kurali "
            "olusturmadan once analist dogrulamasi kesinlikle onerilir."
        )

    return {
        "rule_name": rule_name,
        "rule_text": rule_text,
        "notes": notes,
    }
