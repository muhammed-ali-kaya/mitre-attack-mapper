"""Girdi isleme ve davranis cikarimi (dokuman bolum 15) + sorgu zenginlestirme
(bolum 16). Kural tabanli / regex tabanli -- fine-tuning yok, deterministik.

Amac: ham log/metni dogrudan embedding modeline gondermek yerine, once
gozlemlenebilir alanlari cikarip (platform, process, komut, uzak/yerel) hem
LLM'e daha yapilandirilmis bir input_summary sunmak, hem de retrieval
sorgusunu bilinen ATT&CK terimleriyle zenginlestirmek.
"""

from __future__ import annotations

import re
from typing import Any

from app.normalization.formats import _MESSAGE_LABEL_RE, unescape_serialized
from app.normalization.path_normalizer import (
    looks_like_registry_path,
    normalize_registry_path,
)

EVENT_ID_RE = re.compile(r"EventID\s*[=:]\s*(\d+)", re.IGNORECASE)

# Tirnakli deger alternatifi ONCE gelmeli: bir yol bosluk iceriyorsa
# (orn. NewProcessName="...\program files\google\chrome\application\chrome.exe")
# yalnizca [^\s,]+ kullanmak degeri ilk bosluktan kesip "...\program" birakiyordu.
_QUOTED_OR_BARE = r'"(?:[^"\\]|\\.)*"|[^\s,]+'
PROCESS_NAME_RE = re.compile(rf"NewProcessName\s*[=:]\s*({_QUOTED_OR_BARE})", re.IGNORECASE)
# Tirnakli dal sondaki (?:\n|$) capasindan MUAF olmali: capa zorunlu oldugunda
# regex tirnakli eslesmeyi geri alip satir sonuna kadar yutuyordu -- yani
# CommandLine="cmd.exe /c whoami" SubjectUserName=jdoe girdisinde komut satirina
# kullanici alani da yapisiyordu.
COMMAND_LINE_RE = re.compile(r'CommandLine\s*[=:]\s*("(?:[^"\\]|\\.)*"|[^\n]+)', re.IGNORECASE)
USER_RE = re.compile(rf"SubjectUserName\s*[=:]\s*({_QUOTED_OR_BARE})", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Jenerik Key=Value cikarimi (bolum 1 -- "once logdan yalnizca dogrulanabilir
# FACT'ler cikarilsin"): yukaridaki alan-ozel regex'ler yalnizca bilinen birkac
# alani yakalar (event_id, process, command line, user). Raw log'da bunlarin
# disinda gecen her Key=Value cifti (orn. ShareName=, AccessMask=, AccessList=)
# bugune kadar tamamen goz ardi ediliyordu -- bu regex hepsini yakalar.
KEY_VALUE_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("(?:[^"\\]|\\.)*"|\S+)')

# Gercek Windows Event Log export'larinda alanlar Key=Value olarak degil,
# Message govdesinde "Etiket:  Deger" olarak gelir ve aralarinda 2+ bosluk
# bulunur ("Process ID:  23356  Application Name:  C:\..."). Bu bicim
# KEY_VALUE_RE tarafindan hic gorulmuyordu: govdesi dolu ama ust seviye alani
# olmayan bir log parser'a tamamen bos gorunuyordu.
# Yalnizca etiket KONUMLARINI bulur; deger, bu etiketle bir sonraki etiket
# arasinda kalan metindir. Degeri regex'in kendisine yakalatmak ise yaramiyor,
# cunku govde ic ice: "Process Information:" bir bolum basligidir ve degeri
# diye kendinden sonraki alt alani ("New Process Name:  C:\...") yutuyordu.
# Basliklarin arasi bos kaldigi icin bu yontemde kendiliginden eleniyorlar.
# TEK TANIM: etiket kurali formats.py'de yasiyor, burada KOPYALANMIYOR
# (Gorev 15). Burada ayri bir kopya vardi ve ayni keyfi 28 karakter sinirini
# tasiyordu; formats tarafi degismezle degistirilip burasi birakilsaydi ayni
# soruya ("bu govdedeki etiketler hangileri") iki farkli cevap veren iki yol
# kalirdi. HANDOFF dersi 7: bir duzeltme yaparken sorulacak soru, ayni isi
# yapan baska kac yol oldugudur.
#
# Hizalamanin etkisi OLCULDU (166 girdi): extracted_facts hicbir girdide
# degismedi, turev alanlar (process_name/command_line/user_account/event_id)
# hicbir girdide degismedi. Yani bu bir davranis degisikligi degil, ikinci
# gercekligin kaldirilmasi.
MESSAGE_FIELD_RE = _MESSAGE_LABEL_RE

# Message govdesindeki etiketleri ust seviye alan adlarina esler. Ust seviyede
# ayni alan zaten varsa O kazanir (setdefault) -- govde yalnizca bosluk doldurur.
MESSAGE_FIELD_ALIASES = {
    "New Process Name": "NewProcessName",
    "Process Name": "NewProcessName",
    "Application Name": "NewProcessName",
    "Command Line": "CommandLine",
    "Process Command Line": "CommandLine",
    "Account Name": "SubjectUserName",
    "Object Name": "ObjectName",
    "Service Name": "ServiceName",
    "Service File Name": "ImagePath",
    "Share Name": "ShareName",
    "Source Address": "SourceIp",
    "Destination Address": "DestinationIp",
    "Source Port": "SourcePort",
    "Destination Port": "DestinationPort",
    "Target Filename": "TargetFilename",
    "Logon Type": "LogonType",
    "Accesses": "Accesses",
}

KNOWN_TOOLS = [
    "schtasks.exe", "powershell.exe", "cmd.exe", "wmic.exe", "regsvr32.exe",
    "rundll32.exe", "mshta.exe", "certutil.exe", "psexec", "mimikatz",
    "net.exe", "netsh", "bitsadmin", "wscript", "cscript",
]

# Arac adlari kelime siniriyla aranir. Duz substring aramasi "net.exe"yi
# "Network Information" iceren her logda eslestiriyordu -- ustelik eski kod
# stem'i str.rstrip(".exe") ile uretiyordu; rstrip son ek silmez, sondaki
# '.', 'e', 'x' karakterlerini kirpar (bkz. "net.exe" -> "net").
_TOOL_PATTERNS = {
    tool: re.compile(
        rf"\b{re.escape(tool[:-4] if tool.endswith('.exe') else tool)}(?:\.exe)?\b",
        re.IGNORECASE,
    )
    for tool in KNOWN_TOOLS
}

# BASKA BIR HOSTTA KOD CALISTIRMA kaniti. "Ag baglantisi var" ile "uzaktan
# calistirildi" ayri seyler: 5156 gibi siradan bir outbound baglantiyi lateral
# movement'a dogru zenginlestirmek yanlis yonlendiriyordu.
#
# Tek basina "remote" bilerek yok -- 5156 loglarinin govdesinde "Remote User
# ID" / "Remote Machine ID" basliklari geciyor ve her baglantiyi uzaktan
# calistirma gibi gosteriyordu. Bu yuzden cok kelimeli ifadeler kullaniliyor.
# "\\\\" (UNC) de yok: kacisli loglar (\\REGISTRY\\..., \\device\\...) yerel
# olaylari uzak gosteriyordu, UNC'yi bu bicimde yerel yoldan ayirmak mumkun degil.
REMOTE_EXECUTION_KEYWORDS = [
    "/s ", "-computername", "/node:", "psexec", "wmiexec", "invoke-command",
    "winrs", "admin$", "ipc$",
    "remote system", "remote host", "remotely executed", "remote execution",
    "uzak sistem", "uzaktaki sistem", "uzaktan calistir",
]

# lsass.exe'nin OZNE mi NESNE mi oldugunu ayirt etmek icin bakilan alanlar.
# Sysmon 10'da TargetImage kurbandir (credential dumping); 4656'da lsass
# NewProcessName ise kendi anahtarini okuyan normal sistem surecidir.
LSASS_TARGET_FIELDS = ("TargetImage", "ObjectName", "TargetFilename", "FilePath")

# Sadece surec olusturma olaylari "calistirildi" demeyi hak eder. Digerlerinde
# NewProcessName olayi KAYDEDEN surectir; onu "calistirildi" diye anlatmak
# (orn. 4656'da lsass.exe'nin bir registry anahtari acmasi) LLM'e yanlis fiil
# veriyordu. EventID bilinmiyorsa eski davranis korunur.
#
# Edilgen yazilmalari kasitli: bu olaylarin cogunda (7045, 1102, 5140, 4624)
# logda bir surec adi hic bulunmuyor. Etkin cumle kurulunca ozne olmadigi icin
# olay tamamen sessiz geciyordu -- servis kurulumu gibi bir olay "Kullanici
# hesabi: X" disinda hicbir sey uretmiyordu.
EVENT_ACTIONS = {
    "3": "ag baglantisi kuruldu",
    "10": "baska bir surecin bellegine erisildi",
    "11": "dosya olusturuldu",
    "13": "registry degeri degistirildi",
    "1102": "denetim gunlugu temizlendi",
    "4104": "PowerShell script block calistirildi",
    "4624": "oturum acildi",
    "4656": "nesne icin erisim tanitici (handle) talep edildi",
    "4663": "nesne uzerinde erisim gerceklestirildi",
    "5140": "ag paylasimina erisildi",
    "5156": "ag baglantisi kuruldu",
    "7045": "servis kuruldu",
}

# Surec olusturma olaylari: bunlarda "calistirildi" dogru fiildir ve NE
# calistirildigi komut satirindan okunur.
PROCESS_CREATION_EVENT_IDS = {"1", "4688"}

# Windows'a ozgu EventID varsa platform tartismasiz Windows'tur. Onceden
# platform yalnizca metindeki ".exe"/"c:\\" gibi ipuclarindan cikariliyordu,
# bu yuzden 4624/7045/1102 gibi saf alan-tabanli loglarda platform None kaliyor
# ve retrieval'daki platform filtresi bosa dusuyordu.
WINDOWS_EVENT_IDS = {
    "1", "3", "10", "11", "13", "1102", "4104", "4624", "4634", "4656",
    "4663", "4688", "4697", "5140", "5145", "5156", "7045",
}

# Eylemin hedefi hangi alandan okunacak (ilk dolu olan kazanir).
EVENT_TARGET_FIELDS = {
    "3": ("DestinationIp",),
    "10": ("TargetImage",),
    "11": ("TargetFilename", "FilePath"),
    "13": ("TargetObject", "FilePath"),
    "4656": ("FilePath", "ObjectName", "TargetFilename"),
    "4663": ("FilePath", "ObjectName", "TargetFilename"),
    # 4624 kasitli yok: oturumu acan hesap zaten "Kullanici hesabi:" satirinda.
    "5140": ("ShareName",),
    "5156": ("DestinationIp",),
    "7045": ("ServiceName",),
}

# Hedefe ek olarak anlamli olan ikincil alanlar: servis kurulumunda asil kritik
# bilgi servisin ADI degil isaret ettigi BINARY'dir (T1543.003), ag olaylarinda
# ise port. Bunlar olmadan olay tarifi "servis kuruldu (UpdaterSvc)" gibi
# eksik kaliyordu.
EVENT_EXTRA_FIELDS = {
    # 4104'te olayin butun icerigi script metnidir -- onsuz "script block
    # calistirildi" NE calistirildigini soylemeyen bos bir cumle oluyordu.
    "4104": ("ScriptBlockText",),
    "3": ("DestinationPort",),
    "5156": ("DestinationPort",),
    "7045": ("ImagePath",),
    "4624": ("LogonType",),
    "4656": ("Accesses",),
    "4663": ("Accesses",),
}

PLATFORM_KEYWORDS = {
    "Windows": ["powershell", ".exe", "schtasks", "hkey_", "c:\\", "wmic", "regsvr32", "rundll32", "windows"],
    "Linux": ["/etc/", "bash", "cron", ".sh", "/usr/bin", "syslog", "systemd", "linux"],
    "macOS": [".plist", "launchd", "launchagent", "macos", "osascript"],
}

# KALDIRILDI (2026-08-17, Ö1) -- eskiden 10 anahtarli bir sozluk vardi:
#   {"certutil": ["ingress tool transfer", ...], "lsass": [...], ...}
# Ham logda anahtar gecerse TEKNIGIN KENDI ADINI sorguya ekliyordu.
#
# NEDEN KALDIRILDI -- performans degil, OLCUM GECERLILIGI:
#
# 1. Kopya cekiyordu. rawlog-005'te beklenen teknik T1105 Ingress Tool
#    Transfer; tablo "certutil" gorup sorguya "ingress tool transfer"
#    yaziyordu. Imza siralama kaymasi degil TOPLU GIRIS: A'nin ilk
#    300'unde T1105'in 24 AYRI chunk'i vardi, tablosuz kolda sifir.
#    Bir teknik semantik yakinlikla listeye boyle girmez.
#
# 2. Fixture bicimliydi. 60 senaryonun 20'sinde tetikleniyordu; 10
#    anahtarin 3'u (sekurlsa, mimikatz, bitsadmin) HIC tetiklenmiyordu,
#    kalan 7'si tam da senaryolardaki araclardi. msiexec, mshta,
#    esentutl, curl, wget yoktu. Held-out sette susardi.
#
# 3. OLCULDU (60 senaryo, iki kirilim):
#      tetiklenmeyen 40 : ort 14.6 -> 14.6, sorgular BIREBIR ayni
#      tetiklenen    20 : ort  2.6 -> 12.9
#      tetiklenen, rawlog-005 haric:
#                         sira toplami 26 -> 26, n=18, ort 1.44 -> 1.44
#      3 senaryo iyilesti, 4 kotulesti, 13 degismedi; kapsama 51/60 sabit
#
#    Yani net katkisi TEK SENARYOYDU ve orada yaptigi sey tekniğin adini
#    sorguya yapistirmakti. "Kadar fayda kadar zarar" bile degil.
#
# 2A ICIN NOT -- bu bir kapi kapatma degil, BICIM ayrimi:
#    ATT&CK bundle'inda 821 canli tool/malware nesnesinin hepsinin
#    tekniğe `uses` iliskisi var (certutil -> T1105/T1140/T1553.004/
#    T1560.001). Bu MITRE'nin KURASYONU, ezber degil -- korpusun
#    technique_description gibi bir alani. Ama BICIM belirleyici:
#      - sorguya TERIM olarak enjekte etmek  -> kopya (bu tablo buydu,
#        yalnizca kucuk olcekte; 821'e cikarmak mesru kilmaz)
#      - retrieval SONRASI SINYAL olarak kullanmak -> tartisilabilir
#        (ornegin "adayin uses iliskisi logdaki araçla eslesiyor mu"
#        diye bir skor bileseni: aday URETIMINI degil SIRALAMAYI etkiler)
#    Ilk bicim yasak. Ikincisi 2A'da yeniden degerlendirilebilir.
#
# BIRLIKTE OLEN KOD: `_lsass_is_subject_only` de kaldirildi. O fonksiyon
# YALNIZCA bu tablonun "lsass" anahtarinin yanlis atesinin bastirmak icin
# vardi -- lsass.exe'nin kendi anahtarini actigi zararsiz 4656 olaylari
# T1003.001'e cekiliyordu. Anahtar kelime -> teknik adi enjeksiyonunun
# fazla atesledigi, ona bir bastirici yazilmis olmasindan belliydi.
# Tablo gidince bastiriciya da gerek kalmadi.


def _detect_platform(text_lower: str, event_id: str | None = None) -> str | None:
    if event_id in WINDOWS_EVENT_IDS:
        return "Windows"
    scores = {p: sum(1 for kw in kws if kw in text_lower) for p, kws in PLATFORM_KEYWORDS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else None


def _unquote(value: str) -> str:
    """Tirnak siler VE serilestirmenin kacisini geri alir.

    Kacis geri alma app.normalization.formats'tan ITHAL ediliyor, burada
    KOPYALANMIYOR (Gorev 15). Iki ayri _unquote vardi ve ikisi de yalnizca
    tirnak siliyordu; formats tarafi duzeltilip burasi birakilsaydi ayni
    degerin iki gerceklige sahip olacagi bir yol acik kalirdi -- sema DISI
    bir alanin tirnakli degeri yalnizca bu yoldan geciyor
    (structured_facts 'unknown.' onekli alanlari eliyor, boslugu
    _extract_facts dolduruyor)."""
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return unescape_serialized(value[1:-1])
    return value


def _parse_structured(raw_text: str) -> tuple[dict[str, Any], dict[str, str], str | None]:
    """Formata duyarli ayristirma (bkz. app/normalization/formats.py).

    Uc sey dondurur: yetkili {canonical_ad: Field} sozlugu, eski tuketiciler
    icin duz izdusum, ve kullanilan bicimin adi."""
    from app.normalization.formats import parse_fields, to_legacy_facts

    fields, fmt = parse_fields(raw_text)
    return fields, to_legacy_facts(fields), fmt


def _split_damgasi(raw_text: str) -> dict[str, Any]:
    """Girdi kac olay tasiyor -- ayristirmanin GECERLILIK damgasi (Gorev 14)."""
    from app.normalization.formats import split_events

    return split_events(raw_text).to_dict()


def _event_id_from_fields(fields: dict[str, Any]) -> str | None:
    """BUG D: EVENT_ID_RE 'EventID' bitisik ariyordu, gercek loglarda
    'Event ID=4656' bosluklu geciyor. Dort probe logunda da event_id None
    kaliyor, boylece event_id_relevance bileseni ve olay anlambilimi
    (EVENT_ACTIONS, EVENT_TARGET_FIELDS) tamamen devre disi kaliyordu.

    Artik olay ID'si semadan okunuyor; yazim farklari alias tablosunda
    (config/field_schema.yaml) tanimli, regex'te degil."""
    field = fields.get("event.id")
    if field is None:
        return None
    text = field.text.strip()
    match = re.search(r"\d+", text)
    return match.group(0) if match else None


def _extract_facts(raw_text: str) -> dict[str, str]:
    """Raw log'daki her Key=Value ciftini oldugu gibi dondurur -- yorum yok,
    cikarim yok, yalnizca girdide gercekten var olan alan=deger ciftleri.

    Ust seviye Key=Value ciftleri once islenir; ardindan Message govdesindeki
    "Etiket:  Deger" ciftleri YALNIZCA eksik alanlari doldurur."""
    facts: dict[str, str] = {}
    for key, value in KEY_VALUE_RE.findall(raw_text):
        facts.setdefault(key, _unquote(value))

    message = facts.get("Message")
    if message:
        matches = list(MESSAGE_FIELD_RE.finditer(message))
        for i, match in enumerate(matches):
            end = matches[i + 1].start() if i + 1 < len(matches) else len(message)
            value = message[match.end():end].strip()
            field = MESSAGE_FIELD_ALIASES.get(match.group(1).strip())
            # "-" ve "NULL SID" Windows'un "deger yok" gosterimleri; bos deger
            # ise bir bolum basligi demektir (bkz. MESSAGE_FIELD_RE yorumu).
            if field and value not in ("-", "NULL SID", ""):
                facts.setdefault(field, value)
    return facts


def _event_detail(event_id: str | None, facts: dict[str, str]) -> str:
    """Olayin hedefini ve varsa kritik ikincil alanini "(hedef: X, Y)" seklinde
    dondurur. Hedef yoksa bos string."""
    key = event_id or ""
    parts = []

    target = next((facts[f] for f in EVENT_TARGET_FIELDS.get(key, ()) if facts.get(f)), None)
    if target:
        parts.append(f"hedef: {target}")
    for field in EVENT_EXTRA_FIELDS.get(key, ()):
        if facts.get(field):
            parts.append(f"{field}: {facts[field]}")

    return f" ({', '.join(parts)})" if parts else ""


def _describe_event(event_id: str | None, process: str | None, command_line: str | None,
                    facts: dict[str, str]) -> str | None:
    """Olayi tek cumlede anlatir: KIM, NE yapti, NEYE.

    Surec adi olmayan olaylarda da (7045 servis kurulumu, 1102 log temizleme)
    cumle uretir -- eskiden bu olaylar tamamen sessiz geciyordu."""
    action = EVENT_ACTIONS.get(event_id or "")

    if not action:
        if not process:
            return None
        # Surec olusturma (ve EventID'si bilinmeyen loglar): NE calistirildigi
        # komut satirindadir -- onu sustumak "sey calisti ama ne yapti belirsiz"
        # ciktisinin ta kendisiydi.
        detail = ""
        if command_line and command_line.strip() and command_line.strip() != process.strip():
            detail = f" (komut: {command_line.strip()})"
        return f"{process} calistirildi{detail}"

    detail = _event_detail(event_id, facts)
    if process:
        return f"{process} tarafindan {action}{detail}"
    return f"{action[0].upper()}{action[1:]}{detail}"


def normalize_input(raw_text: str) -> dict[str, Any]:
    text_lower = raw_text.lower()

    event_id_match = EVENT_ID_RE.search(raw_text)
    process_match = PROCESS_NAME_RE.search(raw_text)
    command_match = COMMAND_LINE_RE.search(raw_text)
    user_match = USER_RE.search(raw_text)
    ip_matches = IP_RE.findall(raw_text)

    # YENI: formata duyarli ayristirma yetkili kaynaktir.
    parsed_fields, structured_facts, log_format = _parse_structured(raw_text)

    # Eski jenerik cikarim YALNIZCA kendi bicimi icin kullanilir.
    #
    # Ikisini korukoru birlestirmek olculmus bir hataydi: brace_kv loglarinda
    # extracted_facts, eski BOZUK anahtarlarla (Name: "N/A,", Domain: "NT,",
    # Mask: "0x2000d,") yeni dogru anahtarlarin BIRLESIMI oluyordu -- T0'da
    # 15 yerine 26, T1'de 21 yerine 33 anahtar. Sonucu: field_match'in
    # paydasi copla siser (o degerler sondaki virgul yuzunden hicbir kanit
    # metnine uymaz) ve evidence_summary analiste copu gosterir.
    #
    # YETKI SIRASI TERSINE CEVRILDI (2026-08-18). Onceden space_kv'de ESKI
    # cikarim yetkiliydi ve yeni ayristirici yalnizca bosluk dolduruyordu.
    # O secim, space_kv ayristiricisinin bug'li oldugu donemde makuldu.
    # Bug 140535c'de kapandi ama SECIM guncellenmedi: duzeltilmis deger,
    # bozuk deger tarafindan eziliyordu.
    #
    # OLCULDU -- ayni girdide UC farkli komut satiri:
    #   parse_fields / to_legacy_facts : 'certutil.exe -urlcache -split -f <url>'  DOGRU
    #   _extract_facts (KEY_VALUE_RE)  : 'certutil.exe'                            KIRPIK
    #   COMMAND_LINE_RE                : '... <url> SubjectUserName=jdoe'          TASAN
    # Kural motoruna en kotusu gidiyordu.
    #
    # Eski cikarim SILINMIYOR, BOSLUK DOLDURUCUYA indiriliyor: Message
    # govdesindeki "Etiket: Deger" zenginlestirmesi hala oradan geliyor ve
    # gercek Windows export'larinda tek kaynak o.
    if log_format in (None, "space_kv"):
        facts = {k: v for k, v in structured_facts.items()
                 if not k.startswith("unknown.")}
        for key, value in _extract_facts(raw_text).items():
            facts.setdefault(key, value)
    else:
        facts = dict(structured_facts)

    event_id = (
        _event_id_from_fields(parsed_fields)
        or (event_id_match.group(1) if event_id_match else None)
    )

    # SIRA: yetkili ayristirici -> facts -> alan-ozel regex.
    #
    # Regex'ler ONCE geliyordu ve bu, duzeltilmis degeri eziyordu. En zararlisi
    # COMMAND_LINE_RE: tirnaksiz dalda `[^\n]+` diyor, yani SATIR SONUNA KADAR
    # yutuyor. Ustundeki yorum bu hatayi anlatiyor ama yalnizca TIRNAKLI dal
    # duzeltilmis. Sonucu: kural motorunun CommandLine alani komsu alanlarin
    # icerigini tasiyor, yani fiilen Message gibi davraniyor.
    #
    # Regex'ler SILINMIYOR: bilgisi yalnizca Message govdesinde olan gercek
    # Windows export'larinda tek kaynak onlar. Ama artik SON careler.
    def _kanonik(ad: str) -> str | None:
        alan = parsed_fields.get(ad)
        return alan.text if alan is not None else None

    process_name = (
        _kanonik("process.name") or facts.get("NewProcessName")
        or (_unquote(process_match.group(1)) if process_match else None)
    )
    command_line = (
        _kanonik("process.command_line") or facts.get("CommandLine")
        or (_unquote(command_match.group(1).strip()) if command_match else None)
    )
    user_account = (
        _kanonik("account.name") or facts.get("SubjectUserName")
        or (_unquote(user_match.group(1)) if user_match else None)
    )

    detected_tools = [tool for tool, pattern in _TOOL_PATTERNS.items() if pattern.search(raw_text)]
    remote_execution = any(kw in text_lower for kw in REMOTE_EXECUTION_KEYWORDS)
    # is_remote "baska bir sistem isin icinde" demek (UI'da gosterilir);
    # remote_execution ise "o sistemde kod calistirildi" -- retrieval
    # zenginlestirmesini yalnizca ikincisi tetikler.
    is_remote = remote_execution or bool(ip_matches)

    observed_actions = []
    event_description = _describe_event(event_id, process_name, command_line, facts)
    if event_description:
        observed_actions.append(event_description)
    for tool in detected_tools:
        if tool not in (process_name or "").lower():
            observed_actions.append(f"{tool} kullanimi tespit edildi")
    if is_remote:
        # ip_matches[0] cogu logda KAYNAK adres oluyor -- hedefi "hedef:" diye
        # gostermek yaniltiyordu; varsa acikca DestinationIp tercih edilir.
        peer = facts.get("DestinationIp") or (ip_matches[0] if ip_matches else None)
        observed_actions.append(f"Islem uzak bir sistemle iliskili" + (f" (hedef: {peer})" if peer else ""))
    if user_account:
        observed_actions.append(f"Kullanici hesabi: {user_account}")

    return {
        "platform": _detect_platform(text_lower, event_id),
        "event_id": event_id,
        "process_name": process_name,
        "command_line": command_line,
        "user_account": user_account,
        "remote_ips": ip_matches,
        "is_remote": is_remote,
        "remote_execution": remote_execution,
        "detected_tools": detected_tools,
        "observed_actions": observed_actions,
        # YETKILI yapi: canonical adlar + alan basina {value, informative,
        # in_schema}. Uc tuketici ayni alandan farkli sey istiyor (on kapi
        # sayim, retrieval filtresi, kanit tablosu gosterimi), o yuzden deger
        # tek basina yetmiyor. Bkz. app/normalization/formats.Field.
        "parsed_fields": parsed_fields,
        "log_format": log_format,
        # BU KAYIT KAC OLAY TASIYOR (Gorev 14). Ayristirma bir olayin
        # alanlarini uretir; girdi birden fazla olay tasiyorsa uretilen
        # alanlar OLAYLAR ARASI DERLEMEDIR ve karar katmani onlara
        # dayanamaz -- acigin kok nedeni buydu. Damga burada uretiliyor
        # ki tuketici "bu tek olay mi" sorusunu tahmin etmek zorunda
        # kalmasin: app/validation/decision.decide bu alani OKUR ve cok
        # olayli girdide calismayi REDDEDER.
        "split": _split_damgasi(raw_text),
        # ESKI tuketiciler icin duz izdusum (kural motoru, QRadar yolu,
        # korelasyon 'EventID'/'CommandLine' gibi adlara bagli).
        "extracted_facts": facts,
    }


# --------------------------------------------------------------------------
# AYIRT EDICI ALAN SECIMI -- elle liste DEGIL, alan tipine gore KURAL.
#
# Ilk yazimda elle bir liste vardi: object.name, object.value_name,
# operation.type, access.list. Dort registry logundan turetilmisti ve
# olculdugunde 60 senaryonun HICBIRINDE dolmadi -- cunku o senaryolar
# surec/komut/ag loglari. Yani liste, dort ornege asiri uydurulmustu; tam da
# "yalnizca fixture'larda gecen degerleri kapsayan tablo" yasaginin ihlali.
#
# Kuralin testi: yarin hic gorulmemis bir log kaynagi geldiginde onun ayirt
# edici alanlarini bulabilmeli. Liste bulamaz, kural bulur.
#
# BIR ALAN AYIRT EDICIDIR EGER:
#   1. semada tanimli   -- unknown.* disarida, retrieval sorgusunu kirletir
#   2. bilgilendirici   -- "N/A"/bos degil
#   3. KIMLIK degil     -- adi '.id' ile biten alanlar (handle.id, process.id,
#                          logon.id, group.id, event.id) opak tanimlayicidir;
#                          '0x2b1c' hicbir ATT&CK metniyle eslesmez.
#                          event.id ayrica 2. KATMANDA anlamiyla temsil
#                          ediliyor, ham sayisiyla degil.
#   4. degeri OPAK degil -- saf hex ya da saf sayi olan degerler taniyici
#                          gorevi gorur, anlam tasimaz
#
#      DIKKAT -- KATMAN AYRIMI, ELEME DEGIL: bu kural value.old="0" ve
#      value.new="1" gibi alanlari SORGUDAN cikarir, cunku "0"/"1" hicbir
#      ATT&CK metniyle eslesmez ve sorguya konsa yalnizca gurultu olur.
#      AMA bu alanlar GEREKSIZ DEGILDIR: T3'te (Defender kapatma) karari
#      veren kanit tam olarak o 0 -> 1 degisimidir. Onlar KARAR katmaninin
#      (Gorev 5) girdisidir, retrieval'in degil. Gorev 5 yazilirken
#      "kural bu alanlari atiyor, demek gereksiz" diye okunmamali.
#   5. degeri KISA degil -- tek kelimelik kisa degerler ("Key", "0") ayirt
#                          etmez; ama coklu parcali degerler (bosluk ya da
#                          ters bolu iceren) kisa olsa da anlamlidir
_IDENTIFIER_SUFFIX = ".id"
_OPAQUE_VALUE_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+|-)$")
_MIN_VALUE_LEN = 4

# Uzun degerler 1. katmani sisirir ve tam kacindigimiz seyreltmeyi geri
# getirir (script.block_text binlerce karakter olabilir). Kirpilir, atilmaz:
# bir betigin ilk 200 karakteri genellikle ne yaptigini soyler.
_MAX_FIELD_VALUE_LEN = 200


def is_discriminating(name: str, field: Any) -> bool:
    """Bu alan sorgunun 1. katmanina girmeli mi? (bkz. yukaridaki kural)"""
    if field is None or not getattr(field, "in_schema", False):
        return False
    if not getattr(field, "informative", False):
        return False
    if name.endswith(_IDENTIFIER_SUFFIX):
        return False

    text = field.text.strip()
    if _OPAQUE_VALUE_RE.match(text):
        return False
    if len(text) < _MIN_VALUE_LEN and not any(c in text for c in " \\/"):
        return False
    return True


def discriminating_fields(
    parsed: dict[str, Any], dedup: str = "identical"
) -> list[tuple[str, str]]:
    """(alan_adi, kirpilmis_deger) ciftleri -- sema sirasinda.

    dedup modlari:
      "none"      : hicbir sey elenmez (olcum tabani)
      "identical" : OZDES degerler tekillestirilir. value.old_type ve
                    value.new_type ikisi de "REG_DWORD" -- ayni metni iki kez
                    gondermek BM25 agirligi ekler, BILGI eklemez.
      "contained" : ozdes + biri digerini iceriyorsa uzun olan tutulur.
                    OLCULDU VE ONERILMIYOR (asagi).

    OLCUM (2026-08-17, 60 senaryo, D kolu, semantic):
        none       51/60  ort 8.4   sorguyu degistirdigi senaryo: --
        identical  51/60  ort 8.4   0/60
        contained  51/60  ort 8.5   1/60  (rawlog-007: sira 3 -> 5)

    Yani "identical" bu veride HICBIR sorguyu degistirmiyor; bedava duruyor.
    "contained" tek ateslendigi yerde ZARAR verdi. process.path
    "C:\\...\\powershell.exe" icindeki process.name "powershell.exe"
    kopyasini atmak sezgisel olarak dogru gorunuyordu -- olcum tersini
    soyluyor: o tekrar gurultu degil, ise yarayan agirlik.

    ONCEKI SONUC GECERSIZ: "contained hicbir sorguyu degistirmiyor (0/8)"
    space_kv bug B ile alinmisti. Kirpik "certutil.exe" tam yolun ICINDE
    gectigi icin atiliyordu; tam komut satiri gelince kapsama iliskisinin
    kendisi degisti.

    SINIRI: bu olcum yalnizca SEMANTIC kol. Asagidaki "tekrar BM25 icin
    terim frekansi ekler" gerekcesi burada SINANMADI -- "contained"i
    kapatmak icin yeterli, "tekrar her zaman iyidir" icin degil."""
    secilenler: list[tuple[str, str]] = []
    for name, field in parsed.items():
        if not is_discriminating(name, field):
            continue
        text = field.text.strip()
        if len(text) > _MAX_FIELD_VALUE_LEN:
            text = text[:_MAX_FIELD_VALUE_LEN]
        secilenler.append((name, text))

    if dedup == "none":
        return secilenler

    gorulen: dict[str, tuple[str, str]] = {}
    for name, text in secilenler:
        anahtar = text.casefold()
        if anahtar not in gorulen:
            gorulen[anahtar] = (name, text)

    sonuc = list(gorulen.values())
    if dedup != "contained":
        return sonuc

    kapsananlar = set()
    for i, (_, a) in enumerate(sonuc):
        for j, (_, b) in enumerate(sonuc):
            if i != j and a.casefold() in b.casefold():
                kapsananlar.add(i)
                break
    return [pair for i, pair in enumerate(sonuc) if i not in kapsananlar]


def build_layered_query(
    raw_text: str,
    normalized: dict[str, Any],
    *,
    include_raw: bool = True,
    include_enrichment: bool = False,
    dedup: str = "identical",
) -> str:
    """Uc katmanli sorgu: ayirt edici alanlar + cozulmus semantik + ham log.

    NEDEN (olculdu 2026-08-16, T3): ham log sorgusu 709 karakter, 88 token,
    bunun 47'si ALAN ADI (Pipe, Name, Type, Value, ID...), 7'si "N/A", 3'u
    hex handle. Ayirt edici icerik avuc ici kadar. BM25'in bu sorguda T1685'i
    bulamamasinin sebebi bu: terim agirliklandirmasi korpusta her yerde gecen
    kelimelerle boguluyor.

    EKLEME, IKAME DEGIL: ham log 3. katmanda AYNEN duruyor. Onu atmak T1'i
    riske atardi -- orada dogru teknik semantic 2. sirada ve o siralamayi
    duzyazi baglam saglıyor. Ayirt edici olan yalnizca ONE ve TEKRARLI
    geliyor; tekrar, BM25 icin dogrudan terim frekansi artisi demek, yani
    ayri bir agirlik parametresi gerekmiyor.
    ^ SINANMAMIS IDDIA. Butun kol karsilastirmalari SEMANTIC uzerinde
      yapildi; BM25 tarafinda terim frekansi etkisi hic olculmedi. Iddia
      makul ama kanitli degil -- BM25 kolu olculene kadar boyle isaretli
      kalir.

    OLCULDU (2026-08-17, 60 senaryo, temiz parser): include_raw=False kolu
    A'dan IYI -- 51/60 ort 8.4 (A: 51/60 ort 10.1), raw_log kategorisinde
    ort 16.6 -> 5.0. Onceki "D daha kotu" sonucu space_kv bug B'nin
    artefaktiydi (komut satirinin %85'i kirpiliyordu).

    DIKKAT -- A KOLU SISKIN: build_enriched_query, QUERY_ENRICHMENT
    tablosundan teknik ADLARINI sorguya ekliyor (bkz. HANDOFF "Ö1").
    Tablo senaryolardaki araclari kapsiyor, held-out sette susar. A ile
    yapilan her karsilastirma bu etki altinda okunmalidir.

    2. KATMAN IKI DILIN BULUSMA NOKTASI: log "Event ID=4657" yazar, ATT&CK
    "registry value modification" yazar. event_semantics cozumu ikincisine
    benzeyen bir ifade uretir.

    include_raw=False: ham log katmani cikarilir. "Ham log semantic'e baglam
    veriyor" varsayimini SINAMAK icin -- varsayim test edilmeden dogru
    sayilmamali.

    URETIM VARSAYILANI: include_raw=True, KOSULSUZ (2A(b), 2026-08-17).
    Dort kol 60 senaryoda olculdu; birincil olcu kapsama kaybi:

        kol            bulundu  top-20  KAYIP  medyan   ort
        A                51/60      46      0     1.0   14.0
        D  (ham yok)     51/60      49      0     1.0    8.4
        D+ham            51/60      49      0     1.0    7.9
        (b) kosullu      51/60      48      0     2.0    8.8

    ESIK GEREKMEDI. Kosullu (b) -- "1. katman doluysa D, degilse A" --
    olculebilir kazanc saglamadi, HAFIFCE ZARARLIYDI. Sebebi yapisal:
    1. katman 45/60 senaryoda bos ve o 45'in HEPSINDE sorgu zaten
    `or raw_text` ile ham metne tam olarak dusuyor (yalnizca 2. katmanin
    kaldigi vaka HIC yok). Yani geri dusus kodda degil VERIDE; (b) o 45'te
    yalnizca A'ya sapiyor ve A orada biraz daha kotu.

    Iki kod yolu, iki test yolu ve AYARLANABILIR bir esik parametresi
    eklemek icin sebep yok -- ayarlanabilir her sey asiri uyum kapisidir.

    ASIL KARAR (b) DEGILDI: 1. katmanin dolu oldugu 15 senaryoda ham logu
    ATMAK dogru mu? Degil. O 15'te A ort 25.8, D 5.5, D+ham 3.5.
    D+ham 5 senaryoda daha iyi (multi-010 16->6, injection-001 20->9,
    rawlog-004 15->12), 2'sinde daha kotu (subtech-002 2->3, rawlog-001
    1->2). Kazanc KATMAN EKLEMEKTEN geliyor, ham logu atmaktan degil --
    yani yukaridaki "EKLEME, IKAME DEGIL" tasarim niyeti dogrulandi."""
    parsed = normalized.get("parsed_fields") or {}
    parcalar: list[str] = []

    # --- 1. katman: ayirt edici ALAN DEGERLERI (alan ADLARI yok)
    ayirt_edici: list[str] = []
    for ad, deger in discriminating_fields(parsed, dedup=dedup):
        ayirt_edici.append(deger)
        # Registry yolu ATT&CK lehcesine de cevrilir: log
        # "\REGISTRY\MACHINE\..." yazar, ATT&CK metinlerinde bu gosterim
        # 697 teknikte TOPLAM 1 kez geciyor (HKLM ise 247). Iki bicimi de
        # gondermek, hangi lehceyi kullanan chunk olursa olsun eslesme
        # sansi birakir. Alan ADINA degil DEGERIN BICIMINE bakiliyor:
        # yarin baska bir alan registry yolu tasirsa da calisir.
        if looks_like_registry_path(deger):
            normalize_edilmis = normalize_registry_path(deger)
            if normalize_edilmis:
                ayirt_edici.append(normalize_edilmis)

    if ayirt_edici:
        parcalar.append(" ".join(ayirt_edici))

    # --- 2. katman: cozulmus olay semantigi
    semantik = _resolved_semantics(normalized, parsed)
    if semantik:
        parcalar.append(semantik)

    # --- 3. katman: ham log
    if include_raw:
        parcalar.append(raw_text)

    sorgu = "\n\n".join(p for p in parcalar if p.strip()) or raw_text

    if include_enrichment:
        ek = build_enriched_query(raw_text, normalized)[len(raw_text):]
        if ek.strip():
            sorgu = f"{sorgu}{ek}"
    return sorgu


def _resolved_semantics(normalized: dict[str, Any], parsed: dict[str, Any]) -> str:
    """Olay ID'si ve erisim maskesini ATT&CK diline yakin bir ifadeye cevirir."""
    from app.normalization.event_semantics import describe

    def deger(ad: str):
        alan = parsed.get(ad)
        return alan.value if alan is not None else None

    ozet = describe(
        normalized.get("event_id"), deger("access.mask"),
        deger("object.type"), deger("access.list"),
    )
    parcalar = [p for p in (ozet.get("meaning"), ozet.get("access_class")) if p]
    parcalar.extend(ozet.get("data_components") or [])
    return " ".join(parcalar)


def build_enriched_query(raw_text: str, normalized: dict[str, Any]) -> str:
    """Ham metni PLATFORM ve UZAKTAN CALISTIRMA terimleriyle zenginlestirir.

    ARAC -> TEKNIK ADI tablosu KALDIRILDI (Ö1, yukarida gerekcesi).
    Buraya bir daha teknik ADI eklenmemeli: teknigin adini sorguya yazmak
    retrieval degil, kopyadir. Kalan iki terim kaynagi teknik adi degil --
    "Windows" bir platform, "remote execution"/"lateral movement" ise
    tekniğe degil TAKTIGE isaret eden genel ifadeler.
    """
    extra_terms: list[str] = []

    # Sadece uzaktan CALISTIRMA kaniti varsa -- salt ag baglantisi degil.
    if normalized.get("remote_execution"):
        extra_terms.extend(["remote execution", "lateral movement"])
    if normalized.get("platform"):
        extra_terms.append(normalized["platform"])

    if not extra_terms:
        return raw_text
    return f"{raw_text}\n\nIlgili terimler: {', '.join(dict.fromkeys(extra_terms))}"
