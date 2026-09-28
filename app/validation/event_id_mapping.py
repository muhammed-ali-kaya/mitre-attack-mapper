"""Windows/Sysmon EventID -> MITRE veri bileseni (data component) eslemesi.

Neden gerekti: guven skorundaki `event_id_relevance` bileseni, girdideki
EventID'yi teknigin resmi `detection` METNINDE gecen EventID'lerle
karsilastiriyordu. Olculdu: 697 teknigin yalnizca 6'sinda (%0.9) detection
metninde EventID geciyor -- MITRE bu metinleri urun-bagimsiz yaziyor,
"Monitor executed commands and arguments" diyor, "Event ID 4688" demiyor.
Sonuc: bilesen tekniklerin %99'unda None donuyordu, yani WEIGHTS'teki 0.15
agirlik fiilen hic kullanilmiyordu.

Dogru sinyal kaynagi STIX'te zaten var: `data_components`, 858 teknigin
652'sinde (%76) dolu. Bir EventID'nin hangi telemetri turunu urettigi sabit
bir bilgi ("4688 = surec olusturma"), dolayisiyla bu esleme elle yazilabilir
ve aciklanabilir bir tablo olarak tutuluyor -- projedeki EVIDENCE_REQUIREMENTS
ve _ROUTINE_SYSTEM_PROCESSES ile ayni desen.

Sordugu soru SOC acisindan anlamli: "senin logundaki olay tipi, bu teknigin
tespit edildigi telemetri turuyle uyusuyor mu?" 4688'lik bir surec olusturma
log'u ile ag trafigi uzerinden tespit edilen bir teknik eslesirse, bu eslesme
sorgulanmali.

Tablodaki adlar data/processed/techniques.json icindeki data_components
degerleriyle BIREBIR ayni olmali; tests/test_event_id_mapping.py bunu dogruluyor
(yazim hatasi sessizce "hicbir zaman eslesmez" haline gelmesin diye).
"""

from __future__ import annotations

# Sysmon kanali. Windows Security ile ayni numaralari kullandigi icin (1, 3, 10...)
# ayri tutuluyor; hangi kanaldan geldigini bilmedigimiz durumlar icin
# asagida ikisinin birlesimi kullaniliyor.
_SYSMON: dict[str, set[str]] = {
    "1": {"Process Creation", "Command Execution"},
    "3": {"Network Connection Creation"},
    "5": {"Process Termination"},
    "6": {"Driver Load"},
    "7": {"Module Load"},
    "8": {"Process Modification"},
    "10": {"Process Access"},
    "11": {"File Creation"},
    "12": {"Windows Registry Key Creation"},
    "13": {"Windows Registry Key Modification"},
    "14": {"Windows Registry Key Modification"},
    "15": {"File Creation"},
    "19": {"WMI Creation"},
    "20": {"WMI Creation"},
    "21": {"WMI Creation"},
    "22": {"Network Traffic Content"},
    "23": {"File Deletion"},
    "26": {"File Deletion"},
}

_WINDOWS_SECURITY: dict[str, set[str]] = {
    "1102": {"Application Log Content"},
    "4103": {"Command Execution", "Script Execution"},
    "4104": {"Script Execution", "Command Execution"},
    "4624": {"Logon Session Creation"},
    "4625": {"User Account Authentication"},
    "4634": {"Logon Session Metadata"},
    "4647": {"Logon Session Metadata"},
    "4648": {"Logon Session Creation"},
    "4656": {"File Access", "Process Access"},
    "4657": {"Windows Registry Key Modification"},
    "4663": {"File Access"},
    "4672": {"Logon Session Metadata"},
    "4688": {"Process Creation", "Command Execution"},
    "4689": {"Process Termination"},
    "4697": {"Service Creation"},
    "4698": {"Scheduled Job Creation"},
    "4699": {"Scheduled Job Modification"},
    "4702": {"Scheduled Job Modification"},
    "4720": {"User Account Creation"},
    "4722": {"User Account Modification"},
    "4724": {"User Account Modification"},
    "4726": {"User Account Deletion"},
    "4728": {"Group Modification"},
    "4732": {"Group Modification"},
    "4756": {"Group Modification"},
    "4768": {"Active Directory Credential Request"},
    "4769": {"Active Directory Credential Request"},
    "4771": {"Active Directory Credential Request"},
    "5140": {"Network Share Access"},
    "5145": {"Network Share Access"},
    "7045": {"Service Creation"},
}

# Girdide olayin hangi kanaldan geldigi cogu zaman yazmiyor. Cakisan
# numaralarda (1, 3, 5...) iki kanalin bileseni birlestiriliyor: amac
# eslesmeyi kacirmamak. Yanlis kanal yuzunden "uyusmuyor" demek, bu sinyalin
# tasidigi 0.15 agirlik dusunuldugunde gereksiz bir ceza olurdu.
EVENT_ID_DATA_COMPONENTS: dict[str, set[str]] = {}
for _table in (_SYSMON, _WINDOWS_SECURITY):
    for _event_id, _components in _table.items():
        EVENT_ID_DATA_COMPONENTS.setdefault(_event_id, set()).update(_components)


def data_components_for_event_id(event_id: str | None) -> set[str]:
    """EventID'nin urettigi telemetri turleri. Bilinmeyen ID icin bos kume."""
    if not event_id:
        return set()
    return EVENT_ID_DATA_COMPONENTS.get(str(event_id).strip(), set())
