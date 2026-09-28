"""ATT&CK taktik adlarinin Turkce karsiliklari.

NE CEVRILIR, NE CEVRILMEZ -- bilincli ayrim:
  - Teknik ADLARI ve ATT&CK ID'leri cevrilmez. "T1059.001 PowerShell" her
    yerde aynen kalir; bunlar referans terminoloji, MITRE dokumantasyonuyla
    ve SOC ekiplerinin gunluk diliyle birebir eslesmeleri gerekiyor. Ayni
    gerekce icin bkz. app/llm/detection_translations.py.
  - TAKTIK adlari ve anlati cumleleri cevrilir; bunlar okuyucuya yonelik
    metin. Taktik adi ayrica parantez icinde Ingilizce de tasinir, boylece
    ATT&CK matrisine bakan biri karsiligi kaybetmez.

Bu projenin ATT&CK v19.1 (ve v19.2) verisi 'Defense Evasion' taktigini 'Stealth' olarak
yeniden adlandirmis ve 'Defense Impairment' diye yeni bir taktik eklemis
(bkz. app/correlation/attack_chain.py) -- ikisi de burada karsilik buluyor.
"""

from __future__ import annotations

TACTIC_LABELS_TR: dict[str, str] = {
    "Reconnaissance": "Keşif",
    "Resource Development": "Kaynak Geliştirme",
    "Initial Access": "İlk Erişim",
    "Execution": "Çalıştırma",
    "Persistence": "Kalıcılık",
    "Privilege Escalation": "Yetki Yükseltme",
    "Stealth": "Gizlenme",
    "Defense Impairment": "Savunmayı Bozma",
    "Defense Evasion": "Savunmadan Kaçınma",
    "Credential Access": "Kimlik Bilgisi Erişimi",
    "Discovery": "Keşif/Envanter Çıkarma",
    "Lateral Movement": "Yanal Hareket",
    "Collection": "Veri Toplama",
    "Command and Control": "Komuta ve Kontrol",
    "Exfiltration": "Veri Sızdırma",
    "Impact": "Etki",
}

# Anlatida kullanilan fiil kaliplari. Ozne her zaman "saldirgan" oldugu icin
# kaliplar edilgen degil etken kurulmus -- olay raporu dili.
TACTIC_NARRATIVE_TR: dict[str, str] = {
    "Reconnaissance": "hedef hakkında keşif yaptı",
    "Resource Development": "saldırı altyapısını hazırladı",
    "Initial Access": "sisteme ilk erişimi sağladı",
    "Execution": "sistemde kod çalıştırdı",
    "Persistence": "kalıcılık sağladı",
    "Privilege Escalation": "yetkilerini yükseltti",
    "Stealth": "tespitten kaçınmaya çalıştı",
    "Defense Impairment": "güvenlik kontrollerini devre dışı bıraktı",
    "Defense Evasion": "savunmalardan kaçındı",
    "Credential Access": "kimlik bilgilerini ele geçirmeye çalıştı",
    "Discovery": "sistem ve ağ envanterini çıkardı",
    "Lateral Movement": "ağ içinde yanal hareket etti",
    "Collection": "veri topladı",
    "Command and Control": "komuta ve kontrol kanalı kurdu",
    "Exfiltration": "veri sızdırdı",
    "Impact": "sistem üzerinde etki oluşturdu",
}


# ATT&CK taktik ID'si -> kanonik Ingilizce ad. Kural dosyasi (rules/
# attack_mappings.yaml) taktigi ID ile yaziyor; gorunum katmani ada ihtiyac
# duyuyor. data/processed/tactics.json'daki source_url'lerden dogrulanabilir
# (bkz. tests/test_tactic_labels.py) -- burada sabit tutulmasinin sebebi
# kural dosyasinin ATT&CK verisi yuklenmeden de dogrulanabilmesi.
TACTIC_ID_TO_NAME: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
    "TA0112": "Defense Impairment",
}


def tactic_name(tactic: str | None) -> str | None:
    """TA00xx ID'sini ada cevirir; zaten adsa oldugu gibi dondurur."""
    if not tactic:
        return None
    return TACTIC_ID_TO_NAME.get(tactic, tactic)


def tactic_label(tactic: str | None, *, with_english: bool = True) -> str:
    """Taktigin gosterim etiketi.

    Sozlukte olmayan bir taktik adi gelirse (ATT&CK surumu yeni bir taktik
    eklemis olabilir) ad OLDUGU GIBI dondurulur -- sessizce '-' yapmak,
    ekranda taktigin kaybolmasi demek olurdu."""
    if not tactic:
        return "-"
    # TA00xx ile de cagrilabilsin: kural dosyasi taktigi ID ile yaziyor.
    tactic = TACTIC_ID_TO_NAME.get(tactic, tactic)
    turkish = TACTIC_LABELS_TR.get(tactic)
    if not turkish:
        return tactic
    return f"{turkish} ({tactic})" if with_english else turkish


def tactic_narrative(tactic: str | None) -> str | None:
    """Taktigin anlati fiili; bilinmeyen taktik icin None (cagiran taraf
    teknik adiyla genel bir kalip kurar)."""
    return TACTIC_NARRATIVE_TR.get(tactic) if tactic else None
