"""Karar katmani sozlesme testleri (Gorev 5).

Beklenen siniflar KOD YAZILMADAN ONCE yazildi:
  docs/beklenti_5_karar_katmani.md bolum 2 (T0-T3) ve bolum 5.4 (T4/T5)
  tests/fixtures/registry_object_access_logs.json
  tests/fixtures/baseline_suppression_logs.json

SINIF YETMEZ, GEREKCE ZINCIRI DE SINANIR. Bu oturumda bes kez ayni desen
yakalandi: dogru cevap, yanlis sebep. Bir sinif tesadufen dogru cikabilir
-- hangi yolun tetiklendigi ve bastirmanin calisip calismadigi ayrica
kontrol edilir.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from app.agents.base import AgentDecision, Verdict
from app.agents.verification import VerificationReport
from app.normalization.input_parser import normalize_input
from app.validation.decision import (
    INSUFFICIENT_DATA,
    SUFFICIENT_BENIGN,
    SUFFICIENT_SUSPICIOUS,
    baseline_bastirir_mi,
    decide,
    varlik_kritikligi,
)

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def _loglar() -> dict[str, dict]:
    kayit: dict[str, dict] = {}
    for ad in ("registry_object_access_logs.json", "baseline_suppression_logs.json"):
        for log in json.loads((FIXTURES / ad).read_text(encoding="utf-8"))["logs"]:
            kayit[log["id"]] = log
    return kayit


LOGLAR = _loglar()


def _rapor(kabul: list[dict], onaylanan: list[str] | None = None) -> VerificationReport:
    """Kanit kapisi CONFIRM vermis gibi bir dogrulama raporu kurar."""
    kararlar = [
        AgentDecision(
            agent_id="test-gate",
            technique_id=tid,
            verdict=Verdict.CONFIRM,
            reason="fixture",
        )
        for tid in (onaylanan or [])
    ]
    return VerificationReport(accepted=kabul, rejected=[], decisions=kararlar)


def _karar(log_id: str, mappings=None, onaylanan=None):
    log = LOGLAR[log_id]
    mappings = mappings or []
    return decide(
        normalized=normalize_input(log["raw"]),
        mappings=mappings,
        verification=_rapor(mappings, onaylanan),
    )


# --------------------------------------------------------- alti fixture

BEKLENEN = {
    "T0": INSUFFICIENT_DATA,
    "T1": SUFFICIENT_SUSPICIOUS,
    "T2": SUFFICIENT_BENIGN,
    "T3": SUFFICIENT_SUSPICIOUS,
    "T4": SUFFICIENT_BENIGN,
    "T5": SUFFICIENT_SUSPICIOUS,
}
#: T1 tek dogrulanmis teknige sahip; digerlerinde teknik seti bos.
TEKNIKLER = {"T1": ([{"attack_id": "T1003.002"}], ["T1003.002"])}


@pytest.mark.parametrize("log_id", sorted(BEKLENEN))
def test_karar_sinifi(log_id: str) -> None:
    mappings, onaylanan = TEKNIKLER.get(log_id, ([], []))
    karar = _karar(log_id, mappings, onaylanan)
    assert karar.decision == BEKLENEN[log_id], (
        f"{log_id}: {karar.decision} — zincir: {karar.reason_chain}"
    )


@pytest.mark.parametrize("log_id", sorted(BEKLENEN))
def test_fixture_dosyasi_ile_tutarli(log_id: str) -> None:
    """Beklenti fixture dosyasinda yaziyor; test onu yeniden yazmaz."""
    assert LOGLAR[log_id]["expected_decision"] == BEKLENEN[log_id]


# ------------------------------------------------- GEREKCE ZINCIRLERI

def test_T0_gerekcesi_yokluk_unknown_degil() -> None:
    """T0'in sinifi INSUFFICIENT ama SEBEBI 'unknown' olmamali.

    Ilk yazimda beklenti T0'i 'unknown' sayiyordu; olcum YOK dedi (logda
    Object Name alani hic yok). Sinif ayni, gerekce zinciri farkli."""
    karar = _karar("T0")
    assert karar.inputs["kritiklik"] == "YOK"
    assert any("varlık yolu YOK" in a for a in karar.reason_chain)
    assert not any("unknown" in a for a in karar.reason_chain)
    assert karar.paths == {"A": False, "B": False}


def test_T1_YOL_A_ile_ayakta_yol_B_artik_tetiklenmiyor() -> None:
    """GOREV 18'DE DEGISTI -- ve degisimin yonu onemli.

    Once iki yol da tetikleniyordu. Yol B (kritiklik + yazma erisimi) 4656'nin
    maskesinden geliyordu; 4656 bir HANDLE TALEBIDIR ve maske orada TALEP
    EDILEN hakki anlatir. Talep artik eylem sayilmiyor, Yol B dusuyor.

    KARAR DEGISMEDI: amiral gemisi vaka (reg.exe -> SAM, T1003.002) Yol A ile
    ayakta. Yani alarm gucu kusura DAYANMIYORDU -- beklenti_18 §3.2'de
    kosulmadan once yazilan iki sonuctan iyi olani."""
    karar = _karar("T1", *TEKNIKLER["T1"])
    assert karar.decision == SUFFICIENT_SUSPICIOUS
    assert karar.paths == {"A": True, "B": False}
    assert karar.suppression is None
    assert any("Yol A" in a for a in karar.reason_chain)
    assert any("§5.2" in a for a in karar.reason_chain)


def test_T2_benign_pozitif_iddiadir() -> None:
    """Uc kosulun UCU de zincirde adiyla gecmeli."""
    karar = _karar("T2")
    zincir = " ".join(karar.reason_chain)
    assert "noise" in zincir
    assert "salt okuma" in zincir
    assert "Doğrulanmış kanıt yok" in zincir
    assert karar.inputs["kritiklik"] == "noise"


def test_T3_teknik_setinden_bagimsiz_alarm() -> None:
    """Dogrulanmis teknik YOKKEN alarm uretmeli -- Yol B'nin varlik sebebi."""
    karar = _karar("T3")
    assert karar.decision == SUFFICIENT_SUSPICIOUS
    assert karar.paths["A"] is False
    assert karar.paths["B"] is True
    assert karar.inputs["dogrulanmis_kanit"] == 0


def test_T4_bastirma_kurali_ADIYLA_raporlanir() -> None:
    """Sessiz bastirma, bastirmanin en tehlikeli bicimidir."""
    karar = _karar("T4")
    assert karar.decision == SUFFICIENT_BENIGN
    assert karar.suppression is not None
    assert karar.suppression["aile"] == "service"
    assert karar.suppression["gerekce"]
    assert any("Baseline bastırdı" in a for a in karar.reason_chain)


def test_T5_ayni_aktor_farkli_aile_bastirilmaz() -> None:
    karar = _karar("T5")
    assert karar.decision == SUFFICIENT_SUSPICIOUS
    assert karar.suppression is None
    assert any("Baseline bastırmadı" in a for a in karar.reason_chain)


def test_T4_T5_aktoru_BIREBIR_AYNI() -> None:
    """Ciftin kanit degeri buna bagli.

    Aktorler ayni degilse T4/T5 farki 'aktore mi cifte mi bakiyor'
    sorusunu AYIRT EDEMEZ ve iki fixture tek fixture kadar bilgi tasir."""
    t4, t5 = _karar("T4").inputs["aktor"], _karar("T5").inputs["aktor"]
    assert t4 == t5, f"{t4} != {t5}"


# ------------------------------------------------ sozlesme: bastirma

def test_baseline_yol_A_yi_bastiramaz() -> None:
    """T5'in aktoru + T1'in dogrulanmis teknigi: sonuc yine SUSPICIOUS.

    Aktor alani taklit edilebilir; dogrulanmis kaniti aktor alaniyla
    sildirmek kanit kapisini aktore devretmek olurdu."""
    log = LOGLAR["T4"]  # bastirilan cift
    mappings = [{"attack_id": "T1003.002"}]
    karar = decide(
        normalized=normalize_input(log["raw"]),
        mappings=mappings,
        verification=_rapor(mappings, ["T1003.002"]),
    )
    assert karar.decision == SUFFICIENT_SUSPICIOUS
    assert karar.suppression is None


def test_bastirma_hem_surec_hem_hesap_ister() -> None:
    """Tek alan eslesmesi yetmez -- bastirma guvenli yonde dar tutuldu.

    Surec degerleri TAM YOL: Gorev 17'de olculdu ki gercek veri bu bicimi
    tasiyor (77 tam yol / 4 taban ad). Taban ad yazmak testi yesil tutar
    ama uretimde bulunmayan bir bicimi sinar -- yontem madde 17."""
    assert baseline_bastirir_mi(
        "service",
        {"process": r"C:\Windows\servicing\TrustedInstaller.exe", "account": "SYSTEM"},
    )
    assert baseline_bastirir_mi(
        "service",
        {"process": r"C:\Windows\servicing\TrustedInstaller.exe", "account": "corp\\attacker"},
    ) is None
    assert baseline_bastirir_mi(
        "service",
        {"process": r"C:\Windows\System32\powershell.exe", "account": "SYSTEM"},
    ) is None


def test_defender_politikasi_hicbir_aktor_icin_bastirilmaz() -> None:
    assert baseline_bastirir_mi(
        "defender-policy",
        {"process": r"C:\Windows\servicing\TrustedInstaller.exe", "account": "SYSTEM"},
    ) is None


def test_aktor_yoksa_bastirma_yok() -> None:
    assert baseline_bastirir_mi("service", {"process": None, "account": None}) is None


# --------------------------------------- Gorev 17: TABAN AD TEK BASINA YETMEZ

@pytest.mark.parametrize("yol", [
    r"C:\Users\Public\trustedinstaller.exe",
    r"C:\Temp\msiexec.exe",
    r"C:\Windows\Temp\msiexec.exe",
    r"C:\Temp\Windows\System32\msiexec.exe",
])
def test_dogru_taban_ad_yanlis_dizin_BASTIRILMAZ(yol: str) -> None:
    r"""Kor nokta testi: mesru ikili adini kopyalamak bastirma kazandirmaz.

    Gorev 17'nin duzeltmesi "taban ada in" OLSAYDI bu dortlu de bastirilirdi
    ve kor nokta tam olarak saldirganin bu adi yazacagi yerde acilirdi.
    Sonuncu vaka onek eslemesini kapatiyor: \Temp\Windows\System32 bir
    System32 DEGILDIR, cunku desen dizinin BASINDAN itibaren tutmak zorunda.
    Ucuncusu ise Windows agacinin ICINDE ama System32 degil -- \Windows
    onekiyle yetinen bir kural bunu kacirirdi."""
    assert baseline_bastirir_mi("service", {"process": yol, "account": "SYSTEM"}) is None


def test_dizinsiz_taban_ad_BASTIRILMAZ() -> None:
    """Surecin nereden calistigi bilinmiyorsa bastirma yok -- guvenli yon.

    G kolunda 4 satir taban ad tasiyor. Bilinmeyen dogrulanmis sayilmaz;
    eksik tablo yalnizca fazladan alarm uretir, fazla tablo KOR NOKTA."""
    assert baseline_bastirir_mi(
        "service", {"process": "trustedinstaller.exe", "account": "SYSTEM"}
    ) is None


@pytest.mark.parametrize("yol", [
    r"C:\Windows\servicing\TrustedInstaller.exe",
    r"C:\Windows\System32\msiexec.exe",
    r"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack\TiWorker.exe",
    r"D:\Program Files\Vendor\msiexec.exe",
    "C:/Windows/System32/msiexec.exe",
])
def test_guvenilir_dizinden_gelen_bilinen_surec_BASTIRILIR(yol: str) -> None:
    """Surucu harfi, alt dizin ve ayrac bicimi ayrimi bozmaz.

    Program Files bir D: bolumunde olabilir; anlamli olan surucu degil,
    dizinin Windows kurulum agacindaki yeri. WinSxS alt dizinleri gercek
    veride derindir. Ileri bolu de kabul edilir -- ayni olay farkli
    kaynaklarda iki ayracla da geliyor."""
    assert baseline_bastirir_mi("service", {"process": yol, "account": "SYSTEM"})


# ------------------------------------- sozlesme: yokluktan BENIGN yok

def test_bos_girdi_INSUFFICIENT_uretir() -> None:
    karar = decide(normalized=normalize_input(""), mappings=[], verification=None)
    assert karar.decision == INSUFFICIENT_DATA
    assert any("yokluktan BENIGN" in a for a in karar.reason_chain)


def test_unknown_kritiklik_BENIGN_uretemez() -> None:
    """Gorev 4'un karari burada baglayici: unknown != noise."""
    raw = ("{Event ID=4656, Object Type=Key, Object Name=\\REGISTRY\\MACHINE\\SOFTWARE"
           "\\AcmeCorp\\Widget, Accesses=Query key value, Access Mask=0x1, "
           "Process Name=svchost.exe, Account Name=LOCAL SERVICE}")
    karar = decide(normalized=normalize_input(raw), mappings=[], verification=None)
    assert karar.inputs["kritiklik"] == "unknown"
    assert karar.decision == INSUFFICIENT_DATA
    assert any("tablo tanımıyor" in a for a in karar.reason_chain)


def test_teknik_var_ama_dogrulanmamis_ise_yol_A_kurulmaz() -> None:
    """Desteksiz teknik iddiasi tek basina SUSPICIOUS uretemez."""
    karar = decide(
        normalized=normalize_input("bir seyler oluyor"),
        mappings=[{"attack_id": "T1059"}],
        verification=_rapor([{"attack_id": "T1059"}], onaylanan=[]),
    )
    assert karar.paths["A"] is False
    assert karar.decision == INSUFFICIENT_DATA


# ------------------------------ sozlesme: kritiklik KAYNAK SIRASI

def test_kritiklik_komut_satirindan_okunur() -> None:
    """Gorev 5 §6 + Gorev 6: yapisal alan yoksa komut satiri."""
    raw = (r"{Event ID=4688, Process Name=reg.exe, Account Name=admin.svc, "
           r"Process Command Line=reg.exe save HKLM\SAM C:\Users\Public\sam.hive}")
    seviye, aile, yol = varlik_kritikligi(normalize_input(raw))
    assert (seviye, yol) == ("critical", r"HKLM\SAM"), f"{seviye} {yol}"
    assert aile == "credential-hive"


def test_yapisal_alan_komut_satirindan_ONCE_gelir() -> None:
    raw = (r"{Event ID=4657, Object Type=Key, "
           r"Object Name=\REGISTRY\MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender, "
           r"Process Command Line=reg.exe save HKLM\SAM C:\out.hive}")
    seviye, aile, _ = varlik_kritikligi(normalize_input(raw))
    assert aile == "defender-policy", f"{seviye}/{aile}"
