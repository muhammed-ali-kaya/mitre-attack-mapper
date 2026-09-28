from __future__ import annotations

import pytest

from app.validation.benign_signals import detect_benign_signals


# -- test setindeki gercek yanlis pozitifler ---------------------------------
# Bu bes girdi, 12 Agustos kosusunda sistemin saldiri olarak isaretledigi
# mesru faaliyetler. Her biri artik sinyal uretmeli.

@pytest.mark.parametrize("raw_input,beklenen_parca", [
    ("BT departmani, onayli bir degisiklik talebi (ticket #4521) kapsaminda her gece "
     "02:00'de calisan bir zamanlanmis gorev olusturdu.", "ticket #4521"),
    # Birden fazla yetki ifadesi varsa ilk eslesen raporlanir ("onayli"),
    # hepsini listelemek analiste ek bilgi vermiyor.
    ("Sistem yoneticisi, imzali ve onayli bir envanter toplama betigini PowerShell ile "
     "calistirdi.", "onayli"),
    ("Yardim masasi personeli, acik bir destek talebi (ticket #7788) icin kullanicinin "
     "bilgisayarina yetkilendirilmis uzak baglanti kurdu.", "ticket #7788"),
    ("EventID=4688 NewProcessName=C:\\Windows\\System32\\wuauclt.exe "
     "CommandLine=wuauclt.exe /detectnow", "wuauclt.exe"),
    ("Bir gelistirici, sirketin kendi dahili Nexus paket deposundan bir yapi artefaktini "
     "indirmek icin curl kullandi.", "Nexus"),
])
def test_known_false_positives_now_produce_signals(raw_input, beklenen_parca):
    result = detect_benign_signals(raw_input)
    assert result.found, f"sinyal uretilmedi: {raw_input[:60]}"
    assert result.strong, f"sinyal zayif kaldi: {raw_input[:60]}"
    assert any(beklenen_parca.lower() in s.lower() for s in result.signals)


# -- gercek saldirilar sinyal URETMEMELI -------------------------------------

@pytest.mark.parametrize("raw_input", [
    "EventID=4688 NewProcessName=schtasks.exe CommandLine=schtasks /create /s 10.10.20.15 "
    "/tn UpdateCheck /tr powershell.exe -enc SQBFAFgA /sc onlogon",
    "wevtutil cl Security komutu calistirildi ve olay gunlugu temizlendi",
    "mimikatz.exe sekurlsa::logonpasswords ile lsass bellegi okundu",
])
def test_real_attacks_produce_no_benign_signals(raw_input):
    assert detect_benign_signals(raw_input).found is False


def test_empty_input_is_safe():
    assert detect_benign_signals("").found is False


# -- zayif sinyaller tek basina yetmez, ikisi birlesince yeter ---------------

def test_single_weak_signal_is_not_strong():
    result = detect_benign_signals("Sistem yoneticisi bir islem gerceklestirdi.")
    assert result.found is True
    assert result.strong is False


def test_two_weak_signals_together_are_strong():
    result = detect_benign_signals("Sistem yoneticisi onayli bir islem gerceklestirdi.")
    assert result.strong is True


# -- assess_activity KALDIRILDI (Gorev 5) -------------------------------------
#
# Bu dosyanin ikinci yarisi assess_activity'yi sinardi: LLM'in
# activity_verdict beyani ile kod sinyallerinin birlesimi. Alan semadan
# cikti, fonksiyon silindi.
#
# Bu katmanin BASTIRMA gorevi kayboldu mu? Hayir, YER DEGISTIRDI ve
# daraldi: detect_benign_signals artik YALNIZCA GOSTERIM icin cagriliyor
# (improved_pipeline "benign_signals_display"), karar girdisi degil.
# Sebep olculdu -- ham metin taramasi taklit edilebilir: T3'e aktor
# OLMAYAN bir alana "trustedinstaller.exe" dizesi konunca sinyal
# strong=False'tan True'ya doniyor, process.name hala powershell.exe.
#
# Bastirma isini artik aktor baseline yapiyor ve (varlik ailesi, aktor)
# CIFTINE bakiyor: tests/test_decision.py.
#
# Yukaridaki detect_benign_signals testleri DURUYOR: fonksiyon hala
# uretimde, yalnizca tuketicisi degisti.
