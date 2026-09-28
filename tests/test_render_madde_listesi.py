"""`app/ui/render.py` madde listesi cizimi -- bos madde ve markdown kacisi.

NEDEN VAR: "Tespit edilmeyenler" bolumu icerigi olmayan madde isaretleri
basiyordu (sunumda gorundu). Iki ayri sebep olculdu:

  1. Liste bosken yer tutucu `["-"]` idi ve `st.write("- -")` uretiyordu.
  2. Kanit terimleri markdown'a sokuluyordu; EVIDENCE_REQUIREMENTS'ta
     GERCEKTEN duran `*.evtx deletion` terimi bir vurgu acmaya calisiyor.

Ikincisi madde 17'nin tersi bir vaka: bicim uretimde VAR, testte yoktu.
"""

from __future__ import annotations

import types

import pytest


@pytest.fixture
def render(monkeypatch):
    """Render modulunun `st` bagini sahteyle degistirir.

    Modulu yeniden ICE AKTARMAK denendi ve SESSIZCE bozuk cikti:
    `sys.modules.pop("app.ui.render")` paket niteligini (`app.ui.render`)
    temizlemiyor, bu yuzden `from app.ui import render` ilk testin modulunu
    geri veriyor ve cizimler ilk testin listesine gidiyor -- ikinci testten
    itibaren kayit BOS gorunuyordu. Modul niteligini dogrudan degistirmek
    hem daha kisa hem de bu tuzagi tasimiyor."""
    kayit: list[tuple[str, str]] = []

    sahte = types.SimpleNamespace(
        write=lambda s, *a, **k: kayit.append(("write", str(s))),
        caption=lambda s, *a, **k: kayit.append(("caption", str(s))),
    )

    from app.ui import render as modul

    monkeypatch.setattr(modul, "st", sahte)
    modul_kayit = kayit
    monkeypatch.setattr(modul, "_kayit", modul_kayit, raising=False)
    return modul


def test_bos_liste_madde_isareti_uretmez(render):
    render._madde_listesi([], "eksik kanit yok")
    assert render._kayit == [("caption", "eksik kanit yok")]


def test_yalnizca_bosluk_iceren_ogeler_madde_uretmez(render):
    """Bos dize ve bosluk `- ` uretiyordu: icerigi olmayan madde isareti."""
    render._madde_listesi(["", "   ", "\n"], "hicbiri yok")
    assert render._kayit == [("caption", "hicbiri yok")]


def test_bos_ogeler_dolu_olanlari_elemez(render):
    render._madde_listesi(["", "gercek oge", "  "], "yok")
    assert render._kayit == [("write", "- gercek oge")]


def test_yildizli_kanit_terimi_markdown_olarak_yorumlanmaz(render):
    """`*.evtx deletion` EVIDENCE_REQUIREMENTS'ta duran GERCEK bir terim."""
    from app.validation.evidence_requirements import EVIDENCE_REQUIREMENTS

    terim = "*.evtx deletion"
    assert terim in EVIDENCE_REQUIREMENTS["T1685.005"], (
        "terim katalogdan kalkmissa bu test artik uretimdeki bir bicimi "
        "ornekleMIYOR demektir -- yenisiyle degistirilmeli"
    )

    render._madde_listesi([f"T1685.005 icin beklenen kanit: {terim}"], "yok")
    (_, cizilen), = render._kayit
    assert "\\*" in cizilen, "yildiz kacirilmali, yoksa vurgu acmaya calisiyor"
    assert "evtx" in cizilen


def test_duz_metin_veriyi_bozmadan_kacirir(render):
    assert render._duz_metin("Win32_Process") == r"Win32\_Process"
    assert render._duz_metin("sade metin") == "sade metin"
