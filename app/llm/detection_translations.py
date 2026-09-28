"""Elle hazirlanmis (curated) MITRE detection metni cevirileri.

Neden statik dosya, neden runtime ceviri degil: bu metinler ATT&CK surumu
degisene kadar birebir sabit -- 697 teknigin detection metni her sorguda
yeniden cevrilecek bir sey degil. Onceden cevirip dosyaya koymanin uc kazanci
var:
  1. Demo sirasinda sifir gecikme, sifir token, internet/Ollama gerekmiyor.
  2. Deterministik -- ayni girdi her calistirmada ayni Turkce metni verir.
     LLM cevirisi her yeni teknikte biraz farkli sonuc uretebiliyor.
  3. Ceviriler gozden gecirilebilir; ATT&CK terminolojisinin ("Scheduled
     Task/Job", "T1053") cevrilmeden kalmasi elle garanti altina alinir.

Dosya bicimi (data/translations/detection_tr.json):
    {
      "attack_version": "19.2",
      "entries": {
        "T1053.005": {"en": "<orijinal Ingilizce metin>", "tr": "<ceviri>"}
      }
    }

"en" alanini da saklamamiz bilincli: onbellek Ingilizce metinden Turkce metne
eslesiyor. ATT&CK verisi guncellenip bir teknigin detection metni degisirse
kayitli "en" artik yeni metinle eslesmez, o kayit sessizce devre disi kalir ve
sistem LLM cevirisine geri duser. Yani bayat bir ceviri yeni metnin yerine
gecemez -- eskimeyi kendisi yakalar.
"""

from __future__ import annotations

import json
from pathlib import Path

TRANSLATIONS_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "translations" / "detection_tr.json"
)


def load_curated_translations(path: Path = TRANSLATIONS_PATH) -> dict[str, str]:
    """Ingilizce metin -> Turkce metin sozlugu dondurur.

    Dosya yoksa ya da bozuksa BOS sozluk doner: ceviri bir sunum detayi,
    eksikligi analizi dusurmemeli -- cagiran taraf LLM cevirisine devam eder.
    Cevirisi henuz yapilmamis ("tr" bos) kayitlar atlanir, boylece yarim
    doldurulmus bir dosya bos metin gostermez.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    entries = raw.get("entries") or {}
    translations: dict[str, str] = {}
    for entry in entries.values():
        english = (entry.get("en") or "").strip()
        turkish = (entry.get("tr") or "").strip()
        if english and turkish:
            translations[english] = turkish
    return translations
