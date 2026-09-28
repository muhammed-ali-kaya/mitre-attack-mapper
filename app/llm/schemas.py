"""LLM'den istenen yapilandirilmis cikti icin JSON schema (dokuman bolum 24).

Ollama'nin 'format' parametresi bu semaya gore kisitli (constrained) decoding
yapiyor, boylece LLM'in gecersiz JSON uretmesi veya alanlari atlamasi engellenir.
attack_version ve input_summary gibi zaten bildigimiz bilgileri LLM'e
urettirmiyoruz -- bunlari kod tarafinda ekliyoruz (halusinasyon riski olmasin diye).
"""

MAPPING_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "observed_behaviors": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Girdiden dogrudan gozlemlenen davranislar (yorum degil, gercek). TURKCE yaz.",
        },
        "mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "attack_id": {"type": "string"},
                    "name": {"type": "string"},
                    "object_type": {"type": "string", "enum": ["technique", "sub-technique"]},
                    "tactics": {"type": "array", "items": {"type": "string"}},
                    "confidence_level": {
                        "type": "string",
                        "enum": ["high", "medium", "low", "insufficient"],
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Kullanici girdisinden BIREBIR ALINTI (kelimesi kelimesine kopyalanmis "
                            "metin parcasi). Teknigin genel aciklamasi veya olasi davranislari DEGIL "
                            "-- yalnizca bu spesifik girdide gecen ifadeler. Ornek: "
                            "'CommandLine=schtasks /create /s 10.10.20.15 ... ifadesi girdide birebir gecmektedir'."
                        ),
                    },
                    "reasoning_summary": {
                        "type": "string",
                        "maxLength": 220,
                        "description": (
                            "KISA gerekce (tek cumle, en fazla ~200 karakter): girdiden kisa bir "
                            "kanit parcasina deginerek bu teknigi neden gosterdigini ozetle. "
                            "Teknigin genel tanimini veya olasi davranis listesini tekrarlama. TURKCE yaz."
                        ),
                    },
                    "source_url": {"type": "string"},
                },
                "required": [
                    "attack_id", "name", "object_type", "tactics",
                    "confidence_level", "evidence", "reasoning_summary", "source_url",
                ],
            },
        },
        "alternative_candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "attack_id": {"type": "string"},
                    "name": {"type": "string"},
                    "reason_not_selected": {"type": "string", "description": "TURKCE yaz."},
                },
                "required": ["attack_id", "name", "reason_not_selected"],
            },
        },
        "additional_data_needed": {
            "type": "array",
            "items": {"type": "string"},
            "description": "TURKCE yaz.",
        },
        # ACTIVITY_VERDICT KALDIRILDI (Gorev 5, 2026-08-19).
        #
        # Alan, modelin "burada saldiri yok" diyebilmesi icin eklenmisti ve o
        # isi gordu: 9 negatif ornegin 9'unda yanlis pozitif uretiliyordu.
        # Ama KARAR olarak kirilgan oldugu OLCULDU -- ayni girdi, ayni prompt,
        # temperature=0, sabit seed; tek fark modelin VRAM'de yuklu olup
        # olmamasi:
        #     model soguk (6/6 kosu) -> malicious_or_suspicious
        #     model sicak (6/6 kosu) -> insufficient_evidence
        # Bir SOC icin bu iki cikti taban tabana zit. Karar artik kod
        # tarafinda, bilesenlerden uretiliyor: app/validation/decision.py.
        #
        # verdict_reason DA GITTI: o alan activity_verdict'in gerekcesiydi;
        # dayanagi kalkinca referanssiz kalirdi. Gerekce metnini artik karar
        # fonksiyonu uretiyor ve HANGI GIRDININ hangi sonucu verdigini yaziyor
        # ("critical varlik + write erisim + 1 dogrulanmis teknik"). Itiraz
        # edilebilir bir zincir; harmanlanmis bir cumle degil.
        #
        # SEMADA YEDEK BIRAKILMADI: alani "ne olur ne olmaz" diye tutmak iki
        # gerceklik demektir -- biri LLM'in beyani, digeri kodun karari.
        #
        # Modelin zorlama eslestirmeye karsi FRENI kalkmadi: prompts.py'deki
        # "her girdi bir saldiri degil" bolumu duruyor ve mappings'i
        # kisitliyor. Kaldirilan sey yalnizca AYRI BIR KARAR ALANI istemekti.
    },
    "required": [
        "observed_behaviors", "mappings", "alternative_candidates", "additional_data_needed",
    ],
}
