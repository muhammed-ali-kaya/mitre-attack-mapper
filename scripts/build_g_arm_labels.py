"""G kolu etiketleri: 51 gercek QRadar satirinin ELLE yazilmis beklenen cevaplari.

HAT CALISTIRILMADAN yazildi (2026-08-30). Etiketler sistemin ciktisina
bakilarak DEGIL, satirin kendi artefaktlarindan ve ATT&CK v19.1 bundle'indan
cikarildi. G kolunun tek degeri bagimsizligidir: veriyi biz uretmedik ve
etiketi sistemin cevabina bakmadan yazdik. O bagimsizlik bir kere kirilirsa
bu kol sentetik kolun tekrarina doner.

ATT&CK DOGRULAMASI -- ezberden etiket yazmamak icin
    Her teknik ID'si `app/validation/validator.AttackKnowledgeBase` uzerinden
    v19.1 bundle'ina karsi dogrulandi: ID var mi, revoked mi, adi ne.
    Olculdu ve iki sonuc etiketleri DEGISTIRDI:

    1) T1562.001 (Disable or Modify Tools) v19.1'de REVOKED, yerine T1685.
       Ezberden yazilsa gecersiz bir ID kaydedilecekti.

    2) "execution policy" ifadesi 858 teknigin HICBIRININ aciklama veya
       detection metninde GECMIYOR. Yani `-ExecutionPolicy Bypass` bir
       ATT&CK teknigine baglanamaz. Suphe uyandiran bir gostergedir,
       eslestirme degil. Onu T1685'e baglamak uydurma olurdu.

    Buna karsilik `-WindowStyle Hidden` T1564.003'un (Hidden Window) kendi
    metninde birebir ornek olarak geciyor -- bu yuzden o eslestirme yazildi.

BU DOSYA CIKTIYI URETIR, KARARI DEGIL. Karar asagidaki tabloda satir satir
yaziliyor; betik yalnizca 51 kaydi tutarli bicimde serilestiriyor.

    .venv/Scripts/python.exe scripts/build_g_arm_labels.py

Cikti: evaluation/g_arm_qradar_labels.json
"""
from __future__ import annotations

import json
import pathlib
import sys

KOK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from app.batch.qradar_adapter import try_convert_qradar_export  # noqa: E402
from app.batch.serialize import row_to_kv_string  # noqa: E402
from app.validation.validator import AttackKnowledgeBase  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CSV = KOK / "tests" / "fixtures" / "qradar_2026-08-06_51rows.csv"
CIKTI = KOK / "evaluation" / "g_arm_qradar_labels.json"

INSUFFICIENT = "INSUFFICIENT_DATA"
BENIGN = "SUFFICIENT_BENIGN"
SUSPICIOUS = "SUFFICIENT_SUSPICIOUS"

# --- GRUPLAR --------------------------------------------------------------
# Ayni artefakt desenini tasiyan satirlar. Gruplama gorsel kolaylik degil:
# ayni desene farkli etiket verilmesi ancak GEREKCE farkliysa mesrudur, ve
# grup disina cikan her satir asagida tek tek gerekcelendirildi.

CHROME_PROXY = [0, 1, 6, 9, 14, 19, 22, 27, 33, 36, 42]  # 5156 chrome -> :8888
SYSTEM_BROADCAST = [3, 46, 47, 49]                        # 5156 System, NetBIOS/multicast
SVCHOST_MULTICAST = [11, 12, 23, 24, 39, 41, 50]          # 5156 svchost, LLMNR/mDNS
BIND_5158 = [4, 10, 13, 17, 21, 31, 32, 37, 44]           # 5158 yerel port bind
PRIV_4673 = [2, 5, 8, 16, 18, 20, 25, 34, 35, 38, 43]     # 4673 ayricalikli servis
REG_PERF_4656 = [7, 15, 29, 30, 40]                       # 4656 Services\*\Performance
HANDLE_CLOSE = [26]                                        # 4658
HANDLE_DUP = [28]                                          # 4690
POWERSHELL_403 = [45]                                      # 403 PowerShell engine
PUBLIC_BINARY = [48]                                       # 5156, users\public\tdrfagent.exe


def _kayit(
    *,
    teknikler: list[str],
    karar: str,
    negatif: bool,
    inceleme: bool,
    gerekce: str,
    attack_kaynak: str = "",
    reddedilen: str = "",
) -> dict:
    return {
        "expected_attack_ids": teknikler,
        "expected_decision": karar,
        "negative_case": negatif,
        "review_flag": inceleme,
        "rationale": gerekce,
        "attack_source": attack_kaynak,
        "considered_and_rejected": reddedilen,
    }


ETIKET: dict[int, dict] = {}

for i in CHROME_PROXY:
    ETIKET[i] = _kayit(
        teknikler=[],
        karar=INSUFFICIENT,
        negatif=True,
        inceleme=False,
        gerekce=(
            "5156 'permitted a connection' bir kontrolun CALISTIGI kaydidir, "
            "bozuldugu degil. chrome.exe'nin 203.0.113.103:8888'e giden "
            "baglantisi tek basina hicbir teknigi kanitlamaz."
        ),
        reddedilen=(
            "T1071.001 (Web Protocols) dusunuldu ve REDDEDILDI: hedefin "
            "kotucul oldugunu gosteren hicbir kanit yok, 8888 kurumsal "
            "aglarda yaygin bir proxy portu. Inceleme bayragi da konmadi -- "
            "tek gerekce 'alisilmadik port' olurdu ve bu 11 satirin hepsinde "
            "ayni, yani bir desen degil ortam ozelligi."
        ),
    )

for i in SYSTEM_BROADCAST:
    ETIKET[i] = _kayit(
        teknikler=[],
        karar=INSUFFICIENT,
        negatif=True,
        inceleme=False,
        gerekce=(
            "System surecinin NetBIOS datagram (138) ve yerel-kapsam "
            "multicast trafigi. Windows aginin rutin isleyisi."
        ),
    )

for i in SVCHOST_MULTICAST:
    ETIKET[i] = _kayit(
        teknikler=[],
        karar=INSUFFICIENT,
        negatif=True,
        inceleme=False,
        gerekce=(
            "svchost.exe'nin LLMNR (5355) ve mDNS (5353) ad cozumleme "
            "trafigi. Isletim sisteminin kendi ad cozumlemesi."
        ),
        reddedilen=(
            "T1557.001 (LLMNR/NBT-NS Poisoning) dusunuldu ve REDDEDILDI: o "
            "teknik ZEHIRLEYEN tarafi tanimlar. Normal bir LLMNR sorgusu "
            "uretmek kurbanin rutin davranisidir, saldirganin degil."
        ),
    )

for i in BIND_5158:
    ETIKET[i] = _kayit(
        teknikler=[],
        karar=INSUFFICIENT,
        negatif=True,
        inceleme=False,
        gerekce=(
            "5158 yerel bir porta bind izni verildigini kaydeder. Baglanti "
            "bile degil, baglanti hazirligi. Tek basina kanit degeri yok."
        ),
    )

for i in PRIV_4673:
    ETIKET[i] = _kayit(
        teknikler=[],
        karar=INSUFFICIENT,
        negatif=True,
        inceleme=False,
        gerekce=(
            "4673, chrome.exe'nin SeProfileSingleProcessPrivilege cagirmasi. "
            "Tarayicinin kendi surec profillemesi; ayricaligin KOTUYE "
            "kullanildigina dair hicbir gosterge yok."
        ),
        reddedilen=(
            "T1134 (Access Token Manipulation) ailesi dusunuldu ve "
            "REDDEDILDI: ayricalik CAGIRMAK ile token MANIPULE ETMEK ayni "
            "sey degil. 4673 cagriyi kaydeder, degisiklik kaydetmez."
        ),
    )

for i in REG_PERF_4656:
    ETIKET[i] = _kayit(
        teknikler=[],
        karar=INSUFFICIENT,
        negatif=True,
        inceleme=False,
        gerekce=(
            "HKLM\\SYSTEM\\ControlSet001\\Services\\<servis>\\Performance "
            "anahtarina handle istegi. Windows performans sayaci alt "
            "sisteminin rutin isi; aktorler svchost.exe/LOCAL SERVICE ve "
            "MpDefenderCoreService.exe/WINHOST-01$."
        ),
        reddedilen=(
            "T1012 (Query Registry) dusunuldu ve REDDEDILDI: erisim maskesi "
            "sorgu hakki iceriyor ama bu satirlarin kaynagi performans "
            "sayaci alt sistemi, kesif yapan bir aktor degil. Kabul edilebilir "
            "alternatif olarak da YAZILMADI -- yazilsaydi yanlis pozitif "
            "olcumu korlesirdi."
        ),
    )

ETIKET[HANDLE_CLOSE[0]] = _kayit(
    teknikler=[],
    karar=INSUFFICIENT,
    negatif=True,
    inceleme=False,
    gerekce=(
        "4658 yalnizca bir handle'in kapandigini soyler. Hangi nesne, ne "
        "amacla -- hicbiri bu kayitta yok. Tanim geregi kanit tasimaz."
    ),
)

ETIKET[HANDLE_DUP[0]] = _kayit(
    teknikler=[],
    karar=INSUFFICIENT,
    negatif=True,
    inceleme=False,
    gerekce=(
        "4690, SYSTEM olarak calisan bir surecin handle kopyalamasi (hedef "
        "surec 0x4 = System). Makine hesabi altinda rutin cekirdek islemi."
    ),
    reddedilen=(
        "T1134.001 (Token Impersonation) dusunuldu ve REDDEDILDI: handle "
        "kopyalamak token taklidi degildir; 4690 token'a hic deginmiyor."
    ),
)

ETIKET[POWERSHELL_403[0]] = _kayit(
    teknikler=["T1059.001", "T1564.003"],
    karar=SUSPICIOUS,
    negatif=False,
    inceleme=True,
    gerekce=(
        "PowerShell/Operational 403, motorun calisip durdugunu ve "
        "HostApplication alaninda tam komut satirini tasiyor: "
        "'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden "
        "-ExecutionPolicy Bypass -File "
        "C:\\ProgramData\\LabTaskAlwaysOn\\Enforce-LabTaskAlwaysOn.ps1'. "
        "PowerShell'in calistigi dogrudan kanitli (T1059.001) ve pencere "
        "gizleme bayragi acik (T1564.003). BELIRSIZLIK KAYDA GECIYOR: betik "
        "adi ve ProgramData konumu yetkilendirilmis bir laboratuvar "
        "otomasyonuna isaret ediyor; gercek bir ortamda bu degisiklik "
        "yonetimiyle cozulurdu. Yine de triyaj analisti bunu kapatmaz, "
        "inceleme kuyruguna alir -- etiket buna gore SUSPICIOUS + inceleme."
    ),
    attack_kaynak=(
        "T1059.001 PowerShell (v19.1, revoked=False, taktik Execution). "
        "T1564.003 Hidden Window (v19.1, revoked=False) -- teknigin kendi "
        "metninde '-WindowStyle Hidden' birebir ornek olarak geciyor."
    ),
    reddedilen=(
        "T1562.001 / T1685 (Disable or Modify Tools) '-ExecutionPolicy "
        "Bypass' icin dusunuldu ve REDDEDILDI. Iki ayri sebep: (a) T1562.001 "
        "v19.1'de REVOKED, yerine T1685 gecmis; (b) 'execution policy' "
        "ifadesi 858 teknigin hicbirinin metninde GECMIYOR, yani bu bayragin "
        "ATT&CK karsiligi yok. Gosterge olarak kaydedildi, eslestirme olarak "
        "degil."
    ),
)

ETIKET[PUBLIC_BINARY[0]] = _kayit(
    teknikler=[],
    karar=INSUFFICIENT,
    negatif=False,
    inceleme=True,
    gerekce=(
        "5156, ama uygulama yolu \\users\\public\\tdrfagent.exe. Baglantinin "
        "kendisi rutin (mDNS 5353, gelen yon). Kanit degeri OLAYDA degil "
        "KONUMDA: C:\\Users\\Public herkesin yazabildigi klasik bir hazirlik "
        "dizini. Tek basina hicbir teknigi kanitlamaz -- bu yuzden teknik "
        "listesi bos ama inceleme bayragi acik."
    ),
    reddedilen=(
        "T1036.005 (Match Legitimate Resource Name or Location) dusunuldu ve "
        "REDDEDILDI: teknik mesru bir ada/konuma BENZEME gerektirir; "
        "'tdrfagent.exe' bilinen bir bileseni taklit etmiyor. Supheli konum "
        "taklit demek degildir."
    ),
)


def main() -> int:
    satirlar = try_convert_qradar_export(CSV.read_bytes()) or []
    if len(satirlar) != 51:
        raise SystemExit(f"51 satir bekleniyordu, {len(satirlar)} bulundu")
    eksik = sorted(set(range(51)) - set(ETIKET))
    if eksik:
        raise SystemExit(f"Etiketsiz satir kaldi: {eksik}")

    kb = AttackKnowledgeBase().by_id
    kayitlar = []
    for i, satir in enumerate(satirlar):
        e = ETIKET[i]
        for tid in e["expected_attack_ids"]:
            t = kb.get(tid)
            if t is None:
                raise SystemExit(f"satir {i}: {tid} v19.1 bundle'inda YOK")
            if t["revoked"]:
                raise SystemExit(
                    f"satir {i}: {tid} REVOKED -> {t.get('revoked_by')}"
                )
        kayitlar.append({
            "id": f"G-{i:03d}",
            "source_row": i,
            "event_id": str(satir.get("EventID") or "").strip(),
            # HATTA VERILEN metin, uretimdeki toplu modun verdiginin AYNISI.
            # `Message` DEGIL: adaptorun Message kolonu olay ID'sini
            # tasimiyor (govde "A handle to an object was requested" diyor,
            # 4656 demiyor) ve FilePath ayri kolonda duruyor. Message ile
            # kosulsaydi kural kosullari olay ID goremeden bos donerdi --
            # yani olcum sistemi degil kendi kurgumuzu olcerdi.
            "input": row_to_kv_string(satir),
            "message": str(satir.get("Message") or ""),
            **e,
            "attack_version": "19.1",
            "labeled_without_running_pipeline": True,
        })

    dagilim: dict[str, int] = {}
    for k in kayitlar:
        dagilim[k["expected_decision"]] = dagilim.get(k["expected_decision"], 0) + 1

    CIKTI.write_text(
        json.dumps(
            {
                "_aciklama": (
                    "G kolu -- 51 gercek QRadar satirinin elle yazilmis beklenen "
                    "cevaplari. Hat calistirilmadan, ATT&CK v19.1 bundle'ina "
                    "karsi dogrulanarak yazildi. Uretici: "
                    "scripts/build_g_arm_labels.py"
                ),
                "_kaynak": str(CSV.relative_to(KOK)).replace("\\", "/"),
                "attack_version": "19.1",
                "kayit_sayisi": len(kayitlar),
                "karar_dagilimi": dagilim,
                "negatif_ornek": sum(1 for k in kayitlar if k["negative_case"]),
                "inceleme_bayragi": sum(1 for k in kayitlar if k["review_flag"]),
                "teknik_bekleyen_satir": sum(
                    1 for k in kayitlar if k["expected_attack_ids"]
                ),
                "kayitlar": kayitlar,
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )

    print(f"{len(kayitlar)} etiket yazildi -> {CIKTI.relative_to(KOK)}")
    print(f"  karar dagilimi     : {dagilim}")
    print(f"  negatif ornek      : {sum(1 for k in kayitlar if k['negative_case'])}/51")
    print(f"  inceleme bayragi   : {[k['id'] for k in kayitlar if k['review_flag']]}")
    print(
        "  teknik bekleyen    : "
        f"{[(k['id'], k['expected_attack_ids']) for k in kayitlar if k['expected_attack_ids']]}"
    )
    print("  ATT&CK dogrulamasi : tum ID'ler v19.1'de var ve revoked degil")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
