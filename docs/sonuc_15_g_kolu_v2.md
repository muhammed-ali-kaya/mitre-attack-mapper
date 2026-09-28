# Sonuç — Görev 15, G kolunun yeniden koşusu (Yol B açıkken)

Koşu: 2026-08-31, 51/51 satır, hata yok, ön planda bütçeli turlarla
(`scripts/run_g_arm.py --out evaluation/results/g_arm_run_v2.json`).
Satır başına ortalama 114 sn.

Beklenti: `docs/beklenti_15_kv_alan_kaybi.md`
Önceki koşu: `docs/sonuc_13_g_kolu.md` (Yol B kapalıyken)
Karşılaştırma: `scripts/compare_g_arm_runs.py`

Her iki koşu da diskte duruyor. Eskisi silinmedi, damgalandı:
`evaluation/results/g_arm_run.json` içindeki `_damga` alanı onu
"Yol B kapalıyken alınmış ölçüm" olarak işaretliyor.

---

## 1. Koşmadan önce yazılan tahmin — TUTTU

Beklenti belgesi §5'te, koşudan önce şu yazılmıştı:

> beş `4656` satırı (G-007, G-015, G-029, G-030, G-040) `0x2001F` maskesiyle
> handle istiyor, maske `Set key value` içeriyor → **Yol B bu beş satırda
> ateşlenir, yanlış alarm 0/49 → 5/49 çıkar.**

```
tahmin: ['G-007', 'G-015', 'G-029', 'G-030', 'G-040']
gerçek: ['G-007', 'G-015', 'G-029', 'G-030', 'G-040']
```

Beşin beşi, fazlası yok. Tahmin `scripts/compare_g_arm_runs.py` içinde
sabit olarak duruyor, çıktıya bakılıp değiştirilemesin diye.

Bu tahmin **Görev 13'ün beklenti belgesinde de vardı ve orada test
edilememişti** — Yol B ölü olduğu için. Şimdi ilk kez sınandı.

---

## 2. Eksen 1 — KARAR (amaçlanan etki)

| | önce | sonra |
|---|---|---|
| sınıf isabeti | 50/51 | 45/51 |
| **yanlış alarm** | **0/49** | **5/49** |
| Yol A ateşleyen | 0 | 0 |
| Yol B ateşleyen | **0** | **5** |
| bastırma ateşleyen | 0 | 0 |
| çıkan sınıf dağılımı | `{INSUFFICIENT_DATA: 51}` | `{INSUFFICIENT_DATA: 46, SUFFICIENT_SUSPICIOUS: 5}` |

**Sınıf isabetinin düşmesi bir gerileme değildir.** Düşen sayı hiç
kazanılmamıştı: önemsiz taban (sabit `INSUFFICIENT_DATA` diyen
sınıflandırıcı) hâlâ 50/51 alıyor ve puanlayıcı bunu kendi uyarısıyla
söylüyor. Önceki 50/51, sistemin ayırt ettiğini değil, bir katmanın hiç
çalışmadığını gösteriyordu.

**Asıl kazanç ölçülebilirlik:** Yol B'nin gerçek yanlış alarm maliyeti artık
bir sayı — 49 negatif örnekte 5. Bu sayı olmadan K1 (kural koşulları) gibi
sonraki işlerin kazancı görünmezdi.

Beş satırın hepsi aynı desen: `Services\*\Performance` anahtarına `0x2001F`
maskesiyle handle isteyen `svchost.exe`. Kritiklik `high`, aile `service`,
erişim `write`. Aktör `NT AUTHORITY\LOCAL SERVICE`, yani
`config/actor_baseline.yaml`'daki tek kayıtla (`service ← TrustedInstaller /
msiexec`) **eşleşmiyor** — bastırma beklenmiyordu, ateşlenmedi de.

### Bu beş satır ne söylüyor

Yol B bugünkü hâliyle "kritik varlık + yazma erişimi" görünce şüpheleniyor.
Ama `Services\<ad>\Performance` anahtarına yazma isteği Windows'ta rutin bir
performans sayacı işlemi. Yani **kusur Yol B'nin ateşlenmesinde değil,
kritiklik tablosunun `service` ailesini fazla geniş çizmesinde** olabilir:
`asset_criticality` bu yolu `high` sayıyor.

Bu bir sonuç değil bir hipotez — bu koşu onu test etmedi. Ayrı kalem olarak
HANDOFF'a taşınıyor.

---

## 3. Eksen 2 — TEKNİK (yan etki)

| | önce | sonra |
|---|---|---|
| toplam üretilen teknik | 109 | 105 |
| satır başına ortalama | 2.1 | 2.1 |
| eşsiz yanlış pozitif teknik | 22 | 24 |
| teknik listesi değişen satır | — | **35/51** |

G-045 (tek pozitif satır) **değişmedi**: iki koşuda da `['T1653']`,
beklenen `['T1059.001', 'T1564.003']`'ün ikisi de yok.

### 35'in kaynağı AYRIŞTIRILAMADI — ve bu ayrıca ölçüldü

`scripts/measure_query_shift.py` (LLM'siz, deterministik) düzeltmenin
sorguyu kaç satırda değiştirdiğini ölçüyor:

```
sorgusu değişen satır   : 46/51
1. katmanı değişen satır: 46/51
```

Yani teknik listesinin değiştiği 35 satırın hepsinin sorgusu da değişmiş
olabilir. **Bu ölçüm sorgu etkisini varyanstan AYIRAMAZ**, çünkü iki koşu da
tek geçiş ve teknik ekseninin varyansı bu projede hiç ölçülmedi
(`docs/sonuc_13_g_kolu.md` §5 bunu zaten yazmıştı). Ayırmak için aynı kodla
ikinci bir koşu gerekir; yapılmadı.

**35 sayısı bu yüzden bir üst sınırdır, bir etki büyüklüğü değildir.**

### 1. katmanda değişen şey çoğunlukla YENİ ALAN DEĞİL, DÜZELEN KAÇIŞ

En sık değişim, kaçışın geri alınması:

```
önce: \\device\\harddiskvolume3\\program files\\google\\...     20 satırda
sonra: \device\harddiskvolume3\program files\google\...
önce: C:\\Program Files\\Google\\Chrome\\Application\\...        11 satırda
sonra: C:\Program Files\Google\Chrome\Application\...
```

Yeni ALAN eklenmesi yalnızca registry/ayrıcalık satırlarında:
`access.list` (5), `object.server` (6), `user.domain` (4+3).

Yani sorgu 46 satırda değişti ama 41'inde değişen şey, ATT&CK metinlerinde
hiç geçmeyen çift ters bölülü yolların düzelmesi — kalite yönü belli,
büyüklüğü ölçülmedi.

---

## 4. Bu koşunun ÖLÇMEDİĞİ şey

- **Teknik ekseninin varyansı.** Yukarıda; 35 bir üst sınır.
- **Yol B'nin tespit gücü.** 51 satırda tek pozitif var ve o satır registry
  değil. Yol B'nin doğru alarm üretip üretmediği bu korpusta ölçülemez —
  yalnızca yanlış alarm maliyeti ölçüldü.
- **`Services\*\Performance` hipotezi** (§2). Kritiklik tablosunun bu yolu
  `high` saymasının doğru olup olmadığı test edilmedi.
- **S ve H kolları.** Değişmedi, koşulmadı. H kolu tanım gereği hâlâ hiç
  koşulmadı.

---

## 5. S koluna etkisi

`docs/sonuc_13_g_kolu.md` §6'daki kayıt **artık geçersiz**: orada
"maske kaybı S'de görünmeyecek, bu bir kapsam ayrımı" yazılmıştı. Kayıp
kapandığı için S ve G artık aynı ayrıştırma davranışını görüyor ve bu ayrım
ortadan kalktı. S yazılırken bu kısıt notu tekrarlanmamalı.
