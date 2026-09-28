# Beklenti 25 — İki ekranın İÇERİĞİNİN okunabilirliği

**Kod yazılmadan önce yazıldı** (madde 1). Ölçüm girdisi:
`data/bulk_results/bulk_20260904_030101.json` — kullanıcının şikâyet ettiği
koşunun ta kendisi (51 satır, INC-1, risk **26/Medium**, **3** güçlü /
**22** zayıf teknik, **2** taktik aşaması).

## Kapsam sınırı — ne DEĞİŞMEYECEK

Bu görev **yalnızca gösterim katmanı**. Aşağıdakiler bu görevde
değiştirilmeyecek, ve değişmediği ölçümle kanıtlanacak:

- `app/correlation/risk_score.py::compute_risk_score` — skor formülü
- `app/mapping/coverage.py::build_coverage_report` — kapsam hesabı
- `app/correlation/dedup.py::split_by_confidence` — güçlü/zayıf ayrımı
- kural kataloğu, şema, ayrıştırma

**Kapanış ölçütü (Ö0):** görev sonrası aynı sonuç dosyası okunduğunda
`risk.score`, `risk.breakdown`, güçlü/zayıf teknik listeleri ve kapsam
raporunun `assessable`/`unassessable` bölünmesi **birebir aynı** olmalı.
Ölçen: `scripts/measure_task25_display_only.py`, gerilemede exit 1.

## 1. Teknik başına "ne oldu" cümlesi

**Kaynak seçimi — madde 7 ("aynı işi yapan başka kaç yol var?").**
Yeni bir "hangi olayda hangi alan gösterilir" tablosu YAZILMAYACAK.
`config/event_semantics.yaml` bunu zaten tutuyor: `anlamli_alanlar`
alanı **olay başına** anlam taşıyan kanonik alanları listeliyor
(5156 → `source.ip, destination.ip, destination.port, process.name`).
Cümle bu listeden kurulacak. `anlam` alanı da olayın Türkçe tek cümlelik
tarifi olarak zaten orada.

Bu, K2'nin çözülmemiş `(teknik, olay) → alan` sorununu **çözmez ve
açmaz**: K2 kural EŞLEŞTİRMESİ için alan seçiyor, burada yalnızca
GÖSTERİM için seçiliyor ve anahtar tek başına olaydır.

Alan değerleri satırın kanonik ayrıştırmasından (`text_to_row`) okunacak,
ham `evidence` dizesinden değil — şikâyetin kaynağı zaten `evidence`'ın
ham log kopyası olması.

### Ö1 — kapsama tahmini (yanlış çıkabilir)

Katalogda **31** olay var. INC-1'in 25 tekniğinin hepsine cümle
üretilemeyecek: en az bir tekniğin olay ID'si katalogda **yok** ve o
teknik cümlesiz kalacak. Somut tahmin: **T1134.002 (satır 28) olay
`4690` ile geliyor ve 4690 katalogda YOK.**

Katalogda olmayan olay için cümle **uydurulmayacak**; bugünkü davranışa
(teknik adı + kayıt sayısı) düşülecek. Kaç teknikte böyle olduğu
ölçülüp raporlanacak — düşük çıkması gerekmiyor, GÖRÜNÜR olması gerekiyor.

### Ö2 — `process.name` tam yol geliyor

Gerçek kaynak `Application Name: \device\harddiskvolume3\...\chrome.exe`
yazıyor. Cümlede **taban ad** (`chrome.exe`) gösterilecek, tam yol
detay listesinde duracak. Yön Görev 24'ün kuralıyla aynı: **yol → ad
tek taraflı**; tersi (adı yol saymak) yapılmayacak.

### Ö3 — cümle şablonu

`{SS:DD} · {aktör} → {hedef}, {olayın anlamı} ({olay_id})`

Aktör ve hedef yalnızca o olayın `anlamli_alanlar` listesinden seçilir.
Dolu alan yoksa o parça düşer, cümle kısalır — **yer tutucu basılmaz**
(Görev 24'ün `- -` dersi).

## 2. Risk skoru bileşenlerinin açıklaması

Skor zaten `0-100` ölçekli ve ekranda `26/100` yazıyor; eşikler de
`_render_risk_breakdown` altındaki caption'da var. **Eksik olan tek şey:
her bileşenin yanında o sayının NEREDEN geldiğini söyleyen cümle.**

Her bileşen için: `"{etiket}: {gerekçe} ({işaretli katkı})"`, ör.
`"Taktik yayılımı: 15 ATT&CK fazının 2'si görüldü (+4,0)"`.

**Ö4:** üretilen cümlelerdeki katkı sayıları, `breakdown` sözlüğündeki
değerlerle **birebir** aynı olacak — cümle üretici hiçbir şey yeniden
hesaplamıyor, yalnızca mevcut değerleri okuyup gerekçelendiriyor.
Toplamları `score`'a yuvarlanarak eşit olmalı (Ö0'ın alt kalemi).

Eşikler tabloya bitişik ve **sayıyla** yazılacak: `<25 Düşük ·
25-49 Orta · 50-74 Yüksek · 75+ Kritik`.

## 3. "Kanıt düzeyi yeterli" eşiği ekranda

Ayıran şey `dedup.STRONG_CONFIDENCE_LEVELS` = `{high, medium}`; alan
yoksa skor `>= 0.5`. Bu iki cümleyle ekrana yazılacak. Eşik **koddan
okunacak**, metne elle yazılmayacak — kod değişirse metin de değişsin.

## 4. Olay ID'lerinin yanına adı

`event_semantics.yaml::anlam` zaten 31 olayın tarifini tutuyor.
`4657 (registry değeri değiştirildi)` biçiminde basılacak; **katalogda
olmayan ID çıplak kalacak** (kullanıcı açıkça böyle istedi).

**Ö5:** kural kataloğunun beklediği olay ID kümesinin tamamı katalogda
YOK. Kaç tanesinin adsız kaldığı ölçülüp yazılacak.

## 5. "Ne yapmalıyım" — gerekli log kaynağı

Kullanıcının verdiği basit eşleme: `1-30` = Sysmon, `4xxx/5xxx` =
Windows Güvenlik denetimi, `7045` = System log.

**Ö6 — bu eşlemenin YANLIŞ sınıflayacağı en az bir ID var.**
Somut tahmin: **`4104` PowerShell script block olayıdır ve Security
log'da değil, `Microsoft-Windows-PowerShell/Operational` kanalındadır.**
`4xxx → Windows Security` kuralı onu yanlış kaynağa yollar — analist
yanlış log kaynağını açar. Ölçülecek; doğrulanırsa eşlemeye bu ID için
ayrı bir kayıt girecek ve **sapma gerekçesiyle** yazılacak.

Eşleme veri olarak tutulacak (kod içine gömülü `if` zinciri değil),
çünkü ikinci bir istisna çıktığında yeri belli olsun.

## Ölçüm araçları

- `scripts/measure_task25_display_only.py` — Ö0: analiz çıktısı değişmedi
- `scripts/measure_task25_readability.py` — Ö1/Ö5/Ö6 kapsama sayıları

Madde 3: **ölçüm aracı da test edilir** (dokuz kez araç hatası bulundu).
Her iki betiğin de üzerinde çalıştığı veri gerçek koşu dosyasıdır,
fixture değil.

---

# SONUÇ — ölçüldü (2026-09-04)

## Ö0 — GEÇTİ: analiz çıktısı değişmedi

`scripts/measure_task25_display_only.py`. Taban çizgi **değişiklikten
önceki kodla** üretildi (`git stash` ile), sonra yeni kodla
karşılaştırıldı — sonradan yazılan bir taban çizgi hiçbir şey kanıtlamaz.

```
Ö0 GECTI — analiz ciktisi taban cizgiyle BIREBIR ayni.
  INC-1: risk 26/100 Medium · 3 guclu / 22 zayif teknik
  kapsam: 2 degerlendirilebilir / 10 degerlendirilemez taktik
```

Tam takım **1322 → 1372** geçiyor (+50).

## Ö1 — DOĞRULANDI: 25 tekniğin 22'sine cümle kuruluyor

Tahmin "en az bir teknik cümlesiz kalacak, somut olarak T1134.002'nin
`4690`'ı katalogda yok" idi. **Doğrulandı, ve bir tane daha çıktı:**

| | sayı |
|---|---|
| teknik | 25 |
| olayı katalogda olan | **22** |
| + anlamlı alanı dolu olan | **22** |
| katalogda olmayan olay | `4690` (2 teknik), `403` (1 teknik) |

Cümlesiz kalan 3 teknikte `-` basılıyor, uydurulmuyor.

## Ö2 — DOĞRULANDI: kaynak tam yol yazıyor

`\device\harddiskvolume3\...\chrome.exe` → cümlede `chrome.exe`.
Türetim yönü tek taraflı (Görev 24 kuralı), test:
`test_taban_ad_turetimi_TEK_TARAFLI`.

## Ö3/Ö4 — GEÇTİ: cümleler hiçbir şey yeniden hesaplamıyor

Katkı sütunundaki her değer `breakdown` sözlüğünün ta kendisi; toplamları
yuvarlandığında `score`'a eşit (`test_katkilarin_toplami_skora_esit`).

## Ö5 — DOĞRULANDI VE BEKLENENDEN AĞIR: 48 ID'nin 27'si adsız

Kural kataloğunun beklediği **48** olay ID'sinin **27'si**
`event_semantics.yaml`de **yok** — yani "Tespit Kapsamı" ekranındaki
ID'lerin yarısından fazlası çıplak kalıyor:

```
104, 12, 22, 400, 4698, 4699, 4700, 4702, 4728, 4756, 4769, 4778,
4946, 4947, 4948, 4949, 4950, 4954, 5001, 5010, 5012, 5025, 5101,
5145, 7, 7040, 8
```

**İkinci bir ad tablosu AÇILMADI.** Kullanıcı "tabloda olmayanlar ID
olarak kalsın" dedi; ayrıca `event_semantics.yaml`e kayıt eklemek
`islem_sinifi`/`anlamli_alanlar` üzerinden **analiz katmanını değiştirir**
ve bu görevin kapsamı dışıdır. Sınır burada **görünür** kılındı.

## Ö6 — DOĞRULANDI, VE İKİNCİ BİR BOŞLUK TESTLE BULUNDU

Basit aralık eşlemesinin **iki** kusuru var, biri tahmin edilmişti:

1. **`4104` YANLIŞ sınıflanıyor** (tahmin edilmişti). `4xxx → Security`
   kuralı onu Güvenlik günlüğüne yolluyor; oysa PowerShell script block
   olayı `Microsoft-Windows-PowerShell/Operational` kanalındadır. Analist
   yanlış log kaynağını açardı.
2. **`1102` HİÇBİR aralığa düşmüyor** (tahmin edilmemişti,
   `test_katalogdaki_her_olay_bir_kaynaga_baglanabiliyor` yakaladı).
   "Denetim günlüğü temizlendi" Security kanalının olayıdır ama 30 ile
   4000 arasında kaldığı için kaynağı "bilinmiyor" çıkıyordu. Aralık
   kuralı bu ID için **yanlış değil, eksik** — sonuç yine analistin
   işine yaramazdı.

İkisi de `config/log_sources.yaml`de istisna olarak, sapma gerekçesiyle
duruyor. `test_istisna_tablosu_ARALIKLARLA_CELISMEYEN_kayit_TASIMAZ`
aralıkla aynı sonucu veren ölü istisna satırı girmesini engelliyor.

## Test ölü bir gösterim satırı yakaladı

`TARGET_FIELDS` tablosunda `target.user.name` vardı ve **hiçbir olayın**
`anlamli_alanlar` listesinde geçmiyordu — yani hiç ateşlenmeyecek ama
tabloyu büyütecek ve desteklendiği izlenimi verecek bir satır. Test
(`test_her_gosterim_alani_en_az_bir_olayin_anlamli_alani`) yakaladı,
satır silindi. Madde 6: düzeltme mekanizma katmanında yapıldı, test
gevşetilmedi.

## YENİ AÇIK KALEM — gösterim K1'i görünür kıldı

Cümleler yan yana gelince şu ortaya çıktı: **beş ayrı teknik AYNI
kaydı gerekçe gösteriyor.**

```
T1049 System Network Connections Discovery | 11:27 · chrome.exe → 203.0.113.103:8888 ... (5156)
T1095 Non-Application Layer Protocol       | 11:27 · chrome.exe → 203.0.113.103:8888 ... (5156)
T1571 Non-Standard Port                    | 11:27 · chrome.exe → 203.0.113.103:8888 ... (5156)
T1559 Inter-Process Communication          | 11:48 · chrome.exe → 203.0.113.103:8888 ... (5156)
T1546.003 WMI Event Subscription           | 11:28 · svchost.exe → 224.0.0.252:5355 ... (5156)
```

Bu **gösterim kusuru değil**, K1'in ta kendisi: 49 kuralın 12'si ayırt
edici koşul taşımıyor (Görev 23). Şimdiye kadar "5 kayıt" rakamının
arkasında saklıydı; cümle onu okunur hâle getirdi. **Düzeltme
yapılmadı** — K1 kuyruğunda duruyor ve bu görevin kapsamı dışı.
Gösterim katmanının beklenmeyen kazancı: kusur artık ekranda görünüyor.

## Yapılmayan, kasıtlı

- `event_semantics.yaml`in Türkçesi düzeltilmedi ("baglantiya IZIN
  VERDI"). Katalog ASCII yazılmış; metni değiştirmek analiz katmanına
  dokunan ayrı bir kalem.
- 27 adsız olay ID'si için ad yazılmadı (Ö5'teki gerekçe).
- Risk formülü, kapsam hesabı, güçlü/zayıf eşiği: hiçbiri değişmedi (Ö0).
