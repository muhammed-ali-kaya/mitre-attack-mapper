# Sonuç — Görev 13, S kolu (60 sentetik log)

Beklenti: `docs/beklenti_13_s_kolu.md` · Set: `evaluation/s_arm_set.json`
(commit `691aced`) · Koşu: `scripts/run_g_arm.py --set` → `evaluation/results/s_arm_run.json`

> **§0, §1 ve §2 KOŞUDAN ÖNCE yazıldı** (commit tarihçesi bunu gösterir).
> Sonuç sayıları geldikten sonra yazılan tek yer §3 ve sonrasıdır.

---

## 0. BU RAPOR G İLE YAN YANA OKUNMAZ

S ve G **farklı giriş yollarını** ölçüyor:

| | G kolu | S kolu |
|---|---|---|
| kaynak | gerçek QRadar CSV export | elle yazılmış sentetik log |
| taşıyıcı | toplu yolun serileştirmesi (`row_to_kv_string`) | toplayıcı zarfı (`Timestamp=... EventID=... Message="..."`) |
| iç gövde | sarmalanmış `Message`, Görev 15'e kadar ayrıştırılmıyordu | doğrudan yazılmış gövde |
| dağılım | gerçek, biz üretmedik | tasarlanmış |

**S'in G'den daha iyi çıkması "sistem iyi" demek DEĞİLDİR — "bu giriş yolu
daha az kayıplı" demektir.** İki kolun sayıları toplanmaz, oranları
karşılaştırılmaz, biri diğerinin gelişmesi olarak okunmaz.

**B2 (beklenti §2, bağlayıcı):**

> `4656` + yazma maskesi + kritik anahtar üçlüsü **BİLİNEN** bir yanlış alarm
> kaynağıdır (Görev 16); S'teki oranı sistemin ayırt etme gücü değil, bu
> bilinen kusurun sıklığıdır.

Bu sette o üçlünün **dozu 3 kayıttır** (B1'in A yarıları) ve bu bir tasarım
parametresidir, ölçüm sonucu değil.

---

## 1. TEK GEÇİŞ — VARYANS ÖLÇÜLMEDİ

Bu koşu **tek geçiştir**. Sette hiçbir kayıt tekrar koşulmadı, `--repeat`
kullanılmadı.

**Sonuçtaki hiçbir fark varyanstan ayrılmış sayılmaz.** G kolunda teknik
ekseni için yazılan kısıt burada da aynen geçerlidir: teknik listesindeki
her değişim bir **ÜST SINIRDIR**, ölçülmüş etki değil. Karar sınıfı ekseni
G'de üç koşuda sabit çıkmıştı (`85e5f32`), ama bu S için **devralınamaz** —
S'in girdileri farklı ve o kararlılık S'te ölçülmedi.

Bu paragraf sonuç görülmeden yazıldı ki, sayılar geldiğinde "aslında
varyans küçüktür" diye gevşetilmesin.

---

## 2. RAPORUN MERKEZİ: B1 ÇİFTİ — toplam sayılar değil

60 logun ortalama isabeti bu koşunun **en az bilgilendirici** çıktısıdır:
G kolu, sabit tek cevap veren aptal bir sınıflandırıcının da 50/51 aldığını
gösterdi. Bu koşunun cevaplaması gereken soru tek:

> **`4656` (talep) → `INSUFFICIENT_DATA` ile `4663` (gerçekleşen) →
> `SUFFICIENT_SUSPICIOUS` ayrımı tutuyor mu?**

Üç anahtar × iki yarı = **6 kayıt**. Değerlendirme kuralı, sonuç görülmeden:

| gözlem | okuma |
|---|---|
| altı yarının altısı beklendiği gibi | ayrım tutuyor — ama Görev 16'nın 4656 kusuru bu sette **görünmedi**, kapandı demek değil |
| A yarıları SUSPICIOUS çıkıyor | **beklenen kusur**: talep gerçekleşmiş sayılıyor (`access_class = mask_class or event_class`) |
| B yarıları INSUFFICIENT çıkıyor | ayrı ve **daha ağır** bir kusur: gerçekleşen erişim bile karar üretmiyor |
| üç anahtarda tutarsız | anahtara bağlı bir etken var; hangi anahtarda saptığı yazılacak |

**Tutarlılık ayrıca raporlanır:** üç anahtarın üçünde aynı davranış mı, yoksa
biri diğerlerinden mi ayrılıyor? Tek anahtarda görülen fark o anahtarın
kazası olabilir — çiftin üç kez tekrarlanmasının sebebi buydu.

---

## 3. B1 çifti — ayrım TUTMUYOR, ve tam tahmin edilen yarıda

Altı kaydın altısı da koşuldu (`evaluation/results/s_arm_run.json`).

| kayıt | olay | beklenen | gerçek | tuttu | Yol A | Yol B |
|---|---|---|---|---|---|---|
| S-B1-1A | 4656 | INSUFFICIENT_DATA | **SUFFICIENT_SUSPICIOUS** | hayır | evet | evet |
| S-B1-1B | 4663 | SUFFICIENT_SUSPICIOUS | SUFFICIENT_SUSPICIOUS | evet | evet | evet |
| S-B1-2A | 4656 | INSUFFICIENT_DATA | **SUFFICIENT_SUSPICIOUS** | hayır | hayır | evet |
| S-B1-2B | 4663 | SUFFICIENT_SUSPICIOUS | SUFFICIENT_SUSPICIOUS | evet | hayır | evet |
| S-B1-3A | 4656 | INSUFFICIENT_DATA | **SUFFICIENT_SUSPICIOUS** | hayır | hayır | evet |
| S-B1-3B | 4663 | SUFFICIENT_SUSPICIOUS | SUFFICIENT_SUSPICIOUS | evet | hayır | evet |

**§2'nin ikinci satırı gerçekleşti:** A yarıları `SUSPICIOUS` çıkıyor — talep
gerçekleşmiş sayılıyor (`access_class = mask_class or event_class`, Görev 16
§4). Okuma sonuç görülmeden yazılmıştı.

**Üç anahtarda TUTARLI: 3/3.** SAM, `SECURITY\Policy\Secrets` ve
`Control\Lsa` — üçünde de aynı davranış. Yani bu bir anahtarın kazası değil,
katmanın kuralı.

### Asıl okuma: bu "3 yanlış, 3 doğru" DEĞİL

Altı kaydın altısında da **Yol B ateşlendi** ve altısı da aynı kararı verdi.
Çiftin iki yarısı arasında sistem **hiçbir fark üretmedi**; B yarılarının
"tutması", ayırt etmesinden değil, beklentinin tesadüfen sistemin sabit
cevabıyla çakışmasından geliyor.

**Doğru cümle: altı kayıtta tek davranış var, biri beklentiye uyuyor.**
"3/6 isabet" diye raporlamak, G kolunun 50/51'ini kazanılmış sanmakla aynı
hata olurdu — bu projede altıncı kez: *doğru cevap, yanlış sebep.*

### Bunun değeri: kusur artık ÖLÇÜLEBİLİR

Görev 16 bu kusuru 5 kontrolsüz gerçek satırda **teşhis** etmişti ve
düzeltmeyi bilerek ertelemişti: G korpusunda 0 tane 4663 vardı, yani
düzeltme "beş alarm sustu" dese bile doğru sebepten mi sustuğu ayrılamazdı.
Artık tek değişkenli, üç tekrarlı bir ölçüm aracı var:

> Düzeltme doğruysa **A yarıları `INSUFFICIENT_DATA`'ya düşer, B yarıları
> `SUFFICIENT_SUSPICIOUS` kalır.** İkisi birden susarsa düzeltme ayırt
> etmiyor, her şeyi bastırıyordur — Görev 16 §5'in korktuğu sonuç.

Bu, `S → düzeltme` sırasının gerekçesiydi ve sıra işledi.

### Kısıtlar (§0 ve §1'den, gevşetilmedi)

- Bu **tek geçiş**. Altı kaydın hiçbiri tekrar koşulmadı; kararların
  varyansı ölçülmedi. Teknik ekseni tamamen okunmadı — A ve B yarılarının
  teknik listeleri farklı çıktı (ör. 1A `[T1012, T1003.002]`, 1B
  `[T1003.002, T1552.002]`) ama bu fark **üst sınırdır**, varyanstan
  ayrılmamıştır.
- Bu tablo G ile yan yana okunmaz.

---

## 4. Tüm set — 60/60 koşuldu, hata 0

### 4.1 Baş sayı ve onu geçersiz kılan taban

```
karar sinifi isabeti            : 36/60  (%60)
ONEMSIZ TABAN (hep SUSPICIOUS)  : 43/60  (%72)
```

**Sistem, sabit tek cevap veren aptal sınıflandırıcının ALTINDA kaldı.**
G kolunda taban sistemin sayısına eşitti; burada tabanın gerisinde.

İki yönlü okunmalı ve iki yönü de yazılıyor:

- **Tabanın yüksekliği S'in tasarımından geliyor.** Set katmanları
  uyandırmak için kuruldu, o yüzden 60 kaydın 43'ünde beklenen cevap
  `SUSPICIOUS`. Bu, setin özelliğidir, sistemin değil — yani "%72 taban"
  bir başarı çıtası değil, **bu setin ne kadar dengesiz olduğunun ölçüsü**.
- **Ama karşılaştırma yine de geçerli:** aynı kural G'de uygulanmıştı ve
  orada 50/51'i kazanılmamış ilan etmişti. Kuralı sayı lehimize düştüğünde
  uygulayıp aleyhimize düştüğünde gevşetmek olmaz. **36/60 kazanılmış bir
  sayı değildir.**

### 4.2 S amacını gerçekleştirdi: katmanlar UYANDI

| | G kolu (51 satır) | S kolu (60 log) |
|---|---|---|
| Yol A ateşledi | 0, sonra 0 | **18/60** |
| Yol B ateşledi | 0, düzeltmeden sonra 5 | **20/60** |

Görev 13'ün açılış gerekçesi buydu: G bu katmanları ölçemiyordu. **Artık
ölçülüyorlar.** (İki sütun yan yana OKUNMAZ — §0. Buradaki karşılaştırma
"hangi set katmanı uyandırıyor" sorusudur, "hangi sistem daha iyi" değil.)

### 4.3 Blok bazında

| blok | isabet | okuma |
|---|---|---|
| **Yol B tetikleyenler** | **10/10** | kritiklik + gerçekleşen erişim yolu beklendiği gibi çalışıyor |
| Negatif örnekler | 9/12 | |
| Yol A tetikleyenler | 7/14 | teknik + kanıt vakalarının yarısı karara dönüşmüyor |
| **B1 çifti** | 3/6 | §3 — tek davranış, biri beklentiye uyuyor |
| **EK-2** | **2/4** | §4.5 |
| Olay ID genişliği | 5/14 | en zayıf blok; çoğu tek satırlık hesap/grup olayı |

### 4.4 Yanlış alarm: 7/17 negatif örnek

`S-B1-1A`, `S-B1-2A`, `S-B1-3A`, `S-EK2-01`, `S-EK2-02`, `S-N-03`, `S-N-06`

**B2 (bağlayıcı, §0):** bu yediden **üçü** (`S-B1-*A`) `4656` + yazma
maskesi + kritik anahtar üçlüsüdür — **BİLİNEN** yanlış alarm kaynağı
(Görev 16). Dozları tasarım gereği 3'tü ve üçü de ateşledi. **Yani bu
setteki yanlış alarm oranının %43'ü sistemin ayırt etme gücünü değil,
önceden teşhis edilmiş tek kusurun sıklığını ölçüyor.**

Kalan dördü ayrı kalemler: `S-N-03` (tek başarısız oturum açma — sayı ve
zaman penceresi olmadan kaba kuvvet iddiası), `S-N-06` (meşru sürücü
kurulumu; `S-A-06` ile çifti, 7045'in kendisinin kanıt olmadığını ölçmek
içindi ve **sistem bu ayrımı yapamadı**), ve iki EK-2 kaydı.

### 4.5 EK-2: beklenen çift BASTIRILMADI

Dördünün de kararı `SUSPICIOUS`, ve dördünde de `suppression = None`.

| kayıt | beklenen | gerçek |
|---|---|---|
| S-EK2-01 `service ← TrustedInstaller/SYSTEM` | BENIGN (bastırılmalı) | SUSPICIOUS |
| S-EK2-02 `service ← msiexec/SYSTEM` | BENIGN (bastırılmalı) | SUSPICIOUS |
| S-EK2-03 `defender-policy ← aynı aktör` | SUSPICIOUS (bastırılmamalı) | SUSPICIOUS ✓ |
| S-EK2-04 `credential-hive ← aynı aktör` | SUSPICIOUS (bastırılmamalı) | SUSPICIOUS ✓ |

**Çiftin iki yönü de aynı cevabı aldı** — yani bu koşuda bastırma katmanı
hiç ayırt etmedi. `suppression` alanının `None` olması (yani "değerlendirdi
ve reddetti" değil, hiç kaydedilmemiş) bastırma adımına **ulaşılmadığına**
işaret ediyor, ama **bu koşu bunu kanıtlamıyor**: alanın hiç doldurulmuyor
olması da aynı görüntüyü verir. Ayrımı yapacak ölçüm yapılmadı.

**Bu, EK-2'nin iki yönlü olmasının tam da işe yaradığı yer:** yalnızca
beklenmeyen yön konsaydı 2/2 görünür ve "bastırma doğru davranıyor"
denirdi. Beklenen yön olmadan bastırmanın **çalışıp çalışmadığı**
görülemezdi.

---

## 5. Bu koşunun ÖLÇMEDİĞİ şey

- **Varyans.** Tek geçiş (§1). Hiçbir fark varyanstan ayrılmadı; teknik
  ekseni hiç puanlanmadı.
- **Bastırmanın neden ateşlemediği.** §4.5 — iki aday açıklama ayrılmadı.
- **Maske düzeltmesinin etkisi.** Düzeltme yazılmadı; bu koşu onun **ölçüm
  aracını** kurdu (§3).
- **Genelleme.** S tasarlanmış bir dağılımdır. Çıkarılabilecek cümle:
  *"bu 60 logda şu katman şöyle davrandı."*
- **G ile karşılaştırma.** §0.

---

## 6. Sıradaki iş — sıra değişti

Görev 16 `S → düzeltme` demişti. S iki kalem üretti ve **ikisi de
düzeltmeden önce ölçüm istiyor:**

1. **4656 maske düzeltmesi** — ölçüm aracı hazır (§3). Kabul ölçütü
   önceden yazıldı: A yarıları düşer, B yarıları kalır.
2. **EK-2 bastırmasının neden ateşlemediği** — düzeltmeden önce
   *hangi* açıklamanın doğru olduğu ayrılmalı (§4.5). Bu, 1'den bağımsız
   ve muhtemelen daha ucuz.

Açık kalemler değişmedi: `decision._alan` yalnızca `N/A`'yı yokluk sayıyor;
teknik ekseninin varyansı hiç ölçülmedi.
