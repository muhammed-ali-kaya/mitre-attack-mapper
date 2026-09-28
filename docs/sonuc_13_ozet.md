# Görev 13 — üç kol tek belgede: G, S, H

Bu belge üç held-out ölçümünü yan yana **koymaz**, arka arkaya **anlatır**.
Üçü farklı soruları cevaplıyor ve tek bir tabloya sıkıştırılırsa hiçbiri
okunamaz.

| kol | ne | kaç | soru |
|---|---|---|---|
| **G** | gerçek QRadar satırları, elle etiketlendi | 51 | sistem **gerçek** veride ne yapıyor? |
| **S** | sentetik, katmanları uyandırmak için tasarlandı | 60 | katmanlar **çalışıyor mu**? |
| **H** | held-out, hiç bakılmadan yazıldı | 15 | ayara mı oturduk? |

## BAŞ BULGU

> **H'nin 4/15'i sistemin doğruluğunu değil, ayrıştırıcının biçim kapsamını
> ölçtü.**

H'nin 15 kaydının **15'inde de** karar girdileri boş çıktı (`kritiklik=YOK`,
`erisim=None`). Sebep tek bir karakter: H'nin logları **tek boşlukla**
yazılmış, Görev 15'in `K-C` değişmezi ise "2+ ardışık boşluk etiket/değer
ayracıdır" diyor. Kural hiç ateşlenemiyor, ayrıştırıcı **sıfır alan**
çıkarıyor, karar katmanı hiç sınanmıyor. Ayrıntı §3.3.

**Ve bu bulgu ancak held-out disiplini sayesinde çıktı.** H, parser
çalışmasından (Görev 15, 2026-08-31) **önce** yazıldı ve protokol gereği
aradaki hiçbir noktada açılmadı. **Ayarlanmış bir set bu bulguyu asla
üretmezdi** — biçim, ayarlama sırasında sessizce düzeltilir ve kimse
ayrıştırıcının biçime bu kadar bağlı olduğunu öğrenmezdi.

Held-out setin tek atışta verdiği en değerli şey sayısı değil, bu.

---

## 0. ÜÇ KOL YAN YANA OKUNMAZ

`sonuc_13_s_kolu.md` §0'ın kuralı burada da geçerli ve genişletiliyor.

- **G** gerçek dağılımdır: 51 satırın 49'u negatif, 1'i pozitif. Tespit gücü
  ölçülemez — recall bilerek raporlanmadı.
- **S** tasarlanmış bir dağılımdır: 60 kaydın 43'ünde beklenen cevap
  `SUSPICIOUS`. Bu setin özelliğidir, sistemin başarısı değil.
- **H** ayrılmış settir: yazıldıktan sonra **hiçbir eşik ona bakılarak
  ayarlanmadı**.

"Hangi kolda sayı yüksek" sorusunun cevabı **setin dağılımıdır**, sistemin
gücü değil. Üç sütunlu tek bir doğruluk tablosu bu belgede bilerek yok.

---

## 1. G KOLU — aynı sayı, üç farklı sebep

G'nin baş sayısı üç kez ölçüldü ve **50 → 45 → 50** yolunu izledi. Üçü de
"sınıf isabeti"; yalnızca üçüncüsü bir şey ifade ediyor.

| durum | sınıf isabeti | yanlış alarm | sebep |
|---|---|---|---|
| ilk koşu (Görev 13) | **50/51** | 0/49 | **kazanılmadı, garanti edildi.** Sarmalanmış `Message` gövdesi ayrıştırılmıyordu, maske kayıptı, Yol B **hiç ateşlenemiyordu**. Doğru cevap, yanlış sebep. |
| Görev 15 sonrası | **45/51** | 5/49 | Yol B canlandı; maliyeti **ilk kez göründü**. Düşen sayı hiç kazanılmamıştı (yöntem madde 15). |
| Görev 18 sonrası | **50/51** | **0/49** | beş yanlış alarm sustu, ve **doğru sebeple** sustuğu S'te ayrıca gösterildi. |

**Bu tablo, yöntem bölümündeki `T1003.002`'nin üç durumunun aynısıdır** —
aynı çıktı, üç farklı mekanizma, ve yalnızca sonuncusu kazanılmış. Kaydı
tutmayan, birinci durumu başarı sanar.

### G'nin yapısal sınırı — sayı hâlâ tabanı geçmiyor

Çıkan dağılım her üç durumda da **tek sınıf**: `{INSUFFICIENT_DATA: 51}`.
Sabit `INSUFFICIENT_DATA` diyen sınıflandırıcı da 50/51 alır. Yani **50/51
bugün de kazanılmış bir sayı değil** — kazanılan şey sayı değil, sayının
**sebebinin bilinmesi**.

### G'nin ölçemediği şey — ve S'in var olma sebebi

G korpusunda **0 tane `4663`, 0 tane `4657`** var (Görev 16'da ölçüldü).
Yani G, Görev 18'in düzeltmesinin **gerçekleşen erişimi hâlâ duyduğunu
gösteremez** — yalnızca sustuğunu gösterir. Her şeyi susturan bir kusur da
aynı görüntüyü verirdi.

**Ayrımı gösteren tek ölçüm B1 çiftidir ve o S'te.** G'nin 0 yanlış alarmını
kazandıran ölçüm G değil S.

### Tek pozitif satır — iki ayrı katmanda kayboldu

`G-045` (gizli PowerShell): beklenen `T1059.001` + `T1564.003`.
`T1059.001` **retrieval aday havuzuna hiç girmedi**; `T1564.003` **ajan
katmanı tarafından elendi**. İki farklı katman, iki farklı düzeltme. Tek bir
"kaçırdı" sayısı bu ayrımı yok ederdi.

---

## 2. S KOLU — katmanlar uyandı, baş sayı hâlâ tabanın altında

S, G'nin ölçemediğini ölçmek için kuruldu: G'de Yol A ve Yol B **bir kez
bile** ateşlenmemişti.

| | G kolu (51) | S kolu (60) |
|---|---|---|
| Yol A ateşledi | 0 | **18/60** |
| Yol B ateşledi | 0 → 5 → 0 | **20/60** |

*(Bu iki sütun "hangi sistem daha iyi" diye okunmaz — "hangi set katmanı
uyandırıyor" diye okunur.)*

### Baş sayı

| | Görev 13 | 17+18 sonrası |
|---|---|---|
| karar sınıfı isabeti | 36/60 (%60) | **40/60 (%67)** |
| yanlış alarm (17 negatif) | 7/17 | **3/17** |
| **önemsiz taban** (hep SUSPICIOUS) | **43/60 (%72)** | **43/60 (%72)** |

**Sistem hâlâ tabanın altında.** İyileşme gerçek (36 → 40, yanlış alarm
7 → 3) ama 40 < 43. Bu cümle burada duruyor çünkü aynı kural G'de bizim
aleyhimize uygulandı; kuralı sayı lehimize düştüğünde gevşetmek olmaz.

Tabanın yüksekliği S'in **tasarımından** geliyor (60 kaydın 43'ünde beklenen
cevap `SUSPICIOUS`), yani "%72" bir başarı çıtası değil, **bu setin ne kadar
dengesiz olduğunun ölçüsü**.

### S'in asıl ürünü: B1 çifti

Toplam sayılar değil, **ayırt edici çift** S'in merkezi. Aynı kritik
anahtara, aynı aktörle, aynı maskeyle giden iki kayıt — tek fark olay ID'si:

| | olay | anlam | Görev 18 öncesi | Görev 18 sonrası |
|---|---|---|---|---|
| A yarısı | `4656` | handle **TALEBİ** | `SUSPICIOUS` | **`INSUFFICIENT_DATA`** |
| B yarısı | `4663` | **gerçekleşen** erişim | `SUSPICIOUS` | `SUSPICIOUS` |

Önce: altı kayıtta **tek davranış**, ikisi tesadüfen beklentiye uyuyordu.
Sonra: **ayrım tutuyor** — üç anahtarın ikisinde (üçüncüsünde Yol A ateşli
olduğu için ölçüt ulaşılamaz, ve bu koşulmadan önce yazıldı).

**Bunun değeri:** düzeltmenin *her şeyi susturmadığını* gösteren tek kanıt
budur. B1 olmasa Görev 18 "beş alarm sustu" derdi ve doğru sebepten mi
sustuğu bilinemezdi.

### EK-2 — iki yönlü olmasının karşılığı

Bastırma çiftinin **beklenen** yönü (bastırılmalı) ve **beklenmeyen** yönü
(bastırılmamalı) birlikte kondu. İlk koşuda dördü de aynı cevabı aldı, yani
bastırma hiç ayırt etmedi. Yalnızca beklenmeyen yön konsaydı **2/2 görünür
ve "bastırma doğru çalışıyor" denirdi.**

Görev 17 sebebi ölçtü: `process.name` **biçimi**. Düzeltmeden sonra 4/4.

---

## 3. H KOLU — held-out, 15 log, bir kez koşuldu

**Protokol:** `evaluation/heldout_set.json` G etiketlendikten sonra, G
koşulmadan önce yazıldı (2026-08-30) ve o günden 2026-09-01'e kadar hiç
açılmadı — hiçbir eşik ona bakılarak ayarlanmadı. **Bu koşu tek atıştır:**
H'nin sayısına bakarak yapılacak her ayar, H'yi held-out olmaktan çıkarır.

Koşu: 15/15, hata 0, toplam 18 dk (ortalama 73 sn/kayıt).

### 3.1 H'nin cevapladığı soru G ve S'inkinden farklı

H bir performans karşılaştırması değil. Sorusu tek: **sistem hiç görmediği
veride ne yapıyor?** Bu yüzden aşağıdaki sayı §1 ve §2'nin tablolarına
eklenmez.

| | H kolu (15) |
|---|---|
| beklenen dağılım | `{SUSPICIOUS: 10, BENIGN: 1, INSUFFICIENT_DATA: 4}` |
| **çıkan dağılım** | **`{INSUFFICIENT_DATA: 15}`** |
| karar sınıfı isabeti | **4/15** |
| **önemsiz taban** (hep `SUSPICIOUS`) | **10/15** |
| yol dağılımı | `A=False B=False` × **15** |
| teknik top-1 | 5/10 |
| teknik top-3 | 5/10 |

### 3.2 Taban üçüncü kez kazandı — bu artık bir desen

| kol | sistem | önemsiz taban | fark |
|---|---|---|---|
| G | 50/51 | 50/51 | berabere |
| S | 40/60 | 43/60 | **taban önde** |
| H | **4/15** | **10/15** | **taban açık ara önde** |

Üç kolda da sistem, sabit tek cevap veren aptal sınıflandırıcıyı **geçmedi**.
Bu tek vaka değil, **desen**. Sunumda söylenecek cümle budur:

> Karar katmanı bugün, tek bir sabit cevabın üzerine ölçülebilir bir değer
> koymuyor. Katmanların *çalıştığı* gösterildi (S'te Yol A 18/60, Yol B
> 20/60 ateşledi); *kazandırdığı* gösterilemedi.

### 3.3 H'nin sayısı karar katmanını DEĞİL, AYRIŞTIRICIYI ölçüyor

Bu, H'nin en değerli çıktısı ve tek atışın karşılığı.

15 kaydın **15'inde de** karar girdileri boştu:

```
kritiklik = YOK   (15/15)     erisim_sinifi = None  (15/15)
dogrulanmis_kanit = 0 (15/15) yollar: A=False B=False (15/15)
```

Dört kayıt `4657` (registry değeri değiştirildi, tanımı gereği yazma) ve
`object.name` alanı ham metinde **var**. Yine de kritiklik `YOK` çıktı.

Sebep ölçüldü — `normalize_input` H'nin biçiminden **sıfır alan**
çıkarıyor:

| girdi | çıkan alan |
|---|---|
| `H-02` olduğu gibi | **0** |
| `H-02` + çift boşluk ayracı | 6 |
| `H-02` + `Message=""` sarmalayıcı | 2 |
| `H-02` + ikisi birden | 8 |
| *(karşılaştırma)* `S-B1-2B` | **16** |

Baskın etken **tek boşluk**. Görev 15'in `K-C` değişmezi şudur: *"2+ ardışık
boşluk etiket/değer ayracıdır, o yüzden etiketin içinde olamaz."* H'nin
logları `Subject: Security ID: NT AUTHORITY\SYSTEM Account Name: SYSTEM`
biçiminde, yani **tek boşlukla** yazılmış; kural hiç ateşlenemiyor.

> **H'nin 4/15'i sistemin doğruluğunu değil, ayrıştırıcının biçim kapsamını
> ölçtü.**

Karar katmanı H'de **hiç sınanmadı** — girdisi hiç oluşmadı. Bu yüzden 4/15
bir genelleme sayısı olarak okunamaz; "sistem genelleşemedi" cümlesi bu
veriden çıkarılamaz.

**Bu, bugün yazılan yöntem maddesi 17'nin aynadaki görüntüsü.** Madde 17
fixture'ın biçimi üretimde var mı diye sorar; H'de ters yönü çıktı — **test
setinin biçimini sistem okuyamıyor.** İki durumda da ölçüm, ölçmek istediği
katmana hiç ulaşmıyor.

**H yazılırken bu bilinemezdi ve bu bir kusur değil:** H, G etiketlendikten
sonra ama parser çalışması (Görev 15, 2026-08-31) yapılmadan önce yazıldı ve
protokol gereği aradaki hiçbir noktada açılmadı. Held-out disiplininin bedeli
tam olarak budur ve ödenmesi doğruydu.

### 3.4 Teknik ekseni ayakta — ve bu ayrımı yapabilmek H'nin kazancı

Yapısal ayrıştırma sıfır alan verirken **teknik ekseni çalıştı:** top-1
5/10, kayıt başına 2.00 teknik. Retrieval ve eşleştirme ham metinden
okuyor, yapısal alanlara bağlı değil.

| katman | H'de durumu |
|---|---|
| retrieval + eşleştirme | ham metinden çalışıyor — **5/10 top-1** |
| yapısal ayrıştırma | biçimi tanımıyor — **0 alan** |
| karar katmanı | girdisi oluşmadığı için **hiç sınanmadı** |

**Bu üç satır tek bir doğruluk sayısına sıkıştırılamaz** — ve Görev 13'ün
"asla tek doğruluk sayısı" kuralının en net karşılığı burada çıktı. "%27
doğruluk" cümlesi teknik olarak doğru ve tamamen yanıltıcı olurdu.

Ayrıca kayda değer: `H-11`, `T1059.001` + `T1564.003` üretti — G kolunda
`G-045`'in **kaçırdığı** tam o iki teknik. Aynı teknik çifti bir kolda
kayboluyor, diğerinde bulunuyor. Tek veri noktası, genelleme değil.

---

## 4. Üç kolun birlikte söylediği

**1. Katmanlar çalışıyor; kazandırdıkları gösterilemedi.**
G'de Yol A ve Yol B bir kez bile ateşlenmedi. S bunu ölçebilmek için kuruldu
ve ateşlettirdi (18/60, 20/60). Ama üç kolda da karar sınıfı isabeti önemsiz
tabanı geçmedi. **Mekanizmanın çalıştığı ile değer kattığı ayrı şeylerdir**
ve bu projede yalnızca birincisi gösterildi.

**2. Aynı sayı üç farklı şey anlatabilir.**
G'nin 50/51'i üç kez ölçüldü, iki kez aynı çıktı ve **sebepleri farklıydı**
(§1). Bu belgenin merkezindeki ders budur: bir metriğin iyileşmesi
mekanizmanın düzeldiği anlamına gelmez.

**3. Ayırt edici çift, toplam sayıdan çok daha bilgilendirici.**
Görev 18'in her şeyi susturmadığını gösteren şey, 60 kayıtlık toplam değil,
**6 kayıtlık B1 çifti** oldu. Aynı şekilde EK-2'nin iki yönlü olması,
bastırmanın hiç ayırt etmediğini görünür kıldı. Tek yönlü bir set ikisini de
"çalışıyor" gösterirdi.

**4. Held-out gerçekten held-out'tu — ve bedelini ödedi.**
H, kendisine bakılmadan yazıldığı için sistemin okuyamadığı bir biçimde
kaldı ve bunu ancak koşulduğunda söyledi (§3.3). Ayarlanmış bir set bu
bulguyu **asla** üretmezdi: biçim, ayarlama sırasında sessizce düzeltilirdi.
**H'nin tek atışta verdiği en değerli şey sayısı değil, bu bulgudur.**

**5. En pahalı kusuru ARAYÜZ buldu, test değil.** (Görev 19)
Sunum öncesi arayüz doğrulaması yapıldığında **1255 test geçiyordu** ve
hiçbiri şu yolu örneklemiyordu: bir `4663` kaydı hex maske taşımadan
yalnızca `Accesses: Set key value` metniyle geldiğinde erişim sınıfı
`read` çıkıyordu. Kritik varlıkta bu **gerçek alarm kaçırıyordu** —
`SAM` + `4663` + `Accesses` → `INSUFFICIENT_DATA`, Yol B hiç ateşlenmeden.

Kusurun özü: **alarmın varlığı, kaynağın hex maskeyi loglayıp
loglamamasına bağlıydı.**

Neden hiçbir test görmedi, ölçüldü: **S'in `4663` kayıtlarının hepsinde
maske var, G'de hiç `4663` yok.** Yani "metin var, maske yok" biçimi
üç kolun hiçbirinde geçmiyordu — yöntem maddesi 17'nin tam konusu, ve
eksik biçimi bu kez sentetik set değil **gerçek veri** getirdi.

İki ders birden:

- **Bir korpus, taşımadığı biçimi doğrulayamaz.** G ve S bu düzeltmeyi
  bugün de ölçemiyor: yan etki **0/51 ve 0/60**. Kanıt yalnızca yeni
  regresyon fixture'ından (`tests/test_access_class_source.py`) geliyor.
- **Aynı belirti iki farklı kusuru gizleyebilir.** İki gerçek log da
  gerekçe zincirinde *"Erişim sınıfı: salt okuma"* diyordu. Biri gerçek
  kusurdu (metin hiç okunmuyordu), diğeri **doğru davranışın yanlış
  cümleyle anlatılmasıydı** (`4656` bir talep, Görev 18). Tek kusur
  sanılıp tek yerde düzeltilseydi biri yerinde kalırdı.

---

## 5. BİLİNEN EKSİKLER

Kesilen işler ve açık kalemler, gerekçeleriyle. Hiçbiri "unutuldu" değil;
her biri bir sıra kararının sonucu.

### 5.1 Kesilen görevler

| # | ne | neden kesildi / ne biliniyor |
|---|---|---|
| **K1** | kural kalitesi | **İki kusur ölçüldü, kaçı olduğu ölçülmedi.** `T1140`'ın deseni `-urlcache`'i kendine sayıyor (o T1105'tir); `T1082`'nin hiç ayırt edici koşulu yok (`wmic.exe` çalıştı mı ateşliyor). İkisi de 4 çakışma çifti incelenirken çıktı, yani **ateşlenen 14 kuralın** görünen kısmından. Ateşlenmeyen 35 kural hiç incelenmedi. **Görev 22 üç somut aday verdi:** `T1685.005`, `T1059.001`, `T1547.001` — kanıt kapısının beklenen tekniği elediği üç vakanın tamamı bu üç kuraldan geliyor ve iki ayrı korpusta tekrarlandı. **"Katalogda iki kusur var" denemez — bilinen iki kusur var.** Ayrıca karar katmanı olmadan K1'in kazancı görünmez olacaktı; sırası bu yüzden sonraydı. |
| **8** | ajan katmanı kalitesi | **Kapsamı ölçüldü ve görev yeniden tanımlandı.** 672 canlı tekniğin **3'ünde** özel ajan var (`T1053.005`, `T1003.001`, `T1686.003`); kalan **669'u** tek genel ajana (`DetectionEvidenceAgent`) düşüyor. Yani üç uzman ajanı iyileştirmek vakaların **%99.5'ine dokunmaz**. Görev ayrıca ikiye bölündü: `evidence-gate` (deterministik, 2B'nin işi) ve genel ajan (LLM kalitesi). |
| **9, 10** | — | 8'in ardına dizilmişti; 8 açılmadığı için hiç başlanmadı. |
| **6B / 7** | güven etiketi | **Bilinmeyen bir gizli girdi var.** `T1012` üç *sıcak* koşuda `low / low / medium` verdi. Isınma yapılmış, `keep_alive=30m`, seed ve sıcaklık sabit; bilinen gizli girdi (model yükleme durumu) kontrol altında ve **varyans hâlâ var**. Görev 7 bu ikinci girdiyi bulmadan "etiket şu katmandan geliyor" cevabı eksik kalır. Etiketin karara sızmadığı ayrıca ölçüldü — yani bugün zarar vermiyor. |
| **12** | kod içi tabloları veriye taşı | Ö1 bunun altına yazılamadı çünkü sorun tablonun *nerede durduğu* değil, **ölçümü geçersiz kılmasıydı**; o kısım ayrı ele alındı ve tablo kaldırıldı. Kalan taşıma işi saf refactor ve takvimde yer bulamadı. |
| **2C** | chunk bölme | Ölçümden bağımsız bir ön karar bekliyor: `chunk_id` `idx = len(chunks)` sıra numarasına dayanıyor; bölme yapıldığı **an tüm ID'ler kayar** ve geçmiş ölçümler karşılaştırılamaz hâle gelir. İçerik hash'ine çevirmek bölmeden **önce** yapılmalı. |

### 5.2 Açık kalemler

| kalem | durum |
|---|---|
| **Ölçüm aracı kusuru (8.)** | `scripts/measure_suppression_shift.py`, kasıtlı bir karar katmanı değişikliğinden sonra "sadıklık bozuk" deyip çıkış 2 veriyor — o durumda sadıklık kaybı ile amaçlanan kayma **aynı ölçümdür** ve araç ikisini ayırmıyor. Kapanış kriteri yazıldı: araç bir "beklenen kayma listesi" almalı. O zamana kadar `--karsilastir`'ın çıkış kodu 2'si **tek başına okunmamalı**. `docs/sonuc_17_ek2_bastirma_bicimi.md` §6.2. |
| **`decision._alan` yalnızca `N/A`'yı yokluk sayıyor** | `-`, `NULL SID`, boş dize yokluk sayılmıyor. Bugün zarar vermiyor çünkü iç gövdeden bilgi taşımayan değer kurtarılmıyor (Görev 15 kararı). Ama **dış** yolda bir kaynak `Object Name=-` kolonu verirse o değer, iyi olan `file.path`'i gölgeler. Şema `non_informative_values` listesini zaten tek kaynak olarak tutuyor; `_alan` onu okumuyor. Görev 15'te **bilerek** düzeltilmedi — karar katmanını değiştirmek G kolunun yeniden koşusunu kirletirdi. |
| **Teknik ekseninin varyansı hiç ölçülmedi** | Bütün kol koşuları **tek geçiş**. Hiçbir teknik farkı varyanstan ayrılmadı. S'in "A ve B yarılarının teknik listeleri farklı" gözlemi bir **üst sınırdır**, ölçüm değil. |
| **Ayrıştırıcının biçim kapsamı** | H'nin bulgusu (§3.3). Ölçüldü, kayda geçti, **düzeltilmedi** — düzeltmek H'yi held-out olmaktan çıkarırdı ve takvim kapandı. |
| ~~Erişim adı takma ad tablosu 9 girdilik~~ **→ KAPANDI (Görev 20)** | Kapsam 9/22 (%40) ölçüldü, kaçanların 7'si yazmaydı. Tablo **büyütülmedi, küçültüldü** (9→1): bağ jeton kümesiyle türetiliyor. Kapsam **22/22**, kaçan yazma **0**. Tanınmayan ad artık sessiz `read` değil **`unknown`** (Görev 4: unknown ≠ noise). `docs/sonuc_20_erisim_adi_kapsami.md`. **Kalan sınır:** tabloda *olmayan bir bit* hâlâ kapsam dışı — ama artık sessiz kalmıyor. |
| **Fixture ham satırları yeniden kuruldu** | `tests/fixtures/access_class_source_logs.json` ham satırları, kullanıcının **bildirdiği alanlardan** yeniden kuruldu; orijinal QRadar metinleri birebir yakalanmadı. Taşıdıkları alanlar aynı ve sarmalayıcı biçim G'nin gerçek biçimi, ama madde 17'nin "biçim üretimde var mı" şartını dosya şu an **kısmen** karşılıyor. Orijinaller elde edilirse `raw` değerleri değiştirilmeli; uyarı fixture'ın içine de yazıldı. |
| ~~`wip/verification-graph` dalı~~ **→ KAPANDI (Görev 22)** | Yeniden ölçüldü: `graph.py`'nin üçüncü döngü tetikleyicisi **kaldırıldı** (döngülerin %43'ü yalnızca ondan, tur başına 52 sn), `verification.py`'nin kapı-elemeyi-kaldır değişikliği **reddedildi** (bugün 10 lehte / 3 aleyhte; zarar üç belirli kuraldan geliyor, kapının tasarımından değil). `docs/karar_22_verification_graph_dali.md`. |

| **G-045 iki katmanda kayıp** | `T1059.001` retrieval aday havuzuna hiç girmedi; `T1564.003` ajan katmanı tarafından elendi. İki farklı katman, iki farklı düzeltme; ikisi de yapılmadı. |
