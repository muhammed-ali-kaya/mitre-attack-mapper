# Beklenti — Görev 18: `4656` maskesi TALEP edileni gerçekleşen sayıyor

**Bu belge kod yazılmadan önce yazıldı ve commit'lendi.** Sonradan yazılan
beklenti, çıktıya bakıp "evet böyle olmalı" demenin kibar hâlidir.

Kaynak: Görev 16 §4, `docs/sonuc_13_s_kolu.md` §3.

---

## 1. Kusur

`describe()` şunu koşulsuz uyguluyor (`app/normalization/event_semantics.py`):

```python
access_class = mask_class or event_class
```

Kural dosyanın kendi başlığında yazılı ve genel hâlinde **doğru**: olay türü
genel bir beyandır, maske o kayda özeldir, çelişirse maske kazanır.

`4656`'da yanlış — çünkü orada maske **talep edilen** haktır.
`config/event_semantics.yaml` bunu Görev 3'te zaten yazmıştı:

> *"Handle TALEBİDİR. Erişimin gerçekleştiğini GÖSTERMEZ — gerçekleşen erişim
> 4663'tür."*

`0x2001F` "yazma hakkı **İSTEDİ**" der, "yazdı" demez. Yol B (`kritiklik +
yazma erişimi`) girişimi eylem gibi okuyor.

## 2. Düzeltme

Katalogda **tek** talep olayı var: `4656`. Diğer 30 olayın hepsi gerçekleşmiş
bir eylemi ya da bir denetim kaydını anlatıyor.

`config/event_semantics.yaml`'a olay başına `erisim_gerceklesti` alanı
(varsayılan `true`); `4656` için `false`. `describe()`:

```python
access_class = (mask_class or event_class) if gerceklesti else event_class
```

Maske **kaybolmuyor** — `requested_class` olarak ayrı raporlanıyor. Kaybolsa
bilgi yok olurdu; mesele maskenin okunması değil, **karara hangi sıfatla
girdiği**.

Düzeltme mekanizma katmanında, örnek katmanında değil (yöntem madde 6):
tablo `4661` gibi ikinci bir talep olayı kazanırsa kod değişmez.

## 3. TAHMİNLER — koşmadan önce

### 3.1 B1 çifti (6 kayıt, `evaluation/results/s_arm_run.json` üzerinden
çevrimdışı oynatma; LLM tarafı DONMUŞ)

Kabul ölçütü `sonuc_13_s_kolu.md` §3'te yazılıydı: *A yarıları
`INSUFFICIENT_DATA`'ya düşer, B yarıları `SUFFICIENT_SUSPICIOUS` kalır.
İkisi birden susarsa düzeltme ayırt etmiyordur.*

| kayıt | olay | kayıtlı Yol A | tahmin |
|---|---|---|---|
| S-B1-1A | 4656 | **True** (1 kanıt) | `SUSPICIOUS` KALIR — ölçüt bu çiftte ulaşılamaz |
| S-B1-1B | 4663 | True | `SUSPICIOUS` kalır |
| S-B1-2A | 4656 | False | `SUSPICIOUS` → **`INSUFFICIENT_DATA`** |
| S-B1-2B | 4663 | False | `SUSPICIOUS` kalır |
| S-B1-3A | 4656 | False | `SUSPICIOUS` → **`INSUFFICIENT_DATA`** |
| S-B1-3B | 4663 | False | `SUSPICIOUS` kalır |

**Ölçüt 1. çiftte ulaşılamaz ve bu şimdi yazılıyor, sonuç görülünce değil.**
`S-B1-1A`'da Yol A ateşlenmiş durumda (`T1012`, `T1003.002`, 1 doğrulanmış
kanıt) ve Yol A bastırılamaz — maske düzeltmesi Yol B'yi öldürür, Yol A
kararı yine `SUSPICIOUS` yapar. Ölçüt yazılırken çiftin tek yolu Yol B
sanılmıştı; 1. çiftte ikinci bir yol var.

Yani **ayırt etme gücü 3 anahtarın 2'sinde ölçülebilir.** 3/3 iddiası
edilemez. 1. çift maskeyi değil **Yol A üstünlüğünü** ölçüyor ve o ayrı bir
sorudur.

**Başarısızlık işareti (§3'ten, gevşetilmedi):** `2B`/`3B` de susarsa
düzeltme ayırt etmiyor, her şeyi bastırıyordur.

### 3.2 T1 fixture'ı — RİSK, önceden yazılıyor

`tests/fixtures/registry_object_access_logs.json` `T1` amiral gemisi vaka
(`reg.exe` → `\REGISTRY\MACHINE\SAM`, T1003.002) **ve o da bir `4656`.**
Beklenen erişim sınıfı `write` yazılı.

Düzeltmeden sonra `T1`'in erişim sınıfı `read` olur. Kararı Yol A taşıyorsa
`SUFFICIENT_SUSPICIOUS` kalır, taşımıyorsa **düşer**.

`T1`'in maskesi `0x2000d` ve `Accesses` metni yalnızca okuma işlemleri
sayıyor (`Query key value | Enumerate sub-keys | Read Control`). `write`
sınıfı metinde bulunmayan bir maske bitinden (`0x4`, create sub-key)
geliyor. Yani `T1`'in `write` etiketi zaten **talep edilmiş** bir haktan
türemiş.

**İki sonuçtan hangisi çıkarsa çıksın kayda geçer; hiçbiri "düzeltme
bozuldu" diye okunmaz:**

- `T1` Yol A ile ayakta kalırsa: fixture'ın `expected_access_class: write`
  satırı **artık yanlıştır** ve düzeltilir — çünkü `4656` gerçekleşmiş
  yazma göstermiyor.
- `T1` düşerse: bu, amiral gemisi vakanın alarm gücünün Yol B'ye, yani
  **talebi eylem sayan kusura** dayandığı anlamına gelir. Bu bir gerileme
  değil, kazanılmamış bir sayının ilk kez görünmesidir (yöntem madde 15).

### 3.3 Yan etki

Yalnızca sadıklık farkı ölçülecek, tam koşu yapılmayacak:
`scripts/measure_suppression_shift.py`, düzeltmeden önce `--kaydet`, sonra
`--karsilastir`. Beklenen: yalnızca `4656` taşıyan kayıtlar değişir.

## 4. Bu düzeltmenin ÖLÇMEDİĞİ şey

- **Varyans.** Çevrimdışı oynatma; LLM tarafı donmuş. Teknik ekseni
  okunmuyor.
- **Genelleme.** G ve S yeniden koşulmuyor (takvim kararı). Ölçülen şey
  yalnızca karar katmanının aynı kayıtlara verdiği yeni cevap.
- **`4656`'nın doğru `islem_sinifi`'nin ne olduğu.** Bu düzeltme maskenin
  sınıfı **yükseltmesini** engelliyor; olayın kendi `read` sınıfının doğru
  olup olmadığı ayrı bir sorudur ve açılmıyor.
