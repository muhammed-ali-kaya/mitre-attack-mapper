# Beklenti — Görev 19: `Accesses` metni erişim sınıfına girmiyor

**Bu belge kod yazılmadan önce yazıldı ve commit'lendi.**

Kaynak: kullanıcının arayüzden geçirdiği iki gerçek QRadar logu (2026-09-01).
Ölçüm bu belgeden önce yapıldı; aşağıdaki §1 ölçülmüş durumdur, tahmin değil.

---

## 1. ÖLÇÜLEN DURUM — iki ayrı kusur, aynı belirti

Belirti ikisinde de aynı: gerekçe zinciri **"Erişim sınıfı: salt okuma"**
diyor. Sebepleri **farklı** ve ayrı ayrı ele alınmalı.

### 1.1 Log 1 (`4656` + `Access Mask=0x20006`) — RAPORLAMA kusuru

```
describe('4656','0x20006','Key',None)
  -> access_class=read  mask_class=write  requested_class=write  realized=False
```

**Karar katmanı doğru çalışıyor.** Maske okunuyor, iki yazma biti
(`KEY_SET_VALUE`, `KEY_CREATE_SUB_KEY`) çözülüyor, ve `requested_class=write`
olarak raporlanıyor. `access_class=read` **Görev 18'in kasıtlı davranışı**:
`4656` bir handle TALEBİDİR, maske orada talep edilen haktır.

**Kusur yalnızca METİNDE.** Gerekçe zinciri *"salt okuma"* diyor; oysa
doğru cümle *"yazma talep edildi, gerçekleşme kanıtı yok"*. Analiste
söylenmesi gereken şey budur ve `requested_class` zaten elde duruyor.

### 1.2 Log 2 (`4663` + `Accesses=Set key value`, maske YOK) — GERÇEK kusur

```
decode_access_mask(None,'Key','Set key value')          -> None
describe('4663',None,'Key','Set key value')             -> access_class=read
```

`decode_access_mask` ilk satırında `if not mask: return None` diyor.
**`access_text` parametresi yalnızca maskeyle ÇAPRAZ KONTROL için var;
hiçbir zaman sınıfın KAYNAĞI değil.** Maske yoksa metin okunmuyor.

Bilgi kayıp değil — parser her ikisini de taşıyor:

```
LOG2 parsed_fields: access.mask=None  access.list=['Set key value']  object.type='Key'
```

Yani Görev 15'in kardeşi: **orada alan parser'a ulaşmıyordu, burada
parser'dan karara ulaşmıyor.**

### 1.3 Risk ÖLÇÜLDÜ — kritik varlıkta gerçek alarm kaçıyor

| girdi | kritiklik | erişim | karar |
|---|---|---|---|
| `SAM` + `4663` + `Accesses` (maske YOK) | critical | **read** | **`INSUFFICIENT_DATA`** ✗ |
| `SAM` + `4663` + maske `0x20006` | critical | write | `SUFFICIENT_SUSPICIOUS` ✓ |
| `SAM` + `4657` + `Accesses` (maske YOK) | critical | write | `SUFFICIENT_SUSPICIOUS` ✓ |

`4657` kurtuluyor çünkü `islem_sinifi`'i **tanımı gereği** write. Boşluk
tam olarak **varsayılan sınıfı `read` olan olaylarda + metin-tek kanıtta**.

### 1.4 Neden bugüne kadar görülmedi

S kolundaki `4663` kayıtlarının **hepsinde maske var** (`0x2001F`).
G kolunda ise Görev 16'da ölçülmüştü: **0 tane `4663`**. Yani hiçbir kol
"metin var, maske yok" yolunu örneklemiyor. Yöntem maddesi 17'nin tam
karşılığı — ve bu kez eksik biçimi **gerçek veri** getirdi.

---

## 2. DÜZELTME — şekli

1. `decode_access_mask`: maske yoksa **`access_text`'ten** bit/sınıf türet.
   Takma ad tablosu (`_ACCESS_ALIASES`) zaten `setkeyvalue → keysetvalue`
   eşlemesini yapıyor; eksik olan, çözülen adın maske tablosundaki
   **sınıfına** bakmak.
2. Sınıfın **nereden** geldiği raporlanır (`source`: `mask` / `text` /
   `mask+text`). Sessizce türetilmiş bir sınıf, denetlenemez bir sınıftır.
3. **Görev 3'ün çelişki politikası korunur:** maske ve metin çelişirse
   ikisi de raporlanır, sessizce biri seçilmez. Mevcut `mask_only` /
   `text_only` / `inconsistent_with_text` alanları kalır.
4. **Görev 18 KORUNUR:** `erisim_gerceklesti: false` olan olayda
   (`4656`) metinden türetilen sınıf da **talep**tir — `requested_class`'a
   gider, `access_class`'ı yükseltmez.
5. Gerekçe metni `requested_class`'ı söyler: *"yazma talep edildi,
   gerçekleşme kanıtı yok"*.

---

## 3. TAHMİNLER — koşmadan önce

### 3.1 Birim

| çağrı | beklenen |
|---|---|
| `decode_access_mask(None,'Key','Set key value')` | `classes={'write'}`, `source='text'` |
| `describe('4663',None,'Key','Set key value')` | `access_class='write'` |
| `describe('4656','0x20006','Key','Set key value')` | `access_class='read'`, `requested_class='write'` — **DEĞİŞMEZ** |
| `describe('4663','0x20006','Key',None)` | `access_class='write'` — **DEĞİŞMEZ** |

### 3.2 İki gerçek log

| log | önce | sonra |
|---|---|---|
| Log 1 (`4656`+maske, noise varlık) | `erişim=read` | `erişim=read` **değişmez**; metin *"yazma talep edildi"* der |
| Log 2 (`4663`+metin, noise varlık) | `erişim=read` | **`erişim=write`** |

**Log 2'nin KARARI yine de değişebilir:** varlık `noise` ve
`SUFFICIENT_BENIGN` dalının şartı `erisim == "read"`. Erişim `write`
olunca o dal **düşer** ve karar `INSUFFICIENT_DATA`'ya döner. Bu bir
gerileme değil, düzeltmenin doğrudan sonucu: gürültü seviyesindeki bir
anahtara **yazma**, "meşru salt okuma" diye kapatılamaz.

Aynı sebeple §6'daki başlık sorusunun cevabı **evet**: *"gürültü
seviyesindeki varlığa salt okuma"* metni bu daldan üretiliyor ve dal
düştüğü için o başlık artık çıkmayacak.

### 3.3 Yan etki — **sıfır kayıt değişmeli**

S'in `4663` kayıtlarının hepsinde maske var; G'de hiç `4663` yok. Yani:

- **B1 çifti (6 kayıt): DEĞİŞMEZ.** `2A`/`3A` `INSUFFICIENT_DATA`,
  `2B`/`3B` `SUSPICIOUS` kalır — ayrım hâlâ tutar.
- **G'nin beş yanlış alarmı (`G-007/015/029/030/040`): GERİ DÖNMEZ.**
  Beşi de `4656`, yani talep; metinden türetilen sınıf da talep sayılır
  ve `access_class`'ı yükseltmez. **Dönerlerse Görev 18'in kazancı geri
  gitmiş demektir ve düzeltme yanlıştır.**
- **S ve G sadıklık farkı: 0/60 ve 0/51.**

**Bu tahmin düzeltmenin sınırını da söylüyor:** mevcut korpuslar bu
düzeltmeyi **ölçemez**. Kanıt yalnızca yeni regresyon fixture'larından
gelebilir (§4) — ve bu, fixture'ların neden gerçek veriden alındığının
gerekçesidir (madde 17).

---

## 4. Regresyon fixture'ı

İki log `tests/fixtures/` altına gerçek biçimleriyle girer. Gerekçe:
gerçek QRadar verisinden geliyorlar ve **üretimde var olan** bir biçimi
örnekliyorlar — yöntem maddesi 17'nin istediği tam olarak bu. Fixture
her iki kusuru da kilitler: metin-tek sınıf çıkarımı **ve** `4656`'nın
talep ayrımının korunması.

## 5. Bu düzeltmenin ÖLÇMEYECEĞİ şey

- **Varyans.** Karar katmanı deterministik; LLM tarafı bu işte yok.
- **Genelleme.** İki log bir teşhis probudur, dağılım değil.
- **`Accesses` metninin tam kapsamı.** Takma ad tablosu 9 girdilik ve
  Windows'un erişim adları bundan çok daha fazla. Bu düzeltme tablonun
  **okunmasını** sağlar, tablonun **tamlığını** değil.
