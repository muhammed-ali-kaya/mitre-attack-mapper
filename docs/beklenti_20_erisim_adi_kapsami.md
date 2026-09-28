# Beklenti — Görev 20: erişim adı kapsamı ve tanınmayan ad politikası

**Bu belge kod yazılmadan önce yazıldı ve commit'lendi.**

Kaynak: Görev 19'un kayıtlı kalan yüzü (`docs/sonuc_19_accesses_metni.md` §5).
§1 **ölçülmüş durumdur**, tahmin değil.

---

## 1. ÖLÇÜLEN DURUM — üç ayrı boşluk, hepsi aynı kaçan alarma çıkıyor

### 1.1 Görüntü adı kapsamı: %40

Windows'un `Accesses` alanına bastığı 22 görüntü adı sınandı. Beklenen sınıf
elle yazılmadı — her adın karşılık geldiği bitin `config/access_mask.yaml`'daki
sınıfından alındı.

```
cozulen 9/22 (%40)  |  kacan 13  |  KACANLARDAN YAZMA 7
```

| aile | kapsam | kaçan yazma adları |
|---|---|---|
| registry | 4/6 | `Create link` |
| standard | 5/5 | — |
| **file** | **0/7** | `WriteData (or AddFile)`, `AppendData (or …)`, `DeleteChild`, `WriteAttributes` |
| **process** | **0/4** | `VM write`, `VM operation` |

**Registry ailesi neredeyse tam, dosya ve süreç aileleri tamamen açık.**
Sebep basit: dokuz elle yazılmış takma adın hepsi registry/standart adlardan
seçilmişti — ilk vaka registry'ydi.

### 1.2 Çok değerli `Accesses` tek dize geliyor — GERÇEK veride

`config/access_mask.yaml`'ın kendi başlığındaki örnek biçim `|` ayraçlı. Ama
G kolunun **gerçek QRadar satırlarında** (5 kayıt) ve S'te (3 kayıt) değer
şöyle geliyor:

```
READ_CONTROL     Query key value     Set key value     Create sub-key     Enumerate sub-keys     Notify about changes to keys
```

Tek dize, aralarında **çoklu boşluk**. `_classes_from_text` yalnızca `|`
üzerinden bölüyor, dolayısıyla bu blok **tek bir ad** sanılıyor ve
çözülmüyor — **içinde `Set key value` olmasına rağmen.**

Ayraç zaten bilinen bir değişmez: Görev 15'in `K-C` kararı *"2+ ardışık
boşluk etiket/değer ayracıdır"*. Aynı değişmez burada uygulanmamış.

### 1.3 Tanınmayan ad SESSİZCE `read` bırakıyor

`decode_access_mask` çözemediğinde `None` dönüyor; `describe` de
`access_class = event_class`'a düşüyor ve `4663` için bu **`read`**.

Ölçüldü — kritik varlık (`SAM`), `4663`, `Object Type=Key`:

| `Accesses` | erişim | Yol B | karar |
|---|---|---|---|
| `Set key value` | write | **True** | `SUFFICIENT_SUSPICIOUS` ✓ |
| `Create link` | **read** | False | **`INSUFFICIENT_DATA`** ✗ |
| gerçek çok değerli dize (`Set key value` içeriyor) | **read** | False | **`INSUFFICIENT_DATA`** ✗ |

**Görev 19'un kapattığı kaçan alarm, başka bir yazımla geri geliyor.**

---

## 2. DÜZELTME — şekli

### 2.1 Takma ad tablosu ELLE BÜYÜTÜLMEZ, TÜRETİLİR

Dokuz girdiyi yirmi ikiye çıkarmak aynı kusuru bir sonraki ada erteler.
`access_mask.yaml` zaten bit adlarını **ve** sınıflarını tutuyor; görüntü adı
ile sabit ad arasındaki bağ mekanik olarak kurulabilir — **jeton kümesi**
üzerinden:

```
"Set key value"    -> {set, key, value}
KEY_SET_VALUE      -> {key, set, value}      ESIT
"DeleteChild"      -> {delete, child}         (camelCase bolunur)
FILE_DELETE_CHILD  -> {file, delete, child}   ALT KUME
```

**Eşleşme kuralı — belirsizlik kabul edilmez:**

1. Önce **tam küme eşitliği**; tek aday varsa o.
2. Yoksa **alt küme**; tek aday varsa o.
3. Birden fazla aday varsa **çözülmez** — uydurmak yerine bilinmez.

Kural 1'in kural 2'den önce gelmesi zorunlu: `DELETE` hem `DELETE`
(tam eşitlik) hem `FILE_DELETE_CHILD` (alt küme) ile eşleşir; tam eşitlik
olmadan belirsiz kalırdı.

Parantezli alternatifler (`ReadData (or ListDirectory)`) ve eğik çizgili
alternatifler (`Execute/Traverse`) **ilk alternatife** indirgenir; Windows
bunları "aynı bit, farklı nesne türünde farklı ad" olarak yazıyor.

Elle takma ad **yalnızca** mekanik kuralın çözemediği ad için kalır.
Ölçülen tek örnek: `Notify about changes to keys` → `KEY_NOTIFY`.

### 2.2 Ayraç: Görev 15'in değişmezi burada da uygulanır

`Accesses` değeri `|`, **2+ ardışık boşluk**, satır sonu ve virgül
üzerinden bölünür. **Tek boşluktan bölünmez** — adların kendisi tek boşluk
içeriyor (`Set key value`).

### 2.3 Tanınmayan ad: `unknown`, sessiz `read` değil

Görev 4'ün kararının aynısı: **`unknown` ≠ `noise`**, ve `unknown` BENIGN
üretemez.

- Erişim bilgisi **var ama çözülemedi** → `access_class = "unknown"`,
  çözülemeyen adlar raporlanır.
- Erişim bilgisi **hiç yok** (ne maske ne metin) → bugünkü davranış korunur
  (olayın kendi sınıfı). **Bu iki durum aynı şey değil** ve karıştırılmamalı:
  biri "bilgi yok", diğeri "bilgi var, okuyamadım".
- `unknown` Yol B'yi **tetiklemez** (bilinmeyenden yazma iddia edilmez) ama
  BENIGN dalını da **kapatır** — bugünkü sessiz `read` ikincisine izin
  veriyordu.

---

## 3. TAHMİNLER — koşmadan önce

### 3.1 Kapsam

| ölçü | önce | sonra |
|---|---|---|
| 22 görüntü adı | 9 (%40) | **22 (%100)**, en fazla **1** elle takma adla |
| kaçan yazma adı | 7 | **0** |

### 3.2 Davranış

| girdi (SAM, `4663`, `Key`) | önce | sonra |
|---|---|---|
| `Create link` | `INSUFFICIENT_DATA` | **`SUFFICIENT_SUSPICIOUS`** |
| gerçek çok değerli dize | `INSUFFICIENT_DATA` | **`SUFFICIENT_SUSPICIOUS`** |
| `Set key value` | `SUSPICIOUS` | `SUSPICIOUS` (değişmez) |
| uydurma ad (`Frobnicate widget`) | `read` → `INSUFFICIENT_DATA` | `unknown` → `INSUFFICIENT_DATA`, **gerekçe adı söyler** |

Son satır önemli: karar sınıfı **aynı** çıkıyor ama sebep farklı ve artık
**yazılı**. "Doğru cevap, yanlış sebep" deseninin kapatılması.

### 3.3 Yan etki — **sıfır kayıt** bekleniyor

G'nin çok değerli `Accesses` taşıyan 5 satırı **hex maske de taşıyor**;
maske kazanır (Görev 3 politikası), dolayısıyla sınıf değişmez. S'in `4663`
kayıtlarının hepsinde maske var.

- **B1 çifti: DEĞİŞMEZ.**
- **G'nin beş yanlış alarmı: GERİ DÖNMEZ.** (Beşi de `4656` = talep.)
  **Dönerlerse düzeltme yanlıştır.**
- **EK-2: 4/4.**
- **S 0/60, G 0/51.**

Yine mevcut korpuslar bu düzeltmeyi ölçemiyor; kanıt yeni testlerden gelecek.

### 3.4 Risk: `unknown` bir gerileme ÜRETEBİLİR

`unknown` BENIGN dalını kapattığı için, bugüne kadar `SUFFICIENT_BENIGN`
alan bir kayıt `INSUFFICIENT_DATA`'ya düşebilir. **Beklenen sayı: 0** —
çünkü BENIGN dalı `erisim == "read"` şartına bağlı ve bugün `read` alan
kayıtların hepsi ya maskeden ya olay varsayılanından geliyor, çözülemeyen
addan değil. Sıfırdan büyük çıkarsa hangi kayıt olduğu **tek tek**
yazılacak; toplu "birkaç kayıt değişti" kabul edilmez.

## 4. Bu düzeltmenin ÖLÇMEYECEĞİ şey

- **Windows'un tüm erişim adları.** Sınanan 22 ad `access_mask.yaml`'ın
  taşıdığı 22 bitin görüntü karşılıkları. Tabloda **olmayan bir bit**
  (ör. `FILE_WRITE_EA`, `PROCESS_TERMINATE`) hâlâ kapsam dışı — bu
  düzeltme *tablonun okunmasını* tamamlar, *tablonun kendisini* değil.
  Tabloyu büyütmek ayrı bir karar ve bu görevde açılmıyor.
- **Varyans.** Karar katmanı deterministik.
- **Genelleme.** Ölçülen adlar Windows belgelerinden; bir kurumun
  toplayıcısı bunları farklı yazabilir.
