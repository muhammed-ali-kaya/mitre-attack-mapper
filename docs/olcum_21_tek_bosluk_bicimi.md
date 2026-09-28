# Ölçüm — Görev 21 adayı: H'nin tek boşluk biçimi

**Bu bir ÖLÇÜM belgesidir, düzeltme yapılmadı.** Sebebi §4'te.
Tarih: 2026-09-02. Kaynak: `docs/sonuc_13_ozet.md` §3.3 (H kolunun bulgusu).

---

## 1. Sorun

H kolunun 15 logu `normalize_input`'tan **sıfır alan** çıkarıyor. Sebep
ölçülmüştü: Görev 15'in `K-C` değişmezi *"2+ ardışık boşluk etiket/değer
ayracıdır"* diyor, H'nin logları ise **tek boşlukla** yazılmış:

```
Subject: Security ID: NT AUTHORITY\SYSTEM Account Name: SYSTEM Account Domain: NT AUTHORITY
```

Değişmezi gevşetip tek boşluğu ayraç saymak **olmaz**: değerlerin kendisi
tek boşluk içeriyor (`NT AUTHORITY\SYSTEM`, `Set key value`). Değişmez
keyfi değil, biçimin kendi kuralı — Görev 15 tam da bunu ölçmüştü.

## 2. Alternatif yol ÖLÇÜLDÜ: şema çıpalı ayrıştırma

Boşluk yerine **bilinen etiketler** çıpa olarak kullanılabilir mi?
`config/field_schema.yaml` 111 etiket taşıyor. H'nin ham metninde
`<Etiket>:` olarak kaçı geçiyor:

```
kayıt başına ortalama 6.7 etiket   (en çok 14, en az 0)
```

| kayıt | olay | bulunan etiket |
|---|---|---|
| H-02..H-05 | `4657` | **14** |
| H-05 | `4657` | 10 |
| H-01 | `4688` | 8 |
| H-11, H-12 | Sysmon 1, 3 | 7 |
| H-13, H-14 | `4624`, `4625` | 6 |
| H-06..H-10 | 1102, 7045, 4698, 4720, 4732 | 2–3 |
| H-15 | `4104` | **0** |

**Yani yol açık:** etiketler metinde duruyor, yalnızca boşlukla
sınırlanmamışlar. Şema çıpalı bir ayrıştırıcı, ardışık iki bilinen etiket
arasını değer olarak dilimleyebilir.

## 3. AMA KAZANÇ SINIRLI — ve sınır ölçüldü

Asıl soru "kaç alan kurtarılır" değil, **"kaç KARAR GİRDİSİ kurtarılır"**.

| karar girdisi | kaç kayıtta kurtarılabilir |
|---|---|
| `account.name` | 13/15 |
| `process.name` | 7/15 |
| **`object.name`** | **4/15** |
| `object.type` | **0/15** |
| `access.mask` | **0/15** |
| `access.list` | **0/15** |
| `registry.path`, `file.path` | 0/15 |

**Erişim kanıtı H'de HİÇ YOK.** Ne maske ne `Accesses` metni — 15 kaydın
hiçbirinde. Yani en kusursuz ayrıştırıcı bile Yol B'ye erişim sınıfını
maskeden veremez; yalnızca **olayın kendi sınıfından** gelebilir
(`4657` tanımı gereği `write`).

### 3.1 Tavan hesabı — düzeltme H'yi tabana çıkarmaz

Kritiklik yalnızca `object.name` olan **4 kayıtta** hesaplanabilir hâle
gelir: `H-02`, `H-03`, `H-04`, `H-05` — dördü de `4657`, yani erişim
sınıfı tanımdan `write`. Yol B bu dördünde ateşlenebilir.

Beklenen kararlarıyla birlikte:

| kayıt | beklenen | Yol B ateşlerse çıkacak | etki |
|---|---|---|---|
| H-02 | `SUFFICIENT_SUSPICIOUS` | `SUSPICIOUS` | **+1 doğru** |
| H-03 | `SUFFICIENT_BENIGN` | `SUSPICIOUS` | **−1 (yanlış alarm)** |
| H-04 | `SUFFICIENT_SUSPICIOUS` | `SUSPICIOUS` | **+1 doğru** |
| H-05 | `INSUFFICIENT_DATA` | `SUSPICIOUS` | **−1 (şu an doğru olan bozulur)** |

Net kazanç en iyi durumda **+2**, gerçekçi olarak **0**.

```
H bugün          : 4/15
Tavan (en iyi)   : 6/15
Önemsiz taban    : 10/15
```

**Düzeltme yapılsa bile H, kendi önemsiz tabanının altında kalır.**
Bu, `sonuc_13_ozet.md` §3.2'deki desenin H için geçerliliğini değiştirmez.

## 4. NEDEN ŞİMDİ DÜZELTİLMEDİ — iki sebep, ikisi de bağlayıcı

### 4.1 Düzeltme H'yi held-out olmaktan ÇIKARIR

`beklenti_13_heldout_set.md` §3'ün protokolü: *"hiçbir eşik H'ye bakılarak
ayarlanmaz"*. Parser'ı **H'nin gösterdiği şey yüzünden** değiştirmek tam
olarak budur.

Düzeltme yapılırsa H artık genelleme ölçemez; **yeni bir held-out set**
gerekir. Bu, düzeltmeyi yasaklamaz — ama bedelini şimdiden yazıya geçirir,
sonradan "H'de %X aldık" denmesin diye.

### 4.2 Parser çekirdeği, kalan sürede güvenle değiştirilemez

Şema çıpalı ayrıştırma `normalize_input`'un biçim seçimine dokunur ve
**1306 testin** dayandığı yol orasıdır. Görev 15 aynı katmanda üç kusurun
birbirine bağlı olduğunu göstermişti (`K-A`/`K-B`/`K-C`); acele bir
dördüncü yol eklemek, yöntem maddesi 7'nin ("aynı işi yapan başka kaç yol
var?") dört kez ısırdığı deseni davet eder.

## 5. Düzeltilecekse — şekli ve ön koşulu

1. **Yeni biçim, mevcut yolların yerine geçmez, yanına eklenir.**
   `detect_format` tek boşluklu Windows anlatısını ayrı bir biçim olarak
   tanımalı; `2+ boşluk` değişmezi kendi biçiminde **aynen kalmalı**.
2. **Çıpa şemadan gelir**, uydurulmuş etiket listesinden değil — Görev 20'nin
   dersinin aynısı (tablo elle büyütülmez, türetilir).
3. **Değer sınırı:** ardışık iki bilinen etiket arası. Değeri bilinen bir
   etiket adı içeren kayıtlar bozulur; bu sınır ölçülmeli, varsayılmamalı.
4. **Ön koşul:** düzeltmeden önce yeni bir held-out set yazılmalı, yoksa
   düzeltmenin etkisi ölçülemez (H artık kullanılamaz).

## 6. Bu ölçümün SÖYLEMEDİĞİ şey

- **Bu biçimin üretimde ne kadar yaygın olduğu.** H sentetik olarak
  yazıldı; gerçek bir toplayıcının bu biçimi ne sıklıkta ürettiği
  ölçülmedi. G kolunun 51 gerçek satırı **sarmalanmış QRadar** biçiminde
  ve tek boşluk sorunu orada yok.
- **Şema çıpalı ayrıştırmanın gerçek isabeti.** 6.7 etiket/kayıt sayısı
  etiketlerin **bulunabildiğini** gösterir; değerlerin **doğru
  dilimlendiğini** göstermez. O ayrı bir ölçüm.
