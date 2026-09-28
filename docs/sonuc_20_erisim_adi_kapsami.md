# Sonuç — Görev 20: erişim adı kapsamı %40 → %100

Beklenti: `docs/beklenti_20_erisim_adi_kapsami.md` (kod yazılmadan önce, `bccfff0`).
Tarih: 2026-09-02.

---

## 1. Ölçülen üç boşluk, üçü de kapandı

| # | boşluk | önce | sonra |
|---|---|---|---|
| 1 | görüntü adı kapsamı | **9/22 (%40)**, kaçanların **7'si yazma** | **22/22 (%100)**, kaçan yazma **0** |
| 2 | çok değerli `Accesses` ayracı | tek ad sanılıyor, çözülmüyor | `{read, write}`, 6 bit, 0 çözülemeyen |
| 3 | tanınmayan ad | sessizce `read` | **`unknown`** + ad gerekçede yazılı |

### 1.1 Kapsam elle değil TÜRETEREK kapandı

Takma ad tablosu **9 girdiden 1 girdiye indi** — büyümedi, küçüldü.
Bağ artık jeton kümesi üzerinden mekanik kuruluyor:

```
"Set key value"    -> {set, key, value}
KEY_SET_VALUE      -> {key, set, value}       ESITLIK
"DeleteChild"      -> {delete, child}         (camelCase bölünür)
FILE_DELETE_CHILD  -> {file, delete, child}   ALT KÜME
```

Kural sırası zorunlu: **önce tam eşitlik, sonra alt küme, birden fazla
aday varsa çözülmez.** `DELETE` hem `DELETE` ile (eşitlik) hem
`FILE_DELETE_CHILD` ile (alt küme) eşleşiyor; eşitlik önce sorulmasa
belirsiz kalırdı.

Parantezli (`ReadData (or ListDirectory)`) ve eğik çizgili
(`Execute/Traverse`) alternatifler ilk seçeneğe indirgeniyor.

Elle kalan **tek** takma ad: `Notify about changes to keys` → `KEY_NOTIFY`
(jeton kümeleri arasında ne eşitlik ne alt küme ilişkisi var).
`test_takma_ad_tablosu_ELLE_BUYUTULMEDI` tabloyu küçük tutmayı sözleşme
yapıyor.

### 1.2 Ayraç: Görev 15'in değişmezi buraya da uygulandı

Gerçek QRadar satırları öğeleri **çoklu boşlukla** paketliyor — G'de 5,
S'te 3 kayıt. Bölme yalnızca `|` üzerindendi, dolayısıyla blok tek ad
sanılıyor ve **içinde `Set key value` olmasına rağmen** çözülmüyordu.

Ayraç artık `|`, **2+ ardışık boşluk**, satır sonu ve virgül. **Tek
boşluktan bölünmüyor** — adların kendisi tek boşluk içeriyor.

### 1.3 `unknown`, sessiz `read` değil

Görev 4'ün kararının aynısı uygulandı: **`unknown` ≠ `noise`**.

- Erişim bilgisi **var ama çözülemedi** → `access_class = "unknown"`, adlar
  raporlanıyor, gerekçe zincirinde tek tek yazılı.
- Erişim bilgisi **hiç yok** → eski davranış korundu. **Bu iki durum aynı
  şey değil** ve kodda da ayrı: "bilgi yok" ile "bilgi var, okuyamadım".
- `unknown` Yol B'yi tetiklemiyor (bilinmeyenden yazma iddia edilmez) ama
  BENIGN dalını da **kapatıyor** — sessiz `read` ikincisine izin veriyordu.

## 2. Kaçan alarm — üçüncü kez aynı yerden

Kritik varlık (`SAM`), `4663`, `Object Type=Key`:

| `Accesses` | önce | sonra |
|---|---|---|
| `Set key value` | `SUSPICIOUS` | `SUSPICIOUS` (Görev 19) |
| `Create link` | **`INSUFFICIENT_DATA`** | **`SUFFICIENT_SUSPICIOUS`** |
| gerçek çok değerli dize | **`INSUFFICIENT_DATA`** | **`SUFFICIENT_SUSPICIOUS`** |
| `Frobnicate widget` (uydurma) | `read` → `INSUFFICIENT_DATA` | `unknown` → `INSUFFICIENT_DATA`, **sebep yazılı** |

Son satır bu belgenin asıl dersi: **karar sınıfı değişmedi, sebep
değişti.** Eskisi "doğru cevap, yanlış sebep"ti — bu projede altı kez ölçüm
kirleten desen.

## 3. Yan etki — sıfır, tahmin edildiği gibi

```
S kolu: 0/60    G kolu: 0/51
```

| kontrol | sonuç |
|---|---|
| B1 çifti (Görev 18) | **SAĞLANDI** |
| G'nin beş yanlış alarmı | **GERİ DÖNMEDİ** — G hâlâ `{INSUFFICIENT_DATA: 51}` |
| EK-2 (Görev 17) | **4/4** |
| §3.4'ün gerileme riski | **gerçekleşmedi** — S'te BENIGN hâlâ 2 |
| tam takım | **1306 geçiyor** (1267 → +39) |

G'nin çok değerli `Accesses` taşıyan 5 satırı hex maske de taşıyor; maske
kazanıyor (Görev 3 politikası), dolayısıyla sınıf değişmedi. **Yine mevcut
korpuslar bu düzeltmeyi ölçemedi** — kanıt yeni testlerden geliyor.

## 4. Değiştirilen bir test — ve neden zayıflatma değil

`test_taninmayan_erisim_adi_sinif_UYDURMAZ` eskiden
`decode_access_mask(...) is None` diyordu. Bu, Görev 19'un **politikasını**
kodluyordu ve Görev 20 o politikayı bilerek değiştirdi.

Testin **asıl iddiası korundu ve hâlâ sınanıyor: sınıf uydurulmuyor**
(`classes == set()`). Eklenen şey, sessizliğin bitmesi
(`access_class == "unknown"`, `unresolved == [...]`). Docstring değişimin
sebebini taşıyor.

## 5. Bu düzeltmenin ÖLÇMEDİĞİ şey

- **Windows'un tüm erişim adları.** Sınanan 22 ad, `access_mask.yaml`'ın
  taşıdığı 22 **bitin** görüntü karşılıkları. Tabloda **olmayan bir bit**
  (`FILE_WRITE_EA`, `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`, …) hâlâ
  kapsam dışı. Bu düzeltme *tablonun okunmasını* tamamladı, *tablonun
  kendisini* değil — ve artık böyle bir ad geldiğinde **sessiz kalmıyor,
  `unknown` diyor.** Tabloyu büyütmek ayrı bir karar, bu görevde açılmadı.
- **Toplayıcı lehçeleri.** Ölçülen adlar Windows belgelerinden; bir kurumun
  toplayıcısı bunları farklı yazabilir. Jeton kuralı bazı varyasyonları
  yakalar, hepsini değil.
- **Varyans / genelleme.** Karar katmanı deterministik; ölçüm bir prob.
