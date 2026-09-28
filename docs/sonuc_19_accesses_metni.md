# Sonuç — Görev 19: `Accesses` metni artık erişim sınıfına giriyor

Beklenti: `docs/beklenti_19_accesses_metni.md` (kod yazılmadan önce, `9c256fb`).
Bulan: kullanıcı, arayüzden iki gerçek QRadar logu geçirerek. Tarih: 2026-09-01.

---

## 0. Bulgunun kendisi bir yöntem dersi

Kusur **arayüzden** bulundu, testten değil. 1255 test geçiyordu ve hiçbiri
bu yolu örneklemiyordu. Sebep §1.4'te ölçüldü ve tam olarak yöntem maddesi
17'nin konusu: **hiçbir kol "metin var, maske yok" biçimini taşımıyordu.**

Ve eksik biçimi bu kez **gerçek veri** getirdi — sentetik set değil.

## 1. İki kusur, aynı belirti

Belirti ikisinde de aynıydı: gerekçe zinciri *"Erişim sınıfı: salt okuma"*.
Sebepler farklıydı ve ayrı ayrı kapatıldı.

### 1.1 Log 1 (`4656` + maske `0x20006`) — RAPORLAMA kusuru

Karar katmanı **zaten doğruydu**: maske okunuyor, `KEY_SET_VALUE` ve
`KEY_CREATE_SUB_KEY` çözülüyor, `requested_class=write` üretiliyor.
`access_class=read` Görev 18'in kasıtlı davranışı — `4656` bir handle
talebidir.

Kusur metindeydi. Artık özet **ve** gerekçe zinciri talebi söylüyor:

```
gürültü seviyesindeki varlığa salt okuma (write talep edildi, gerçekleşmedi),
doğrulanmış kanıt yok
  - Erişim sınıfı: salt okuma — write talep edildi, gerçekleşme kanıtı yok
    (olay gerçekleşen erişimi göstermiyor; gerçekleşen erişim 4663'tür)
```

### 1.2 Log 2 (`4663` + `Accesses=Set key value`, maske YOK) — GERÇEK kusur

`decode_access_mask`'in ilk satırı `if not mask: return None` idi;
`access_text` yalnızca çapraz kontrol içindi, **hiçbir zaman sınıfın kaynağı
değildi**. Bilgi parser'da vardı (`access.list=['Set key value']`), karara
ulaşmıyordu.

**Görev 15'in kardeşi:** orada alan parser'a ulaşmıyordu, burada
parser'dan karara.

### 1.3 Risk kapandı — kritik varlıkta kaçan alarm

| girdi | önce | sonra |
|---|---|---|
| `SAM` + `4663` + `Accesses` (maskesiz) | `INSUFFICIENT_DATA`, B=False | **`SUFFICIENT_SUSPICIOUS`, B=True** |
| `SAM` + `4663` + maske `0x20006` | `SUSPICIOUS` | `SUSPICIOUS` (değişmedi) |

Kusurun özü: **alarmın varlığı, kaynağın hex maskeyi loglayıp
loglamamasına bağlıydı.** `test_L3_alarmin_varligi_kaynagin_maskeyi_yazmasina_BAGLI_DEGIL`
bu bağımlılığı kilitliyor.

### 1.4 Neden bugüne kadar görülmedi

S kolundaki `4663` kayıtlarının **hepsinde maske var** (`0x2001F`); G kolunda
**hiç `4663` yok** (Görev 16). Yani "metin var, maske yok" yolu hiçbir kolda
örneklenmemişti.

## 2. Düzeltme

1. `decode_access_mask` maske yoksa `Accesses` metninden bit/sınıf türetiyor.
   Takma ad tablosu zaten `setkeyvalue → keysetvalue` eşlemesini yapıyordu;
   eksik olan, çözülen adın **bit tablosundaki sınıfına** bakmaktı.
2. Sınıfın nereden geldiği raporlanıyor: `source` = `mask` / `text` /
   `mask+text`, `describe()` çıktısında `access_class_source`.
   **Sessizce türetilmiş bir sınıf, denetlenemez bir sınıftır** — metnin ve
   maskenin güvenilirliği aynı değil (metin lehçeye göre değişir, maske bit
   tablosudur).
3. **Görev 3'ün çelişki politikası korundu:** maske varken kaynak maske
   kalıyor, `mask_only`/`text_only`/`inconsistent_with_text` raporlanmaya
   devam ediyor. Sessizce biri seçilmiyor.
4. **Görev 18 korundu:** `erisim_gerceklesti: false` olan olayda metinden
   türetilen sınıf da **talep**tir; `requested_class`'a gider,
   `access_class`'ı yükseltmez.
5. Tanınmayan erişim adı sınıf **uydurmaz** — `None` döner.

## 3. YAN ETKİ — sıfır kayıt, tahmin edildiği gibi

Beklenti §3.3 "mevcut korpuslarda sıfır kayıt değişir" demişti. Ölçüldü:

```
S kolu: 0/60 kayıt sınıf değiştirdi
G kolu: 0/51 kayıt sınıf değiştirdi
```

| kontrol | sonuç |
|---|---|
| **B1 çifti (Görev 18)** | **SAĞLANDI** — `2A`/`3A` `INSUFFICIENT_DATA`, `2B`/`3B` `SUSPICIOUS` |
| **G'nin beş yanlış alarmı** | **GERİ DÖNMEDİ** — G hâlâ `{INSUFFICIENT_DATA: 51}` |
| **EK-2 (Görev 17)** | **4/4**, çıkış kodu 0 |
| tam takım | **1267 geçiyor** (1255 → +12 yeni test) |

G'nin beşinin geri dönmemesi bu düzeltmenin **kritik kabul ölçütüydü**:
dönselerdi Görev 18'in kazancı geri gitmiş olurdu. Dönmediler çünkü beşi de
`4656`, yani talep — metinden türetilen sınıf da talep sayılıyor.

### 3.1 Bu düzeltme mevcut korpuslarla ÖLÇÜLEMEZ

Sıfır kayıt değişmesi iyi haber ama aynı zamanda bir sınır: **hiçbir kol bu
düzeltmenin kazancını gösteremez.** Kanıt yalnızca yeni regresyon
fixture'ından geliyor (§4). Bu, fixture'ın neden gerçek veriden alındığının
gerekçesidir.

## 4. Regresyon fixture'ı

`tests/fixtures/access_class_source_logs.json` + `tests/test_access_class_source.py`
(12 test). Üç kayıt:

| # | ne kilitler |
|---|---|
| **L1** | `4656` + hex maske — Görev 18'in talep ayrımı **korunuyor**, ve metin talebi söylüyor |
| **L2** | `4663` + yalnızca `Accesses` — metin-tek sınıf çıkarımı |
| **L3** | **kritik** varlık + `4663` + yalnızca `Accesses` — **kaçan alarmın kendisi** |

L3 ayrı bir kayıt olarak eklendi çünkü L1/L2 gürültü seviyesinde ve orada
kusur kararı değiştirmiyor; **kusur ancak kritik varlıkta alarm kaçırıyor.**
L3 olmadan fixture, düzeltmenin neyi kurtardığını göstermezdi.

### 4.1 KAYNAK UYARISI — dürüstlük kaydı

Ham satırlar kullanıcının **bildirdiği alanlardan yeniden kuruldu**;
orijinal metinler birebir yakalanmadı. Taşıdıkları alanlar bildirilenle aynı
ve sarmalayıcı biçim G kolunun gerçek QRadar biçimi. **Ama madde 17'nin
"biçim üretimde var mı" şartını bu dosya şu an yalnızca KISMEN karşılıyor.**
Orijinaller elde edilirse `raw` değerleri onlarla değiştirilmelidir; uyarı
fixture'ın içine de yazıldı.

## 5. Bu düzeltmenin ÖLÇMEDİĞİ şey

- **`Accesses` metninin tam kapsamı.** Takma ad tablosu **9 girdilik**;
  Windows'un erişim adları bundan çok daha fazla. Bu düzeltme tablonun
  **okunmasını** sağlar, **tamlığını** değil. Tabloda olmayan bir yazma adı
  hâlâ sessizce `read` bırakır — aynı kusurun kalan yüzü.
- **Varyans.** Karar katmanı deterministik; LLM bu işte yok.
- **Genelleme.** Üç kayıt bir teşhis probudur, dağılım değil.
