# Sonuç — Görev 18: `4656` maskesi artık talebi eylem saymıyor

Beklenti: `docs/beklenti_18_maske_talep.md` (kod yazılmadan önce commit'lendi, `e31d08e`).
Ölçüm: `scripts/measure_b1_mask.py` (LLM ve indeks gerekmez).
Tarih: 2026-09-01.

---

## 0. Ne değişti

`config/event_semantics.yaml`'a olay başına `erisim_gerceklesti` alanı geldi
(varsayılan `true`); katalogdaki 31 olaydan **yalnızca `4656`** `false`.
`describe()` artık:

```python
access_class    = (mask_class or event_class) if gerceklesti else event_class
requested_class = None if gerceklesti else mask_class
```

**Maske kaybolmuyor.** `4656`'da yazma biti hâlâ çözülüyor, hâlâ
raporlanıyor — `requested_class` olarak. Değişen tek şey, maskenin karara
hangi **sıfatla** girdiği.

Düzeltme mekanizma katmanında: tablo `4661` gibi ikinci bir talep olayı
kazanırsa kod değişmez (yöntem madde 6).

## 1. B1 ÇİFTİ — ölçüt sağlandı, 3 anahtarın 2'sinde

Kabul ölçütü `sonuc_13_s_kolu.md` §3'te yazılıydı: *A yarıları
`INSUFFICIENT_DATA`'ya düşer, B yarıları `SUFFICIENT_SUSPICIOUS` kalır.
İkisi birden susarsa düzeltme ayırt etmiyordur.*

| kayıt | olay | erişim sınıfı | talep edilen | Yol A/B | önce | sonra | ölçüt |
|---|---|---|---|---|---|---|---|
| S-B1-1A | 4656 | read | write | **A=T**, B=F | SUSPICIOUS | SUSPICIOUS | **ULAŞILAMAZ** |
| S-B1-1B | 4663 | write | — | A=T, B=T | SUSPICIOUS | SUSPICIOUS | sağlandı |
| S-B1-2A | 4656 | **read** | write | A=F, **B=F** | SUSPICIOUS | **INSUFFICIENT_DATA** | sağlandı |
| S-B1-2B | 4663 | **write** | — | A=F, **B=T** | SUSPICIOUS | SUSPICIOUS | sağlandı |
| S-B1-3A | 4656 | **read** | write | A=F, **B=F** | SUSPICIOUS | **INSUFFICIENT_DATA** | sağlandı |
| S-B1-3B | 4663 | **write** | — | A=F, **B=T** | SUSPICIOUS | SUSPICIOUS | sağlandı |

**Düzeltme ayırt ediyor, susturmuyor.** Görev 16 §5'in korktuğu sonuç
çıkmadı: aynı kritik anahtara aynı maskeyle giden iki kayıttan yalnızca
**talep** olanı sustu, **gerçekleşen** olan gürültüde kaldı. Tek değişkenli:
çiftin iki yarısı arasında olay ID'sinden başka fark yok.

**1. çiftte ölçüt ULAŞILAMAZ ve bu koşmadan önce yazıldı**
(`beklenti_18` §3.1, `e31d08e`). `S-B1-1A`'da Yol A ateşli (`T1012`,
`T1003.002`, 1 doğrulanmış kanıt) ve Yol A bastırılamaz. Ölçüt yazılırken
çiftin tek yolu Yol B sanılmıştı; 1. çiftte ikinci bir yol var.

**Yani ayırt etme gücü 3/3 değil 2/3 anahtarda gösterildi.** 1. çift maskeyi
değil **Yol A üstünlüğünü** ölçüyor ve o ayrı bir sorudur. Kod bunu
gevşetmiyor, `ULASILAMAZ` sabitiyle **ilan ediyor** — sayı 3/3 diye
raporlanamasın diye.

## 2. T1 — amiral gemisi vaka kusura DAYANMIYORMUŞ

`beklenti_18` §3.2 iki olası sonuç yazmıştı. **Birincisi çıktı:**

```
T1  (reg.exe -> \REGISTRY\MACHINE\SAM, 4656, maske 0x2000d)
    karar : SUFFICIENT_SUSPICIOUS   (DEĞİŞMEDİ)
    yollar: A=True  B=True -> B=False
```

Karar ayakta çünkü Yol A taşıyor: `T1003.002` + doğrulanmış kanıt. Yol B
düştü çünkü `4656`'nın maskesindeki `KEY_CREATE_SUB_KEY` **talep edilmiş**
bir haktı — `Accesses` metni zaten yalnızca okuma işlemleri sayıyordu.

**Bu, alınabilecek en iyi sonuç.** İkinci ihtimal gerçekleşseydi (T1 düşerdi)
projenin amiral gemisi vakasının alarm gücünün baştan beri bir kusura
dayandığı ortaya çıkardı.

`tests/fixtures/registry_object_access_logs.json` T1 kaydında
`expected_access_class` **`write` → `read`** olarak düzeltildi ve
`expected_requested_class: write` eklendi. Eski değer *yanlış türetilmemişti*
— Görev 3 tablosundan doğru geliyordu; eksik olan maskenin çözümü değil
**olayın kendisiydi**.

## 3. Yan etki — 7 kayıt, hepsi `4656`

Taban, kayıtlı koşuya değil **bir önceki kodun oynatmasına** göre alındı;
karşılaştırılan iki sayı da aynı yoldan üretildi (`--kaydet` / `--karsilastir`).

| kol | değişen | kayıtlar |
|---|---|---|
| S | 2/60 | `S-B1-2A`, `S-B1-3A` |
| G | **5/51** | `G-007`, `G-015`, `G-029`, `G-030`, `G-040` |

**G'nin beş yanlış alarmının beşi birden sustu** — ve bunlar Görev 15'te Yol
B canlanınca ortaya çıkan tam olarak o beş satır. Görev 16 bu beşi teşhis
etmiş, düzeltmeyi bilerek ertelemişti: *"G korpusunda 0 tane 4663, 0 tane
4657 var — düzeltme yapılsa 'beş alarm sustu' görülür ama doğru sebeple mi
sustu yoksa her şeyi mi susturdu ayırt edilemez."*

**O ayrım artık S'te yapıldı.** G'nin beşi, doğru sebeple sustu.

### 3.1 Ama G bunu tek başına GÖSTEREMEZ

G şimdi 51/51 `INSUFFICIENT_DATA` üretiyor: **sıfır alarm.** Bu sayı tek
başına okunmamalı. G korpusunda hiç `4663`/`4657` yok (Görev 16'da ölçüldü),
yani G **düzeltmenin gerçekleşen erişimi hâlâ duyduğunu gösteremez** —
yalnızca sustuğunu gösterir. Bir susturucu da aynı görüntüyü verirdi.

Ayrımı gösteren tek şey B1 çiftidir ve o S'te. G'nin "0 yanlış alarm"ı bu
belgede **kazanılmış** sayılıyor, ama kazandıran ölçüm G değil S.

## 4. S kolunun sayıları — ve hâlâ tabanın altında

Çevrimdışı oynatma (LLM tarafı donmuş, teknik ekseni okunmadı):

| | S kolu, Görev 13 | S kolu, 17+18 sonrası |
|---|---|---|
| karar sınıfı isabeti | 36/60 (%60) | **40/60 (%67)** |
| yanlış alarm (17 negatif örnek) | 7/17 | **3/17** |
| önemsiz taban (hep SUSPICIOUS) | 43/60 (%72) | 43/60 (%72) |

**Sistem hâlâ tabanın altında.** 40/60 < 43/60. Bu cümle burada duruyor
çünkü G kolunda aynı kural bizim aleyhimize uygulanmıştı; kuralı sayı lehimize
düştüğünde gevşetmek olmaz. İyileşme gerçek (36 → 40, ve yanlış alarm 7 → 3)
ama **baş sayı hâlâ kazanılmış değil.**

Kalan üç yanlış alarm: `S-B1-1A` (Yol A üstünlüğü, §1), `S-N-03` (tek
başarısız oturum açma), `S-N-06` (meşru sürücü kurulumu).

## 5. Testler — kural silinmedi, DARALTILDI

Dört test güncellendi, ikisi eklendi (1253 → **1255 geçiyor**).

Eski kural — *"çelişkide maske kazanır"* — bir örneğini `4656` üzerinden
kodluyordu. O örnek artık istisnanın kendisi. Kuralı silmek yerine **iki
yeni testle korundu:**

- `test_mask_write_bit_STILL_overrides_the_event_default_when_access_realized`
  — aynı maske `4663`'e verildiğinde eski davranış aynen duruyor. Bu test
  olmasa Görev 18 kuralı topyekûn kaldırmış gibi görünürdü.
- `test_only_4656_is_a_request_in_the_catalogue` — katalog taraması. İkinci
  bir talep olayı eklenirse test düşer; ekleyen kişi Görev 18'in kararını
  **bilerek** genişletmiş olur, sessizce değil.

## 6. Bu düzeltmenin ÖLÇMEDİĞİ şey

- **Varyans.** Çevrimdışı oynatma, tek geçiş. LLM tarafı donmuş.
- **Teknik ekseni.** Hiç okunmadı. Düzeltme yalnızca karar katmanında.
- **Yeniden koşu.** G ve S yeniden koşulmadı (takvim kararı). Ölçülen şey
  karar katmanının **aynı kayıtlara** verdiği yeni cevap; retrieval ve
  eşleştirme tarafının bu değişiklikten nasıl etkileneceği ölçülmedi.
- **`4656`'nın doğru `islem_sinifi`'nin ne olduğu.** Bu düzeltme maskenin
  sınıfı **yükseltmesini** engelliyor. Olayın kendi `read` sınıfının doğru
  olup olmadığı ayrı bir sorudur ve açılmadı — `config/event_semantics.yaml`
  kendi notunda *"tek başına 'okudu' demek fazla ileri gitmektir"* diyor.
