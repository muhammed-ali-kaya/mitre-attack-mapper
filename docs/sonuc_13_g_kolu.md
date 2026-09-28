# Sonuç — Görev 13, G kolu (51 gerçek QRadar satırı)

Koşu: 2026-08-30, tek geçiş, ön planda, devam edebilir betikle
(`scripts/run_g_arm.py`). **51/51 satır, hata yok, toplam 89 dakika**, satır
başına ortalama 105 sn (en uzun 182 sn — soğuk başlangıçlar).

Etiketler koşudan **önce** yazılıp commit'lendi (`256e287`). Puanlama
`scripts/score_g_arm.py`, eksen tanımları beklenti belgesi §4'ten alındı.

---

## 1. Baş bulgu — isabet sayısı hiçbir şey söylemiyor

| | |
|---|---|
| sınıf isabeti | **50/51** |
| çıkan sınıf dağılımı | `{INSUFFICIENT_DATA: 51}` |
| **önemsiz taban** | sabit `INSUFFICIENT_DATA` diyen sınıflandırıcı da **50/51** alır |
| yanlış alarm | 0/49 negatif örnek |
| kaçırılan pozitif | 1 (G-045) |
| yol dağılımı | `A=False B=False` × **51** |
| bastırma ateşleyen | 0 |

Sistem 51 girdinin **51'ine de aynı cevabı verdi**. Ne Yol A ne Yol B bir kez
bile ateşlendi. "%98 doğruluk" cümlesi teknik olarak doğru ve tamamen
yanıltıcı olurdu — tam olarak tek doğruluk sayısı yasağının var olma sebebi.

Puanlayıcı bunu artık kendi yakalıyor: çıkan dağılım tek sınıfsa önemsiz
taban hesaplanır ve isabet onu geçmiyorsa uyarı basılır.

---

## 2. Kök neden — 0/49 yanlış alarm kazanılmadı, garanti edildi

Beklenti belgesinde koşmadan önce şu tahmin yazılmıştı: beş `4656` satırı
(G-007, G-015, G-029, G-030, G-040) `Services\*\Performance` anahtarına
`0x2001F` maskesiyle handle istiyor; maske `Set key value` içerdiği için
**Yol B yanlış alarm üretecek**.

**Tahmin tutmadı.** Beşinde de Yol B ateşlenmedi. Sebep ölçüldü:

```
G-007 inputs: kritiklik=high  ailesi=service
              varlik_yolu=\REGISTRY\MACHINE\SYSTEM\...\tapisrv\Performance
              erisim_sinifi="read"        <-- maske 0x2001F olmasina ragmen
```

Zincir:

1. `decode_access_mask("0x2001F", "Key")` tek başına çağrıldığında **doğru
   şekilde `write`** diyor (bitler: `KEY_SET_VALUE`, `KEY_CREATE_SUB_KEY`, …).
2. Ama G-007'nin `parsed_fields`'inde `access.mask` **yok**. Ayrıştırıcı
   maskeyi bu girdiden çıkaramamış.
3. Maske yoksa `erisim_sinifi` olay ID başına **varsayılana** düşüyor →
   4656 için `read`.
4. Yol B yazma erişimi istediği için ateşlenemiyor.

**Nerede kayboluyor, ölçüldü:**

| Girdi biçimi | `access.mask` çıkıyor mu |
|---|---|
| ham Windows `Message` metni | **evet** (`0x2001F`, `access.list` de dolu) |
| üretimin verdiği `row_to_kv_string` | **hayır** |

Yani ayrıştırıcı bu alanı okuyabiliyor; QRadar toplu yolunun serileştirmesi
`Message`'ı tek bir tırnaklı değere sarınca alt alanlara ulaşılamıyor.

**Sonuç: QRadar toplu yolunda Yol B hiçbir registry satırında ateşlenemez.**
0/49'luk kusursuz yanlış alarm oranı sistemin ayırt etmesinden değil, bir
katmanın hiç çalışmamasından geliyor. Doğru sonuç, çalışmayan sebep.

> Bu bir gerileme değil, hiç ölçülmemiş bir boşluk. Görev 14'ün E5'i "bölmenin
> gerçek QRadar CSV'sindeki doğruluğu ölçülmedi" derken bu tür bir şeyi
> kastediyordu. Ölçüm G kolunun var olma gerekçesini doğruladı: sentetik set
> bunu **hiçbir zaman** gösteremezdi, çünkü sentetik loglar ham metin olarak
> beslenir ve o yolda maske çıkıyor.

---

## 3. Eksen 2 — teknik katmanı gürültülü

| | |
|---|---|
| teknik BEKLENMEYEN satır | 50 |
| bunların kaçı gerçekten boş | **0/50** |
| toplam üretilen teknik | **109** |
| satır başına ortalama | 2.1 |
| eşsiz yanlış pozitif teknik | 22 |

En sık yanlış pozitifler:

| teknik | kaç satırda |
|---|---|
| T1571 (Non-Standard Port) | 25 |
| T1095 (Non-Application Layer Protocol) | 13 |
| T1548.002 (Bypass UAC) | 11 |
| T1546 (Event Triggered Execution) | 9 |
| T1134 (Access Token Manipulation) | 8 |
| T1205.001 (Port Knocking) | 8 |

Karar katmanı hiç alarm üretmediği için bu 109 teknik alarma dönüşmüyor —
ama arayüzde ve raporda görünüyor. **Karar sınıfı doğruluğu ile teknik
doğruluğunun ayrı raporlanması gerektiğinin ölçülmüş kanıtı bu:** tek sayı
kullanılsaydı 50/51 iyi haber gibi okunur, 109/0 kaybolurdu.

G-029'un ürettiği `T1012`, etiketinde "düşünüldü ve reddedildi, kabul
edilebilir alternatif olarak da yazılmadı" diye kayıtlıydı. Alternatif olarak
yazılsaydı bu yanlış pozitif görünmez olacaktı.

---

## 4. Eksen 3 — tek pozitif satır iki AYRI katmanda kayboldu

G-045 (gizli PowerShell, 403):

| | |
|---|---|
| beklenen | `T1059.001`, `T1564.003` |
| çıkan | `T1653` |
| top-1 / top-3 | HAYIR / HAYIR |
| karar | `INSUFFICIENT_DATA` (beklenen `SUFFICIENT_SUSPICIOUS`) |

Kayıp katmanı:

| teknik | nerede kayboldu |
|---|---|
| `T1059.001` | **retrieval aday havuzuna hiç girmedi** |
| `T1564.003` | **ajan katmanı eledi** |

İki farklı katman, iki farklı düzeltme. Tek bir "kaçırdı" sayısı bu ayrımı
yok ederdi. Retrieval'ın PowerShell'i bir PowerShell olayında aday bile
yapmaması ayrıca dikkat çekici — girdi `HostApplication=powershell.exe …`
dizesini birebir taşıyor.

İnceleme bayraklı diğer satır G-048 (`users\public\tdrfagent.exe`) da
`INSUFFICIENT_DATA` aldı; beklenen buydu (teknik listesi boş), ama sistemin
onu "incelenmeli" olarak işaretlemesini sağlayan bir mekanizma yok — bayrak
yalnızca etikette var.

---

## 5. Bu ölçümün ÖLÇMEDİĞİ şey

- **Tespit gücü.** 51 satırın 1'i pozitif; recall bilerek raporlanmadı
  (beklenti §2.2). G-045'in kaçırılması bir veri noktasıdır, bir oran değil.
- **Varyans.** Tek geçiş. Beklenti §5'in kuralı gereği tekrar yalnızca
  varyansın kararı oynattığı gösterilirse yapılır; burada karar 51/51 aynı
  sınıf olduğu için oynatacak bir şey görünmüyor, ama teknik listesinin
  varyansı ölçülmedi.
- **Maske kaybının kapsamı.** `access.mask`'in KV biçiminde düştüğü ölçüldü;
  aynı sarmalamanın `object.name` gibi başka alanları da düşürüp
  düşürmediği tek tek ölçülmedi (G-007'de `object.name` iki biçimde de yoktu,
  yani en az bir alan daha şüpheli).

---

## 6. S koluna etkisi — donmuş kriterler değişmiyor

Beklenti §2.1'in kuralı burada uygulanıyor: G'de ortaya çıkan zayıflığı
kapatmak için S'ye teknik/olay ID **eklenmeyecek**. G'nin sonucu S'ye
yalnızca şu şekilde giriyor:

- ~~S logları **ham Windows metni** olarak yazılacak (zaten öyle
  planlanmıştı); bu, maske kaybının S'de görünmeyeceği anlamına gelir. **Bu
  bir kusur değil, kapsam ayrımı** — ve S raporunda açıkça yazılacak, yoksa
  S'nin daha iyi sonuç vermesi sistemin iyi olduğu sanılır.~~
- Maske kaybı S'nin değil, ayrı bir düzeltme kaleminin konusu. Bu belgeden
  HANDOFF'a bir madde olarak taşınıyor.

> **BU KAYIT GEÇERSİZ (Görev 15, commit `7c9fe73`).** Üstü çizili madde
> yazıldığında maske toplu yolda okunamıyordu. K-A/K-B/K-C düzeltmesi
> sarmalanmış `Message` gövdesini ayrıştırdı; 84 şema içi alan geri geldi ve
> **erişim maskesi artık S'de de görünür.** Sonucu bir düzeltme değil bir ön
> koşul: `beklenti_13_s_kolu.md` §2'nin B1 ayırt edici çifti ancak maske
> okunabildiği için ölçülebilir. Bu maddeye dayanarak "S maskeyi ölçemez"
> denmeyecek.
