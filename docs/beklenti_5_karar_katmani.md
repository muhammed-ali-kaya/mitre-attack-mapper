# Beklenti — Görev 5: kararı LLM beyanından koda taşı

**Kod yazılmadan önce yazıldı.**

`activity_verdict` şemadan **tamamen çıkacak**. Karar kod tarafında,
bileşenlerden üretilecek. Kompozit skor **okunmayacak** — o skor zaten iki
durumlu bir fonksiyon ("LLM alıntı yaptı mı", 0.29 / 0.65) ve
`assess_activity` onu hiç okumuyor.

Üç çıktı sınıfı: `INSUFFICIENT_DATA` / `SUFFICIENT_BENIGN` /
`SUFFICIENT_SUSPICIOUS`.

---

## 1. Beş girdi — kaynağı, `None` olabilirliği, `None` ise davranışı

| girdi | hangi katmandan | `None` olabilir mi | `None` ise |
|---|---|---|---|
| **teknik seti** | ajan katmanından geçmiş `accepted` listesi | evet (boş liste) | boşsa tek başına `INSUFFICIENT_DATA` sebebi — değerlendirilecek bir iddia yok |
| **doğrulanmış kanıt sayısı** | `evidence_gate` `CONFIRM` + ajan `confirm` kararları | evet (0) | 0 ise teknik iddiası **desteksiz**; `SUFFICIENT_SUSPICIOUS` üretemez |
| **varlık kritikliği** | Görev 4 tablosu (`asset_criticality`) | **evet, ve ÜÇ DURUMLU** (aşağı bak) | duruma göre farklı |
| **erişim sınıfı** | `event_semantics.describe()` → `access_class` | evet | `None` ise okuma/yazma ayrımı yapılamaz; kritikliği **yükseltmez** ama düşürmez de |
| **aktör baseline** | `account.name` + `process.name` (**yapısal alan**, ham metin değil) | evet | baseline yoksa aktör **nötr**; ne ağırlaştırır ne hafifletir. Rolü §5'te bağlandı: yalnızca **Yol B'nin bastırıcısı**, ağırlaştırıcı değil |

### Varlık kritikliği ÜÇ DURUMLU — ölçümde ortaya çıktı

Bu ayrım Görev 4'te öngörülmemişti, ölçüm gösterdi:

```
YOK       girdide hic yol yok         -> degerlendirilecek varlik yok
unknown   yol VAR, tablo tanimiyor    -> varlik gorduk, bilmiyoruz
<seviye>  siniflandirildi             -> critical / high / medium / noise
```

**İkisi aynı şey değil ve aynı davranmamalı:**
- **YOK** → kritiklik bu kararda **hiç girdi değil**. Diğer dört girdiyle
  karar verilir. Düzyazı bir tehdit istihbaratı metninde registry yolu
  olmaması, o metnin değerlendirilemez olduğu anlamına gelmez.
- **unknown** → Görev 4'ün kararı burada bağlayıcı: `SUFFICIENT_BENIGN`
  **üretemez**. Bir varlığa dokunulduğunu gördük ama ne olduğunu
  bilmiyoruz; "zararsız" demek kapsama boşluğunu kör noktaya çevirir.

---

## 2. Dört fixture — sınıf VE gerekçe zinciri

Girdiler ölçüldü (kod yazılmadan önce), sınıflar öngörülüyor:

```
      kritiklik   aile              erisim  aktor(hesap/surec)          yapisal alan
T0    YOK         -                 read    LOCAL SERVICE/svchost.exe   15
T1    critical    credential-hive   write   svc_backup/reg.exe          21
T2    noise       time-zone         read    LOCAL SERVICE/svchost.exe   21
T3    high        defender-policy   write   administrator/powershell    24
```

**T0 DÜZELTMESİ (ölçüldü, ilk yazımda yanlıştı).** Bu satırda `unknown`
yazıyordu; ölçüm `YOK` diyor. T0'ın ham logunda `Object Name` alanı **hiç
bulunmuyor** — `object.name` ayrıştırılmış alanlar arasında yok, zaten
fixture'ın kendi `expected_missing_fields` alanı da onu listeliyor.

Fark önemsiz değil: §1'deki üç durumlu ayrım tam olarak bunu ayırıyor.
`unknown` "varlık gördük, tanımıyoruz" demek ve `SUFFICIENT_BENIGN`'i
yasaklıyor; `YOK` ise kritikliğin bu kararda **hiç girdi olmaması** demek.
Aşağıdaki gerekçe zinciri buna göre düzeltildi — T0'ın sınıfı değişmiyor,
**sebebi** değişiyor. Doğru cevabı yanlış sebeple almak bu projede daha
önce iki kez ölçüm kirletti (bkz. HANDOFF, T1003.002'nin üç durumu).

| fixture | beklenen | gerekçe zinciri |
|---|---|---|
| **T0** | `INSUFFICIENT_DATA` | Bilgilendirici alan yok; teknik seti boş, doğrulanmış kanıt **0**. Kritiklik `YOK` — yani Yol B hiç kurulamıyor, Yol A da desteksiz. `SUFFICIENT_BENIGN` yine **yasak**, ama gerekçesi `unknown` değil: **yokluktan BENIGN üretilmez** (§4). Geriye tek seçenek kalıyor. |
| **T1** | `SUFFICIENT_SUSPICIOUS` | `critical` varlık **+** `write` erişim **+** doğrulanmış teknik (`T1003.002`, kapı `CONFIRM`). Üçü de var; **ikisi bile yeterdi** (kritik+yazma, ya da doğrulanmış teknik). |
| **T2** | `SUFFICIENT_BENIGN` | `noise` varlık **+** `read` erişim **+** doğrulanmış teknik **yok**. **Üçü birden gerekli** — aşağıda gerekçesi. |
| **T3** | `SUFFICIENT_SUSPICIOUS` | `high` varlık (Defender politikası) **+** `write` erişim. Doğrulanmış teknik **yok** (retrieval T1685'i bulamıyor, 2A'nın işi) — yani bu vaka **teknik setinden bağımsız** alarm üretmeli. |

### T2 için: üçü birden mi, biri yeter mi?

**Üçü birden gerekli.** `SUFFICIENT_BENIGN` **pozitif** bir iddiadır:
"baktım, zararsız". Yokluktan üretilemez.

- `noise` varlık tek başına yetmez: gürültü bir anahtara **yazmak**
  hâlâ ilgi çekicidir.
- `read` tek başına yetmez: kritik bir anahtarı okumak (T1'in yarısı)
  zararsız değildir.
- "doğrulanmış teknik yok" tek başına yetmez — bu bir **yokluk**tur ve
  yokluktan `BENIGN` çıkarmak, Görev 4'ün `unknown ≠ noise` kararının
  tam tersidir.

**T3'ün önemi:** doğrulanmış teknik olmadan alarm üretmeli. Bu, karar
fonksiyonunun teknik setine **bağımlı olmadığını** kanıtlayan vaka.

---

## 3. 60 senaryo — EN KRİTİK MADDE, ölçüldü

Endişe haklıydı ve ölçüm daha da sert çıktı:

```
60 SENARYODA GIRDI MEVCUDIYETI
   olay ID           15/60   %25
   erisim sinifi     15/60   %25
   aktor              8/60   %13
   VARLIK KRITIKLIGI  0/60   %0     <-- SIFIR
      (yapisal alanda 0; ham metinde 2 senaryoda yol geciyor -- ilk
       olcumde 1 sayilmisti, duzeltildi. Bkz. bolum 6.)
```

**Varlık kritikliği 60 senaryonun HİÇBİRİNDE mevcut değil.**

### Bağlayıcı tasarım sonucu

Karar fonksiyonu kritikliği **zorunlu girdi yaparsa 60/60 senaryo
`INSUFFICIENT_DATA` üretir** ve sistem yine alarm vermeyen bir sistem
olur — yalnızca sebebi değişir. Bu kabul edilemez.

**Bu yüzden, önceden bağlanan kural:**

> **Teknik seti + doğrulanmış kanıt sayısı, TEK BAŞINA
> `SUFFICIENT_SUSPICIOUS` üretebilmelidir.** Kritiklik ve erişim sınıfı
> **ağırlaştırıcı**dır, ön koşul değil.

Ve simetrik olarak:

> **Kritiklik + erişim sınıfı da TEK BAŞINA yeterlidir** (T3 vakası):
> `high`/`critical` varlığa `write`, doğrulanmış teknik olmadan da alarm
> üretir.

Yani beş girdi **VE'lenmiyor**; iki bağımsız yol var. Bir logda hangi
girdiler mevcutsa o yol çalışır.

### 60 senaryo için beklenti

| beklenti | tutmazsa ne öğrenilir |
|---|---|
| `SUFFICIENT_SUSPICIOUS` sayısı **> 0** ve teknik setinden geliyor | karar fonksiyonu hâlâ kritikliğe bağımlı; iki yol kurulmamış |
| `negatif_ornek` kategorisinin 5'i **`SUFFICIENT_SUSPICIOUS` OLMAMALI** | yanlış pozitif üretiyoruz; eşik gevşek |
| `INSUFFICIENT_DATA` oranı **%100 değil** | kritiklik zorunlu girdi olmuş |

---

## 4. Yasak biçimler

- Eşikleri fixture çıktısına bakarak ayarlamak. Sayısal eşik **türetilecek**
  ve gerekçesi yazılacak; "T2 benign çıksın diye 0.4 yaptım" kabul edilmez.
- Kompozit skoru okumak — açıkça yasak.
- `activity_verdict`'i şemada bırakıp "yedek olarak" kullanmak. **Tamamen
  çıkacak**; yedek bırakmak iki gerçeklik demektir.
- Yokluktan `BENIGN` üretmek.

---

## 5. Aktör baseline — Yol B'nin BASTIRICISI

§3 iki bağımsız yol açtı. Yol B (`kritiklik + erişim`) tek başına alarm
üretebiliyor ve bu **ters yönde bir risk** taşıyor: bastırıcı konmazsa
`high`/`critical` bir yola yapılan **her yazma** alarm olur. Meşru yönetici
faaliyeti de öyle görünür — GPO uygulaması, yazılım kurulumu, yama,
yedekleme ajanı. O hâlde Yol B bir yanlış alarm fabrikasına döner ve
`benign_signals.py`'nin varlık sebebi olan alarm yorgunluğu geri gelir.

**Karar: aktör baseline Yol B üzerinde BASTIRICI olarak çalışır.**
Ağırlaştırıcı değildir — hiçbir aktör tek başına şüphe *yükseltmez*.

### 5.1 Bastırma anahtarı AKTÖR DEĞİL, `(varlık ailesi, aktör)` ÇİFTİ

Bu maddenin gerekçesi ölçüldü. İki aday log kuruldu — **aynı aktör**
(`SYSTEM` / `TrustedInstaller.exe`), **farklı varlık ailesi**:

```
id    kritiklik  aile              erisim  aktor                        benign_strong
T4*   high       service           write   SYSTEM/TrustedInstaller.exe  True
T5*   high       defender-policy   write   SYSTEM/TrustedInstaller.exe  True
```

T4* meşru yazılım kurulumu (`...\CurrentControlSet\Services\AcmeAgent`
altına `ImagePath` yazılıyor). T5* Defender'ın kapatılması. **Mevcut
`detect_benign_signals` ikisini birbirinden ayıramıyor** — ikisine de aynı
`strong` sinyali veriyor, çünkü yalnızca **aktöre** bakıyor.

Bastırma aktöre bakarak yapılırsa T5* de bastırılır ve sonuç, tam olarak
saldırganın hedeflediği yerde bir **kör nokta** olur: `SYSTEM` ve
`TrustedInstaller` ayrıcalık yükseltmenin **varış noktasıdır**, muafiyet
listesi değil.

Bu yüzden bastırma anahtarı çifttir. Görev 4 tablosu bu ayrımı zaten
üretiyor — `aile` alanı (`service`, `defender-policy`, `credential-hive`,
`time-zone`) mevcut, yeni bir taksonomi gerekmiyor:

```
(service,         TrustedInstaller)  BEKLENEN     -> bastir
(defender-policy, TrustedInstaller)  BEKLENMEYEN  -> bastirma
```

### 5.2 Bastırma TEK YÖNLÜ ve TEK YOLLUDUR

> **Baseline yalnızca Yol B'yi bastırabilir. Yol A'yı
> (`teknik + doğrulanmış kanıt`) ASLA bastıramaz. İki yol da tetiklenmişse
> sonuç `SUFFICIENT_SUSPICIOUS`'tur.**

Gerekçe: aktör alanı **taklit edilebilir**. Bir saldırgan `SYSTEM`
bağlamına geçebilir; bu, ele geçirmenin başarısızlığı değil **amacıdır**.
Doğrulanmış kanıtı taklit edilebilir bir alanla sildirmek, kanıt kapısını
aktör alanına devretmek olurdu.

### 5.3 Baseline YAPISAL ALANDAN okunur, ham metinden değil

Ölçüldü. T3 alındı, **tek değişiklik** aktör olmayan bir alana sahte bir
dize kondu (`File Path=C:\Users\Public\trustedinstaller.exe.log`):

```
T3 (orijinal)      benign_strong=False   process.name='powershell.exe'
T3 + sahte dize    benign_strong=True    process.name='powershell.exe'
```

Defender'ı kapatan log, **hiçbir davranışı değişmeden** meşru ilan edildi.
`detect_benign_signals` ham metinde alt dize arıyor; `process.name` hâlâ
`powershell.exe`.

Bu, Görev 2B'nin tezinin aynısı: 57 kural koşulu `Message`'dan yapısal
alanlara bu yüzden taşındı. Baseline `account.name` ve `process.name`
alanlarını okuyacak. Mevcut ham metin taraması karar girdisi **değildir**;
analiste gösterilen bir sinyal olarak kalabilir.

### 5.4 Fixture'lar — kararı sabitleyen ÇİFT

Tek fixture bu kararı sabitleyemez, çünkü cevap "aktöre göre" değil
"**çifte** göre". İkisi birden gerekiyor ve ikisi de `tests/fixtures/
baseline_suppression_logs.json` dosyasına konuldu (sentetik oldukları
dosyada yazılı — dört probu taşıyan fixture, verilen log iddiası
bozulmasın diye ayrı tutuldu):

| fixture | girdi | beklenen | gerekçe zinciri |
|---|---|---|---|
| **T4** | `high` (`service`) + `write` + `SYSTEM/TrustedInstaller.exe` | `SUFFICIENT_BENIGN` | Yol A boş (doğrulanmış teknik yok). Yol B tetikleniyor ama çift **beklenen listede**. Bu bir yokluk değil, **eşleşme** — `BENIGN`'in pozitif iddia olma şartı (§2, T2) karşılanıyor: eşleşen beklenti kuralı çıktıda adıyla raporlanacak. |
| **T5** | `high` (`defender-policy`) + `write` + `SYSTEM/TrustedInstaller.exe` | `SUFFICIENT_SUSPICIOUS` | Aynı aktör, **beklenmeyen** çift. Bastırma yok. Bu vaka 5.1'in kör noktasını kilitler: cevabı `BENIGN` çıkarsa bastırma aktöre kaymış demektir. |

**T4/T5 çifti neyi kanıtlar:** ikisinin aktörü birebir aynı. Sınıfları
farklıysa karar çifte bakıyordur; aynıysa aktöre bakıyordur ve kural
uygulanmamıştır.

### 5.5 Eşleşme yoksa ne olur

Çift beklenen listede **yoksa** bastırma **yoktur** — sonuç Yol B'nin
ürettiği sınıf olarak kalır. Yokluk `BENIGN` üretmez (§4). Aktör `None`
ise de bastırma yoktur; bu, §1'deki "baseline yoksa aktör nötr" satırının
Yol B'deki karşılığıdır.

### 5.6 Yasak biçim (§4'e ek)

- Bastırmayı **aktör listesiyle** yapmak — ölçülen sebeple yasak (5.1).
- Baseline'ı **ham metinden** beslemek — ölçülen sebeple yasak (5.3).
- Beklenen çift listesini fixture çıktısına bakarak doldurmak. Liste
  **gerekçesiyle** yazılacak: bir çift, o aktörün o varlık ailesine
  yazmasının **işletim sistemi tasarımı gereği** olduğu gösterilebiliyorsa
  girer. "T4 benign çıksın diye ekledim" kabul edilmez.

---

## 6. Kritiklik hangi alandan okunacak? — KARAR VERİLDİ

Beklenti bunu söylemiyordu ve ölçüm bir boşluk açtı. 60 senaryoda
`object.name` **0/60**; ama ham metinde registry yolu geçen **2** senaryo
var:

```
alt_teknik_gerektiren  "...HKCU\Software\Microsoft\Windows\CurrentVersion\Run
                        altina yeni bir anahtar ekledi"     -> high, write
raw_log                "reg.exe save HKLM\SAM C:\Users\Public\sam.hive"
                        SubjectUserName=admin.svc            -> critical (bkz. asagi)
```

İki sonuç:

1. Kritiklik **yalnızca** `object.name`'den okunursa Yol B 60 senaryonun
   **hiçbirinde** tetiklenmez ve §3'ün "`SUFFICIENT_SUSPICIOUS` > 0 ve
   teknik setinden geliyor" beklentisi Yol A'yı ölçer, Yol B'yi **hiç
   ölçmez**.
2. Komut satırından da okunursa `reg.exe save HKLM\SAM` vakası kritiklik
   kazanır — ki bu, projenin amiral gemisi olan SAM hırsızlığı vakasının
   düzyazı olmayan ikizidir.

**Ölçümde çıkan yan bulgu:** o satırda yol `HKLM\SAM C` olarak çıkarılıyor
(hedef argüman boşlukla bitişik) ve `siniflandir` buna `unknown` diyor.
`HKLM\SAM` tek başına `critical`. Yani çıkarım sınırı bir **tokenizasyon
artefaktı** yüzünden kritik varlığı `unknown`'a düşürüyor.

**KARAR — ONAYLANDI (2026-08-19).** Kritiklik önce yapısal yol
alanlarından (`object.name`, `file.path`) okunur; yoksa **komut
satırından** okunur; **düzyazıdan okunmaz.** Gerekçe projede zaten var:
komut satırı olayın **artefaktıdır**, düzyazı ise olayın **iddiasıdır** —
"bir PowerShell süreci kod indirdi" bir iddiadır, kanıt değildir.

**ÖN KOŞUL — komut satırı, tokenizasyon çözülmeden kaynak olarak
BAĞLANMAZ.** Yukarıdaki yan bulgu bunu zorunlu kılıyor: kaynağı önce
bağlayıp sonra çıkarımı düzeltmek, amiral gemisi vakanın `unknown`
göründüğü bir ara durum yaratırdı ve o ara durumda yapılan her ölçüm
kirlenirdi.

Sıra: **(1)** yol çıkarımının sınırını düzelt ve fixture'la sabitle →
**(2)** kaynak olarak bağla.

Adım (1) bitti: `docs/beklenti_6_komut_satiri_yol_siniri.md` (beklenti),
`app/normalization/command_line_paths.py` (K1–K5 kuralları),
`tests/fixtures/command_line_path_boundary.json` (10 vaka).
Ölçüm — `scripts/measure_baseline_inputs.py` bölüm 4:

```
V1  unknown -> critical    reg.exe save HKLM\SAM C:\Users\Public\sam.hive
V2  unknown -> critical    reg save HKLM\SAM sam.hive
V7  (yok)   -> high        Set-ItemProperty -Path "HKLM:\...\Windows Defender"
V9  unknown -> critical    reg save HKLM\SAM backup
V3-V6       -> degismedi   (regresyon sarti tutuldu)
```

Adım (2) Görev 5'in kodunda yapılacak; artık engel yok.

---

## 7. Sonuç raporuna ŞİMDİDEN yazılacak kısıt

2B'de aynısı yapıldı ve doğru çıktı; burada da kod yazılmadan yazılıyor.

> **Yol B'nin doğruluğu bu test setiyle gösterilemez.** 60 senaryoda Yol B
> yalnızca `object.name` okunursa **0**, komut satırı da eklenince **2**
> girdide tetiklenebiliyor. İki senaryo bir karar yolunu doğrulamaz.
> Yol B için elimizdeki tek kanıt **dört prob logu (T0–T3)** ve
> **T4/T5 bastırma çifti**dir. Rapor bu cümleyi taşıyacak; "Yol B çalışıyor"
> denmeyecek, "Yol B bu altı fixture'da beklendiği gibi davranıyor"
> denecek.

### Bu bulgu bu oturumda DÖRDÜNCÜ kez çıktı

Aynı kusur dört ayrı katmanda ölçüldü — tesadüf değil, **test setinin
yapısal bir özelliği**:

| katman | ölçülen kapsama | nerede |
|---|---|---|
| kural motoru koşulları | 57 koşulun **18'i** ölçülebiliyor (49 kuralın 14'ü ateşleniyor) | 2B |
| olay ID temsili | kataloğun beklediği 48 ID'nin **6'sı** (%12) | Görev 13 |
| registry yolu | test verisinin **tamamında 3** yol; 60 senaryoda **0** yapısal | Görev 4 |
| **Yol B tetiklenmesi** | **0/60** (komut satırıyla 2/60) | Görev 5 |

**Ortak kök:** 60 senaryonun **45'i düzyazı**. Düzyazı bir iddiadır; bu
katmanların hepsi **artefakt** okur (yapısal alan, olay ID, yol, maske).
Set, RAG hattını ölçmek için kurulmuş ve onu iyi ölçüyor; karar ve kural
katmanlarını **ölçmüyor**, ölçemez.

**Sonuç — Görev 13 bir iyileştirme değil, ön koşul.** Ondan önce yazılan
her "şu katman çalışıyor" cümlesi altı fixture'a dayanır ve raporda böyle
yazılır. Görev 13'ün kabul kriterleri (≥24 olay ID, üç kritiklik sınıfı,
baseline bastırmasının iki yönü) HANDOFF'ta toplandı.

---

## 8. Bitince: soğuk/sıcak ölçümü TEKRAR

`activity_verdict` şemadan çıktıktan sonra kollar hâlâ farklı mı?

HANDOFF'taki kayıt: *"Soğuk vs sıcak model: aynı girdi, zıt karar
(`malicious_or_suspicious` ↔ `insufficient_evidence`), her kol kendi içinde
6/6 kararlı"* — ve sonradan sıcak kolda da varyans ölçüldü
(`T1012` etiketi `low/low/medium`, T1 kararı 2/3).

**Beklenti:** karar koda geçtikten sonra **karar sınıfı** kollar arasında
değişmemeli. Etiket varyansı sürebilir (o Görev 7'nin işi) ama
`INSUFFICIENT_DATA` ↔ `SUFFICIENT_SUSPICIOUS` salınımı **bitmeli**.

Tutarsa HANDOFF'taki kırılganlık kaydı kapanır. Tutmazsa karar fonksiyonu
hâlâ LLM çıktısının varyans gösteren bir alanına bağlı demektir ve o alan
bulunmalı.

---

## 9. SONUÇ — ölçüldü (2026-08-19, `--repeat 3`, iki kol)

### Karar sınıfı: kollar arasında DEĞİŞMİYOR — beklenti tuttu

| log | soğuk ×3 | sıcak ×3 | aynı mı |
|---|---|---|---|
| T0 | `INSUFFICIENT_DATA` | `INSUFFICIENT_DATA` | ✔ |
| T1 | `SUFFICIENT_SUSPICIOUS` | `SUFFICIENT_SUSPICIOUS` | ✔ |
| T2 | `SUFFICIENT_BENIGN` | `SUFFICIENT_BENIGN` | ✔ |
| T3 | `SUFFICIENT_SUSPICIOUS` | `SUFFICIENT_SUSPICIOUS` | ✔ |

Her log kendi içinde 3/3 sabit, iki kol arasında da aynı. **HANDOFF'taki
kırılganlık kaydı kapandı** — kayıt tam olarak T1'e aitti (soğuk
`malicious_or_suspicious` / sıcak `insufficient_evidence`).

### Etiket varyansı SÜRÜYOR — ve bu beklenmişti (Görev 7)

Aynı koşularda, karar sınıfı sabitken:

```
T1  guven etiketi     medium / low / low     (T1003.002)
T1  dogrulanmis kanit 1 / 2 / 2
T1  dongu tur sayisi  0 / 1
T0  kompozit skor     2 varyant
T3  teknik listesi    soguk ['T1112','T1685']  vs  sicak ['T1112']
```

**Karar bu varyansların hiçbirinden etkilenmiyor**, ve sebebi yapısal:

- Yol A eşiği bir **taban**, eşleşme değil (`kanıt ≥ 1`). Kanıt sayısı
  1↔2 oynayabilir, eşik yine geçilir.
- Yol B teknik setini **hiç okumuyor**. T3'te doğru teknik (`T1685`)
  sıcak kolda listeden düşmüş; karar değişmemiş. T3'ün fixture olarak
  var olma sebebi tam olarak buydu ve iki kolda birden doğrulandı.
- Güven **etiketi** karar girdisi değil. Etiket oynaması Görev 7'nin
  konusu ve karara taşınmıyor.

**Yani kararı LLM çıktısının varyans gösteren bir alanına bağlı
bulamadık.** Aranan alan yok; varyans var ama karara giden yolda değil.

### Yan etki: `detect_benign_signals` karardan çıkınca

Etkilenen popülasyon **4/60**, hepsi `negatif_ornek` (kategorinin 5'inin
4'ü). Beşi de gerçek hattan geçirildi (5. kontrol vakası — güçlü sinyali
yok, eski sistemde kararı LLM'den geliyordu):

```
negative-001..005   INSUFFICIENT_DATA   alarm=False   informational_only=[True,...]
dagilim: {'INSUFFICIENT_DATA': 5}      tutarsizlik: 0
```

**Alarm davranışı korundu — ölçüldü, varsayılmadı.** Yanlış alarm 0/5;
`informational_only` beşinde de doğru okunuyor, yani `metrics.py`'nin
alarm saymama kuralı bozulmadı.

**Ama etiket zayıfladı ve bu bir kayıptır.** Onaylı bir değişiklik talebi
artık "Meşru aktivite" değil "Karar için yetersiz veri" diyor. Alarm
üretmemesi aynı; analiste söylediği şey aynı değil. Meşruiyet belirtileri
arayüzde hâlâ gösteriliyor (`benign_signals_display`), yani bilgi
kaybolmuyor — başlık cümlesi zayıflıyor.

**Bu bilinçli bir takas, ama kapatılmış bir mesele değil.** `BENIGN`
üretebilmek için pozitif bir eşleşme gerekiyor (§4) ve düzyazıda böyle
bir eşleşme yok: kritiklik 59/60'ta `YOK`. Doğru çözüm sinyali karara geri
koymak DEĞİL (taklit edilebilir, §5.3); düzyazı için **taklit edilemez
bir pozitif kaynak** bulmak — örneğin değişiklik yönetimi kaydının
kendisiyle doğrulama. Bugün öyle bir kaynak yok, bu yüzden
`INSUFFICIENT_DATA` dürüst cevaptır.
