# Sonuç — Görev 17: EK-2 bastırması neden ateşlemedi

Ölçüm: `scripts/measure_ek2_suppression.py` (LLM ve indeks gerekmez, deterministik).
Girdi: `tests/fixtures/baseline_suppression_logs.json` (T4/T5), `evaluation/s_arm_set.json`
(S-EK2-01..04), `evaluation/test_scenarios.json`, `evaluation/results/g_arm_run_v2.json`.
Tarih: 2026-09-01. Kaynak kalem: `docs/sonuc_13_s_kolu.md` §4.5.

---

## 0. Bu ölçüm ne için yapıldı

S kolunda dört EK-2 kaydının **dördü de** `SUFFICIENT_SUSPICIOUS` çıktı ve
dördünde de `suppression = None` idi. Beklenen çiftin iki yönü de aynı cevabı
aldı — yani o koşuda bastırma katmanı **hiç ayırt etmedi**.

S raporu iki aday açıklama saydı ve **ikisini ayırmadığını yazdı:**

- **(a)** bastırma adımına hiç ulaşılmıyor (Yol B kurulmuyor ya da Yol A onu
  geçiyor — iki durumda da `baseline_bastirir_mi` çağrılmaz),
- **(b)** aktör alanı doldurulmuyor (`process.name` / `account.name` boş).

Düzeltmeden **önce** hangisinin doğru olduğunun ayrılması gerekiyordu, çünkü
iki açıklama iki farklı katmanda iki farklı düzeltme ister.

Ayıran ölçüm: bastırma fonksiyonuna giden **girdiyi yaz**. Çağrılıyor mu,
çağrılıyorsa hangi değerlerle?

---

## 1. TEŞHİS: ikisi de değil — ÜÇÜNCÜ bir sebep

```
(a) bastırma adımına ulaşılmıyor  : 0/4 kayıt
(b) aktör alanı boş               : 0/4 kayıt
üçüncü sebep (BİÇİM uyuşmazlığı)  : 2/4 kayıt yalnızca BİÇİM değişince sınıf değiştirdi
```

Dört kaydın dördünde de Yol B kuruldu (`A=False B=True`), aktör alanlarının
ikisi de doluydu ve `baseline_bastirir_mi` **çağrıldı**. Mekanizma çalışıyor.
Eşleşme, `process.name`'in **biçimi** yüzünden tutmuyor.

| kayıt | `process.name` | eşleşme | karar | beklenen |
|---|---|---|---|---|
| FIXTURE T4 | `TrustedInstaller.exe` *(taban ad)* | **EŞLEŞTİ** | `SUFFICIENT_BENIGN` | ✓ |
| FIXTURE T5 | `TrustedInstaller.exe` *(taban ad)* | eşleşmedi | `SUFFICIENT_SUSPICIOUS` | ✓ |
| S-EK2-01 | `C:\Windows\servicing\TrustedInstaller.exe` *(TAM YOL)* | eşleşmedi | `SUFFICIENT_SUSPICIOUS` | ✗ `BENIGN` bekleniyordu |
| S-EK2-02 | `C:\Windows\System32\msiexec.exe` *(TAM YOL)* | eşleşmedi | `SUFFICIENT_SUSPICIOUS` | ✗ `BENIGN` bekleniyordu |
| S-EK2-03 | `C:\Windows\servicing\TrustedInstaller.exe` *(TAM YOL)* | eşleşmedi | `SUFFICIENT_SUSPICIOUS` | ✓ |
| S-EK2-04 | `C:\Windows\servicing\TrustedInstaller.exe` *(TAM YOL)* | eşleşmedi | `SUFFICIENT_SUSPICIOUS` | ✓ |

`baseline_bastirir_mi` süreç adını **tam eşitlikle** karşılaştırıyor
(`app/validation/decision.py`), tablo ise taban ad tutuyor
(`config/actor_baseline.yaml`: `[trustedinstaller.exe, msiexec.exe, tiworker.exe]`).

## 2. Tek değişkenli prob — nedensellik kanıtı

Yalnızca `process.name`'in biçimi değiştirildi (tam yol → taban ad). Başka
**hiçbir** alan değişmedi:

| kayıt | değişiklik | karar | bastırma |
|---|---|---|---|
| S-EK2-01 | `C:\Windows\servicing\TrustedInstaller.exe` → `TrustedInstaller.exe` | `SUSPICIOUS` → **`BENIGN`** ✓ | YOK → **VAR** |
| S-EK2-02 | `C:\Windows\System32\msiexec.exe` → `msiexec.exe` | `SUSPICIOUS` → **`BENIGN`** ✓ | YOK → **VAR** |
| S-EK2-03 | `C:\Windows\servicing\TrustedInstaller.exe` → `TrustedInstaller.exe` | `SUSPICIOUS` → `SUSPICIOUS` ✓ | YOK → YOK |
| S-EK2-04 | `C:\Windows\servicing\TrustedInstaller.exe` → `TrustedInstaller.exe` | `SUSPICIOUS` → `SUSPICIOUS` ✓ | YOK → YOK |

**Beklenen yön biçim değişince düzeliyor, beklenmeyen yön düzelmiyor.** İkinci
yarı birincisi kadar önemli: eğer biçim düzeltmesi 03/04'ü de bastırsaydı,
düzeltme bir kör nokta açıyor olurdu. Ayrım `aile` ekseninde duruyor ve orada
sağlam — kusur yalnızca süreç adının biçiminde.

**Bu, EK-2'nin iki yönlü tasarlanmasının karşılığıdır.** Yalnız beklenmeyen yön
konsaydı 2/2 görünür ve "bastırma doğru davranıyor" denirdi.

## 3. ASIL BULGU: fixture gerçek dağılımın TAM TERSİNİ örnekliyor

`process.name` hangi biçimde geliyor:

| kaynak | tam yol | taban ad | boş |
|---|---|---|---|
| **fixture T4/T5** | **0** | **2** | 0 |
| S kolu (60 log) | 32 | 0 | — |
| G kolu (51 gerçek QRadar satırı) | 45 | 4 | 2 |
| 60 senaryo | 9 | 3 | — |

Gerçek/ölçüm korpuslarında toplam **77 tam yol / 4 taban ad**. Fixture'da
**0 tam yol / 2 taban ad**.

T4/T5 **yeşildi**, bir bastırma davranışını doğruladığı iddiasındaydı ve
2026-08-19'da ölçülüp kayda geçmişti. Ama doğruladığı şey üretimde
**neredeyse hiç görülmeyen** bir biçimdi. Yeşil test, tam eşitlik kuralının
gerçek veride tutmadığını göremezdi — çünkü kendisi gerçek veriyi hiç
örneklemiyordu.

Fixture'ın ham logu bunu çıplak gösteriyor: iki alanı birden taşıyor —
`Process Path=C:\Windows\servicing\TrustedInstaller.exe` **ve**
`Process Name=TrustedInstaller.exe`. Gerçek Windows 4657 mesaj gövdesi
(`S-EK2-01`) tek alan taşıyor ve içi tam yol:
`Process Information: ... Process Name: C:\Windows\servicing\TrustedInstaller.exe`.

Yöntem maddesi olarak yazıldı: **HANDOFF madde 17.**

## 4. Bu ölçümün ÖLÇMEDİĞİ şey

- **Düzeltmenin ne olması gerektiği.** Prob "taban ada indirmek sınıfı
  değiştiriyor" der; "taban ada indirmek DOĞRU düzeltmedir" **demez**. Taban
  ad eşleşmesi tek başına `C:\Temp\msiexec.exe`'yi de bastırırdı — bu dosyanın
  kendi kuralıyla ("fazla tablo KÖR NOKTA üretir") çelişir.
- **Düzeltmenin yan etkisi.** Kaç kaydın sınıf değiştireceği ölçülmedi.
  Aracı var (`scripts/measure_suppression_shift.py`), koşulmadı.
- **4656 maske kalemi.** Ayrı kalem, ayrı belge. Bu ölçüm ona hiç dokunmadı.

## 5. DÜZELTMENİN KABUL ÖLÇÜTÜ — kod yazılmadan önce yazıldı

Seçilen biçim: **beklenen yol deseni + taban ad**. Taban ad tek başına
yetmez; süreç dosyasının bulunduğu dizin de beklenen dizin desenlerinden
biriyle eşleşmek zorunda.

1. `python scripts/measure_ek2_suppression.py` → **çıkış kodu 0**, EK-2
   karar sınıfı **4/4**.
2. Bölüm 1'in "EK2-03/04 bastırılmadı" satırları **ayakta kalır**. Sayılar
   düzelirken kör nokta açılmamalı — sadece 0'a bakmak yetmez.
3. **Negatif testler geçer:** `C:\Users\Public\trustedinstaller.exe` ve
   `C:\Temp\msiexec.exe` bastırılmaz. Taban ad doğru, dizin yanlış.
4. Config'e **yol deseni** yazılır (`System32`, `WinSxS`, `servicing`,
   `Program Files`), tek tek exe adı değil. Tablo büyüdüğünde kod değişmez
   (yöntem madde 6).
5. **T4/T5 fixture'ları gerçek biçime çevrilir** (`Process Name` tam yol
   taşır). Bu yapılmazsa aynı yanılgı devam eder: fixture yeşil kalır ve
   üretimde var olmayan bir biçimi doğrulamayı sürdürür.

Ölçüt 5, ölçüt 1'den bağımsız olarak zorunludur — 1 fixture'a dokunmadan da
sağlanabilir, ve o hâlde madde 17'nin teşhis ettiği kusur yerinde kalır.

---

## 6. DÜZELTME UYGULANDI — beş ölçüt de sağlandı (`615d1b4`)

Eşleşme iki parçalı: taban ad `surecler` listesinde olacak **ve** dizin
`guvenilir_dizinler` desenlerinden biriyle **ayraç sınırında** eşleşecek.

| ölçüt (§5) | sonuç |
|---|---|
| 1. `measure_ek2_suppression.py` çıkış 0, EK-2 4/4 | ✓ 4/4, çıkış 0 |
| 2. EK2-03/04 hâlâ bastırılmıyor | ✓ ikisi de `ESLESMEDI` |
| 3. Negatif testler geçiyor | ✓ 4 kör nokta vakası + dizinsiz değer |
| 4. Config desen tutuyor, exe yolu değil | ✓ 6 desen |
| 5. T4/T5 gerçek biçimde | ✓ fixture artık 2 tam yol / 0 taban ad |

Tam takım **1253 geçti** (önceki sayım 1234; +19 yeni parametrik test).

### 6.1 Yan etki — kaç kayıt sınıf değiştirdi

Madde 11: kazancın yanında kaybın ölçüsü ayrı raporlanmazsa iyileşme
uydurulabilir. Ölçüldü — `scripts/measure_suppression_shift.py`, düzeltmeden
**önce** `--kaydet` (kod `git checkout HEAD~1` ile geri alınarak), sonra
`--karsilastir`:

```
DÜZELTMEDEN ÖNCE   S 60/60 sadık, G 51/51 sadık, bastırma ateşleyen 0
DÜZELTMEDEN SONRA  S 58/60,       G 51/51,       bastırma ateşleyen 2
   FARK  S-EK2-01  SUSPICIOUS -> BENIGN
   FARK  S-EK2-02  SUSPICIOUS -> BENIGN
```

**Tam iki kayıt değişti ve ikisi de hedeflenen kayıt.** Yan etki yok.

**G kolu hiç değişmedi (51/51, 0 bastırma).** Bu ayrıca raporlanıyor çünkü
akla gelen ilk şüphe buydu: G'deki beş yanlış alarmın dördü `svchost.exe`
ve `svchost.exe` `\Windows\System32`'de oturur. Desen listesi o dördünü
susturmuş olsaydı, `config/actor_baseline.yaml`'ın bilerek reddettiği
`service <- svchost.exe` bastırıcısı arka kapıdan girmiş olurdu. Girmedi —
çünkü kural iki parçalı: `svchost.exe` **taban adı** `surecler` listesinde
yok, dizininin güvenilir olması tek başına hiçbir şey kazandırmıyor.

### 6.2 Aracın kendi kusuru — SEKİZİNCİ ölçüm aracı hatası (madde 3)

`measure_suppression_shift.py` sadıklığı bozuk görünce çıkış kodu 2 verip
"fark okunmaz" diyor. Kural bir ölçüm aracı için doğru, ama **kasıtlı bir
karar katmanı değişikliğinden sonra yanlış**: o durumda "sadıklık kaybı" ile
"amaçlanan kayma" **aynı ölçümdür** ve araç ikisini ayırmıyor.

Bugün zarar vermedi çünkü farkın kendisi çıktıda satır satır yazılı ve iki
satır da beklenen kayıt. Ama araç, doğru düzeltmeyi bozuk oynatma diye
raporluyor. **Kapanış kriteri:** araç bir "beklenen kayma listesi" almalı;
listedeki farklar sadıklığı bozmaz, liste dışı tek bir fark bozar. Bu
yapılana kadar `--karsilastir`'ın çıkış kodu 2'si tek başına okunmamalı.
