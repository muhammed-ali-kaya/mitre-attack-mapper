# Beklenti 24 — şema alan boşluğu (`Command`, `Parent Process Path`)

**Durum:** ölçüm bitti, düzeltme YAZILMADI.
**Ölçüm aracı:** `scripts/measure_schema_field_gap.py` (LLM/indeks gerekmez).
**Ham çıktı:** `evaluation/results/schema_field_gap.json`
**Tetikleyen gözlem:** kullanıcının powercfg koşusu — karar doğru
(`INSUFFICIENT_DATA`) ama iki alan `unknown.*` altına düşüyor.

---

## 0. Bu belge kod yazılmadan önce yazıldı

Yöntem maddesi: eşikleri ve kararı fixture çıktısına bakarak ayarlamak yasak.
Aşağıdaki §6 kabul ölçütleri, düzeltme yazılmadan ÖNCE bağlanmıştır.

Ayrıca yöntem maddesi 16 gereği: bu belgenin ölçtüğü katmanın o an çalışır
durumda olduğunu göstermesi gerekiyor. Göstermiyor — §5'e bakınız. Bu, ölçümün
bir sonucu değil, ölçümün **baş bulgusu**.

---

## 1. Bildirilen iki iddia, ölçüm sonrası hali

| # | iddia | hüküm |
|---|---|---|
| 1 | `Command` → `unknown.Command`, komut satırı hatta hiç girmiyor | **DOĞRU, ve eksik** — space_kv biçiminde durum daha ağır (§3) |
| 2 | `parent.process.name` şemada yok, o kurallar hiç çalışamaz | **ÖNCÜLÜ YANLIŞ** — alan şemada var (`field_schema.yaml:41`), aliasları `Parent Process Name` / `ParentProcessName` / `ParentImage`. Kural hedefsiz değil; **log başka bir ad yazmış** |

İkincisinin doğru ifadesi: `Parent Process Path` hiçbir aliasa uymuyor, bu
yüzden `unknown.*` altına düşüyor. Hedef alan sağlam, **köprü yok**.

Bu ayrım kararı değiştiriyor: (1) bir alias boşluğu, (2) de bir alias boşluğu —
ama (2)'de eklenecek adın **hangi kanonik alana** bağlanacağı serbest değil,
§4'te ölçülüyor.

---

## 2. Ölçüm A — kural haritasının hedefleri şemada var mı

**14 eşsiz hedef.** Hepsi tanımlı. `rule_field_map.yaml`'ın sessiz bir boşluğu
**yok**.

Bu sonuca ilk denemede yanlış ulaşıldı ve düzeltildi; kaydı §5'te.

---

## 3. Ölçüm B — biçime göre iki farklı arıza

Aynı eksik ad, girdi biçimine göre iki farklı sonuç veriyor. Bu ayrım
ölçülmeden düzeltme tasarlanamaz.

### 3a. `windows_message` biçimi — kullanıcının gördüğü

```
Event ID:  4688
Command:  powercfg.exe /change standby-timeout-ac 0
Parent Process Path:  C:\Windows\System32\cmd.exe
```
→ `event.id='4688'`, `unknown.Command=...`, `unknown.Parent Process Path=...`

Alan **kaybolur ama komşusunu bozmaz**. Bildirilen davranış bu.

### 3b. `space_kv` biçimi — bildirilmedi, daha ağır

```
EventID=4688 Command=powershell -enc AAA NewProcessName=C:\x.exe
```
→ `event.id = '4688 Command=powershell -enc AAA'`

Alan `unknown.*` altına bile düşmüyor: **bir önceki alanın değerine yutuluyor.**
Sebep `_space_kv_boundary_pattern` — değer sınırı ŞEMADAN türetiliyor, yani
şemada olmayan ad değer bitirmiyor.

Bu, `field_schema.yaml:62`'deki **TargetUserName kaydının aynısı**, başka bir
adla tekrar ediyor. Orada da ad şemada olmadığı için önceki alan onu yutuyordu.

**Neden 3b, 3a'dan ağır:** yutulan alan `event.id`. Her kuralın
`required.event_ids` kapısı bu alanı okuyor. Yani space_kv biçiminde
`Command=` taşıyan bir log yalnızca komut satırını değil, **olay ID eşleşmesinin
tamamını** kaybediyor.

**Bu satır bir tahmin değil, koşuldu** (`scratchpad/probe_command2.py`, vaka 1).
Ama üretim korpusunda örneklenmiş DEĞİL — §5.

---

## 4. Ölçüm C — hangi kurallar açılır (ÜST SINIR)

| aday | bağlanacağı kanonik | bu hedefi kullanan koşul | katalogda karşılığı olan teknik |
|---|---|---|---|
| `Command` | `process.command_line` | **22** | 22 teknik |
| `Parent Process Path` | `parent.process.path` (yeni) | **0** | — |

`Command` için 22 teknik: T1003.002, T1047, T1053.005, T1055.001, T1057,
T1059.001, T1070.001, T1070.003, T1071.001, T1074, T1083, T1105, T1140,
T1218.010, T1218.011, T1486, T1489, T1490, T1505.003, T1560, T1564.003,
T1685.005.

**Bu bir ÜST SINIRDIR, kazanç değil.** Alan dolduğu için desen tutacak diye bir
şey yok; K1 ölçümü (Görev 23) koşulların 12/49'unun ayırt edici olmadığını
zaten gösterdi.

### 4a. `parent.process.path` tek başına HİÇBİR ŞEY açmıyor

Ölçümün en net sayısı bu: **0 koşul.** Kurallar `parent.process.name` diyor
(T1204.002 ve T1566.001, `rules/attack_mappings.yaml:295,311`). Yeni bir
`parent.process.path` kanonik alanı eklemek satıra bir anahtar daha koyar ve
**hiçbir kural onu okumaz**.

Yani "yeni kanonik alan + `parent.process.name` türetimi" önerisindeki asıl iş
kanonik alan değil, **türetim**. Türetim yazılmazsa değişiklik ölü doğar.

---

## 5. BAŞ BULGU — bu ölçüm düzeltmeyi doğrulayamaz (madde 17)

Ölçüm E, adayların üretim korpuslarında kaç kez geçtiğini sayıyor:

| ad | G (51 gerçek QRadar) | S (60) | H (15) |
|---|---|---|---|
| `Command=` (CommandLine hariç) | **0** | **0** | **0** |
| `CommandLine=` | 1 | 0 | 0 |
| `Parent Process Path` | **0** | **0** | **0** |
| `Parent Process Name` | **0** | **0** | **0** |
| `ParentImage` | 0 | 1 | 1 |

**İki adayın ikisi de 126 kaydın hiçbirinde geçmiyor.** Tek kanıt kullanıcının
powercfg logu ve o log depoda yok.

Sonuçları:

1. **Ölçüm D boş bir ölçümdür.** D "şemaya bu iki adı ekleyince 0/126 kaydın
   ayrıştırması değişti" diyor. Bu "yan etki yok" DEMEK DEGİL; "bu korpus o
   biçimi hiç içermiyor" demek. Tek gerçek veri noktası: `CommandLine=` taşıyan
   1 G satırı değişmedi, yani `Command`/`CommandLine` çakışması en-uzun-eşleşme
   ile doğru çözülüyor. Bir satır, bir çakışma — hepsi bu.

2. **Ebeveyn süreç dalı korpusta neredeyse hiç örneklenmemiş:** 126 kaydın
   yalnızca 2'sinde (`ParentImage`). T1204.002 ve T1566.001 bugün ölçülemiyor.

3. **Fixture yazılamaz.** Madde 17: bir fixture'ın biçimi, temsil ettiği
   korpusta sayılmalıdır; sayı sıfırsa fixture bir sözleşme değil bir
   temennidir. Görev 17'de EK-2 bastırması tam bu yüzden yeşil testle birlikte
   çalışmıyordu.

**Bu yüzden düzeltme bu oturumda YAZILMADI.** Gereken tek şey powercfg logunun
ham metni.

---

## 5a. ARAÇ KUSURU 9 — `parse_fields` verilen şemayı uygulamıyor

Bu betiğin ilk hali D'yi `parse_fields(metin, aday_sema)` ile ölçtü ve
"0 değişti" dedi. Sebep şemanın zararsızlığı değildi:

`SpaceKeyValueFormat.extract_pairs` (`formats.py:245`) kendisine verilen şemayı
kullanmıyor, **kendi içinde `load_schema()` çağırıyor** ve modül önbelleğini
okuyor. Yani sınır deseni her zaman ÜRETİM şemasından kuruluyor.

Aynı log, aynı çağrı:

| yol | `event.id` | `process.command_line` |
|---|---|---|
| şema parametreyle | `'4688 Command=powershell -enc AAA'` | yok |
| şema önbellekle | `'4688'` | `'powershell -enc AAA'` |

Ölçüm aracı kusuru sayacı **8 → 9** (HANDOFF §351 sekizinciyi kaydediyor).
Deseni yine aynı: **çıktıya bakılarak kabul edilmişti**, `0/126` makul
görünüyordu.

Betik artık şemayı önbelleği değiştirerek uyguluyor (`_ayristir`). Düzeltilmiş
D yine 0/126 veriyor — ama artık bu sayı ölçülmüş bir sonuç, bir kaza değil.

**Ayrı kalem:** `parse_fields(raw, schema)` imzası bir yalan söylüyor; şema
parametresi alias eşlemesine uygulanıyor ama tokenizasyona uygulanmıyor. Bu
düzeltilecek AYRI bir iştir; bu görevin kapsamında değil, kayda geçti.

---

## 6. KARAR ve KABUL ÖLÇÜTLERİ (kod yazılmadan önce bağlandı)

### 6a. `Command` → `process.command_line` ALIAS

Gerekçe: kanonik alan var, 22 kural koşulu onu okuyor, ad bir yazım
farkı — yeni bir kavram değil.

Kabul ölçütleri:
- Ö1 `Command:  <deger>` taşıyan windows_message girdisinde
  `process.command_line` DOLU, `unknown.Command` YOK.
- Ö2 `Command=<deger>` taşıyan space_kv girdisinde `event.id` artık
  yutulmuyor (§3b tersine döner).
- Ö3 `CommandLine=` taşıyan mevcut girdilerde alan kümesi ve DEĞERLER
  değişmiyor (en-uzun-eşleşme korunur) — G'nin 1 satırı + gidiş-dönüş vakaları.
- Ö4 126 kayıtta ayrıştırma çıktısı Ö3 dışında değişmiyor.

### 6b. `Parent Process Path` — ALIAS mı, YENİ KANONİK mi

**Ölçüm yeni kanonik alanı tek başına eliyor: 0 koşul açıyor (§4a).**
Geriye iki seçenek kalıyor ve ikisi de kod istiyor:

| seçenek | ne yapar | riski |
|---|---|---|
| **(a)** `Parent Process Path` → `parent.process.name` aliası | 2 kuralı hemen ateşlenebilir yapar; desenler (`(?i)(winword\|excel\|powerpnt\|outlook)\.exe`) çıpasız olduğu için tam yol da eşleşir | "name" adlı alana YOL koyar. Bugün zararsız: hiçbir Python tüketicisi `parent.process.name`'e dokunmuyor (ölçüldü). Yarın bir tüketici tam eşitlik yaparsa Görev 17'nin hatası tekrar eder |
| **(b)** yeni `parent.process.path` + `parent.process.name` türetimi (taban ad) | anlamı doğru tutar | türetim yeni mekanizmadır; `process.name`/`process.path` çiftinde bugün böyle bir türetim YOK, yani şemaya tek örnek bir kural girer |

**Öneri: (b), ama Görev 17'nin biçimiyle.** Görev 17 tam bu sorunu
"beklenen yol deseni + taban ad" olarak çözdü; aynı idyom burada da
kullanılmalı ki şemada iki farklı ad-yol eşleştirme kuralı olmasın.

**KARAR ASKIDA** — (a) ile (b) arasındaki fark ancak gerçek logun biçimi
görülünce bağlanabilir: log tam yol mu yazıyor, taban ad mı? Görev 17'nin dersi
tam olarak buydu ve fixture gerçek dağılımın tersini örneklemişti.

Kabul ölçütleri (hangisi seçilirse seçilsin):
- Ö5 T1204.002 ve T1566.001, ebeveyn koşulu SAĞLANAN bir girdide ateşlenir.
- Ö6 Aynı teknikler, ebeveyn koşulu SAĞLANMAYAN bir girdide ateşlenmez
  (iki yönlü — Görev 17'nin EK-2'de işe yarayan tasarımı).
- Ö7 `ParentImage` taşıyan 2 mevcut kayıtta davranış değişmez.

### 6c. Yan etki ölçümü (G, S, B1, EK-2)

Ö4 ve Ö7 ayrıştırma düzeyini kapatıyor. Karar düzeyi için:
- Ö8 S kolunun B1 çifti: altı yarının kararı DEĞİŞMEZ (bu düzeltme
  4656 maske kalemine dokunmuyor).
- Ö9 EK-2 bastırma davranışı değişmez.
- Ö10 G kolunun 5 yanlış alarmı artmaz.

Ö8–Ö10 **hat koşusu gerektirir** ve S/G'nin yan yana okunmadığı kuralı burada
da geçerli.

---

## 7. Bu düzeltme yapıldıktan sonra ne DENMEYECEK

"Komut satırı artık hatta giriyor" denmeyecek.
"Şu iki biçimde, şu fixture'larda beklendiği gibi davranıyor" denecek —
çünkü §5'in tablosu düzeltmeden sonra da büyük ölçüde sıfır kalacak.

---

## 8. GERÇEK LOG GELDİ (2026-09-03) — §5'in bloğu kalktı

Ham kayıt `tests/fixtures/powercfg_4688_brace.json`. Biçim **`brace_kv`** —
§3b'de ölçülen space_kv yutulması bu kayıtta **geçerli değil**, ayrı bir arıza
olarak durmaya devam ediyor.

Ayrıştırma sonucu (ölçüldü, `probe_powercfg.py`):

| alan | değer |
|---|---|
| `process.name` | `powercfg.exe` — **taban ad** |
| `process.path` | `C:\Windows\System32\powercfg.exe` — tam yol |
| `unknown.Command` | `"C:\...\powercfg.exe" /setdcvalueindex ...` (değer bütün olarak okunmuş) |
| `unknown.Parent Process Path` | `C:\...\v1.0\powershell.exe` — **tam yol** |
| `parent.process.name` | **YOK** |

**Belirleyici gözlem:** kaynak çocuk süreç için **hem yol hem taban ad**
yazıyor (`Process Path` + `Process Name`), ebeveyn için **yalnızca yol**.
Asimetri şemada değil, **logda**.

### 8a. `text_to_row` hakkındaki önceki ifade düzeltildi

`unknown.*` anahtarları satıra **giriyor** (legacy izdüşümü tüm alanları
taşıyor); yalnızca kanonik döngü onları atlıyor. Yani veri kayıp değil,
**hiçbir kural onu okumuyor**. Sonuç aynı, mekanizma farklı.

### 8b. YENİ ÖLÇÜM — ebeveyn düzelse bile kural ateşlenmiyor

Gerçek biçimde bir Office→kabuk zinciri kurulup sınandı (`probe_child.py`):

| T1204.002 koşulu | bugün | ebeveyn elle doldurulunca |
|---|---|---|
| `parent.process.name ~ /(winword\|excel\|powerpnt\|outlook)\.exe/` | False | **True** |
| `process.name ~ /\(cmd\|powershell\|...)\.exe/` | False | **False** |

Çocuk koşulu deseninde **ayraç zorunlu** (`\`), ama bu kaynak
`Process Name` alanına **taban ad** yazıyor. Yani ebeveyn boşluğu
kapatılsa da kural bu biçimde ateşlenmez.

### 8c. Bu tekil değil — katalog geneli bir varsayım

Ad alanlarına bakan 19 koşulun **11'i tam yol varsayıyor**:
T1059.003, T1018, T1016, T1082, T1047, T1218.010, T1218.011, T1204.002,
T1566.001, T1055, T1560.

G korpusunda varsayım büyük ölçüde tutuyor (`process.name` 45 tam yol /
4 taban ad). Bu kaynakta **tutmuyor**. Yani katalogun körlüğü kaynağa bağlı.

**Bu AYRI bir kalemdir ve bu görevde düzeltilmiyor.** Gerekçe commit
`a45c433`'ün dersi: iki değişikliği tek ölçüme sokmak, hangisinin ne
yaptığını ayırt edilemez yapar. Kalem K1 düzeltme kuyruğuna yazıldı.

---

## 9. NİHAİ KARAR (gerçek biçim görüldükten sonra)

### 9a. `Command` → `process.command_line` ALIAS — DEĞİŞMEDİ
Log `Command=` yazıyor, değer bütün olarak ayrıştırılıyor. §6a geçerli.

### 9b. `Parent Process Path` → YENİ KANONİK + TÜRETİM

§6b'de askıya alınan seçim artık bağlanabiliyor. **Alias seçeneği (a) elendi**,
iki ölçülmüş sebeple:

1. **Çakışma riski gerçek.** Kaynak çocuk için `Process Path` ve
   `Process Name`'i AYRI alanlar olarak yazıyor. Aynı kaynağın bir gün
   `Parent Process Name`'i de yazması beklenir; ikisi tek kanonik ada
   eşlenirse `parse_fields` sessizce İLKİNİ tutar (dedup yok, ilk kazanır).
   İki ayrı kaynak alanı tek kanonik ada eşlenmez.
2. **Şema zaten ayırıyor.** `process.name`/`process.path` çifti var;
   ebeveyn tarafını farklı kurmak şemada tek örnek bir istisna yaratırdı.

**Türetim neden gerekli:** ölçüm C, `parent.process.path`'in tek başına
**0 koşul** açtığını gösterdi. Türetim yazılmazsa değişiklik ölü doğar.
Türetim uydurma değil, yolun **taban adı** — kesin bir izdüşüm.

Türetim **veri ile** sürülür (`derive:` anahtarı), kod ile değil: tablo
büyüdüğünde kod değişmemeli (yöntem maddesi 6).

**Yön tek taraflıdır:** yol → ad. Ters yön (ad → yol) yasak, çünkü taban
addan dizin ÜRETİLEMEZ ve Görev 17 tam bu noktada "dizinsiz değer
doğrulanmış sayılmaz" kuralını koydu.

### 9c. KABUL ÖLÇÜTLERİ — §6'ya ek, kod yazılmadan önce

- Ö11 Gerçek powercfg kaydında `process.command_line` DOLU,
  `unknown.Command` YOK, `parent.process.path` DOLU,
  `unknown.Parent Process Path` YOK.
- Ö12 Aynı kayıtta `parent.process.name` = `powershell.exe` (türetim).
- Ö13 Kaynak HEM `Parent Process Name` HEM `Parent Process Path` yazarsa
  **açık değer kazanır**, türetim onu EZMEZ.
- Ö14 `parent.process.path` bilgi taşımıyorsa (`N/A`, `-`) türetim
  ÇALIŞMAZ — boşluğu boş değerle doldurmak boşluktan kötüdür.
- Ö15 126 kayıtta (G+S+H) ayrıştırma çıktısı Ö3 dışında değişmez.

**Ö5 BU GÖREVDE SAĞLANAMAZ** ve bu bilerek kayda geçiyor: §8b, çocuk
koşulunun ayrı kusuru yüzünden T1204.002'nin bu biçimde ateşlenemeyeceğini
gösteriyor. Ö5'i sağlamak için katalog değişikliği gerekir; o ayrı kalem.
Ölçüt gevşetilmiyor, **karşılanmadığı yazılıyor**.

---

## 10. SONUÇ — düzeltme uygulandı (2026-09-03)

`config/field_schema.yaml`: `Command` → `process.command_line` alias'ı,
yeni `parent.process.path` kanonik alanı, ve `parent.process.name` üzerinde
veri ile sürülen `derive: {from: parent.process.path, rule: basename}`.
Türetimin uygulaması `app/normalization/formats.py::_turetilmis_alanlari_doldur`.

| ölçüt | sonuç |
|---|---|
| Ö11 `Command`/`Parent Process Path` şemada, `unknown.*` yok | **geçti** |
| Ö12 `parent.process.name` = `powershell.exe` (türetim) | **geçti** |
| Ö13 açık değer türetimi ezmiyor | **geçti** |
| Ö14 `N/A`/`-`/`NULL SID`/boş yoldan türetim yok | **geçti** |
| Ö3 + Ö15 126 kayıtta düşen/oynayan alan yok | **geçti** (0/126, 0 ihlal) |
| **Ö5 T1204.002 gerçek biçimde ateşleniyor** | **KARŞILANMADI** |

Sözleşme `tests/test_turetilmis_alanlar.py` (10 test), yan etki ölçümü
`scripts/measure_task24_side_effect.py` (taban çizgisini `git show HEAD`'den
okur, gerilemede çıkış kodu 1). Tam takım **1322** geçiyor.

### 10a. Ö5 neden karşılanmadı — gevşetilmedi, yazıldı

Gerçek biçimde kurulan Office→kabuk zincirinde:

| T1204.002 koşulu | düzeltmeden önce | sonra |
|---|---|---|
| `parent.process.name ~ /(winword\|...)\.exe/` | False | **True** |
| `process.name ~ /\(cmd\|powershell\|...)\.exe/` | False | **False** |

Ebeveyn yarısı kazanıldı, çocuk yarısı §8c'deki katalog varsayımına takılıyor
(19 ad-koşulunun 11'i tam yol istiyor, bu kaynak taban ad yazıyor). Kural
ateşlenmiyor.

**Bu ölçümün başarısızlığı değil, kapsamının sınırı.** Ölçüt önceden
yazılmıştı ve karşılanmadığı için silinmedi; G kolunda 50/51'i "kazanılmamış"
ilan eden kural, sayı aleyhe düştüğünde de aynen uygulanıyor.

### 10b. Ölçüm A düzeltildi — İKİ kez yanlış namespace

A "11 hedef şemada eksik" dedi ve bu yanlıştı: `text_to_row`
(`graph.py:209`'un kullandığı yol) **iki namespace'i birden** yazıyor ve
bunu açıkça gerekçelendiriyor. Doğru karşılaştırma kümesi legacy izdüşümü +
kanonik adlar + `Message`. Düzeltilmiş A: **14 hedefin 14'ü bulunabilir.**

İlk yazım kanonik kümeyle karşılaştırıp `Message`i "eksik" ilan etmişti,
ikinci yazım yalnızca legacy'ye bakıp 11 hedefi. **Aynı ölçüm, iki farklı
yönde, iki kez yanlış** — ve ikisi de makul görünen bir sayı üretti.

### 10c. Açık kalan kalemler

1. **Katalog tam yol varsayımı** (§8c) — 11 koşul, 11 teknik. K1 düzeltme
   kuyruğuna. Kabul ölçütü şimdiden: düzeltme hem tam yol hem taban ad
   taşıyan kaynakta ateşlemeli, ve negatif yönü de sınanmalı.
2. **space_kv yutulması** (§3b) — `Command=` artık şemada olduğu için bu
   ad için kapandı, ama mekanizma duruyor: şemada olmayan HERHANGİ bir ad
   önceki alanın değerine yutulur ve yutulan `event.id` olabilir.
3. **`parse_fields(raw, schema)` imzası** (§5a) — şema parametresi
   tokenizasyona uygulanmıyor.
