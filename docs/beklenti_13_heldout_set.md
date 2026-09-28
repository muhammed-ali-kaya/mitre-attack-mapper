# Beklenti — Görev 13: held-out ölçüm seti

**Kod yazılmadan ÖNCE yazıldı** (2026-08-30). Bu projede en sık ihlal edilen
yöntem kuralı budur; §1'deki bütün sayılar belge yazılmadan önce ölçüldü ve
tekrarlanabilir bir betiğe bağlandı: `scripts/measure_heldout_baseline.py`.

Görev 13 bir **iyileştirme değil, ön koşul**. Gerekçesi HANDOFF'ta dört ayrı
yerde ölçülmüş çapraz bulgudur: mevcut 60 senaryoluk set karar ve kural
katmanlarını **ölçemiyor**, çünkü o katmanlar artefakt okuyor ve senaryoların
45/60'ı düzyazı. Set RAG hattını ölçmek için kurulmuş ve onu iyi ölçüyor —
sorun setin kötü olması değil, **başka bir şeyi ölçüyor olması**.

---

## 1. Ölçülen girdiler — bugün neredeyiz

Ölçüm: `.venv/Scripts/python.exe scripts/measure_heldout_baseline.py`
(LLM ve indeks gerekmez, hepsi deterministik ayrıştırma katmanlarında).

**A) Katalog ne bekliyor** (`rules/attack_mappings.yaml`)

| | |
|---|---|
| kural sayısı | 49 |
| **required event ID** | **48** |
| forbidden event ID | 2 (5156, 5158) |
| field_condition | 57 |

**B) Bugünkü iki set ne veriyor**

| | 60 senaryo | QRadar 51 satır |
|---|---|---|
| olay ID çıkarılamayan kayıt | **45/60** | 0/51 |
| eşsiz event ID | 6 | 7 |
| katalogla ortak ID | **6/48 (%12)** | **2/48 (%4)** |
| registry yolu | **0** | 5 |
| registry seviyeleri | yok | yalnız `high` |
| registry aileleri | yok | yalnız `service` |
| (aile, aktör) çiftleri | yok | `service\|LOCAL SERVICE` ×4, `service\|WINHOST-01$` ×1 |
| bölünen kayıt | 0 | 0 |

**Sonuç: iki set de üç kriterin hiçbirini karşılamıyor.** QRadar örneği
gerçek veri olduğu için cazip görünüyor ama ID çeşitliliği 7 ve registry
yollarının beşi de aynı aile (`service`), tek bir aktör kümesiyle. Aktörün
**beklenen** ve **beklenmeyen** varlık ailesine yazdığı çift yok — yani
EK-2 tek yönlü bile temsil edilmiyor.

> Ölçüm hijyeni notu: bu tablonun QRadar sütunu ilk denemede "0 olay ID,
> 0 registry yolu" çıktı. Sebep sette değil **ölçümdeydi** — adaptörün
> `Message` kolonu okunuyordu, oysa EventID ve FilePath ayrı kolonlar.
> Düzeltme: üretimin kullandığı `row_to_kv_string` serileştirmesi ve
> `decision.py`'nin alan sırası (`object.name → registry.path → file.path`)
> aynen kullanılıyor. İkinci bir okuma yolu yazmak ikinci bir gerçeklik
> demekti.

---

## 2. Set NEREDEN gelecek?

### Karar: iki ölçülen kol + bir ayrılmış kol

Gerçek veriden genişletmek tek başına **mümkün değil**: elimizdeki tek gerçek
örnek 51 satırlık QRadar dosyası ve §1'de ölçüldüğü gibi kriterlerin
hiçbirine yaklaşmıyor (2/48 ID, tek registry ailesi, aktör çifti yok). Yeni
gerçek veri yok. Dolayısıyla set **elle kurulacak** — ama gerçek veri
tamamen dışarıda bırakılmayacak, çünkü elle kurulan bir setin en büyük riski
"sistemin anladığı biçimde" yazılmasıdır.

| Kol | Ne | Kaç | Ölçülür mü |
|---|---|---|---|
| **G — Gerçek** | 51 QRadar satırı, elle etiketlenmiş | 51 | evet, **ayrı raporlanır** |
| **S — Sentetik** | kriterleri karşılamak için kurulan yapısal loglar | ~60 | evet |
| **H — Held-out** | §3'e göre ayrılan, hiç ölçülmeyen loglar | 15 | **hayır** |

G kolu ayrı raporlanır, S ile toplanmaz: biri gerçek dağılım, diğeri
tasarlanmış dağılım. Toplanırsa "sistem gerçek veride ne yapıyor" sorusu
sentetik çoğunlukta kaybolur.

### Disiplin kuralı — beklenen cevaplar hat çalıştırılmadan yazılır

Kullanıcının koyduğu kural aynen geçerlidir ve üç kolun **hepsi** için:

1. Her log için beklenen cevap **ATT&CK korpusundan ve gerçek log
   biçimlerinden** yazılır. Kaynak alanı zorunlu: hangi teknik sayfası,
   hangi olay ID tanımı.
2. Beklenen cevaplar **commit'lenir**.
3. **Sonra** hat koşulur.

Sıra tersine dönerse ölçüm "sistem ne yapıyor"u değil "sistemin yaptığını
beklenti diye yazdık"ı ölçer. Bu projede tam bu desen dört kez yakalandı
(DISCRIMINATING_FIELDS, D kolu, zenginleştirme önerisi, kritiklik tablosu),
o yüzden kural gevşetilmiyor.

**Sentetik log yazma sınırı:** bir log "sistemin anlayacağı" biçimde değil,
**Windows'un ürettiği** biçimde yazılır. Alan adları, alan sırası ve
mesaj gövdesi gerçek 4656/4688/4657 kayıtlarından alınır. Bir alanı
sistemin kolay okuması için eklemek veya kolay okunmayacak bir alanı
çıkarmak, seti sisteme göre ayarlamaktır.

---

## 2.1 Kolların YAZILMA SIRASI — karara bağlandı (2026-08-30)

**Sıra: G etiketle → H yaz → G koş → S yaz.**

| Adım | Neden bu sırada |
|---|---|
| 1. G etiketle | Gerçek veri, biz üretmedik, ezber riski yok. Sistemin ne dediğine bakılmadan etiketlenir. |
| 2. **H yaz** | H, **hiçbir ölçüm sonucu görülmeden** yazılır. Kullanıcının kuralı "H, S'den önce" idi; bir adım daha sıkısı seçildi: H, G'nin sonucundan da önce. Böylece H ne S'nin gölgesi ne G'nin boşluklarının aynası olur. Yazıldıktan sonra dosya bir daha açılmaz. |
| 3. G koş | Etiketler commit'lendikten **sonra**. |
| 4. S yaz | G'nin ölçümünden sonra — **bilerek**. |

**S için seçilen şık ve gerekçesi:** kullanıcının sunduğu iki seçenekten
*"G'nin ölçümünden sonra yaz"* alındı. Sebep: S'nin bileşimini zaten §6'daki
**donmuş** kriterler belirliyor (≥24 olay ID, üç registry ailesi, iki yönlü
aktör çifti) ve o kriterler herhangi bir ölçüm yapılmadan önce yazıldı. G'nin
sonucu S'nin **log biçimi gerçekçiliğini** bilgilendirebilir; S'nin **teknik
ve olay ID bileşimini değiştiremez**. Bu ayrım bir kaçış kapısına dönüşmesin
diye kural şudur:

> G'nin sonucu S'ye ancak §6'daki kriterler DEĞİŞMEDEN girebilir. G'de
> ortaya çıkan bir zayıflığı kapatmak için S'ye teknik/olay ID eklenmesi
> **aşırı uyumdur** ve yapılmayacaktır. Böyle bir ihtiyaç doğarsa S'ye değil,
> ayrı bir kola yazılır ve ayrı raporlanır.

---

## 2.2 G kolu etiketlendi — sonuç ve sınırı

`evaluation/g_arm_qradar_labels.json` (üretici: `scripts/build_g_arm_labels.py`).
Hat çalıştırılmadan, ATT&CK v19.1 bundle'ına karşı doğrulanarak yazıldı.

| | |
|---|---|
| kayıt | 51 |
| beklenen karar | 50 × `INSUFFICIENT_DATA`, 1 × `SUFFICIENT_SUSPICIOUS` |
| negatif örnek | 49/51 |
| inceleme bayrağı | G-045 (gizli PowerShell), G-048 (`users\public\tdrfagent.exe`) |
| teknik bekleyen satır | **yalnız G-045** → `T1059.001`, `T1564.003` |

### ATT&CK doğrulaması iki etiketi değiştirdi

Ezberden yazılsa iki hata birden yapılacaktı:

1. **`T1562.001` v19.1'de REVOKED** (yerine `T1685`). Geçersiz bir ID
   kaydedilecekti.
2. **"execution policy" ifadesi 858 tekniğin hiçbirinin açıklama veya
   detection metninde geçmiyor.** Yani `-ExecutionPolicy Bypass` bir ATT&CK
   tekniğine bağlanamaz; şüphe uyandıran bir **göstergedir**, eşleştirme
   değil. Gösterge olarak kaydedildi.

Buna karşılık `-WindowStyle Hidden`, `T1564.003`'ün kendi metninde birebir
örnek olarak geçtiği için eşleştirme olarak yazıldı.

### G'nin yapısal sınırı — şimdiden yazılıyor

**G, yanlış alarm oranını iyi ölçer; tespit gücünü neredeyse hiç ölçmez.**
51 satırın yalnızca 1'i teknik bekliyor. Yani G'den çıkacak "recall" sayısı
tek satıra dayanır ve anlamsızdır. G'nin raporunda recall **yazılmayacak**;
G şu üç şeyi ölçer:

- yanlış alarm oranı (49 negatif örnek)
- yanlış pozitif teknik sayısı
- G-045'in bulunup bulunmadığı (tek pozitif, ayrı satır olarak)

Tespit gücü S kolunun işidir. Bu, S'nin neden gerekli olduğunun ölçülmüş
gerekçesidir — G'nin sonucuna bakılmadan yazıldı.

### Koşmadan önce yazılan tahmin

Beş `4656` satırı (G-007, G-015, G-029, G-030, G-040)
`HKLM\SYSTEM\ControlSet001\Services\<servis>\Performance` anahtarına
**0x2001F** erişim maskesiyle handle istiyor — maske `Set key value` ve
`Create sub-key` içeriyor, yani **yazma hakkı**. Kritiklik katmanı bu yolları
`high`/`service` sınıflıyor ve aktörler (svchost.exe/LOCAL SERVICE,
MpDefenderCoreService.exe/WINHOST-01$) `config/actor_baseline.yaml`'da
**yok**.

**Tahmin: Yol B bu beş satırda yanlış alarm üretecek.** Doğru cevap
`INSUFFICIENT_DATA`'dır: handle *istemek* değişiklik değildir; gerçek yazma
4657 ile kaydedilirdi ve o olay bu veride yok.

Tahmin tutarsa bu bir kusur değil, `actor_baseline.yaml`'ın kendi yazdığı
takasın ölçülmesidir ("eksik tablo yalnızca fazladan alarm üretir, fazla
tablo KÖR NOKTA üretir"). Tahmin tutmazsa Yol B'nin erişim sınıfı çıkarımı
beklediğimden dar demektir. **İki sonuç da bilgi taşır; tahmin bu yüzden
koşmadan önce yazıldı.**

---

## 3. Held-out gerçekten held-out mu?

**Risk kabul ediliyor:** seti kuran taraf ölçen tarafla aynıysa, farkında
olmadan sisteme göre ayar yapılır. Bu oturumun kendisi örnek verdi: E2E-1
kriteri yanlış anahtar okuduğu için **totoloji olarak** geçiyordu
(`len(events) == len(events)`) ve ancak anahtar düzeltilince bir şey
söylemeye başladı. Kriterin "geçmesi" tek başına delil değildir.

### Ayırma protokolü

- **H kolu ayrı dosyada durur:** `evaluation/heldout_set.json`. S ve G
  kollarının dosyalarından fiziksel olarak ayrı.
- **H kolu bu oturumda ve sonraki oturumlarda HİÇ koşulmaz.** Hat üzerinde
  çalıştırılmaz, çıktısına bakılmaz, hiçbir metriğe katılmaz, hiçbir eşik
  H'ye bakılarak ayarlanmaz.
- **En az 15 log** (kullanıcının alt sınırı 10–15; üst sınır seçildi çünkü
  15 log üç kriterin üçünü birden temsil edecek kadar yer bırakıyor).
- H kolu S ile **aynı disiplinle** yazılır (§2) ama S'nin dağılımının
  kopyası olmaz: aynı teknikleri farklı olay ID'leri ve farklı aktörlerle
  taşır. Aksi hâlde H, S'nin ezberini ölçer.
- **Kullanıcı ayrı çalıştırır.** H kolunun sonucu bu belgeye yazılmaz.

### H koşulduğunda ne beklenmeli

S kolundaki metrikler H'de **düşerse** bu bir kusur değil, ayarın
yakalanmasıdır — ve tam olarak Görev 13'ün var olma sebebidir. Bu cümle
şimdiden yazılıyor ki sonuç geldiğinde yeniden yorumlanmasın.

---

## 4. Metrikler — iki eksen, asla tek "doğruluk" sayısı

Gerekçe ölçülmüş: T2 senaryosunda sistem **doğru karar sınıfını doğru
gerekçeyle** verdi ama LLM iki **yanlış teknik** seçti. Tek bir doğruluk
sayısı bu iki katmanı birbirine karıştırır ve hangisinin düzeltileceğini
kaybettirir.

### Eksen 1 — Karar sınıfı isabeti

Üç sınıf: `INSUFFICIENT_DATA` / `SUFFICIENT_BENIGN` / `SUFFICIENT_SUSPICIOUS`.

| Metrik | Tanım | Kaynak anahtar |
|---|---|---|
| sınıf isabeti | beklenen sınıf == çıkan sınıf | `decision.decision` |
| **yanlış alarm oranı** | negatif örnekte SUSPICIOUS çıkma oranı | `decision.decision` + `negative_case` |
| kaçırma oranı | pozitif örnekte INSUFFICIENT/BENIGN çıkma oranı | aynı |
| yol dağılımı | kararı Yol A mı Yol B mi taşıdı | `decision.paths` |
| bastırma sayısı | kaç olayda baseline bastırması ateşlendi | `decision.event_kararlari[].suppression` |

Yol dağılımı ayrı raporlanır çünkü **doğru sınıf yanlış yoldan gelebilir**:
bu oturumun uçtan uca koşusunda V-BASTIRMA doğru sınıfı aldı ama
`paths={'A': False, 'B': True}` — yani doğrulanmış kanıt sayısı 0'dı ve
kararı kritiklik yolu taşıdı.

### Eksen 2 — Teknik isabeti

| Metrik | Tanım | Kaynak anahtar |
|---|---|---|
| top-1 | beklenen teknik listedeki ilk teknik mi | `mappings[0].attack_id` |
| top-3 | beklenen teknik ilk üçte mi | `mappings[:3]` |
| precision / recall | beklenen küme ile çıkan küme | `mappings` |
| yanlış pozitif teknik | beklenmeyen ama çıkan teknikler | `mappings` |

### Eksen 3 — Doğru teknik HANGİ KATMANDA kayboldu

Beklenen teknik çıktıda yoksa, kaybın katmanı tespit edilir. Hattın çıktısı
bunu zaten taşıyor — yeni bir enstrümantasyon gerekmiyor:

| Katman | Soru | Kaynak anahtar |
|---|---|---|
| retrieval | aday havuzuna girdi mi | `retrieval_candidates` (ilk tur havuzu dahil) |
| reranking | sıralamada elendi mi | `retrieved_chunk_ids` |
| LLM seçimi | model seçti mi | `mappings_before_agents` |
| kanıt kapısı | kanıtsız diye elendi mi | `rejected_mappings` |
| ajan katmanı | ajan eledi/düşürdü mü | `agent_rejected_mappings`, `agent_decisions` |
| döngü | ikinci tur geri getirdi mi | `mappings_after_first_pass`, `loop_passes` |

Bu dağılım **sayı olarak** raporlanır (ör. "beklenen 40 teknikten 9'u
retrieval'a hiç girmedi, 6'sı LLM tarafından seçilmedi, 3'ü kanıt kapısında
elendi"). "Doğruluk %62" cümlesi bu üç sayının hepsini yok eder.

### Raporlama biçimi

Üç eksen **ayrı tablolar** hâlinde, G ve S kolları **ayrı satırlar**
hâlinde. Tek bir birleşik skor üretilmez — ne kollar arasında, ne eksenler
arasında.

---

## 5. Süre bütçesi — ölçüldü, kısıt gerçek

Bu oturumda gerçek hat üzerinde ölçüldü
(`evaluation/results/task14_end_to_end.json`):

| Koşu | Süre | Olay | Olay başına |
|---|---|---|---|
| V-BASTIRMA (soğuk model) | 321 s | 2 | 161 s |
| V-CAPRAZ (sıcak) | 160 s | 2 | 80 s |
| TEKIL single-001 (sıcak) | 118 s | 1 | 118 s |

Sıcak kolda **olay başına ~80–120 sn**. Buradan:

- S kolu (~60 log, tek koşu): **~100 dakika**
- G kolu (51 satır, tek koşu): **~85 dakika**
- `--repeat 3` ile ikisi birden: **~9 saat**

**Bağlayıcı kurallar:**

1. **Önce tek koşu.** `--repeat` yalnızca varyansın karar değiştirdiği
   gösterilen alt küme için. Görev 5'in kapanış ölçümü varyansın karara
   ulaşmadığını gösterdi (T0–T3, iki kol, 3'er koşu); aksi ölçülene kadar
   tam set tekrarı bütçe israfıdır.
2. **Ölçüm betiğinde ilerleme çıktısı zorunlu** — her log bittiğinde
   sıra numarası, süre ve tahmini kalan süre, `flush=True` ile.
3. **ARKA PLANDA KOŞTURULMAZ.** Sıcak kol daha önce iki kez arka planda
   sebebi bulunamadan öldü. Ön planda, log log koşturulur.
4. Ölçüm betiği **çıktısını borulanmadan** yazar. Bu oturumda uçtan uca
   koşu `| tail -60` ile çağrıldı ve bütün ilerleme çıktısı tamponlandı —
   ilerleme görünürlüğü betiğin değil çağrının kusuruyla kayboldu.
5. Ara sonuçlar **koşu ilerledikçe** diske yazılır; 100 dakikalık bir koşu
   sonunda tek seferde yazarsa yarıda kesilme her şeyi götürür.

---

## 6. Kabul kriterleri — set için

Aday set `scripts/measure_heldout_baseline.py --set <yol>` ile sınanır.

| Kriter | Eşik | Kaynağı |
|---|---|---|
| **KRİTER** olay ID temsili | katalogun 48 required ID'sinin **≥24'ü** | 2B ölçümü |
| **EK-1** registry yolu | `critical`, `high`, `noise` seviyelerinden **birer** aile | Görev 4 ölçümü |
| **EK-2** baseline çifti | aynı aktörün **beklenen** ve **beklenmeyen** varlık ailesine yazdığı en az birer log | Görev 5 §5 ölçümü |
| yapısal ağırlık | kayıtların **≥%70'i** olay ID taşır (bugün: 60 senaryoda %25) | 2B ölçümü |
| negatif örnek | S kolunun **≥%20'si** negatif örnek | yanlış alarm oranı ölçülemez olmasın diye |

EK-2 neden **iki yönlü**: yalnızca beklenen çift konursa bastırmanın fazla
geniş olduğu (kör nokta) görülmez; yalnızca beklenmeyen çift konursa yanlış
alarm oranı ölçülmez.

---

## 7. Bu beklentinin ÖLÇMEDİĞİ şey

- **H kolunun sonucu.** Tanım gereği (§3). Bu belgeye yazılmayacak.
- **Genelleme.** S kolu tasarlanmış bir dağılımdır; "sistem sahada şu kadar
  doğru" cümlesi bu setten çıkarılamaz. Çıkarılabilecek cümle şudur:
  *"bu 60 logda şu katman beklendiği gibi davranıyor."* Bu kısıt Görev 5
  §7'den devralındı ve gevşetilmiyor.
- **Çok olaylı girdinin gerçek veri üzerindeki bölme doğruluğu.** Görev 14
  E5'te açık bırakılmıştı; uçtan uca koşu bölmenin fixture'larda çalıştığını
  gösterdi (2/2 doğru bölme, atıf doğru event'e) ama 51 QRadar satırının her
  birinin gerçekten tek olay olduğu bağımsız olarak doğrulanmadı. G kolunun
  elle etiketlenmesi bu doğrulamayı **üretecek** — etiketleyen kişi her
  satıra tek tek bakacağı için.
- **Süre ölçümünün kararlılığı.** §5'teki sayılar üç koşudan; soğuk/sıcak
  farkı ayrıldı ama sıcak kolun kendi varyansı ölçülmedi.
