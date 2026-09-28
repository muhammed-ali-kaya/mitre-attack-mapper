# Beklenti — 2B: kural koşullarını `Message`'dan yapısal alanlara taşı

**Kod yazılmadan önce yazıldı.** Ölçüm gelince "zaten böyle olmalıydı"
demeyi imkânsız kılmak için.

---

## Ölçülmüş başlangıç durumu

```
49 kuralin 44'u kosul tasiyor
57 kosulun 57'si  ->  field: Message      (istisna YOK)
semada 43 kanonik alan var, HICBIRI kullanilmiyor
```

Bu bir instance fix değil: `T1003.002`'yi düzeltmek 57'de 1'ini düzeltmektir.

### DÜZELTME: "57/57 Message" durumu OLDUĞUNDAN İYİ gösteriyordu

Taşımaya başlarken ölçüldü — kural motoruna giden satırdaki `CommandLine`
alanı **komşu alanların içeriğini taşıyordu**:

```
ayni girdi, uc farkli komut satiri:
  parse_fields / to_legacy_facts : 'certutil.exe -urlcache -split -f <url>'   DOGRU
  _extract_facts (KEY_VALUE_RE)  : 'certutil.exe'                             KIRPIK
  COMMAND_LINE_RE                : '... <url> SubjectUserName=jdoe'           TASAN
kural motoruna giden: TASAN olan
```

Sebebi `COMMAND_LINE_RE`'nin tırnaksız dalı: `[^\n]+`, yani satır sonuna
kadar yutuyor. Üstündeki yorum tam bu hatayı anlatıyor ama **yalnızca
tırnaklı dal** düzeltilmiş.

**Sonucu:** `CommandLine`'da desen aramak bugün kısmen `Message`'da aramakla
aynı şeydi. Yani "57 koşulun 57'si Message'a bakıyor" ifadesi bağımlılığı
**hafife alıyordu** — gerçek bağımlılık daha derin, çünkü `Message`'a
bakmayan bir koşul bile pratikte tüm loga bakabiliyordu.

**Taşımanın önkoşulu buydu ve yapıldı:** yetki sırası tersine çevrildi
(yetkili ayrıştırıcı → facts → regex, önceden regex ilkti), ve
`tests/test_extraction_paths.py` beş tüketici yolunun aynı değeri
gördüğünü sözleşme haline getirdi. Bu yapılmadan koşulları
`process.command_line`'a taşımak **sessizce başarısız** olurdu: satır
kanonik anahtar taşımıyor, `row.get()` `None` döner, eşleşme olmaz, ve
57 koşulun 39'u zaten ateşlenmediği için kimse fark etmez.

---

## 1. Kaçı gerçekten taşınabilir?

Kaba sınıflandırma (aşağıdaki uyarıyla):

| sınıf | sayı | ne demek |
|---|---|---|
| **T** taşınabilir | ~48 | kanonik alan var, desen o alanda çalışır |
| **KARMA** | ~2 | desen hem süreç **adı** hem komut **bayrağı** taşıyor → **iki koşula bölünmeli**, tek alana taşınamaz |
| **S** olay anlambilimi | ~4 | yapısal alan değil, olayın **anlamı**. `Message`'da kalmamalı ama alana da gitmemeli — Görev 3'ün `event_semantics` tablosuna ait |
| **KANITSIZ** | 3 | hedef alan şemada yok **ve o alanın gerçek yazımını gösteren tek bir log örneği de yok** — aşağı bak |

Hedef alan dağılımı:

```
process.name          20      file.path           4      script.block_text  1
process.command_line  17      logon.type          3      share.name         1
event_semantics        4      object.name         3      destination.port   1
SEMADA YOK: dns.question.name 1 · auth.package 1 · ticket.encryption 1
```

### UYARI — bu sayılar TASLAK, kesin değil

Sınıflandırma bir sezgisel betikle üretildi ve **bilinen yanlış atamaları var**:
`cipher\s+/w` `process.name` sayıldı (komut satırı deseni), `dir /s` de öyle.
İlk koşuda üç kural daha yanlış sınıflanmıştı — `-executionpolicy` ve
`bootstatuspolicy` içindeki `polic` dizisi "audit policy" anlatı kuralını
tetikliyordu; her satır basıldığı için görüldü.

**2B'nin İLK teslimi bu tablonun kendisidir:** `config/rule_field_map.yaml`,
57 satır, her biri `{teknik, desen, hedef_alan, sınıf, gerekçe}`. Satır satır
gözden geçirilmiş ve commit'lenmiş olacak; bir test her `hedef_alan`'ın
`field_schema.yaml`'da var olduğunu doğrulayacak. Sezgisel betiğin çıktısı o
tablonun **taslağıdır**, kendisi değil.

### KANITSIZ üçlü — şema BÜYÜTÜLMEYECEK

İlk yazımda "şemasız hedef 3 → 0, şema büyüyecek" denmişti. **Ölçüldü,
geri alındı.** Üç koşulun aradığı alanlar hiçbir test verisinde geçmiyor:

```
Query Name / QueryName              : HICBIR test verisinde yok
NtLmSsp / AuthenticationPackageName : HICBIR test verisinde yok
0x17 / rc4-hmac / TicketEncryption  : HICBIR test verisinde yok
Kerberos-NTLM olay ID'leri (4768/4769/4776) : yok
```

60 senaryodaki tek "DNS" geçişi Türkçe düzyazı (*"DNS sorgularını
kullandı"*), yapısal alan değil.

**Sonuç: bu üç koşul bugün ÖLÜ.** `T1071.004`, `T1550.002` ve `T1558.003`
kuralları hiçbir test verisinde ateşlenemiyor.

Kanonik alan adı uydurmak — `dns.question.name` mi `dns.query.name` mi,
`auth.package` mi `winlog.event_data.AuthenticationPackageName` mi — gerçek
bir log örneği görmeden **tahmin** olur. Oturumun kendi kuralı:
*"fixture yoksa format da yazılmasın; sınanmamış bir ayrıştırıcı, eksik
olandan kötüdür."* Aynısı alan tanımı için de geçerli.

**Yapılacak:** üçü `KANITSIZ` işaretiyle olduğu gibi bırakılır, tabloya
gerekçesi yazılır. Şema ancak gerçek bir log örneği geldiğinde büyür.
Taşımadıkları için ölçülebilir bir kayıp da yok — zaten ateşlenmiyorlar.

### `S` sınıfı en öğretici bulgu
`(?i)(disabled|turned off|stopped)` gibi koşullar bir **alanın değerini**
değil, **olayın ne olduğunu** arıyor. Bunlar `Message`'da kalmak zorunda
değil — yanlış katmanda duruyorlar. Doğru yer Görev 3'te yazılan
`config/event_semantics.yaml`. Yani "taşınamaz" değil, "başka yere taşınır".

---

## 2. Kabul kriteri — sayıyla

"`T1003.002` düzeldi" **kabul kriteri değildir**, instance fix'tir.

| ölçü | hedef |
|---|---|
| `field: Message` kalan koşul sayısı | 57 → **≤ 9** = `S` sınıfı ~6 (`event_semantics`'e taşınana kadar) + `KANITSIZ` 3 (log örneği gelene kadar) |
| `KANITSIZ` koşul | 3 → **3** (değişmez; şema tahminle büyütülmez) |
| kural motorunun yapısal alan okuyan kod yolu | **var** (şu an yok) |
| `rule_field_map.yaml` satır sayısı | **57** — eksik satır testle yakalanır |

Kod tablo büyüdüğünde **değişmemeli**: motor `{alan, desen}` çiftini okuyan
genel bir eşleştirici olacak, 57 dalı olan bir `if` zinciri değil.

---

## 3. Regresyon riski gerçek — ölçülmeden kapatılmaz

57 koşul şu an `Message`'a bakıyor ve 60 senaryoda **bir şekilde çalışıyor**.
Yapısal alana taşımak, `Message`'da eşleşen ama yapısal alanda eşleşmeyen
vakaları kırar. Örnek: `Message` tüm alanları düz metin olarak içerdiği için
`\\cmd\.exe` deseni `process.name` boşken bile `process.command_line`
üzerinden eşleşebiliyordu.

**Taşıma sonrası 60 senaryoda ölçülecek ve raporlanacak:**

1. kaç senaryoda kapı elemesi **arttı**
2. kaç senaryoda **azaldı**
3. elemelerin kaçı **doğruydu** (`gate_was_wrong` ölçüsü)
4. beklenen teknik kaç senaryoda top-20'den **düştü** (2A(b)'nin dersi:
   ortalama değil kapsama)

Ölçüm **`--repeat 3`** ile yapılacak. Tek koşu bu hatta ayırt edici değil,
ölçüldü.

### Düzeltilmesi gereken tablo
`wip/verification-graph` dalındaki 60 senaryoluk üç kollu ablasyon
(`evaluation/results/agent_loop_ablation_summary.json`) kapının **7 senaryoyu
değiştirdiğini, 4'ünü kötüleştirdiğini, 0'ını iyileştirdiğini** ölçmüştü.

**Taşıma bu tabloyu düzeltmeli.** Düzeltmiyorsa sorun koşulların nereye
baktığı değil, koşulların **kendisidir** — ve taşıma yetmiyor demektir. Bu
ayrımı taşımadan önce yazıyorum ki sonuç gelince gerekçe uydurulmasın.

---

## 4. Mesaj düzeltmesi AYRI commit

Kapının *"hangi koşul düştü"* mesajı taşımadan **bağımsız** bir iyileştirme.
Taşıma geri alınsa bile mesaj kalmalı. Ayrı ölçülür, ayrı commit'lenir.

Şu anki hâli (`verification.py:196`) beklenen olay ID'lerini **koşulsuz**
ekliyor:

> ⛔ T1003.002 elendi — "kanıt koşulları girdide sağlanmıyor
> (beklenen olay ID'leri: 1, 4656, 4663, 4688)"

Logda `EventID=4656` **var** ve listede de **var**. Olay ID'si eşleşti; eleyen
şey `field_condition`. Mesaj analisti yanlış yere baktırıyor.

Olması gereken: *"olay ID eşleşti (4656), field_condition eşleşmedi:
`<desen>`"* — hangi koşulun düştüğünü ayırt eden metin.

**Bu, denetim iziyle doğrulandı** (2026-08-17): eleyen `evidence-gate`,
`detection-evidence` çekimser kaldı. Mesaj yanlış katmanı suçladığı için ben
de Görev 8'in kapsamını yanlış ajana göre yazmıştım.

---

## 4.5. Satır hangi anahtarları taşıyacak — TAŞIMADAN ÖNCE karar

Seçenekler: yalnızca kanonik (`process.name`) mi, yoksa kanonik + legacy
(`NewProcessName`) birden mi? Cevap "legacy anahtarları başka kim bekliyor"
sorusuna bağlı ve **ölçüldü**:

```
app/agents/verification.py      EventID                                    (kanit kapisi)
app/mapping/rule_engine.py      EventID, Message                           (motorun kendisi)
app/correlation/ioc_extraction  CommandLine, FilePath, NewProcessName, SubjectUserName
app/correlation/incident.py     SubjectUserName
app/reporting/qradar_rule.py    EventID, NewProcessName
app/batch/qradar_adapter.py     EventID, Message                           (kendi satirini uretir)
```

### KARAR: İKİSİ BİRDEN — ama legacy TÜRETİLMİŞ GÖRÜNÜM olarak

Yalnızca kanoniğe geçmek, kural taşımasıyla **aynı commit'te** altı modüle
dokunmayı gerektirirdi. İki sakıncası var: şartnamenin "her görev ayrı
commit" maddesini ihlal eder, ve regresyon ölçümünü yorumlanamaz kılar —
bir gerileme çıktığında taşımadan mı yoksa altı modülden mi geldiği
ayrılamaz.

**İki gerçeklik riski geri gelmesin diye üç şart:**

1. **Legacy anahtarlar bağımsız çıkarım DEĞİL, kanoniğin izdüşümü olacak.**
   Bu `483b9a1`'de zaten sağlandı: `facts` artık `structured_facts`'ten
   geliyor, eski çıkarım yalnızca boşluk dolduruyor.
2. **Yetki kodda açıkça yazılacak** — hangi anahtarın yetkili olduğu
   yorumdan okunabilmeli, çıkarım gerektirmemeli.
3. **Sözleşme testi ikisini birlikte kontrol edecek**: aynı satırda
   `row["process.name"] == row["NewProcessName"]`. Ayrışırlarsa test kırılır.

**Legacy anahtarların kaldırılması ayrı bir görevdir** (Görev 12'nin
yanına). Bugün kaldırılmıyor çünkü altı tüketicinin her biri ayrı bir
regresyon riski ve hiçbiri 2B'nin konusu değil.

## 5. Çakışma kararı — TAŞIMADAN ÖNCE veriliyor

"Taşımada gözden geçirilir" yeterli değil: sonra verilen karar, sonuca göre
gerekçe uydurmak olur. Ölçüldü — 60 senaryoda **aynı satırda birlikte
ateşleyen 4 çift** var ve üç ayrı kategoriye düşüyorlar:

```
T1053.005 + T1059.001   multi-010   beklenen ['T1059.001','T1053.005']  IKISI DE dogru
T1047     + T1082       rawlog-001  beklenen ['T1047']                  BIRI dogru
T1105     + T1140       rawlog-005  beklenen ['T1105']                  BIRI dogru
T1070.001 + T1562.002   rawlog-009  beklenen ['T1685.005']              HICBIRI dogru degil
```

### KARAR: kurallar BİRLEŞTİRİLMEZ. Çakışma AYIRT EDİCİLİKLE çözülür.

Gerekçe, üç kategorinin her birinden:

**1. Birleştirme yanlış olurdu.** `multi-010`'da iki teknik de **beklenen**:
PowerShell çalıştıran zamanlanmış görev gerçekten hem T1053.005 hem
T1059.001'dir. ATT&CK bunları ayrı modelliyor. Birleştirmek doğru cevabı
yok ederdi.

**2. Kalan ikisi politika sorunu değil, KOŞUL KUSURU.** İkisi de "iki kural
aynı anda haklı" vakası değil:

- `T1082` yalnızca süreç ADI listesine bakıyor (`wmic.exe` orada) ve **hiç
  komut satırı koşulu yok**. Yani `wmic` ne yaparsa yapsın ateşliyor.
  Eksik olan şey ayırt edici koşul.
- `T1140` deseni `certutil.*(-decode|-urlcache)` diyor — ama `-urlcache`
  **indirme**dir (T1105), `-decode` ise çözme (T1140). Desen yanlış bayrağı
  kendi tekniğine sayıyor.

**3. Dördüncüsü `S` sınıfının işi.** `T1070.001` ("günlük temizlendi") ve
`T1562.002` ("günlük kaydı kapatıldı") aynı 1102 olayında buluşuyor. İkisini
ayıran şey bir alan değeri değil, olayın **anlamı** — yani her ikisinin de
`event_semantics`'e taşınması gereken kolları.

### Kabul kriteri — çakışma için, ölçülebilir

| ölçü | hedef |
|---|---|
| **yalnızca biri beklenen** olan birlikte-ateşleme çifti | 2 → **0** |
| **ikisi de beklenen** olan çift | 1 → **1** (korunmalı, kaybedilirse gerileme) |
| hiçbiri beklenen olmayan çift | 1 → ayrı incelenir (`rawlog-009` beklenen `T1685.005`; senaryonun kendi etiketi de sorgulanmalı) |

**İlke tek cümlede:** aynı log iki teknik üretiyorsa cevap kuralları
birleştirmek değil, hangi kanıtın hangi tekniğe ait olduğunu **koşulda**
söylemektir. Birleştirme, isabet ölçümünü düzeltmez — ölçülecek şeyi yok eder.

---

## 6. Görev 13'e giden kısıt — held-out setin tasarımını belirliyor

Katalog **48 farklı olay ID** bekliyor. 60 senaryoluk set bunların
**6'sını = %12'sini** temsil ediyor.

```
katalogun bekledigi : 1, 3, 7, 8, 10, 11, 12, 13, 22, 104, 400, 1102, 4104,
                      4624, 4625, 4656, 4657, 4663, 4688, 4697, 4698, 4699,
                      4700, 4702, 4719, 4720, 4728, 4732, 4738, 4756, 4769,
                      4778, 4946-4954, 5001, 5010, 5012, 5025, 5101, 5140,
                      5145, 5156, 7040, 7045                        (48 adet)
veride var          : 3, 11, 1102, 4688, 4720, 4732                  (6 adet)
```

**Görev 13 kabul kriteri (şimdi yazılıyor):** held-out set, 49 kuralın
gerektirdiği 48 olay ID'sinin **en az yarısını (≥24)** temsil etmeli ve
**yapısal log ağırlıklı** olmalı — şu anki setin %75'i düzyazı.

Gerekçe: taşınan 44 koşulun 39'u hiç ateşlenmiyorsa, taşımanın **doğru olup
olmadığı test edilemez**. Bir koşulu `Message`'dan `process.name`'e taşıyıp
"testler geçiyor" demek, o koşulu hiç çalıştırmamış olmak anlamına gelir.

**Bu, 2B'nin sonuç raporuna da yazılacak:** 2B'nin regresyon ölçümü
**yapısal olarak kısıtlı** olacak. 60 senaryoda ölçülebilecek şey 57
koşulun 18'i; kalan 39 için taşımanın doğruluğu **iddia edilemez**, yalnızca
tablo gözden geçirmesine dayanır. Bu bir kusur değil, ölçümün sınırı — ve
raporda böyle duracak.

---

---

# SONUÇ RAPORU (2026-08-18)

## Kabul kriteri: `known_regression` KAPANDI

Bu, taşımanın **tek somut kabul kriteriydi**. İki yarısı da ölçüldü:

| yarım | kriter | durum |
|---|---|---|
| 2A | T1'de `T1003.002` `in_retrieval` TRUE | **sağlandı** (probe izi) |
| 2B | koşul `object.name`'e baksın **VE** çekirdek ad-uzayı gösterimini tanısın | **sağlandı** |

Kanıt, iddia değil ölçüm: **kanıt kapısı T1'de `T1003.002` için
`REJECT` → `CONFIRM`.**

İkinci yarım iki adımdı ve **birincisi tek başına yetmedi**: koşulu
`object.name`'e taşımak, `\REGISTRY\MACHINE\SAM` ile `HKLM\SAM`'ı hâlâ
eşleştirmiyordu. `rule_engine` artık değeri registry lehçesine normalize
edip **her iki biçimi de** deniyor. Kurala özel değil: alan **adına** değil
değerin **biçimine** bakıyor, tablo `config/path_normalization.yaml`'da veri.

## Taşımanın ölçülebilir faydası — dürüst cevap

**60 senaryoda kazanç GÖSTERİLEMEDİ, kayıp GÖSTERİLDİ.**

```
DOGRU atesleme  11 -> 10      (multi-010 kayboldu)
YANLIS atesleme  4 ->  4      (hic azalmadi)
```

Bunu yumuşatmıyorum: taşıma bu sette bir doğru eşleşme kaybetti ve tek bir
yanlış eşleşmeyi bile elemedi.

**Kazanç ölçülebilir ama başka yerde:** probe fixture'ı T1'de kapı
`REJECT` → `CONFIRM`. 60 senaryonun **hiçbiri registry yolu taşımıyor**, o
yüzden normalizasyonun kazancı orada görünemezdi.

Yani her iki taraf da **tek vaka**: kazanç T1'de, kayıp `multi-010`'da.
Bu sette daha fazlası gösterilemez çünkü **57 koşulun 39'u hiç ateşlenmiyor**.
"Testler geçiyor" o 39 için hiçbir şey ifade etmiyor — bu, ölçümden önce
yazılmıştı ve aynen geçerli.

## Boru hattı ölçümü — `--repeat 3`, dört probe

Tek koşu bu hatta ayırt edici değil (ölçüldü), o yüzden üç tur.

### T1 — bayrak vaka ÇÖZÜLDÜ

```
2B ONCESI   T1003.002  in_retrieval TRUE · in_llm_selection TRUE · in_final FALSE
            ajanlar: 6 karar, elenen ['T1003.002']
2B SONRASI  T1003.002  in_retrieval TRUE · in_llm_selection TRUE · in_final TRUE
            ajanlar: 6 karar, elenen []
```

Teknik **3/3 koşuda** final listede. Karar `insufficient_evidence` →
`malicious_or_suspicious` (beklenen `SUFFICIENT_SUSPICIOUS`) — **2/3 koşuda**.

### Üç durumlu yay — kaydın öngördüğü şey aynen çıktı

| durum | T1003.002 | sebep |
|---|---|---|
| taban (Görev 1 öncesi) | **VAR** | `event_id` None'dı, kapı "sınanamadı → çekimser" diyordu. **Doğru cevap, yanlış sebep.** |
| Görev 1 sonrası | **YOK** | kapı artık değerlendirebiliyordu ve desen yanlıştı. Yanlış cevap, doğru mekanizma. |
| 2B sonrası | **VAR** | koşul `object.name`'e bakıyor + lehçe normalizasyonu. **Doğru cevap, doğru sebep.** |

### Dört ölçü

| ölçü | sonuç |
|---|---|
| kapı hasarı (yanlış eleme) | **0** — dört probe, üç koşu, hepsinde |
| kapı hasarı T3'te | **2 → 0** (tabana göre) |
| beklenen teknik final'de | T1 **yok → var**; T3 hâlâ yok |
| yanlış eleme eklendi mi | **hayır** |

T3'te elenen `T1547.001` beklenen değil, yani eleme **doğru**.

### Varyans — `--repeat 3` kararının karşılığı

```
T0: teknik listesi 2 varyant
T1: KARAR 2 varyant (insufficient / malicious), dongu turu [0, 1]
T2: SABIT
T3: SABIT
```

T1'in başarısı **kararda 2/3**, teknikte 3/3. Tek koşuluk bir ölçüm bunu ya
"çözüldü" ya "çözülmedi" diye raporlardı; ikisi de eksik olurdu.

### Yeni kapı mesajı üretimde görünüyor

T3'te: *"olay ID eşleşti (4657), koşul düştü: `object.name` deseni
`/(\\CurrentVersion\\Run|...)/` ile eşleşmedi"* — hangi katmanın düştüğü artık
çıktının kendisinde.

### 2B'nin dürüst sonucu — tekrar

- **60 senaryoda kazanç gösterilemedi, kayıp gösterildi** (doğru 11 → 10)
- **Probe'da kazanç gösterildi**: T1'de beklenen teknik geri geldi, kapı
  hasarı 0
- **57 koşulun 39'u hâlâ hiç ateşlenmiyor**; onlar için "testler geçiyor"
  hiçbir şey ifade etmiyor
- T3 çözülmedi ve 2B'nin işi değil — retrieval T1685'i bulamıyor (2A)

## Kalan kayıp — kabul edilmedi, sabitlendi

`multi-010` / `T1053.005`. Kök neden: `text_to_row` çok olaylı girdiyi tek
satıra indiriyor. Taşımanın hatası değil, **görünür kıldığı şey** — önceden
`Message` üzerinden ikinci olaydan eşleşiyordu, yani bir olayın kimliğiyle
başka bir olayın kanıtını birleştiriyordu. Kapanış kriteriyle
`test_a_multi_event_input_collapses_into_a_single_row`'da kayıtlı.

## Ortaya çıkan yapısal soru → **K2**

Alan seçimi tekniğe değil **olaya** bağlı. Ayrıntı HANDOFF'ta K2 maddesinde.

---

## Açık soru — cevabı taşıma sırasında çıkabilir

**Kapı hangi koşulda hiç karar üretmiyor?**

Eski probe koşusunda (`2c09424`) LLM aynı üç tekniği seçmiş, ama yalnızca
**4** karar üretilmiş ve `T1003.002` **elenmemiş**. Bugün aynı üç seçimde
**7** karar var ve eleme var. `verification.py` iki commit arasında **hiç
değişmemiş**. 3 bulgu için kapı + genel ajan çalışsaydı 6 karar ederdi; 4
çıkması kapının o koşuda **karar üretmediğini** gösteriyor.

Bu gürültü değil — aynı koşullarda tekrar 7/7/7 kararlı. Açıklanmamış yapısal
bir fark ve 2B kapıya dokunacağı için burada duruyor.
