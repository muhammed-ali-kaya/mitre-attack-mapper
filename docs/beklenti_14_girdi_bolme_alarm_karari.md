# Beklenti — Görev 14: girdi bölme + alarm seviyesi karar

**Kod yazılmadan önce yazıldı.**

Tetikleyen: QRadar triage senaryosu (bir alarmın altındaki event'leri toplu
vermek) ve o senaryoyu ölçerken çıkan **güvenlik açığı**
(`tests/fixtures/merge_vulnerability_logs.json`).

Sıra bağlandı: **girdi bölme + alarm kararı → sonra Görev 13 (held-out
set).** Bugünkü hâliyle gerçek alarm verisi sisteme verilirse sonuçlar
veriyi değil bu kusuru ölçer.

---

## 0. Ölçülen durum — kusur ne kadar geniş

Sorun sandığımdan geniş: yalnızca bastırma değil, **doğrulama katmanının
tamamı satırlar arası `any()` semantiği kullanıyor.**

```
BIRLESTIRME (normalize_input cok olayli metni TEK KAYIT saniyor)
  event.id / process.name  -> ILK event kazanir
  account.name             -> SON event kazanir        <-- tutarsiz
  8 event'lik alarmda: 8 EventID -> 1, 8 Account Name -> 1

KAPI (evidence_gate_decisions)
  satir kumesi                    T1003.002
  ------------------------------  ---------
  yalniz SAM                      confirm
  yalniz LOGON                    reject
  yalniz duz METIN                abstain
  SAM + LOGON                     confirm     <-- kanit BASKA satirda
  METIN + SAM                     confirm     <-- kanit BASKA satirda
  METIN + LOGON                   reject      <-- abstain'di, ELEMEYE dondu

ATIF (verify_mappings)
  row_ids = list(range(len(rows)))  -> her bulgu HER satiri kaniti sayiyor
```

**İki yönlü silahlandırılabilir:**

| vaka | saldırganın eklediği | sonuç |
|---|---|---|
| V-BASTIRMA | zararsız `4624` logon | `SUSPICIOUS` → **`BENIGN`** |
| V-ELEME | zararsız `4624` logon | kapı `abstain` → **`reject`** |

Biri alarmı susturuyor, diğeri doğru bulguyu siliyor. **Kök aynı**, bu
yüzden yalnızca birini düzeltmek açığı kapatmaz.

---

## 1. Alarm seviyesi karar NASIL türetilecek?

**KARAR: EN SERT KAZANIR. Zincir değerlendirmesi YAPILMAYACAK ve bu
açıkça yazılacak.**

Sıralama:

```
SUFFICIENT_SUSPICIOUS  >  INSUFFICIENT_DATA  >  SUFFICIENT_BENIGN
```

`INSUFFICIENT_DATA`'nın `BENIGN`'den **sert** olması kasıtlı: bir alarm
ancak **her** event'i `BENIGN` ise `BENIGN` okur. Tek bir "bilmiyorum"
alarmı meşru ilan etmeye yetmez. Bu, Görev 4'ün `unknown ≠ noise`
kararının ve §4'ün "yokluktan BENIGN üretilmez" kuralının alarm
seviyesindeki karşılığıdır.

### Neden zincir değil

- **Bugün de zincir değerlendirilmiyor — sadece yanlış yapılıyor.**
  Alanları birleştirmek zincir kurmak değil, zincir kurmuş gibi
  yapmaktır. Kaldırılan şey bir yetenek değil, bir yanılsama.
- Zincir anlatısı için **zaten ayrı bir katman var**:
  `app/correlation/` (`build_attack_chain`, `compute_risk_score`,
  `summary_builder`). Karar katmanına ikinci bir zincir mantığı koymak
  iki gerçeklik demektir — `activity_verdict`'i "yedek" bırakmama
  kararının aynısı.
- En sert kazanan kural **denetlenebilir**: "alarm şüpheli, çünkü event
  #4 şüpheli" tek cümlede gösterilebilir. Zincir puanı gösterilemez.

### Zorunlu çıktı — özet tek başına yetmez

Alarm kararı **hangi event'in** o sınıfı verdiğini taşımak zorunda:

```
alarm_decision = {
  "decision": "SUFFICIENT_SUSPICIOUS",
  "belirleyen_event": 4,                 # sinifi veren event
  "event_kararlari": [ {index, decision, reason_chain}, ... ],
  "dagilim": {"SUSPICIOUS": 1, "INSUFFICIENT_DATA": 6, "BENIGN": 1}
}
```

Gerekçesi Görev 5 ile aynı: "SUSPICIOUS" demek analiste itiraz edilebilir
bir şey söylememektir.

### Bilinen sınır — rapora yazılacak

Yalnız başına zararsız ama **birlikte** saldırı olan event dizileri bu
kuralla yakalanmaz. Bu bilinçli: bugün de yakalanmıyor. Yakalamak Görev
13 sonrası ayrı bir iştir ve gerçek alarm verisi olmadan tasarlanamaz.

---

## 2. Bastırma HANGİ seviyede?

**KARAR: EVENT SEVİYESİNDE. Bastırma alarm seviyesine ASLA çıkmaz.**

Bu, açığın gerçek çözümüdür.

### Gerekçe

Bastırma bir üçlü hakkında iddiadır: **belirli bir aktör**, **belirli bir
varlığa**, **belirli bir erişim** yaptı ve bu beklenen bir iştir. Bu üçlü
yalnızca **tek bir event içinde** anlamlıdır. Bir alarmın tek bir aktörü
ya da tek bir varlığı yoktur — yani alarm seviyesinde bu iddia **iyi
tanımlı bile değildir**.

Açığın mekanizması tam olarak buydu: `(TrustedInstaller.exe, SYSTEM)`
çifti iki ayrı event'ten derlendi. Event seviyesinde değerlendirme, bir
çiftin ancak **gerçekten birlikte gözlendiğinde** kurulabilmesini
garanti eder.

### Bağlayıcı sonuçlar

> **Bastırma yukarı doğru YAYILMAZ.** İçinde bir bastırılmış event ve bir
> şüpheli event bulunan alarm `SUSPICIOUS`'tur (§1 sıralaması). Bastırma
> yalnızca kendi event'ini `BENIGN` yapar.

> **Alarm seviyesinde bastırma kuralı YAZILMAZ.** "Alarm meşru bir çift
> içeriyorsa sustur" biçimindeki her kural, aynı açığı başka kılıkta geri
> getirir — çünkü yine olaylar arası derleme yapar.

Yani bir saldırgan zararsız event ekleyerek alarmı en fazla
**INSUFFICIENT_DATA'lık gürültü** ekleyebilir; şüpheli event'i
susturamaz.

---

## 3. Çok satırlı girdide kanıt kapısı — ÖLÇÜLDÜ, sonra tasarlandı

### Ölçülen (bkz. §0 tablosu)

Kapı **çapraz çarpım** yapıyor:
`any(rule.row_matches(row) for rule in kurallar for row in satirlar)`.
Teknik satır 3'ten gelse bile kanıt satır 1'de bulunursa onaylanıyor.
Ayrıca `input_has_event_id` de satırlar arası `any()` — bu yüzden
`METIN + LOGON` birleşimi `abstain`'i `reject`'e çeviriyor.

Ve **atıf hiç yok**: `row_ids = list(range(len(rows)))`.

### Tasarım kararı

> **Kanıt, tekniğin GELDİĞİ satırda aranır.** Bunun ön koşulu her
> eşleştirmenin kaynak satırını taşımasıdır.

**İyi haber: bu kaynağı yeniden icat etmeye gerek yok.** Toplu mod zaten
doğru yapıyor — her satır kendi `run_improved_query` çağrısını alıyor,
yani `rows` tek elemanlı ve çapraz çarpım kendiliğinden çöküyor. Kusur
**yalnızca tekli girdiye çok olay yapıştırıldığında** ortaya çıkıyor.

Dolayısıyla iş, yeni bir doğrulama mimarisi değil:

```
cok olayli tekli girdi
      -> olaylara BOL
      -> her olayi MEVCUT tek-olay yolundan gecir   (batch modun yaptigi)
      -> event kararlarini EN SERT KAZANIR ile birlestir   (§1)
```

Bölme katmanının işi: metni olay sınırlarından ayırmak. Aşağı akış
sözleşmesi (`rows: list[dict]`) zaten çoklu satır alıyor.

### Bölme nerede yapılacak

`app/normalization/formats.py` — biçim algılama zaten orada ve
eklenebilir yapıda. Bölme **biçime özgüdür**: `brace_comma_kv` satır
başına bir olay; CSV satır başına bir olay (zaten öyle); düzyazı
**bölünmez** (tek olay sayılır).

**Fixture olmadan bölücü yazılmaz.** `brace_comma_kv` için fixture var
(`merge_vulnerability_logs.json`); CSV için gerçek QRadar örneği var
(`qradar_2026-08-06_51rows.csv`).

---

## 4. Kapanış kriteri — üçü birden

Açık, `merge_vulnerability_logs.json`'daki üç ölçüt birlikte geçmeden
**kapanmış sayılmaz**:

1. **V-BASTIRMA**: EV1+EV2 → `SUFFICIENT_SUSPICIOUS` (bugün `BENIGN`)
2. **V-ELEME**: METIN+LOGON → kapı `abstain` (bugün `reject`)
3. **V-ATIF**: her bulgu yalnızca kendi kaynak satırını kanıt sayar
   (bugün `range(len(rows))`)

`tests/test_merge_vulnerability.py` bugünkü davranışı kilitliyor: biri
düzelince test **kırmızı yanar** ve ters çevrilmesi gerekir. Kırmızı
burada iyi haberdir.

---

## 5. Bu beklentinin ölçmediği şey

- Bölmenin gerçek QRadar CSV'sinde ne kadar doğru çalıştığı. Ölçüm Görev
  13'ün held-out setiyle yapılacak; sıra bu yüzden bu iş → sonra 13.
- Alarm seviyesi kararın yanlış alarm oranı. Bugünkü 60 senaryoda alarm
  kavramı yok; ölçülemez (bkz. beklenti 5 §7).

---

# EK — kod yazıldıktan SONRA yazıldı (2026-08-19)

Bu bölüm beklenti değil **kayıt**. Yukarıdaki §0–§5 koddan önce yazıldı ve
değiştirilmedi; burada yalnızca (a) beklentinin cevaplamadığı sınır kuralı,
(b) uygulamada beklentiden **sapan** iki nokta, (c) ölçülen yan etki
duruyor. Ayrımın korunması şart: sonradan yazılan beklenti, çıktıya bakıp
"evet böyle olmalı" demenin kibar hâlidir.

## E1. Bölücü NEYE GÖRE bölüyor — kural tablosu

§3 bölmenin *nerede* yapılacağını söylüyordu (`formats.py`), *neye göre*
bölüneceğini değil. Kural, koddan önce yazılıp modül başlığına kondu ve
`tests/fixtures/event_split_cases.json` ile sabitlendi:

| # | kural | sınır |
|---|---|---|
| 1 | `json_array` | metnin tamamı bir JSON dizisi → öğe başına bir olay |
| 2 | `brace_blocks` | ≥2 **dengeli** üst seviye `{...}` bloğu, dışında yalnızca boşluk → blok başına bir olay. Satır sonuna bağlı **değil**: `{a} {b}` de bölünür |
| 3 | `cok_satirli_kayit` | `{` ile başlayan satır YOK ve ≥2 `"Etiket:  Değer"` işareti VAR → Windows Event Log gövdesi. Bu biçimde kayıt sınırı satır sonu **değildir**; BÖLÜNMEZ |
| 4 | `lines` | satır sonu sınırdır. İki istisna: (a) ayraç dengesi bozukken satır sonu sınır değildir, (b) ardışık **düzyazı** satırları tek olayda birleşir, boş satır düzyazıyı bölmez |
| 5 | `single` | hiçbiri >1 olay üretmedi → tek olay |

Kuralların hepsi **bölmemeye meyilli**. Gerekçe §3'te zaten yazılıydı ama
sınır kuralına şöyle iniyor: yanlış bölmek birleştirmek kadar zararlıdır —
bir event ikiye bölünürse kanıtın yarısı bir tarafta, tekniğin geldiği satır
öbür tarafta kalır ve kanıt kapısı **kendi bulgusunu çürütür**.

### BÖLÜNEMEYEN durum — sessiz geri dönüş yok

Bağımsız bir sayaç girdideki olay işaretlerini (`Event ID=` / `Event ID:`)
sayar. İşaret sayısı üretilen olay sayısından büyükse sonuç bir **uyarı**
taşır (`SplitResult.warning`), uyarı karar zincirine yazılır ve arayüzde
gösterilir. Girdi yine tek olay olarak işlenir — ama bu artık sessiz bir
varsayım değil, yazılı bir kısıt.

**Sayaç BÖLGE BAŞINA sayar (blok içi / blok dışı, büyüğü alınır) — ölçülmüş
düzeltme.** Düz sayım 51 gerçek QRadar satırının **51'inde** yanılıyordu:
bir QRadar satırı aynı olayı iki kodlamada taşıyor (yapısal alanda
`Event ID=5156`, ham payload'da `EventID=5156`). Her satırda yanan bir uyarı,
uyarı değil gürültüdür ve okunmamayı öğretir. Bölge başına sayımla QRadar'da
**0** yanlış uyarı kalıyor ve 60 senaryodaki tek gerçek pozitif
(`multi-010`, tek satırda iki olay) **korunuyor**.

Bilinen sınırı yazılı: aynı bölgede aynı olayın iki kez serileştirildiği bir
girdi hâlâ iki olay sayılır. Böyle bir örnek elde yok; görüldüğünde
fixture'lanacak.

## E2. Beklentiden SAPAN iki nokta

**1. `dagilim` anahtarları.** §1'in örneği kısa adlar gösteriyordu
(`{"SUSPICIOUS": 1, ...}`). Kod tam sınıf sabitlerini kullanıyor
(`SUFFICIENT_SUSPICIOUS` vb.). Gerekçe: kısa adlar ikinci bir sözlük
demektir ve bu projede iki isim/iki gerçeklik deseni defalarca ölçüm
kirletti. Sıralama, karşılaştırma ve dağılım anahtarları **tek kaynaktan**
(`ALARM_SERTLIGI`) okunuyor.

**2. `decide` artık çok olaylı girdiyi REDDEDİYOR** (`MultiEventDecisionError`).
Beklentide yoktu; uygulama sırasında çıktı. Bölme yapılsa bile `decide`
birleştirilmiş metinle çağrılabiliyordu ve o çağrı eski (açık) davranışı
aynen üretiyordu — yani düzeltmenin yanında **kullanılabilir bir kaçış yolu**
duruyordu. Kaçış yolu bırakan bir kapanış, kapanış değildir. Bunun ön koşulu
olarak `normalize_input` çıktısına `split` damgası eklendi: "bu kayıt kaç olay
taşıyor" sorusu tüketiciye tahmin ettirilmiyor.

## E3. Ölçülen yan etki — geçmiş ölçümler kımıldamıyor

Bölme, mevcut ölçüm setlerinin **hiçbirinde** ateşlenmiyor:

```
60 senaryo             n=60   bolunen=0  uyarili=1   (multi-010, gercek pozitif)
probe loglari          n=4    bolunen=0  uyarili=0
QRadar CSV satirlari   n=51   bolunen=0  uyarili=0
```

Yani katmanlı sorgu D kolu, dedup karşılaştırması ve ablasyon ölçümleri
karşılaştırılabilir kalıyor. Bu ölçüm olmadan "düzeltme geçmiş ölçümleri
geçersiz kıldı mı" sorusu cevapsız kalırdı; bu projede aynı soru iki kez
sorulmadığı için iki ölçüm kirlendi.

Ölçüm betiği: `scripts/measure_task14_closure.py` (üç kriter + yan etki,
LLM ve indeks gerektirmez).

## E4. Kapanış ölçümü (2026-08-19)

```
V-BASTIRMA   once=SUFFICIENT_BENIGN            simdi=SUFFICIENT_SUSPICIOUS   hedef=SUFFICIENT_SUSPICIOUS
V-ELEME      once=reject                       simdi=abstain                 hedef=abstain
V-ATIF       once=range(len(rows)) her satir    simdi=yalnizca kaynak satir   hedef=yalnizca kaynak satir
```

Üçü birden geçti. `tests/test_merge_vulnerability.py` ters çevrildi: artık
açığın **kapalı kaldığını** doğruluyor ve beklenen değerler kayıttaki
`birlesik_beklenen` alanlarından okunuyor.

Asıl sözleşme sonuç değil **izolasyon**: bir event'in kararı girdideki diğer
olaylardan bağımsızdır. Sonucu kilitlemek yerine sözleşmeyi kilitlemek, aynı
açığın üçüncü bir kılıkta (başka alan, başka bastırıcı) geri gelmesini de
engeller. Sözleşme **iki yolda birden** koşuyor: tekli yol (böl → her olayı
tek-olay yolundan geçir) ve toplu yol (satır başına ayrı çağrı) aynı event
için aynı kararı vermek zorunda.

## E5. Bu ekin de ÖLÇMEDİĞİ şey

- Bölmenin gerçek QRadar CSV'sindeki **doğruluğu**. Ölçüldü ki 51 satırın
  51'i bölünmüyor — ama o satırların her biri gerçekten tek olay mı,
  bağımsız olarak doğrulanmadı. §5'teki kısıt yerinde duruyor: ölçüm Görev
  13'ün held-out setiyle yapılacak.
- Alarm seviyesi kararın **yanlış alarm oranı**. Bugünkü 60 senaryoda alarm
  kavramı yok; ölçülemez.
- Çok olaylı bir girdinin **uçtan uca** (LLM + indeks) davranışı. İndeks
  damgasız olduğu için bu oturumda koşturulamadı; birleştirme yarısı
  `tests/test_multi_event_pipeline.py`'de tek-olay analizi sahtelenerek
  ölçüldü.
