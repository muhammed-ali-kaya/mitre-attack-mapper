# Beklenti — Görev 15: toplu yolda sarmalanan Message'ın alan kaybı

**Kod yazılmadan önce yazıldı.** Ölçümler `scripts/measure_kv_field_loss.py`
ile tekrarlanabilir; gerilemede çıkış kodu 1.

Kaynak: `docs/sonuc_13_g_kolu.md` §2 — G kolunda Yol B hiçbir satırda
ateşlenmedi, sebebi `access.mask`'in KV yolunda düşmesiydi. Bu belge o
bulguyu bir alandan bir MEKANİZMAYA genişletiyor.

---

## 1. Ölçülen kayıp — tek alan değil

51 gerçek QRadar satırı, iki yol yan yana ayrıştırıldı:

- **A yolu:** `parse_fields(satır["Message"])` — ham Windows gövdesi
- **B yolu:** `parse_fields(row_to_kv_string(satır))` — üretimin toplu modda
  hatta verdiği metin

Biçim seçimi: A yolunda 50/51 `windows_message`, B yolunda 51/51 `space_kv`.

**B yolunda kaybolan ŞEMA İÇİ alanlar:**

| alan | kaç satırda | karara iniyor mu |
|---|---|---|
| `process.id` | 49/51 | hayır (sorgu 1. katmanına girer) |
| `service.name` | 11/51 | hayır |
| `source.ip` | 9/51 | hayır |
| `access.mask` | 5/51 | **evet — `erisim_sinifi`, Yol B** |
| `access.list` | 5/51 | **evet — `erisim_sinifi`, Yol B** |
| `handle.id` | 5/51 | hayır |

Ayrıca 25 ayrı `unknown.*` alan kayboluyor (kanıt tablosu gösterimi;
sorguya girmez).

`object.name` **iki yolda da yok** — ayrı bir kusur, §6'da.

Karara inen kayıp yalnızca `access.mask` + `access.list`, ve yalnızca beş
`4656` registry satırında. Diğer dört alan sorgu 1. katmanını
(`discriminating_fields`) besliyor, yani **düzeltme retrieval'ı da
değiştirecek** — §5'in ölçüm kısıtı buradan geliyor.

---

## 2. Üç ayrı kusur, tek sarmalama

### K-A — yuvalama: bir log, iki biçim

`row_to_kv_string` Message'ı boşluk içerdiği için tırnaklı TEK değere
sarıyor (`app/batch/serialize.py:_format_kv_value`). Ortaya çıkan metin
gerçekten iki biçimlidir: dışta `space_kv`, `Message=` değerinin İÇİNDE
`windows_message`.

`detect_format` tam olarak BİR biçim döndürür (`formats.py`). Yuvalanmış
girdi bu sözleşmenin dışında kalıyor: dış biçim seçiliyor, iç gövde tek bir
`event.message` değeri olarak duruyor ve alt alanlarına hiç bakılmıyor.

### K-B — kaçış asimetrisi: serileştirme kaçırıyor, ayrıştırma geri almıyor

`_format_kv_value` tırnaklarken `\` → `\\` ve `"` → `\"` kaçışı uyguluyor.
**Hiçbir ayrıştırıcı bunu geri almıyor.** İki ayrı `_unquote` var
(`formats.py:271`, `input_parser.py:243`) ve ikisi de yalnızca baştaki ve
sondaki tırnağı siliyor.

Ölçüldü — gidiş-dönüş:

```
girdi   CommandLine = reg.exe save HKLM\SAM C:\Users\Public\sam.hiv
kv      CommandLine="reg.exe save HKLM\\SAM C:\\Users\\Public\\sam.hiv"
çıktı   process.command_line = reg.exe save HKLM\\SAM C:\\Users\\Public\\sam.hiv
```

Bu **yalnızca Message'ı değil, boşluk içeren HER değeri** bozuyor —
komut satırı dahil. Etkisi ölçüldü:

```
siniflandir("\REGISTRY\MACHINE\SAM")    -> critical / credential-hive
siniflandir("\\REGISTRY\\MACHINE\\SAM") -> unknown
```

Yani K-B tek başına bırakılırsa, K-A düzeltilse bile iç gövdeden gelen
registry yolları `unknown`'a düşer: **doğru düzeltme, çalışmayan sonuç.**
İkisi birlikte düzeltilmek zorunda.

> Bu kusurun testi yoktu ve olamazdı:
> `test_row_to_kv_string_quoted_commandline_roundtrips_through_normalize_input`
> ters bölü de tırnak da içermeyen bir komut satırı kullanıyor. HANDOFF
> dersi 9'un yeni örneği — test sayısı değil, testin NEYE baktığı.

### K-C — etiket sınırı iç gövdeyi kirletiyor

`_MESSAGE_LABEL_RE` etiketi `[A-Z][A-Za-z ]{2,28}?` ile sınırlıyor. 51
satırın gövdesinde bu sınırı aşan **tek gerçek etiket** var:

```
'Privileges Used for Access Check'   (32 karakter, 5 satırda)
```

Tanınmadığı için metni bir önceki alanın DEĞERİNE yapışıyor:

```
access.mask = '0x2001F  Privileges Used for Access Check: -'
decode_access_mask(...)  ->  None
```

Yani K-A ve K-B düzeltilip K-C bırakılırsa `access.mask` kurtarılır ama
**çözülemez**; Yol B yine ateşlenmez.

#### K-C'nin çözümü uzunluk sınırını BÜYÜTMEK DEĞİL (ölçüldü)

İlk akla gelen düzeltme sınırı 28'den 40'a çekmekti. Reddedildi: 40 sayısı
yalnızca fixture'daki 32 karakterlik etikete bakılarak seçilebilirdi ve bu,
projenin *"eşikleri fixture çıktısına bakarak ayarlamak yasaktır"* kuralının
ihlalidir. Dört sınır 166 girdilik korpusta ölçüldü (51 QRadar KV + 51 ham
Message + 60 senaryo + 4 probe logu):

| sınır | etki |
|---|---|
| 28 (mevcut) | taban |
| 40 | `access.mask` düzelir, kayıp yok |
| 60 | `access.mask` düzelir **ama** `access.list` bozulur, `Access Reasons` kaybolur |
| sınırsız | 60 ile aynı bozulma |

Yani sınır gerçek bir işi var — ama uzunluk onu ölçmenin **yanlış aracı**.
`60`'ta bozulan şey şu: `'Notify about changes to keys       Access Reasons'`
dizesi etiket sanılıyor. Bu dize etiket OLAMAZ, çünkü içinde 7 boşluk var ve
**2+ ardışık boşluk bu biçimde etiket/değer AYRACIDIR**.

**Karar: sınır uzunluktan değil, biçimin kendi değişmezinden türetiliyor —
etiketin içinde 2+ ardışık boşluk olamaz.**

```
[A-Z][A-Za-z]+(?: [A-Za-z]+)*:      tek boşluklu kelime dizisi, uzunluk sınırı YOK
```

166 girdide ölçülen sonuç:

| korpus | girdi | biçim seçimi değişen | alan kümesi değişen |
|---|---|---|---|
| probe | 4 | 0 | 0 |
| senaryo | 60 | 0 | 0 |
| qradar_kv | 51 | 0 | 0 |
| qradar ham Message | 51 | 0 | **41** |

**Şema içi alan kaybeden girdi: YOK.** Kazanç, kural bozuk etiketleri
reddettiği için ayrıştırıcının GERÇEK etiketten başlamasından geliyor:
`object.name` +5, `source.ip` +23, `user.domain` +18, `account.name` +15,
`logon.id` +7, `object.server` +6, `object.type` +5; silinen adların hepsi
`unknown.Key  Object Name`, `unknown.NULL SID  Remote Machine ID` gibi
**bozuk isimler**.

> Biçim seçimi ayrıca kontrol edildi: `WindowsMessageFormat.matches` bu
> regex'i kullanıyor, yani kural değişimi bir girdiyi başka bir biçime
> kaydırabilirdi. 166 girdinin hiçbirinde kaymadı.

---

## 3. Kök neden hangi katmanda — karar ve gerekçesi

Soru: `row_to_kv_string`'in mi, `formats`'ın mı, sözleşmenin mi kusuru?

**Karar: sözleşmenin. Düzeltme `formats` katmanına konuyor — sarmalamayı
çözmek DEĞİL, sarmalanmış gövdenin içini de ayrıştırmak.**

İki modül de kendi başına doğru:

- `serialize.py` docstring'i sözleşme ortağını açıkça yazıyor: *"Felsefe:
  input_parser.py hiç değiştirilmiyor. Onun genel KEY_VALUE_RE regex'i..."*
  O ortak, Görev 1'de yazılan `formats.py` DEĞİL — sarmalama, formata
  duyarlı katman var olmadan önce tasarlandı. Boşluklu değeri tırnaklamak
  kendi ortağına karşı doğru davranış.
- `formats.py` "bir log = bir biçim" varsayıyor. Kendi fixture'larının
  hepsinde bu doğru.

Kusur ikisinin ARASINDA: sarmalama yeni bir biçim sınıfı (yuvalanmış log)
üretti, ayrıştırma sözleşmesi bu sınıfı tanımıyor. HANDOFF dersi 8'in tam
tanımı — *bir düzeltme başka yerdeki bir varsayımı geçersiz kıldı ve o
varsayım güncellenmedi.*

### Reddedilen seçenekler ve nedenleri

| seçenek | neden reddedildi |
|---|---|
| **serialize'da sarmalamayı çöz** (Message alt alanlarını ayrı KV çifti olarak yaz) | LLM'e giden HAM METNİ değiştirir. G kolu yeniden koşulduğunda fark, düzeltmeden mi girdi değişiminden mi geldiği ayırt edilemez — ölçüm kirlenir. Ayrıca serialize'ın Windows gövdesi ayrıştırmayı bilmesi gerekir; bu `formats.py`'nin kopyası olur. |
| **adaptörün `FIELD_LABEL_SUFFIXES` tablosuna `Access Mask` ekle** | Örnek katmanı düzeltmesi (HANDOFF dersi 6). Yalnızca QRadar'ı düzeltir; Message sarmalayan başka her kaynak aynı kaybı yaşamaya devam eder. Ayrıca tablo 10 alan taşıyor, kayıp 31 alanda. |
| **`decode_access_mask`'i kirli değere toleranslı yap** | Semptomu susturur, mekanizmayı sorgulamaz — HANDOFF dersi 4'ün tam kalıbı (bastırıcı yazmak). |

### Yetki sırası — açıkça yazılıyor

İç gövdeden gelen alanlar **yalnızca boşluk doldurur**; dış alan varsa dış
alan kazanır. Gerekçe: dış alanlar adaptörün AÇIK kolonlarıdır, iç gövde
etiket ayrıştırmasının best-effort ürünüdür. Ölçülen çakışma bunu
doğruluyor — `process.name`, 12/51 satırda dışta temiz, içte kaçışlı;
`host.name` 1/51 satırda içte tamamen yanlış (`ConsoleHost HostVersion=...`).

**Bu bir `setdefault` kararıdır ve HANDOFF dersi 8 uyarınca varsayımı
yazılıdır:** *dış alanlar açık kolonlardan gelir, iç gövde best-effort'tur.*
Bir gün adaptör kolonları best-effort hale gelirse bu sıra yeniden
değerlendirilmelidir.

---

## 4. Kapanış ölçütleri

Ölçüm: `.venv/Scripts/python.exe scripts/measure_kv_field_loss.py`

| # | ölçüt | şu an | hedef |
|---|---|---|---|
| Ö1 | KV yolunda kaybolan şema içi alan sayısı (51 satır toplamı) | 84 | 0 (`object.name` hariç, §6) |
| Ö2 | `decode_access_mask` çözülebilen satır | 0/5 | 5/5 |
| Ö3 | `erisim_sinifi == "write"` olan registry satırı | 0/5 | 5/5 |
| Ö4 | kaçış gidiş-dönüşü: `row_to_kv_string` → `parse_fields` değeri korur | hayır | evet (ters bölü + tırnak) |
| Ö5 | 60 senaryo + 4 probe logunda alan kümesi değişmeyen girdi | — | değişen her girdi tek tek gerekçelenir |

Ö5 bir "değişmesin" ölçütü DEĞİL: değişebilir, ama sessizce değişemez.

---

## 5. Bu düzeltme G kolunun yeniden koşusunda NEYİ karıştırır

Kurtarılan alanların dördü (`process.id`, `service.name`, `source.ip`,
`handle.id`) `discriminating_fields` üzerinden **sorgu 1. katmanına**
giriyor. Yani yeniden koşuda iki şey birden değişecek:

1. **karar yolu** — Yol B artık ateşlenebilir (amaçlanan etki)
2. **teknik listesi** — sorgu değişti, retrieval farklı aday getirebilir
   (yan etki)

**Bu ikisi AYRI raporlanacak.** Tek bir "iyileşti/kötüleşti" sayısı hangi
katmanın değiştiğini kaybettirir — `docs/sonuc_13_g_kolu.md`'nin kendi
kuralı ve HANDOFF'un "karar sınıfı doğruluğu ≠ teknik listesi doğruluğu"
maddesi.

Eski G sonucu **silinmiyor**: `evaluation/results/g_arm_run.json` ve
`g_arm_score.json` "Yol B kapalıyken alınmış ölçüm" damgasıyla korunuyor,
yeni koşu ayrı dosyaya yazılıyor.

### Koşmadan önceki tahmin (bu satır sonuçtan ÖNCE yazıldı)

Beklenti belgesi 13'ün orijinal tahmini şuydu: *beş `4656` satırı
`Services\*\Performance` anahtarına `0x2001F` maskesiyle handle istiyor,
maske `Set key value` içeriyor, **Yol B yanlış alarm üretecek**.*

O tahmin G kolunda test EDİLEMEDİ — Yol B ölüydü. Düzeltmeden sonra ilk kez
test edilebilir hale geliyor. Tahminin kendisi değiştirilmiyor:

- **beklenen:** 5 satırda Yol B ateşlenir, `SUFFICIENT_SUSPICIOUS` çıkar,
  yanlış alarm 0/49 → **5/49**'a çıkar.
- Eğer 5'ten AZ çıkarsa bastırıcı (aktör baseline, `service` ailesi ←
  `TrustedInstaller`/`msiexec`) devreye girmiş demektir; bu satırlarda aktör
  `NT AUTHORITY\LOCAL SERVICE`, yani baseline kaydı EŞLEŞMEZ ve bastırma
  beklenmiyor.
- **Yanlış alarmın artması bir gerileme değil, ölçümün ilk kez mümkün
  olması.** 0/49 kazanılmamıştı; 5/49 kazanılmış bir sayıdır ve Yol B'nin
  gerçek maliyetini gösterir. K1 (kural koşulları) bundan sonra ölçülebilir
  hale gelir.

---

## 6. Bu düzeltmenin KAPSAMADIĞI şey

- ~~**`object.name` iki yolda da kayıp.**~~ **KAPSAMA GİRDİ.** Sebebi
  etiket BAŞLANGICI idi (`Key  Object Name:` — önündeki değer etikete
  yapışıyordu). K-C'nin uzunluk sınırı yerine 2+ boşluk değişmezi
  konunca aynı mekanizma bunu da çözdü: `object.name` 5/51 satırda geri
  geldi. **Bu, düzeltmenin planlanmamış bir kazancıdır ve ayrı
  raporlanmalıdır** — kritiklik bugün adaptörün `FilePath` kolonundan
  geliyordu, artık iki kaynak birden var ve ikisinin AYNI FİKİRDE olduğu
  test edilmelidir (HANDOFF dersi 7).
- **Adaptörün `Object Name` → `FilePath` eşlemesi anlamsal olarak yanlış**
  (registry anahtarı `file.path` alanında duruyor). Bugün zararsız çünkü
  `varlik_kritikligi` üç alana birden bakıyor. Ayrı kalem.
- **Diğer kaynakların yuvalama davranışı.** Düzeltme kaynaktan bağımsız
  yazılıyor ama yalnızca QRadar korpusunda ölçülüyor; başka bir sarmalayan
  kaynak geldiğinde yeniden ölçülmeli.
