# Beklenti — Görev 4: varlık kritikliği tablosu

**Kod yazılmadan önce yazıldı.** Görev 5'in (karar katmanı) girdisidir:
`\REGISTRY\MACHINE\SAM` kritik, `Time Zones` gürültü — bu ayrım olmadan
karar fonksiyonu yazılamaz.

---

## Tasarım girdisi (ölçüldü, sonuç değil)

Şart: tablo test loglarındaki yollardan **türetilemez**. Kaynağın yeterli
olup olmadığı, yazmadan önce sayılabilir bir soru. Sayıldı:

```
canli teknik                    697
ATT&CK metinlerinde BENZERSIZ registry yolu   291
yol iceren teknik                35
persistence + credential izi tasiyan aday      56
```

**56 > 40**, yani "kritik+yüksek seviyede en az 40 desen" şartı ATT&CK
verisinden karşılanabiliyor. Ham çıkarım **doğrudan kullanılamaz**: JSON
kaçışları (`HKCU\\Software`), kırpılmış cümleler
(`...Secrets or memory scraping via tools such as Mimikatz o`) ve yanlış
pozitifler (`system\screenshot.bmp`) var. Tablo **temizlenmiş** olacak,
ham çıkarım taslak.

---

## Kaynak — üç tane, hiçbiri test logu değil

| kaynak | ne verir |
|---|---|
| ATT&CK teknik metinleri (`description` + `detection` + procedure) | 291 yol, 56 kritik aday |
| Kamuya açık Windows **persistence** listeleri | `Run`/`RunOnce`/`Winlogon`/`IFEO`/`AppInit`/`BootExecute`/`Services` |
| Kamuya açık Windows **credential** konumları | `SAM`, `SECURITY\Policy\Secrets`, `LSA`, `Terminal Server Client` |

**Test loglarındaki üç yol kaynak DEĞİL.** `\REGISTRY\MACHINE\SAM`
tabloya girecek — ama `SAM` bir credential konumu **olduğu için**, T1'de
geçtiği için değil. Her satır **kaynağını beyan edecek**; kaynağı
"fixture'da vardı" olan satır kabul edilmez.

---

## Seviyeler ve EŞLEŞMEYEN YOL

```
critical  kimlik bilgisi deposu / dogrudan yetki yukseltme
high      persistence ya da guvenlik kontrolu devre disi birakma
medium    yapilandirma, baglami olmadan karar verilemez
noise     olculmus gurultu (Time Zones, MUICache, tema...)
unknown   TABLODA YOK
```

### `unknown` ≠ `noise` — bu maddenin en önemli kararı

Eşleşmeyen yolun varsayılanı **`noise` DEĞİL `unknown`**.

Gerekçe: bilinmeyeni zararsız saymak, **tablonun kapsamadığı her saldırıyı
görünmez yapar**. Tablo 291 yolun bir alt kümesini kapsayacak; Windows
registry'sinde on binlerce anahtar var. "Listede yoksa gürültüdür" kuralı,
kapsama boşluğunu **sessiz bir kör nokta**ya çevirir — ve bu oturumun
tekrar tekrar gördüğü desendir: eksik kayıt, yanlış kayıt kadar zararlı.

**Görev 5'e bağlayıcı sonuç:** `unknown`, `SUFFICIENT_BENIGN` üretmek için
**yeterli olmayacak**. `unknown` + başka kanıt yoksa çıktı
`INSUFFICIENT_DATA` olmalı — "zararsız" değil, "bilmiyorum".

---

## Kabul kriteri — sayıyla

| ölçü | hedef |
|---|---|
| `critical` + `high` desen sayısı | **≥ 40** |
| kaynağı beyan edilmeyen satır | **0** |
| kaynağı yalnızca test fixture'ı olan satır | **0** |
| tablo koddan okunuyor mu | **evet** (`config/asset_criticality.yaml`), kod tabloyu okuyan motor |
| lehçe bağımsızlığı | `HKLM\SAM`, `HKEY_LOCAL_MACHINE\SAM`, `\REGISTRY\MACHINE\SAM` **aynı** sonucu vermeli |

Son satır bedava geliyor: `path_normalizer` 2B'de motora bağlandı, aynı
mekanizma burada da kullanılacak — **yeni normalizasyon yazılmayacak**.

---

## Beklentiler

| # | beklenti | tutmazsa ne öğrenilir |
|---|---|---|
| 1 | Dört probe yolundan **T1 kritik**, **T2 gürültü**, T3'ün Defender yolu **high** | Tablo yanlış kurulmuş ya da seviye tanımları belirsiz |
| 2 | 60 senaryonun **çoğunda `unknown`** çıkacak — senaryoların 45'i düzyazı, registry yolu taşımıyor | `unknown` az çıkıyorsa tablo fazla geniş eşleşiyor demektir (yanlış pozitif riski) |
| 3 | Tablo, **test verisinde hiç geçmeyen** yolları da sınıflandıracak (`IFEO`, `AppInit_DLLs`, `BootExecute`) | Tablo fixture biçimli demektir — Ö1'in aynısı |
| 4 | Kritiklik **tek başına** alarm üretmeyecek | Görev 5 karar fonksiyonu kritikliği tek girdi sanmış olur; `SAM` okuması yedekleme yazılımı da olabilir |

---

## 5. KAPSAMA ORANI — "40 desen yazmak" bitirmek değil

40+ desenli bir tablo, gerçek registry evreninin küçük bir kısmını kapsar.
Kapsama ölçülmezse Görev 5 pratikte **hep `INSUFFICIENT_DATA`** üretir ve
sistem yine alarm vermez — sadece sebebi değişmiş olur. *"Yetersiz veri"*
diyen bir sistemden *"bilmiyorum"* diyen bir sisteme geçmiş oluruz: daha
dürüst, aynı derecede işe yaramaz.

### PAYDA PROBLEMİ — ölçüldü, ve ölçüm yerini değiştirdi

Kapsama oranını **test verisinde ölçmek anlamsız**:

```
4 probe fixture : 3 benzersiz registry yolu (T1 SAM, T2 Time Zones, T3 Defender)
60 senaryo      : 0
TOPLAM          : 3
```

Üçü de **tablonun tasarlandığı hedeflerin ta kendisi**. Orada kapsama
ölçmek, tabloyu kendi tasarım hedeflerine karşı sınamaktır — Ö1'in aynı
tuzağı. Payda 3 olduğu için oran zaten anlamsız.

**Bu, kural ateşlenme bulgusunun aynısı:** bu set Görev 4'ü de sınayamıyor.
Görev 13'ün kabul kriterine ekleniyor — held-out set **registry yolu
taşıyan loglar** içermeli, en az `critical`, `high`, `noise` sınıflarından
birer aile.

### Bağımsız payda: ATT&CK'in 291 yolu

Ölçüm ATT&CK metinlerindeki **291 benzersiz registry yolu** üzerinde
yapılacak. Kısmen dairesel — tablo bu havuzdan besleniyor — ve bu sınır
raporda yazılacak. Ama tablo 291'in tamamını değil, **aile** seviyesinde
bir alt kümesini kapsayacak, yani ölçüm yine bilgi taşıyor.

### Eşik — ÖLÇÜMDEN ÖNCE, ve yüzde değil

Ham yüzde eşiği **oyunlaştırılabilir**: tabloya çöp desen ekleyerek oran
yükseltilir. O yüzden eşik **aile** üzerinden:

> **`unknown` çıkan her yol ailesi, ya tabloya eklenecek ya da
> GEREKÇESİYLE kapsam dışı ilan edilecek. Gerekçesiz `unknown` ailesi
> kalmayacak.**

Meşru kapsam dışı örneği: `HKLM\Software\NFC\IPA`, `HKCU\Office365DCOMCheck`
gibi **tek bir zararlıya özgü artefakt anahtarları** — bunlar bir aile
değil, bir örnektir; tabloya girerlerse tablo fixture biçimli olur.

Yardımcı eşik (uyarı seviyesi, sert şart değil): 291 yolun **%50'den
fazlası** `unknown` kalıyorsa tablo aile seviyesinde **dar** demektir ve
genişletilmeden Görev 5'e geçilmez.

### Zorunlu çıktı: `unknown` LİSTESİ

Ölçüm yalnızca oran vermeyecek, **`unknown` kalan yolları aile bazında
listeleyecek**. Tablonun nereye büyümesi gerektiğini söyleyen şey o liste.
Liste `docs/`'a yazılacak ve her ailenin yanında karar duracak:
*eklendi* / *kapsam dışı: <gerekçe>*.

### "Bitti mi" sorusunun cevabı

Görev 4 şu üçü birden sağlanınca biter:
1. `critical` + `high` ≥ 40 desen
2. kaynağı beyan edilmeyen satır 0
3. **gerekçesiz `unknown` ailesi 0**

---

---

# SONUÇ RAPORU (2026-08-18)

## Kabul kriteri: ÜÇÜ DE SAĞLANDI

| kriter | hedef | sonuç |
|---|---|---|
| `critical` + `high` desen | ≥ 40 | **146** |
| kaynağı beyan edilmeyen satır | 0 | **0** (test zorluyor) |
| gerekçesiz `unknown` ailesi | 0 | **0** |

## Sınıf dağılımı ve katkı ayrıştırması

```
payda:  ham 280  ->  temiz 226        (C: 54 artefakt cikarildi)

   critical    13   %6
   high       133   %59
   medium      19   %8
   noise       12   %5
   unknown     49   %22   <-- HEPSI gerekceli kapsam disi
```

Katkılar ayrı ölçüldü — eski tablo git'ten yüklenerek, elle "şu kadardı"
denmeden:

```
kol                                                unknown    oran
TABAN  (eski tablo, hive'siz eslestirme yok)      107/226     %47
+A     (hive'siz eslestirme + segment normalize)   91/226     %40    (-16)
+A+B   (yeni aileler eklendi)                      49/226     %22    (-42)
```

**C paydada çalışıyor:** çıplak kökler (21), yalnızca jenerik konteynerden
oluşan yollar (19), cümleden kırpılmışlar (8), hive'sız tek segment (6).
Bunlar yol değil, çıkarım aracının artefaktı; paydada sayılınca unknown
oranını yapay şişiriyorlardı.

## "Gürültü adayı" diye hızlı geçilmedi

Payda ATT&CK'ten geldiği için **her yol bir teknikte geçiyor**; soru hangi
bağlamda geçtiğiydi. Yapılandırma gibi görünen üçü, bağlamına bakılınca
teknik taşıdı:

| yol | görünüşü | gerçeği |
|---|---|---|
| `Explorer\Advanced` | yapılandırma | **T1564.001** — `Hidden`/`ShowSuperHidden` burada, dosya gizleme → **high** |
| `Internet Settings` | keşif hedefi (T1012) | proxy yapılandırması, C2 yönlendirmesi → **medium**, gürültü değil |
| `Internet Explorer\Privacy` | tarayıcı ayarı | **T1070** Indicator Removal → **medium** |

## `noise` sınıfının kaynağı — ayrı bir sorunun cevabı

Başlangıçta `noise` **1 satırdı** ve bu dengesizlik haklı olarak soruldu:
payda ATT&CK'ten geliyorsa, gerçekten zararsız yollar orada zaten yok mudur?

**Cevap: var — ama yalnızca KEŞİF tekniklerinde.** `T1012 Query Registry`,
`T1082`, `T1614.001`, `T1652`, `T1497.001`. O tekniklerde yol, saldırganın
**yazdığı** değil **okuduğu** şeydir:

```
Cryptography\MachineGuid        T1012/T1082/T1497   makine kimligi
HARDWARE\DESCRIPTION\System     T1012               donanim bilgisi
Control\Nls\Language            T1614.001           sistem dili
CurrentVersion\Uninstall        T1012               kurulu yazilim
WBEM\WDM                        T1652               surucu envanteri
```

Varlığın kendisi hassas değil; okumak keşiftir ama aynı anahtarları normal
yazılım da sürekli okur. **Varlık olarak gürültüdürler.**

**Yani noise için ayrı bir kaynağa gerek kalmadı** — ama sebebi tabloyu
zorlamak değil, doğru mercekle bakmaktı. `noise` 1 → **12** satır.

**Ayrım Görev 5'e bırakıldı:** kritiklik **varlığın** özelliği, okuma/yazma
ise **erişim sınıfı** — Görev 5'in ayrı girdisi. Aynı anahtarı **okumak**
keşif, **yazmak** başka şey olabilir; tablo bunu karıştırmaz.

**T2'nin `SUFFICIENT_BENIGN` üretmesi buna bağlıydı ve `Time Zones` zaten
`noise`** (kaynağı `measured`, ATT&CK değil). Yani T2 için gereken şey
tabloda vardı; keşif ailelerinin eklenmesi onu genişletti.

## Kalan `unknown` — 49, hepsi gerekçeli

- **tek zararlıya özgü artefakt anahtarları** (`Backtsaleht\StubPath`,
  `Pniumj`, `spreadCpuXmr`...) — aile değil örnek; tabloya girerlerse tablo
  fixture biçimli olur
- **üçüncü taraf ürün anahtarları** (`KasperskyLab`, `Bitcoin-Qt`,
  `Foxit Reader`) — kritiklik Windows varlığına göre tanımlı
- **ATT&CK metnindeki bozuk yazımlar** — yol ile değer adı ayraçsız
  bitişik (`Control SystemStartOptions`, `Lsa Name`), harf hataları
  (`nNT`, `Paramenters`, `HKEY_CURRENT_USERS`). Tablo eksiği **değil**,
  kaynak metnin kusuru; düzeltilmiş biçimleri tabloda zaten var.

## Yasak biçimler — bu görevde özellikle

- `if "SAM" in path: return "critical"` → tablo veri olacak, kod motor
- Yalnızca T1/T2/T3'te geçen yolları kapsayan tablo → beklenti 3 bunu ölçer
- Eşleşmeyeni `noise` saymak → yukarıda gerekçesi yazılı
- Seviyeyi tekniğe göre vermek → **yol kritikliği tekniğe değil VARLIĞA ait**;
  aynı yol farklı tekniklerde geçer (2B'nin K2 dersi)
