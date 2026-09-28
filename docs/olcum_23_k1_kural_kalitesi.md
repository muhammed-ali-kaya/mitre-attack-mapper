# Ölçüm — Görev 23 (K1): kural kataloğu kalitesi

**Bu bir ÖLÇÜM belgesidir. Hiçbir kural değiştirilmedi, düzeltme önerisi
yazılmadı.** Tarih: 2026-09-02.

Kaynak: `K1` kalemi — iki kusur biliniyordu (`T1140`, `T1082`), **kaçta kaç
olduğu ölçülmemişti**. Bu belge o sayıyı çıkarıyor.

---

## 0. Kapsam ve yöntemin avantajı

| | |
|---|---|
| katalogdaki kural | **49** |
| farklı teknik | 47 |

**Tarama STATİK.** Önceki bilgi şuydu: *49 kuralın yalnızca 14'ü 60
senaryoda ateşleniyor, 35'i hiç incelenmedi.* Statik tarama bu sınırı
aşıyor — **49 kuralın 49'u da tarandı**, ateşlenip ateşlenmediğine
bakılmaksızın. Ampirik kısım (§4) ayrıca korpuslara bakıyor ve iki yöntem
birbirini doğruluyor.

Tanımlar **işlemsel**: her sınıfın ölçütü aşağıda yazılı, "kötü kural" gibi
yargı terimi kullanılmıyor. Bir kural birden fazla sınıfa girebilir.

---

## 1. SINIF 3 — ayırt edici koşul taşımıyor → **12/49 kural (%24)**

| alt sınıf | ölçüt | sayı |
|---|---|---|
| **3a** | hiç `field_conditions` yok — yalnızca olay ID'siyle ateşliyor | **5** |
| **3b** | yalnızca AD tabanlı koşul (`process.name`/`parent.process.name`); komut satırı, nesne yolu, argüman yok | **6** |
| **3c** | yalnızca `must_not_match` — pozitif kanıt hiç yok | **1** |

### 3a — olay ID'si tek başına kanıt sayılıyor (5)

```
T1053.005   ev=[4698, 4699, 4700, 4702]
T1543.003   ev=[7045, 4697]
T1136.001   ev=[4720]
T1098       ev=[4728, 4732, 4756, 4738]
T1110.001   ev=[4625]
```

`T1110.001` (Password Guessing) yalnızca `4625`'e (başarısız oturum açma)
bakıyor: **tek bir başarısız giriş kaba kuvvet sayılıyor.** Sayı ve zaman
penceresi koşulu yok. Bu, S kolunda ölçülen `S-N-03` yanlış alarmının
kural tarafındaki karşılığı.

### 3b — bilinen kusurun genel hali (6)

```
T1059.003   process.name ~ \cmd\.exe
T1018       process.name ~ \(net|net1|nltest|arp)\.exe
T1016       process.name ~ \(ipconfig|netsh|route|arp|nbtstat)\.exe
T1082       process.name ~ \(systeminfo|hostname|wmic)\.exe     <- BILINEN
T1204.002   parent.process.name + process.name (ikisi de ad)
T1566.001   parent.process.name + process.name (ikisi de ad)
```

`T1082` biliniyordu; **beş tane daha var.** Karşılaştırma ölçütü kataloğun
kendi içinde duruyor: `T1047` aynı `wmic.exe` ikilisini kullanıyor ama
**ikinci bir koşulu var** (`process call create|/node:`). `T1082`'de o yok.
`T1059.003` en uçtaki hâli: `cmd.exe` çalıştı mı ateşliyor.

### 3c — pozitif kanıt yok (1)

```
T1055   ev=[8, 10]   process.name must_not_match (MsMpEng|CSFalconService|SentinelAgent|xagt)\.exe
```

Olay 8/10 geldiğinde, süreç bir EDR ikilisi **değilse** ateşliyor. Kural
neyin şüpheli olduğunu değil, neyin şüpheli **olmadığını** tanımlıyor.

---

## 2. SINIF 2 — başka tekniğin göstergesini mal etme → **1 doğrulanmış**

Aday üretimi otomatik, sınıflandırma elle (ATT&CK anlamı gerektiriyor).

**2b (çapraz kural jeton çakışması) bilinen kusuru KENDİLİĞİNDEN buldu:**

```
-urlcache  ->  ['T1105', 'T1140']
```

Tarayıcıya `T1140` vakası anlatılmadı; aynı ayırt edici bayrağın iki farklı
teknikte geçtiğini kendi buldu. **Detektörün kendi doğrulaması.**

**2a adayları: 3, doğrulanan: 1**

| kural | bayraklar | karar |
|---|---|---|
| `T1059.001` | `-enc`, `-encodedcommand`, `-executionpolicy` | temiz — üçü de aynı davranış (PowerShell yürütme) |
| **`T1140`** | `-decode`, **`-urlcache`** | **KUSUR** — `-decode` çözme (T1140), `-urlcache` **indirme** (T1105) |
| `T1105` | `-urlcache`, `/transfer` | temiz — ikisi de indirme/aktarım |

**Bayrak tabanlı taramada yeni sınıf-2 kusuru çıkmadı.** Sınırı §6'da.

---

## 3. SINIF 1 — kapsadığını beyan ettiği olay için eşleşemez

### 1a — koşulun alanı, olayın anlamlı alanlarında yok → **4 çift**

```
T1505.003 / 4663    bakıyor: file.name, file.path, process.command_line
                    olayın alanları: access.list, access.mask, account.name,
                                     object.name, object.type, process.name
T1070.001 / 1102    bakıyor: process.command_line   olayın alanları: account.name, host.name
T1070.003 / 4104    bakıyor: process.command_line   olayın alanları: account.name, host.name, script.block_text
T1564.003 / 4104    bakıyor: process.command_line   olayın alanları: account.name, host.name, script.block_text
```

**Sınama sınırı:** kuralların bildirdiği **9** (kural, olay) çifti
`config/event_semantics.yaml` kataloğunda yok (`104, 12, 400, 4778, 5145,
7, 7040, 8`), yani 1a ile **sınanamadı**. Bu ayrıca kendi başına bir bulgu:
kurallar, anlambilim kataloğunun tanımadığı olaylara dayanıyor.

### 1c — YENİ SINIF: olayın eşdeğeri listede yok → **8 çift, 8 teknik**

**Bu sınıf görev tanımında yoktu; ölçüm sırasında çıktı.**

Windows ve Sysmon aynı davranışı farklı olay ID'leriyle yazıyor
(`4688`↔`1` süreç oluşturma, `4657`↔`13` registry yazma, `4663`↔`11`
dosya). Kural bir tarafı beyan edip diğerini atlarsa, teknik gerçekten
gerçekleşse bile eşleşemez:

```
T1059.003   4688 var, Sysmon 1 YOK
T1053.005   4688 var, Sysmon 1 YOK
T1059.001   4688 var, Sysmon 1 YOK
T1018       4688 var, Sysmon 1 YOK
T1070.001   4688 var, Sysmon 1 YOK
T1003.001   4663 var, Sysmon 11 YOK
T1003.002   4663 var, Sysmon 11 YOK
T1074       Sysmon 11 var, 4663 YOK
```

### 1c'nin en keskin hâli — `T1547.001`

```
olay listesi : [4657, 12, 13]          <- yalnizca REGISTRY
alan         : object.name             <- yalnizca REGISTRY
desen        : (\CurrentVersion\Run|\CurrentVersion\RunOnce|\Start Menu\Programs\Startup)
                                                            ^^^^^^^^^^^^^^^^^^^^^^^^^^
```

**Desen, Başlangıç klasörü varyantını açıkça tanıyor** — yani kuralı yazan
kişi o varyantı biliyordu. Ama o varyant bir **dosya oluşturma** olayıdır
(Sysmon 11, `TargetFilename`), registry değil. Kural kendi deseninin
öngördüğü vakayı, olay listesi ve alan seçimiyle **dışarıda bırakıyor**.

---

## 4. AMPİRİK DOĞRULAMA — ve kazanılmamış sayının ayrılması

Statik taramanın yanında: beklenen tekniğin **kuralı olan** her (kayıt,
teknik) çifti için kural o kayıtta eşleşiyor mu? Korpus 252 kayıt
(S 60 + G 51 + H 15 + 60 senaryo + fixtures).

| durum | sayı | okuma |
|---|---|---|
| **eşleşti** | 26 | |
| kayıt **düzyazı**, olay ID'si yok | **58** | **kural kusuru DEĞİL** — kurallar olay ID'siyle kapılı, düzyazıda olay ID'si yok |
| olay var ama **kural o olayı kapsamıyor** | **12** | sınıf 1c |
| olay kapsanıyor ama **koşul düşüyor** | **6** | sınıf 1a / desen |
| **toplam** | 102 | |

**Ham sayı 76/102 (%75) eşleşmiyor — ama bu kazanılmamış bir sayı.**
58'i düzyazı girdiden geliyor ve orada hiçbir olay-ID kapılı kural
eşleşemez. Ayrı sütunda tutulmazsa katalog gerçekte olduğundan çok daha
bozuk görünür.

**Kazanılmış sayı: olay taşıyan 44 çiftin 18'i (%41) eşleşmiyor** —
12'si olay kapsanmadığı için, 6'sı koşul düştüğü için.

### 4.1 Ayrı bir kapsam bulgusu

Beklenen (kayıt, teknik) çiftlerinin **29'unda kuralın kendisi yok**;
katalog beklentilerin **%78'ini** kapsıyor.

### 4.2 Düzyazı bulgusu — kural kusuru değil, KAPSAM kararı

58 sayısı bir kusur listesi değil, bir olgu: **kural kataloğu düzyazı
girdiye hiçbir katkı yapamıyor**, çünkü her kural `required.event_ids` ile
kapılı. 60 senaryonun 45'i düzyazı. Bu bir kural kalitesi meselesi değil,
kataloğun kapsam tasarımıdır — ama K1 raporunda durması gerekiyor, çünkü
"kurallar neden az ateşliyor" sorusunun asıl cevabı burada.

---

## 5. GÖREV 22'NİN ÜÇ TEKNİĞİ — hangi sınıf?

Görev 22, kanıt kapısının **beklenen tekniği elediği** üç vakayı bulmuş ve
zararın senaryoya değil kurala bağlı olduğunu göstermişti. Sınıfları:

| teknik | kayıt | kaydın olayı | kuralın olayları | **sınıf** |
|---|---|---|---|---|
| `T1685.005` | S-A-10 | `1102` | `[1, 4688]` | **1c** |
| `T1059.001` | S-A-12 | Sysmon `1` | `[4104, 4688]` | **1c** |
| `T1547.001` | S-A-13 | Sysmon `11` | `[4657, 12, 13]` | **1c** |

**Üçü de aynı sınıf: 1c — kural, tekniğin göründüğü olay ailesini
kapsamıyor.** Hiçbiri sınıf 2 (mal etme) ya da sınıf 3 (ayırt edici koşul
yok) değil.

Bu, Görev 22'nin bulgusunu tamamlıyor: kanıt kapısı **doğru çalışıyordu** —
kural gerçekten sağlanmıyordu. Sağlanmamasının sebebi kapının tasarımı
değil, kuralın **yanlış olay ailesine bakması**. Kapının eleme yetkisini
kaldırmak bu üç kuralı düzeltmezdi, yalnızca sonucunu gizlerdi.

Aynı üç teknik geniş korpusta da en çok eşleşemeyenler arasında:
`T1059.001` 10 kayıt, `T1547.001` 5, `T1685.005` 4.

---

## 6. Bu ölçümün SÖYLEMEDİĞİ şey

- **Sınıf 2'nin tam sayısı.** Tarama yalnızca `-flag` / `/flag` biçimli
  jetonlara bakıyor. Alt komut biçimindeki mal etmeler (`reg save`,
  `process call create` gibi) **taranmadı**; oradaki sayı bilinmiyor.
- **Sınıf 1a'nın tam sayısı.** 9 (kural, olay) çifti anlambilim
  kataloğunda olmadığı için sınanamadı.
- **Bir kusurun ne kadar zarar verdiği.** Bu tarama kusurları **sayıyor**,
  etkilerini tartmıyor. `T1110.001`'in tek başarısız girişte ateşlemesi ile
  `T1074`'ün Sysmon eşdeğerini atlaması aynı ağırlıkta sayıldı.
- **Kuralların doğru olup olmadığı.** Eşleşen 26 çiftin **doğru sebeple**
  eşleştiği kontrol edilmedi — bu projede altı kez çıkan "doğru cevap,
  yanlış sebep" deseni burada ölçülmedi.
- **Düzeltme.** Hiçbir kural değiştirilmedi; düzeltme önerisi bilerek
  yazılmadı.

---

## 7. Tek tabloda

| sınıf | ölçüt | sayı |
|---|---|---|
| **3a** | koşul yok, olay ID'si tek başına | 5 kural |
| **3b** | yalnızca ad tabanlı koşul | 6 kural |
| **3c** | yalnızca negatif koşul | 1 kural |
| **3 toplam** | **ayırt edici koşul yok** | **12/49 kural (%24)** |
| **2** | başka tekniğin göstergesini mal etme (doğrulanmış) | 1 kural |
| **1a** | koşulun alanı olayda yok | 4 (kural, olay) |
| **1c** | olayın eşdeğeri listede yok | 8 (kural, olay), 8 teknik |
| **ampirik** | olay taşıyan kayıtta eşleşmeyen | **18/44 çift (%41)** |
| kapsam | beklenen çiftlerin kuralı var | %78 |

---

## 8. DÜZELTME (2026-09-28) — T1685.005'in teşhisi yanlıştı

**Özgün metin yukarıda olduğu gibi duruyor; bu bölüm onu düzeltir, silmez.**

§5 `T1685.005`'i sınıf **1c** saydı ("kural, tekniğin olay ailesini
kapsamıyor"; kayıt 1102, kural [1, 4688]). **Sebep yanlıştı.** 19.2 bilgi
tabanına karşı yapılan katalog taraması (`tests/test_rule_catalog_ids.py`,
K1a) şunu gösterdi:

- `T1685.005` ID'si altındaki kural bir **güvenlik duvarı** kuralıydı
  (`netsh ... firewall ... off`, ad alanı "Disable or Modify System Firewall").
  19.2'de `T1685.005` = **Clear Windows Event Logs**.
- Gerçek günlük temizleme kuralı (1102/104, `wevtutil cl`) **emekli**
  `T1070.001` altında duruyordu; model canlı ID ürettiği için hiç çalışmıyordu.

Yani kapı doğru teknik seçildiğinde onu **yanlış tekniğin koşuluyla**
sınayıp eliyordu. Sonuç (kural sağlanmıyor) doğruydu, sebep yanlıştı —
"doğru cevap, yanlış sebep" deseninin bir örneği daha. Görev 22'nin üç
tekniğinden `T1059.001` ve `T1547.001` için 1c teşhisi geçerliydi (K1d'de
düzeldiler); `T1685.005` için değildi (K1a'da düzeldi).

Ayrıntı ve ölçüm: `docs/beklenti_K1_kural_kalitesi.md` §8.
