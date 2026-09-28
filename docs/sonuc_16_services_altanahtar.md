# Sonuç — Görev 16: `Services\<ad>\Performance` gerçekten `high` mı olmalı?

Ölçüm: `scripts/measure_services_subkeys.py` (LLM/indeks gerekmez)
Çıktı: `evaluation/results/services_subkeys.json`
Kaynak: `docs/sonuc_15_g_kolu_v2.md` §2 — Yol B'nin beş yanlış alarmı

---

## 0. Cevap

**Hipotez çürüdü. Tablo doğru, değiştirilmedi.** Kusur `asset_criticality.yaml`'da
değil, **talep edilen erişim ile gerçekleşen erişimin ayırt edilmemesinde.**

---

## 1. Hipotez neydi

> `Performance` bir servisin sayaç yapılandırmasıdır — kalıcılık noktası
> değil. `ImagePath` kalıcılıktır. Yani kritiklik ALT ANAHTARA bağlı olmalı;
> tablo `Services` altını tek satırla `high` sayarak fazla geniş çiziyor.

Payda ATT&CK seçildi. Gerekçe `measure_criticality_coverage.py`'nin
gerekçesiyle aynı: elde beş gerçek `Performance` satırı var ve **onlara
bakarak tablo düzenlemek** projenin "eşikleri fixture çıktısına bakarak
ayarlamak yasaktır" kuralının ta kendisi olurdu.

---

## 2. Ölçüm — ATT&CK ne diyor

697 canlı teknik metninde `Services\` **14 kez, 9 teknikte** geçiyor:

| teknik | yol |
|---|---|
| T1012 | `Services\Tcpip\Parameters\Interfaces`, `Services\mssmbios\Data\SMBiosData`, `Services\[service name]\Parameters` |
| T1112 | `Services\[service_name]\Start`, `Services\SharedAccess\Parameters\FirewallPolicy\...`, `Services\lanmanserver\parameters\NullSessionPipes` |
| T1505.005 | `Services\TermService\Parameters\` |
| T1543.003 | `Services\DeviceSync\` |
| T1547.003 | `Services\W32Time\TimeProviders\` |
| T1574.011 | `Services\WinSock2\Parameters` |
| T1680 | `Services\Disk\Enum` |
| T1685.001 | `Services\EventLog` |
| T1686 | `Services\SharedAccess\Parameters\FirewallPolicy` |

Alt anahtar adlarının registry bağlamındaki geçişi:

| ad | teknik | değerlendirme |
|---|---|---|
| `ServiceDll` | 4 | kalıcılık — T1112, T1505.005, T1543.003, T1574.011 |
| `Performance` | 3 | **1'i gerçek** (T1574.011); diğer 2'si `\PLA\Server Manager Performance Monitor` adlı ZAMANLANMIŞ GÖREV, registry alt anahtarı değil |
| `ImagePath` | 2 | kalıcılık — T1543.003, T1574.011 |
| `FailureCommand` | 1 | kalıcılık — T1574.011 |
| `TimeProviders` | 1 | kalıcılık — T1547.003 |
| `Enum` | 1 | keşif — T1680 |

> `Performance` için "3 teknik" sayısını olduğu gibi raporlamak yanıltıcı
> olurdu; ikisi kelimenin başka bir bağlamda geçmesi. **İlk ölçümde bu
> filtre yoktu ve `Start` 62, `Data` 339, `Type` 75 teknik çıkıyordu** —
> yani sayım registry'yi değil İngilizceyi ölçüyordu. Filtre eklendi.

### Belirleyici kanıt — T1574.011 `Performance`'ı ANLATIYOR

> *"The **Performance** key contains the name of a driver service..."*
>
> *"If the **Performance** key is not already present and if an adversary's
> user has the Create Subkey permission, adversaries may create the
> **Performance** key in the service's Registry tree to..."*
>
> *"Unauthorized modification of service-related registry keys such as
> ImagePath, FailureCommand, ServiceDll, or **Performance**/Parameters keys."*

ATT&CK'in kendi tespit rehberi `Performance`'ı `ImagePath`, `ServiceDll` ve
`FailureCommand` ile **aynı cümlede** sayıyor. Hipotezin "yapılandırma,
kalıcılık değil" ayrımı yanlış.

---

## 3. Tablo bu ayrımı yapabilecek yapıda mı?

Evet, yapabilir — desen listesi zaten alt anahtar düzeyinde satır kabul
ediyor (`Services\EventLog`, `Services\SharedAccess\Parameters\FirewallPolicy`,
`Services\LanmanServer\Parameters`, `Services\WinSock2\Parameters`,
`Services\W32Time` hepsi ayrı satır) ve **en uzun eşleşen desen kazanıyor.**

Ölçülen 10 alt anahtarın 10'u da tek desene (`...\Services`) düşüyor — ama
bu bir kusur değil, çünkü ölçülen alt anahtarların hepsi ATT&CK'te
kalıcılık/hijack taşıyor. **Ayırt edecek bir şey yok.**

**Karar: tablo DEĞİŞTİRİLMEDİ.** `Services\...\Performance` = `high` doğru
ve kaynaklı (`kaynak: [persist, attack]`).

---

## 4. O hâlde beş alarm neden yanlış?

Ölçüldü:

```
beş alarm satırının olay ID'si : hepsi 4656
QRadar korpusunda 4663 satırı  : 0
QRadar korpusunda 4657 satırı  : 0
```

**4656 bir handle TALEBİDİR.** Proje bunu zaten biliyor ve Görev 3'te
yazmış — `config/event_semantics.yaml`:

> `"4656"` … `islem_sinifi: read`
> **not:** *"Handle TALEBİDİR. Erişimin gerçekleştiğini GÖSTERMEZ —
> gerçekleşen erişim 4663'tür. Tek başına 'okudu' demek fazla ileri
> gitmektir."*

Ama aynı dosyanın başlığındaki kural bunu geçersiz kılıyor:

> *"Bu ayrım erişim maskesinden de türetilir; **ikisi çelişirse maske
> kazanır**, çünkü olay türü genel, maske o kayda özeldir."*

Ve kod bunu koşulsuz uyguluyor — `app/normalization/event_semantics.py`:

```python
"access_class": mask_class or event_class,
```

**Maske 4656'da "talep edilen" erişimdir, gerçekleşen değil.** `0x2001F`
maskesi "bu süreç yazma hakkı İSTEDİ" der; "yazdı" demez. Yol B ise
`erisim_sinifi == "write"`'ı gerçekleşmiş yazma sayıyor.

`describe()`'ın kendi docstring'i bunu farkında olmadan söylüyor: *"maskede
KEY_SET_VALUE varsa o kayıt bir **yazma girişimidir**"* — girişim.
Yol B girişimi eylem gibi okuyor.

**Bu, "maske kazanır" kuralının 4656 için yanlış olduğu anlamına gelir:**
olay türü burada genel bir beyan değil, maskenin NE OLDUĞUNU söyleyen
bağlamdır. Aynı `0x2001F`, 4663'te gerçekleşen yazma, 4656'da yalnızca
istenen haktır.

---

## 5. Neden ŞİMDİ düzeltilmiyor

Üç sebep, üçü de ölçüme dayanıyor:

1. **G korpusu bu düzeltmeyi doğrulayamaz.** 51 satırda 0 tane 4663, 0 tane
   4657 var. Düzeltme yapılsa "beş alarm sustu" görülür ama **sustuğu için
   mi doğru, yoksa her şeyi susturduğu için mi** ayırt edilemez. Bu tam
   olarak projenin iki kez ısırdığı "doğru cevap, yanlış sebep" kalıbı.

2. **Karar/anlambilim katmanı değişikliğidir**, kendi beklenti belgesini
   hak eder: "maske kazanır" kuralı 4656 dışında da geçerli ve tek tek
   olay türleri için gözden geçirilmeli.

3. **Yeni alınmış G tabanını geçersiz kılar.** `g_arm_run_v2.json` bir gün
   önce ölçüldü; ardı ardına iki kez taban değiştirmek karşılaştırmayı
   kaybettirir.

### Bunun yerine: S kolu için BAĞLAYICI şart

**S kolu ayırt edici çifti İÇERMEK ZORUNDA:** aynı kritik anahtara, biri
`4656` (yazma biti taşıyan maskeyle talep) diğeri `4663`/`4657`
(gerçekleşen yazma) olmak üzere iki log. Beklenen kararlar da farklı
olmalı.

Bu çift olmadan düzeltme yazılamaz — çünkü doğru davrandığını gösterecek
ölçüm aracı ortada olmaz. Yani **ölçüm S'e bağımlı, düzeltme ölçüme
bağımlı: doğru sıra S → düzeltme.**

### S raporunda işaretlenecek

S raporu şu cümleyi taşıyacak: *"`4656` + yazma maskesi + kritik anahtar
üçlüsü BİLİNEN bir yanlış alarm kaynağıdır (Görev 16); S'teki oranı
sistemin ayırt etme gücü değil, bu bilinen kusurun sıklığıdır."*

---

## 6. Bu ölçümün ölçmediği

- **`Performance` dışındaki alt anahtarların yanlış alarm oranı.** Korpusta
  yalnızca `Performance` var.
- **"Maske kazanır" kuralının diğer olay türlerindeki doğruluğu.** Yalnızca
  4656 incelendi; 4658/4690/4673 için aynı soru sorulmadı.
- **4656'yı tamamen bastırmanın maliyeti.** Bazı ortamlarda 4663 denetimi
  kapalıdır ve elde yalnızca 4656 olur; talebi tümüyle yok saymak körlük
  yaratabilir. Doğru davranış "yok say" değil, "farklı sınıf olarak taşı"
  olabilir — bu, düzeltmenin beklenti belgesinde karara bağlanacak.
