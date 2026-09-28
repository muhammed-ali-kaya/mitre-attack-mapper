# Karar — Görev 22: `wip/verification-graph` dalı

**Bu bir KARAR belgesidir.** Dal 2026-08-16'dan beri açıktı; iki değişiklik
taşıyordu ve gerekçeleri o günün ölçümüne dayanıyordu. Aradan Görev 15, 17,
18, 19, 20 geçti. **Sayılar yeniden ölçüldü ve ikisi ayrı kadere gitti.**

Tarih: 2026-09-02.

---

## 0. Karar

| değişiklik | karar |
|---|---|
| `graph.py` — üçüncü döngü tetikleyicisini kaldır | **UYGULANDI** |
| `verification.py` — kanıt kapısı `REJECT` → `DOWNGRADE` | **REDDEDİLDİ** |

Dal artık kapatılabilir: taşıdığı iki değişiklikten biri alındı, diğeri
gerekçesiyle reddedildi. **Açık dal bırakılmıyor.**

## 1. Nasıl ölçüldü — LLM çağrılmadan

Dalın gerekçesi 60 senaryoluk ablasyona dayanıyordu ve o koşunun kaydı yok;
yeniden koşmak ~75 dk sürerdi. Ama iki katman da **deterministik**:

- **Kanıt kapısı**: `(mappings, rows, rules)` verilince aynı kararı üretir.
  `rows`, `text_to_row` ile ham girdiden yeniden üretildi; `mappings`,
  kayıtlı koşuların `mappings_before_agents` alanından alındı.
- **Döngü tetikleyicisi**: kayıtlı koşular `loop_passes`,
  `rejected_mappings`, `agent_rejected_mappings` ve `mappings` alanlarını
  zaten tutuyor.

Korpus: **126 kayıt** (S 60 + G 51 + H 15) — dalın dayandığı 60 senaryodan
hem daha yeni hem daha büyük.

---

## 2. `verification.py` — REDDEDİLDİ

### 2.1 Dalın iddiası

> Kapı yanlış POZİTİF avlamak için yazılmıştı; ölçtüğümüzde yaptığı şey
> yanlış NEGATİF üretmekti. 7 senaryo değişti, **4'ü kötüleşti, 0'ı
> iyileşti**; dördün üçünde elediği şey tam olarak beklenen teknikti.

### 2.2 Bugün ölçülen

126 kayıtta kapı **83 karar** üretti (17 confirm, 57 reject, 9 abstain) ve
**150 teknikte sustu** (kural yok).

Elemelerin ayrımı:

| | sayı | okuma |
|---|---|---|
| **beklenen tekniği eledi** | **3** | yanlış negatif — dalın korktuğu şey |
| beklenmeyeni eledi, kayıtta beklenti VAR | **10** | kazanılmış yanlış pozitif avı |
| beklenmeyeni eledi, kayıt NEGATİF (beklenti boş) | 44 | **kazanılmamış** — negatif kayıtta her eleme bedavaya iyi görünür |

**Kazanılmış oran 10 lehte / 3 aleyhte.** Dalın "4 kötüleşti, 0 iyileşti"
tablosu bugün **yeniden üretilmiyor.**

44'ü ayrı sütunda tutmak zorunlu: bunların 24'ü tek bir teknik
(`T1686.003`), 9'u `T1543.003`. Yani "kapı ayırt ediyor" değil, "LLM iki
tekniği ısrarla öneriyor, kapı ısrarla siliyor". Aynı sütuna katılsaydı
oran 54/3 görünürdü ve bu, bu projede altı kez ölçüm kirleten desen olurdu.

### 2.3 Asıl bulgu: zarar KAPININ TASARIMINDA değil, ÜÇ KURALDA

Beklenen tekniği elenen üç kayıt:

```
S-A-10   T1685.005    (beklenen: T1685.005)
S-A-12   T1059.001    (beklenen: T1027, T1059.001)
S-A-13   T1547.001    (beklenen: T1547.001)
```

**Bunlar dalın adını verdiği üç teknikle BİREBİR AYNI** — dal
`rawlog-009 → T1685.005`, `injection-001 → T1059.001`,
`rawlog-008 → T1547.001` demişti. Farklı korpus, farklı kayıtlar, **aynı üç
teknik**.

Yani zarar senaryoya değil **tekniğe** bağlı ve tekrarlanabilir: bu üç
kuralın koşulları meşru kanıtla eşleşmiyor. Bu bir **kural kalitesi**
kusurudur (`K1`), kapının mimarisi değil.

**Kapının eleme yetkisini kaldırmak, üç bozuk kuralı düzeltmek yerine
mekanizmayı susturmak olurdu** — yöntem maddesi 4'ün tam konusu:
*"bir mekanizmaya bastırıcı yazılmışsa, o mekanizma fazla ateşliyordur"*
sorusunun tersi burada geçerli: mekanizma doğru ateşliyor, üç kural yanlış.

### 2.4 Reddin sınırı — dürüstlük kaydı

Bu ölçüm dalın ölçümüyle **aynı metrik değil**. Dal uçtan uca
`hierarchical_score` deltası ölçmüştü; bu ölçüm elemeleri beklenen listeye
karşı sayıyor. "Beklenmeyeni eledi" ≠ "sonucu iyileştirdi".

Söylenebilecek şey: **dalın dayandığı olgu (kapı çoğunlukla beklenen
tekniği eliyor) bugün doğru değil.** Söylenemeyecek şey: "kapı skoru
yükseltiyor" — o ölçülmedi.

---

## 3. `graph.py` — UYGULANDI

### 3.1 Dalın iddiası

Üçüncü tetikleyici (*"geçenlerin hepsi düşük güvenli"*) iç gürültüye tepki
veriyor: güveni zaten ajan katmanının kendisi düşürüyor. **Bir geri besleme
döngüsünün tetiği, döngünün kendi çıktısı olamaz.**

### 3.2 Bugün ölçülen — gerekçe ZAYIFLAMADI, GÜÇLENDİ

126 kayıt, kayıtlı koşulardan:

```
döngü koşan kayıt          105/126  (%83)
tetikleyici 1 veya 2        59
YALNIZCA tetikleyici 3      46      (döngülerin %43'ü)
tur başına ek süre          52 sn   (medyan 50 -> 102)
46 x 52 sn                  ~40 dk
```

İlk ölçüm (2026-08-16) tetiklenme oranını **%63.8** bulmuştu; bugün **%83**.

### 3.3 Kazanç tarafı BUGÜN ölçülmedi — kayıt açık

Eski ablasyon döngünün `hierarchical_score` katkısını **+0.0018** bulmuştu
ve o sayı 2026-08-16 kodundan geliyor. Bugünkü kazancı ölçmek 126 kaydın
LLM ile yeniden koşulmasını gerektirirdi.

**Yani bu değişiklik ÖLÇÜLMÜŞ MALİYETE ve ESKİ ölçülmüş (~0) kazanca
dayanıyor.** Yapısal argüman (tetik, döngünün kendi çıktısı olamaz) bundan
bağımsız olarak geçerli.

---

## 4. Dal neden OLDUĞU GİBİ uygulanamadı

`git diff agentic-simplification wip/verification-graph` **39.046 satır
silme / 129 dosya** gösteriyor. Dal 2026-08-16'da dallandı; o günden sonra
gelen Görev 14–20'nin tamamı dalda yok. Birleştirmek `decide` düğümünü,
olay bölücüyü, parser düzeltmelerini ve altı test dosyasını silerdi.

Değişiklik bu yüzden **cerrahi olarak** bugünkü dosyaya uygulandı, dosya
kopyalanarak değil. Dalın `graph.py`'sini olduğu gibi almak **11 test**
kırdı; cerrahi uygulama **3** kırdı ve üçü de kaldırılan tetikleyicinin
kendi testleriydi (HANDOFF bunu önceden yazmıştı).

## 5. Kırılan üç test — silinmedi, yeniden yönlendirildi

| test | ne yapıldı |
|---|---|
| `test_refine_when_every_survivor_is_weak` | **Politika testi**: artık `done` bekliyor, adı `test_hepsi_zayif_TEK_BASINA_ikinci_tura_CIKARMAZ`. Docstring değişimin ölçümünü taşıyor. |
| `test_second_pass_cannot_lose_first_pass_findings` | Asıl iddiası tur **birleştirme**; "hepsi zayıf"ı yalnızca ikinci turu zorlamak için kullanıyordu. Geçerli tetikleyiciye (eleme) bağlandı. **Kapsam kaybı yok.** |
| `test_second_pass_findings_are_added_to_the_first` | aynı |

Ayrıca **yeni bir koruma testi** eklendi:
`test_zayif_olsa_da_ELEME_varsa_ikinci_tura_CIKILIR` — bu olmasa değişiklik
"döngü tamamen öldürüldü" diye okunabilirdi.

**1307 test geçiyor** (1306 → +1).

## 6. Bu kararın ÖLÇMEDİĞİ şey

- **Döngünün bugünkü kazancı.** §3.3.
- **Kapının uçtan uca skor etkisi.** §2.4.
- **Üç bozuk kuralın kaçta kaç olduğu.** `T1685.005`, `T1059.001`,
  `T1547.001` ölçüldü; katalogda başka kaç kuralda aynı kusur var
  **bilinmiyor** — bu `K1`'in konusu ve açılmadı.
