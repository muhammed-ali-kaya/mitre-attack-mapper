# Beklenti 26 — Toplu mod sohbeti (incident veri sorgusu)

**Kod yazılmadan önce yazıldı** (madde 1). Kapsam kullanıcı tarafından
ölçüm sonrası onaylandı: **P2 paketi**.

## Ne bu, ne değil

Tekli moddaki sohbet **açıklama** yapıyor ("bu teknik neden seçildi").
Toplu moddaki sohbet **veri sorgusu** cevaplayacak: "hangi satırlardan
geldi", "11:28'de ne oldu", "risk neden 26", "neden 22 sinyal zayıf".
**Cevaplar JSON'da zaten var** — modelin işi hesaplamak değil, bulmak
ve okunur biçimde söylemek.

`app/llm/chat_assistant.py` **kopyalanmayacak**: `build_chat_context`
tek satır analizinin (`mappings`, `rejected_mappings`, `input_summary`)
şeklini okuyor, incident dict'inin anahtarları bambaşka. Yeniden
kullanılan: `chat_turn` (taşıma) ve arayüz döngüsü deseni.

## Bağlam — ÖLÇÜLDÜ, P2 seçildi

Bütçe: `6144` (num_ctx) − `720` (geçmiş) − `700` (yanıt) = **4724 token**.
`num_ctx` BÜYÜTÜLMEYECEK: `DETERMINISTIC_OPTIONS`ta analiz hattıyla
paylaşılıyor ve VRAM 8GB (aynı kısıt için bkz. `app/retrieval/reranker.py`).

Ölçüm (`scripts/measure_bulk_chat_context.py`, gerçek `prompt_eval_count`):

| paket | token | durum |
|---|---|---|
| P0 (kesintisiz) | 7.169 | taşıyor (+2.445) |
| P1 | 4.565 | %97 dolu — marj yetersiz |
| **P2** | **3.471** | **%73 dolu — seçilen** |
| P3 | 4.579 | %97 dolu |

P2 = timeline **gruplu** (aynı olay tek satırda), kapsam **çıplak**
(taktik + eksik ID), zayıf sinyaller **kompakt** (ID + sayı), IOC
**bağlam dışı**.

### Ö1 — birleştirilmiş gerçek bağlam ≤ 4724

Yukarıdaki 3.471 bir **prototipten** ölçüldü. Asıl kod başka bir metin
üretebilir. Kapanış ölçütü: `build_bulk_chat_context`in GERÇEK çıktısı
gerçek koşu dosyasında ölçülecek ve **4724'ü aşmayacak**. Aşarsa kapsam
daha da daraltılır, eşik gevşetilmez (madde 14).

## Ö2 — taşma SESSİZ OLMAYACAK (madde 16'nın sohbet karşılığı)

Ollama `num_ctx`i aşan prompt'u **sessizce kırpar**. Sessizce bozuk
çalışan bir katman istemiyoruz.

İki katmanlı sayaç:

1. **Gönderimden ÖNCE**: kaba tahminci. Bütçe aşılıyorsa çağrı
   **yapılmaz**, arayüzde "sohbet geçmişi doldu, yeni sohbet başlatın"
   uyarısı çıkar. Boşa 30 saniye harcanmaz.
2. **Gönderimden SONRA**: `usage_since()` Ollama'nın döndürdüğü
   **gerçek** `prompt_eval_count`'u verir — tahmin değil. Gerçek sayı
   bütçeyi aşmışsa uyarı yine çıkar (tahminci yanılmış demektir).

**Ö2a — tahminci ASLA az saymamalı.** Az sayan bir tahminci, taşmayı
kaçırır; çok sayan yalnızca erken uyarır. Ölçülmüş yedi bölümün gerçek
token sayıları `evaluation/results/bulk_chat_context.json`de duruyor;
test tahmincinin bu yedisinin hiçbirinde gerçek sayının **altında**
kalmadığını doğrulayacak.

## Ö3 — IOC "sorulunca" tek turda, ikinci LLM turu YOK

Kullanıcının sınırı: ikinci bir tur süreyi ikiye katlar, o zaman
yapılmasın. Bu yüzden niyet tespiti **deterministik**: soruda IOC
terimleri (`ioc`, `ip`, `hash`, `domain`, `artefakt`...) geçiyorsa **o
turda** bağlama IOC özeti eklenir ve **timeline çıkarılır** — yer açılır,
tur sayısı değişmez.

Ö3 ölçütü: IOC'lu varyant da 4724'ü aşmayacak. Aşarsa özellik
**yapılmaz** ve arayüzde "IOC listesi ekranda, sohbet kapsamı dışında"
denir — yarım bırakılmaz.

## Ö4 — sınır prompt'ta AÇIK, ama tek savunma değil

Prompt açıkça yasaklayacak: yeni ATT&CK tekniği/ID yok, yeni eşleştirme
yok, risk skoru **yeniden hesaplanmaz**, ekranda olmayan sayı üretilmez.

Prompt tek başına yetmez. Asıl savunma: **bağlam zaten hesaplanmış
cümleleri taşıyor.** Risk bölümü `risk_score.breakdown_sentences`
çıktısıdır ("15 ATT&CK fazından 2 tanesi görüldü → +4"), eşik cümlesi
`dedup.confidence_threshold_sentence`ten gelir. Modelin yapacağı iş
hesaplamak değil **alıntılamak**. Sayıyı üretmediği sürece yanlış
üretemez — oturumun karar katmanı ilkesinin sohbet tarafındaki karşılığı.

## Ö5 — sohbet incident'a BAĞLI

Toplu modda N incident var. `session_state` anahtarı incident id'sini
taşıyacak; yoksa "risk neden 26" hangi incident'ın sorusu belirsiz olur.
Yeni sonuç yüklendiğinde geçmiş sıfırlanır (tekli moddaki davranış).

## Kapsam dışı — kasıtlı

- Yeni bir analiz/eşleştirme akışı yok.
- Satır bazlı ham log dökümü bağlama girmiyor (ekranda duruyor).
- LLM'e niyet sınıflandırması yaptırılmıyor (deterministik anahtar
  kelime; ikinci tur maliyeti yok).

## Süre sınırı

2 saat. Aşılırsa özellik **tamamen iptal** edilir ve sunumda
gösterilmez — yarım çalışan bir sohbet demo sırasında saçma cevap
verirse anlatıyı bozar (kullanıcı kararı).

---

# SONUÇ — ölçüldü (2026-09-04)

## Ö1 — GEÇTİ: bağlam 4.558 token (bütçe 4.724)

Prototipin 3.471'i değil, **gerçek kodun çıktısı** ölçüldü. Aradaki fark
iki yerden: gruplu timeline'a teknik etiketleri eklendi ("hangi
satırlardan geldi" bu sohbetin ana sorusu) ve prompt canlı denemeden
sonra sertleştirildi (+~350 token, aşağıda).

| | gerçek | tahmin |
|---|---|---|
| normal (timeline'lı) | **4.558** | 5.156 |
| IOC turu (timeline yok) | **3.093** | 3.742 |

## Ö2 — GEÇTİ, ama iki kusur bulundu ve düzeltildi

**Kusur 1: geçmiş İKİ KEZ sayılıyordu.** `budget_status` `TOKEN_BUDGET`e
bakıyordu — geçmiş hem `RESERVE_HISTORY` düşülerek hem üstüne eklenerek.
Sonuç: **ilk mesajda bile** "geçmiş doldu" uyarısı. Yanlış alarm veren
uyarı, uyarı değil gürültüdür (madde 11). Ayrıldı: `TOKEN_BUDGET` =
tasarım bütçesi (bağlam tek başına), `INPUT_LIMIT` = çalışma zamanı
sınırı (bağlam + geçmiş).

**Kusur 2: sabit oranlı tahminci %13 fazla sayıyordu** (4.558 → 5.156).
İkinci turda yanlış alarm verirdi. Ollama zaten her çağrıda gerçek
`prompt_eval_count` döndürüyor; o oran bir sonraki tura taşınıyor
(`calibration_ratio`). Sapma **+588 → +109**'a düştü. Kalibrasyon
tabanla (asla az saymaz) ve tavanla (bozuk ölçüm tahminciyi kör edemez)
sınırlı.

## Kapsam gerçekten dar: pencereye ~1.600 token kalıyor

Bağlam 4.558, pencere 6.144. Tüm geçmişi taşımak **üçüncü turda**
sohbeti bitiriyordu. Çözüm: `trim_history` eski turları düşürür.

Meşru, çünkü bunlar **bağımsız veri sorguları** — "T1205.002 hangi
satırlardan geldi" için önceki cevaba ihtiyaç yok. **Düşen tur sessiz
değil:** kaç mesajın gönderilmediği arayüzde yazıyor. En son soru asla
düşmez; tek başına sığmıyorsa bütçe uyarısı çıkar, sessizce kırpılmaz.

Sekiz turluk gerçek koşu (canlı Ollama): pencere hiç aşılmadı.

```
tur 1: 4.581/6144  düşen 0    tur 5: 5.357/6144  düşen 4
tur 2: 4.953/6144  düşen 0    tur 6: 4.747/6144  düşen 8
tur 3: 5.223/6144  düşen 0    tur 7: 4.906/6144  düşen 8
tur 4: 5.294/6144  düşen 0    tur 8: 5.053/6144  düşen 8
```

## Ö3 — GEÇTİ: IOC tek turda, ikinci LLM turu yok

`wants_ioc` deterministik anahtar kelime. IOC turunda timeline çıkıyor,
bağlam **3.093** token'a düşüyor. Timeline'ın çıktığı bağlamda açıkça
yazılı ki model kullanıcıya söyleyebilsin.

## Ö4 — CANLI DENENDİ: altı sorunun dördü ilk denemede kusursuz

Gerçek Ollama, gerçek incident. Süre 3-23 sn.

**Çalışan:** "risk neden Medium" cevabı bileşenleri **birebir aktardı**
(+4, +9, +13,08 → 26/100). Model toplamak zorunda olmadığı için yanlış
toplamadı — "hesaplamaz, alıntılar" tasarımı işe yaradı. "T1205.002
hangi satırlardan geldi" → `[13, 21, 31, 49, 50]`, birebir doğru.
"11:28'de ne oldu" → svchost.exe, T1546.003, satır [12, 24], doğru.

**İki kusur bulundu ve prompt sertleştirildi:**

1. **"Zayıf sinyaller ELENMİŞ" dedi** — bağlamda `ELENMEDILER` yazmasına
   rağmen. Bu projenin en çok koruduğu ayrım. Prompt'a yasak kelimeler
   ("elendi", "elenmiş", "çıkarıldı") ve doğru ifade açıkça yazıldı.
2. **10 değerlendirilemeyen taktikten 6'sını saydı.** Sebep muhtemelen
   şu görünür çelişki: Persistence ve Privilege Escalation hem zincirde
   hem "değerlendirilemeyen" listesinde. Çelişki değil — zincir olay ID
   şart koşmayan kurallardan da besleniyor, kapsam ise o taktiği görecek
   olay ID'sinin veri setinde olup olmadığını soruyor. Bu ayrım prompt'a
   yazıldı; ayrıca "liste sorulursa tamamını ver, eleme yapma".

Sertleştirmeden sonra ikisi de düzeldi: 10 taktiğin 10'u listelendi,
zayıf sinyal cevabı eşiği ("yüksek, orta") aktardı ve "ana anlatıya
alınmadı" dedi.

**Uydurma bulunmadı.** "Defense Impairment" ilk bakışta uydurma
sanılmıştı; `tactic_labels`ta gerçek bir taktik adı olduğu doğrulandı.

## Ö5 — sohbet incident'a bağlı

`session_state` anahtarı `bulk_chat_{incident_id}`; kalibrasyon da aynı
anahtara bağlı ve "Sohbeti temizle" ikisini birden sıfırlıyor.

## Test 1372 → 1408 (+36). Görev 25'in Ö0'ı hâlâ geçiyor.
