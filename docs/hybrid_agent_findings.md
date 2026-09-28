# Hibrit ajan katmanı — ölçülen bulgular

Doğrulama katmanının (şartname Bölüm 27) LLM'li yarısı `app/agents/hybrid.py`.
Bu belge, modülün tasarımının **neden bu hâlde olduğunu** ölçümle anlatır.
Üç bulgunun üçü de canlı koşuda (qwen3:8b, `temperature=0`, `seed=42`) çıktı.

## Test kurulumu

8 vaka, iki teknik üzerinde, her tekniğin 2 zararsız + 2 kötücül örneği:

| Teknik | Zararsız | Kötücül |
|---|---|---|
| T1053.005 | OneDrive güncelleyici görevi, Defender tarama görevi | gizli+encoded PowerShell çalıştıran görev, AppData'dan rundll32 |
| T1059.001 | diskteki `.ps1` çalıştırma, AD sorgusu | `-w hidden -enc`, `IEX (DownloadString)` |

8 vaka bir doğruluk ölçümü değildir; tasarım hatalarını görünür kılmak için
yeterli, bir isabet oranı iddia etmek için değildir. Gerçek ölçüm 60 senaryoluk
sete aittir.

## Bulgu 1 — Modelden eylem istenirse kararı gerekçesiyle ters düşüyor

İlk tasarımda şema doğrudan eylem soruyordu: `reject` / `downgrade` /
`abstain`. Sözleşme gereği `confirm` yoktu (LLM onaylayamaz).

Sonuç: model kötücül bir kaydı **doğru** tespit edip gerekçesine
*"saldırganın kalıcılık kurmaya çalıştığını gösterir"* yazdı, ama kararı
`reject` oldu. 4 vakanın 2'sinde tekrarlandı. Sebep: elindeki kelimelerle
"bu gerçekten kötücül, dokunma" diyemiyordu ve `reject`'i *"zararsızdır
iddiasını reddediyorum"* anlamında kullandı. Sözleşme doğruydu, **sözlük**
yanlıştı — ve bu hâliyle doğru bulgular silinecekti.

**Düzeltme:** modelden eylem değil **kanıt sınıfı** isteniyor
(`supports` / `weak` / `absent` / `cannot_tell`); sınıfın hangi eyleme
karşılık geldiğine kod karar veriyor (`_EVIDENCE_TO_ACTION`).

## Bulgu 2 — Şemada alan sırası, yargının kendisini belirliyor

Kısıtlı üretimde (Ollama `format`) model JSON'u **şema sırasına göre** üretir.
`evidence` alanı `reason`'dan önce gelirse, model sınıf kelimesini
gerekçesini yazmadan önce vermek zorunda kalır — koşullanacağı bir muhakeme
yoktur.

| Kurulum | Doğru | Davranış |
|---|---|---|
| `evidence` önce | 4/8 | **8/8 vakada `supports`** — sınıf hep aynı, ayırt etme sıfır |
| `reason` önce | 6/8 | dört zararsız vakanın dördü de doğru `absent` |
| şema yok, serbest metin (önce gerekçe, sonra tek kelime) | 7/8 | — |

`evidence` önce kurulumundaki 4/8, "her zaman `supports` de" politikasının
doğruluğuna eşit; yani bilgi taşımıyor.

Ayrıca elenen iki hipotez: enum sırasını ters çevirmek (`absent` başa) ve
istemden teknik ID'sini kaldırmak **hiçbir şeyi değiştirmedi** — 24 çağrının
24'ü `supports` geldi. Yani sorun demirleme ya da onaylama eğilimi değil,
gerekçeden önce taahhüt ettirilmesiydi.

**Düzeltme:** `reason` şemada `evidence`'tan önce. `tests/test_agents_hybrid.py`
bunu kilitliyor (`test_reason_comes_before_evidence_in_the_schema`).

## Bulgu 3 — LLM'e silme yetkisi verilemez

`reason` önce kurulumundaki 2 hatanın **ikisi de** kötücül vakayı `absent`
saymaktı (gizli encoded PowerShell çalıştıran zamanlanmış görev dahil).
`absent` → eleme eşlemesi yapılsaydı, doğru bulguların yarısı silinirdi.

**Düzeltme:** hiçbir kanıt sınıfı `REJECT`'e eşlenmiyor. `absent` yalnızca
güveni `low`'a düşürüyor. Gerekçe: eleme geri dönüşü olmayan bir işlemdir ve
bir insanın okuyabileceği bir kurala dayanmalıdır. **Silme yetkisi
deterministik ajanlarda** (regex, kutupsallık, bilinen-iyi listeleri) kalıyor;
olasılıksal bir yargıcın yapabileceği en fazla şey güveni düşürmek — görünür,
geri alınabilir ve bulgu "Doğrulama Gerektiren Zayıf Sinyaller" bölümüne
düşer, kaybolmaz.

## Son durum

Aynı 4 vakalık duman testinde düzeltilmiş modül: 4/4 doğru — iki zararsız
vaka `absent` → güven `low`, iki kötücül vaka `supports` → bulguya
dokunulmuyor. Çağrı başına ~5 sn.

## Katman varsayılan olarak KAPALI

`DETERMINISTIC_AGENTS` değişmedi; değerlendirme koşuları ve 537 testin tamamı
ağ erişimi olmadan çalışıyor. Hibrit katman açıkça seçilir:

```python
from app.agents.hybrid import agents_with_llm
verify_mappings(mappings, rows, agents=agents_with_llm())
```

`agents_with_llm()` düz toplama değildir: hibrit ajan sardığı deterministik
ajanı zaten kendi içinde çalıştırdığı için, sarılan ajan listeden çıkarılır —
aksi hâlde aynı kontrol iki kez çalışır ve denetim izinde iki bağımsız kontrol
varmış gibi görünür.
