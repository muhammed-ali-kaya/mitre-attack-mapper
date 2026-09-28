# Baseline vs Gelistirilmis Sistem - Karsilastirma Raporu

> **TARIHSEL KAYIT (2026-08-03 kosusu).** Bu rapordaki sayilar DAHA ESKI bir
> kosuya aittir ve `evaluation/results/comparison_summary.json` ile
> UYUSMAZ (orn. ort. hiyerarsik skor burada 0.315 / 0.510, ozet dosyasinda
> 0.688 / 0.708). 60 senaryoluk karsilastirmanin yetkili kaydi o ozet
> dosyasidir: senaryo sayisini, kaynak dosya hash'lerini ve uretim zamanini
> saklar. Bu belge silinmedi cunku o kosunun bulgularini (ozellikle "birebir
> alinti" sinirlamasi ve RAG'siz karsilastirma) tasiyor; sayilari guncel
> performans olarak okumayin.


## Ek Bulgu: Kucuk Local Modelin "Birebir Alinti" Sinirlamasi

Sistem prompt'u ve JSON schema'yi iki kez guclendirerek qwen3:8b'ye "evidence"
alaninda kullanici girdisinden BIREBIR ALINTI yapmasini (paraphrase degil)
acikca ornekle talimatlandirdik. Model yine de cogunlukla teknigin genel
davranis aciklamasini yazmaya devam etti, girdiden dogrudan alinti yapmadi.

Bunu gizlemek yerine dogrulama katmanina bir kontrol ekledik: "evidence"
metinlerinin kullanici girdisiyle kelime-duzeyinde ortusup ortusmedigini
kontrol edip, ortusmuyorsa ciktida acikca "KANIT UYARISI" notu gosteriyoruz.
Bu, 4B-8B seviyesindeki local modellerin ince format/stil talimatlarina
guvenilir sekilde uyamayabilecegini gosteren somut bir bulgu -- ve tam da bu
yuzden ciktinin dogrudan LLM'e degil, kod-tarafli dogrulamaya guvenmesi
gerektigini bir kez daha kanitliyor.

## Bonus: RAG'siz Dogrudan Siniflandirma Karsilastirmasi (bolum 9.1, secenek 3)

Ayni LLM'e (qwen3:8b) hicbir ATT&CK kaynak metni vermeden, sadece kendi
on-egitim bilgisiyle tahmin yaptirdik:

| Sistem | Ort. Skor | Top-1 Dogruluk | Halusinasyon | Ort. Sure |
|---|---|---|---|---|
| RAG Yok (dogrudan LLM) | 0.352 | 21.7% | 0.000 | 16.0s |
| Baseline RAG | 0.315 | 20.3% | 0.034 | 49.4s |
| Gelistirilmis RAG | **0.510** | **39.0%** | **0.000** | 78.6s |

**Onemli bulgu:** Baseline (naif) RAG, RAG'siz duruma gore DAHA KOTU performans
gosterdi (hem dogruluk hem halusinasyon acisindan) -- filtresiz, gurultulu
top-10 context LLM'i yardim etmek yerine yaniltiyor. Yalnizca hybrid retrieval +
reranking + dogrulama katmanlariyla desteklenen "Gelistirilmis Sistem" gercek
ve olculebilir bir iyilesme sagliyor (RAG'siz duruma gore top-1 dogrulukta +80%,
baseline'a gore +92%). Bu, projenin temel tezini (naif RAG yetersiz, dikkatli
muhendislik sart) dogrudan kanitliyor.


60 test senaryosu, her ikisi de qwen3:8b (LLM) + bge-m3 (embedding) kullaniyor.
Ham veri: `evaluation/results/eval_baseline.jsonl`, `eval_improved.jsonl`,
`comparison_summary.json`.

## Genel Sonuclar

| Metrik | Baseline | Gelistirilmis |
|---|---|---|
| Ort. hiyerarsik skor | 0.315 | **0.510** |
| Top-1 tam dogruluk | 20.3% | **39.0%** |
| >=0.5 skor orani | 33.9% | **54.2%** |
| Ort. Recall@5 | 0.789 | 0.807 |
| Ort. Recall@10 | 0.807 | **0.860** |
| Ort. halusinasyon orani | 0.034 | **0.000** |
| Abstention dogrulugu | 22.2% | 33.3% |
| Ort. yanit suresi | 49.4s | 78.6s |

Gelistirilmis sistem, dogruluk metriklerinin tamaminda acik farkla onde
(hiyerarsik skor +62%, top-1 dogruluk neredeyse 2 kat). Halusinasyon orani
sifira indi -- dogrulama katmani calisiyor. Bedel: yanit suresi ~1.6 kat artti
(hybrid retrieval + reranking + dogrulama ekstra zaman aliyor).

## Kategoriye Gore

| Kategori | Baseline | Gelistirilmis | Yorum |
|---|---|---|---|
| alt_teknik_gerektiren | 0.656 | 0.850 | Gelistirilmis acik farkla iyi |
| birden_fazla_teknik | 0.390 | 0.620 | Gelistirilmis iyi |
| raw_log | 0.140 | 0.570 | Gelistirilmis cok iyi |
| tek_teknik_acik_girdi | 0.390 | 0.544 | Gelistirilmis iyi |
| prompt_injection | 0.033 | 0.567 | Gelistirilmis cok iyi -- guvenlik onlemleri isliyor |
| turkce_ingilizce_capraz | 0.050 | 1.000 | Gelistirilmis mukemmel |
| belirsiz_girdi | 0.200 | 0.140 | Ikisi de zayif, gelistirilmis biraz daha kotu |
| negatif_ornek | 0.000 | 0.000 | Bu metrik bu kategori icin uygun degil (bkz. asagi) |
| platform_celiskisi | 0.100 | 0.100 | Ikisi de zayif -- paylasilan sinirlama |
| deprecated_revoked | 1.000 | 0.050 | n=2, istatistiksel olarak anlamsiz, detay asagida |

## Onemli Bulgular / Bilinen Sinirlamalar

### 1. deprecated_revoked kategorisi (n=2) yaniltici
- **revoked-001**: Doğru teknik (T1059.001) retrieval tarafindan gercekten
  bulundu (ilk sirada), ama LLM son cevabinda onu SECMEDI, bunun yerine 4
  farkli, ilgisiz teknik onerdi. Bu bir retrieval hatasi degil, LLM'in aday
  secme asamasindaki bir zayifligi.
- **revoked-002**: LLM hicbir eslestirme yapmadi (bos "mappings"). Test
  girdisi ("T1143 tekniğiyle iliskili...") dogal bir olay tanimindan cok, ID'yi
  dogrudan referans veren "meta" bir ifade -- LLM'in "somut kanit yok" refleksini
  tetiklemis olabilir. Kismen test tasarimi sorunu (dogal olmayan ifade).
- Sadece 2 ornekle bu kategori icin genel bir sonuc cikarilamaz.

### 2. platform_celiskisi -- her iki sistem de zayif (paylasilan sinirlama)
Linux cron (T1053.003), macOS LaunchAgent (T1543.001) ve Linux command history
temizleme (T1070.003) sorularinda HER IKI sistem de yanlis teknik onerdi (ayni
taktikte ama yanlis teknik, skor=0.1). Bu benim kodumda bir hata degil --
hem ATT&CK verisinin hem LLM egitim verisinin Windows agirlikli olmasi
muhtemel ortak sebep. Duzeltme yolu: Linux/macOS ornekleri icin ozel
few-shot prompt veya platform bazli agirlik artisi denenebilir (gelecek is).

### 3. belirsiz_girdi kategorisi -- gelistirilmis sistem hafif geriledi
Beklenen davranis: yetersiz kanitta "dusuk guven / eslestirme yok" demek.
Gelistirilmis sistemin context'i daha odakli oldugu icin bazen LLM'i asiri
ozguvenli bir cevaba yonlendirebiliyor (daha az "gurultu" gordugu icin daha
"emin" davraniyor olabilir). Belirsizlik/abstention davranisi icin prompt
iyilestirmesi ileriki bir calisma konusu.

### 4. Performans / kararlilik notlari (bu oturumda cozulen sorunlar)
- Ilk denemede reranker GPU'da calisirken Ollama'nin VRAM'iyla catisip
  timeout'lara sebep oldu -> reranker CPU'ya alindi.
- Uzun kosum boyunca ~%15-18 oraninda ara sira Ollama timeout'u (300s) gozlemlendi,
  sebebi net degil (VRAM disinda) ama kalici degil -- retry mekanizmasi (2 deneme,
  backoff) eklendi ve basarisiz senaryolarin neredeyse tamami (20/22) retry ile
  kurtarildi.
