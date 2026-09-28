# Beklenti — 2A(b): katmanlı sorgunun eşiği

**Kod yazılmadan ve sıralamalar ölçülmeden önce yazıldı.** Amacı, ölçüm
gelince "evet zaten böyle olmalıydı" demeyi imkânsız kılmak.

Açık soru: `(b)` **gerekli mi?** "Eşik gerekmedi" geçerli bir sonuçtur, hatta
tercih edilenidir — eşik parametresi ayarlanabilecek bir şeydir, ayarlanabilir
her şey aşırı uyum kapısıdır.

---

## Tasarım girdisi (ölçüldü, sonuç değil)

`(b)`'nin dal yüzeyi olup olmadığı yapısal bir sorudur; sıralamalara bakmadan
ölçülür. Ölçüldü:

```
1. katman DOLU : 15 / 60
1. katman BOS  : 45 / 60
  bos olanlarda ham loga TAM geri dusen : 45
  YALNIZCA 2. katman kalan              : 0
```

45 senaryonun **hepsinde** `build_layered_query`, `"\n\n".join(...) or raw_text`
geri dönüşüyle ham metne düşüyor. 2. katman da boş çünkü bunlar serbest metin /
düzyazı girdiler — ayrıştırılacak olay kimliği yok. **"Yalnızca 2. katman
kaldı" vakası hiç yok** — koşullu mantığın en korktuğum senaryosu
(sorgunun `"Yeni bir surec olusturuldu"` gibi 40 karakterlik bir ifadeye
inmesi) bu veride gerçekleşmiyor.

### Bunun doğrudan sonucu

Koşullu `(b)` ile koşulsuz D **yalnızca 45 senaryoda** ayrışabilir, ve orada
tek fark A'nın geriye kalan zenginleştirmesidir (`platform` + `remote_execution`
terimleri; teknik adı tablosu Ö1'de kaldırıldı). Geri düşüş zaten kodda değil,
**verinin kendisinde** oluyor.

Yani asıl karar `(b)` değil: **1. katmanın dolu olduğu 15 senaryoda ham logu
atmak doğru mu?**

---

## Kollar

| kol | tanım |
|---|---|
| **A** | `build_enriched_query` — ham log + kalan zenginleştirme |
| **D** | `build_layered_query(include_raw=False)` — koşulsuz varsayılan adayı |
| **D+ham** | `build_layered_query(include_raw=True)` — 3. katman duruyor |
| **(b)** | koşullu: 1. katman doluysa D, değilse A |

`D+ham` üçüncü kol olarak **eklendi**: 15 senaryoda ham logu atma kararı
`(b)`'den daha sonuçlu, ve ölçülmeden varsayılamaz.

---

## Birincil ölçü — ortalama DEĞİL

`rawlog-005` kanıtladı: 60 senaryoluk ortalamadaki `10.2 → 14.0` farkının
tamamı tek senaryodan geliyordu (196/60 ≈ 3.3). Sıra ortalaması aykırı
değerden etkileniyor.

Sıra ile:

1. **Kapsama kaybı** — beklenen teknik kaç senaryoda top-20'den düştü *(birincil)*
2. **Medyan sıra** — aykırı değere dayanıklı
3. **Bulunma sayısı** — ilk 300'de var mı
4. Ortalama sıra — yalnızca bağlam için, karar vermez

---

## Beklentiler

| # | beklenti | tutmazsa ne öğrenilir |
|---|---|---|
| 1 | **45 boş-katman senaryosunda A ≈ D.** Fark yalnızca `Ilgili terimler: Windows` benzeri kalıntıdan gelebilir; kapsama kaybı **0** olmalı | Kalan zenginleştirme (platform/remote) sanılandan etkili demektir; o zaman kaldırılan tablo değil **kalanı** incelenmeli |
| 2 | **`(b)` ile koşulsuz D arasında ölçülebilir fark çıkmaz.** Çünkü ayrışabilecekleri tek yer o 45 senaryo ve orada zaten aynı ham metne düşüyorlar | `(b)`'nin savunulabilir bir yüzeyi var demektir; o zaman eşik ölçümden türetilir |
| 3 | **Karar 15 senaryoda düğümlenir** — D vs D+ham. Hangisinin kazanacağına dair **öngörüm yok**; ham log hem bağlam veriyor hem seyreltiyor, iki etki zıt yönde | — |
| 4 | 15 senaryonun çoğu `raw_log` + yapılandırılmış girdi; `single`/`multi`/`ambig` kategorilerinin **tamamı** boş-katman tarafında, yani D bu kategorilerde zaten ham metinle çalışıyor | Kategori kırılımındaki `multi` zayıflığı (11.7 vs 10.1) katmanlı sorgudan **gelemez** — başka bir sebebi olmalı |

---

## Önceden bağlanan karar kuralı

Ölçüm geldikten sonra kural değiştirilmez.

- **`(b)` yalnızca** koşulsuz D'ye karşı **kapsama kaybında** ölçülebilir bir
  kazanç sağlarsa eklenir. Medyan veya ortalamadaki küçük fark yeterli değil:
  iki kod yolu, iki test yolu ve bir eşik parametresinin maliyeti var.
- **Fark yoksa `(b)` eklenmez**, D koşulsuz varsayılan olur ve bu sonuç
  *"eşik gerekmedi"* olarak yazılır — başarısızlık değil.
- **D vs D+ham** birincil ölçüde berabere kalırsa **D+ham** seçilir: ham logu
  tutmak bilgi atmamaktır, ve 2C'nin chunk bölmesi geldiğinde daha az
  varsayım bozulur.
