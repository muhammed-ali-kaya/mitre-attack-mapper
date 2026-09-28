# Beklenti — Görev 13, S kolu (~60 sentetik log)

Bu belge **S yazılmadan ve hat çalıştırılmadan önce** yazıldı.
Devralınan kurallar: `docs/beklenti_13_heldout_set.md` §2.1, §6 · Bağlayıcı
şartların kaynağı: `docs/sonuc_16_services_altanahtar.md` §5.

---

## 0. S neyi ölçmek için var

G kolu bir şeyi kanıtladı: **isabet sayısı hiçbir şey söylemiyor.** 51 gerçek
satırda sistem 51'ine de `INSUFFICIENT_DATA` dedi; sınıf isabeti 50/51 ama
sabit tek cevap veren aptal sınıflandırıcı da 50/51 alıyor. Yol A ve Yol B
G'de bir kez bile ateşlenmedi (Görev 15'ten sonra Yol B 5 kez ateşlendi,
beşi de aynı desende).

Sebep yapısal: G'nin dağılımı karar/kural katmanlarını **uyarmıyor**.
S bu boşluğu kapatmak için var — genellemek için değil. S'ten çıkarılabilecek
tek cümle biçimi Görev 5 §7'den devralınıyor:

> *"Bu ~60 logda şu katman beklendiği gibi davranıyor."*

"Sistem sahada şu kadar doğru" cümlesi S'ten **çıkarılamaz.**

---

## 1. Devralınan donmuş kriterler — DEĞİŞTİRİLMİYOR

`beklenti_13` §6'daki tablo aynen geçerli. Eşikler burada elle
tekrarlanmıyor — `scripts/measure_heldout_baseline.py` paydayı kataloğun
kendisinden hesaplıyor:

```
required event ID : 48   (rules/attack_mappings.yaml, yalnız required.event_ids)
KRITER esigi      : 24   (KRITER_ID_ORANI = 0.5, kodda)
```

| Kriter | Eşik | S'te nasıl karşılanacak |
|---|---|---|
| KRİTER — olay ID temsili | ≥24/48 | bileşim §4'te ID listesiyle planlandı |
| EK-1 — registry yolu | `critical`, `high`, `noise` seviyelerinden birer aile | tablo bugün 10 critical / 80 high / 12 medium / 15 noise desen taşıyor; seçim §4 |
| EK-2 — baseline çifti | aynı aktörün beklenen **ve** beklenmeyen varlık ailesine yazdığı en az birer log | `service ← trustedinstaller.exe` (beklenen) / `defender-policy ← trustedinstaller.exe` (beklenmeyen) |
| yapısal ağırlık | kayıtların ≥%70'i olay ID taşır | §4 |
| negatif örnek | S'in ≥%20'si | §4, ve §4'teki doz sınırı |

**S bu kriterleri karşıladığı için değil, ölçüldüğü için kabul edilir:**
kabul kararı `measure_heldout_baseline.py --set` çıktısıyla verilir, göz
kararıyla değil.

---

## 2. İKİ BAĞLAYICI ŞART

Bunlar tercih değil, Görev 16'nın S'e bıraktığı borçtur.

### B1 — Ayırt edici çift ZORUNLU

S, aynı kritik registry anahtarına giden **iki logu birlikte** içermek
zorunda:

| | olay | anlam | beklenen karar |
|---|---|---|---|
| çiftin A yarısı | `4656`, yazma biti taşıyan maske | handle **TALEBİ** | talep tek başına gerçekleşen erişim sayılmamalı |
| çiftin B yarısı | `4663` veya `4657` | **gerçekleşen** yazma | erişim gerçekleşti |

**Beklenen kararları FARKLI olacak.** Aynı çıkması beklenen bir çift ayırt
etme gücünü ölçemez — yalnızca iki satır ekler.

**Çift tek değişkenli olmalı:** anahtar, aktör, maske, süreç aynı; **yalnızca
olay ID ve onun getirdiği anlam** değişir. İkinci bir alan da değişirse
sonucun sebebi ayrılamaz — bu projede "doğru cevap, yanlış sebep" iki kez
ölçüm kirletti.

**Çift en az üç ayrı kritik anahtarda tekrarlanacak.** Tek anahtarda görülen
fark o anahtarın kazası olabilir; üç anahtar bunu ayırır.

### B2 — S raporunun taşıyacağı cümle

S raporu şu cümleyi **birebir** taşıyacak:

> `4656` + yazma maskesi + kritik anahtar üçlüsü **BİLİNEN** bir yanlış alarm
> kaynağıdır (Görev 16); S'teki oranı sistemin ayırt etme gücü değil, bu
> bilinen kusurun sıklığıdır.

Sebebi: bu üçlü S'te kaç kez geçerse yanlış alarm oranı o kadar yükselir.
Cümle olmazsa okuyan kişi bunu sistemin performansı sanır.

---

## 3. GEÇERSİZ KAYIT — `sonuc_13` §6

`docs/sonuc_13_g_kolu.md` §6 şunu yazıyordu:

> *"S logları ham Windows metni olarak yazılacak; bu, maske kaybının S'de
> görünmeyeceği anlamına gelir."*

**Bu kayıt ARTIK GEÇERSİZ.** Görev 15 (`7c9fe73`) sarmalanmış `Message`
gövdesini ayrıştırdı (K-A yuvalama, K-B kaçış asimetrisi, K-C etiket sınırı);
84 şema içi alan geri geldi ve erişim maskesi artık toplu yolda da okunuyor.

Sonucu yalnızca bir düzeltme değil, bir **ön koşul**: B1 ancak maske
okunabildiği için ölçülebilir. S Görev 15'ten önce yazılsaydı çiftin iki
yarısı da maskesiz görülür, fark ölçülemez ve "sistem ayırt edemiyor" diye
raporlanırdı.

**Bu belgenin ölçtüğü katmanın çalışır durumda olduğu böylece yazılı olarak
gösterilmiştir** — HANDOFF çalışma yöntemi maddesi 16'nın her beklenti
belgesinden istediği şey budur. Genel kural orada; burada yalnızca bu ölçüme
ait kayıt duruyor.

---

## 4. Bileşim planı (~60 kayıt)

Sayılar hedef; kabul `measure_heldout_baseline.py` çıktısıyla verilir.

| Blok | Kaç | Ne için |
|---|---|---|
| **B1 ayırt edici çiftler** | 6 (3 anahtar × 2) | §2 B1 |
| Yol A tetikleyen — teknik + doğrulanmış kanıt | ~14 | Yol A G'de hiç ateşlenmedi |
| Yol B tetikleyen — kritiklik + gerçekleşen erişim | ~10 | Yol B yalnızca kusurlu desende ateşlendi |
| EK-2 baseline çifti (iki yönlü) | 4 | bastırmanın hem çalıştığı hem çalışmadığı yön |
| Olay ID genişliği — süreç/servis/görev/oturum/log temizleme | ~14 | KRİTER ≥24/48 |
| Negatif örnek (≥%20 → ≥12) | ~12 | yanlış alarm oranı ölçülebilsin |

**Olay ID hedefi** kataloğun required listesinden seçilecek; registry dışı
aileler zorunlu, çünkü G tek registry ailesine sıkışmıştı:
`4688`, `4697`, `4698`, `4702`, `4719`, `4720`, `4728`, `4732`, `7045`,
`7040`, `1102`, `4104`, `5140`, `5145`, `4624`, `4625`, `4769`, `4778`
— artı registry tarafı `4656`, `4657`, `4663`.

**Registry aileleri (EK-1):**

| seviye | seçilen aile | neden |
|---|---|---|
| `critical` | `credential-hive` | SAM/SECURITY kovanı; amiral gemisi vaka (T1003.002) |
| `high` | `service`, `defender-policy` | EK-2'nin iki yönü buradan geçiyor |
| `noise` | `time-zone` veya `os-version` | kritik olmayanın bastırılmadan sessiz kalması ölçülsün |

### Doz sınırı — bilinen kusur kaç kez geçecek

`4656` + yazma maskesi + kritik anahtar üçlüsü S'te **yalnızca B1'in A
yarılarında** (3 kayıt) geçecek. Bu bir tasarım parametresidir ve S raporunda
sayı olarak yazılacak. Serbest bırakılırsa S'in yanlış alarm oranı Görev
16'da teşhis edilmiş tek kusurun sıklığını ölçer, sistemi değil.

---

## 5. Yazım disiplini — devralınan, gevşetilmiyor

1. Her log için beklenen cevap **ATT&CK korpusundan ve gerçek log
   biçimlerinden** yazılır. `kaynak` alanı zorunlu: hangi teknik sayfası,
   hangi olay ID tanımı.
2. Beklenen cevaplar **commit'lenir.**
3. **Sonra** hat koşulur.

**Biçim sınırı:** log "sistemin anlayacağı" biçimde değil, **Windows'un
ürettiği** biçimde yazılır — alan adları, alan sırası ve mesaj gövdesi gerçek
kayıtlardan alınır. Bir alanı sistemin kolay okuması için eklemek, seti
sisteme göre ayarlamaktır.

**Ek sınır (Görev 16'dan):** bir logun beklenen kararı, o log yazıldıktan
sonra sistemin ne dediğine bakılarak DEĞİŞTİRİLEMEZ. Değişmesi gerekiyorsa
gerekçesi ATT&CK'ten veya olay ID tanımından gelmeli, çıktıdan değil.

---

## 6. Bu beklentinin ÖLÇMEDİĞİ şey

- **Maske/4656 anlambilim düzeltmesinin kendisi.** Sıra `S → düzeltme`;
  S düzeltmenin ölçüm aracını kurar, düzeltmeyi içermez.
- **H kolu.** Tanım gereği.
- **Genelleme.** §0.
- **Teknik ekseninin varyansı.** Görev 15'ten devralınan açık kalem.
- **`decision._alan`'ın `-` ve `NULL SID`'i yokluk saymaması.** Açık kalem;
  S'te bu değerleri taşıyan log varsa etkisi ayrı raporlanır.
- **`svchost.exe ← service` bastırıcısının etkisi.** Böyle bir çift
  ALINMADI ve gerekçesi `config/actor_baseline.yaml`'a yazıldı: G'deki beş
  yanlış alarmın dördü svchost olduğu için eklenmesi caziptir, ve tam bu
  yüzden yasaktır — yanlış alarmı susturmak için bastırıcı eklemek,
  ölçülecek şeyi yok etmektir.

---

## 7. Kabul kriterleri — S için

S kabul edilir ancak ve ancak:

1. `measure_heldout_baseline.py --set evaluation/s_arm_set.json` **tüm**
   kriterleri geçerse (çıktı raporlanır, elle sayım yok);
2. B1 çifti üç ayrı kritik anahtarda mevcut ve iki yarının **beklenen
   kararları farklı** yazılmışsa;
3. beklenen cevaplar hat koşulmadan **önce** commit'lenmişse;
4. S raporu B2 cümlesini ve bilinen kusurun **dozunu** (3 kayıt) taşıyorsa.
