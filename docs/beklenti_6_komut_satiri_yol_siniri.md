# Beklenti — Komut satırında registry yolu SINIRI

**Kod yazılmadan önce yazıldı.**

Görev 5 §6'nın kararı onaylandı: kritiklik **yapısal alan → komut satırı**
sırasıyla okunacak, **düzyazıdan okunmayacak**. Ama komut satırını kaynak
olarak bağlamak **bu belge bitmeden yasak**: bugünkü çıkarım amiral gemisi
vakayı kaybediyor.

---

## 1. Ölçülen durum — bugünkü naif desen ne yapıyor

`scripts/measure_baseline_inputs.py` içindeki desenle on vaka:

```
vaka                       cikarim                                             kritiklik
V1 amiral gemisi           HKLM\SAM C                                          unknown    <-- KAYIP
V2 goreli dosya            HKLM\SAM sam.hive                                   unknown    <-- KAYIP
V3 bosluklu son segment    HKLM\SOFTWARE\Policies\Microsoft\Windows Defender   high/defender-policy
V4 tirnakli + bosluk ici   HKCU\...\Windows NT\CurrentVersion\Windows          high/appinit-dll
V5 bayrakla biten          HKCU\...\CurrentVersion\Run                         high/autorun-run
V6 deger dosya yolu        HKLM\SYSTEM\CurrentControlSet\Services\AcmeAgent    high/service
V7 powershell surucu       None                                                -          <-- KAYIP
V8 negatif UNC             None                                                -          (dogru)
V9 uzantisiz 2. pozisyonel HKLM\SAM backup                                     unknown    <-- KAYIP
V10 yalin kovan            None                                                -          (dogru)
```

**Kırılma dar ve tarif edilebilir.** Naif desen boşluğu segment içi sayıyor;
bu V3'te DOĞRU (`Windows Defender` gerçekten tek anahtardır), V1/V2'de
YANLIŞ (`C:\...` ve `sam.hive` ikinci pozisyoneldir). Yani sorun "boşluk
kabul edilmesi" değil, **boşluktan sonrasının ne olduğuna bakılmaması**.

V7 ayrı bir kusur: PowerShell sürücü gösterimi (`HKLM:\...`) hiç
yakalanmıyor.

**V1 neden amiral gemisi:** `reg.exe save HKLM\SAM ...` SAM hırsızlığının
komut satırı biçimidir — T1003.002, projenin `known_regression` kaydındaki
teknik. Bir tokenizasyon artefaktı yüzünden `critical` varlık `unknown`'a
düşüyor; Görev 4'ün kuralınca `unknown` BENIGN üretemez ama
`SUFFICIENT_SUSPICIOUS` de üretemez. Vaka sessizce ortadan kayboluyor.

---

## 2. Sınır kuralı — kod yazılmadan önce bağlandı

Yol **bilinen bir kovan önekiyle başlar** ve şu kurallarla biter:

### K1 — Tırnak sınırdır
Yol bir tırnak (`"` veya `'`) içinde başlıyorsa, kapanış tırnağına kadar
her şey yola dahildir. Boşluk sorgulanmaz. Gerekçe: tırnak, komut satırını
yazan kişinin **açık sınır beyanıdır**; tahmin etmeye gerek yok.

### K2 — Tırnaksızda boşluk, SONRASINA bakılarak kabul edilir
Boşluk yolu şu üç durumda **bitirir**:

| durur | örnek | neden |
|---|---|---|
| **yeni kök** | `C:\...`, `\\sunucu\...`, `HKCU\...` | ikinci bir pozisyonel başlıyor |
| **bayrak** | `/v`, `/s`, `-Name` | argüman listesi başlıyor |
| **dosya adı biçimi** | `sam.hive`, `out.reg` | `ad.uzanti` (1–5 karakter uzantı) |

Aksi hâlde boşluk **segment içidir** ve yola dahildir (`Windows Defender`,
`Windows NT`, `Time Zones`).

### K3 — `reg.exe` fiil aritesi belirsizliği çözer
K2 tek başına `reg save HKLM\SAM backup` vakasını çözemez: `backup` ne kök,
ne bayrak, ne dosya adı biçiminde — ama ikinci pozisyoneldir. Belirsizliği
komutun **kendi dilbilgisi** çözer:

```
arite 1  add query delete unload import   -> anahtar adi TEK pozisyonel,
                                             ilk bayraga kadar her sey yol
arite 2  save restore load export copy    -> ikinci pozisyonel bir DOSYADIR;
         compare                            K2 durdurmadiysa SON token atilir
```

İki mekanizma **üst üste biner** ve bu kasıtlı: K2 token'ın *biçimine*
bakar, K3 komutun *dilbilgisine*. `reg export ...\Windows Defender out.reg`
vakasını K2 zaten `out.reg` uzantısından keser; K3 aynı vakayı uzantı
olmasa da (`... backup`) keser. Biri diğerinin yedeği değil — V9 yalnızca
K3 ile, V3 yalnızca K2 ile çözülüyor.

### K4 — PowerShell sürücü gösterimi normalize edilir
`HKLM:\SOFTWARE\...` → `HKLM\SOFTWARE\...`. Kovan adından sonraki `:`
düşürülür. Gerekçe: `_kanonik` ilk segmenti `hklm:` olarak görüyor ve hiçbir
desenle eşleşmiyor — V7'nin `None` dönmesinin sebebi bu.

### K5 — Yalın kovan yol DEĞİLDİR
`HKLM` tek başına (ardında `\` yok) çıkarılmaz. `path_normalizer`'daki
mevcut karar bunun aynısı: yalın kovan ayırt edici bilgi taşımaz.

---

## 3. Beklenen çıktı — fixture ile sabitlenecek

`tests/fixtures/command_line_path_boundary.json`. **Kabul ölçütü V1'dir:**
o komut satırından `HKLM\SAM` çıkmalı, `HKLM\SAM C` değil.

```
V1  -> HKLM\SAM                                                   critical
V2  -> HKLM\SAM                                                   critical
V3  -> HKLM\SOFTWARE\Policies\Microsoft\Windows Defender          high
V4  -> HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows  high
V5  -> HKCU\Software\Microsoft\Windows\CurrentVersion\Run         high
V6  -> HKLM\SYSTEM\CurrentControlSet\Services\AcmeAgent           high
V7  -> HKLM\SOFTWARE\Policies\Microsoft\Windows Defender          high
V8  -> (yok)                                                      -
V9  -> HKLM\SAM  (reg save ... backup, K3 arite)                  critical
```

**Regresyon şartı:** V3–V6 bugün DOĞRU çalışıyor. Yeni kural onları
bozarsa kural geri alınır — V1'i kazanıp V3'ü kaybetmek ilerleme değildir.
(Bu şart 2C'de bir kez yazıldı ve işe yaradı; aynısı.)

---

## 4. Bilinen sınır — rapora yazılacak, gizlenmeyecek

- Kural **`reg.exe` dışındaki** komutların dilbilgisini bilmiyor. PowerShell
  tırnak kullandığı sürece K1 yeter; tırnaksız ve bayraksız bir PowerShell
  ifadesi fazla uzatabilir.
- K2'nin "dosya adı biçimi" ölçütü uzantısız dosya adlarını kaçırır; K3
  yalnızca `reg` fiilleri için kapatır.
- Çıkarım **düzyazıya uygulanmaz** (Görev 5 §6 kararı). Bu kural burada
  test edilmez, çağıran tarafta zorlanır.

---

## 5. Bu neden Yol B'yi ÖLÇÜLEBİLİR yapmaya YETMİYOR

Komut satırı kaynak olarak bağlanınca Yol B 60 senaryonun **0'ı yerine
2'sinde** tetiklenebilir hâle gelir. 2 de yeterli değildir. Görev 5'in
sonuç raporuna şimdiden yazılan kısıt için bkz.
`docs/beklenti_5_karar_katmani.md` §7.

---

## 6. SONUÇ — ölçüldü (kod yazıldıktan sonra)

`app/normalization/command_line_paths.py`, 10 vakanın 10'unda beklentiyi
tutturdu (`tests/test_command_line_paths.py`, 23 test).

```
id   ONCE       SONRA      yol
V1   unknown -> critical   HKLM\SAM                         <-- kabul olcutu
V2   unknown -> critical   HKLM\SAM
V3   high    -> high       ...\Windows Defender              (regresyon: korundu)
V4   high    -> high       ...\Windows NT\CurrentVersion\Windows
V5   high    -> high       ...\CurrentVersion\Run
V6   high    -> high       ...\Services\AcmeAgent
V7   (yok)   -> high       ...\Windows Defender              (K4 surucu gosterimi)
V8   -       -> -          (dogru sekilde bos)
V9   unknown -> critical   HKLM\SAM                         (K3 arite)
V10  -       -> -          (dogru sekilde bos)
```

**Kurtarilan: 4 vaka** (unknown/kayip -> siniflanabilir). Regresyon
sarti tutuldu: V3-V6 bozulmadi.

Tekrarlanabilir: `python scripts/measure_baseline_inputs.py`, bolum 4.
