# Baseline Sistem Gözlemleri

## Test: schtasks raw log (dokuman bölüm 4.2 örneği)

Baseline pipeline (yalnızca semantic search, top-10, filtre/reranking/doğrulama yok)
ile çalıştırıldığında, LLM (qwen3:8b) 6 eşleştirmeden 5'inde **yanlış veya uydurma
ATT&CK ID/isim çifti** üretti:

| ATT&CK ID | LLM'in dediği isim | Gerçek isim | Durum |
|---|---|---|---|
| T1059 | Command and Scripting Interpreter | Command and Scripting Interpreter | DOĞRU |
| T1052 | Exploit Public-Facing Application | Exfiltration Over Physical Medium | UYDURMA |
| T1053 | Scheduled Task | Scheduled Task/Job | YANLIŞ (yakın ama hatalı) |
| T1127 | Control Panel Item | Trusted Developer Utilities Proxy Execution | UYDURMA |
| T1003 | Indicator Removal from Logs | OS Credential Dumping | UYDURMA |
| T1027 | System Services | Obfuscated Files or Information | UYDURMA |

Ayrıca `observed_behaviors` listesi girdide hiç geçmeyen davranışlar içeriyordu
(PowerSploit, CPL dosyaları, shell history incelemesi) -- bunlar log'da yok.

## Kök neden analizi

Context'i ayrıca kontrol ettim: LLM'e gönderilen kaynak veri **doğruydu** (T1053.005
"Scheduled Task" açıklaması doğru sekilde context'in başında yer alıyordu). Yani bu
bir retrieval veya prompt olusturma hatasi degil -- model, acikca "kaynaklarda
olmayan ATT&CK kimligi/isim uydurma" talimatina ragmen kendi on-egitim bilgisinden
uydurdu.

Olasi nedenler:
1. **Filtresiz top-10 context gürültülü** -- retrieval hybrid/reranking/metadata
   filtreleme yapmadigi icin ilgisiz chunk'lar da (T1086, T1569.002, T1196,
   T1552.003 gibi) context'e girdi, bu da modelin odaginin dagilmasina katki
   sunmus olabilir.
2. **Context token bütçesi yönetimi yok** -- context 25.715 karakter (~6-8K token),
   baseline bunu kirpmiyor/onceliklendirmiyor.
3. **Dogrulama katmani yok** -- ciktinin ATT&CK ID/isim tutarliligi hic
   kontrol edilmiyor, dogrudan kullaniciya gidiyor.

## Sonuç

Bu, dokumanin "Gelistirilmis Sistem"in neden hybrid retrieval + reranking +
context butcesi + dogrulama katmani gerektirdigini somut olarak kanitliyor
(bolum 33 karsilastirma tablosu). Milestone 5'te bu 3 bilesen eklendiginde
ayni test tekrarlanip iyilesme olculecek -- rapor icin dogrudan kullanilabilir
bir "once/sonra" ornegi.
