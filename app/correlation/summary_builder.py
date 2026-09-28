"""Incident sonu 'Analist Ozeti': LLM CAGRISI YOK -- kullanicinin acikca talep
ettigi gibi ('LLM yeni davranis uretmesin'), yalnizca kanittan uretilen
tekniklerden sablon tabanli bir anlati kurulur. Her ifade app/correlation/
dedup.py'nin urettigi bir deduped teknige birebir izlenebilir; uydurma bir
bulgu eklenmez.

Metin neden yeniden yazildi: onceki surum tek bir Ingilizce cumle uretiyordu
ve gercek bir kosuda 27 cumlecik yan yana diziliyordu ("The attacker
established command and control via ..., established persistence using ...,
and escalated privileges via ...") -- ne okunuyor ne de bir olay raporunda
kullanilabiliyordu. Yeni surum Turkce ve dort bolume ayrilmis: kapsam, kill
chain sirasinda akis, yuksek riskli bulgular, yontem notu.

Anlati SIRASI kanonik kill chain sirasidir, kronolojik sira degil -- ve metin
bunu acikca soyler. Kronolojik sira gercek loglarda "once C2, sonra kalicilik"
gibi okunamayan diziler uretiyordu; kill chain sirasi ise anlatiyi kurar ama
zaman iddiasi tasimaz. Olaylarin gercek zaman sirasi Timeline bolumunde."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.correlation.attack_chain import TACTIC_ORDER, primary_tactic

# 'One cikan bulgular' bolumune giren taktikler risk_score'dan aliniyor: risk
# skorunu yukselten kume ile raporda vurgulanan kume ayrilirsa, "skor neden
# 84?" sorusunun cevabi metinde gorunmez olur.
from app.correlation.risk_score import HIGH_RISK_TACTICS
from app.correlation.tactic_labels import tactic_label, tactic_narrative

# Bir taktik fazinda en fazla kac teknik adi yazilsin; gerisi "ve N teknik
# daha" olarak ozetlenir. Sinir olmadan Persistence gibi fazlar tek basina
# 14 teknik siralayip cumleyi yine okunamaz hale getiriyordu.
TECHNIQUES_NAMED_PER_TACTIC = 3

_NO_EVIDENCE = (
    "Bu olay için anlatı kurmaya yetecek doğrulanmış teknik bulunamadı. "
    "Satır bazlı sonuçlar için 'Bireysel Log Analizi' sekmesine bakın."
)
_METHOD_NOTE = (
    "Bu özet şablon tabanlıdır: her ifade yukarıda listelenen tekniklerden birine "
    "dayanır, dil modeli tarafından üretilmemiştir."
)


def _format_time_window(timeline: list[dict[str, Any]]) -> str | None:
    stamps = [e["timestamp"] for e in timeline if isinstance(e.get("timestamp"), datetime)]
    if not stamps:
        return None
    first, last = min(stamps), max(stamps)
    if first.date() == last.date():
        if first == last:
            return f"{first:%d.%m.%Y %H:%M:%S}"
        return f"{first:%d.%m.%Y %H:%M:%S}–{last:%H:%M:%S}"
    return f"{first:%d.%m.%Y %H:%M:%S} – {last:%d.%m.%Y %H:%M:%S}"


def _technique_mention(technique: dict[str, Any]) -> str:
    """'PowerShell (T1059.001, 5 kayıt)' -- teknik adi ve ID cevrilmez."""
    name = technique.get("name") or technique.get("attack_id")
    count = technique.get("occurrence_count") or 0
    return f"{name} ({technique.get('attack_id')}, {count} kayıt)"


def _group_by_primary_tactic(techniques: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Teknikleri birincil taktiklerine gore gruplar -- attack chain ile AYNI
    yerlestirme (bkz. app/correlation/attack_chain.py::primary_tactic), boylece
    ozetteki faz ile diyagramdaki faz birbirini tutar."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for technique in techniques:
        tactic = primary_tactic(technique)
        if tactic:
            grouped.setdefault(tactic, []).append(technique)
    for group in grouped.values():
        group.sort(key=lambda t: (-(t.get("occurrence_count") or 0), t.get("attack_id") or ""))
    return grouped


def _ordered_tactics(grouped: dict[str, list[dict[str, Any]]]) -> list[str]:
    ordered = [t for t in TACTIC_ORDER if t in grouped]
    # TACTIC_ORDER'da olmayan bir taktik gelirse sona eklenir -- kaybolmasin.
    ordered += [t for t in grouped if t not in TACTIC_ORDER]
    return ordered


def _phase_clause(tactic: str, techniques: list[dict[str, Any]]) -> str:
    named = techniques[:TECHNIQUES_NAMED_PER_TACTIC]
    mentions = "; ".join(_technique_mention(t) for t in named)
    remaining = len(techniques) - len(named)
    if remaining > 0:
        mentions += f" ve {remaining} teknik daha"

    narrative = tactic_narrative(tactic)
    if narrative:
        return f"**{tactic_label(tactic)}** — {narrative}: {mentions}"
    # Bilinmeyen taktik: fiil uydurmak yerine yalnizca teknikleri sirala.
    return f"**{tactic_label(tactic)}** — {mentions}"


def _scope_sentence(
    timeline: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
    tactic_count: int,
    hostname: str | None,
    primary_user: str | None,
) -> str:
    subject_parts = []
    if hostname:
        subject_parts.append(f"**{hostname}** ana bilgisayarında")
    if primary_user:
        subject_parts.append(f"**{primary_user}** hesabıyla")
    subject = " ".join(subject_parts)

    window = _format_time_window(timeline)
    window_part = f"{window} aralığındaki " if window else ""

    lead = f"{subject} {window_part}".strip()
    lead = f"{lead} {len(timeline)} log kaydı" if lead else f"{len(timeline)} log kaydı"

    return (
        f"{lead} tek bir olayda ilişkilendirildi. "
        f"Kanıt düzeyi yeterli **{len(techniques)} teknik**, "
        f"**{tactic_count} ATT&CK taktiğine** yayılıyor."
    )


def _highlight_sentence(grouped: dict[str, list[dict[str, Any]]]) -> str | None:
    parts = []
    for tactic in _ordered_tactics(grouped):
        if tactic not in HIGH_RISK_TACTICS:
            continue
        mentions = ", ".join(
            _technique_mention(t) for t in grouped[tactic][:TECHNIQUES_NAMED_PER_TACTIC]
        )
        parts.append(f"{tactic_label(tactic, with_english=False)} — {mentions}")
    if not parts:
        return None
    return "**Öne çıkan bulgular:** " + "; ".join(parts) + "."


def build_attack_summary(
    evidence_timeline: list[dict[str, Any]],
    deduped_techniques: list[dict[str, Any]],
    *,
    hostname: str | None = None,
    primary_user: str | None = None,
    weak_technique_count: int = 0,
) -> str:
    """deduped_techniques YALNIZCA guclu teknikleri almalidir (bkz.
    app/correlation/dedup.py::split_by_confidence). Zayif olanlarin sayisi
    weak_technique_count ile gecilir; ozet onlari saymadigini acikca yazar --
    okuyucu neyin disarida birakildigini bilmeli."""
    if not deduped_techniques:
        return _NO_EVIDENCE

    grouped = _group_by_primary_tactic(deduped_techniques)
    ordered = _ordered_tactics(grouped)

    blocks = [
        _scope_sentence(
            evidence_timeline, deduped_techniques, len(ordered), hostname, primary_user
        ),
        "**Saldırı akışı** (ATT&CK kill chain sırasıyla; olayların gerçek zaman "
        "sırası için Timeline bölümüne bakın):",
    ]
    blocks += [f"- {_phase_clause(tactic, grouped[tactic])}" for tactic in ordered]

    highlight = _highlight_sentence(grouped)
    if highlight:
        blocks.append(highlight)

    if weak_technique_count:
        blocks.append(
            f"Düşük güvenli **{weak_technique_count} sinyal** bu özetin, risk skorunun ve "
            "saldırı zincirinin dışında tutuldu; 'Doğrulama Gerektiren Zayıf Sinyaller' "
            "bölümünde listelenmiştir."
        )

    blocks.append(f"_{_METHOD_NOTE}_")
    return "\n\n".join(blocks)
