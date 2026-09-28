"""Bir incident'i (app/correlation/incident.py::build_incidents ciktisi) insan
okunur Markdown rapora cevirir. app/ui/bulk_view.py::_render_incident_tab ile
ayni bilgiyi (timeline, attack chain, risk, IOC ozeti, analyst summary)
gosterir; indirilebilir/paylasilabilir statik bir metin olarak.

LLM cagirmaz -- yalnizca incident sozlugunu formatlar."""

from __future__ import annotations

from typing import Any

from app.correlation.risk_score import BREAKDOWN_LABELS_TR
from app.correlation.tactic_labels import tactic_label

# Arayuz de ayni listeyi kullaniyor (bkz. app/ui/bulk_view.py) -- iki yerde
# ayri ayri yazilirsa rapordaki baslikla ekrandaki baslik zamanla ayrisir.
IOC_CATEGORY_LABELS_TR: list[tuple[str, str]] = [
    ("Şüpheli Süreçler", "suspicious_processes"),
    ("Şüpheli Ağ Bağlantıları", "suspicious_network_connections"),
    ("İndirilen Dosyalar", "downloaded_files"),
    ("Oluşturulan Servisler", "created_services"),
    ("Oluşturulan Kullanıcılar", "created_users"),
    ("Kayıt Defteri Değişiklikleri", "registry_changes"),
    ("Kimlik Bilgisi Erişimi", "credential_access"),
]

SEVERITY_LABEL_TR = {"Low": "Düşük", "Medium": "Orta", "High": "Yüksek", "Critical": "Kritik"}


def _format_timestamp(ts) -> str:
    return ts.strftime("%H:%M:%S") if ts is not None else "-"


def _format_entry_dict(entry: dict[str, Any]) -> str:
    parts = [f"{k}={v}" for k, v in entry.items() if k != "row_index" and v]
    return ", ".join(parts) if parts else "-"


def _ip_reputation_section(lookup: Any) -> list[str]:
    """VirusTotal IP itibar tablosu. lookup, app/enrichment/virustotal.py
    LookupResult'i (ya da hic sorgu yapilmadiysa None).

    Atlanan adresler de raporda GORUNUR: "bu IP temiz" ile "bu IP'ye hic
    bakilmadi" ayrimi bir olay raporunda kritik."""
    if lookup is None:
        return []

    lines = ["", "## IP İtibar Kontrolü (VirusTotal)", ""]
    if not getattr(lookup, "enabled", False):
        lines.append("_VirusTotal sorgusu yapılmadı: API anahtarı tanımlı değil._")
        return lines

    if lookup.reputations:
        lines += ["| IP | Sonuç | Zararlı | Şüpheli | Zararsız | Ülke | AS |", "|---|---|---|---|---|---|---|"]
        for r in lookup.reputations:
            lines.append(
                f"| {r.ip} | {r.verdict} | {r.malicious} | {r.suspicious} | {r.harmless} "
                f"| {r.country or '-'} | {r.as_owner or '-'} |"
            )
    else:
        lines.append("_Sorgulanabilecek public IP bulunamadı._")

    if lookup.skipped_private:
        lines += [
            "",
            f"**Sorgulanmayan özel/iç ağ adresleri ({len(lookup.skipped_private)}):** "
            + ", ".join(lookup.skipped_private),
            "",
            "_Bu adresler kasıtlı olarak gönderilmedi: VirusTotal'de karşılıkları yok ve "
            "iç ağ topolojisinin üçüncü tarafa aktarılmaması gerekir._",
        ]

    if lookup.skipped_over_limit:
        lines += [
            "",
            f"**Kota nedeniyle sorgulanamayan ({len(lookup.skipped_over_limit)}):** "
            + ", ".join(lookup.skipped_over_limit),
        ]

    return lines


def _weak_signal_section(incident: dict[str, Any]) -> list[str]:
    """Anlatiya girmeyen dusuk guvenli teknikler.

    Rapor bunlari GOSTERMELI: bir olay raporunda 'sunu degerlendirdim ve
    disarida biraktim' ile 'bunu hic gormedim' arasindaki fark, raporu
    okuyanin yapacagi ise dogrudan etki eder."""
    weak = incident.get("weak_techniques") or []
    if not weak:
        return []

    lines = [
        "",
        f"## Doğrulama Gerektiren Zayıf Sinyaller ({len(weak)})",
        "",
        "_Bu teknikler tek kanıta dayandığı veya güven skoru düşük kaldığı için saldırı "
        "zincirine, analist özetine ve risk skoruna dahil edilmedi; doğrulama için "
        "listelenmiştir._",
        "",
        "| ATT&CK ID | Teknik | Güven | Skor | Kayıt |",
        "|---|---|---|---|---|",
    ]
    for t in weak:
        lines.append(
            f"| {t['attack_id']} | {t['name']} | {t.get('confidence_level') or '-'} "
            f"| {round(t.get('max_confidence_score') or 0.0, 2)} | {t['occurrence_count']} |"
        )
    return lines


def build_incident_report_markdown(incident: dict[str, Any], ip_lookup: Any = None) -> str:
    risk = incident["risk"]
    severity_tr = SEVERITY_LABEL_TR.get(risk["severity"], risk["severity"])
    # Eski kayitli sonuclarda 'techniques' yok; deduped'a duseriz.
    techniques = incident.get("techniques") or incident["deduped_techniques"]

    lines: list[str] = [
        f"# {incident['id']} — Sunucu: {incident['hostname'] or '-'} — "
        f"Kullanıcı: {incident['primary_user'] or '-'}",
        "",
        f"**Risk Skoru:** {risk['score']}/100 ({severity_tr})",
        "",
        f"{len(incident['row_indices'])} log kaydı · {len(techniques)} doğrulanmış teknik · "
        f"{len(incident['attack_chain'])} taktik aşaması",
        "",
        "## Analist Özeti",
        "",
        incident["attack_summary"],
        "",
        "## Risk Skoru Nasıl Hesaplandı?",
        "",
    ]
    for key, value in risk["breakdown"].items():
        label = BREAKDOWN_LABELS_TR.get(key, key)
        printable = ", ".join(str(v) for v in value) if isinstance(value, list) else value
        lines.append(f"- **{label}:** {printable if printable != '' else '-'}")

    lines += ["", "## Olay Zaman Çizelgesi", ""]
    for entry in incident["timeline"]:
        lines.append(
            f"- `{_format_timestamp(entry['timestamp'])}` EventID={entry['event_id'] or '-'} "
            f"— {entry['evidence']}"
        )

    lines += ["", "## MITRE ATT&CK Saldırı Zinciri", ""]
    chain = incident["attack_chain"]
    lines.append(" → ".join(tactic_label(p["tactic"], with_english=False) for p in chain) or "-")
    lines.append("")
    for phase in chain:
        techniques_str = ", ".join(
            f"{t['attack_id']} ({t['occurrence_count']})" for t in phase["techniques"]
        )
        lines.append(f"- **{tactic_label(phase['tactic'])}:** {techniques_str}")
    lines.append("")
    lines.append(
        "_Her teknik kill chain sırasındaki birincil taktiğinde bir kez listelenir; "
        "tekniğin tüm taktikleri aşağıdaki matriste görünür._"
    )

    lines += [
        "", "## MITRE Matrisi (Tekilleştirilmiş)", "",
        "| ATT&CK ID | Teknik | Taktikler | Güven | Kayıt Sayısı |", "|---|---|---|---|---|",
    ]
    for t in techniques:
        tactics_str = ", ".join(tactic_label(x, with_english=False) for x in t["tactics"])
        lines.append(
            f"| {t['attack_id']} | {t['name']} | {tactics_str} "
            f"| {t.get('confidence_level') or '-'} | {t['occurrence_count']} |"
        )

    lines += _weak_signal_section(incident)

    ioc = incident["ioc_summary"]
    lines += ["", "## IOC / Artefakt Özeti", ""]
    ioc_list_str = ", ".join(f"{i['type']}:{i['value']}" for i in ioc["ioc_list"]) or "-"
    lines.append(f"**IOC Listesi:** {ioc_list_str}")
    for label, key in IOC_CATEGORY_LABELS_TR:
        entries = ioc[key]
        lines.append(f"\n**{label}** ({len(entries)}):")
        if entries:
            for entry in entries:
                lines.append(f"- {_format_entry_dict(entry)}")
        else:
            lines.append("- -")

    lines += _ip_reputation_section(ip_lookup)
    lines.append("")

    return "\n".join(lines)
