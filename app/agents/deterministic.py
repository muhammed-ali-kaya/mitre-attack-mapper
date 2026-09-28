"""Deterministik kontrol ajanlari -- LLM yok, her calistirmada ayni sonuc.

Her ajanin GOREVI FARKLI. Ortak sablon yok, cunku "bu bulgu gercek mi?"
sorusunun cevabi teknige gore tamamen degisiyor:

  T1053.005  gorev NE calistiriyor, kim olusturdu?
  T1003.001  erisim maskesi gercekten bellek okuma mi, erisen sey EDR mi?
  T1686.003  bu bir DEGISIKLIK mi, yoksa denetim kaydi mi?

Hibrit mimarinin deterministik yarisi burasi (bkz. app/agents/hybrid.py):
once bunlar calisir, cunku bedava ve tekrarlanabilir. LLM yalnizca metin
yargisi gerektiren yerde devreye girer."""

from __future__ import annotations

import re
from typing import Any

from app.agents.base import AgentDecision, Verdict, is_weakening, joined_text
from app.mapping.polarity import Polarity, classify
from app.mapping.rule_engine import Finding

# ---------------------------------------------------------------- T1053.005

# Zamanlanmis gorevin calistirdigi ikili bunlardan biriyse, gorev olusturma
# rutin sistem/yonetim isidir. Liste KASITLI olarak dar: "Program Files
# altindaki her sey guvenli" demek, saldirganin oraya yazabildigi anda
# korlugumuz olurdu.
_KNOWN_GOOD_TASK_BINARIES = [
    r"\\windows\\system32\\(sc|wevtutil|defrag|compattelrunner)\.exe",
    r"\\program files\\windows defender\\",
    r"\\program files\\microsoft\\.*\\updater\.exe",
    r"\\windows\\system32\\usoclient\.exe",
]
_KNOWN_GOOD_TASK_RE = [re.compile(p, re.IGNORECASE) for p in _KNOWN_GOOD_TASK_BINARIES]

# Uzak makinede gorev olusturma: /s <host>. Bu, yanal harekete isaret eder
# ve gorevi kesinlikle rutin olmaktan cikarir.
_REMOTE_TASK_RE = re.compile(r"/s\s+\S+", re.IGNORECASE)


class ScheduledTaskAgent:
    """T1053.005 -- gorev ne calistiriyor, uzak makinede mi olusturuluyor?"""

    agent_id = "t1053.005-scheduled-task"
    technique_id = "T1053.005"

    def review(self, finding: Finding, rows: list[dict[str, Any]]) -> AgentDecision:
        text = joined_text(finding, rows)

        if _REMOTE_TASK_RE.search(text):
            return AgentDecision(
                agent_id=self.agent_id,
                technique_id=self.technique_id,
                verdict=Verdict.CONFIRM,
                reason="Görev uzak makinede oluşturuluyor (/s <host>) — rutin yerel bakım değil.",
            )

        for pattern in _KNOWN_GOOD_TASK_RE:
            if pattern.search(text):
                return AgentDecision(
                    agent_id=self.agent_id,
                    technique_id=self.technique_id,
                    verdict=Verdict.REJECT,
                    reason=(
                        "Görevin çalıştırdığı ikili bilinen-iyi listesinde "
                        f"(/{pattern.pattern}/) — rutin sistem bakımı."
                    ),
                )

        return AgentDecision(
            agent_id=self.agent_id,
            technique_id=self.technique_id,
            verdict=Verdict.ABSTAIN,
            reason="Görevin çalıştırdığı ikili tanınmıyor; ek bağlam olmadan karar verilmedi.",
        )


# ---------------------------------------------------------------- T1003.001

# LSASS'a erisim tek basina kotucul degil: EDR, yedekleme ve Windows'un kendi
# surecleri de LSASS'i acar. Ayirt edici olan ERISIM MASKESI.
_MEMORY_READ_ACCESS = re.compile(
    r"(0x1010|0x1410|0x143a|PROCESS_VM_READ|VMRead)", re.IGNORECASE
)
_KNOWN_SECURITY_TOOLS = re.compile(
    r"\\(MsMpEng|MpDefenderCoreService|CSFalconService|SentinelAgent|"
    r"cb\.exe|xagt|SysmonDrv)\b|\\windows defender\\",
    re.IGNORECASE,
)


class LsassAccessAgent:
    """T1003.001 -- erisim maskesi bellek okuma mi, erisen sey guvenlik araci mi?"""

    agent_id = "t1003.001-lsass-access"
    technique_id = "T1003.001"

    def review(self, finding: Finding, rows: list[dict[str, Any]]) -> AgentDecision:
        text = joined_text(finding, rows)

        if _KNOWN_SECURITY_TOOLS.search(text):
            return AgentDecision(
                agent_id=self.agent_id,
                technique_id=self.technique_id,
                verdict=Verdict.REJECT,
                reason=(
                    "LSASS'a erişen süreç bilinen bir güvenlik/EDR bileşeni — "
                    "bu ürünler LSASS'ı rutin olarak açar."
                ),
            )

        if _MEMORY_READ_ACCESS.search(text):
            return AgentDecision(
                agent_id=self.agent_id,
                technique_id=self.technique_id,
                verdict=Verdict.CONFIRM,
                reason="Erişim maskesi bellek okuma haklarını içeriyor (PROCESS_VM_READ).",
            )

        reason = (
            "LSASS erişimi var ama erişim maskesi bellek okumayı göstermiyor; "
            "handle açılışı tek başına kimlik bilgisi dökümü kanıtı değil."
        )
        # "medium'a dusur" bir TAVAN ifadesidir, mutlak bir hedef degil.
        # Bulgu zaten daha zayifsa (orn. genel ajan onu 'low'a indirmisse)
        # medium'u dayatmak YUKSELTME olur ve runner sozlesmeyi ihlal
        # sayip istisna firlatir -- olcumde 3 senaryo tam boyle dusmustu
        # (subtech-001, multi-002, crosslang-002). Yapacak sey kalmadiysa
        # dogru davranis cekimser kalmaktir.
        if not is_weakening(finding.confidence, "medium"):
            return AgentDecision(
                agent_id=self.agent_id,
                technique_id=self.technique_id,
                verdict=Verdict.ABSTAIN,
                reason=f"{reason} Güven zaten '{finding.confidence}'; düşürülecek seviye yok.",
            )

        return AgentDecision(
            agent_id=self.agent_id,
            technique_id=self.technique_id,
            verdict=Verdict.DOWNGRADE,
            downgrade_to="medium",
            reason=reason,
        )


# ---------------------------------------------------------------- T1686.003

class FirewallChangeAgent:
    """T1686.003 -- bu bir DEGISIKLIK mi, denetim kaydi mi?

    Kutupsallik kontrolu zaten kural motorunda calisiyor (app/mapping/
    polarity.py). Bu ajan ikinci savunma hatti: projedeki en pahali hata tam
    burada olustugu icin ayni kontrol iki bagimsiz yerde yapiliyor."""

    agent_id = "t1686.003-firewall-change"
    technique_id = "T1686.003"

    def review(self, finding: Finding, rows: list[dict[str, Any]]) -> AgentDecision:
        text = joined_text(finding, rows)
        polarity = classify(text)

        if polarity is Polarity.BREAKING:
            return AgentDecision(
                agent_id=self.agent_id,
                technique_id=self.technique_id,
                verdict=Verdict.CONFIRM,
                reason="Kayıt, güvenlik duvarı yapılandırmasının değiştiğini gösteriyor.",
            )

        return AgentDecision(
            agent_id=self.agent_id,
            technique_id=self.technique_id,
            verdict=Verdict.REJECT,
            reason=(
                f"Kaydın kutupsallığı '{polarity.value}' — güvenlik duvarının "
                "çalıştığını gösteren bir denetim kaydı, yapılandırma değişikliği değil."
            ),
        )


DETERMINISTIC_AGENTS = [
    ScheduledTaskAgent(),
    LsassAccessAgent(),
    FirewallChangeAgent(),
]
