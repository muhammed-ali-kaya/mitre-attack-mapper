"""Deterministik korelasyon motoru (LLM kullanilmaz): birbiriyle iliskili
loglari bir araya getirip 'incident' gruplari olusturur.

Yaklasim: her satir bir dugum, iki satir arasinda su durumlarda kenar (edge)
kurulur --
  (a) app/correlation/fields.py'deki CORRELATION_FIELDS alanlarindan herhangi
      biri iki satirda da dolu ve birebir ayni (buyuk/kucuk harf duyarsiz), VEYA
  (b) surec soy zinciri (process lineage): birinin ProcessGuid'i digerinin
      ParentProcessGuid'ine esit (GUID yoksa ProcessId/ParentProcessId'e
      dusulur) --
ve (eger IKI satirin da zaman damgasi varsa) aralarindaki fark CORRELATION_WINDOW
icinde kalir. Baglanan dugumler union-find ile bilesenlere (connected
components) ayrilir; yalnizca 2+ satir iceren bilesenler 'incident' sayilir --
tek basina kalan satirlar hicbir incident'e dahil edilmez (kullanici talebi:
iliskisiz loglar icin incident uydurulmasin).

Bilinen tasarim tercihi: eslesme "herhangi bir alan" mantigiyla calisir,
agirliklandirilmamistir -- kullanicinin spesifikasyonu boyle (13 alanin
herhangi biri korelasyon kurabilir). Uzun bir CSV'de ayni Hostname/Username'in
cok tekrarlanmasi beklenenden genis gruplar olusturabilir; CORRELATION_WINDOW
bunu zaman ekseninde sinirlar."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from app.correlation.fields import CORRELATION_FIELDS

CORRELATION_WINDOW = timedelta(hours=24)

_GUID_PAIRS = [("ProcessGuid", "ParentProcessGuid")]
_ID_FALLBACK_PAIRS = [("ProcessId", "ParentProcessId")]


class _UnionFind:
    def __init__(self, indices: list[int]) -> None:
        self.parent = {i: i for i in indices}

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _within_window(item_a: dict[str, Any], item_b: dict[str, Any]) -> bool:
    ts_a, ts_b = item_a.get("timestamp"), item_b.get("timestamp")
    if ts_a is None or ts_b is None:
        return True
    return abs(ts_a - ts_b) <= CORRELATION_WINDOW


def _shares_field(fields_a: dict[str, str | None], fields_b: dict[str, str | None]) -> bool:
    for name in CORRELATION_FIELDS:
        va, vb = fields_a.get(name), fields_b.get(name)
        if va and vb and va.casefold() == vb.casefold():
            return True
    return False


def _shares_process_lineage(fields_a: dict[str, str | None], fields_b: dict[str, str | None]) -> bool:
    for child_key, parent_key in _GUID_PAIRS:
        guid_a, parent_a = fields_a.get(child_key), fields_a.get(parent_key)
        guid_b, parent_b = fields_b.get(child_key), fields_b.get(parent_key)
        if guid_a and parent_b and guid_a.casefold() == parent_b.casefold():
            return True
        if guid_b and parent_a and guid_b.casefold() == parent_a.casefold():
            return True
    # GUID yoksa ProcessId/ParentProcessId'e dusulur -- PID'ler zaman icinde
    # yeniden kullanilabildiginden GUID'e gore daha az guvenilir, bu yuzden
    # yalnizca GUID hic yoksa devreye girer.
    if fields_a.get("ProcessGuid") or fields_b.get("ProcessGuid"):
        return False
    for child_key, parent_key in _ID_FALLBACK_PAIRS:
        pid_a, ppid_a = fields_a.get(child_key), fields_a.get(parent_key)
        pid_b, ppid_b = fields_b.get(child_key), fields_b.get(parent_key)
        if pid_a and ppid_b and pid_a.casefold() == ppid_b.casefold():
            return True
        if pid_b and ppid_a and pid_b.casefold() == ppid_a.casefold():
            return True
    return False


def build_incident_groups(items: list[dict[str, Any]]) -> list[list[int]]:
    """items[i]: 'index', 'skipped', 'correlation_fields', 'timestamp' anahtarlarini
    icermeli (bkz. app/batch/orchestrator.py). Donus: her biri en az 2 satir
    iceren, orijinal satir index'lerinden olusan gruplarin listesi (kucukten
    buyuge sirali)."""
    usable = [it for it in items if not it.get("skipped")]
    uf = _UnionFind([it["index"] for it in usable])

    for a in range(len(usable)):
        for b in range(a + 1, len(usable)):
            item_a, item_b = usable[a], usable[b]
            if not _within_window(item_a, item_b):
                continue
            fields_a, fields_b = item_a["correlation_fields"], item_b["correlation_fields"]
            if _shares_field(fields_a, fields_b) or _shares_process_lineage(fields_a, fields_b):
                uf.union(item_a["index"], item_b["index"])

    groups: dict[int, list[int]] = {}
    for it in usable:
        root = uf.find(it["index"])
        groups.setdefault(root, []).append(it["index"])

    return sorted((sorted(g) for g in groups.values() if len(g) >= 2), key=lambda g: g[0])
