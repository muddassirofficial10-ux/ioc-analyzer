"""Orchestrates an analysis: detect the indicator, query sources, score, save."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from . import indicators as ind
from . import intel
from .models import Lookup

MALICIOUS_AT = 70
SUSPICIOUS_AT = 25


def verdict_for(results: list[intel.SourceResult]) -> tuple[str, int]:
    """Combine source opinions. The strongest signal wins, since one confident
    detection (e.g. many AV engines) matters more than other sources being silent."""
    scored = [r for r in results if r.status == intel.OK]
    if not scored:
        seen = any(r.status == intel.NOT_FOUND for r in results)
        return (Lookup.Verdict.CLEAN if seen else Lookup.Verdict.UNKNOWN), 0
    score = max(r.score for r in scored)
    if score >= MALICIOUS_AT:
        return Lookup.Verdict.MALICIOUS, score
    if score >= SUSPICIOUS_AT:
        return Lookup.Verdict.SUSPICIOUS, score
    return Lookup.Verdict.CLEAN, score


def analyze(raw: str, clients: list[intel.BaseClient] | None = None) -> Lookup:
    indicator = ind.detect(raw)
    if indicator.kind == ind.UNKNOWN:
        raise ValueError("Could not recognise this as an IP, domain, URL or file hash.")

    clients = clients if clients is not None else intel.default_clients()
    with ThreadPoolExecutor(max_workers=max(1, len(clients))) as pool:
        results = list(pool.map(lambda c: c.lookup(indicator), clients))

    verdict, score = verdict_for(results)
    return Lookup.objects.create(
        raw_input=raw[:4096],
        indicator=indicator.value,
        kind=indicator.kind,
        verdict=verdict,
        score=score,
        results=[r.to_dict() for r in results],
    )
