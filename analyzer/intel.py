"""Threat-intelligence source clients (VirusTotal, AbuseIPDB, urlscan.io).

Each client returns a `SourceResult` and never raises: network errors,
missing API keys and unsupported indicator types become a status the UI
can show, so one failing source never breaks a whole analysis.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from typing import Any

import requests
from django.conf import settings

from . import indicators as ind

OK = "ok"
NOT_CONFIGURED = "not_configured"
UNSUPPORTED = "unsupported"
NOT_FOUND = "not_found"
ERROR = "error"


@dataclass
class SourceResult:
    source: str
    status: str
    score: int = 0  # 0 (clean) .. 100 (malicious), this source's opinion
    summary: str = ""
    link: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _cfg(key: str) -> Any:
    return settings.THREAT_INTEL.get(key)


class BaseClient:
    name = "base"
    supports: tuple[str, ...] = ()
    key_setting = ""

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()
        self.timeout = _cfg("TIMEOUT") or 10

    @property
    def api_key(self) -> str:
        return _cfg(self.key_setting) or ""

    def lookup(self, indicator: ind.Indicator) -> SourceResult:
        if indicator.kind not in self.supports:
            return SourceResult(self.name, UNSUPPORTED, summary=f"{self.name} does not check {indicator.kind}s")
        if self.key_setting and not self.api_key:
            return SourceResult(self.name, NOT_CONFIGURED, summary=f"Set {self.key_setting} to enable {self.name}")
        try:
            return self._lookup(indicator)
        except requests.RequestException as exc:
            return SourceResult(self.name, ERROR, summary=f"Request failed: {exc.__class__.__name__}")
        except (ValueError, KeyError) as exc:
            return SourceResult(self.name, ERROR, summary=f"Unexpected response: {exc}")

    def _lookup(self, indicator: ind.Indicator) -> SourceResult:  # pragma: no cover - abstract
        raise NotImplementedError


class VirusTotalClient(BaseClient):
    name = "VirusTotal"
    supports = (ind.IP, ind.DOMAIN, ind.URL, ind.HASH)
    key_setting = "VIRUSTOTAL_API_KEY"
    base = "https://www.virustotal.com/api/v3"

    def _path(self, indicator: ind.Indicator) -> tuple[str, str]:
        if indicator.kind == ind.IP:
            return f"ip_addresses/{indicator.value}", f"https://www.virustotal.com/gui/ip-address/{indicator.value}"
        if indicator.kind == ind.DOMAIN:
            return f"domains/{indicator.value}", f"https://www.virustotal.com/gui/domain/{indicator.value}"
        if indicator.kind == ind.HASH:
            return f"files/{indicator.value}", f"https://www.virustotal.com/gui/file/{indicator.value}"
        url_id = base64.urlsafe_b64encode(indicator.value.encode()).decode().strip("=")
        return f"urls/{url_id}", f"https://www.virustotal.com/gui/url/{url_id}"

    def _lookup(self, indicator: ind.Indicator) -> SourceResult:
        path, link = self._path(indicator)
        resp = self.session.get(f"{self.base}/{path}", headers={"x-apikey": self.api_key}, timeout=self.timeout)
        if resp.status_code == 404:
            return SourceResult(self.name, NOT_FOUND, summary="Not seen by VirusTotal", link=link)
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = min(100, round(100 * (malicious + 0.5 * suspicious) / total * 4))  # 25% of engines => 100
        if malicious >= 3:
            score = max(score, 80)
        return SourceResult(
            self.name, OK, score,
            summary=f"{malicious} malicious, {suspicious} suspicious of {total} engines",
            link=link,
            data={"stats": stats, "reputation": attrs.get("reputation"), "tags": attrs.get("tags", [])[:10]},
        )


class AbuseIPDBClient(BaseClient):
    name = "AbuseIPDB"
    supports = (ind.IP,)
    key_setting = "ABUSEIPDB_API_KEY"

    def _lookup(self, indicator: ind.Indicator) -> SourceResult:
        link = f"https://www.abuseipdb.com/check/{indicator.value}"
        if indicator.is_private_ip:
            return SourceResult(self.name, UNSUPPORTED, summary="Private/internal IP - not checked", link=link)
        resp = self.session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": indicator.value, "maxAgeInDays": 90},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        d = resp.json()["data"]
        confidence = int(d.get("abuseConfidenceScore", 0))
        return SourceResult(
            self.name, OK, confidence,
            summary=f"Abuse confidence {confidence}% from {d.get('totalReports', 0)} reports",
            link=link,
            data={k: d.get(k) for k in ("countryCode", "isp", "usageType", "domain", "totalReports", "lastReportedAt", "isTor")},
        )


class UrlscanClient(BaseClient):
    """Searches existing urlscan.io scans (no new scan is submitted)."""

    name = "urlscan.io"
    supports = (ind.DOMAIN, ind.URL, ind.IP)
    key_setting = ""  # search works without a key; a key raises rate limits

    def _lookup(self, indicator: ind.Indicator) -> SourceResult:
        host = ind.host_of(indicator)
        field_name = "page.ip" if indicator.kind == ind.IP else "page.domain"
        headers = {"API-Key": _cfg("URLSCAN_API_KEY")} if _cfg("URLSCAN_API_KEY") else {}
        resp = self.session.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"{field_name}:{host}", "size": 10},
            headers=headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
        link = f"https://urlscan.io/search/#{field_name}:{host}"
        if not results:
            return SourceResult(self.name, NOT_FOUND, summary="No previous scans", link=link)
        malicious = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious"))
        score = 90 if malicious else 0
        return SourceResult(
            self.name, OK, score,
            summary=f"{len(results)} recent scans, {malicious} flagged malicious",
            link=link,
            data={"scans": [{"url": r.get("page", {}).get("url"), "time": r.get("task", {}).get("time")} for r in results[:5]]},
        )


def default_clients(session: requests.Session | None = None) -> list[BaseClient]:
    return [VirusTotalClient(session), AbuseIPDBClient(session), UrlscanClient(session)]
