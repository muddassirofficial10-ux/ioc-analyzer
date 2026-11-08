"""Threat-intelligence source clients (VirusTotal, AbuseIPDB, urlscan.io, AlienVault OTX, MxToolbox).

Each client returns a `SourceResult` and never raises: network errors,
missing API keys and unsupported indicator types become a status the UI
can show, so one failing source never breaks a whole analysis.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import quote

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


class AlienVaultOTXClient(BaseClient):
    """AlienVault OTX: how many community threat reports ("pulses") mention this indicator.

    The `general` endpoint works without a key (lower rate limit); a free key raises the limit.
    """

    name = "AlienVault OTX"
    supports = (ind.IP, ind.DOMAIN, ind.URL, ind.HASH)
    key_setting = ""  # optional - see OTX_API_KEY
    base = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, session: requests.Session | None = None):
        super().__init__(session)
        # Heavily reported indicators return large responses (~70 KB) that take 10-15 s.
        self.timeout = max(self.timeout, float(_cfg("OTX_TIMEOUT") or 25))

    def _path(self, indicator: ind.Indicator) -> tuple[str, str]:
        value = indicator.value
        if indicator.kind == ind.IP:
            section = "IPv6" if ":" in value else "IPv4"
            return f"{section}/{value}", f"https://otx.alienvault.com/indicator/ip/{value}"
        if indicator.kind == ind.DOMAIN:
            # OTX separates registrable domains (example.com) from hostnames (mail.example.com).
            section = "domain" if value.count(".") == 1 else "hostname"
            return f"{section}/{value}", f"https://otx.alienvault.com/indicator/{section}/{value}"
        if indicator.kind == ind.HASH:
            return f"file/{value}", f"https://otx.alienvault.com/indicator/file/{value}"
        encoded = quote(value, safe=":/")
        return f"url/{encoded}", f"https://otx.alienvault.com/indicator/url/{encoded}"

    def _lookup(self, indicator: ind.Indicator) -> SourceResult:
        path, link = self._path(indicator)
        headers = {"X-OTX-API-KEY": _cfg("OTX_API_KEY")} if _cfg("OTX_API_KEY") else {}
        resp = self.session.get(f"{self.base}/{path}/general", headers=headers, timeout=self.timeout)
        if resp.status_code == 404:
            return SourceResult(self.name, NOT_FOUND, summary="Not known to OTX", link=link)
        resp.raise_for_status()
        body = resp.json()

        # OTX marks well-known infrastructure (e.g. 8.8.8.8) as whitelisted / false positive.
        validation = [v.get("name", "") for v in body.get("validation") or []]
        if any(v.lower().startswith(("whitelisted", "known false positive")) for v in validation):
            return SourceResult(self.name, OK, 0, summary=f"Trusted by OTX ({', '.join(validation)})", link=link,
                                data={"validation": validation})

        pulse_info = body.get("pulse_info") or {}
        count = int(pulse_info.get("count") or 0)
        pulses = pulse_info.get("pulses") or []
        malware = sorted({m.get("display_name") for p in pulses for m in p.get("malware_families") or [] if m.get("display_name")})
        tags = sorted({t for p in pulses for t in (p.get("tags") or [])})
        if count >= 10:
            score = 85
        elif count >= 3:
            score = 60
        elif count >= 1:
            score = 30
        else:
            score = 0
        return SourceResult(
            self.name, OK, score,
            summary=f"Mentioned in {count} threat report{'s' if count != 1 else ''} (pulses)",
            link=link,
            data={"malware_families": malware[:8], "tags": tags[:10], "pulses": [p.get("name") for p in pulses[:5]]},
        )


class MxToolboxClient(BaseClient):
    """MxToolbox blacklist check: is this IP/domain listed on spam/abuse blocklists?

    Note: MxToolbox counts blacklist checks as "Network" requests, which the free plan does not include.
    """

    name = "MxToolbox"
    supports = (ind.IP, ind.DOMAIN, ind.URL)  # URLs are checked by their host
    key_setting = "MXTOOLBOX_API_KEY"

    def _lookup(self, indicator: ind.Indicator) -> SourceResult:
        target = ind.host_of(indicator)
        link = f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{target}"
        if indicator.is_private_ip:
            return SourceResult(self.name, UNSUPPORTED, summary="Private/internal IP - not checked", link=link)
        resp = self.session.get(
            "https://api.mxtoolbox.com/api/v1/Lookup/blacklist/",
            params={"argument": target},
            headers={"Authorization": self.api_key},  # plain key, no "Bearer"
            timeout=self.timeout,
        )
        if resp.status_code == 401:
            return SourceResult(self.name, ERROR, summary="API key rejected (check MXTOOLBOX_API_KEY)", link=link)
        if resp.status_code == 429:
            return SourceResult(self.name, ERROR, summary="Quota exceeded (blacklist checks need a paid MxToolbox plan)", link=link)
        resp.raise_for_status()
        body = resp.json()
        failed = [f.get("Name") for f in body.get("Failed") or []]
        warnings = [w.get("Name") for w in body.get("Warnings") or []]
        checked = len(failed) + len(warnings) + len(body.get("Passed") or [])
        score = 0 if not failed else min(100, 40 + 15 * (len(failed) - 1))
        return SourceResult(
            self.name, OK, score,
            summary=f"Listed on {len(failed)} of {checked} blacklists" + (f", {len(warnings)} warnings" if warnings else ""),
            link=link,
            data={"blacklisted_on": failed[:10], "warnings": warnings[:5]},
        )


def default_clients(session: requests.Session | None = None) -> list[BaseClient]:
    return [
        VirusTotalClient(session),
        AbuseIPDBClient(session),
        UrlscanClient(session),
        AlienVaultOTXClient(session),
        MxToolboxClient(session),
    ]
