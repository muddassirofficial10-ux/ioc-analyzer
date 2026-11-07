"""Offline phishing triage of raw email headers.

Checks the things a SOC analyst looks at first: SPF/DKIM/DMARC results,
From vs Reply-To / Return-Path mismatches, and the relay IPs in the
Received chain. Extracted IPs and domains can then be sent to `analyze`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string, policy
from email.utils import getaddresses, parseaddr

from . import indicators as ind

_IP_IN_RECEIVED = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]|\((?:[^()]*?)(\d{1,3}(?:\.\d{1,3}){3})\)")
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""


@dataclass
class HeaderReport:
    subject: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    auth: dict[str, str] = field(default_factory=dict)
    relay_ips: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk(self) -> str:
        sev = {f.severity for f in self.findings}
        if HIGH in sev:
            return "high"
        if MEDIUM in sev:
            return "medium"
        return "low"

    @property
    def indicators(self) -> list[str]:
        """Public IPs and sender domains worth checking against threat intel."""
        out: list[str] = []
        for ip in self.relay_ips:
            i = ind.detect(ip)
            if i.kind == ind.IP and not i.is_private_ip and ip not in out:
                out.append(ip)
        for addr in (self.from_address, self.reply_to, self.return_path):
            dom = _domain(addr)
            if dom and dom not in out:
                out.append(dom)
        return out


def _domain(address: str) -> str:
    _, email = parseaddr(address or "")
    return email.rsplit("@", 1)[1].lower() if "@" in email else ""


def _org_domain(domain: str) -> str:
    """Rough organisational domain (last two labels) to avoid flagging mail.x.com vs x.com."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def analyze_headers(raw: str) -> HeaderReport:
    msg = message_from_string(raw.strip() + "\n\n", policy=policy.compat32)
    report = HeaderReport(
        subject=str(msg.get("Subject", "") or ""),
        from_address=str(msg.get("From", "") or ""),
        reply_to=str(msg.get("Reply-To", "") or ""),
        return_path=str(msg.get("Return-Path", "") or ""),
    )
    report.from_domain = _domain(report.from_address)

    if not report.from_address:
        report.findings.append(Finding(MEDIUM, "No From header found", "Paste the full raw headers (e.g. Gmail: Show original)."))

    # Authentication results (first value wins; most recent hop is listed first).
    for header in msg.get_all("Authentication-Results", []) + msg.get_all("ARC-Authentication-Results", []):
        for mech, result in _AUTH_RE.findall(str(header)):
            report.auth.setdefault(mech.lower(), result.lower())
    spf_header = msg.get("Received-SPF")
    if spf_header and "spf" not in report.auth:
        report.auth["spf"] = str(spf_header).split()[0].lower()

    for mech in ("spf", "dkim", "dmarc"):
        result = report.auth.get(mech)
        if result is None:
            report.findings.append(Finding(LOW, f"No {mech.upper()} result", "The receiving server did not record this check."))
        elif result in {"fail", "softfail", "permerror"}:
            sev = HIGH if mech == "dmarc" or result == "fail" else MEDIUM
            report.findings.append(Finding(sev, f"{mech.upper()} {result}", f"The sender failed {mech.upper()} authentication."))
        elif result in {"none", "neutral", "temperror"}:
            report.findings.append(Finding(LOW, f"{mech.upper()} {result}", "Authentication was inconclusive."))

    # Sender mismatches.
    if report.from_domain:
        for label, value in (("Reply-To", report.reply_to), ("Return-Path", report.return_path)):
            for _, addr in getaddresses([value]):
                dom = _domain(addr)
                if dom and _org_domain(dom) != _org_domain(report.from_domain):
                    sev = HIGH if label == "Reply-To" else MEDIUM
                    report.findings.append(Finding(sev, f"{label} domain differs from From", f"From: {report.from_domain} / {label}: {dom}"))

    display, _ = parseaddr(report.from_address)
    if display and re.search(r"[\w.-]+@[\w.-]+", display):
        shown = _domain(re.search(r"[\w.-]+@[\w.-]+", display).group(0))
        if shown and shown != report.from_domain:
            report.findings.append(Finding(HIGH, "Display name spoofs another address", f"Display shows {shown}, real sender is {report.from_domain}"))

    # Relay IPs, oldest hop last in the header list -> reverse to get origin first.
    for received in reversed(msg.get_all("Received", [])):
        for a, b in _IP_IN_RECEIVED.findall(str(received)):
            ip = a or b
            if ind.detect(ip).kind == ind.IP and ip not in report.relay_ips:
                report.relay_ips.append(ip)

    if not report.findings:
        report.findings.append(Finding(INFO, "No header red flags found", "Still check links and attachments before trusting the email."))
    return report
