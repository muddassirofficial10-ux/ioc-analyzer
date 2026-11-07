"""Indicator-of-compromise (IOC) parsing: refanging and type detection."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

IP = "ip"
DOMAIN = "domain"
URL = "url"
HASH = "hash"
UNKNOWN = "unknown"

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.I)
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[a-f0-9]+$", re.I)


@dataclass(frozen=True)
class Indicator:
    value: str
    kind: str
    detail: str = ""  # e.g. hash algorithm, or "private" for internal IPs

    @property
    def is_private_ip(self) -> bool:
        return self.kind == IP and self.detail == "private"


def refang(raw: str) -> str:
    """Undo common defanging so `hxxps://evil[.]com` becomes `https://evil.com`."""
    value = raw.strip().strip("'\"<>")
    replacements = [
        ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
        ("[:]", ":"), ("[://]", "://"), ("[@]", "@"), ("[at]", "@"),
    ]
    for old, new in replacements:
        value = value.replace(old, new)
    value = re.sub(r"^hxxp", "http", value, flags=re.I)
    value = re.sub(r"^fxp", "ftp", value, flags=re.I)
    return value


def defang(value: str) -> str:
    """Make an indicator safe to display or share (not clickable)."""
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    return value.replace(".", "[.]")


def detect(raw: str) -> Indicator:
    value = refang(raw)
    if not value:
        return Indicator(value, UNKNOWN)

    try:
        ip = ipaddress.ip_address(value)
        scope = "private" if (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local) else "public"
        return Indicator(str(ip), IP, scope)
    except ValueError:
        pass

    if _HEX_RE.match(value) and len(value) in _HASH_LENGTHS:
        return Indicator(value.lower(), HASH, _HASH_LENGTHS[len(value)])

    if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        parsed = urlparse(value)
        if parsed.hostname:
            return Indicator(value, URL)

    candidate = value.lower().rstrip(".")
    if _DOMAIN_RE.match(candidate):
        return Indicator(candidate, DOMAIN)

    return Indicator(value, UNKNOWN)


def host_of(indicator: Indicator) -> str | None:
    """Return the domain or IP behind an indicator (useful for URLs)."""
    if indicator.kind in (IP, DOMAIN):
        return indicator.value
    if indicator.kind == URL:
        return urlparse(indicator.value).hostname
    return None
