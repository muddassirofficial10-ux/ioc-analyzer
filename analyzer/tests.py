from unittest import mock

import requests
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from . import indicators as ind
from . import intel, services
from .email_headers import analyze_headers
from .models import Lookup

KEYS = {"VIRUSTOTAL_API_KEY": "vt-test", "ABUSEIPDB_API_KEY": "ab-test", "URLSCAN_API_KEY": "", "TIMEOUT": 5}


def fake_response(status=200, payload=None):
    resp = mock.Mock()
    resp.status_code = status
    resp.json.return_value = payload or {}
    if status >= 400 and status != 404:
        resp.raise_for_status.side_effect = requests.HTTPError(f"{status}")
    else:
        resp.raise_for_status.return_value = None
    return resp


class IndicatorTests(TestCase):
    def test_detects_types(self):
        cases = {
            "8.8.8.8": ind.IP,
            "2001:4860:4860::8888": ind.IP,
            "example.com": ind.DOMAIN,
            "https://example.com/login?x=1": ind.URL,
            "44d88612fea8a8f36de82e1278abb02f": ind.HASH,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": ind.HASH,
            "not an indicator": ind.UNKNOWN,
        }
        for raw, kind in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(ind.detect(raw).kind, kind)

    def test_refangs_defanged_input(self):
        self.assertEqual(ind.detect("hxxps://evil[.]example[.]com/a").value, "https://evil.example.com/a")
        self.assertEqual(ind.detect("1[.]2[.]3[.]4").value, "1.2.3.4")

    def test_private_ip_flag(self):
        self.assertTrue(ind.detect("192.168.1.10").is_private_ip)
        self.assertFalse(ind.detect("8.8.8.8").is_private_ip)

    def test_defang_for_display(self):
        self.assertEqual(ind.defang("http://evil.com"), "hxxp://evil[.]com")


@override_settings(THREAT_INTEL=KEYS)
class ClientTests(TestCase):
    def test_virustotal_scores_malicious(self):
        session = mock.Mock()
        session.get.return_value = fake_response(payload={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 10},
            "reputation": -40, "tags": ["phishing"],
        }}})
        result = intel.VirusTotalClient(session).lookup(ind.detect("evil.example.com"))
        self.assertEqual(result.status, intel.OK)
        self.assertGreaterEqual(result.score, 80)
        self.assertIn("12 malicious", result.summary)
        self.assertEqual(session.get.call_args.kwargs["headers"]["x-apikey"], "vt-test")

    def test_virustotal_not_found(self):
        session = mock.Mock()
        session.get.return_value = fake_response(status=404)
        result = intel.VirusTotalClient(session).lookup(ind.detect("8.8.8.8"))
        self.assertEqual(result.status, intel.NOT_FOUND)

    def test_abuseipdb_skips_unsupported_types_and_private_ips(self):
        client = intel.AbuseIPDBClient(mock.Mock())
        self.assertEqual(client.lookup(ind.detect("example.com")).status, intel.UNSUPPORTED)
        self.assertEqual(client.lookup(ind.detect("10.0.0.5")).status, intel.UNSUPPORTED)

    def test_abuseipdb_confidence(self):
        session = mock.Mock()
        session.get.return_value = fake_response(payload={"data": {"abuseConfidenceScore": 100, "totalReports": 321, "countryCode": "NL"}})
        result = intel.AbuseIPDBClient(session).lookup(ind.detect("185.220.101.1"))
        self.assertEqual(result.score, 100)
        self.assertEqual(result.data["countryCode"], "NL")

    @override_settings(THREAT_INTEL={**KEYS, "VIRUSTOTAL_API_KEY": ""})
    def test_missing_key_is_reported_not_raised(self):
        result = intel.VirusTotalClient(mock.Mock()).lookup(ind.detect("8.8.8.8"))
        self.assertEqual(result.status, intel.NOT_CONFIGURED)

    def test_network_error_is_contained(self):
        session = mock.Mock()
        session.get.side_effect = requests.ConnectionError("down")
        result = intel.VirusTotalClient(session).lookup(ind.detect("8.8.8.8"))
        self.assertEqual(result.status, intel.ERROR)

    def test_urlscan_flags_malicious_scans(self):
        session = mock.Mock()
        session.get.return_value = fake_response(payload={"results": [
            {"page": {"url": "https://evil.example.com"}, "task": {"time": "2026-11-01"}, "verdicts": {"overall": {"malicious": True}}},
        ]})
        result = intel.UrlscanClient(session).lookup(ind.detect("evil.example.com"))
        self.assertEqual(result.score, 90)


@override_settings(THREAT_INTEL={**KEYS, "OTX_API_KEY": "", "MXTOOLBOX_API_KEY": "mx-test"})
class NewSourceTests(TestCase):
    """AlienVault OTX and MxToolbox (responses shaped like the real APIs)."""

    def test_otx_many_pulses_is_malicious(self):
        session = mock.Mock()
        session.get.return_value = fake_response(payload={"validation": [], "pulse_info": {"count": 50, "pulses": [
            {"name": "Tor exit nodes", "tags": ["tor", "scanner"], "malware_families": [{"display_name": "Mirai"}]},
        ]}})
        result = intel.AlienVaultOTXClient(session).lookup(ind.detect("185.220.101.1"))
        self.assertEqual(result.status, intel.OK)
        self.assertEqual(result.score, 85)
        self.assertEqual(result.data["malware_families"], ["Mirai"])
        self.assertIn("/IPv4/185.220.101.1/general", session.get.call_args.args[0])
        self.assertNotIn("X-OTX-API-KEY", session.get.call_args.kwargs["headers"])  # works without a key

    def test_otx_whitelisted_is_clean(self):
        session = mock.Mock()
        session.get.return_value = fake_response(payload={
            "validation": [{"name": "Whitelisted IP"}, {"name": "Known False Positive"}],
            "pulse_info": {"count": 3, "pulses": []},
        })
        result = intel.AlienVaultOTXClient(session).lookup(ind.detect("8.8.8.8"))
        self.assertEqual(result.score, 0)
        self.assertIn("Trusted", result.summary)

    def test_otx_paths_per_type(self):
        client = intel.AlienVaultOTXClient(mock.Mock())
        self.assertTrue(client._path(ind.detect("example.com"))[0].startswith("domain/"))
        self.assertTrue(client._path(ind.detect("mail.example.com"))[0].startswith("hostname/"))
        self.assertTrue(client._path(ind.detect("44d88612fea8a8f36de82e1278abb02f"))[0].startswith("file/"))
        self.assertTrue(client._path(ind.detect("2001:db8::1"))[0].startswith("IPv6/"))

    def test_mxtoolbox_blacklisted(self):
        session = mock.Mock()
        session.get.return_value = fake_response(payload={
            "Failed": [{"Name": "Spamhaus ZEN"}, {"Name": "Barracuda"}],
            "Warnings": [], "Passed": [{"Name": f"BL{i}"} for i in range(80)], "Timeouts": [],
        })
        result = intel.MxToolboxClient(session).lookup(ind.detect("https://bad.example.com/login"))
        self.assertEqual(result.score, 55)
        self.assertIn("2 of 82", result.summary)
        self.assertEqual(session.get.call_args.kwargs["params"], {"argument": "bad.example.com"})  # URL -> host
        self.assertEqual(session.get.call_args.kwargs["headers"], {"Authorization": "mx-test"})

    def test_mxtoolbox_quota_message(self):
        session = mock.Mock()
        session.get.return_value = fake_response(status=429)
        result = intel.MxToolboxClient(session).lookup(ind.detect("example.com"))
        self.assertEqual(result.status, intel.ERROR)
        self.assertIn("paid", result.summary)

    @override_settings(THREAT_INTEL={**KEYS, "MXTOOLBOX_API_KEY": ""})
    def test_mxtoolbox_needs_key_and_skips_hashes(self):
        client = intel.MxToolboxClient(mock.Mock())
        self.assertEqual(client.lookup(ind.detect("example.com")).status, intel.NOT_CONFIGURED)
        self.assertEqual(client.lookup(ind.detect("44d88612fea8a8f36de82e1278abb02f")).status, intel.UNSUPPORTED)


class FakeClient(intel.BaseClient):
    name = "Fake"
    supports = (ind.IP, ind.DOMAIN, ind.URL, ind.HASH)

    def __init__(self, score, status=intel.OK):
        super().__init__(mock.Mock())
        self._score, self._status = score, status

    def _lookup(self, indicator):
        return intel.SourceResult(self.name, self._status, self._score, "fake")


class ServiceTests(TestCase):
    def test_strongest_signal_wins(self):
        lookup = services.analyze("8.8.8.8", clients=[FakeClient(5), FakeClient(85)])
        self.assertEqual(lookup.verdict, Lookup.Verdict.MALICIOUS)
        self.assertEqual(lookup.score, 85)

    def test_suspicious_and_clean(self):
        self.assertEqual(services.analyze("8.8.8.8", clients=[FakeClient(40)]).verdict, Lookup.Verdict.SUSPICIOUS)
        self.assertEqual(services.analyze("8.8.8.8", clients=[FakeClient(0)]).verdict, Lookup.Verdict.CLEAN)

    def test_no_usable_sources_is_unknown(self):
        lookup = services.analyze("8.8.8.8", clients=[FakeClient(0, intel.NOT_CONFIGURED)])
        self.assertEqual(lookup.verdict, Lookup.Verdict.UNKNOWN)

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            services.analyze("hello world", clients=[])


PHISH_HEADERS = """Received: from mail.attacker.example (mail.attacker.example [203.0.113.45])
        by mx.google.com with ESMTPS id abc; Mon, 03 Nov 2026 10:00:00 +0000
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of billing@paypa1-secure.example does not designate 203.0.113.45 as permitted sender) smtp.mailfrom=billing@paypa1-secure.example;
       dkim=none;
       dmarc=fail (p=REJECT) header.from=paypal.com
From: "service@paypal.com" <billing@paypa1-secure.example>
Reply-To: refunds@collect-funds.example
Return-Path: <billing@paypa1-secure.example>
Subject: Your account has been limited
To: victim@example.com
"""

CLEAN_HEADERS = """Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com; Mon, 03 Nov 2026 10:00:00 +0000
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=friend@gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass header.from=gmail.com
From: Friend <friend@gmail.com>
Return-Path: <friend@gmail.com>
Subject: Lunch?
"""


class EmailHeaderTests(TestCase):
    def test_phishing_headers_are_high_risk(self):
        report = analyze_headers(PHISH_HEADERS)
        titles = " | ".join(f.title for f in report.findings)
        self.assertEqual(report.risk, "high")
        self.assertEqual(report.auth["spf"], "fail")
        self.assertEqual(report.auth["dmarc"], "fail")
        self.assertIn("Reply-To domain differs", titles)
        self.assertIn("Display name spoofs", titles)
        self.assertIn("203.0.113.45", report.relay_ips)
        self.assertIn("collect-funds.example", report.indicators)

    def test_clean_headers_are_low_risk(self):
        report = analyze_headers(CLEAN_HEADERS)
        self.assertEqual(report.risk, "low")
        self.assertEqual(report.auth, {"spf": "pass", "dkim": "pass", "dmarc": "pass"})


class ApiAndPageTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        patcher = mock.patch.object(intel, "default_clients", return_value=[FakeClient(90)])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_api_analyze_and_list(self):
        resp = self.api.post(reverse("api-analyze"), {"indicator": "hxxp://bad[.]example[.]com"}, format="json")
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["verdict"], "malicious")
        self.assertEqual(resp.json()["defanged"], "hxxp://bad[.]example[.]com")
        listing = self.api.get(reverse("api-lookups"), {"verdict": "malicious"}).json()
        self.assertEqual(listing["count"], 1)

    def test_api_rejects_bad_input(self):
        self.assertEqual(self.api.post(reverse("api-analyze"), {"indicator": "???"}, format="json").status_code, 400)
        self.assertEqual(self.api.post(reverse("api-analyze"), {}, format="json").status_code, 400)

    def test_api_headers(self):
        resp = self.api.post(reverse("api-headers"), {"headers": PHISH_HEADERS}, format="json")
        self.assertEqual(resp.json()["risk"], "high")

    def test_web_flow(self):
        resp = self.client.post(reverse("index"), {"indicator": "8.8.8.8"})
        self.assertEqual(resp.status_code, 302)
        page = self.client.get(resp["Location"])
        self.assertContains(page, "8[.]8[.]8[.]8")
        self.assertContains(page, "Malicious")
        self.assertContains(self.client.get(reverse("history")), "8[.]8[.]8[.]8")
        self.assertContains(self.client.post(reverse("email-headers"), {"headers": PHISH_HEADERS}), "high risk")

    def test_health(self):
        self.assertEqual(self.api.get(reverse("api-health")).json()["status"], "ok")
