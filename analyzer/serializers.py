from dataclasses import asdict

from rest_framework import serializers

from .indicators import defang
from .models import Lookup


class LookupSerializer(serializers.ModelSerializer):
    defanged = serializers.SerializerMethodField()

    class Meta:
        model = Lookup
        fields = ["id", "indicator", "defanged", "kind", "verdict", "score", "results", "created_at"]

    def get_defanged(self, obj: Lookup) -> str:
        return defang(obj.indicator)


class AnalyzeRequestSerializer(serializers.Serializer):
    indicator = serializers.CharField(max_length=2048, trim_whitespace=True)


class HeadersRequestSerializer(serializers.Serializer):
    headers = serializers.CharField(max_length=100_000)


def header_report_to_dict(report) -> dict:
    return {
        "subject": report.subject,
        "from": report.from_address,
        "from_domain": report.from_domain,
        "reply_to": report.reply_to,
        "return_path": report.return_path,
        "auth": report.auth,
        "relay_ips": report.relay_ips,
        "risk": report.risk,
        "findings": [asdict(f) for f in report.findings],
        "indicators": report.indicators,
    }
