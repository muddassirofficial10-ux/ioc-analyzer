from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods
from rest_framework import generics, status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from . import services
from .email_headers import analyze_headers
from .indicators import defang
from .models import Lookup
from .serializers import (
    AnalyzeRequestSerializer,
    HeadersRequestSerializer,
    LookupSerializer,
    header_report_to_dict,
)

SOURCE_KEYS = {"VirusTotal": "VIRUSTOTAL_API_KEY", "AbuseIPDB": "ABUSEIPDB_API_KEY", "urlscan.io": None}


def _sources_status():
    cfg = settings.THREAT_INTEL
    return [{"name": n, "enabled": (k is None) or bool(cfg.get(k))} for n, k in SOURCE_KEYS.items()]


# ---------- Web pages ----------

@require_http_methods(["GET", "POST"])
def index(request):
    if request.method == "POST":
        raw = request.POST.get("indicator", "").strip()
        if not raw:
            messages.error(request, "Enter an IP, domain, URL or file hash.")
        else:
            try:
                lookup = services.analyze(raw)
                return redirect("lookup-detail", pk=lookup.pk)
            except ValueError as exc:
                messages.error(request, str(exc))
    recent = Lookup.objects.all()[:8]
    return render(request, "analyzer/index.html", {"recent": recent, "sources": _sources_status()})


def lookup_detail(request, pk):
    lookup = get_object_or_404(Lookup, pk=pk)
    return render(request, "analyzer/detail.html", {"lookup": lookup, "defanged": defang(lookup.indicator)})


def history(request):
    qs = Lookup.objects.all()
    verdict = request.GET.get("verdict")
    if verdict in Lookup.Verdict.values:
        qs = qs.filter(verdict=verdict)
    page = Paginator(qs, 25).get_page(request.GET.get("page"))
    return render(request, "analyzer/history.html", {"page": page, "verdict": verdict, "verdicts": Lookup.Verdict.choices})


@require_http_methods(["GET", "POST"])
def email_headers(request):
    report, raw = None, ""
    if request.method == "POST":
        raw = request.POST.get("headers", "")
        if raw.strip():
            report = analyze_headers(raw)
        else:
            messages.error(request, "Paste the raw email headers first.")
    return render(request, "analyzer/headers.html", {"report": report, "raw": raw})


# ---------- REST API ----------

@api_view(["POST"])
def api_analyze(request):
    req = AnalyzeRequestSerializer(data=request.data)
    req.is_valid(raise_exception=True)
    try:
        lookup = services.analyze(req.validated_data["indicator"])
    except ValueError as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    return Response(LookupSerializer(lookup).data, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def api_headers(request):
    req = HeadersRequestSerializer(data=request.data)
    req.is_valid(raise_exception=True)
    return Response(header_report_to_dict(analyze_headers(req.validated_data["headers"])))


@api_view(["GET"])
def api_health(request):
    return Response({"status": "ok", "sources": _sources_status()})


class LookupList(generics.ListAPIView):
    serializer_class = LookupSerializer

    def get_queryset(self):
        qs = Lookup.objects.all()
        if v := self.request.query_params.get("verdict"):
            qs = qs.filter(verdict=v)
        if q := self.request.query_params.get("q"):
            qs = qs.filter(indicator__icontains=q)
        return qs


class LookupDetail(generics.RetrieveAPIView):
    queryset = Lookup.objects.all()
    serializer_class = LookupSerializer
