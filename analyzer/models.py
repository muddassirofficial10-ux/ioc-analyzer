from django.db import models


class Lookup(models.Model):
    class Verdict(models.TextChoices):
        MALICIOUS = "malicious", "Malicious"
        SUSPICIOUS = "suspicious", "Suspicious"
        CLEAN = "clean", "No detections"
        UNKNOWN = "unknown", "Unknown"

    raw_input = models.TextField()
    indicator = models.CharField(max_length=2048)
    kind = models.CharField(max_length=16)
    verdict = models.CharField(max_length=16, choices=Verdict.choices, default=Verdict.UNKNOWN)
    score = models.PositiveSmallIntegerField(default=0)
    results = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["indicator"]), models.Index(fields=["-created_at"])]

    def __str__(self) -> str:
        return f"{self.indicator} ({self.verdict})"
