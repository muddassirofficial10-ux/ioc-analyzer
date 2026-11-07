from django.contrib import admin

from .models import Lookup


@admin.register(Lookup)
class LookupAdmin(admin.ModelAdmin):
    list_display = ("indicator", "kind", "verdict", "score", "created_at")
    list_filter = ("verdict", "kind")
    search_fields = ("indicator",)
    readonly_fields = ("results", "created_at")
