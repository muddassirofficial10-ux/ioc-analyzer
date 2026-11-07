from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("lookup/<int:pk>/", views.lookup_detail, name="lookup-detail"),
    path("history/", views.history, name="history"),
    path("email-headers/", views.email_headers, name="email-headers"),
    # REST API
    path("api/analyze/", views.api_analyze, name="api-analyze"),
    path("api/headers/", views.api_headers, name="api-headers"),
    path("api/lookups/", views.LookupList.as_view(), name="api-lookups"),
    path("api/lookups/<int:pk>/", views.LookupDetail.as_view(), name="api-lookup-detail"),
    path("api/health/", views.api_health, name="api-health"),
]
