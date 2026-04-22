from django.contrib import admin
from .models import Alert, AlertRule


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ("value", "rule_type", "is_active", "added_by", "created_at")
    list_filter = ("rule_type", "is_active")
    search_fields = ("value",)


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("detected_name", "client_ip", "hostname", "alert_type", "is_active", "received_at")
    list_filter = ("alert_type", "is_active")
    search_fields = ("detected_name", "client_ip", "hostname")
    raw_id_fields = ("client",)
