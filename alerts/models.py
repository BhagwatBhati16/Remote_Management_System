from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class AlertRule(models.Model):
    """Configurable monitoring rule — process name, window keyword, or website domain."""

    RULE_TYPE_CHOICES = [
        ("process_name", "Process Name"),
        ("window_keyword", "Window Keyword"),
        ("website_domain", "Website Domain"),
    ]

    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES)
    value = models.CharField(max_length=200, help_text="Process name, keyword, or domain to flag")
    is_active = models.BooleanField(default=True)
    added_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("rule_type", "value")
        ordering = ["rule_type", "value"]

    def __str__(self):
        return f"[{self.get_rule_type_display()}] {self.value}"


class Alert(models.Model):
    """A single detection event sent from a client PC."""

    ALERT_TYPE_CHOICES = [
        ("process", "Process Detected"),
        ("window_title", "Window Title Detected"),
    ]

    client = models.ForeignKey(
        "clients.Client",
        on_delete=models.CASCADE,
        related_name="alerts",
        null=True,
        blank=True,
    )
    client_ip = models.GenericIPAddressField(protocol="IPv4")
    hostname = models.CharField(max_length=100, blank=True, default="")
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPE_CHOICES)
    detected_name = models.CharField(max_length=300)
    process_list = models.TextField(blank=True, default="[]", help_text="JSON array of running processes")
    timestamp = models.DateTimeField(help_text="When the client detected the event")
    received_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True, db_index=True)
    dismissed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="dismissed_alerts")
    dismissed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-received_at"]
        indexes = [
            models.Index(fields=["client_ip", "detected_name", "received_at"]),
        ]

    def __str__(self):
        return f"Alert: {self.detected_name} on {self.client_ip} ({self.get_alert_type_display()})"
