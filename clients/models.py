from django.db import models
from django.contrib.auth import get_user_model


class Client(models.Model):
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(protocol="IPv4")
    os_name = models.CharField(max_length=100, blank=True, default="")
    # SSH + Glances + Files config
    ssh_port = models.PositiveIntegerField(default=22)
    ssh_username = models.CharField(max_length=100, blank=True, default="")
    ssh_password = models.CharField(max_length=255, blank=True, default="")  # optional, prefer keys
    ssh_private_key_path = models.CharField(max_length=255, blank=True, default="")  # optional
    glances_port = models.PositiveIntegerField(default=61208)
    mac_address = models.CharField(max_length=17, blank=True, default="", help_text="e.g. AA:BB:CC:DD:EE:FF — required for Wake on LAN")
    # Hardware info (auto-detected during registration)
    cpu = models.CharField(max_length=200, blank=True, default="")
    ram_gb = models.PositiveIntegerField(null=True, blank=True)
    disk_gb = models.PositiveIntegerField(null=True, blank=True)
    os_version = models.CharField(max_length=50, blank=True, default="")
    vnc_port = models.PositiveIntegerField(default=5900)
    # Tracking
    last_seen = models.DateTimeField(null=True, blank=True)
    auto_registered = models.BooleanField(default=False)
    admin_viewed = models.BooleanField(default=True)  # False for auto-registered until admin opens detail page

    def __str__(self):
        return f"{self.name} ({self.ip_address})"


class VNCSession(models.Model):
    client = models.OneToOneField(Client, on_delete=models.CASCADE, related_name="vnc_session")
    started_at = models.DateTimeField(auto_now_add=True)
    pid = models.IntegerField()
    listen_host = models.CharField(max_length=100, default="127.0.0.1")
    listen_port = models.IntegerField(default=6080)
    started_by = models.ForeignKey(get_user_model(), null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"VNCSession for {self.client} (pid {self.pid})"


class SSHSession(models.Model):
    client = models.OneToOneField(Client, on_delete=models.CASCADE, related_name="ssh_session")
    pid = models.IntegerField(null=True, blank=True)
    listen_host = models.CharField(max_length=64, default="127.0.0.1")
    listen_port = models.PositiveIntegerField(default=8022)
    started_at = models.DateTimeField(auto_now_add=True)
    started_by = models.ForeignKey(get_user_model(), null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"SSHSession({self.client.name}@{self.listen_host}:{self.listen_port}, pid={self.pid})"
