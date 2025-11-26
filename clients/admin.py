from django.contrib import admin
from .models import Client, VNCSession, SSHSession


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ("name", "ip_address", "os_name", "ssh_username", "ssh_port", "glances_port")
    search_fields = ("name", "ip_address", "os_name", "ssh_username")


@admin.register(VNCSession)
class VNCSessionAdmin(admin.ModelAdmin):
    list_display = ("client", "pid", "listen_host", "listen_port", "started_by", "started_at")
    search_fields = ("client__name", "client__ip_address")


@admin.register(SSHSession)
class SSHSessionAdmin(admin.ModelAdmin):
    list_display = ("client", "pid", "listen_host", "listen_port", "started_by", "started_at")
    search_fields = ("client__name", "client__ip_address")
