"""
Client Auto-Registration API and Quick Password endpoints.
"""
import json
import logging

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required, user_passes_test

from .models import Client

logger = logging.getLogger(__name__)


@csrf_exempt
@require_POST
def register_client(request):
    """
    Auto-registration endpoint called by provisioning scripts.
    POST /api/clients/register/
    Validates registration token, creates or updates client record.
    """
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    # Validate registration token
    token = body.get("registration_token", "")
    expected_token = getattr(settings, "RMS_REGISTRATION_TOKEN", "")
    if not token or token != expected_token:
        return JsonResponse({"ok": False, "error": "Invalid registration token"}, status=403)

    # Extract fields
    hostname = (body.get("hostname") or "").strip()
    ip_address = (body.get("ip_address") or "").strip()
    mac_address = (body.get("mac_address") or "").strip()
    os_name = (body.get("os_name") or "").strip()
    os_version = (body.get("os_version") or "").strip()
    ssh_port = int(body.get("ssh_port", 22) or 22)
    ssh_username = (body.get("ssh_username") or "").strip()
    ssh_password = (body.get("ssh_password") or "").strip()
    glances_port = int(body.get("glances_port", 61208) or 61208)
    vnc_port = int(body.get("vnc_port", 5900) or 5900)
    cpu = (body.get("cpu") or "").strip()
    ram_gb = body.get("ram_gb")
    disk_gb = body.get("disk_gb")
    is_heartbeat = body.get("heartbeat", False)

    if not ip_address:
        return JsonResponse({"ok": False, "error": "ip_address is required"}, status=400)
    if not hostname:
        hostname = ip_address  # Fallback

    # Try to find existing client by IP or hostname
    client = None
    status = "created"

    # First try by IP
    try:
        client = Client.objects.get(ip_address=ip_address)
        status = "updated"
    except Client.DoesNotExist:
        pass

    # If not found by IP, try by hostname (machine may have new IP via DHCP)
    if client is None:
        try:
            client = Client.objects.get(name=hostname)
            old_ip = client.ip_address
            logger.info(f"Client '{hostname}' IP changed: {old_ip} → {ip_address}")
            status = "updated"
        except Client.DoesNotExist:
            pass

    now = timezone.now()

    if client:
        # Update existing record
        client.name = hostname
        client.ip_address = ip_address
        if mac_address:
            client.mac_address = mac_address
        if os_name:
            client.os_name = os_name
        if os_version:
            client.os_version = os_version
        client.ssh_port = ssh_port
        if ssh_username:
            client.ssh_username = ssh_username
        # Only set password if provided AND client doesn't already have one
        if ssh_password and not client.ssh_password:
            client.ssh_password = ssh_password
        client.glances_port = glances_port
        client.vnc_port = vnc_port
        if cpu:
            client.cpu = cpu
        if ram_gb is not None:
            client.ram_gb = int(ram_gb)
        if disk_gb is not None:
            client.disk_gb = int(disk_gb)
        client.last_seen = now
        client.save()
    else:
        # Create new client
        client = Client.objects.create(
            name=hostname,
            ip_address=ip_address,
            mac_address=mac_address or "",
            os_name=os_name or "",
            os_version=os_version or "",
            ssh_port=ssh_port,
            ssh_username=ssh_username or "",
            ssh_password=ssh_password or "",
            glances_port=glances_port,
            vnc_port=vnc_port,
            cpu=cpu or "",
            ram_gb=int(ram_gb) if ram_gb is not None else None,
            disk_gb=int(disk_gb) if disk_gb is not None else None,
            last_seen=now,
            auto_registered=True,
            admin_viewed=False,
        )
        status = "created"

    return JsonResponse({
        "ok": True,
        "status": status,
        "client_id": client.id,
        "client": {
            "name": client.name,
            "ip_address": client.ip_address,
            "os_name": client.os_name,
            "mac_address": client.mac_address,
        },
    })


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def set_password_quick(request, client_id):
    """Quick password set endpoint — used by the dashboard modal."""
    client = get_object_or_404(Client, pk=client_id)
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    password = body.get("password", "").strip()
    if not password:
        return JsonResponse({"ok": False, "error": "Password is required"}, status=400)

    client.ssh_password = password
    client.save(update_fields=["ssh_password"])
    return JsonResponse({"ok": True, "message": f"SSH password set for {client.name}"})
