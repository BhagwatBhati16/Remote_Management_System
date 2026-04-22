"""
Quick Actions — Remote Power Management views.
Provides single-client actions, bulk actions, scheduled shutdown, MAC detection, and Wake-on-LAN.
"""
import json
import socket
import time
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_POST

from .models import Client


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _ssh_action(client, command, action_name, timeout=5):
    """Execute a command on a client via SSH. Returns a result dict.
    Handles shutdown-induced connection drops gracefully."""
    import paramiko
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            client.ip_address,
            port=client.ssh_port or 22,
            username=client.ssh_username,
            password=client.ssh_password,
            timeout=timeout,
        )
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=10)
            stdout.channel.recv_exit_status()
        except (paramiko.SSHException, EOFError, OSError):
            # Connection dropped — expected for shutdown/restart
            pass
        ssh.close()
        return {"ok": True, "message": f"{action_name} command sent to {client.name}"}
    except Exception as e:
        return {"ok": False, "error": f"SSH connection failed: {str(e)[:200]}"}


def send_wol(mac_address, broadcast="255.255.255.255", port=9):
    """Send a Wake-on-LAN magic packet."""
    mac_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))
    magic = b"\xff" * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic, (broadcast, port))


# ═══════════════════════════════════════════════════════════════════════════════
# Single-client action endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def action_shutdown(request, pk):
    client = get_object_or_404(Client, pk=pk)
    result = _ssh_action(client, "shutdown /s /t 5 /f", "Shutdown")
    return JsonResponse(result)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def action_restart(request, pk):
    client = get_object_or_404(Client, pk=pk)
    result = _ssh_action(client, "shutdown /r /t 5 /f", "Restart")
    return JsonResponse(result)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def action_logoff(request, pk):
    client = get_object_or_404(Client, pk=pk)
    result = _ssh_action(client, "shutdown /l /f", "Log Off")
    return JsonResponse(result)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def action_lock(request, pk):
    client = get_object_or_404(Client, pk=pk)
    result = _ssh_action(client, "rundll32.exe user32.dll,LockWorkStation", "Lock")
    return JsonResponse(result)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def action_sleep(request, pk):
    client = get_object_or_404(Client, pk=pk)
    result = _ssh_action(client, "rundll32.exe powrprof.dll,SetSuspendState 0,1,0", "Sleep")
    return JsonResponse(result)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def action_cancel_shutdown(request, pk):
    client = get_object_or_404(Client, pk=pk)
    result = _ssh_action(client, "shutdown /a", "Cancel Shutdown")
    return JsonResponse(result)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def action_wake(request, pk):
    client = get_object_or_404(Client, pk=pk)
    mac = (client.mac_address or "").strip()
    if not mac:
        return JsonResponse({"ok": False, "error": "No MAC address configured for this client. Edit the client to add one."})
    try:
        # Send to global broadcast
        send_wol(mac)
        # Also send to subnet broadcast (e.g., 192.168.29.255)
        parts = client.ip_address.split(".")
        if len(parts) == 4:
            subnet_broadcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
            send_wol(mac, broadcast=subnet_broadcast)
        return JsonResponse({"ok": True, "message": f"Wake-on-LAN packet sent to {client.name} ({mac})"})
    except Exception as e:
        return JsonResponse({"ok": False, "error": f"Failed to send WoL packet: {str(e)}"})


# ═══════════════════════════════════════════════════════════════════════════════
# Detect MAC address via SSH
# ═══════════════════════════════════════════════════════════════════════════════

@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def detect_mac(request, pk):
    """SSH into client and auto-detect its MAC address."""
    import paramiko
    client = get_object_or_404(Client, pk=pk)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            client.ip_address,
            port=client.ssh_port or 22,
            username=client.ssh_username,
            password=client.ssh_password,
            timeout=5,
        )
        stdin, stdout, stderr = ssh.exec_command(
            'powershell -NoProfile -Command "'
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Name -notlike '*VMware*' "
            "-and $_.Name -notlike '*Loopback*' -and $_.Name -notlike '*vEthernet*'} "
            '| Select-Object -First 1 -ExpandProperty MacAddress"',
            timeout=10,
        )
        mac_raw = stdout.read().decode().strip()
        ssh.close()
        if mac_raw and len(mac_raw) >= 12:
            # Normalize to AA:BB:CC:DD:EE:FF
            mac = mac_raw.replace("-", ":").upper()
            client.mac_address = mac
            client.save(update_fields=["mac_address"])
            return JsonResponse({"ok": True, "mac": mac})
        else:
            return JsonResponse({"ok": False, "error": f"Could not detect MAC. Raw output: {mac_raw[:100]}"})
    except Exception as e:
        return JsonResponse({"ok": False, "error": f"SSH failed: {str(e)[:200]}"})


# ═══════════════════════════════════════════════════════════════════════════════
# Bulk action endpoints
# ═══════════════════════════════════════════════════════════════════════════════

def _resolve_client_ids(body):
    """Resolve client_ids from request body. Returns list of Client objects."""
    client_ids = body.get("client_ids", [])
    if client_ids == "all":
        return list(Client.objects.all())
    elif client_ids == "online":
        all_clients = list(Client.objects.all())

        def _check(c):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((c.ip_address, c.ssh_port or 22))
                s.close()
                return c
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = pool.map(_check, all_clients)
            return [c for c in results if c is not None]
    elif isinstance(client_ids, list):
        return list(Client.objects.filter(id__in=client_ids))
    return []


def _bulk_action(request, action_name, command_fn):
    """Generic bulk action handler."""
    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    clients = _resolve_client_ids(body)
    if not clients:
        return JsonResponse({"ok": False, "error": "No clients to target"}, status=400)

    results = []

    def _execute(c):
        r = command_fn(c)
        return {
            "client_id": c.id,
            "client_name": c.name,
            "status": "success" if r.get("ok") else "failed",
            "message": r.get("message", ""),
            "error": r.get("error", ""),
        }

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_execute, c): c for c in clients}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                c = futures[future]
                results.append({"client_id": c.id, "client_name": c.name, "status": "failed", "error": str(e)[:200]})

    success = sum(1 for r in results if r["status"] == "success")
    failed = len(results) - success
    return JsonResponse({
        "ok": True,
        "action": action_name,
        "total": len(results),
        "success": success,
        "failed": failed,
        "results": results,
    })


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def bulk_shutdown(request):
    return _bulk_action(request, "shutdown", lambda c: _ssh_action(c, "shutdown /s /t 5 /f", "Shutdown"))


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def bulk_restart(request):
    return _bulk_action(request, "restart", lambda c: _ssh_action(c, "shutdown /r /t 5 /f", "Restart"))


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def bulk_logoff(request):
    return _bulk_action(request, "logoff", lambda c: _ssh_action(c, "shutdown /l /f", "Log Off"))


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def bulk_lock(request):
    return _bulk_action(request, "lock", lambda c: _ssh_action(c, "rundll32.exe user32.dll,LockWorkStation", "Lock"))


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def bulk_wake(request):
    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)
    clients = _resolve_client_ids(body)
    results = []
    for c in clients:
        mac = (c.mac_address or "").strip()
        if not mac:
            results.append({"client_id": c.id, "client_name": c.name, "status": "failed", "error": "No MAC address"})
            continue
        try:
            send_wol(mac)
            parts = c.ip_address.split(".")
            if len(parts) == 4:
                send_wol(mac, broadcast=f"{parts[0]}.{parts[1]}.{parts[2]}.255")
            results.append({"client_id": c.id, "client_name": c.name, "status": "success", "message": f"WoL sent ({mac})"})
        except Exception as e:
            results.append({"client_id": c.id, "client_name": c.name, "status": "failed", "error": str(e)[:200]})
    success = sum(1 for r in results if r["status"] == "success")
    return JsonResponse({"ok": True, "action": "wake", "total": len(results), "success": success, "failed": len(results) - success, "results": results})


# ═══════════════════════════════════════════════════════════════════════════════
# Scheduled Shutdown
# ═══════════════════════════════════════════════════════════════════════════════

_scheduled_shutdown = {
    "active": False,
    "target_time": None,
    "scope": "online",
    "message": "Lab closing. Please save your work.",
    "warning_seconds": 300,
}
_schedule_lock = threading.Lock()


def _schedule_daemon():
    """Background daemon thread that checks every 60s if it's time to execute."""
    while True:
        time.sleep(60)
        with _schedule_lock:
            if not _scheduled_shutdown["active"]:
                continue
            target = _scheduled_shutdown["target_time"]
            if target and datetime.now() >= target:
                _scheduled_shutdown["active"] = False
                scope = _scheduled_shutdown["scope"]
                msg = _scheduled_shutdown["message"]
                warn_s = _scheduled_shutdown["warning_seconds"]
                cmd = f'shutdown /s /t {warn_s} /f /c "{msg}"'

                if scope == "all":
                    targets = list(Client.objects.all())
                else:
                    all_c = list(Client.objects.all())

                    def _check(c):
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(2)
                            s.connect((c.ip_address, c.ssh_port or 22))
                            s.close()
                            return c
                        except Exception:
                            return None

                    with ThreadPoolExecutor(max_workers=20) as pool:
                        targets = [c for c in pool.map(_check, all_c) if c is not None]

                def _do_shutdown(c):
                    _ssh_action(c, cmd, "Scheduled Shutdown")

                with ThreadPoolExecutor(max_workers=20) as pool:
                    list(pool.map(_do_shutdown, targets))


# Start daemon on module load
_daemon = threading.Thread(target=_schedule_daemon, daemon=True)
_daemon.start()


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def schedule_shutdown(request):
    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    time_str = body.get("time", "")
    scope = body.get("scope", "online")
    message = body.get("message", "Lab closing. Please save your work.")
    warn_s = int(body.get("warning_seconds", 300))

    if not time_str:
        return JsonResponse({"ok": False, "error": "No time specified"}, status=400)

    try:
        hour, minute = map(int, time_str.split(":"))
        now = datetime.now()
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
    except Exception:
        return JsonResponse({"ok": False, "error": f"Invalid time format: {time_str}. Use HH:MM"}, status=400)

    with _schedule_lock:
        _scheduled_shutdown["active"] = True
        _scheduled_shutdown["target_time"] = target
        _scheduled_shutdown["scope"] = scope
        _scheduled_shutdown["message"] = message
        _scheduled_shutdown["warning_seconds"] = warn_s

    return JsonResponse({
        "ok": True,
        "message": f"Shutdown scheduled for {target.strftime('%H:%M')}",
        "target_time": target.isoformat(),
    })


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def cancel_scheduled_shutdown(request):
    with _schedule_lock:
        was_active = _scheduled_shutdown["active"]
        _scheduled_shutdown["active"] = False
        _scheduled_shutdown["target_time"] = None
    return JsonResponse({"ok": True, "was_active": was_active})


@login_required
@user_passes_test(lambda u: u.is_staff)
def schedule_status(request):
    with _schedule_lock:
        active = _scheduled_shutdown["active"]
        target = _scheduled_shutdown["target_time"]
    if active and target:
        remaining = (target - datetime.now()).total_seconds()
        return JsonResponse({
            "active": True,
            "target_time": target.strftime("%H:%M"),
            "remaining_seconds": max(0, int(remaining)),
        })
    return JsonResponse({"active": False})
