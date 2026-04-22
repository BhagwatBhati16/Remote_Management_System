import json
import re
from datetime import timedelta

from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET

from clients.models import Client
from .models import Alert, AlertRule

_DEDUP_MINUTES = 5  # ignore duplicate alerts within this window


# ---------------------------------------------------------------------------
# Public API — called by client PowerShell agents (no auth required)
# ---------------------------------------------------------------------------

@csrf_exempt
@require_POST
def api_report_alert(request):
    """Receive an alert from a client detection agent.

    POST /api/alerts/report/
    Body JSON: { client_ip, hostname, alert_type, detected_name, process_list, timestamp }
    """
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, Exception):
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    client_ip = data.get("client_ip", "").strip()
    if not client_ip:
        return JsonResponse({"ok": False, "error": "client_ip required"}, status=400)

    hostname = data.get("hostname", "").strip()
    alert_type = data.get("alert_type", "process").strip()
    detected_name = data.get("detected_name", "").strip()
    process_list_raw = data.get("process_list", [])
    ts_str = data.get("timestamp", "")

    if not detected_name:
        return JsonResponse({"ok": False, "error": "detected_name required"}, status=400)
    if alert_type not in ("process", "window_title"):
        alert_type = "process"

    # Parse timestamp
    ts = timezone.now()
    if ts_str:
        try:
            from django.utils.dateparse import parse_datetime
            parsed = parse_datetime(ts_str)
            if parsed:
                ts = parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)
        except Exception:
            pass

    # Deduplication
    cutoff = timezone.now() - timedelta(minutes=_DEDUP_MINUTES)
    if Alert.objects.filter(
        client_ip=client_ip,
        detected_name=detected_name,
        received_at__gte=cutoff,
    ).exists():
        return JsonResponse({"ok": True, "status": "duplicate_ignored"})

    client_obj = Client.objects.filter(ip_address=client_ip).first()

    if isinstance(process_list_raw, list):
        process_json = json.dumps(process_list_raw[:200])
    else:
        process_json = "[]"

    Alert.objects.create(
        client=client_obj,
        client_ip=client_ip,
        hostname=hostname or (client_obj.name if client_obj else ""),
        alert_type=alert_type,
        detected_name=detected_name,
        process_list=process_json,
        timestamp=ts,
    )
    return JsonResponse({"ok": True, "status": "created"})


@require_GET
def api_get_rules(request):
    """Return current monitoring rules so client scripts can auto-update."""
    rules = AlertRule.objects.filter(is_active=True).values_list("rule_type", "value")
    result = {"process_names": [], "window_keywords": [], "website_domains": []}
    for rtype, val in rules:
        key = {
            "process_name": "process_names",
            "window_keyword": "window_keywords",
            "website_domain": "website_domains",
        }.get(rtype)
        if key:
            result[key].append(val)
    return JsonResponse(result)


@require_GET
def api_active_count(request):
    """Return count of active (undismissed) alerts for badge display."""
    count = Alert.objects.filter(is_active=True).count()
    return JsonResponse({"count": count})


@require_GET
def api_client_alerts(request, client_id):
    """Return recent alerts for a specific client (last 24h) as JSON."""
    cutoff = timezone.now() - timedelta(hours=24)
    alerts = Alert.objects.filter(
        client_id=client_id,
        received_at__gte=cutoff,
    ).order_by("-received_at")[:50]

    items = []
    for a in alerts:
        items.append({
            "id": a.id,
            "alert_type": a.alert_type,
            "detected_name": a.detected_name,
            "is_active": a.is_active,
            "received_at": a.received_at.isoformat(),
            "ago": f"{a.received_at}",
        })

    active_count = Alert.objects.filter(client_id=client_id, is_active=True).count()
    return JsonResponse({"ok": True, "items": items, "active_count": active_count})


# ---------------------------------------------------------------------------
# Staff dashboard views
# ---------------------------------------------------------------------------

@login_required
@user_passes_test(lambda u: u.is_staff)
def alert_dashboard(request):
    """Show all active (undismissed) alerts."""
    alerts = Alert.objects.filter(is_active=True).select_related("client")[:200]
    active_count = Alert.objects.filter(is_active=True).count()
    process_count = Alert.objects.filter(is_active=True, alert_type="process").count()
    browser_count = Alert.objects.filter(is_active=True, alert_type="window_title").count()
    return render(request, "alerts/dashboard.html", {
        "alerts": alerts,
        "active_count": active_count,
        "process_count": process_count,
        "browser_count": browser_count,
    })


@login_required
@user_passes_test(lambda u: u.is_staff)
def alert_history(request):
    """Show all alerts including dismissed, with optional filters."""
    qs = Alert.objects.select_related("client", "dismissed_by")

    client_id = request.GET.get("client")
    alert_type = request.GET.get("type")
    status = request.GET.get("status")

    if client_id:
        qs = qs.filter(client_id=client_id)
    if alert_type in ("process", "window_title"):
        qs = qs.filter(alert_type=alert_type)
    if status == "active":
        qs = qs.filter(is_active=True)
    elif status == "dismissed":
        qs = qs.filter(is_active=False)

    alerts = qs[:500]
    clients = Client.objects.all().order_by("name")
    return render(request, "alerts/history.html", {
        "alerts": alerts,
        "clients": clients,
        "filter_client": client_id or "",
        "filter_type": alert_type or "",
        "filter_status": status or "",
    })


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def dismiss_alert(request, alert_id):
    """Dismiss an alert."""
    alert = get_object_or_404(Alert, id=alert_id)
    alert.is_active = False
    alert.dismissed_by = request.user
    alert.dismissed_at = timezone.now()

    try:
        body = json.loads(request.body)
        notes = body.get("notes", "")
        if notes:
            alert.notes = notes
    except Exception:
        pass

    alert.save()
    return JsonResponse({"ok": True})


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def dismiss_all(request):
    """Dismiss all active alerts at once."""
    updated = Alert.objects.filter(is_active=True).update(
        is_active=False,
        dismissed_by=request.user,
        dismissed_at=timezone.now(),
    )
    return JsonResponse({"ok": True, "dismissed": updated})


# ---------------------------------------------------------------------------
# API: Recent alerts (for live toast notifications)
# ---------------------------------------------------------------------------

@require_GET
def api_recent_alerts(request):
    """Return alerts created after a given timestamp for live notifications.
    GET /api/alerts/recent/?since=<iso-timestamp>
    """
    since_str = request.GET.get("since", "")
    cutoff = timezone.now() - timedelta(seconds=30)  # default: last 30 seconds
    if since_str:
        try:
            from django.utils.dateparse import parse_datetime
            parsed = parse_datetime(since_str)
            if parsed:
                cutoff = parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)
        except Exception:
            pass

    alerts = Alert.objects.filter(
        received_at__gt=cutoff,
        is_active=True,
    ).select_related("client").order_by("-received_at")[:10]

    items = []
    for a in alerts:
        items.append({
            "id": a.id,
            "client_name": a.hostname or (a.client.name if a.client else a.client_ip),
            "client_ip": a.client_ip,
            "alert_type": a.alert_type,
            "detected_name": a.detected_name,
            "received_at": a.received_at.isoformat(),
        })

    count = Alert.objects.filter(is_active=True).count()
    return JsonResponse({"ok": True, "items": items, "count": count})


# ---------------------------------------------------------------------------
# Delete alerts (permanent deletion)
# ---------------------------------------------------------------------------

@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def delete_alert(request, alert_id):
    """Delete a single alert permanently."""
    alert = get_object_or_404(Alert, id=alert_id)
    alert.delete()
    return JsonResponse({"ok": True})


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def delete_selected_alerts(request):
    """Delete multiple alerts by IDs. Body: {"ids": [1, 2, 3]}"""
    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)
    ids = body.get("ids", [])
    if not ids:
        return JsonResponse({"ok": False, "error": "No ids provided"}, status=400)
    deleted, _ = Alert.objects.filter(id__in=ids).delete()
    return JsonResponse({"ok": True, "deleted": deleted})


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def delete_all_alerts(request):
    """Delete all alerts. Optional filter by active/all."""
    try:
        body = json.loads(request.body)
    except Exception:
        body = {}
    scope = body.get("scope", "active")  # 'active' or 'all'
    qs = Alert.objects.filter(is_active=True) if scope == "active" else Alert.objects.all()
    deleted, _ = qs.delete()
    return JsonResponse({"ok": True, "deleted": deleted})


@login_required
@user_passes_test(lambda u: u.is_staff)
def rules_manage(request):
    """Page to manage monitoring rules."""
    rules = AlertRule.objects.all()
    process_rules = rules.filter(rule_type="process_name")
    keyword_rules = rules.filter(rule_type="window_keyword")
    domain_rules = rules.filter(rule_type="website_domain")
    return render(request, "alerts/rules.html", {
        "process_rules": process_rules,
        "keyword_rules": keyword_rules,
        "domain_rules": domain_rules,
    })


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def rule_add(request):
    """Add a new monitoring rule. POST JSON: {rule_type, value}"""
    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    rule_type = body.get("rule_type", "").strip()
    value = body.get("value", "").strip()

    if rule_type not in ("process_name", "window_keyword", "website_domain"):
        return JsonResponse({"ok": False, "error": "Invalid rule_type"}, status=400)
    if not value:
        return JsonResponse({"ok": False, "error": "Value required"}, status=400)

    rule, created = AlertRule.objects.get_or_create(
        rule_type=rule_type,
        value=value,
        defaults={"added_by": request.user, "is_active": True},
    )
    if not created and not rule.is_active:
        rule.is_active = True
        rule.save()

    return JsonResponse({"ok": True, "id": rule.id, "created": created})


# ---------------------------------------------------------------------------
# Fix 2: Bulk import endpoint
# ---------------------------------------------------------------------------

def _parse_bulk_text(text: str) -> list[str]:
    """Parse a bulk text input into a list of clean values.

    Accepts:
    - One entry per line
    - Comma-separated on a single line
    - Numbered lines like "1. VALORANT" or "1, " etc.
    Strips leading numbers, dots, commas, dashes, bullets, whitespace.
    """
    # Split by newlines first
    lines = text.replace("\r\n", "\n").split("\n")
    values = []
    for line in lines:
        # Also split by commas if the line contains them and is a single line list
        parts = [line] if "\n" in text else line.split(",")
        if "," in line and len(lines) <= 1:
            parts = line.split(",")
        else:
            parts = [line]
        for part in parts:
            # Strip leading numbering: "1. ", "1, ", "1) ", "- ", "* ", "• "
            cleaned = re.sub(r"^\s*[\d]+[\.\),\-]?\s*", "", part)
            cleaned = re.sub(r"^\s*[-*•►]\s*", "", cleaned)
            cleaned = cleaned.strip().strip(",").strip()
            if cleaned:
                values.append(cleaned)
    return values


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def rule_bulk_add(request):
    """Bulk import monitoring rules from text.

    POST JSON: {"rule_type": "process_name", "values": "VALORANT\\ncsgo\\nMinecraft"}
    Returns: {"ok": true, "added": 12, "skipped": 3, "total": 15}
    """
    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    rule_type = body.get("rule_type", "").strip()
    raw_text = body.get("values", "").strip()

    if rule_type not in ("process_name", "window_keyword", "website_domain"):
        return JsonResponse({"ok": False, "error": "Invalid rule_type"}, status=400)
    if not raw_text:
        return JsonResponse({"ok": False, "error": "No values provided"}, status=400)

    values = _parse_bulk_text(raw_text)
    added = 0
    skipped = 0
    for val in values:
        _, created = AlertRule.objects.get_or_create(
            rule_type=rule_type,
            value=val,
            defaults={"added_by": request.user, "is_active": True},
        )
        if created:
            added += 1
        else:
            skipped += 1

    return JsonResponse({
        "ok": True,
        "added": added,
        "skipped": skipped,
        "total": added + skipped,
    })


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def rule_delete(request, rule_id):
    """Delete a monitoring rule."""
    rule = get_object_or_404(AlertRule, id=rule_id)
    rule.delete()
    return JsonResponse({"ok": True})


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def rule_toggle(request, rule_id):
    """Toggle a rule active/inactive."""
    rule = get_object_or_404(AlertRule, id=rule_id)
    rule.is_active = not rule.is_active
    rule.save()
    return JsonResponse({"ok": True, "is_active": rule.is_active})


# ---------------------------------------------------------------------------
# Deploy monitoring agent to existing clients
# ---------------------------------------------------------------------------
import os
import threading

_deploy_status = {"running": False, "results": [], "total": 0, "done": 0}


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def deploy_monitoring_agent(request):
    """Push monitor.ps1 to all clients via SFTP + SSH one-click deployment.

    POST /alerts/deploy-agent/
    Kicks off background deployment, returns immediately.
    """
    if _deploy_status["running"]:
        return JsonResponse({"ok": False, "error": "Deployment already in progress"}, status=409)

    try:
        body = json.loads(request.body)
    except Exception:
        body = {}
    rms_ip = body.get("rms_server_ip", request.get_host())

    clients = Client.objects.all()
    _deploy_status["running"] = True
    _deploy_status["results"] = []
    _deploy_status["total"] = clients.count()
    _deploy_status["done"] = 0

    thread = threading.Thread(
        target=_deploy_agent_background,
        args=(list(clients), rms_ip),
        daemon=True,
    )
    thread.start()
    return JsonResponse({"ok": True, "total": clients.count()})


def _deploy_agent_background(clients, rms_ip):
    """Background worker: push monitor.ps1 + launcher.vbs to each client via SFTP+SSH."""

    monitor_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "monitor.ps1")
    launcher_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "launcher.vbs")
    try:
        with open(monitor_path, "r", encoding="utf-8") as f:
            monitor_content = f.read()
    except FileNotFoundError:
        _deploy_status["running"] = False
        _deploy_status["results"].append({"client": "N/A", "status": "error", "msg": "monitor.ps1 not found on server"})
        return

    # Read or generate the VBS launcher for truly hidden execution
    try:
        with open(launcher_path, "r", encoding="utf-8") as f:
            launcher_content = f.read()
    except FileNotFoundError:
        launcher_content = (
            "' RMS Monitor Launcher\r\n"
            'CreateObject("Wscript.Shell").Run "powershell.exe -NonInteractive -NoProfile -NoLogo '
            '-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\RMS\\monitor.ps1", 0, False\r\n'
        )

    # Replace server IP placeholder
    monitor_content = monitor_content.replace(
        '$RMS_SERVER     = "http://192.168.29.168:8000"',
        '$RMS_SERVER     = "http://' + rms_ip + '"'
    )

    for client in clients:
        result = {"client": client.name, "ip": client.ip_address}
        try:
            import paramiko
            import time as _time

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                client.ip_address,
                port=client.ssh_port or 22,
                username=client.ssh_username,
                password=client.ssh_password,
                timeout=10,
            )

            # Create C:\RMS directory
            ssh.exec_command('powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path C:\\RMS | Out-Null"')
            _time.sleep(1)

            # Upload monitor.ps1 AND launcher.vbs via SFTP
            sftp = ssh.open_sftp()
            with sftp.file("C:\\RMS\\monitor.ps1", "w") as rf:
                rf.write(monitor_content)
            with sftp.file("C:\\RMS\\launcher.vbs", "w") as rf:
                rf.write(launcher_content)
            sftp.close()

            # Register scheduled task: wscript.exe runs launcher.vbs (truly hidden, no terminal)
            task_cmd = (
                "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
                "$a = New-ScheduledTaskAction -Execute 'wscript.exe' "
                "-Argument 'C:\\\\RMS\\\\launcher.vbs'; "
                "$t1 = New-ScheduledTaskTrigger -AtLogOn; "
                "$t2 = New-ScheduledTaskTrigger -AtStartup; "
                "$p = New-ScheduledTaskPrincipal -GroupId 'Users' -RunLevel Limited; "
                "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden "
                "-RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew; "
                "Register-ScheduledTask -TaskName 'RMS_Monitor' -Action $a -Trigger @($t1,$t2) -Principal $p -Settings $s -Force | Out-Null; "
                "Start-ScheduledTask -TaskName 'RMS_Monitor'"
                "\""
            )
            stdin, stdout, stderr = ssh.exec_command(task_cmd, timeout=30)
            stdout.channel.recv_exit_status()
            ssh.close()

            result["status"] = "success"
            result["msg"] = "Agent deployed and started"
        except Exception as e:
            result["status"] = "error"
            result["msg"] = str(e)[:200]

        _deploy_status["results"].append(result)
        _deploy_status["done"] += 1

    _deploy_status["running"] = False


@require_GET
@login_required
@user_passes_test(lambda u: u.is_staff)
def deploy_agent_status(request):
    """Poll deployment progress."""
    return JsonResponse({
        "running": _deploy_status["running"],
        "total": _deploy_status["total"],
        "done": _deploy_status["done"],
        "results": _deploy_status["results"],
    })

