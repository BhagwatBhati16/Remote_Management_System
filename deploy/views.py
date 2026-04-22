import json
import logging
import os
import threading
import urllib.request

from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import Software, Deployment, DeploymentTarget
from clients.models import Client

logger = logging.getLogger(__name__)


# ---- Dashboard ----

@login_required
@user_passes_test(lambda u: u.is_staff)
@ensure_csrf_cookie
def deploy_dashboard(request):
    """Main deployment page — renders the single-page dashboard.
    If there is an active (pending/running) deployment, pass its ID so the
    JavaScript can resume polling immediately on page load."""
    clients = Client.objects.all().order_by("name")

    # Check for any active deployment to auto-resume on page load/refresh
    active_dep = Deployment.objects.filter(
        status__in=["pending", "running"]
    ).order_by("-triggered_at").first()
    active_deployment_id = active_dep.id if active_dep else 0

    return render(request, "deploy/dashboard.html", {
        "clients": clients,
        "active_deployment_id": active_deployment_id,
    })


# ---- Software Library CRUD ----

@login_required
@user_passes_test(lambda u: u.is_staff)
def software_list(request):
    """Return all software entries as JSON."""
    q = request.GET.get("q", "").strip()
    qs = Software.objects.all()
    if q:
        qs = qs.filter(name__icontains=q)
    items = []
    for s in qs:
        items.append({
            "id": s.id,
            "name": s.name,
            "version": s.version,
            "description": s.description,
            "deployment_mode": s.deployment_mode,
            "choco_package_name": s.choco_package_name,
            "filename": s.filename,
            "file_size": s.file_size,
            "silent_args": s.silent_args,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M"),
        })
    return JsonResponse({"ok": True, "items": items})


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def software_add(request):
    """Add new software. Multipart form with deployment_mode field."""
    name = request.POST.get("name", "").strip()
    if not name:
        return JsonResponse({"ok": False, "error": "Name is required"}, status=400)

    mode = request.POST.get("deployment_mode", "choco").strip()

    if mode == "choco":
        choco_pkg = request.POST.get("choco_package_name", "").strip()
        if not choco_pkg:
            return JsonResponse({"ok": False, "error": "Chocolatey package name is required"}, status=400)
        sw = Software.objects.create(
            name=name,
            version=request.POST.get("version", "").strip(),
            description=request.POST.get("description", "").strip(),
            deployment_mode="choco",
            choco_package_name=choco_pkg,
        )
    else:
        f = request.FILES.get("installer_file")
        if not f:
            return JsonResponse({"ok": False, "error": "Installer file is required for local mode"}, status=400)
        sw = Software.objects.create(
            name=name,
            version=request.POST.get("version", "").strip(),
            description=request.POST.get("description", "").strip(),
            deployment_mode="local",
            installer_file=f,
            silent_args=request.POST.get("silent_args", "").strip(),
        )

    return JsonResponse({"ok": True, "id": sw.id, "name": sw.name})


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def software_edit(request, sw_id):
    """Edit software metadata. Optionally replace the installer file."""
    sw = get_object_or_404(Software, id=sw_id)
    sw.name = request.POST.get("name", sw.name).strip()
    sw.version = request.POST.get("version", sw.version).strip()
    sw.description = request.POST.get("description", sw.description).strip()

    mode = request.POST.get("deployment_mode", sw.deployment_mode).strip()
    sw.deployment_mode = mode

    if mode == "choco":
        sw.choco_package_name = request.POST.get("choco_package_name", sw.choco_package_name).strip()
    else:
        sw.silent_args = request.POST.get("silent_args", sw.silent_args).strip()
        f = request.FILES.get("installer_file")
        if f:
            if sw.installer_file:
                try:
                    sw.installer_file.delete(save=False)
                except Exception:
                    pass
            sw.installer_file = f

    sw.save()
    return JsonResponse({"ok": True})


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def software_delete(request, sw_id):
    """Delete software and its installer file."""
    sw = get_object_or_404(Software, id=sw_id)
    if sw.installer_file:
        try:
            sw.installer_file.delete(save=False)
        except Exception:
            pass
    sw.delete()
    return JsonResponse({"ok": True})


# ---- Clients Online Status (batch) ----

@login_required
@user_passes_test(lambda u: u.is_staff)
def clients_online_status(request):
    """Check online status for all clients at once. Returns dict of client_id → bool."""
    clients = Client.objects.all()
    result = {}
    for c in clients:
        host = c.ip_address
        port = c.glances_port or 61208
        reachable = False
        for api_ver in ("4", "3"):
            url = f"http://{host}:{port}/api/{api_ver}/cpu"
            try:
                with urllib.request.urlopen(url, timeout=2) as resp:
                    if resp.status == 200:
                        reachable = True
                        break
            except Exception:
                continue
        result[str(c.id)] = reachable
    return JsonResponse({"ok": True, "statuses": result})


# ---- Deployment ----

def _run_engine_background(deployment_id):
    """Background thread target: imports and runs the engine.
    Catches all exceptions so the thread never crashes silently."""
    try:
        from .engine import start_deployment as engine_start
        logger.info("[Deploy %d] Engine thread started.", deployment_id)
        engine_start(deployment_id)
        logger.info("[Deploy %d] Engine thread finished.", deployment_id)
    except Exception:
        logger.exception("[Deploy %d] ENGINE CRASHED — marking deployment failed.", deployment_id)
        try:
            Deployment.objects.filter(id=deployment_id).update(status="failed")
        except Exception:
            pass


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def start_deployment(request):
    """Trigger a deployment. POST JSON: {software_id: int, client_ids: [int, ...]}."""
    # Parse JSON body safely
    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    software_id = body.get("software_id")
    client_ids = body.get("client_ids", [])

    if not software_id:
        return JsonResponse({"ok": False, "error": "No software selected"}, status=400)
    if not client_ids:
        return JsonResponse({"ok": False, "error": "No clients selected"}, status=400)

    # Look up software — return JSON error, NOT html 404
    try:
        sw = Software.objects.get(id=software_id)
    except Software.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Software not found"}, status=404)

    clients = Client.objects.filter(id__in=client_ids)
    if not clients.exists():
        return JsonResponse({"ok": False, "error": "No valid clients found"}, status=400)

    # Validate based on mode
    if sw.deployment_mode == "choco":
        if not sw.choco_package_name.strip():
            return JsonResponse({"ok": False, "error": "No Chocolatey package name configured"}, status=400)
    else:
        if not sw.installer_file:
            return JsonResponse({"ok": False, "error": f"No installer file for {sw.name}"}, status=400)
        try:
            if not os.path.isfile(sw.installer_file.path):
                return JsonResponse({"ok": False, "error": f"Installer file not found on server: {sw.filename}"}, status=400)
        except Exception:
            return JsonResponse({"ok": False, "error": "Installer file path error"}, status=400)

    # Create deployment record
    deployment = Deployment.objects.create(
        software=sw,
        triggered_by=request.user,
        status="pending",
        total_targets=clients.count(),
    )

    # Create per-client target records
    targets = []
    for client in clients:
        t = DeploymentTarget(deployment=deployment, client=client, status="queued")
        targets.append(t)
    DeploymentTarget.objects.bulk_create(targets)

    logger.info("[Deploy %d] Created: %s → %d clients. Launching engine thread.",
                deployment.id, sw.name, clients.count())

    # Launch engine in a BACKGROUND THREAD so the HTTP response returns immediately
    t = threading.Thread(
        target=_run_engine_background,
        args=(deployment.id,),
        daemon=True,
        name=f"deploy-engine-{deployment.id}",
    )
    t.start()

    return JsonResponse({"ok": True, "deployment_id": deployment.id})


# ---- Status Polling ----

@login_required
@user_passes_test(lambda u: u.is_staff)
def deployment_status(request, dep_id):
    """Live status for an active deployment. Polled by the browser every 2 seconds.
    Returns the exact JSON structure the frontend expects."""
    try:
        deployment = Deployment.objects.select_related("software").get(id=dep_id)
    except Deployment.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Deployment not found"}, status=404)

    targets = DeploymentTarget.objects.filter(
        deployment=deployment
    ).select_related("client").order_by("client__name")

    # Count in-progress targets
    in_progress = targets.filter(
        status__in=["connecting", "transferring", "installing", "verifying"]
    ).count()

    target_data = []
    for t in targets:
        target_data.append({
            "client_name": t.client.name,
            "client_ip": t.client.ip_address,
            "status": t.status,
            "progress": t.progress_pct,
            "error": t.error_message,
            "stdout": t.stdout_log[:3000] if t.stdout_log else "",
            "stderr": t.stderr_log[:3000] if t.stderr_log else "",
            "exit_code": t.exit_code,
            "started_at": t.started_at.strftime("%H:%M:%S") if t.started_at else None,
            "finished_at": t.finished_at.strftime("%H:%M:%S") if t.finished_at else None,
        })

    # Determine deployment mode label
    mode_label = "chocolatey" if deployment.software.deployment_mode == "choco" else "local"
    sw_name = deployment.software.name
    sw_version = deployment.software.version
    display_name = f"{sw_name} v{sw_version}" if sw_version else sw_name

    return JsonResponse({
        "ok": True,
        "deployment_id": deployment.id,
        "software_name": display_name,
        "deployment_mode": mode_label,
        "status": deployment.status,
        "started_at": deployment.triggered_at.strftime("%Y-%m-%d %H:%M:%S"),
        "triggered_by": str(deployment.triggered_by) if deployment.triggered_by else "System",
        "total_targets": deployment.total_targets,
        "completed": deployment.completed_count,
        "failed": deployment.failed_count,
        "in_progress": in_progress,
        "targets": target_data,
    })


# ---- History ----

@login_required
@user_passes_test(lambda u: u.is_staff)
def deployment_history(request):
    """List past deployments."""
    deps = Deployment.objects.all().select_related("software", "triggered_by")[:50]
    items = []
    for d in deps:
        sw_name = d.software.name
        sw_version = d.software.version
        display = f"{sw_name} v{sw_version}" if sw_version else sw_name
        items.append({
            "id": d.id,
            "software_name": display,
            "deployment_mode": "chocolatey" if d.software.deployment_mode == "choco" else "local",
            "status": d.status,
            "total": d.total_targets,
            "completed": d.completed_count,
            "failed": d.failed_count,
            "triggered_at": d.triggered_at.strftime("%Y-%m-%d %H:%M:%S"),
            "triggered_by": str(d.triggered_by) if d.triggered_by else "System",
        })
    return JsonResponse({"ok": True, "items": items})
