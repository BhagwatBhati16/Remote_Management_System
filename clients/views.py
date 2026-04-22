import os
import sys
import signal
import socket
import subprocess
import io
import time
import stat as stat_module
import posixpath
import mimetypes
import json
import base64
from typing import Optional
from contextlib import contextmanager

from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, Http404, HttpResponse, FileResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render, redirect
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.clickjacking import xframe_options_exempt

from .models import Client, VNCSession, SSHSession
from .utils import (
    pid_alive,
    kill_pid_tree,
    get_free_port,
    sftp_connect,
    safe_join,
)
from .forms import ClientForm, ScriptGeneratorForm


def _is_process_running(pid: int) -> bool:
    try:
        if os.name == "nt":
            result = subprocess.run([
                "powershell",
                "-NoProfile",
                "-Command",
                f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Where-Object {{$_.Id -eq {pid}}} | Measure-Object | Select-Object -ExpandProperty Count",
            ], capture_output=True, text=True)
            count = result.stdout.strip()
            return count not in ("", "0")
        else:
            os.kill(pid, 0)
            return True
    except Exception:
        return False


def _get_free_port() -> int:
    """Ask OS for a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@login_required
def overview(request):
    clients = Client.objects.all().order_by("name")
    return render(request, "clients/main_page.html", {"clients": clients})


@login_required
@ensure_csrf_cookie
def client_detail(request, client_id: int):
    client = get_object_or_404(Client, id=client_id)
    # Mark as viewed by admin (clears "New" badge on dashboard)
    if not client.admin_viewed:
        client.admin_viewed = True
        client.save(update_fields=["admin_viewed"])
    session = getattr(client, "vnc_session", None)
    running = False
    if session:
        running = _is_process_running(session.pid)
        if not running:
            session.delete()
            session = None
    ssh_session = getattr(client, "ssh_session", None)
    ssh_running = False
    ssh_url = ""
    if ssh_session:
        ssh_running = _is_process_running(ssh_session.pid)
        if not ssh_running:
            ssh_session.delete()
            ssh_session = None
        else:
            # Build auto-connect URL for resume
            scheme = "https" if request.is_secure() else "http"
            host_only = request.get_host().split(":")[0]
            ssh_url = _build_webssh_url(scheme, host_only, ssh_session.listen_port, client)
    return render(
        request,
        "clients/client_page.html",
        {
            "client": client,
            "session": session,
            "running": running,
            "ssh_session": ssh_session,
            "ssh_running": ssh_running,
            "ssh_url": ssh_url,
            "glances_url": f"http://{client.ip_address}:{client.glances_port}",
        },
    )


@login_required
@user_passes_test(lambda u: u.is_staff)
@ensure_csrf_cookie
def add_client(request):
    if request.method == "POST":
        form = ClientForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("clients:overview")
    else:
        form = ClientForm()
    return render(request, "clients/add_client.html", {"form": form})


@login_required
@user_passes_test(lambda u: u.is_staff)
@ensure_csrf_cookie
def edit_client(request, client_id: int):
    client = get_object_or_404(Client, pk=client_id)
    if request.method == "POST":
        if request.POST.get("_delete") == "1":
            client.delete()
            return redirect("clients:overview")
        form = ClientForm(request.POST, instance=client)
        if form.is_valid():
            form.save()
            return redirect("clients:client_detail", client_id=client.id)
    else:
        form = ClientForm(instance=client)
    return render(request, "clients/add_client.html", {"form": form, "client": client, "editing": True})


# ---------------------------------------------------------------------------
# VNC
# ---------------------------------------------------------------------------

@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def start_vnc(request, client_id: int):
    client = get_object_or_404(Client, id=client_id)

    existing = getattr(client, "vnc_session", None)
    if existing and _is_process_running(existing.pid):
        scheme = "https" if request.is_secure() else "http"
        host_only = request.get_host().split(":")[0]
        url = f"{scheme}://{host_only}:{existing.listen_port}/vnc.html?resize=scale"
        return JsonResponse({"ok": True, "already": True, "url": url})
    elif existing:
        existing.delete()

    target = f"{client.ip_address}:5900"
    listen_host = "0.0.0.0"
    listen_port = _get_free_port()

    def _port_open() -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.connect(("127.0.0.1", listen_port))
                return True
        except Exception:
            return False

    try:
        cmd = [
            sys.executable, "-m", "novnc",
            "--listen", f"{listen_host}:{listen_port}",
            "--target", target,
        ]
        if os.name == "nt":
            proc = subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            proc = subprocess.Popen(
                cmd,
                preexec_fn=os.setsid,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        # Wait for the websocket proxy to become ready
        ok = False
        for _ in range(20):
            time.sleep(0.25)
            if _port_open():
                ok = True
                break
            if proc.poll() is not None:
                break
        if not ok:
            err = ""
            try:
                if proc.poll() is not None and proc.stderr:
                    err_bytes = proc.stderr.read(4096) or b""
                    err = err_bytes.decode(errors="ignore")
            except Exception:
                pass
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/F", "/T"], capture_output=True)
                else:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
            msg = f"Failed to start noVNC on port {listen_port}."
            if err:
                head = " ".join(err.splitlines()[:3])
                msg += f" Details: {head}"
            return JsonResponse({"ok": False, "error": msg}, status=500)

    except FileNotFoundError:
        return JsonResponse({"ok": False, "error": "'novnc' module not found. Install with: pip install novnc"}, status=500)
    except Exception as e:
        return JsonResponse({"ok": False, "error": f"Failed to start noVNC: {e}"}, status=500)

    session = VNCSession.objects.create(
        client=client,
        pid=proc.pid,
        listen_host=listen_host,
        listen_port=listen_port,
        started_by=request.user,
    )

    scheme = "https" if request.is_secure() else "http"
    host_only = request.get_host().split(":")[0]
    url = f"{scheme}://{host_only}:{listen_port}/vnc.html?resize=scale"
    return JsonResponse({"ok": True, "pid": proc.pid, "url": url})


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def stop_vnc(request, client_id: int):
    client = get_object_or_404(Client, id=client_id)
    session = getattr(client, "vnc_session", None)
    if not session:
        return JsonResponse({"ok": True, "already": True})

    pid = session.pid
    killed = False
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
            killed = True
        except Exception:
            killed = False
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            killed = True
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
                killed = True
            except Exception:
                killed = False

    if killed or not _is_process_running(pid):
        session.delete()
        return JsonResponse({"ok": True, "stopped": True})
    else:
        return JsonResponse({"ok": False, "error": "Could not stop process"}, status=500)


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def start_ssh(request, client_id: int):
    """Start a local webssh server bound to 0.0.0.0 on a dynamic port for the given client.

    Before launching, validates SSH credentials via paramiko.
    Builds a full auto-connect URL with base64-encoded password so
    webssh skips its login form entirely.
    """
    client = get_object_or_404(Client, id=client_id)

    existing = getattr(client, "ssh_session", None)
    if existing and _is_process_running(existing.pid):
        scheme = "https" if request.is_secure() else "http"
        host_only = request.get_host().split(":")[0]
        url = _build_webssh_url(scheme, host_only, existing.listen_port, client)
        return JsonResponse({"ok": True, "already": True, "url": url})
    elif existing:
        existing.delete()

    # ── Part 3: Validate SSH credentials BEFORE launching webssh ──
    if not client.ssh_username:
        return JsonResponse({
            "ok": False,
            "error": "No SSH username configured for this client. Go to Add/Edit Client to set credentials."
        }, status=400)
    if not client.ssh_password and not (client.ssh_private_key_path and os.path.isfile(client.ssh_private_key_path)):
        return JsonResponse({
            "ok": False,
            "error": "No SSH password or private key configured. Go to Add/Edit Client to set credentials."
        }, status=400)

    # Quick paramiko test connection
    try:
        import paramiko
        test_transport = paramiko.Transport((client.ip_address, client.ssh_port or 22))
        try:
            if client.ssh_private_key_path and os.path.isfile(client.ssh_private_key_path):
                # Try key-based auth
                pkey = None
                for key_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
                    try:
                        pkey = key_class.from_private_key_file(client.ssh_private_key_path)
                        break
                    except Exception:
                        continue
                if pkey is None:
                    return JsonResponse({"ok": False, "error": "Could not load SSH private key file."}, status=400)
                test_transport.connect(username=client.ssh_username, pkey=pkey)
            else:
                test_transport.connect(username=client.ssh_username, password=client.ssh_password)
        finally:
            test_transport.close()
    except paramiko.AuthenticationException:
        return JsonResponse({
            "ok": False,
            "error": "SSH authentication failed. The stored username/password is incorrect. Update credentials in client settings."
        }, status=400)
    except Exception as e:
        err_msg = str(e)
        if "connect" in err_msg.lower() or "timeout" in err_msg.lower() or "refused" in err_msg.lower():
            return JsonResponse({
                "ok": False,
                "error": f"Cannot reach {client.ip_address}:{client.ssh_port} — {err_msg}"
            }, status=400)
        return JsonResponse({"ok": False, "error": f"SSH connection test failed: {err_msg}"}, status=400)

    listen_host = "0.0.0.0"
    listen_port = _get_free_port()

    def _port_open() -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.connect(("127.0.0.1", listen_port))
                return True
        except Exception:
            return False

    try:
        cmd = [
            sys.executable,
            "-m",
            "webssh.main",
            f"--address={listen_host}",
            f"--port={listen_port}",
            "--origin=*",
            "--policy=autoadd",
            "--debug",
            "--redirect=False",
            "--fbidhttp=False",
        ]
        if os.name == "nt":
            proc = subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            proc = subprocess.Popen(
                cmd,
                preexec_fn=os.setsid,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        ok = False
        for _ in range(20):
            time.sleep(0.25)
            if _port_open():
                ok = True
                break
            if proc.poll() is not None:
                break
        if not ok:
            err = ""
            try:
                if proc.poll() is not None and proc.stderr:
                    err_bytes = proc.stderr.read(4096) or b""
                    err = err_bytes.decode(errors="ignore")
            except Exception:
                pass
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/F", "/T"], capture_output=True)
                else:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
            msg = f"Failed to start WebSSH on port {listen_port}. Check firewall/permissions and try again."
            if err:
                head = " ".join(err.splitlines()[:3])
                msg += f" Details: {head}"
            return JsonResponse({"ok": False, "error": msg}, status=500)
    except FileNotFoundError:
        return JsonResponse({"ok": False, "error": "'webssh' module not found. Add 'webssh' to requirements and install."}, status=500)
    except Exception as e:
        return JsonResponse({"ok": False, "error": f"Failed to start webssh: {e}"}, status=500)

    ssh_session = SSHSession.objects.create(
        client=client,
        pid=proc.pid,
        listen_host=listen_host,
        listen_port=listen_port,
        started_by=request.user,
    )

    scheme = "https" if request.is_secure() else "http"
    host_only = request.get_host().split(":")[0]
    url = _build_webssh_url(scheme, host_only, listen_port, client)
    return JsonResponse({"ok": True, "pid": proc.pid, "url": url})


def _build_webssh_url(scheme: str, host: str, port: int, client) -> str:
    """Build a WebSSH URL that includes all credentials for auto-connect.

    WebSSH auto-submits the login form when all required fields are provided
    via URL parameters.  The password must be base64-encoded.
    """
    import urllib.parse
    params = {
        "hostname": client.ip_address,
        "port": str(client.ssh_port or 22),
        "username": client.ssh_username or "",
    }
    if client.ssh_password:
        params["password"] = base64.b64encode(client.ssh_password.encode()).decode()
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return f"{scheme}://{host}:{port}/?{qs}"


@login_required
@user_passes_test(lambda u: u.is_staff)
@xframe_options_exempt
def ssh_terminal_wrapper(request, client_id: int):
    """Serve a dark-themed HTML wrapper page that embeds the WebSSH iframe.

    This avoids the bright-white WebSSH login form flashing inside the
    management panel.  The wrapper loads with a dark background and a
    \"Connecting…\" spinner, then loads the real WebSSH URL into a
    full-page iframe.  Even if the auto-connect fails, the fallback
    form is surrounded by a dark page.
    """
    client = get_object_or_404(Client, id=client_id)
    webssh_url = request.GET.get("url", "")
    return render(request, "clients/ssh_wrapper.html", {
        "client": client,
        "webssh_url": webssh_url,
    })


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def stop_ssh(request, client_id: int):
    client = get_object_or_404(Client, id=client_id)
    session = getattr(client, "ssh_session", None)
    if not session:
        return JsonResponse({"ok": True, "already": True})

    pid = session.pid
    killed = False
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
            killed = True
        except Exception:
            killed = False
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            killed = True
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
                killed = True
            except Exception:
                killed = False

    if killed or not _is_process_running(pid):
        session.delete()
        return JsonResponse({"ok": True, "stopped": True})
    else:
        return JsonResponse({"ok": False, "error": "Could not stop process"}, status=500)


# ---------------------------------------------------------------------------
# Process management
# ---------------------------------------------------------------------------

@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def kill_pid(request, client_id: int, pid: int):
    """Force-kill a local process by PID and clear any matching session records for this client."""
    client = get_object_or_404(Client, id=client_id)
    ok = kill_pid_tree(pid)
    # Clean up DB session objects if they match this PID
    v = getattr(client, "vnc_session", None)
    if v and v.pid == pid:
        v.delete()
    s = getattr(client, "ssh_session", None)
    if s and s.pid == pid:
        s.delete()
    return JsonResponse({"ok": ok})


# ---------------------------------------------------------------------------
# Glances health
# ---------------------------------------------------------------------------

@login_required
@user_passes_test(lambda u: u.is_staff)
def glances_health(request, client_id: int):
    """Lightweight health/metrics probe for Glances on the remote client.

    Returns JSON:
      { ok: true, reachable: bool, cpu: {...optional...} }
    We attempt a single HTTP GET to /api/<ver>/cpu, trying v4 first then v3.
    """
    client = get_object_or_404(Client, id=client_id)
    host = client.ip_address
    port = client.glances_port or 61208
    import json as _json, urllib.request
    cpu_data = None
    reachable = False
    # Try API v4 first (Glances 4.x), then fall back to v3 (Glances 3.x)
    for api_ver in ("4", "3"):
        url = f"http://{host}:{port}/api/{api_ver}/cpu"
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:  # nosec
                if resp.status == 200:
                    raw = resp.read().decode("utf-8", errors="ignore")
                    try:
                        cpu_data = _json.loads(raw)
                    except Exception:
                        cpu_data = None
                    reachable = True
                    break
        except Exception:
            continue
    return JsonResponse({"ok": True, "reachable": reachable, "cpu": cpu_data})


# ---------------------------------------------------------------------------
# SFTP File Manager (paramiko-based, built from scratch)
# ---------------------------------------------------------------------------

# Text file extensions allowed for preview
_TEXT_EXTENSIONS = {
    ".txt", ".log", ".md", ".json", ".xml", ".yaml", ".yml", ".csv",
    ".ini", ".cfg", ".conf", ".toml", ".env", ".sh", ".bash", ".bat",
    ".cmd", ".ps1", ".py", ".js", ".ts", ".html", ".htm", ".css",
    ".sql", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".go",
    ".rb", ".php", ".rs", ".swift", ".kt", ".lua", ".r", ".pl",
    ".gitignore", ".editorconfig", ".dockerfile",
}

_MAX_PREVIEW_BYTES = 512 * 1024  # 512 KB


@contextmanager
def _sftp_session(client):
    """Context manager that yields an SFTP client and auto-closes on exit."""
    sftp, transport = sftp_connect(client)
    try:
        yield sftp
    finally:
        try:
            sftp.close()
        except Exception:
            pass
        try:
            transport.close()
        except Exception:
            pass


def _format_file_list(sftp, remote_path: str, rel_path: str):
    """Return sorted list of dicts for each entry in remote_path."""
    items = []
    for attr in sftp.listdir_attr(remote_path):
        mode = int(getattr(attr, "st_mode", 0) or 0)
        is_dir = stat_module.S_ISDIR(mode)
        items.append({
            "name": attr.filename,
            "is_dir": is_dir,
            "size": int(getattr(attr, "st_size", 0) or 0),
            "mtime": int(getattr(attr, "st_mtime", 0) or 0),
            "path": posixpath.join(rel_path, attr.filename) if rel_path != "/" else "/" + attr.filename,
        })
    # Sort: directories first, then alphabetical
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return items


@login_required
@user_passes_test(lambda u: u.is_staff)
def sftp_browse(request, client_id: int):
    """List a remote directory's contents. GET ?path=/some/dir (default /)."""
    client = get_object_or_404(Client, id=client_id)
    req_path = request.GET.get("path", "/") or "/"

    # Normalize requested path
    if not req_path.startswith("/"):
        req_path = "/" + req_path
    req_path = posixpath.normpath(req_path)

    try:
        with _sftp_session(client) as sftp:
            items = _format_file_list(sftp, req_path, req_path)
            return JsonResponse({"ok": True, "cwd": req_path, "items": items})
    except FileNotFoundError:
        return JsonResponse({"ok": False, "error": f"Directory not found: {req_path}"}, status=404)
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


@login_required
@user_passes_test(lambda u: u.is_staff)
def sftp_download(request, client_id: int):
    """Download a remote file. GET ?path=/full/path/to/file."""
    client = get_object_or_404(Client, id=client_id)
    remote_path = request.GET.get("path")
    if not remote_path:
        return JsonResponse({"ok": False, "error": "Missing path parameter"}, status=400)

    remote_path = posixpath.normpath(remote_path)

    try:
        sftp, transport = sftp_connect(client)
        try:
            with sftp.file(remote_path, mode="rb") as f:
                data = f.read()
            filename = posixpath.basename(remote_path)
            content_type, _ = mimetypes.guess_type(filename)
            if not content_type:
                content_type = "application/octet-stream"
            resp = HttpResponse(data, content_type=content_type)
            resp["Content-Disposition"] = f'attachment; filename="{filename}"'
            return resp
        finally:
            try:
                sftp.close()
            except Exception:
                pass
            try:
                transport.close()
            except Exception:
                pass
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def sftp_upload(request, client_id: int):
    """Upload file(s). POST multipart: file (the file), path (target directory)."""
    client = get_object_or_404(Client, id=client_id)
    target_dir = request.POST.get("path", "/") or "/"
    up = request.FILES.get("file")
    if not up:
        return JsonResponse({"ok": False, "error": "No file provided"}, status=400)

    target_dir = posixpath.normpath(target_dir)
    remote_path = posixpath.join(target_dir, up.name)

    try:
        with _sftp_session(client) as sftp:
            with sftp.file(remote_path, mode="wb") as f:
                for chunk in up.chunks():
                    f.write(chunk)
            return JsonResponse({"ok": True, "path": remote_path, "name": up.name})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


def _rmtree_sftp(sftp, path: str):
    """Recursively delete a remote directory tree."""
    for attr in sftp.listdir_attr(path):
        child = posixpath.join(path, attr.filename)
        mode = int(getattr(attr, "st_mode", 0) or 0)
        if stat_module.S_ISDIR(mode):
            _rmtree_sftp(sftp, child)
        else:
            sftp.remove(child)
    sftp.rmdir(path)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def sftp_delete(request, client_id: int):
    """Delete a file or directory (recursive). POST JSON body: {"path": "..."}."""
    client = get_object_or_404(Client, id=client_id)
    try:
        body = json.loads(request.body)
    except Exception:
        body = {}
    remote_path = body.get("path") or request.POST.get("path")
    if not remote_path:
        return JsonResponse({"ok": False, "error": "Missing path"}, status=400)

    remote_path = posixpath.normpath(remote_path)

    # Prevent deleting root
    if remote_path == "/":
        return JsonResponse({"ok": False, "error": "Cannot delete root directory"}, status=400)

    try:
        with _sftp_session(client) as sftp:
            st = sftp.stat(remote_path)
            mode = int(getattr(st, "st_mode", 0) or 0)
            if stat_module.S_ISDIR(mode):
                _rmtree_sftp(sftp, remote_path)
            else:
                sftp.remove(remote_path)
            return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def sftp_mkdir(request, client_id: int):
    """Create a directory. POST JSON body: {"path": "/parent", "name": "newdir"}."""
    client = get_object_or_404(Client, id=client_id)
    try:
        body = json.loads(request.body)
    except Exception:
        body = {}
    parent = body.get("path") or request.POST.get("path") or "/"
    name = body.get("name") or request.POST.get("name")
    if not name:
        return JsonResponse({"ok": False, "error": "Missing directory name"}, status=400)

    # Basic name validation
    if "/" in name or "\\" in name or name in (".", ".."):
        return JsonResponse({"ok": False, "error": "Invalid directory name"}, status=400)

    parent = posixpath.normpath(parent)
    target = posixpath.join(parent, name)

    try:
        with _sftp_session(client) as sftp:
            sftp.mkdir(target)
            return JsonResponse({"ok": True, "path": target})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def sftp_rename(request, client_id: int):
    """Rename / move a file or directory. POST JSON body: {"src": "...", "dst": "..."}."""
    client = get_object_or_404(Client, id=client_id)
    try:
        body = json.loads(request.body)
    except Exception:
        body = {}
    src = body.get("src") or request.POST.get("src")
    dst = body.get("dst") or request.POST.get("dst")
    if not src or not dst:
        return JsonResponse({"ok": False, "error": "Missing src or dst"}, status=400)

    src = posixpath.normpath(src)
    dst = posixpath.normpath(dst)

    try:
        with _sftp_session(client) as sftp:
            sftp.rename(src, dst)
            return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


@login_required
@user_passes_test(lambda u: u.is_staff)
def sftp_preview(request, client_id: int):
    """Preview a text file's contents. GET ?path=/some/file.txt."""
    client = get_object_or_404(Client, id=client_id)
    remote_path = request.GET.get("path")
    if not remote_path:
        return JsonResponse({"ok": False, "error": "Missing path"}, status=400)

    remote_path = posixpath.normpath(remote_path)
    filename = posixpath.basename(remote_path)
    ext = os.path.splitext(filename)[1].lower()

    # Extension guard
    if ext not in _TEXT_EXTENSIONS and filename not in _TEXT_EXTENSIONS:
        return JsonResponse({"ok": False, "error": f"File type '{ext}' is not supported for preview"}, status=400)

    try:
        with _sftp_session(client) as sftp:
            # Size guard
            st = sftp.stat(remote_path)
            size = int(getattr(st, "st_size", 0) or 0)
            if size > _MAX_PREVIEW_BYTES:
                return JsonResponse({
                    "ok": False,
                    "error": f"File too large for preview ({size:,} bytes, max {_MAX_PREVIEW_BYTES:,})"
                }, status=400)

            with sftp.file(remote_path, mode="rb") as f:
                data = f.read(_MAX_PREVIEW_BYTES)

            # Attempt to decode as UTF-8
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = data.decode("latin-1")
                except Exception:
                    return JsonResponse({"ok": False, "error": "File does not appear to be text"}, status=400)

            return JsonResponse({
                "ok": True,
                "filename": filename,
                "size": size,
                "content": text,
            })
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)


# ---------------------------------------------------------------------------
# Script Generator
# ---------------------------------------------------------------------------

@login_required
@user_passes_test(lambda u: u.is_staff)
def script_generator(request):
    """
    GET: render script_generator.html with ScriptGeneratorForm
    POST with download=1: validate form, build PowerShell, return as attachment 'custom_setup.ps1'
    """
    from django.conf import settings as django_settings
    # Auto-detect RMS server IP from the request
    server_host = request.get_host()  # e.g. "192.168.29.76:8000"
    reg_token = getattr(django_settings, "RMS_REGISTRATION_TOKEN", "rms-default-token-change-me")

    if request.method == "POST" and request.POST.get("download") == "1":
        form = ScriptGeneratorForm(request.POST)
        if not form.is_valid():
            return render(request, "clients/script_generator.html", {"form": form, "server_host": server_host, "reg_token": reg_token})

        ps = build_powershell_from_options(form.cleaned_data, reg_token)
        if not ps or not ps.strip():
            return HttpResponseBadRequest("Failed to generate script")

        fname = f"custom_setup_{int(time.time())}.ps1"
        buf = io.BytesIO(ps.encode("utf-8-sig"))
        resp = FileResponse(buf, as_attachment=True, filename=fname, content_type="text/plain")
        resp["X-Content-Type-Options"] = "nosniff"
        return resp

    else:
        form = ScriptGeneratorForm(initial={"rms_server_ip": server_host})
        return render(request, "clients/script_generator.html", {"form": form, "server_host": server_host, "reg_token": reg_token})


def _pwsh_escape(s: str) -> str:
        # Basic safe escaping for arguments we embed in PS strings
        return (s or "").replace("`", "``").replace('"', '""')


def build_powershell_from_options(opts: dict, reg_token: str = "") -> str:
        """
        opts keys (already cleaned by form):
            zerotier_id, install_* booleans, enable_glances_service, bind_address, bind_port, boot_delay, firewall_rules(list)
            auth_windows_password, auth_win_only_if_blank, auth_win_auto_login,
            auth_vnc_password, auth_vnc_always_overwrite, auth_ssh_password
        Returns a single PowerShell script string.
        """
        zt = _pwsh_escape(opts.get("zerotier_id") or "")
        bind_addr = _pwsh_escape(opts.get("bind_address") or "0.0.0.0")
        bind_port = int(opts.get("bind_port") or 61208)
        boot_delay = int(opts.get("boot_delay") or 15)
        fw_rules = opts.get("firewall_rules") or []

        # --- Authentication fields ---
        win_password = _pwsh_escape(opts.get("auth_windows_password") or "")
        win_only_if_blank = opts.get("auth_win_only_if_blank", True)
        win_auto_login = opts.get("auth_win_auto_login", True)
        vnc_password = _pwsh_escape(opts.get("auth_vnc_password") or "")
        vnc_always_overwrite = opts.get("auth_vnc_always_overwrite", True)
        ssh_password = _pwsh_escape(opts.get("auth_ssh_password") or "")

        # helper: conditional Chocolatey installs
        def choco_line(pkg: str, extra: str = "") -> str:
                key = f"install_{pkg.replace('-', '_')}"
                if opts.get(key, False):
                        arglist = f"@({extra})" if extra else "@()"
                        return f'  InstallChoco "{pkg}" {arglist}\n'
                return ""

        # firewall block from list
        fw_lines = []
        for r in fw_rules:
                n = _pwsh_escape(str(r["name"]))
                d = "Inbound" if r["direction"] == "Inbound" else "Outbound"
                p = "TCP" if str(r["protocol"]).upper() != "UDP" else "UDP"
                port = int(r["port"])
                fw_lines.append(f'''
        if (-not (Get-NetFirewallRule -DisplayName "{n}" -ErrorAction SilentlyContinue)) {{
            New-NetFirewallRule -DisplayName "{n}" -Direction {d} -Protocol {p} -Action Allow -LocalPort {port} | Out-Null
            Info "Firewall rule '{n}' added."
        }} else {{
            Info "Firewall rule '{n}' exists."
        }}
''')

        # --- Glances service block only if enabled ---
        glances_block = f"""
    # ---------- Create venv & install Glances web stack ----------
    $VenvRoot = "C:\\\\GlancesSvc\\\\venv"
    $venvPy = Join-Path $VenvRoot "Scripts\\\\python.exe"
    if (-not (Test-Path $venvPy)) {{
        Info "Creating venv at $VenvRoot ..."
        & $pythonExe -m venv $VenvRoot
    }} else {{
        Info "Using existing venv at $VenvRoot"
    }}
    & $venvPy -m pip install --upgrade pip setuptools wheel
    & $venvPy -m pip install glances jinja2 starlette fastapi "uvicorn[standard]" psutil

    # ---------- Wrapper script (boot delay + launch) ----------
    $WrapperPath = "C:\\\\GlancesSvc\\\\run_glances.cmd"
    New-Item -ItemType Directory -Force -Path (Split-Path $WrapperPath) | Out-Null
    $wrapper = @"
@echo off
timeout /t {boot_delay} /nobreak >nul
"$venvPy" -m glances -w --bind {bind_addr} --port {bind_port} --disable-autodiscover
"@
    Set-Content -Path $WrapperPath -Value $wrapper -Encoding ASCII -Force
    Unblock-File -Path $WrapperPath

    # ---------- NSSM service (robust) ----------
    $SvcName    = "GlancesWeb"
    $SvcDisplay = "Glances Web Server"
    $LogDir     = "C:\\\\ProgramData\\\\Glances\\\\logs"
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    $nssmCandidates = @(
        (Join-Path $env:ProgramData "chocolatey\\\\bin\\\\nssm.exe"),
        (Join-Path $env:ProgramFiles "nssm\\\\win64\\\\nssm.exe"),
        (Join-Path $env:ProgramFiles "nssm\\\\win32\\\\nssm.exe")
    ) + (Get-Command nssm -ErrorAction SilentlyContinue | ForEach-Object {{ $_.Source }})
    $nssm = $nssmCandidates | Where-Object {{ $_ -and (Test-Path $_) }} | Select-Object -First 1
    if (-not $nssm) {{ throw "NSSM not found after install." }}

    $svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($svc) {{
        Info "Removing existing service '$SvcName'..."
        try {{
            if ($svc.Status -ne 'Stopped') {{ Stop-Service $SvcName -Force -ErrorAction SilentlyContinue; Start-Sleep 2 }}
        }} catch {{}}
        & $nssm remove $SvcName confirm | Out-Null
        $timeout = 0
        while (Get-Service -Name $SvcName -ErrorAction SilentlyContinue) {{
            Start-Sleep -Seconds 2; $timeout += 2
            if ($timeout -gt 30) {{ Warn "Service name '$SvcName' still pending deletion after 30s, continuing."; break }}
        }}
    }}

    Info "Creating NSSM service '$SvcName'..."
    $create = Start-Process -FilePath $nssm -ArgumentList @("install",$SvcName,"cmd.exe","/c",$WrapperPath) -NoNewWindow -Wait -PassThru
    if ($create.ExitCode -ne 0) {{ Warn "NSSM create failed (exit $($create.ExitCode)). Retrying in 5s..."; Start-Sleep 5; Start-Process -FilePath $nssm -ArgumentList @("install",$SvcName,"cmd.exe","/c",$WrapperPath) -NoNewWindow -Wait | Out-Null }}

    & $nssm set $SvcName DisplayName   $SvcDisplay | Out-Null
    & $nssm set $SvcName Description   "Runs Glances Web UI via venv + wrapper." | Out-Null
    & $nssm set $SvcName Start         SERVICE_AUTO_START | Out-Null
    & $nssm set $SvcName AppStdout     (Join-Path $LogDir "glances_stdout.log") | Out-Null
    & $nssm set $SvcName AppStderr     (Join-Path $LogDir "glances_stderr.log") | Out-Null
    & $nssm set $SvcName AppNoConsole  1 | Out-Null
    & $nssm set $SvcName AppRestartDelay  5000 | Out-Null
    & $nssm set $SvcName AppThrottle      15000 | Out-Null
    & $nssm set $SvcName AppStopMethodConsole 15000 | Out-Null
    & $nssm set $SvcName AppStopMethodSkip    6 | Out-Null
    & $nssm set $SvcName AppExit Default Restart | Out-Null
    & $nssm set $SvcName AppEnvironmentExtra ("PATH=$($VenvRoot)\\\\Scripts;`%PATH`%") | Out-Null
    sc.exe config $SvcName start= delayed-auto | Out-Null
    sc.exe config $SvcName depend= Tcpip/Dnscache/DHCP | Out-Null
    sc.exe failure $SvcName reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    sc.exe failureflag $SvcName 1 | Out-Null

    Info "Starting service '$SvcName'..."
    Start-Service $SvcName
    Start-Sleep 5
    $state = (Get-Service $SvcName).Status
    if ($state -ne 'Running') {{
        Warn "Service state: $state. Tail logs:"
        Get-Content (Join-Path $LogDir "glances_stderr.log") -ErrorAction SilentlyContinue | Select-Object -Last 80
    }} else {{
        Info "Service '$SvcName' is RUNNING on http://{bind_addr}:{bind_port}"
    }}
""" if opts.get("enable_glances_service") else "  Info 'Glances service disabled by user.'\n"

        # --- ZeroTier block (optional) ---
        zt_block = f"""
    # ---------- ZeroTier ----------
    if ("{zt}" -ne "") {{
        $ztCli = "C:\\\\Program Files (x86)\\\\ZeroTier\\\\One\\\\zerotier-cli.bat"
        $wait = 0
        while (-not (Test-Path $ztCli) -and $wait -lt 90) {{ Info "Waiting for ZeroTier CLI ($wait/90s)..."; Start-Sleep 5; $wait += 5 }}
        if (Test-Path $ztCli) {{
            $ztService = Get-Service -Name 'ZeroTierOneService' -ErrorAction SilentlyContinue
            if ($ztService -and $ztService.Status -ne 'Running') {{
                Info "Starting ZeroTier service..."; Start-Service $ztService.Name; $ztService.WaitForStatus('Running',[TimeSpan]::FromSeconds(60))
            }}
            try {{
                $joined = & $ztCli listnetworks | Select-String "{zt}"
                if (-not $joined) {{ Info "Joining ZeroTier {zt}..."; & $ztCli join "{zt}" | Out-Null }} else {{ Info "Already joined ZeroTier {zt}." }}
            }} catch {{ Warn "ZeroTier join error: $($_)" }}
        }} else {{ Warn "ZeroTier CLI not found; skipping join." }}
    }} else {{
        Info "ZeroTier ID empty; skipping join."
    }}
"""

        # --- TightVNC: force-install if VNC password is provided ---
        if vnc_password and opts.get("install_tightvnc", False):
            # Force reinstall so it's always present before we set the password via registry
            tightvnc_line = '  InstallChoco "tightvnc" @("--force")\n'
        else:
            tightvnc_line = choco_line("tightvnc")

        # --- Chocolatey install section (conditional) ---
        choco_block = f"""
    # ---------- Chocolatey core installs ----------
{choco_line("openssh", "'--params','/SSHServerFeature'")}
{choco_line("zerotier-one")}
{tightvnc_line}
{choco_line("winscp")}
{choco_line("sysinternals", "'--ignore-checksums'")}
{choco_line("nssm")}
{choco_line("python")}
"""

        # --- Firewall rules (exactly as user provided) ---
        firewall_block = "  # ---------- Firewall rules ----------\n" + "".join(fw_lines) if fw_lines else "  Info 'No firewall rules provided.'\n"

        # --- Monitoring Agent block (optional) ---
        monitor_block = ""
        if opts.get("install_monitoring_agent"):
            rms_ip = _pwsh_escape(opts.get("rms_server_ip") or "127.0.0.1:8000")
            # Read the monitor.ps1 template
            monitor_script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "monitor.ps1")
            try:
                with open(monitor_script_path, "r", encoding="utf-8") as f:
                    monitor_content = f.read()
                # Replace the placeholder server IP with the actual one
                monitor_content = monitor_content.replace(
                    '$RMS_SERVER     = "http://192.168.29.168:8000"',
                    f'$RMS_SERVER     = "http://{rms_ip}"'
                )
                monitor_block = f"""
    # ═══════════ RMS Monitoring Agent ═══════════
    Info "Installing RMS Monitoring Agent..."
    New-Item -ItemType Directory -Force -Path "C:\\\\RMS" | Out-Null

    $monitorScript = @'
{monitor_content}
'@
    Set-Content -Path "C:\\\\RMS\\\\monitor.ps1" -Value $monitorScript -Force -Encoding UTF8
    Unblock-File -Path "C:\\\\RMS\\\\monitor.ps1"

    # Create VBS launcher for truly hidden execution (bypasses Windows Terminal)
    $launcherVbs = @'
' RMS Monitor Launcher
CreateObject("Wscript.Shell").Run "powershell.exe -NonInteractive -NoProfile -NoLogo -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\RMS\monitor.ps1", 0, False
'@
    Set-Content -Path "C:\\\\RMS\\\\launcher.vbs" -Value $launcherVbs -Force -Encoding ASCII

    # Register as a scheduled task using wscript.exe (zero visible window)
    $mAction  = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "C:\\\\RMS\\\\launcher.vbs"
    $mTrigger1 = New-ScheduledTaskTrigger -AtLogOn
    $mTrigger2 = New-ScheduledTaskTrigger -AtStartup
    $mPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\\\\Users" -RunLevel Limited
    $mSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName "RMS_Monitor" -Action $mAction -Trigger @($mTrigger1,$mTrigger2) -Principal $mPrincipal -Settings $mSettings -Force | Out-Null
    Start-ScheduledTask -TaskName "RMS_Monitor"
    Info "Monitoring Agent installed and started (reporting to http://{rms_ip})."
"""
            except FileNotFoundError:
                monitor_block = "  Warn 'monitor.ps1 not found on server; skipping monitoring agent.'\n"
        else:
            monitor_block = "  Info 'Monitoring agent disabled by user.'\n"

        # --- Windows Password block (optional) ---
        win_password_block = ""
        if win_password:
            only_blank_ps = "$true" if win_only_if_blank else "$false"
            auto_login_ps = "$true" if win_auto_login else "$false"
            win_password_block = f"""
    # ═══════════ Windows Password Setup ═══════════
    Info ""
    Info "═══════════════════════════════════════════════"
    Info "  Configuring Windows Account Password..."
    Info "═══════════════════════════════════════════════"
    $desiredPassword = "{win_password}"
    $username = $env:USERNAME
    $onlyIfBlank = {only_blank_ps}
    $enableAutoLogin = {auto_login_ps}

    # Detect if account has a password
    $hasPassword = $false
    try {{
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction SilentlyContinue
        $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Machine
        )
        $blankWorks = $context.ValidateCredentials($username, "")
        $hasPassword = -not $blankWorks
        $context.Dispose()
    }} catch {{
        # Fallback: try net user
        $userInfo = net user $username 2>&1
        if ($userInfo -match "Password required\\s+No") {{ $hasPassword = $false }}
        else {{ $hasPassword = $true }}
    }}

    if ($desiredPassword) {{
        if (-not $hasPassword) {{
            Info "Account '$username' has NO password. Setting password..."
            net user $username $desiredPassword | Out-Null
            if ($LASTEXITCODE -eq 0) {{ Info "Windows password set successfully." }}
            else {{ Warn "Failed to set password. Error code: $LASTEXITCODE" }}
        }} elseif (-not $onlyIfBlank) {{
            Warn "Overwriting existing password for '$username'..."
            net user $username $desiredPassword | Out-Null
            if ($LASTEXITCODE -eq 0) {{ Info "Windows password overwritten." }}
            else {{ Warn "Failed to set password." }}
        }} else {{
            Info "Account '$username' already has a password. Skipping."
        }}

        # Auto-login configuration
        if ($enableAutoLogin) {{
            $regPath = "HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon"
            Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1"
            Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $username
            Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $desiredPassword
            Set-ItemProperty -Path $regPath -Name "DefaultDomainName" -Value $env:COMPUTERNAME
            Info "Auto-login configured. PC will boot to desktop automatically."
        }}

        # Disable blank password network restriction (safety net for SSH)
        Set-ItemProperty -Path "HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa" -Name "LimitBlankPasswordUse" -Value 0
    }}
"""

        # --- VNC Password via DES Registry Encryption (optional) ---
        vnc_password_block = ""
        if vnc_password:
            vnc_password_block = f"""
    # ═══════════ VNC Password Setup (DES Registry Method) ═══════════
    Info ""
    Info "═══════════════════════════════════════════════"
    Info "  Setting VNC Password via Registry..."
    Info "═══════════════════════════════════════════════"
    $vncPassword = "{vnc_password}"

    # TightVNC only uses first 8 characters — hard limit
    if ($vncPassword.Length -gt 8) {{
        Warn "VNC password truncated to 8 characters (TightVNC limitation)."
        $vncPassword = $vncPassword.Substring(0, 8)
    }}

    function Encrypt-VNCPassword {{
        param([string]$Password)
        if ($Password.Length -gt 8) {{ $Password = $Password.Substring(0, 8) }}

        # Pad to exactly 8 bytes
        $passBytes = New-Object byte[] 8
        $raw = [System.Text.Encoding]::ASCII.GetBytes($Password)
        [Array]::Copy($raw, $passBytes, $raw.Length)

        # Fixed DES key used by ALL VNC implementations
        $desKey = [byte[]]@(0xe8, 0x4a, 0xd6, 0x60, 0xc4, 0x72, 0x1a, 0xe0)

        $des = New-Object System.Security.Cryptography.DESCryptoServiceProvider
        $des.Mode    = [System.Security.Cryptography.CipherMode]::ECB
        $des.Padding = [System.Security.Cryptography.PaddingMode]::None
        $des.Key     = $desKey

        $enc = $des.CreateEncryptor()
        $encrypted = $enc.TransformFinalBlock($passBytes, 0, 8)
        $des.Dispose()

        return $encrypted
    }}

    $encPwd  = Encrypt-VNCPassword -Password $vncPassword
    $vncReg  = "HKLM:\\\\SOFTWARE\\\\TightVNC\\\\Server"

    # Create registry key if it doesn't exist
    if (-not (Test-Path $vncReg)) {{ New-Item -Path $vncReg -Force | Out-Null }}

    # Write encrypted password as binary registry values
    Set-ItemProperty -Path $vncReg -Name "Password"                 -Value $encPwd -Type Binary
    Set-ItemProperty -Path $vncReg -Name "ControlPassword"          -Value $encPwd -Type Binary
    Set-ItemProperty -Path $vncReg -Name "UseVncAuthentication"     -Value 1 -Type DWord
    Set-ItemProperty -Path $vncReg -Name "UseControlAuthentication" -Value 1 -Type DWord

    # Restart TightVNC service to apply the new password
    $tvnSvc = Get-Service -Name "tvnserver" -ErrorAction SilentlyContinue
    if ($tvnSvc) {{
        Restart-Service -Name "tvnserver" -Force
        Info "VNC password set and service restarted."
    }} else {{
        Warn "TightVNC service not found after install."
    }}
"""

        # --- OpenSSH config block (optional) ---
        openssh_config_block = ""
        if win_password and opts.get("install_openssh", False):
            openssh_config_block = """
    # ═══════════ OpenSSH Password Auth Config ═══════════
    $sshdConfig = "C:\\\\ProgramData\\\\ssh\\\\sshd_config"
    if (Test-Path $sshdConfig) {
        $content = Get-Content $sshdConfig -Raw
        $changed = $false

        # Make sure PasswordAuthentication is yes
        if ($content -match '#?PasswordAuthentication\\s+no') {
            $content = $content -replace '#?PasswordAuthentication\\s+no', 'PasswordAuthentication yes'
            $changed = $true
        }
        # Ensure it's explicitly set to yes if not present
        if ($content -notmatch 'PasswordAuthentication\\s+yes') {
            $content += \"`nPasswordAuthentication yes`n\"
            $changed = $true
        }

        if ($changed) {
            Set-Content -Path $sshdConfig -Value $content -Force
            Info \"SSH password authentication enabled.\"
        } else {
            Info \"SSH password authentication already enabled.\"
        }

        # Restart SSH service to apply changes
        Restart-Service sshd -Force -ErrorAction SilentlyContinue
    } else {
        Info \"sshd_config not found — OpenSSH may not be installed yet.\"
    }
"""

        # --- Auto-Registration block (optional) ---
        registration_block = ""
        if opts.get("auto_register"):
            rms_ip = _pwsh_escape(opts.get("rms_server_ip") or "127.0.0.1:8000")
            reg_token_val = _pwsh_escape(reg_token)
            reg_ssh_user = _pwsh_escape(opts.get("reg_ssh_username") or "")
            reg_ssh_pass = _pwsh_escape(ssh_password)
            ssh_pass_line = '        ssh_password = "' + reg_ssh_pass + '"' if reg_ssh_pass else ""
            glances_p = int(opts.get("bind_port") or 61208)
            registration_block = (
                '    # ══════════ Auto-Registration with RMS ══════════\n'
                '    Info ""\n'
                '    Info "═══════════════════════════════════════════════"\n'
                '    Info "  Registering with RMS server..."\n'
                '    Info "═══════════════════════════════════════════════"\n'
                '\n'
                '    $script:registrationSuccess = $false\n'
                '\n'
                '    function Get-PrimaryIP {\n'
                "        $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.Name -notmatch 'VMware|VirtualBox|ZeroTier|VPN|vEthernet' }\n"
                '        foreach ($a in $adapters) {\n'
                '            $ips = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue\n'
                '            foreach ($ip in $ips) {\n'
                "                if ($ip.IPAddress -and $ip.IPAddress -notmatch '^(169\\.254|127\\.)') { return $ip.IPAddress }\n"
                '            }\n'
                '        }\n'
                "        $fallback = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(169\\.254|127\\.)' } | Select-Object -First 1).IPAddress\n"
                '        return $fallback\n'
                '    }\n'
                '\n'
                '    $regIP = Get-PrimaryIP\n'
                '    $regHostname = $env:COMPUTERNAME\n'
                '    $regMac = ""\n'
                '    $adapter = Get-NetAdapter | Where-Object { (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -eq $regIP } | Select-Object -First 1\n'
                "    if ($adapter) { $regMac = $adapter.MacAddress.Replace('-', ':') }\n"
                '\n'
                "    $regOS = ((Get-CimInstance Win32_OperatingSystem).Caption -replace '^Microsoft ', '')\n"
                '    $regOSVer = (Get-CimInstance Win32_OperatingSystem).Version\n'
                '    $regCPU = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()\n'
                '    $regRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)\n'
                "    $regDisk = [math]::Round((Get-CimInstance Win32_DiskDrive | Where-Object { $_.MediaType -like '*fixed*' } | Select-Object -First 1).Size / 1GB)\n"
                '\n'
                f'    $regSSHUser = "{reg_ssh_user}"\n'
                '    if (-not $regSSHUser) { $regSSHUser = $env:USERNAME }\n'
                '\n'
                '    Info "  Hostname:  $regHostname"\n'
                '    Info "  IP:        $regIP"\n'
                '    Info "  MAC:       $regMac"\n'
                '    Info "  OS:        $regOS ($regOSVer)"\n'
                '    Info "  SSH User:  $regSSHUser"\n'
                '    Info "  CPU:       $regCPU"\n'
                '    Info "  RAM:       ${regRAM}GB"\n'
                '    Info "  Disk:      ${regDisk}GB"\n'
                '\n'
                '    $regBody = @{\n'
                f'        registration_token = "{reg_token_val}"\n'
                '        hostname = $regHostname\n'
                '        ip_address = $regIP\n'
                '        mac_address = $regMac\n'
                '        os_name = $regOS\n'
                '        os_version = $regOSVer\n'
                '        ssh_port = 22\n'
                '        ssh_username = $regSSHUser\n'
                + (ssh_pass_line + '\n' if ssh_pass_line else '')
                + f'        glances_port = {glances_p}\n'
                '        vnc_port = 5900\n'
                '        cpu = $regCPU\n'
                '        ram_gb = $regRAM\n'
                '        disk_gb = $regDisk\n'
                '    } | ConvertTo-Json -Depth 3\n'
                '\n'
                '    try {\n'
                f'        $regResp = Invoke-RestMethod -Uri "http://{rms_ip}/api/clients/register/" -Method POST -ContentType "application/json" -Body $regBody -TimeoutSec 10\n'
                '        if ($regResp.ok) {\n'
                '            Info "Registered successfully! Status: $($regResp.status), Client ID: $($regResp.client_id)"\n'
                '            $script:registrationSuccess = $true\n'
                '        } else {\n'
                '            Warn "Registration failed: $($regResp.error)"\n'
                '        }\n'
                '    } catch {\n'
                '        Warn "Could not reach RMS server: $($_)"\n'
                f'        Warn "You may need to add this client manually at http://{rms_ip}/clients/add/"\n'
                '    }\n'
                '    Info "═══════════════════════════════════════════════"\n'
            )

        # --- Summary block ---
        rms_ip_for_summary = _pwsh_escape(opts.get("rms_server_ip") or "127.0.0.1:8000")
        summary_block = f"""
    # ═══════════ Setup Summary ═══════════
    Info ""
    Write-Host "" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "  RMS Client Setup Complete!" -ForegroundColor Green
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Computer Name:    $env:COMPUTERNAME"
    try {{ $clientIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.IPAddress -notmatch '^(169\\.254|127\\.)' }} | Select-Object -First 1).IPAddress }} catch {{ $clientIP = 'Unknown' }}
    Write-Host "  IP Address:       $clientIP"
    try {{ $macAddr = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).MacAddress }} catch {{ $macAddr = 'Unknown' }}
    Write-Host "  MAC Address:      $macAddr"
    Write-Host ""
    Write-Host "  Windows Password: {'SET' if win_password else 'NOT SET'}"
    Write-Host "  Auto-Login:       {'ENABLED' if win_password and win_auto_login else 'DISABLED'}"
    Write-Host "  VNC Password:     {'SET' if vnc_password else 'NOT SET'}"
    Write-Host "  SSH:              {'READY' if win_password else 'NEEDS PASSWORD'}"
    if ($script:registrationSuccess) {{ Write-Host "  RMS Registered:   YES" -ForegroundColor Green }} else {{ Write-Host "  RMS Registered:   NO" -ForegroundColor Yellow }}
    Write-Host ""
    Write-Host "  RMS Dashboard: http://{rms_ip_for_summary}" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
"""

        # --- Base script skeleton ---
        script = f"""
# Auto-generated by your Django app
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$ZeroTierId = "{zt}"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$script:registrationSuccess = $false
function Info($m){{ Write-Host $m -ForegroundColor Cyan }}
function Warn($m){{ Write-Host $m -ForegroundColor Yellow }}
function Err ($m){{ Write-Host $m -ForegroundColor Red }}

# Elevate if needed
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = "powershell"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ZeroTierId $ZeroTierId"
    $psi.Verb      = "runas"
    try {{ [System.Diagnostics.Process]::Start($psi) | Out-Null }} catch {{ Write-Error $_; exit 1 }}
    exit 0
}}

# TLS
try {{ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 }} catch {{}}

# Transcript
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$transcriptPath = Join-Path $scriptDir ("custom-setup-log-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".txt")
Start-Transcript -Path $transcriptPath -Force
try {{
    Info "Transcript: $transcriptPath"

{win_password_block}

    # ---------- Chocolatey bootstrap ----------
    $chocoExe = Join-Path $env:ProgramData 'Chocolatey\\\\bin\\\\choco.exe'
    if (-not (Test-Path $chocoExe)) {{
        Info "Installing Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        $script = (New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
        Invoke-Expression $script
        Start-Sleep 8
        if (-not (Test-Path $chocoExe)) {{ throw "Chocolatey install failed." }}
    }} else {{ Info "Chocolatey found." }}

    function ChocoInstalled($pkg) {{
        $res = & $chocoExe list --local-only --exact $pkg 2>$null
        return $res -match ("^$pkg ")
    }}
    function InstallChoco($pkg, $extraArgs) {{
        if (ChocoInstalled $pkg) {{ Info "$pkg already installed."; return }}
        Info "Installing $pkg..."
        $args = @('install',$pkg,'-y','-a','--no-progress')
        if ($extraArgs){{ $args += $extraArgs }}
        $p = Start-Process -FilePath $chocoExe -ArgumentList $args -Wait -NoNewWindow -PassThru
        if ($p.ExitCode -ne 0){{ throw "Failed to install $pkg, exit $($p.ExitCode)" }}
    }}

{choco_block}

    # ---------- Refresh env ----------
    try {{
        $profileScript = Join-Path $env:ChocolateyInstall 'helpers\\\\chocolateyProfile.psm1'
        if (Test-Path $profileScript) {{
            Import-Module $profileScript -Force -ErrorAction SilentlyContinue
            if (Get-Command refreshenv -ErrorAction SilentlyContinue) {{ refreshenv | Out-Null; Info "Environment refreshed." }}
        }}
    }} catch {{ Warn "refreshenv failed: $($_)" }}

{vnc_password_block}

{openssh_config_block}

    # ---------- Python locate (for venv seed) ----------
    function FindPython(){{
        $dirs = Get-ChildItem -Path "C:\\\\" -Directory -Filter "Python*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        foreach($d in $dirs){{
            $py = Join-Path $d.FullName "python.exe"
            if (Test-Path $py){{ try {{ if ((& $py --version 2>&1) -match "Python") {{ return $py }} }} catch {{}} }}
        }}
        return $null
    }}
    $pythonExe = FindPython
    if (-not $pythonExe) {{
        if (Get-Command python -ErrorAction SilentlyContinue) {{ $pythonExe = "python" }} else {{ Info "No base Python found; installing..."; InstallChoco "python" @(); $pythonExe = FindPython; if (-not $pythonExe) {{ $pythonExe = "python" }} }}
    }}
    Info "Base Python: $pythonExe"

{glances_block}

{zt_block}

    # ---------- Enable and start common services ----------
        foreach($m in @(
            @{{Name='sshd'; Friendly='OpenSSH Server'}},
            @{{Name='ZeroTierOneService'; Friendly='ZeroTier One'}},
            @{{Name='tvnserver'; Friendly='TightVNC Server'}}
        )) {{
        $svc = Get-Service -Name $m.Name -ErrorAction SilentlyContinue
        if ($svc) {{
            Set-Service -Name $m.Name -StartupType Automatic
            if ($svc.Status -ne 'Running'){{ Start-Service $m.Name }}
            Info "$($m.Friendly) set to Automatic and running."
        }} else {{ Info "$($m.Friendly) not present (skipped)." }}
    }}

{firewall_block}

{monitor_block}

{registration_block}

{summary_block}

    Info "Done. If anything fails, check C:\\\\ProgramData\\\\Glances\\\\logs and the transcript."
}} catch {{
    Write-Error "Fatal: $($_)"
}} finally {{
    Stop-Transcript
}}
"""
        return script
