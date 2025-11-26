import os
import sys
import signal
import socket
import subprocess
import io
import time
from typing import Optional

from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, Http404, HttpResponse, FileResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render, redirect
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import Client, VNCSession, SSHSession
from .utils import (
    pid_alive,
    kill_pid_tree,
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
    session = getattr(client, "vnc_session", None)
    running = False
    if session:
        running = _is_process_running(session.pid)
        if not running:
            session.delete()
            session = None
    ssh_session = getattr(client, "ssh_session", None)
    ssh_running = False
    if ssh_session:
        ssh_running = _is_process_running(ssh_session.pid)
        if not ssh_running:
            ssh_session.delete()
            ssh_session = None
    return render(
        request,
        "clients/client_page.html",
        {
            "client": client,
            "session": session,
            "running": running,
            "ssh_session": ssh_session,
            "ssh_running": ssh_running,
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


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def start_vnc(request, client_id: int):
    client = get_object_or_404(Client, id=client_id)

    existing = getattr(client, "vnc_session", None)
    if existing and _is_process_running(existing.pid):
        return JsonResponse({"ok": True, "already": True, "url": f"http://{existing.listen_host}:{existing.listen_port}/vnc.html"})
    elif existing:
        existing.delete()

    target = f"{client.ip_address}:5900"
    listen_host = "127.0.0.1"
    listen_port = 6080

    try:
        if os.name == "nt":
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"novnc --target {target} --listen {listen_host}:{listen_port}"
            ]
            proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            cmd = [
                "novnc",
                "--target", target,
                "--listen", f"{listen_host}:{listen_port}",
            ]
            proc = subprocess.Popen(cmd, preexec_fn=os.setsid)
    except FileNotFoundError:
        return JsonResponse({"ok": False, "error": "'novnc' command not found on server PATH. Install noVNC CLI and try again."}, status=500)
    except Exception as e:
        return JsonResponse({"ok": False, "error": f"Failed to start noVNC: {e}"}, status=500)

    session = VNCSession.objects.create(
        client=client,
        pid=proc.pid,
        listen_host=listen_host,
        listen_port=listen_port,
        started_by=request.user,
    )

    return JsonResponse({"ok": True, "pid": proc.pid, "url": f"http://{listen_host}:{listen_port}/vnc.html"})


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


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def start_ssh(request, client_id: int):
    """Start a local webssh server bound to 127.0.0.1 and expose it for the given client."""
    client = get_object_or_404(Client, id=client_id)

    existing = getattr(client, "ssh_session", None)
    if existing and _is_process_running(existing.pid):
        # Pre-fill client IP, user will enter credentials in webssh UI
        scheme = "https" if request.is_secure() else "http"
        host_only = request.get_host().split(":")[0]
        url = f"{scheme}://{host_only}:{existing.listen_port}/?hostname={client.ip_address}&port=22"
        return JsonResponse({"ok": True, "already": True, "url": url})
    elif existing:
        existing.delete()

    listen_host = "0.0.0.0"
    listen_port = 8888

    def _port_open() -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.connect(("127.0.0.1", listen_port))
                return True
        except Exception:
            return False

    if _port_open():
        scheme = "https" if request.is_secure() else "http"
        host_only = request.get_host().split(":")[0]
        url = f"{scheme}://{host_only}:{listen_port}/?hostname={client.ip_address}&port=22"
        return JsonResponse({"ok": True, "already": True, "url": url})

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
            msg = "Failed to start WebSSH on port 8888. Check firewall/permissions and try again."
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
    url = f"{scheme}://{host_only}:{listen_port}/?hostname={client.ip_address}&port=22"
    return JsonResponse({"ok": True, "pid": proc.pid, "url": url})


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


@login_required
@user_passes_test(lambda u: u.is_staff)
def files_list(request, client_id: int):
    """List files at a given path via SFTP (JSON). Pass ?path= relative to client's base."""
    client = get_object_or_404(Client, id=client_id)
    rel = request.GET.get("path", ".")
    base = client.file_base_path or "/"
    try:
        target = safe_join(base, rel)
    except ValueError:
        return JsonResponse({"ok": False, "error": "Invalid path"}, status=400)

    try:
        sftp, transport = sftp_open(client)  # type: ignore[assignment]
        items = []
        for attr in sftp.listdir_attr(target):  # type: ignore[attr-defined]
            mode = int(getattr(attr, "st_mode", 0) or 0)
            is_dir = stat_is_dir(mode)
            items.append({
                "name": attr.filename,
                "is_dir": is_dir,
                "size": int(getattr(attr, "st_size", 0) or 0),
                "mtime": getattr(attr, "st_mtime", None),
                "path": posixpath.join(rel, attr.filename),
            })
        return JsonResponse({"ok": True, "cwd": rel, "items": items})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)
    finally:
        try:
            sftp.close()  # type: ignore[union-attr]
            transport.close()  # type: ignore[union-attr]
        except Exception:
            pass


@login_required
@user_passes_test(lambda u: u.is_staff)
def files_download(request, client_id: int):
    """Download a remote file. Provide ?path= relative to client's base."""
    client = get_object_or_404(Client, id=client_id)
    rel = request.GET.get("path")
    if not rel:
        return JsonResponse({"ok": False, "error": "Missing path"}, status=400)
    base = client.file_base_path or "/"
    try:
        target = safe_join(base, rel)
    except ValueError:
        return JsonResponse({"ok": False, "error": "Invalid path"}, status=400)

    try:
        sftp, transport = sftp_open(client)  # type: ignore[assignment]
        with sftp.file(target, mode="rb") as f:  # type: ignore[attr-defined]
            data = f.read()
        filename = posixpath.basename(rel)
        content_type, _ = mimetypes.guess_type(filename)
        if not content_type:
            content_type = "application/octet-stream"
        resp = HttpResponse(data, content_type=content_type)
        resp["Content-Disposition"] = f"attachment; filename=\"{filename}\""
        return resp
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)
    finally:
        try:
            sftp.close()  # type: ignore[union-attr]
            transport.close()  # type: ignore[union-attr]
        except Exception:
            pass


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def files_upload(request, client_id: int):
    """Upload a file to remote directory. POST form-data: file, path (dir)."""
    client = get_object_or_404(Client, id=client_id)
    rel_dir = request.POST.get("path", ".")
    up = request.FILES.get("file")
    if not up:
        return JsonResponse({"ok": False, "error": "Missing file"}, status=400)
    base = client.file_base_path or "/"
    try:
        target_dir = safe_join(base, rel_dir)
    except ValueError:
        return JsonResponse({"ok": False, "error": "Invalid path"}, status=400)
    remote_path = posixpath.join(target_dir, up.name)

    try:
        sftp, transport = sftp_open(client)  # type: ignore[assignment]
        with sftp.file(remote_path, mode="wb") as f:  # type: ignore[attr-defined]
            for chunk in up.chunks():
                f.write(chunk)
        return JsonResponse({"ok": True, "path": posixpath.join(rel_dir, up.name)})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)
    finally:
        try:
            sftp.close()  # type: ignore[union-attr]
            transport.close()  # type: ignore[union-attr]
        except Exception:
            pass


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def files_mkdir(request, client_id: int):
    """Create a new directory. POST: path (parent), name (new directory)."""
    client = get_object_or_404(Client, id=client_id)
    rel_dir = request.POST.get("path", ".")
    name = request.POST.get("name")
    if not name:
        return JsonResponse({"ok": False, "error": "Missing name"}, status=400)
    base = client.file_base_path or "/"
    try:
        target_dir = safe_join(base, rel_dir)
        target = posixpath.join(target_dir, name)
    except ValueError:
        return JsonResponse({"ok": False, "error": "Invalid path"}, status=400)

    try:
        sftp, transport = sftp_open(client)  # type: ignore[assignment]
        sftp.mkdir(target)  # type: ignore[union-attr]
        return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)
    finally:
        try:
            sftp.close()  # type: ignore[union-attr]
            transport.close()  # type: ignore[union-attr]
        except Exception:
            pass


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def files_rename(request, client_id: int):
    """Rename or move a file. POST: src, dst (both relative to base)."""
    client = get_object_or_404(Client, id=client_id)
    src = request.POST.get("src")
    dst = request.POST.get("dst")
    if not src or not dst:
        return JsonResponse({"ok": False, "error": "Missing src/dst"}, status=400)
    base = client.file_base_path or "/"
    try:
        src_abs = safe_join(base, src)
        dst_abs = safe_join(base, dst)
    except ValueError:
        return JsonResponse({"ok": False, "error": "Invalid path"}, status=400)

    try:
        sftp, transport = sftp_open(client)  # type: ignore[assignment]
        sftp.rename(src_abs, dst_abs)  # type: ignore[union-attr]
        return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)
    finally:
        try:
            sftp.close()  # type: ignore[union-attr]
            transport.close()  # type: ignore[union-attr]
        except Exception:
            pass


@require_POST
@login_required
@user_passes_test(lambda u: u.is_staff)
def files_delete(request, client_id: int):
    """Delete a file or an empty directory. POST: path (relative)."""
    client = get_object_or_404(Client, id=client_id)
    rel = request.POST.get("path")
    if not rel:
        return JsonResponse({"ok": False, "error": "Missing path"}, status=400)
    base = client.file_base_path or "/"
    try:
        target = safe_join(base, rel)
    except ValueError:
        return JsonResponse({"ok": False, "error": "Invalid path"}, status=400)

    try:
        sftp, transport = sftp_open(client)  # type: ignore[assignment]
        st = sftp.stat(target)  # type: ignore[union-attr]
        mode = int(getattr(st, "st_mode", 0) or 0)
        if stat_is_dir(mode):
            sftp.rmdir(target)  # type: ignore[union-attr]
        else:
            sftp.remove(target)  # type: ignore[union-attr]
        return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=500)
    finally:
        try:
            sftp.close()  # type: ignore[union-attr]
            transport.close()  # type: ignore[union-attr]
        except Exception:
            pass


# small helper for mode checks without importing stat globally elsewhere
def stat_is_dir(mode: int) -> bool:
    try:
        import stat as _stat
        return _stat.S_ISDIR(mode)
    except Exception:
        return False


@login_required
@user_passes_test(lambda u: u.is_staff)
def glances_health(request, client_id: int):
    """Lightweight health/metrics probe for Glances on the remote client.

    Returns JSON:
      { ok: true, reachable: bool, cpu: {...optional...} }
    We attempt a single HTTP GET to /api/3/cpu. If it fails we mark reachable False.
    """
    client = get_object_or_404(Client, id=client_id)
    host = client.ip_address
    port = client.glances_port or 61208
    import json, urllib.request
    url = f"http://{host}:{port}/api/3/cpu"
    cpu_data = None
    reachable = False
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:  # nosec
            if resp.status == 200:
                raw = resp.read().decode("utf-8", errors="ignore")
                try:
                    cpu_data = json.loads(raw)
                except Exception:
                    cpu_data = None
                reachable = True
    except Exception:
        reachable = False
    return JsonResponse({"ok": True, "reachable": reachable, "cpu": cpu_data})


@login_required
@user_passes_test(lambda u: u.is_staff)
def script_generator(request):
    """
    GET: render script_generator.html with ScriptGeneratorForm
    POST with download=1: validate form, build PowerShell, return as attachment 'custom_setup.ps1'
    """
    if request.method == "POST" and request.POST.get("download") == "1":
        form = ScriptGeneratorForm(request.POST)
        if not form.is_valid():
            return render(request, "clients/script_generator.html", {"form": form})

        ps = build_powershell_from_options(form.cleaned_data)
        if not ps or not ps.strip():
            return HttpResponseBadRequest("Failed to generate script")

        fname = f"custom_setup_{int(time.time())}.ps1"
        buf = io.BytesIO(ps.encode("utf-8-sig"))
        resp = FileResponse(buf, as_attachment=True, filename=fname, content_type="text/plain")
        resp["X-Content-Type-Options"] = "nosniff"
        return resp

    else:
        form = ScriptGeneratorForm()
        return render(request, "clients/script_generator.html", {"form": form})


def _pwsh_escape(s: str) -> str:
        # Basic safe escaping for arguments we embed in PS strings
        return (s or "").replace("`", "``").replace('"', '""')


def build_powershell_from_options(opts: dict) -> str:
        """
        opts keys (already cleaned by form):
            zerotier_id, install_* booleans, enable_glances_service, bind_address, bind_port, boot_delay, firewall_rules(list)
        Returns a single PowerShell script string.
        """
        zt = _pwsh_escape(opts.get("zerotier_id") or "")
        bind_addr = _pwsh_escape(opts.get("bind_address") or "0.0.0.0")
        bind_port = int(opts.get("bind_port") or 61208)
        boot_delay = int(opts.get("boot_delay") or 15)
        fw_rules = opts.get("firewall_rules") or []

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
    $VenvRoot = "C:\\GlancesSvc\\venv"
    $venvPy = Join-Path $VenvRoot "Scripts\\python.exe"
    if (-not (Test-Path $venvPy)) {{
        Info "Creating venv at $VenvRoot ..."
        & $pythonExe -m venv $VenvRoot
    }} else {{
        Info "Using existing venv at $VenvRoot"
    }}
    & $venvPy -m pip install --upgrade pip setuptools wheel
    & $venvPy -m pip install glances jinja2 starlette fastapi "uvicorn[standard]" psutil

    # ---------- Wrapper script (boot delay + launch) ----------
    $WrapperPath = "C:\\GlancesSvc\\run_glances.cmd"
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
    $LogDir     = "C:\\ProgramData\\Glances\\logs"
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    $nssmCandidates = @(
        (Join-Path $env:ProgramData "chocolatey\\bin\\nssm.exe"),
        (Join-Path $env:ProgramFiles "nssm\\win64\\nssm.exe"),
        (Join-Path $env:ProgramFiles "nssm\\win32\\nssm.exe")
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
    & $nssm set $SvcName AppEnvironmentExtra ("PATH=$($VenvRoot)\\Scripts;`%PATH`%") | Out-Null
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
        $ztCli = "C:\\Program Files (x86)\\ZeroTier\\One\\zerotier-cli.bat"
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

        # --- Chocolatey install section (conditional) ---
        choco_block = f"""
    # ---------- Chocolatey core installs ----------
{choco_line("openssh", "'--params','/SSHServerFeature'")}
{choco_line("zerotier-one")}
{choco_line("tightvnc")}
{choco_line("winscp")}
{choco_line("sysinternals", "'--ignore-checksums'")}
{choco_line("nssm")}
{choco_line("python")}
"""

        # --- Firewall rules (exactly as user provided) ---
        firewall_block = "  # ---------- Firewall rules ----------\n" + "".join(fw_lines) if fw_lines else "  Info 'No firewall rules provided.'\n"

        # --- Base script skeleton ---
        script = f"""
# Auto-generated by your Django app
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$ZeroTierId = "{zt}"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
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

    # ---------- Chocolatey bootstrap ----------
    $chocoExe = Join-Path $env:ProgramData 'Chocolatey\\bin\\choco.exe'
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
        $profileScript = Join-Path $env:ChocolateyInstall 'helpers\\chocolateyProfile.psm1'
        if (Test-Path $profileScript) {{
            Import-Module $profileScript -Force -ErrorAction SilentlyContinue
            if (Get-Command refreshenv -ErrorAction SilentlyContinue) {{ refreshenv | Out-Null; Info "Environment refreshed." }}
        }}
    }} catch {{ Warn "refreshenv failed: $($_)" }}

    # ---------- Python locate (for venv seed) ----------
    function FindPython(){{
        $dirs = Get-ChildItem -Path "C:\\" -Directory -Filter "Python*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending
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

    Info "Done. If anything fails, check C:\\ProgramData\\Glances\\logs and the transcript."
}} catch {{
    Write-Error "Fatal: $($_)"
}} finally {{
    Stop-Transcript
}}
"""
        return script
