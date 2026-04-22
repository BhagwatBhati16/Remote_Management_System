"""
Deployment engine — handles parallel software deployment to multiple clients.

Two modes:
  1. Chocolatey: SSH into client, run `choco install <pkg> -y`, verify with `choco list`
  2. Local Installer: SFTP the file, run via Start-Process with -Wait -PassThru, verify via registry

Uses ThreadPoolExecutor so each client runs in its own thread.
One client's failure cannot affect another.
"""

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from django.utils import timezone

logger = logging.getLogger(__name__)

# Global executor — max 10 parallel deployments at once
_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="deploy")
_lock = threading.Lock()

# 10 minute timeout for install commands
INSTALL_TIMEOUT_SECONDS = 600


def start_deployment(deployment_id: int):
    """Kick off deployment in background threads. Called from the view after
    creating the Deployment + DeploymentTarget rows.

    This function itself is fast — it just sets status='running' and submits
    worker tasks to the ThreadPoolExecutor. The actual install work happens
    in the worker threads.
    """
    from .models import Deployment, DeploymentTarget

    logger.info(">>> start_deployment(id=%d) CALLED", deployment_id)

    try:
        deployment = Deployment.objects.get(id=deployment_id)
    except Deployment.DoesNotExist:
        logger.error("Deployment %d does not exist!", deployment_id)
        return

    deployment.status = "running"
    deployment.save(update_fields=["status"])
    logger.info(">>> Deployment %d status set to 'running'", deployment_id)

    targets = list(
        DeploymentTarget.objects.filter(deployment=deployment).select_related("client")
    )
    logger.info(">>> Deployment %d has %d targets", deployment_id, len(targets))

    if not targets:
        deployment.status = "completed"
        deployment.save(update_fields=["status"])
        logger.warning(">>> Deployment %d has 0 targets — marking completed", deployment_id)
        return

    for target in targets:
        logger.info(">>> Submitting target %d (%s) to executor", target.id, target.client.name)
        _executor.submit(
            _safe_deploy_single_target, deployment.id, target.id, deployment.software_id
        )


def _safe_deploy_single_target(deployment_id, target_id, software_id):
    """Wrapper that catches absolutely everything, so one target can never
    crash the thread pool or affect other targets."""
    try:
        _deploy_single_target(deployment_id, target_id, software_id)
    except Exception as e:
        logger.exception("[Deploy %d] UNCAUGHT exception for target %d: %s",
                         deployment_id, target_id, e)
        try:
            _update_target(target_id, status="failed",
                           error_message=f"Uncaught engine error: {e}")
            _finalize_deployment(deployment_id, success=False)
        except Exception:
            logger.exception("[Deploy %d] Failed to finalize after crash", deployment_id)


def _get_ssh_client(client):
    """Create and return a connected paramiko SSHClient for the given client."""
    import paramiko

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kwargs = {
        "hostname": client.ip_address,
        "port": client.ssh_port or 22,
        "username": client.ssh_username,
        "timeout": 15,
    }
    if client.ssh_password:
        kwargs["password"] = client.ssh_password
    elif client.ssh_private_key_path and os.path.isfile(client.ssh_private_key_path):
        kwargs["key_filename"] = client.ssh_private_key_path

    ssh.connect(**kwargs)
    return ssh


def _run_ssh_command(ssh, command, timeout=INSTALL_TIMEOUT_SECONDS):
    """Run a command over SSH and block until it completes OR timeout expires.
    Returns (exit_code, stdout_text, stderr_text).

    Uses a polling loop on exit_status_ready() instead of blocking
    recv_exit_status(), because recv_exit_status() ignores the channel
    timeout and blocks forever if the remote process spawns a child
    that stays alive (e.g. Discord opening after install).
    """
    import time

    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
    channel = stdout.channel

    # Poll for completion instead of blocking forever
    start = time.time()
    while not channel.exit_status_ready():
        elapsed = time.time() - start
        if elapsed > timeout:
            # Force-close the channel — the installer ran too long
            logger.warning("SSH command timed out after %ds: %s", timeout, command[:100])
            try:
                channel.close()
            except Exception:
                pass
            raise TimeoutError(f"Command timed out after {timeout}s")
        time.sleep(1)  # Check every second

    exit_code = channel.recv_exit_status()
    stdout_text = stdout.read().decode(errors="ignore").strip()
    stderr_text = stderr.read().decode(errors="ignore").strip()
    return exit_code, stdout_text, stderr_text


def _update_target(target_id, **fields):
    """Atomically update a DeploymentTarget's fields."""
    from .models import DeploymentTarget

    if "status" in fields:
        status = fields["status"]
        if status in ("connecting",):
            fields.setdefault("started_at", timezone.now())
        if status in ("success", "failed"):
            fields["finished_at"] = timezone.now()
    DeploymentTarget.objects.filter(id=target_id).update(**fields)


def _deploy_single_target(deployment_id: int, target_id: int, software_id: int):
    """Deploy to a single client. Runs in a worker thread."""
    from .models import Software, DeploymentTarget

    target = DeploymentTarget.objects.select_related("client").get(id=target_id)
    software = Software.objects.get(id=software_id)
    client = target.client

    logger.info("[Deploy %d] Starting target %s (%s) — mode=%s",
                deployment_id, client.name, client.ip_address, software.deployment_mode)

    if software.deployment_mode == "choco":
        _deploy_choco(deployment_id, target_id, software, client)
    else:
        _deploy_local(deployment_id, target_id, software, client)


# ---------------------------------------------------------------------------
# Mode 1: Chocolatey
# ---------------------------------------------------------------------------

def _deploy_choco(deployment_id, target_id, software, client):
    """Deploy via Chocolatey: SSH → choco install → verify."""
    pkg = software.choco_package_name.strip()
    if not pkg:
        _update_target(target_id, status="failed", error_message="No Chocolatey package name configured")
        _finalize_deployment(deployment_id, success=False)
        return

    ssh = None
    try:
        # ---- Connect ----
        _update_target(target_id, status="connecting", progress_pct=0)
        logger.info("[Deploy %d] Choco: connecting to %s (%s)...",
                     deployment_id, client.name, client.ip_address)

        try:
            ssh = _get_ssh_client(client)
        except Exception as e:
            _update_target(target_id, status="failed", progress_pct=0,
                           error_message=f"SSH connection failed: {e}")
            _finalize_deployment(deployment_id, success=False)
            return

        # ---- Install via Chocolatey ----
        _update_target(target_id, status="installing", progress_pct=10)

        install_cmd = f"choco install {pkg} -y --no-progress"
        logger.info("[Deploy %d] SSH exec: %s", deployment_id, install_cmd)

        try:
            exit_code, stdout_text, stderr_text = _run_ssh_command(
                ssh, install_cmd, timeout=INSTALL_TIMEOUT_SECONDS
            )
        except Exception as e:
            _update_target(
                target_id, status="failed", progress_pct=10,
                error_message=f"Install command timed out or SSH error: {e}",
            )
            _finalize_deployment(deployment_id, success=False)
            return

        _update_target(
            target_id,
            exit_code=exit_code,
            stdout_log=stdout_text[:5000],
            stderr_log=stderr_text[:5000],
            progress_pct=80,
        )

        if exit_code != 0:
            err = f"choco install exited with code {exit_code}"
            if stderr_text:
                err += f"\nstderr: {stderr_text[:500]}"
            if stdout_text:
                err += f"\nstdout (tail): {stdout_text[-500:]}"
            _update_target(target_id, status="failed", error_message=err)
            logger.warning("[Deploy %d] FAIL %s: %s", deployment_id, client.name, err)
            _finalize_deployment(deployment_id, success=False)
            return

        # ---- Verify ----
        _update_target(target_id, status="verifying", progress_pct=90)
        verify_cmd = f"choco list --local-only {pkg}"
        try:
            v_exit, v_stdout, v_stderr = _run_ssh_command(ssh, verify_cmd, timeout=30)
        except Exception:
            v_stdout = ""

        # Mark success — choco exit code 0 is our primary signal
        _update_target(
            target_id, status="success", progress_pct=100,
            stdout_log=stdout_text[:5000],
        )
        logger.info("[Deploy %d] OK %s: choco install %s succeeded.",
                     deployment_id, client.name, pkg)
        _finalize_deployment(deployment_id, success=True)

    except Exception as e:
        _update_target(target_id, status="failed", error_message=f"Unexpected error: {e}")
        logger.exception("[Deploy %d] Unexpected error for %s", deployment_id, client.name)
        _finalize_deployment(deployment_id, success=False)
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Mode 2: Local Installer
# ---------------------------------------------------------------------------

def _deploy_local(deployment_id, target_id, software, client):
    """Deploy via local installer: SFTP transfer → SSH Start-Process → verify."""
    from clients.utils import sftp_connect

    local_path = software.installer_file.path if software.installer_file else None
    if not local_path or not os.path.isfile(local_path):
        _update_target(target_id, status="failed",
                       error_message="Installer file not found on server")
        _finalize_deployment(deployment_id, success=False)
        return

    filename = os.path.basename(local_path)
    remote_dir = "C:\\RMS_Deploy"
    remote_path = f"{remote_dir}\\{filename}"
    is_msi = filename.lower().endswith(".msi")

    sftp = None
    transport = None
    ssh = None

    try:
        # ---- Connect via SFTP ----
        _update_target(target_id, status="connecting", progress_pct=0)
        logger.info("[Deploy %d] Local: connecting to %s (%s)...",
                     deployment_id, client.name, client.ip_address)

        try:
            sftp, transport = sftp_connect(client)
        except Exception as e:
            _update_target(target_id, status="failed", progress_pct=0,
                           error_message=f"SFTP connection failed: {e}")
            _finalize_deployment(deployment_id, success=False)
            return

        # ---- Ensure remote directory ----
        try:
            sftp.stat(remote_dir)
        except Exception:
            try:
                sftp.mkdir(remote_dir)
            except Exception:
                pass

        # ---- Transfer file ----
        _update_target(target_id, status="transferring", progress_pct=0,
                       remote_path=remote_path)
        logger.info("[Deploy %d] Transferring %s -> %s:%s",
                     deployment_id, filename, client.name, remote_path)

        def _progress_cb(transferred, total):
            if total > 0:
                pct = min(int(transferred * 100 / total), 99)
                _update_target(target_id, progress_pct=pct)

        try:
            sftp.put(local_path, remote_path, callback=_progress_cb)
            _update_target(target_id, progress_pct=100)
        except Exception as e:
            _update_target(target_id, status="failed", progress_pct=0,
                           error_message=f"File transfer failed: {e}")
            _finalize_deployment(deployment_id, success=False)
            return
        finally:
            try:
                sftp.close()
            except Exception:
                pass
            try:
                transport.close()
            except Exception:
                pass

        # ---- Execute installer via SSH ----
        _update_target(target_id, status="installing", progress_pct=100)
        logger.info("[Deploy %d] Executing installer on %s", deployment_id, client.name)

        try:
            ssh = _get_ssh_client(client)
        except Exception as e:
            _update_target(target_id, status="failed",
                           error_message=f"SSH connection for install failed: {e}")
            _finalize_deployment(deployment_id, success=False)
            return

        # Build the PowerShell command for Start-Process with -Wait -PassThru
        silent_args = software.silent_args.strip()

        if is_msi:
            # MSI files: use msiexec.exe as the process
            msi_args = (f'/i \\"{remote_path}\\" {silent_args}'
                        if silent_args
                        else f'/i \\"{remote_path}\\" /quiet /norestart')
            ps_cmd = (
                f'powershell -NoProfile -Command "'
                f"$p = Start-Process -FilePath 'msiexec.exe' "
                f"-ArgumentList '{msi_args}' "
                f"-Wait -PassThru -WindowStyle Hidden; "
                f'exit $p.ExitCode"'
            )
        else:
            # EXE files: run directly with Start-Process
            if silent_args:
                ps_cmd = (
                    f'powershell -NoProfile -Command "'
                    f"$p = Start-Process -FilePath '{remote_path}' "
                    f"-ArgumentList '{silent_args}' "
                    f"-Wait -PassThru -WindowStyle Hidden; "
                    f'exit $p.ExitCode"'
                )
            else:
                ps_cmd = (
                    f'powershell -NoProfile -Command "'
                    f"$p = Start-Process -FilePath '{remote_path}' "
                    f"-Wait -PassThru -WindowStyle Hidden; "
                    f'exit $p.ExitCode"'
                )

        logger.info("[Deploy %d] SSH exec: %s", deployment_id, ps_cmd)

        try:
            exit_code, stdout_text, stderr_text = _run_ssh_command(
                ssh, ps_cmd, timeout=INSTALL_TIMEOUT_SECONDS
            )
        except Exception as e:
            _update_target(
                target_id, status="failed",
                error_message=f"Installer execution timed out or failed: {e}",
            )
            _finalize_deployment(deployment_id, success=False)
            return

        _update_target(
            target_id,
            exit_code=exit_code,
            stdout_log=stdout_text[:5000],
            stderr_log=stderr_text[:5000],
        )

        if exit_code != 0:
            err = f"Installer exited with code {exit_code}"
            if stderr_text:
                err += f"\nstderr: {stderr_text[:500]}"
            if stdout_text:
                err += f"\nstdout: {stdout_text[:500]}"
            _update_target(target_id, status="failed", error_message=err)
            logger.warning("[Deploy %d] FAIL %s: %s", deployment_id, client.name, err)
            _finalize_deployment(deployment_id, success=False)
            _cleanup_remote(ssh, remote_path)
            return

        # ---- Verify via registry ----
        _update_target(target_id, status="verifying", progress_pct=100)
        verify_cmd = (
            f'powershell -NoProfile -Command "'
            f"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            f"| Where-Object {{ $_.DisplayName -like '*{software.name}*' }} "
            f'| Select-Object -First 1 -ExpandProperty DisplayName"'
        )
        try:
            v_exit, v_stdout, v_stderr = _run_ssh_command(ssh, verify_cmd, timeout=30)
        except Exception:
            v_stdout = ""

        # Mark as success — installer exit code 0 is our primary signal
        _update_target(target_id, status="success", progress_pct=100)
        logger.info("[Deploy %d] OK %s: installer completed (exit 0). Registry: %s",
                     deployment_id, client.name, v_stdout[:100] if v_stdout else "none")
        _finalize_deployment(deployment_id, success=True)

        # Cleanup remote file (best-effort)
        _cleanup_remote(ssh, remote_path)

    except Exception as e:
        _update_target(target_id, status="failed",
                       error_message=f"Unexpected error: {e}")
        logger.exception("[Deploy %d] Unexpected error for %s", deployment_id, client.name)
        _finalize_deployment(deployment_id, success=False)
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


def _cleanup_remote(ssh, remote_path):
    """Best-effort delete of the remote installer file."""
    try:
        _run_ssh_command(ssh, f'del /f /q "{remote_path}"', timeout=10)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Finalization
# ---------------------------------------------------------------------------

def _finalize_deployment(deployment_id: int, success: bool):
    """Atomically update deployment counters. When all targets done, set final status."""
    from .models import Deployment
    from django.db.models import F

    with _lock:
        if success:
            Deployment.objects.filter(id=deployment_id).update(
                completed_count=F("completed_count") + 1
            )
        else:
            Deployment.objects.filter(id=deployment_id).update(
                failed_count=F("failed_count") + 1
            )

        deployment = Deployment.objects.get(id=deployment_id)
        done = deployment.completed_count + deployment.failed_count
        logger.info("[Deploy %d] Finalize: done=%d/%d (completed=%d, failed=%d)",
                     deployment_id, done, deployment.total_targets,
                     deployment.completed_count, deployment.failed_count)
        if done >= deployment.total_targets:
            if deployment.failed_count == 0:
                deployment.status = "completed"
            else:
                deployment.status = "failed"
            deployment.save(update_fields=["status"])
            logger.info("[Deploy %d] FINAL STATUS: %s", deployment_id, deployment.status)
