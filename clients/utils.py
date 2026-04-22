import os, socket, signal, subprocess, stat
import posixpath


def get_free_port(bind_host: str = "127.0.0.1") -> int:
    """Return an ephemeral free TCP port bound to bind_host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((bind_host, 0))
        return s.getsockname()[1]


def is_windows_os_name(os_name: str) -> bool:
    return (os_name or "").lower().startswith("win")


def pid_alive(pid: int) -> bool:
    try:
        if os.name == "nt":
            proc = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
            return str(pid) in proc.stdout
        else:
            os.kill(pid, 0)
            return True
    except Exception:
        return False


def kill_pid_tree(pid: int) -> bool:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        else:
            # Kill process group first
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            return True
    except Exception:
        try:
            if os.name != "nt":
                os.kill(pid, signal.SIGKILL)
                return True
        except Exception:
            return False
    return False


# ---------------------------------------------------------------------------
# SFTP utilities (paramiko-based)
# ---------------------------------------------------------------------------

def safe_join(base: str, *parts: str) -> str:
    """Join path components and ensure the result stays under *base*.

    All paths are treated as POSIX (remote SSH targets are typically Linux).
    Raises ValueError on path-traversal attempts.
    """
    # Normalize base
    base = posixpath.normpath(base)
    # Join and normalize the requested path
    joined = posixpath.normpath(posixpath.join(base, *parts))
    # Ensure the resolved path is under or equal to the base
    if not (joined == base or joined.startswith(base + "/")):
        raise ValueError(f"Path traversal blocked: {joined!r} escapes {base!r}")
    return joined


def sftp_connect(client):
    """Open an SFTP session to *client* using its SSH credentials.

    Returns (sftp, transport). The caller MUST close both when done.
    Supports password auth and private-key auth (key takes precedence).
    """
    import paramiko

    transport = paramiko.Transport((client.ip_address, client.ssh_port or 22))

    if client.ssh_private_key_path and os.path.isfile(client.ssh_private_key_path):
        # Try loading the key (supports RSA, Ed25519, ECDSA)
        pkey = paramiko.RSAKey.from_private_key_file(client.ssh_private_key_path)
        try:
            pkey = paramiko.RSAKey.from_private_key_file(client.ssh_private_key_path)
        except Exception:
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(client.ssh_private_key_path)
            except Exception:
                try:
                    pkey = paramiko.ECDSAKey.from_private_key_file(client.ssh_private_key_path)
                except Exception:
                    pkey = paramiko.DSSKey.from_private_key_file(client.ssh_private_key_path)
        transport.connect(username=client.ssh_username, pkey=pkey)
    elif client.ssh_password:
        transport.connect(username=client.ssh_username, password=client.ssh_password)
    else:
        raise ValueError(
            f"Client {client.name} has no SSH password or private key configured. "
            "Set ssh_password or ssh_private_key_path in the admin panel."
        )

    sftp = paramiko.SFTPClient.from_transport(transport)
    return sftp, transport
