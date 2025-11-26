import os, socket, signal, subprocess, stat


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
