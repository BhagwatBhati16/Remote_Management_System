# VNC Management (Django)

Minimal cleaned repository for deployment/upload.

## Quickstart (Windows PowerShell)

```powershell
# 1) Create & activate venv (optional but recommended)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2) Install deps
pip install -r requirements.txt

# 3) Migrate DB and create admin (creates new db.sqlite3)
python manage.py migrate
python manage.py createsuperuser

# 4) Run server
python manage.py runserver
```

Open http://127.0.0.1:8000/ for the panel.
Open http://127.0.0.1:8000/admin/ to add Clients.

## Repository Layout (minimal)
```
manage.py
requirements.txt
vnc_management/        # Project settings
clients/               # App (models, views, migrations, utils)
templates/clients/     # add_client.html, main_page.html, client_page.html, script_generator.html
static/                # (add static assets as needed)
```

Generated/ephemeral artifacts removed: helper PowerShell scripts, alternate HTML prototypes, logs and scratch files.

## VNC Usage
1. Overview page lists clients.
2. Click "Start VNC" on a client page. Backend runs:
   `novnc --target <client_ip>:5900 --listen 127.0.0.1:6080`
3. Page shows iframe to http://127.0.0.1:6080.
4. "Stop VNC" terminates process and clears session.

## SSH Usage (Web Terminal)
Requires `webssh` (installed via `pip install -r requirements.txt`). From client page click "SSH"; backend launches `python -m webssh` bound locally, then iframe passes hostname automatically. Use credentials/key in UI. "Stop SSH" terminates the process.

## Notes
* Ensure `novnc` CLI is on PATH (install separately, e.g. `npm i -g novnc` or system package).
* Ensure `webssh` Python package is installed.
* Start/stop endpoints require authenticated staff/admin.
* Sessions tracked via `VNCSession` and `SSHSession`; stale PIDs are cleaned on page load.
* Regenerate `db.sqlite3` any time via migrations.

## Optional Script Generator
Access under `tools/script-generator/` to download a customizable PowerShell setup script for Windows hosts.
