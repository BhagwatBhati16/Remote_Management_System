# Remote Management System (RMS)

A web-based lab infrastructure management tool built with **Django** that allows administrators to **remotely manage, monitor, and provision** Windows PCs from a single browser dashboard.

## Features

- **Dashboard** — Real-time overview of all client PCs (online/offline, hardware stats, OS info)
- **Remote Desktop (VNC)** — View and control any PC's screen via noVNC in the browser
- **Remote Terminal (SSH)** — Browser-based PowerShell terminal via WebSSH
- **File Manager (SFTP)** — Upload, download, rename, delete files on any PC remotely
- **Software Deployment** — Push software to one or multiple PCs simultaneously via Chocolatey or local installers
- **Alert Monitoring** — Detect when students run specific applications or visit flagged websites, with real-time alerts
- **Auto-Provisioning** — Generate PowerShell scripts to configure fresh PCs with all required software, passwords, firewall rules, and auto-register with RMS

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, Django 6.0 |
| Database | SQLite |
| Remote Desktop | TightVNC + noVNC + Websockify |
| Remote Terminal | OpenSSH + WebSSH |
| File Transfer | Paramiko (SFTP over SSH) |
| Monitoring | Glances REST API + PowerShell agent |
| Provisioning | PowerShell + Chocolatey |
| Networking | ZeroTier (optional VPN) |

## Project Structure

```
├── clients/          # Core app: client management, SFTP, VNC, SSH, script generator
├── alerts/           # Alert monitoring system (process/window title detection)
├── deploy/           # Software deployment engine
├── templates/        # HTML templates for all pages
├── scripts/          # Client-side scripts (monitor agent, launcher)
├── static/           # Static assets (alert sounds)
├── vnc_management/   # Django project settings and URL routing
├── manage.py         # Django management script
└── requirements.txt  # Python dependencies
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser

# Start the server
python manage.py runserver 0.0.0.0:8000
```

Then open `http://localhost:8000` in your browser.

## Client Setup

1. Open the **Script Generator** from the dashboard
2. Configure passwords, software, and network settings
3. Download the generated PowerShell script
4. Run the script on each client PC as Administrator
5. The PC will auto-register and appear on the dashboard

## Requirements

- Python 3.10+
- Django 6.0+
- Paramiko (SSH/SFTP)
- Client PCs: Windows 10/11 with OpenSSH Server

## Author

**Bhagwat Singh Bhati**

## License

This project is for educational purposes.
