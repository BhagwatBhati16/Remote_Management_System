from django import forms
from .models import Client


WINDOWS_CHOICES = [
    ("Windows 7", "Windows 7"),
    ("Windows 8", "Windows 8"),
    ("Windows 10", "Windows 10"),
    ("Windows 11", "Windows 11"),
]


class ClientForm(forms.ModelForm):
    # Replace free-text OS with a dropdown of Windows versions
    os_name = forms.ChoiceField(choices=WINDOWS_CHOICES, required=True, label="Windows Version",
                                widget=forms.Select(attrs={"class": "form-control"}))

    class Meta:
        model = Client
        fields = ["name", "ip_address", "os_name", "ssh_port", "ssh_username", "ssh_password", "glances_port", "mac_address"]
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control", "placeholder": "PC Name"}),
            "ip_address": forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. 192.168.1.10"}),
            "ssh_port": forms.NumberInput(attrs={"class": "form-control", "placeholder": "22", "min": 1, "max": 65535}),
            "ssh_username": forms.TextInput(attrs={"class": "form-control", "placeholder": "SSH username"}),
            "ssh_password": forms.PasswordInput(attrs={"class": "form-control", "placeholder": "SSH password", "render_value": True}),
            "glances_port": forms.NumberInput(attrs={"class": "form-control", "placeholder": "61208", "min": 1}),
            "mac_address": forms.TextInput(attrs={"class": "form-control", "placeholder": "AA:BB:CC:DD:EE:FF"}),
        }


class ScriptGeneratorForm(forms.Form):
    # ZeroTier
    zerotier_id = forms.CharField(
        required=False,
        max_length=32,
        help_text="Leave blank to skip joining a network."
    )

    # Install toggles
    install_openssh     = forms.BooleanField(required=False, initial=True)
    install_zerotier    = forms.BooleanField(required=False, initial=True)
    install_tightvnc    = forms.BooleanField(required=False, initial=True)
    install_winscp      = forms.BooleanField(required=False, initial=True)
    install_sysinternals= forms.BooleanField(required=False, initial=True)
    install_nssm        = forms.BooleanField(required=False, initial=True)
    install_python      = forms.BooleanField(required=False, initial=True)

    # ── Authentication Setup ──
    # 1) Windows Account Password
    auth_windows_password = forms.CharField(
        required=False, max_length=255, label="Windows Account Password",
        widget=forms.PasswordInput(attrs={"render_value": True, "placeholder": "e.g. Lab@2026", "id": "id_auth_windows_password"}),
        help_text="Sets this as the Windows login password. Required for SSH, SFTP, and File Manager to work.",
    )
    auth_win_only_if_blank = forms.BooleanField(
        required=False, initial=True, label="Only set if account has no password",
    )
    auth_win_auto_login = forms.BooleanField(
        required=False, initial=True, label="Enable auto-login (boots to desktop, no login screen)",
    )
    # 2) VNC Password
    auth_vnc_password = forms.CharField(
        required=False, max_length=255, label="VNC Password (for Remote Desktop)",
        widget=forms.PasswordInput(attrs={"render_value": True, "placeholder": "Max 8 characters", "id": "id_auth_vnc_password"}),
        help_text="Separate from Windows password. Used when connecting via VNC/noVNC.",
    )
    auth_vnc_always_overwrite = forms.BooleanField(
        required=False, initial=True, label="Always overwrite VNC password",
    )
    # 3) SSH Password (for RMS registration)
    auth_ssh_password = forms.CharField(
        required=False, max_length=255, label="SSH Password (stored in RMS)",
        widget=forms.PasswordInput(attrs={"render_value": True, "placeholder": "Should match Windows password", "id": "id_auth_ssh_password"}),
        help_text="RMS will use this to SSH into the client. Sent during auto-registration.",
    )

    # Glances service
    enable_glances_service = forms.BooleanField(required=False, initial=True)
    bind_address = forms.CharField(required=False, initial="0.0.0.0")
    bind_port    = forms.IntegerField(required=False, initial=61208, min_value=1, max_value=65535)
    boot_delay   = forms.IntegerField(required=False, initial=15, min_value=0, max_value=300)

    # Monitoring Agent
    install_monitoring_agent = forms.BooleanField(required=False, initial=True)
    rms_server_ip = forms.CharField(required=False, max_length=200, help_text="Auto-detected. Override if using ZeroTier or a different network.")

    # Firewall
    firewall_rules_json = forms.CharField(widget=forms.HiddenInput, required=False)

    # Auto-Registration
    auto_register = forms.BooleanField(required=False, initial=True, label="Auto-register with RMS")
    reg_ssh_username = forms.CharField(required=False, max_length=100, label="SSH Username",
                                        help_text="Leave blank to auto-detect from client's logged-in user.")

    def clean_bind_address(self):
        val = (self.cleaned_data.get("bind_address") or "").strip()
        return val or "0.0.0.0"

    def clean(self):
        data = super().clean()
        # Default firewall rules if empty JSON
        import json
        try:
            rules = json.loads(data.get("firewall_rules_json") or "[]")
        except Exception:
            rules = []
        # Normalize rules
        norm = []
        for r in rules:
            name = str(r.get("name","")).strip()[:50]
            direction = "Inbound" if str(r.get("direction","Inbound")).lower().startswith("in") else "Outbound"
            protocol = "TCP" if str(r.get("protocol","TCP")).upper() != "UDP" else "UDP"
            try:
                port = int(r.get("port"))
            except Exception:
                continue
            if not name or not (1 <= port <= 65535):
                continue
            norm.append({"name":name, "direction":direction, "protocol":protocol, "port":port})
        data["firewall_rules"] = norm
        return data