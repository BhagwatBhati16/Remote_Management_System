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
        fields = ["name", "ip_address", "os_name", "glances_port"]
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control", "placeholder": "PC Name"}),
            "ip_address": forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. 192.168.1.10"}),
            "glances_port": forms.NumberInput(attrs={"class": "form-control", "placeholder": "61208", "min": 1}),
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

    # Glances service
    enable_glances_service = forms.BooleanField(required=False, initial=True)
    bind_address = forms.CharField(required=False, initial="0.0.0.0")
    bind_port    = forms.IntegerField(required=False, initial=61208, min_value=1, max_value=65535)
    boot_delay   = forms.IntegerField(required=False, initial=15, min_value=0, max_value=300)

    # Firewall
    firewall_rules_json = forms.CharField(widget=forms.HiddenInput, required=False)

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