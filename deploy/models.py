import os
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class Software(models.Model):
    """A piece of software in the deployment library."""
    MODE_CHOICES = [
        ("choco", "Chocolatey"),
        ("local", "Local Installer"),
    ]

    name = models.CharField(max_length=200)
    version = models.CharField(max_length=50, blank=True, default="")
    description = models.TextField(blank=True, default="")
    deployment_mode = models.CharField(
        max_length=10, choices=MODE_CHOICES, default="choco",
        help_text="Chocolatey = install via choco. Local = upload installer file."
    )
    # Chocolatey mode fields
    choco_package_name = models.CharField(
        max_length=200, blank=True, default="",
        help_text="Chocolatey package id, e.g. winrar, googlechrome, 7zip"
    )
    # Local installer mode fields
    installer_file = models.FileField(upload_to="installers/", blank=True, null=True)
    silent_args = models.CharField(
        max_length=500, blank=True, default="",
        help_text="Silent install arguments, e.g. /S, /quiet /norestart, /VERYSILENT"
    )
    file_size = models.BigIntegerField(default=0, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name", "version"]

    def __str__(self):
        v = f" v{self.version}" if self.version else ""
        mode_tag = "🍫" if self.deployment_mode == "choco" else "📦"
        return f"{mode_tag} {self.name}{v}"

    def save(self, *args, **kwargs):
        if self.installer_file:
            try:
                self.file_size = self.installer_file.size
            except Exception:
                pass
        super().save(*args, **kwargs)

    @property
    def filename(self):
        if self.installer_file:
            return os.path.basename(self.installer_file.name)
        return ""


class Deployment(models.Model):
    """One deployment job — pushing software to a set of clients."""
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name="deployments")
    triggered_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    triggered_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    total_targets = models.IntegerField(default=0)
    completed_count = models.IntegerField(default=0)
    failed_count = models.IntegerField(default=0)

    class Meta:
        ordering = ["-triggered_at"]

    def __str__(self):
        return f"Deploy {self.software} → {self.total_targets} targets ({self.status})"


class DeploymentTarget(models.Model):
    """Per-machine status within a deployment."""
    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("connecting", "Connecting"),
        ("transferring", "Transferring"),
        ("installing", "Installing"),
        ("verifying", "Verifying"),
        ("success", "Success"),
        ("failed", "Failed"),
    ]

    deployment = models.ForeignKey(Deployment, on_delete=models.CASCADE, related_name="targets")
    client = models.ForeignKey("clients.Client", on_delete=models.CASCADE, related_name="deployment_targets")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="queued")
    progress_pct = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, default="")
    stdout_log = models.TextField(blank=True, default="")
    stderr_log = models.TextField(blank=True, default="")
    exit_code = models.IntegerField(null=True, blank=True)
    remote_path = models.CharField(max_length=500, blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["client__name"]

    def __str__(self):
        return f"{self.client.name}: {self.status}"
