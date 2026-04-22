from django.contrib import admin
from .models import Software, Deployment, DeploymentTarget


class DeploymentTargetInline(admin.TabularInline):
    model = DeploymentTarget
    extra = 0
    readonly_fields = ("client", "status", "progress_pct", "error_message", "started_at", "finished_at")


@admin.register(Software)
class SoftwareAdmin(admin.ModelAdmin):
    list_display = ("name", "version", "filename", "file_size", "silent_args", "created_at")
    search_fields = ("name", "version")


@admin.register(Deployment)
class DeploymentAdmin(admin.ModelAdmin):
    list_display = ("software", "triggered_by", "triggered_at", "status", "total_targets", "completed_count", "failed_count")
    list_filter = ("status",)
    inlines = [DeploymentTargetInline]


@admin.register(DeploymentTarget)
class DeploymentTargetAdmin(admin.ModelAdmin):
    list_display = ("deployment", "client", "status", "progress_pct", "started_at", "finished_at")
    list_filter = ("status",)
