from django.urls import path
from . import views
from . import actions
from . import registration

app_name = "clients"

urlpatterns = [
    path("", views.overview, name="overview"),
    path("tools/script-generator/", views.script_generator, name="script_generator"),
    path("clients/<int:client_id>/", views.client_detail, name="client_detail"),
    path("clients/add/", views.add_client, name="add_client"),
    path("clients/<int:client_id>/edit/", views.edit_client, name="edit_client"),
    path("clients/<int:client_id>/start_vnc/", views.start_vnc, name="start_vnc"),
    path("clients/<int:client_id>/stop_vnc/", views.stop_vnc, name="stop_vnc"),
    path("clients/<int:client_id>/start_ssh/", views.start_ssh, name="start_ssh"),
    path("clients/<int:client_id>/stop_ssh/", views.stop_ssh, name="stop_ssh"),
    path("clients/<int:client_id>/ssh/terminal/", views.ssh_terminal_wrapper, name="ssh_terminal_wrapper"),
    path("clients/<int:client_id>/glances/health/", views.glances_health, name="glances_health"),
    # Process management
    path("clients/<int:client_id>/kill/<int:pid>/", views.kill_pid, name="kill_pid"),
    # SFTP File Manager
    path("clients/<int:client_id>/files/browse/", views.sftp_browse, name="sftp_browse"),
    path("clients/<int:client_id>/files/download/", views.sftp_download, name="sftp_download"),
    path("clients/<int:client_id>/files/upload/", views.sftp_upload, name="sftp_upload"),
    path("clients/<int:client_id>/files/delete/", views.sftp_delete, name="sftp_delete"),
    path("clients/<int:client_id>/files/mkdir/", views.sftp_mkdir, name="sftp_mkdir"),
    path("clients/<int:client_id>/files/rename/", views.sftp_rename, name="sftp_rename"),
    path("clients/<int:client_id>/files/preview/", views.sftp_preview, name="sftp_preview"),

    # ── Quick Actions: Single client ──
    path("clients/<int:pk>/action/shutdown/", actions.action_shutdown, name="action_shutdown"),
    path("clients/<int:pk>/action/restart/", actions.action_restart, name="action_restart"),
    path("clients/<int:pk>/action/logoff/", actions.action_logoff, name="action_logoff"),
    path("clients/<int:pk>/action/lock/", actions.action_lock, name="action_lock"),
    path("clients/<int:pk>/action/sleep/", actions.action_sleep, name="action_sleep"),
    path("clients/<int:pk>/action/cancel-shutdown/", actions.action_cancel_shutdown, name="action_cancel_shutdown"),
    path("clients/<int:pk>/action/wake/", actions.action_wake, name="action_wake"),
    path("clients/<int:pk>/detect-mac/", actions.detect_mac, name="detect_mac"),

    # ── Quick Actions: Bulk ──
    path("clients/action/bulk/shutdown/", actions.bulk_shutdown, name="bulk_shutdown"),
    path("clients/action/bulk/restart/", actions.bulk_restart, name="bulk_restart"),
    path("clients/action/bulk/logoff/", actions.bulk_logoff, name="bulk_logoff"),
    path("clients/action/bulk/lock/", actions.bulk_lock, name="bulk_lock"),
    path("clients/action/bulk/wake/", actions.bulk_wake, name="bulk_wake"),

    # ── Scheduled Shutdown ──
    path("clients/action/schedule-shutdown/", actions.schedule_shutdown, name="schedule_shutdown"),
    path("clients/action/cancel-scheduled-shutdown/", actions.cancel_scheduled_shutdown, name="cancel_scheduled_shutdown"),
    path("clients/action/schedule-status/", actions.schedule_status, name="schedule_status"),

    # ── Auto-Registration API ──
    path("api/clients/register/", registration.register_client, name="register_client"),
    path("clients/<int:client_id>/set-password/", registration.set_password_quick, name="set_password_quick"),
]
