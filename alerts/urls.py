from django.urls import path
from . import views

app_name = "alerts"

urlpatterns = [
    # ── Public API (no auth — called by client agents) ──
    path("api/alerts/report/", views.api_report_alert, name="api_report"),
    path("api/alerts/rules/", views.api_get_rules, name="api_rules"),
    path("api/alerts/active/count/", views.api_active_count, name="api_active_count"),
    path("api/alerts/client/<int:client_id>/", views.api_client_alerts, name="api_client_alerts"),
    path("api/alerts/recent/", views.api_recent_alerts, name="api_recent_alerts"),

    # ── Staff dashboard ──
    path("alerts/", views.alert_dashboard, name="dashboard"),
    path("alerts/history/", views.alert_history, name="history"),
    path("alerts/<int:alert_id>/dismiss/", views.dismiss_alert, name="dismiss"),
    path("alerts/dismiss-all/", views.dismiss_all, name="dismiss_all"),

    # ── Delete alerts ──
    path("alerts/<int:alert_id>/delete/", views.delete_alert, name="delete_alert"),
    path("alerts/delete-selected/", views.delete_selected_alerts, name="delete_selected"),
    path("alerts/delete-all/", views.delete_all_alerts, name="delete_all"),

    # ── Rules management ──
    path("alerts/rules/manage/", views.rules_manage, name="rules_manage"),
    path("alerts/rules/add/", views.rule_add, name="rule_add"),
    path("alerts/rules/bulk-add/", views.rule_bulk_add, name="rule_bulk_add"),
    path("alerts/rules/<int:rule_id>/delete/", views.rule_delete, name="rule_delete"),
    path("alerts/rules/<int:rule_id>/toggle/", views.rule_toggle, name="rule_toggle"),

    # ── Monitoring agent deployment ──
    path("alerts/deploy-agent/", views.deploy_monitoring_agent, name="deploy_agent"),
    path("alerts/deploy-agent/status/", views.deploy_agent_status, name="deploy_agent_status"),
]
