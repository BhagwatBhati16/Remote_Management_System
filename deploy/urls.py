from django.urls import path
from . import views

app_name = "deploy"

urlpatterns = [
    path("", views.deploy_dashboard, name="dashboard"),
    path("library/", views.software_list, name="software_list"),
    path("library/add/", views.software_add, name="software_add"),
    path("library/<int:sw_id>/edit/", views.software_edit, name="software_edit"),
    path("library/<int:sw_id>/delete/", views.software_delete, name="software_delete"),
    path("start/", views.start_deployment, name="start_deployment"),
    path("status/<int:dep_id>/", views.deployment_status, name="deployment_status"),
    path("history/", views.deployment_history, name="deployment_history"),
    path("clients/status/", views.clients_online_status, name="clients_online_status"),
]
