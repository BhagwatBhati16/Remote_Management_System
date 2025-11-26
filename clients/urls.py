from django.urls import path
from . import views

app_name = "clients"

urlpatterns = [
    path("", views.overview, name="overview"),
    path("tools/script-generator/", views.script_generator, name="script_generator"),
    path("clients/<int:client_id>/", views.client_detail, name="client_detail"),
    path("clients/add/", views.add_client, name="add_client"),
    path("clients/<int:client_id>/start_vnc/", views.start_vnc, name="start_vnc"),
    path("clients/<int:client_id>/stop_vnc/", views.stop_vnc, name="stop_vnc"),
    path("clients/<int:client_id>/start_ssh/", views.start_ssh, name="start_ssh"),
    path("clients/<int:client_id>/stop_ssh/", views.stop_ssh, name="stop_ssh"),
    path("clients/<int:client_id>/glances/health/", views.glances_health, name="glances_health"),
    # Process management
    path("clients/<int:client_id>/kill/<int:pid>/", views.kill_pid, name="kill_pid"),
]
