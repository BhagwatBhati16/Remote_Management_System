from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Client",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100)),
                ("ip_address", models.GenericIPAddressField(protocol="IPv4")),
                ("os_name", models.CharField(blank=True, default="", max_length=100)),
                ("is_online", models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name="VNCSession",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("pid", models.IntegerField()),
                ("listen_host", models.CharField(default="127.0.0.1", max_length=100)),
                ("listen_port", models.IntegerField(default=6080)),
                ("client", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="vnc_session", to="clients.client")),
                ("started_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
