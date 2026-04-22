import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    """Rename GameAlert model to Alert, preserving all data."""

    dependencies = [
        ("clients", "0001_initial"),
        ("alerts", "0002_seed_default_rules"),
    ]

    operations = [
        # Remove old index first
        migrations.RemoveIndex(
            model_name="gamealert",
            name="alerts_game_client__188277_idx",
        ),
        # Rename the model
        migrations.RenameModel(
            old_name="GameAlert",
            new_name="Alert",
        ),
        # Update the related_name
        migrations.AlterField(
            model_name="alert",
            name="client",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="alerts",
                to="clients.client",
            ),
        ),
        # Recreate index with new naming
        migrations.AddIndex(
            model_name="alert",
            index=models.Index(
                fields=["client_ip", "detected_name", "received_at"],
                name="alerts_aler_client__e3f891_idx",
            ),
        ),
    ]
