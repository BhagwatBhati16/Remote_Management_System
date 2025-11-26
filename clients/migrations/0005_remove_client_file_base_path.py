from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("clients", "0004_client_file_base_path_client_glances_port_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="client",
            name="file_base_path",
        ),
    ]
