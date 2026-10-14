from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("component_mapping", "0001_initial")]

    operations = [
        migrations.CreateModel(
            name="PackageScope",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("ps_update_stream", models.CharField(max_length=100, unique=True)),
                ("components", models.JSONField(default=list)),
            ],
        ),
    ]
