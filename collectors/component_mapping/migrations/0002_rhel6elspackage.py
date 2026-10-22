from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("component_mapping", "0001_initial")]

    operations = [
        migrations.CreateModel(
            name="Rhel6ElsPackage",
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
                ("name", models.CharField(max_length=512, unique=True)),
            ],
        ),
    ]
