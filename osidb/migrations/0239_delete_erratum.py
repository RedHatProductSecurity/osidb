from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0238_exclude_last_validated_dt_from_history"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Erratum",
        ),
    ]
