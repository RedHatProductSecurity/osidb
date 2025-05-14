import re

from celery.schedules import crontab
from django.db import migrations, models

# original crontab order
CRONTAB_PARAMS_NAMES = [
    "minute",
    "hour",
    "day_of_week",
    "day_of_month",
    "month_of_year",
]


def forwards_func(apps, schema_editor):
    """
    migrate the Collector crontabs to the new format
    """
    CollectorMetadata = apps.get_model("framework", "CollectorMetadata")
    for collector_metadata in CollectorMetadata.objects.all():
        if not collector_metadata.crontab:
            continue

        print(f"Migrating crontab format of {collector_metadata.name}")

        values = re.search(
            r"<crontab: (.*) \(m/h/d/dM/MY\)>", collector_metadata.crontab
        ).group(1)
        params = {
            key: value for key, value in zip(CRONTAB_PARAMS_NAMES, values.split())
        }
        collector_metadata.crontab = crontab(**params)
        collector_metadata.save()


class Migration(migrations.Migration):
    dependencies = [
        ("framework", "0001_initial_squashed_0004_collector_required_fields_revision"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
    ]
