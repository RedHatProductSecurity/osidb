"""
Written manually on 2024-06-14.
"""
from django.conf import settings
from django.db import migrations, models

from osidb.core import set_user_acls

BATCH_SIZE = 1000


def forwards_func(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)
    Flaw = apps.get_model("osidb", "Flaw")

    flaws = Flaw.objects.all().iterator(chunk_size=BATCH_SIZE)

    batch = []
    for i, flaw in enumerate(flaws, 1):
        if flaw.workflow_state == "NEW" and not flaw.task_key:
            flaw.workflow_state = ""
        batch.append(flaw)

        if i % BATCH_SIZE == 0:
            Flaw.objects.bulk_update(batch, ["workflow_state"])
            batch = []

    if batch:
        Flaw.objects.bulk_update(batch, ["workflow_state"])


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0147_flaw_major_incident_start_dt"),
    ]

    operations = [
        migrations.AlterField(
            model_name="flaw",
            name="workflow_state",
            field=models.CharField(
                blank=True,
                choices=[
                    ("", "Novalue"),
                    ("NEW", "New"),
                    ("TRIAGE", "Triage"),
                    ("PRE_SECONDARY_ASSESSMENT", "Pre Secondary Assessment"),
                    ("SECONDARY_ASSESSMENT", "Secondary Assessment"),
                    ("DONE", "Done"),
                    ("REJECTED", "Rejected"),
                ],
                default="",
                max_length=24,
            ),
        ),
        migrations.AlterField(
            model_name="flawaudit",
            name="workflow_state",
            field=models.CharField(
                blank=True,
                choices=[
                    ("", "Novalue"),
                    ("NEW", "New"),
                    ("TRIAGE", "Triage"),
                    ("PRE_SECONDARY_ASSESSMENT", "Pre Secondary Assessment"),
                    ("SECONDARY_ASSESSMENT", "Secondary Assessment"),
                    ("DONE", "Done"),
                    ("REJECTED", "Rejected"),
                ],
                default="",
                max_length=24,
            ),
        ),
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
    ]
