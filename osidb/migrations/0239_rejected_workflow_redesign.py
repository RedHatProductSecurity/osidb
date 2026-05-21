"""
Written manually on 2026-05-20.

Redesigns the REJECTED workflow to be data-driven:
1. Migrates flaws with workflow_state=REJECTED to workflow_state=DONE
   and creates a "rejected" workflow label for each
2. Removes REJECTED from workflow_state choices
"""
import uuid

from django.conf import settings
from django.db import migrations, models

from osidb.core import set_user_acls

BATCH_SIZE = 1000


def migrate_rejected_flaws(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)
    Flaw = apps.get_model("osidb", "Flaw")
    FlawCollaborator = apps.get_model("osidb", "FlawCollaborator")

    rejected_flaws = Flaw.objects.filter(workflow_state="REJECTED")

    batch = []
    for i, flaw in enumerate(rejected_flaws.iterator(chunk_size=BATCH_SIZE), 1):
        flaw.workflow_state = "DONE"
        flaw.workflow_name = "REJECTED"
        batch.append(flaw)

        FlawCollaborator.objects.get_or_create(
            flaw=flaw,
            label="rejected",
            defaults={
                "uuid": uuid.uuid4(),
                "type": "workflow",
                "state": "NEW",
                "relevant": True,
            },
        )

        if i % BATCH_SIZE == 0:
            Flaw.objects.bulk_update(batch, ["workflow_state", "workflow_name"])
            batch = []

    if batch:
        Flaw.objects.bulk_update(batch, ["workflow_state", "workflow_name"])


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0238_add_workflow_label_type"),
    ]

    operations = [
        # Data migration: convert REJECTED state to DONE + rejected label
        migrations.RunPython(
            migrate_rejected_flaws, migrations.RunPython.noop, atomic=True
        ),
        # Remove REJECTED from workflow_state choices
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
                ],
                default="",
                max_length=24,
            ),
        ),
    ]
