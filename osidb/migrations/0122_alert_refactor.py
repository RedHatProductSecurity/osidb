"""
Written manually on 2024-03-26

Create new Alert model, convert alerts stored in a JSON field to Alert records,
and remove the JSON field.
"""

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
from itertools import islice
import uuid

from osidb.core import set_user_acls


BATCH_SIZE = 1000

# From a migration we cannot get the models that implement the ALertMixin programmatically so
# these need to be declared explicitly.
ALERTABLE_MODELS = [
    "Flaw",
    "Affect",
    "Snippet",
    "FlawCVSS",
    "AffectCVSS",
    "Tracker",
    "FlawMeta",
    "FlawComment",
    "FlawAcknowledgment",
    "FlawReference",
    "Package",
]


def generate_alertmixins(apps, model):
    Alert = apps.get_model("osidb", "Alert")
    # Convert alerts in JSON format to Alert records.
    # At this point in the migration we have both the old _alerts field and the
    # new alerts relation.
    for instance in (
        model.objects.exclude(_alerts={}).exclude(_alerts__isnull=True).iterator()
    ):
        for key in instance._alerts.keys():
            values = instance._alerts.get(key)
            yield Alert(
                name=key,
                description=values.get("description", ""),
                alert_type=values.get("type", "warning"),
                resolution_steps=values.get("resolution_steps", ""),
                content_object=instance,
            )


def forwards_func(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)

    for model_name in ALERTABLE_MODELS:
        model = apps.get_model("osidb", model_name)
        generator = generate_alertmixins(apps, model)
        while batch := list(islice(generator, BATCH_SIZE)):
            model.objects.bulk_create(batch, BATCH_SIZE)


class Migration(migrations.Migration):
    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("osidb", "0121_fix_workflow_state"),
    ]

    operations = [
        migrations.CreateModel(
            name="Alert",
            fields=[
                (
                    "uuid",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                ("description", models.TextField()),
                (
                    "alert_type",
                    models.CharField(
                        choices=[("warning", "Warning"), ("error", "Error")],
                        default="warning",
                        max_length=10,
                    ),
                ),
                ("resolution_steps", models.TextField(blank=True)),
                ("object_id", models.CharField(max_length=36)),
                (
                    "content_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="contenttypes.contenttype",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
        migrations.RemoveField(
            model_name="affect",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="affectcvss",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="flaw",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="flawacknowledgment",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="flawcomment",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="flawcvss",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="flawmeta",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="flawreference",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="package",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="snippet",
            name="_alerts",
        ),
        migrations.RemoveField(
            model_name="tracker",
            name="_alerts",
        ),
    ]
