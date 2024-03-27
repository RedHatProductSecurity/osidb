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
    ContentType = apps.get_model("contenttypes", "ContentType")
    # Convert alerts in JSON format to Alert records.
    # At this point in the migration we have both the old _alerts field and the
    # new alerts relation.
    for instance in (
        model.objects.exclude(_alerts={}).exclude(_alerts__isnull=True).iterator()
    ):
        for key, values in instance._alerts.items():
            yield Alert(
                name=key,
                description=values.get("description", ""),
                alert_type=values.get("type", "WARNING").upper(),
                resolution_steps=values.get("resolution_steps", ""),
                content_type=ContentType.objects.get_for_model(instance),
                object_id=instance.uuid,
            )


def forwards_func(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)
    Alert = apps.get_model("osidb", "Alert")

    for model_name in ALERTABLE_MODELS:
        model = apps.get_model("osidb", model_name)
        generator = generate_alertmixins(apps, model)
        while batch := list(islice(generator, BATCH_SIZE)):
            Alert.objects.bulk_create(batch, BATCH_SIZE)


class Migration(migrations.Migration):
    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("osidb", "0126_flaw_default_workflow_state"),
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
                        choices=[("WARNING", "Warning"), ("ERROR", "Error")],
                        default="WARNING",
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
                (
                    "acl_read",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.UUIDField(), default=list, size=None
                    ),
                ),
                (
                    "acl_write",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.UUIDField(), default=list, size=None
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
        # Add row level security to the alert model
        migrations.RunSQL(
            reverse_sql=migrations.RunSQL.noop,
            sql="""
ALTER TABLE osidb_alert ENABLE ROW LEVEL SECURITY;
ALTER TABLE osidb_alert FORCE ROW LEVEL SECURITY;
--following policies define fine grained read/write control on osidb_alert entity
--policy for entity insert (eg. create)
DROP policy if exists acl_policy_alert_create on osidb_alert;
create policy acl_policy_alert_create
on osidb_alert
for INSERT
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity select
DROP policy if exists acl_policy_alert_select on osidb_alert;
create policy acl_policy_alert_select
on osidb_alert
for select
USING (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
--policy for entity update
DROP policy if exists acl_policy_alert_update on osidb_alert;
create policy acl_policy_alert_update
on osidb_alert
for update
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[])
WITH CHECK (acl_read::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]
     AND   acl_write::uuid[] && string_to_array(current_setting('osidb.acl'), ',')::uuid[]);
--policy for entity delete
DROP policy if exists acl_policy_alert_delete on osidb_alert;
create policy acl_policy_alert_delete
on osidb_alert
for delete
USING (acl_write::uuid[] && string_to_array(current_setting('osidb.acl'),',')::uuid[]);
""",
        ),
    ]
