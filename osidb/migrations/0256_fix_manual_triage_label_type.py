"""
Data migration to fix "manual-triage" labels that were erroneously
created as AliasLabel instead of WorkflowLabel.
"""

from django.db import migrations

from osidb.helpers import bypass_rls


@bypass_rls
def fix_manual_triage_labels(apps, schema_editor):
    AliasLabel = apps.get_model("osidb", "AliasLabel")

    mistyped = AliasLabel.objects.filter(name="manual-triage")
    uuids = list(mistyped.values_list("flawlabelv2_ptr_id", flat=True))

    if not uuids:
        return

    ContentType = apps.get_model("contenttypes", "ContentType")
    FlawLabelV2 = apps.get_model("osidb", "FlawLabelV2")

    workflow_ct, _ = ContentType.objects.get_or_create(
        app_label="osidb", model="workflowlabel"
    )

    # Move rows from the AliasLabel child table to the WorkflowLabel child table.
    # Both are simple pointer tables with only the FK to the base table.
    with schema_editor.connection.cursor() as cursor:
        for uid in uuids:
            cursor.execute(
                'INSERT INTO osidb_workflowlabel (flawlabelv2_ptr_id) VALUES (%s)',
                [uid],
            )
            cursor.execute(
                'DELETE FROM osidb_aliaslabel WHERE flawlabelv2_ptr_id = %s',
                [uid],
            )

    # Update polymorphic content type on the base table
    FlawLabelV2.objects.filter(uuid__in=uuids).update(polymorphic_ctype=workflow_ct)


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("osidb", "0255_delete_erratum"),
    ]

    operations = [
        migrations.RunPython(
            fix_manual_triage_labels,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
