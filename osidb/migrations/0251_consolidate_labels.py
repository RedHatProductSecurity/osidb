"""
Consolidate labels: remove v1 models, update v2 related_name.

1. Drop RLS policies from v1 table.
2. Delete v1 models (FlawCollaborator, FlawLabel).
3. Update FlawLabelV2.flaw related_name from labels_v2 to labels.
"""

from django.db import migrations, models


DROP_V1_RLS_SQL = """
DROP policy if exists acl_policy_flawcollaborator_create on osidb_flawcollaborator;
DROP policy if exists acl_policy_flawcollaborator_select on osidb_flawcollaborator;
DROP policy if exists acl_policy_flawcollaborator_update on osidb_flawcollaborator;
DROP policy if exists acl_policy_flawcollaborator_delete on osidb_flawcollaborator;
ALTER TABLE osidb_flawcollaborator DISABLE ROW LEVEL SECURITY;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("osidb", "0250_add_workflow_field_indexes"),
    ]

    operations = [
        # 1. Drop RLS policies on v1 table before deleting it
        migrations.RunSQL(
            sql=DROP_V1_RLS_SQL,
            reverse_sql=migrations.RunSQL.noop,
        ),
        # 2. Delete v1 models
        migrations.DeleteModel(name="FlawCollaborator"),
        migrations.DeleteModel(name="FlawLabel"),
        # 3. Update FK related_name from labels_v2 to labels
        migrations.AlterField(
            model_name="flawlabelv2",
            name="flaw",
            field=models.ForeignKey(
                on_delete=models.deletion.CASCADE,
                related_name="labels",
                to="osidb.flaw",
            ),
        ),
    ]
