"""Remove the explicit label FK index while retaining its automatic counterpart."""

from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0286_remove_reindex_artifacts"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    "DROP INDEX CONCURRENTLY IF EXISTS osidb_flawl_flaw_id_e760d6_idx",
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
                    "osidb_flawl_flaw_id_e760d6_idx ON osidb_flawlabelv2 (flaw_id)",
                ),
            ],
            state_operations=[
                migrations.RemoveIndex(
                    model_name="flawlabel", name="osidb_flawl_flaw_id_e760d6_idx"
                ),
            ],
        ),
    ]
