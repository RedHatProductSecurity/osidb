"""Remove known production-only reindex artifacts without restoring them on rollback."""

from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0285_components_case_insensitive_collation"),
    ]

    operations = [
        # These objects were never in migration state. Reversal deliberately
        # does not resurrect duplicate indexes.
        migrations.RunSQL(
            "DROP INDEX CONCURRENTLY IF EXISTS osidb_tracker_pkey_ccnew",
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            "DROP INDEX CONCURRENTLY IF EXISTS "
            "osidb_flawreference_flaw_id_8d78bb7f_ccold",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
