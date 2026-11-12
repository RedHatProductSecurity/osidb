"""Remove the unused operational index on legacy Bugzilla ID metadata."""

from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0288_manage_acl_write_indexes"),
    ]

    operations = [
        # This index was never in migration state. The numeric bz_id index
        # supports current lookups, so rollback need not recreate this one.
        migrations.RunSQL(
            "DROP INDEX CONCURRENTLY IF EXISTS flaw_meta_bz_id_idx",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
