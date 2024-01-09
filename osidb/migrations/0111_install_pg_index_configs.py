from django.contrib.postgres.operations import BtreeGinExtension, TrigramExtension
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0110_snippet_miscellaneous"),
    ]

    operations = [
        BtreeGinExtension(),
        # Note: setting gin indexes on django model does not - so we set them manually
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_flaw_acl_read_gin_idx ON osidb_flaw USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_flawmeta_acl_read_gin_idx ON osidb_flawmeta USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_flawcomment_acl_read_gin_idx ON osidb_flawcomment USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_affect_acl_read_gin_idx ON osidb_affect USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_flawreference_acl_read_gin_idx ON osidb_flawreference USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_flawack_acl_read_gin_idx ON osidb_flawacknowledgment USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_flawcvss_acl_read_gin_idx ON osidb_flawcvss USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_flawmeta_acl_read_gin_idx ON osidb_flawmeta USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_package_acl_read_gin_idx ON osidb_package USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_affectcvss_acl_read_gin_idx ON osidb_affectcvss USING GIN (acl_read);"
        ),
        migrations.RunSQL(
            "CREATE INDEX IF NOT EXISTS osidb_tracker_acl_read_gin_idx ON osidb_tracker USING GIN (acl_read);"
        ),
    ]
