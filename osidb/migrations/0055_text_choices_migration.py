from django.db import migrations, transaction
from django.db.models import Q

from osidb.core import generate_acls


ACLS = ",".join(
    generate_acls(
        [
            "osidb-prod-public-read",
            "osidb-prod-embargo-read",
            "osidb-prod-public-write",
            "osidb-prod-embargo-write",
            "osidb-stage-public-read",
            "osidb-stage-embargo-read",
            "osidb-stage-public-write",
            "osidb-stage-embargo-write",
        ]
    )
)


class Migration(migrations.Migration):

    atomic = False

    dependencies = [
        ("osidb", "0054_unify_created_updated_dt"),
    ]

    operations = [
        migrations.RunSQL(f"SET osidb.acl='{ACLS}';", migrations.RunSQL.noop),
        migrations.RunSQL(
            """
            UPDATE osidb_flaw SET resolution = '' WHERE resolution = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_flaw SET impact = '' WHERE impact = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_flaw SET source = '' WHERE source = 'NOVALUE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_flawevent SET resolution = '' WHERE resolution = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_flawevent SET impact = '' WHERE impact = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_flawevent SET source = '' WHERE source = 'NOVALUE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_flawhistory SET resolution = '' WHERE resolution = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_flawhistory SET impact = '' WHERE impact = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_flawhistory SET source = '' WHERE source = 'NOVALUE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_affect SET affectedness = '' WHERE affectedness = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_affect SET resolution = '' WHERE resolution = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_affect SET impact = '' WHERE impact = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_affectevent SET affectedness = '' WHERE affectedness = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_affectevent SET resolution = '' WHERE resolution = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            """
            UPDATE osidb_affectevent SET impact = '' WHERE impact = 'NONE';
            """,
            migrations.RunSQL.noop,
        ),
    ]
