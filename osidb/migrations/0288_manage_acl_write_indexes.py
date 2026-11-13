"""Adopt existing operational ACL-write indexes or build them concurrently."""

from django.contrib.postgres.indexes import GinIndex
from django.db import migrations
from psycopg import sql

INDEXES = (
    ("flawacknowledgment", "idx_test7w", "osidb_flawack_acl_write_gin"),
    ("flawcvss", "idx_test8w", "osidb_flawcvss_acl_write_gin"),
    ("flawreference", "idx_test6w", "osidb_flawref_acl_write_gin"),
    ("package", "idx_test10w", "osidb_package_acl_write_gin"),
    ("tracker", "idx_test12w", "osidb_tracker_acl_write_gin"),
)


def table_identity(apps, schema_editor, model_name):
    """Resolve the historical model's table through the deployment search path."""
    table_name = apps.get_model("osidb", model_name)._meta.db_table
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.oid, n.nspname, c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.oid = to_regclass(%s)
            """,
            [table_name],
        )
        row = cursor.fetchone()
    if row is None:
        raise RuntimeError(f"Cannot resolve ACL-write index table {table_name}")
    return row


def index_state(schema_editor, table_oid, schema, name):
    """Reject name collisions; return whether an existing matching index is usable."""
    qualified_name = sql.Identifier(schema, name).as_string(
        schema_editor.connection.connection
    )
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                i.indrelid = %s
                AND am.amname = 'gin'
                AND NOT i.indisunique AND NOT i.indisexclusion
                AND i.indnatts = 1 AND i.indnkeyatts = 1
                AND i.indkey::text = a.attnum::text
                AND i.indpred IS NULL AND i.indexprs IS NULL
                AND opc.opcname = 'array_ops'
                AND opn.nspname = 'pg_catalog' AS matches,
                i.indisvalid AND i.indisready AND i.indislive AS usable
            FROM pg_class c
            LEFT JOIN pg_index i ON i.indexrelid = c.oid
            LEFT JOIN pg_am am ON am.oid = c.relam
            LEFT JOIN pg_attribute a
              ON a.attrelid = i.indrelid AND a.attname = 'acl_write'
            LEFT JOIN pg_opclass opc ON opc.oid = i.indclass[0]
            LEFT JOIN pg_namespace opn ON opn.oid = opc.opcnamespace
            WHERE c.oid = to_regclass(%s)
            """,
            [table_oid, qualified_name],
        )
        row = cursor.fetchone()
    if row is None:
        return None
    if not row[0]:
        raise RuntimeError(
            f"{qualified_name} is not the expected GIN index on acl_write"
        )
    return row[1]


def execute_ddl(schema_editor, statement):
    """Render driver-composed identifiers before Django processes the DDL."""
    schema_editor.execute(statement.as_string(schema_editor.connection.connection))


def adopt_indexes(apps, schema_editor):
    """Reuse valid legacy indexes and recover interrupted concurrent index builds."""
    for model_name, legacy_name, name in INDEXES:
        table_oid, schema, table = table_identity(apps, schema_editor, model_name)
        legacy = index_state(schema_editor, table_oid, schema, legacy_name)
        current = index_state(schema_editor, table_oid, schema, name)
        qualified_name = sql.Identifier(schema, name)
        qualified_legacy = sql.Identifier(schema, legacy_name)

        # A failed CREATE INDEX CONCURRENTLY may leave an invalid index behind.
        if current is False:
            execute_ddl(
                schema_editor,
                sql.SQL("DROP INDEX CONCURRENTLY {}").format(qualified_name),
            )
            current = None

        if current is None:
            if legacy:
                execute_ddl(
                    schema_editor,
                    sql.SQL("ALTER INDEX {} RENAME TO {}").format(
                        qualified_legacy, sql.Identifier(name)
                    ),
                )
                continue
            execute_ddl(
                schema_editor,
                sql.SQL(
                    "CREATE INDEX CONCURRENTLY {} ON {} USING gin (acl_write)"
                ).format(sql.Identifier(name), sql.Identifier(schema, table)),
            )

        # Includes the both-names-present case and invalid legacy leftovers.
        if legacy is not None:
            execute_ddl(
                schema_editor,
                sql.SQL("DROP INDEX CONCURRENTLY {}").format(qualified_legacy),
            )


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0287_remove_redundant_indexes"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            # Some indexes predate this migration. Preserve all physical indexes
            # on rollback, including newly created ones, rather than risk
            # dropping an adopted operational index. Only Django's state is
            # reversed; reapplying reuses the existing managed indexes.
            database_operations=[
                migrations.RunPython(adopt_indexes, migrations.RunPython.noop),
            ],
            state_operations=[
                migrations.AddIndex(
                    model_name=model_name,
                    index=GinIndex(fields=["acl_write"], name=name),
                )
                for model_name, _legacy_name, name in INDEXES
            ],
        ),
    ]
