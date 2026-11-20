"""Seed exact legacy timestamps after statement writers are installed.

Retry-safe, bounded keyset batches. Concurrent writes already append events;
there is no parent UPDATE, row lock, historical repair, or head overwrite.
"""

from django.db import migrations, transaction

BATCH_SIZE = 2000


def backfill_events(apps, schema_editor):
    connection = schema_editor.connection
    last_uuid = None
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user"
        )
        if not cursor.fetchone()[0]:
            raise RuntimeError(
                "Change-log backfill requires a BYPASSRLS migration owner"
            )
    while True:
        with transaction.atomic(using=connection.alias), connection.cursor() as cursor:
            cursor.execute(
                "SELECT uuid FROM osidb_flaw "
                "WHERE (%s::uuid IS NULL OR uuid > %s::uuid) ORDER BY uuid LIMIT %s",
                [last_uuid, last_uuid, BATCH_SIZE],
            )
            ids = [row[0] for row in cursor.fetchall()]
            if not ids:
                break
            cursor.execute(
                "INSERT INTO osidb_flawchangeevent (flaw_id, local_updated_dt) "
                "SELECT f.uuid, f.local_updated_dt FROM osidb_flaw f "
                "WHERE f.uuid = ANY(%s::uuid[]) AND NOT EXISTS ("
                "SELECT 1 FROM osidb_flawchangeevent e WHERE e.flaw_id=f.uuid)",
                [ids],
            )
            last_uuid = ids[-1]


class Migration(migrations.Migration):
    atomic = False
    dependencies = [("osidb", "0284_flaw_change_events")]
    operations = [migrations.RunPython(backfill_events, migrations.RunPython.noop)]
