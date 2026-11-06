"""Bounded head-preserving compaction on the normal application connection.

Call through the scheduled task or management command, both of which use the
project's bypass_rls decorator so hidden live parents cannot look like orphans.
"""

import time

from django.db import connection, transaction

PRUNE_BATCH_SQL = """
    WITH victims AS MATERIALIZED (
        SELECT e.id FROM osidb_flawchangeevent e
        WHERE e.id > %s AND (
            NOT EXISTS (SELECT 1 FROM osidb_flaw f WHERE f.uuid=e.flaw_id)
            OR ((%s=0 OR e.local_updated_dt < statement_timestamp()
                 - make_interval(days => %s)) AND EXISTS (
                SELECT 1 FROM osidb_flawchangeevent newer
                WHERE newer.flaw_id=e.flaw_id
                  AND (newer.local_updated_dt, newer.id) > (e.local_updated_dt, e.id)
            ))
        ) ORDER BY e.id LIMIT %s FOR UPDATE OF e SKIP LOCKED
    ), removed AS (
        DELETE FROM osidb_flawchangeevent e USING victims v
        WHERE e.id=v.id RETURNING e.id
    ) SELECT count(*), COALESCE(max(id),%s) FROM removed
"""


def compact_change_events(
    *, batch_size=1000, history_days=0, max_batches=1000, seconds=60
):
    """Batch core; caller must supply ALL_GROUPS via bypass_rls.

    Each batch commits independently. There is no SQL role elevation or stored
    pruning function: parent visibility comes from the normal session ACLs.
    """
    if connection.in_atomic_block:
        raise ValueError("Compaction requires top-level, short batch transactions")
    if not 1 <= batch_size <= 5000 or not 0 <= history_days <= 36500:
        raise ValueError("Invalid batch size/history retention")
    if not 1 <= max_batches <= 10000 or not 0 < seconds <= 3600:
        raise ValueError("Invalid compaction run budget")
    started = time.monotonic()
    after_id = deleted = batches = 0
    exhausted = False
    while batches < max_batches and time.monotonic() - started < seconds:
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout='1s'")
            cursor.execute("SET LOCAL statement_timeout='10s'")
            cursor.execute(
                PRUNE_BATCH_SQL,
                [after_id, history_days, history_days, batch_size, after_id],
            )
            count, after_id = cursor.fetchone()
        batches += 1
        deleted += count
        if not count:
            exhausted = True
            break
    return {
        "deleted": deleted,
        "batches": batches,
        "seconds": time.monotonic() - started,
        "exhausted_snapshot": exhausted,
        "history_days": history_days,
    }
