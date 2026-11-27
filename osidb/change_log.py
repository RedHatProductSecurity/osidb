"""Bounded head-preserving compaction on the normal application connection.

Call through the scheduled task or management command, both of which use the
project's bypass_rls decorator so hidden live parents cannot look like orphans.
"""

import time
from datetime import timedelta

from django.db import connection, transaction
from django.db.models import Exists, OuterRef, Q
from django.db.models.functions import Now

from osidb.models import Flaw, FlawChangeEvent


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
    newer = FlawChangeEvent.objects.filter(flaw_id=OuterRef("flaw_id")).filter(
        Q(local_updated_dt__gt=OuterRef("local_updated_dt"))
        | Q(local_updated_dt=OuterRef("local_updated_dt"), id__gt=OuterRef("id"))
    )
    eligible = Q(Exists(newer))
    if history_days:
        eligible &= Q(local_updated_dt__lt=Now() - timedelta(days=history_days))
    eligible |= Q(~Exists(Flaw.objects.filter(uuid=OuterRef("flaw_id"))))
    while batches < max_batches and time.monotonic() - started < seconds:
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout='1s'")
            cursor.execute("SET LOCAL statement_timeout='10s'")
            ids = list(
                FlawChangeEvent.objects.filter(eligible, id__gt=after_id)
                .order_by("id")
                .select_for_update(skip_locked=True)
                .values_list("id", flat=True)[:batch_size]
            )
            count, _ = FlawChangeEvent.objects.filter(pk__in=ids).delete()
            if ids:
                after_id = ids[-1]
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
