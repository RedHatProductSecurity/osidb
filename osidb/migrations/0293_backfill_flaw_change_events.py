"""Seed exact legacy timestamps after statement writers are installed.

Retry-safe, bounded keyset batches. Concurrent writes already append events;
there is no parent UPDATE, row lock, historical repair, or head overwrite.
"""

from django.db import migrations, transaction
from django.db.models import Exists, OuterRef

from osidb.helpers import bypass_rls

BATCH_SIZE = 2000


@bypass_rls
def backfill_events(apps, schema_editor):
    alias = schema_editor.connection.alias
    Flaw = apps.get_model("osidb", "Flaw")
    FlawChangeEvent = apps.get_model("osidb", "FlawChangeEvent")
    events = FlawChangeEvent.objects.using(alias)
    last_uuid = None
    while True:
        with transaction.atomic(using=alias):
            flaws = (
                Flaw.objects.using(alias)
                .annotate(has_event=Exists(events.filter(flaw_id=OuterRef("uuid"))))
                .order_by("uuid")
            )
            if last_uuid is not None:
                flaws = flaws.filter(uuid__gt=last_uuid)
            rows = list(
                flaws.values_list("uuid", "local_updated_dt", "has_event")[:BATCH_SIZE]
            )
            if not rows:
                break
            events.bulk_create(
                [
                    FlawChangeEvent(flaw_id=pk, local_updated_dt=timestamp)
                    for pk, timestamp, has_event in rows
                    if not has_event
                ]
            )
            last_uuid = rows[-1][0]


class Migration(migrations.Migration):
    atomic = False
    dependencies = [("osidb", "0292_flaw_change_events")]
    operations = [migrations.RunPython(backfill_events, migrations.RunPython.noop)]
