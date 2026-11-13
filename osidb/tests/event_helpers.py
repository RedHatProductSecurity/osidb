"""Test-only head/reset helpers; normal application code never resets history."""

from osidb.models import FlawChangeEvent


def latest_event(flaw):
    pk = getattr(flaw, "pk", flaw)
    return (
        FlawChangeEvent.objects.filter(flaw_id=pk)
        .order_by("-local_updated_dt", "-id")
        .first()
    )


def reset_events(flaws, timestamp):
    ids = [getattr(f, "pk", f) for f in flaws]
    FlawChangeEvent.objects.filter(flaw_id__in=ids).delete()
    FlawChangeEvent.objects.bulk_create(
        [FlawChangeEvent(flaw_id=pk, local_updated_dt=timestamp) for pk in ids]
    )
