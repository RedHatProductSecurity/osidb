"""Latest-state reads from the append log, with the legacy rollout control."""

from django.conf import settings
from django.db.models import DateTimeField, Exists, OuterRef, Subquery

EVENT_TIMESTAMP = "_change_updated_dt"


def filter_latest_change(queryset, *, after=None, before=None):
    """Constrain the latest event without projecting it for every parent.

    A bounded event candidate relation plus an anti-newer predicate implements
    inclusive latest-state bounds, even when older history matches the window.
    Bounds are typed and validated; the caller applies any V1 overlap once.
    """
    from osidb.models import FlawChangeEvent

    if after is not None and before is not None and after > before:
        return queryset.none()
    events = FlawChangeEvent.objects.order_by()
    if after is not None:
        candidates = events.filter(local_updated_dt__gte=after)
        if before is not None:
            candidates = candidates.filter(local_updated_dt__lte=before)
        # DISTINCT keeps the time-bounded candidate relation from flattening
        # into an ordered parent-first semi-loop for paginated LIMIT queries.
        queryset = queryset.filter(
            pk__in=Subquery(candidates.values("flaw_id").distinct())
        )
    else:
        # Missing coverage must behave like MAX(NULL), not qualify by accident.
        queryset = queryset.filter(Exists(events.filter(flaw_id=OuterRef("pk"))))
    if before is not None:
        newer = events.filter(flaw_id=OuterRef("pk"), local_updated_dt__gt=before)
        queryset = queryset.filter(~Exists(newer))
    return queryset


def with_flaw_timestamp(queryset):
    """Project latest time only where needed, keeping identity/RLS on live Flaw."""
    if not settings.OSIDB_USE_FLAW_WATERMARK:
        return queryset
    from osidb.models import FlawChangeEvent

    latest = (
        FlawChangeEvent.objects.filter(flaw_id=OuterRef("pk"))
        .order_by("-local_updated_dt", "-id")
        .values("local_updated_dt")[:1]
    )
    return queryset.annotate(
        **{EVENT_TIMESTAMP: Subquery(latest, output_field=DateTimeField())}
    )


def flaw_timestamp_field() -> str:
    """Select the prepared annotation or legacy column, never a fake field.

    Complete baseline coverage is an enablement prerequisite. Do not silently
    repair missing events by falling back to the legacy column.
    """
    return EVENT_TIMESTAMP if settings.OSIDB_USE_FLAW_WATERMARK else "local_updated_dt"
