"""Internal latest-state change records, not a public history/delivery feed."""

from django.db import models


class FlawChangeEvent(models.Model):
    flaw = models.ForeignKey(
        "Flaw",
        db_constraint=False,
        db_index=False,
        on_delete=models.DO_NOTHING,
        related_name="change_events",
    )
    local_updated_dt = models.DateTimeField()

    class Meta:
        indexes = [
            models.Index(
                fields=["flaw", "-local_updated_dt", "-id"],
                name="flaw_event_latest_idx",
            ),
            models.Index(
                fields=["local_updated_dt", "flaw"], name="flaw_event_time_idx"
            ),
        ]
