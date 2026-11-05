"""
Data migration accompanying the removal of the ``has label approved``
requirement from the DEFAULT workflow's DONE state.

The DONE state is now unconditional. SECONDARY_ASSESSMENT was the only DEFAULT
state whose classification this changes: a flaw resting there (it already has
trackers, resolved affects and complete triage data - those requirements
predate this PR) satisfied every state up to SECONDARY_ASSESSMENT and now
trivially satisfies the empty DONE, so it belongs in DONE. Every other state is
unaffected.

A flaw that is legitimately in SECONDARY_ASSESSMENT therefore moves to DONE
unconditionally, so this is a single bulk UPDATE rather than a per-flaw
re-classification - no flaw in SECONDARY_ASSESSMENT can resolve to anything but
DONE under the new definition.

The MANUAL workflow received the same DONE change, but its non-DONE flaws
(including anything in SECONDARY_ASSESSMENT) are re-classified by
0281_realign_manual_embargoed_workflows, so this migration is scoped to DEFAULT.

``resolved_dt`` is stamped (entering DONE) and the timestamps are bumped so
incremental consumers (the changed_after filter reads ``local_updated_dt``)
notice the change. The classification history gets a STATE_PROGRESSION record
appended via a jsonb concatenation.
"""

import json
import logging

from django.db import migrations
from django.db.models.expressions import RawSQL
from django.utils import timezone

from osidb.helpers import bypass_rls

logger = logging.getLogger(__name__)


@bypass_rls
def promote_default_secondary_assessment_to_done(apps, schema_editor):
    import pghistory

    from osidb.models import Flaw

    now = timezone.now()
    change_record = {
        "timestamp": now.isoformat(),
        "change_type": "STATE_PROGRESSION",
        "workflow": "DEFAULT",
        "state": "DONE",
        "reason": {
            "explanation": (
                "State progressed from SECONDARY_ASSESSMENT to DONE by migration "
                "0282_default_secondary_assessment_done: the manual approval "
                "requirement was removed from the DEFAULT DONE state, which is now "
                "unconditional."
            )
        },
    }

    with pghistory.context(
        user="OSIDB data migration 0282_default_secondary_assessment_done",
        source="migration",
        action="promote_default_secondary_assessment_to_done",
    ):
        promoted = Flaw.objects.filter(
            workflow_name="DEFAULT",
            workflow_state="SECONDARY_ASSESSMENT",
        ).update(
            workflow_state="DONE",
            resolved_dt=now,
            # whole-second precision to match the codebase convention
            # (TrackingMixin.save truncates microseconds) and its exact mid-air
            # collision comparison, so a client truncating updated_dt to seconds
            # does not hit a false collision
            updated_dt=now.replace(microsecond=0),
            local_updated_dt=now,
            # append the change record to the existing (possibly empty) history
            classification_meta=RawSQL(
                "COALESCE(classification_meta, '[]'::jsonb) || %s::jsonb",
                (json.dumps([change_record]),),
            ),
        )

    if promoted:
        logger.info(
            "Promoted %d DEFAULT flaw(s) from SECONDARY_ASSESSMENT to DONE",
            promoted,
        )


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0281_realign_manual_embargoed_workflows"),
    ]

    operations = [
        migrations.RunPython(
            code=promote_default_secondary_assessment_to_done,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
