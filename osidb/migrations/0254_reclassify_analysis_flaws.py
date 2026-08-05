import logging

from django.db import migrations
from django.db.models import Exists, OuterRef
from django.utils import timezone

from osidb.helpers import bypass_rls

logger = logging.getLogger(__name__)


@bypass_rls
def reclassify_analysis_flaws(apps, schema_editor):
    """
    Advance flaws stuck in ANALYSIS due to NOTAFFECTED affects being
    incorrectly treated as unresolved by the old has_affects_resolved check.

    The DEFAULT workflow transition from ANALYSIS to PRE_SECONDARY_ASSESSMENT
    requires only "has affects resolved". The fixed check considers an affect
    resolved unless it has affectedness=NEW and resolution="" (empty string).
    """
    Flaw = apps.get_model("osidb", "Flaw")
    Affect = apps.get_model("osidb", "Affect")

    has_unresolved_affect = Exists(
        Affect.objects.filter(
            flaw=OuterRef("pk"),
            affectedness="NEW",
            resolution="",
        )
    )

    flaws = (
        Flaw.objects.select_for_update()
        .filter(
            workflow_name="DEFAULT",
            workflow_state="ANALYSIS",
        )
        .exclude(has_unresolved_affect)
    )

    now = timezone.now()
    now_iso = now.isoformat()
    count = 0
    for flaw in flaws.iterator():
        # Lock all Affect rows for this flaw to serialize concurrent writes,
        # then re-check eligibility under the lock.
        affects = list(
            Affect.objects.select_for_update()
            .filter(flaw=flaw)
            .values_list("affectedness", "resolution")
        )
        if any(row == ("NEW", "") for row in affects):
            continue

        if flaw.classification_meta is None:
            flaw.classification_meta = []
        flaw.classification_meta.append(
            {
                "timestamp": now_iso,
                "change_type": "STATE_PROGRESSION",
                "workflow": "DEFAULT",
                "state": "PRE_SECONDARY_ASSESSMENT",
                "reason": {
                    "explanation": (
                        "State progressed from ANALYSIS to PRE_SECONDARY_ASSESSMENT:"
                        " data migration to fix resolved affects check"
                    ),
                },
            }
        )
        flaw.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw.updated_dt = now
        flaw.save(
            update_fields=["workflow_state", "classification_meta", "updated_dt"]
        )
        count += 1

    if count:
        logger.info("Advanced %d flaws from ANALYSIS to PRE_SECONDARY_ASSESSMENT", count)


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0253_flaw_search_vector_index"),
    ]

    operations = [
        migrations.RunPython(
            code=reclassify_analysis_flaws,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
