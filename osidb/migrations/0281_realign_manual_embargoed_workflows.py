"""
Data migration accompanying the MANUAL and EMBARGOED workflow realignment
(aligning them with the multi-team distribution model).

The workflow definitions changed in several ways that affect where existing
flaws should sit:

  * the ``has owner`` requirement was dropped from the TRIAGE state (a single
    owner no longer gates triage under multi-team distribution),
  * a new ANALYSIS state (``has affects``) was inserted,
  * PRE_SECONDARY_ASSESSMENT now requires ``has affects resolved`` (stricter
    than the former ``has affects``),
  * the MANUAL DONE state no longer requires ``has label approved`` (it now
    has no requirements at all).

Any of these can move a flaw up or down relative to its stored state, so every
non-DONE MANUAL and EMBARGOED flaw is re-run through the live classifier and
its stored classification corrected to match. Because MANUAL's DONE state is
now unconditional, a MANUAL flaw sitting in SECONDARY_ASSESSMENT with all
affects resolved falls through to DONE here - which is why the sibling
SECONDARY_ASSESSMENT -> DONE cleanup migration only has to handle the DEFAULT
workflow.

DONE flaws are deliberately left untouched: re-running them could un-resolve
already-closed flaws and create a large burst of churn for data consumers.
They will re-classify naturally the next time they are saved.

Embargoed flaws live in the EMBARGOED workflow, so the migration grants itself
full ACLs (``@bypass_rls``) to see and update them under Row-Level Security.

NOTE: like 0266_manual_triage_kernel_flaws, this uses the real ``Flaw`` model
and the workflow framework (not historical models) because classification is
runtime business logic that only exists on the concrete model. State is
advanced via ``bulk_update`` to bypass the Bugzilla/Jira sync signals that a
full ``save()`` would fire.
"""

import logging

from django.db import migrations
from django.utils import timezone

from osidb.helpers import bypass_rls

logger = logging.getLogger(__name__)

WORKFLOWS = ["MANUAL", "EMBARGOED"]
BATCH_SIZE = 500


@bypass_rls
def realign_manual_embargoed_workflows(apps, schema_editor):
    import pghistory

    from apps.workflows.tracking import add_classification_change, create_change_record
    from apps.workflows.workflow import WorkflowFramework
    from osidb.models import Flaw

    framework = WorkflowFramework()

    # Non-DONE flaws currently classified in the realigned workflows. task_key
    # is required for a flaw to be classified at all, so an empty one means the
    # flaw never entered a workflow and must be skipped.
    target_flaws = (
        Flaw.objects.filter(workflow_name__in=WORKFLOWS)
        .exclude(workflow_state="DONE")
        .exclude(task_key="")
    )

    reclassified = 0
    to_update = []

    def _flush():
        nonlocal reclassified
        if not to_update:
            return
        Flaw.objects.bulk_update(
            to_update,
            [
                "workflow_name",
                "workflow_state",
                "classification_meta",
                "resolved_dt",
                "updated_dt",
                "local_updated_dt",
            ],
        )
        reclassified += len(to_update)
        to_update.clear()

    with pghistory.context(
        user="OSIDB data migration 0281_realign_manual_embargoed_workflows",
        source="migration",
        action="realign_manual_embargoed_workflows",
    ):
        for flaw in target_flaws.iterator(chunk_size=BATCH_SIZE):
            result = framework.classify(flaw)
            if result is None:
                continue
            workflow, state = result
            new_classification = {"workflow": workflow.name, "state": state.name}
            old_classification = flaw.classification

            if new_classification == old_classification:
                continue

            add_classification_change(
                flaw,
                create_change_record(
                    old_classification,
                    new_classification,
                    instance=flaw,
                    framework=framework,
                ),
            )
            flaw.classification = new_classification

            # Mirror adjust_classification()'s resolved_dt handling: stamp it
            # when entering DONE, clear it whenever the flaw is not DONE.
            now = timezone.now()
            was_done = old_classification["state"] == "DONE"
            is_done = new_classification["state"] == "DONE"
            if is_done and not was_done:
                flaw.resolved_dt = now
            elif not is_done:
                flaw.resolved_dt = None

            # Bump timestamps so incremental consumers (changed_after reads
            # local_updated_dt) notice the correction; bulk_update skips the
            # pre_save hook that would normally refresh them. updated_dt is
            # stored with whole-second precision to match the rest of the
            # codebase (TrackingMixin.save truncates microseconds) and the
            # exact mid-air-collision comparison, so a client that truncates
            # updated_dt to seconds does not hit a false collision.
            flaw.updated_dt = now.replace(microsecond=0)
            flaw.local_updated_dt = now

            to_update.append(flaw)
            if len(to_update) >= BATCH_SIZE:
                _flush()

        _flush()

    if reclassified:
        logger.info(
            "Reclassified %d non-DONE flaw(s) in the %s workflow(s)",
            reclassified,
            ", ".join(WORKFLOWS),
        )


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0280_flaw_bz_id_index"),
    ]

    operations = [
        migrations.RunPython(
            code=realign_manual_embargoed_workflows,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
