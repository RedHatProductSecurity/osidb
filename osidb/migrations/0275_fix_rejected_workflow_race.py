from django.apps.registry import Apps
from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor
from django.utils import timezone

import pghistory

from osidb.helpers import bypass_rls

REJECT_LABELS = ["auto-rejected", "rejected"]


@bypass_rls
def fix_rejected_workflow_race(apps: Apps, schema_editor: BaseDatabaseSchemaEditor):
    """
    Repair flaws left misclassified by a classification race condition.

    A lost update between two concurrent flaw saves could move a flaw that
    was auto-rejected (carries a terminal ``auto-rejected``/``rejected``
    workflow label) back out of the ``REJECTED``/``DONE`` classification.
    Such flaws keep the terminal label but sit in another workflow/state,
    reappearing in triage queues.

    This brings them in line with what the automatic classifier would now
    produce: any flaw with a task and a terminal reject workflow label
    belongs to ``REJECTED``/``DONE`` (the highest-priority workflow, which
    accepts on ``has label auto-rejected OR has label rejected``).
    """
    Flaw = apps.get_model("osidb", "Flaw")
    FlawLabel = apps.get_model("osidb", "FlawLabel")
    ContentType = apps.get_model("contenttypes", "ContentType")

    # Restrict to WorkflowLabel rows - classify()'s has_label() only considers
    # WorkflowLabel, so other label types sharing a name must be ignored.
    wl_ctype = ContentType.objects.filter(
        app_label="osidb", model="workflowlabel"
    ).first()

    label_qs = FlawLabel.objects.filter(name__in=REJECT_LABELS)
    if wl_ctype is not None:
        label_qs = label_qs.filter(polymorphic_ctype=wl_ctype)

    reject_label_flaw_ids = list(
        label_qs.values_list("flaw_id", flat=True).distinct()
    )
    if not reject_label_flaw_ids:
        return

    flaws = (
        Flaw.objects.filter(uuid__in=reject_label_flaw_ids)
        .exclude(workflow_name="REJECTED")
        .exclude(task_key="")
    )

    with pghistory.context(
        user="OSIDB data migration 0275_fix_rejected_workflow_race",
        source="migration",
        action="fix_rejected_workflow_race",
    ):
        for flaw in flaws.iterator(chunk_size=500):
            old_workflow = flaw.workflow_name
            old_state = flaw.workflow_state

            # resolution time: when the terminal label was applied, if known
            resolved_dt = (
                label_qs.filter(flaw_id=flaw.uuid)
                .order_by("-created_dt")
                .values_list("created_dt", flat=True)
                .first()
            )

            flaw.workflow_name = "REJECTED"
            flaw.workflow_state = "DONE"
            if flaw.resolved_dt is None:
                flaw.resolved_dt = resolved_dt or timezone.now()

            if flaw.classification_meta is None:
                flaw.classification_meta = []
            flaw.classification_meta.append(
                {
                    "timestamp": timezone.now().isoformat(),
                    "change_type": "DATA_MIGRATION_CORRECTION",
                    "workflow": "REJECTED",
                    "state": "DONE",
                    "reason": {
                        "explanation": (
                            f"Corrected from {old_workflow}:{old_state} to "
                            "REJECTED:DONE by migration "
                            "0275_fix_rejected_workflow_race: the flaw carries a "
                            "terminal reject workflow label but was left in a "
                            "non-REJECTED classification by a classification race "
                            "condition."
                        )
                    },
                }
            )

            # bump local_updated_dt so incremental consumers (the changed_after
            # filter reads local_updated_dt) pick up the correction - the
            # historical model save does not run the runtime pre_save hook that
            # would normally refresh it
            flaw.local_updated_dt = timezone.now()
            flaw.save(
                update_fields=[
                    "workflow_name",
                    "workflow_state",
                    "resolved_dt",
                    "classification_meta",
                    "local_updated_dt",
                ]
            )


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0274_remove_flaw_insert_insert_remove_flaw_update_update_and_more"),
    ]

    operations = [
        migrations.RunPython(
            fix_rejected_workflow_race, reverse_code=migrations.RunPython.noop
        ),
    ]
