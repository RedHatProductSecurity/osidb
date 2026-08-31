from django.db import transaction
from django.db.models.signals import pre_save
from django.dispatch import receiver

from apps.workflows.signals import classification_changed
from osidb.models import Flaw
from osidb.models.affect import AffectSettings


def _is_eligible(workflow_name, workflow_state):
    """Check if a workflow position qualifies for ACE triggering."""
    return workflow_name == "DEFAULT" and workflow_state not in ("", "NEW", "DONE")


def _has_nonempty_components(components):
    """Check if at least one non-empty component exists."""
    return any(c and str(c).strip() for c in (components or []))


def _enqueue_ace(flaw_id):
    """Enqueue the ACE Celery task via transaction.on_commit."""

    def enqueue_sync():
        from apps.ace.tasks import sync_flaw_affects_from_newcli

        # Celery adds .delay at import time; static checkers do not see it
        sync_flaw_affects_from_newcli.delay(flaw_id)  # type: ignore[attr-defined]

    transaction.on_commit(enqueue_sync)


@receiver(pre_save, sender=Flaw)
def schedule_sync_flaw_affects_on_components_change(sender, instance, **kwargs) -> None:
    """
    Trigger ACE when components change on a flaw that is already in an eligible workflow state.

    This handler checks the DB flaw's eligibility (not the instance's) to avoid race conditions
    with the workflow pre_save signal that updates workflow_state. When both components and
    workflow change in one save, the DB flaw is still in the old (ineligible) state, so this
    handler skips and the classification_changed handler picks it up.

    Gated by :attr:`osidb.models.affect.AffectSettings.auto_create`
    (``OSIDB_AFFECTS_AUTO_CREATE``, default false).
    """
    if not AffectSettings().auto_create:
        return

    if kwargs.get("raw"):
        return

    if instance._state.adding:
        return

    update_fields = kwargs.get("update_fields")
    if update_fields is not None and "components" not in update_fields:
        return

    db_flaw = Flaw.objects.get(pk=instance.pk)

    # Check eligibility using DB flaw's state to avoid pre_save ordering race
    if not _is_eligible(db_flaw.workflow_name, db_flaw.workflow_state):
        return

    # Check if components changed
    old_list = list(db_flaw.components or [])
    new_list = list(instance.components or [])
    if old_list == new_list:
        return

    if not _has_nonempty_components(new_list):
        return

    _enqueue_ace(str(instance.uuid))


@receiver(classification_changed, sender=Flaw)
def schedule_sync_flaw_affects_on_classification_change(
    sender, instance, old_classification, new_classification, **kwargs
) -> None:
    """
    Trigger ACE when a flaw transitions into an eligible workflow state.

    This handler listens to the classification_changed signal emitted by
    adjust_classification() after the workflow state has been updated in memory.
    It only triggers when moving FROM an ineligible state TO an eligible state
    (e.g., NEW -> TRIAGE).

    Gated by :attr:`osidb.models.affect.AffectSettings.auto_create`
    (``OSIDB_AFFECTS_AUTO_CREATE``, default false).
    """
    if not AffectSettings().auto_create:
        return

    old_workflow = old_classification.get("workflow", "")
    old_state = old_classification.get("state", "")
    new_workflow = new_classification.get("workflow", "")
    new_state = new_classification.get("state", "")

    was_eligible = _is_eligible(old_workflow, old_state)
    now_eligible = _is_eligible(new_workflow, new_state)

    # Only trigger when transitioning INTO an eligible state
    if not now_eligible or was_eligible:
        return

    if not _has_nonempty_components(instance.components):
        return

    _enqueue_ace(str(instance.uuid))
