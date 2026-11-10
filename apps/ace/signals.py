from django.db import transaction
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.ace.constants import LABEL_AUTO_AFFECTS
from apps.workflows.signals import classification_changed
from osidb.models import Flaw
from osidb.models.affect import AffectSettings
from osidb.models.flaw.label import WorkflowLabel


def _is_eligible(old_workflow, old_state, new_workflow, new_state):
    """
    True when workflow transition may be the first move into an eligible state.

    New workflow must be DEFAULT and not NEW or DONE. Old workflow
    must be NEW, an empty workflow, or EMBARGOED.
    """

    destination_eligible = new_workflow == "DEFAULT" and new_state not in (
        "",
        "NEW",
        "DONE",
    )
    if old_workflow == "EMBARGOED":
        source_may_be_first = True
    else:
        source_may_be_first = old_workflow in ("", "DEFAULT") and old_state in (
            "",
            "NEW",
        )
    return destination_eligible and source_may_be_first


def _has_nonempty_components(components):
    """Check if at least one non-empty component exists."""
    return any(c and str(c).strip() for c in (components or []))


def _enqueue_ace(flaw_id, trigger):
    """Enqueue the ACE Celery task via transaction.on_commit."""

    def enqueue_sync():
        from apps.ace.tasks import sync_flaw_affects_from_newcli

        # Celery adds .delay at import time; static checkers do not see it
        sync_flaw_affects_from_newcli.delay(flaw_id, trigger=trigger)  # type: ignore[attr-defined]

    transaction.on_commit(enqueue_sync)


def _enqueue_hummingbird(flaw_id, trigger):
    """Enqueue the Hummingbird Celery task via transaction.on_commit."""

    def enqueue_sync():
        from apps.ace.tasks import sync_hummingbird_affects

        # Celery adds .delay at import time; static checkers do not see it
        sync_hummingbird_affects.delay(flaw_id, trigger=trigger)  # type: ignore[attr-defined]

    transaction.on_commit(enqueue_sync)


@receiver(classification_changed, sender=Flaw)
def qualify_flaw_on_first_entry(
    sender, instance, old_classification, new_classification, **kwargs
) -> None:
    """
    Qualify a flaw for ACE once, on its first move into an eligible state.

    Qualification runs after commit. It may create workflow labels, and a
    label save writes the flaw again, which must not happen inside this
    pre_save. The ``auto-affects`` label enqueues ACE.

    Gated by :attr:`osidb.models.affect.AffectSettings.auto_create`
    (``OSIDB_AFFECTS_AUTO_CREATE``, default false).
    """
    if not AffectSettings().auto_create:
        return

    old_workflow = old_classification.get("workflow") or ""
    old_state = old_classification.get("state") or ""
    new_workflow = new_classification.get("workflow") or ""
    new_state = new_classification.get("state") or ""

    if not _is_eligible(old_workflow, old_state, new_workflow, new_state):
        return
    if not _has_nonempty_components(instance.components):
        return

    flaw_id = str(instance.uuid)

    def qualify_on_commit():
        from apps.ace.tasks import qualify_flaw_for_ace

        qualify_flaw_for_ace(flaw_id)

    transaction.on_commit(qualify_on_commit)


@receiver(post_save, sender=WorkflowLabel)
def schedule_sync_flaw_affects_on_auto_affects_label(
    sender, instance, created, **kwargs
) -> None:
    """
    Enqueue ACE when the auto-affects label is created.

    ``get_or_create`` of an existing label does not set ``created``, so the
    task cannot enqueue itself by applying the label again. Deleting the
    label does not enqueue ACE. A re-run is a new label after the old one
    is removed, and only while the flaw is eligible: the task still refuses
    NEW, DONE, and non-DEFAULT workflows.

    Gated by :attr:`osidb.models.affect.AffectSettings.auto_create`
    (``OSIDB_AFFECTS_AUTO_CREATE``, default false).
    """
    if not created or instance.name != LABEL_AUTO_AFFECTS:
        return
    if not AffectSettings().auto_create:
        return
    _enqueue_ace(str(instance.flaw_id), "auto-affects label applied")


@receiver(pre_save, sender=Flaw)
def schedule_sync_hummingbird_affects_on_components_change(
    sender, instance, **kwargs
) -> None:
    """
    Trigger Hummingbird affect creation when components change, regardless of workflow state.

    Unlike ACE, this handler:
    - Has no workflow gate (fires for any workflow type/state)
    - Fires on flaw creation if components are set
    - Never applies labels

    Gated by :attr:`osidb.models.affect.AffectSettings.auto_create`
    (``OSIDB_AFFECTS_AUTO_CREATE``, default false).
    """
    if not AffectSettings().auto_create:
        return

    if kwargs.get("raw"):
        return

    update_fields = kwargs.get("update_fields")
    if update_fields is not None and "components" not in update_fields:
        return

    if not _has_nonempty_components(instance.components):
        return

    if instance._state.adding:
        # New flaw with components: trigger hummingbird
        _enqueue_hummingbird(str(instance.uuid), "flaw created with components")
        return

    # Existing flaw: check if components actually changed (use set comparison to ignore order)
    db_flaw = Flaw.objects.get(pk=instance.pk)
    old_set = set(db_flaw.components or [])
    new_set = set(instance.components or [])
    if old_set == new_set:
        return

    _enqueue_hummingbird(str(instance.uuid), "flaw components changed")
