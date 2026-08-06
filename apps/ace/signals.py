from django.db import transaction
from django.db.models.signals import pre_save
from django.dispatch import receiver

from osidb.models import Flaw
from osidb.models.affect import AffectSettings


@receiver(pre_save, sender=Flaw)
def schedule_sync_flaw_affects_on_components_change(sender, instance, **kwargs) -> None:
    """
    When :attr:`Flaw.components` is set or updated and the flaw has at least one
    non-empty component, register :func:`apps.ace.tasks.sync_flaw_affects_from_newcli`
    to run after the current DB transaction commits (via :func:`django.db.transaction.on_commit`).

    Gated by :attr:`osidb.models.affect.AffectSettings.auto_create`
    (``OSIDB_AFFECTS_AUTO_CREATE``, default false).
    """
    if not AffectSettings().auto_create:
        return

    if kwargs.get("raw"):
        return

    new_list = list(instance.components or [])

    if instance._state.adding:
        return

    update_fields = kwargs.get("update_fields")
    if (
        update_fields is not None
        and "components" not in update_fields
        and "workflow_state" not in update_fields
        and "workflow_name" not in update_fields
    ):
        return

    db_flaw = Flaw.objects.get(pk=instance.pk)

    if instance.workflow_name != "DEFAULT" or instance.workflow_state in (
        "",
        "NEW",
        "DONE",
    ):
        return

    old_list = list(db_flaw.components or [])
    components_changed = old_list != new_list
    workflow_state_became_eligible = (
        db_flaw.workflow_name != "DEFAULT" or db_flaw.workflow_state in ("", "NEW")
    ) and instance.workflow_state not in ("", "NEW", "DONE")

    if not (components_changed or workflow_state_became_eligible):
        return

    if not any(c and str(c).strip() for c in new_list):
        return

    flaw_id = str(instance.uuid)

    def enqueue_sync() -> None:
        from apps.ace.tasks import sync_flaw_affects_from_newcli

        # Celery adds .delay at import time; static checkers do not see it
        sync_flaw_affects_from_newcli.delay(flaw_id)  # type: ignore[attr-defined]

    transaction.on_commit(enqueue_sync)
