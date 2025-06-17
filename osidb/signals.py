import logging

from bugzilla import Bugzilla
from django.contrib.auth.models import User
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from jira import JIRA

from apps.workflows.workflow import WorkflowModel
from osidb.helpers import get_env
from osidb.models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawCollaborator,
    FlawCVSS,
    Impact,
    Profile,
    Tracker,
)
from osidb.models.flaw.acknowledgment import FlawAcknowledgment
from osidb.models.flaw.comment import FlawComment
from osidb.models.flaw.reference import FlawReference

logger = logging.getLogger(__name__)


def get_bz_user_id(email: str) -> str:
    api_key = get_env("BZIMPORT_BZ_API_KEY")
    bz_url = get_env("BZIMPORT_BZ_URL", "https://bugzilla.redhat.com")
    try:
        bz_api = Bugzilla(
            bz_url,
            api_key=api_key,
            force_rest=True,
        )
        users = bz_api.searchusers([email])
    except Exception:
        logger.error(
            f"Failed to fetch Bugzilla username for {email}, is the Bugzilla token valid?"
        )
        return ""
    else:
        if users:
            return users[0].name
        return ""


def get_jira_user_id(email: str) -> str:
    auth_token = get_env("JIRA_AUTH_TOKEN")
    jira_url = get_env("JIRA_URL", "https://issues.redhat.com")
    try:
        jira_api = JIRA(
            options={
                "server": jira_url,
                # avoid auto-updating the lib
                "check_update": False,
            },
            token_auth=auth_token,
            get_server_info=False,
        )
        users = jira_api.search_users([email])
    except Exception:
        logger.error(
            f"Failed to fetch JIRA username for {email}, is the JIRA token valid?"
        )
        return ""
    else:
        if users:
            return users[0].name
        return ""


def update_major_incident_start_dt(flaw: Flaw) -> None:
    # Set the date when the flaw became a MI if needed
    is_major_incident = flaw.major_incident_state in {
        Flaw.FlawMajorIncident.APPROVED,
        Flaw.FlawMajorIncident.CISA_APPROVED,
        # Flaw.FlawMajorIncident.MINOR is not
        # included as it has no impact on the SLA
        Flaw.FlawMajorIncident.ZERO_DAY,
    }
    if is_major_incident and flaw.major_incident_start_dt is None:
        flaw.major_incident_start_dt = timezone.now()
    elif not is_major_incident:
        flaw.major_incident_start_dt = None


@receiver(post_save, sender=User)
def auto_create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(
            user=instance,
            # TODO I am disabling the external system queries for now to safe the extra API calls
            # and dependencies but the full removal requires User-Profile rework and major release
            # bz_user_id=get_bz_user_id(instance.email),
            # jira_user_id=get_jira_user_id(instance.email),
        ).save()


@receiver(pre_save, sender=FlawCVSS)
@receiver(pre_save, sender=AffectCVSS)
def populate_cvss_score(sender, instance, **kwargs):
    instance.score = float(instance.cvss_object.base_score)


@receiver(pre_save, sender=Flaw)
def update_flaw_fields(sender, instance, **kwargs):
    instance.local_updated_dt = timezone.now()
    update_major_incident_start_dt(instance)


@receiver(post_save, sender=Affect)
@receiver(post_save, sender=FlawReference)
@receiver(post_save, sender=FlawAcknowledgment)
@receiver(post_save, sender=FlawComment)
@receiver(post_save, sender=FlawCollaborator)
@receiver(post_save, sender=FlawCVSS)
def flaw_dependant_update_local_updated_dt(sender, instance, **kwargs):
    instance.flaw.save(auto_timestamps=False, raise_validation_error=False)


@receiver(post_save, sender=Tracker)
@receiver(m2m_changed, sender=Tracker.affects.through)
def update_local_updated_dt_tracker(sender, instance, **kwargs):
    flaws = set()
    # /!\ in the case of an m2m_changed signal, instance can be either a
    # Tracker or an Affect object, see Django docs on m2m_changed signal
    if isinstance(instance, Affect):
        flaws.add(instance.flaw)
    else:
        for affect in instance.affects.all():
            flaws.add(affect.flaw)
    for flaw in list(flaws):
        flaw.save(
            auto_timestamps=False,
            no_alerts=True,  # recreating alerts from nested entities can cause deadlocks
            raise_validation_error=False,
        )


@receiver(post_save, sender=AffectCVSS)
def updated_local_updated_dt_affectcvss(sender, instance, **kwargs):
    instance.affect.flaw.save(auto_timestamps=False, raise_validation_error=False)


@receiver(post_save, sender=Affect)
def create_flaw_labels(sender, instance, **kwargs):
    if instance.flaw.workflow_state == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT:
        if instance._state.adding:
            FlawCollaborator.objects.create_from_affect(instance)
        else:
            FlawCollaborator.objects.mark_irrelevant(instance.flaw)


@receiver(post_delete, sender=Affect)
def delete_flaw_labels(sender, instance, **kwargs):
    if instance.flaw.workflow_state == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT:
        FlawCollaborator.objects.mark_irrelevant(instance.flaw)


@receiver(pre_save, sender=Flaw)
def create_labels_on_promote(sender, instance, **kwargs):
    if (
        not instance._state.adding
        and instance.workflow_state == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        and Flaw.objects.get(pk=instance.pk).workflow_state
        != WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
    ):
        FlawCollaborator.objects.create_from_flaw(instance)


@receiver(pre_save, sender=Affect)
def update_last_impact_increase_dt_affect(sender, instance, **kwargs):
    if not instance._state.adding and Impact(instance.impact) > Impact(
        Affect.objects.get(pk=instance.pk).impact
    ):
        to_update = set()
        for tracker in instance.trackers.all():
            if Impact(instance.impact) > tracker.aggregated_impact:
                to_update.add(tracker.uuid)

        if to_update:
            Tracker.objects.filter(uuid__in=to_update).update(
                last_impact_increase_dt=timezone.now()
            )


@receiver(pre_save, sender=Affect)
def remove_not_affected_justification(sender, instance, **kwargs):
    """
    Remove the not affected justification if the affect has an affectedness different
    to NOT_AFFECTED.
    """
    if instance.affectedness != Affect.AffectAffectedness.NOTAFFECTED:
        instance.not_affected_justification = ""


@receiver(pre_save, sender=Flaw)
def update_last_impact_increase_dt_flaw(sender, instance, **kwargs):
    if not instance._state.adding and Impact(instance.impact) > Impact(
        Flaw.objects.get(pk=instance.pk).impact
    ):
        to_update = set()
        for tracker in Tracker.objects.filter(affects__flaw=instance).distinct():
            # Tracker will only take the flaw's impact if none of its affects have an impact
            if (
                not tracker.affects.exclude(impact="").exists()
                and Impact(instance.impact) > tracker.aggregated_impact
            ):
                to_update.add(tracker.uuid)

        if to_update:
            Tracker.objects.filter(uuid__in=to_update).update(
                last_impact_increase_dt=timezone.now()
            )
