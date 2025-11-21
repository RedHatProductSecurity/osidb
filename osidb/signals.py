import logging

from bugzilla import Bugzilla
from django.contrib.auth.models import User
from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.utils import timezone
from jira import JIRA

from apps.workflows.workflow import WorkflowModel
from collectors.jiraffe.constants import HTTPS_PROXY
from config.settings import EmailSettings
from osidb.helpers import get_env, get_execution_env
from osidb.models import (
    Affect,
    AffectCVSS,
    Flaw,
    FlawCollaborator,
    FlawCVSS,
    Impact,
    Profile,
    PsModule,
    PsUpdateStream,
    Tracker,
)
from osidb.models.flaw.acknowledgment import FlawAcknowledgment
from osidb.models.flaw.comment import FlawComment
from osidb.models.flaw.reference import FlawReference
from osidb.tasks import async_send_email

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
            proxies={
                "https": HTTPS_PROXY,
            },
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
        Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
        Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
        # Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED is not
        # included as it has no impact on the SLO
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
@receiver(post_save, sender=Affect)
@receiver(post_delete, sender=Affect)
def update_local_updated_dt_tracker(sender, instance, **kwargs):
    flaws = set()
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
    if (
        instance.flaw.workflow_state
        == WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
    ):
        if instance._state.adding:
            FlawCollaborator.objects.create_from_affect(instance)
        else:
            FlawCollaborator.objects.mark_irrelevant(instance.flaw)


@receiver(post_delete, sender=Affect)
def delete_flaw_labels(sender, instance, **kwargs):
    if (
        instance.flaw.workflow_state
        == WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
    ):
        FlawCollaborator.objects.mark_irrelevant(instance.flaw)


@receiver(pre_save, sender=Flaw)
def create_labels_on_promote(sender, instance, **kwargs):
    if (
        not instance._state.adding
        and instance.workflow_state
        == WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        and Flaw.objects.get(pk=instance.pk).workflow_state
        != WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
    ):
        FlawCollaborator.objects.create_from_flaw(instance)


@receiver(pre_save, sender=Affect)
def update_last_impact_increase_dt_affect(sender, instance, **kwargs):
    if not instance._state.adding and Impact(instance.impact) > Impact(
        Affect.objects.get(pk=instance.pk).impact
    ):
        if (
            instance.tracker is not None
            and Impact(instance.impact) > instance.tracker.aggregated_impact
        ):
            Tracker.objects.filter(uuid=instance.tracker.uuid).update(
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


@receiver(pre_save, sender=Flaw)
def update_denormalized_cve_ids_on_flaw_update(sender, instance, **kwargs):
    # while it's very unlikely for a Flaw's CVE ID to be updated, it's best
    # to cover this scenario for denormalized CVE IDs in other models.
    if not instance._state.adding:
        db_instance = Flaw.objects.get(pk=instance.pk)
        trackers = set()
        if instance.cve_id != db_instance.cve_id:
            instance.affects.all().update(cve_id=instance.cve_id)
            for affect in instance.affects.all():
                if affect.tracker is not None:
                    affect.tracker.cve_id = instance.cve_id
                    trackers.add(affect.tracker)
            Tracker.objects.bulk_update(list(trackers), fields=["cve_id"])


@receiver(pre_save, sender=PsModule)
@receiver(pre_save, sender=PsUpdateStream)
def update_denormalized_ps_module(sender, instance, **kwargs):
    # Cover the extremely unlikely case in which a ps_module changes name or a
    # ps_update_stream changes module
    if not instance._state.adding:
        if sender is PsModule:
            db_instance = PsModule.objects.get(pk=instance.pk)
            if instance.name != db_instance.name:
                Affect.objects.filter(ps_module=db_instance.name).update(
                    ps_module=instance.name
                )
        elif sender is PsUpdateStream:
            db_instance = PsUpdateStream.objects.get(pk=instance.pk)
            new_ps_module = PsModule.objects.filter(name=instance.ps_module).first()
            old_ps_module = PsModule.objects.filter(name=db_instance.ps_module).first()
            if new_ps_module != old_ps_module:
                Affect.objects.filter(ps_module=db_instance.ps_module).update(
                    ps_module=new_ps_module.name
                )


@receiver(pre_save, sender=Affect)
@receiver(pre_save, sender=Tracker)
def mirror_parent_cve_id(sender, instance, **kwargs):
    if sender is Affect:
        parent = instance.flaw
    else:
        parent = instance.affects.first()
    if parent:
        instance.cve_id = parent.cve_id


@receiver(pre_save, sender=Affect)
def update_denormalized_labels_on_affect_change(sender, instance, **kwargs):
    """
    Update denormalized labels when ps_module or ps_component change.
    """
    if instance._state.adding:
        # New affect - always update labels
        instance.update_denormalized_labels()
    else:
        # Existing affect - check if ps_module or ps_component changed
        db_instance = Affect.objects.get(pk=instance.pk)
        if (
            instance.ps_module != db_instance.ps_module
            or instance.ps_component != db_instance.ps_component
        ):
            instance.update_denormalized_labels()


@receiver(pre_save, sender=Flaw)
def send_email_on_incident_state_change(
    sender: type[Flaw], instance: Flaw, **kwargs
) -> None:
    """
    Sends a notification email to key stakeholders whenever the incident
    state field on Flaw changes.
    """
    previous_incident_state = None
    if (
        instance._state.adding
        and instance.major_incident_state == Flaw.FlawMajorIncident.NOVALUE
    ):
        # No notification on Flaw creation with empty incident value
        return
    elif not instance._state.adding:
        # No notification on Flaw update with no incident state changes
        db_instance = Flaw.objects.get(pk=instance.pk)
        if instance.major_incident_state == db_instance.major_incident_state:
            return
        previous_incident_state = db_instance.major_incident_state

    def get_osim_url():
        if (env := get_execution_env()) == "prod":
            return "https://osim.prodsec.redhat.com"
        elif env in ["stage", "uat"]:
            return f"https://osim-{env}.prodsec.redhat.com"
        return "http://localhost:8000"

    flaw_id = instance.cve_id or instance.uuid
    context = {
        "flaw_id": flaw_id,
        "previous_incident_state": previous_incident_state,
        "new_incident_state": instance.major_incident_state,
        "osim_url": get_osim_url(),
    }

    text_body = render_to_string("email/incident_state_change.txt", context=context)
    html_body = render_to_string("email/incident_state_change.html", context=context)

    recipient = EmailSettings().incident_request_recipient
    payload = {
        "subject": f"Incident state change for Flaw {flaw_id}",
        "to": [recipient],
        "body": text_body,
        # We don't want to receive replies as service providers, assumes
        # recipient is a mailing list
        "reply_to": [recipient],
        "headers": {
            "List-Post": f"<mailto:{recipient}>",
        },
    }
    # Celery dynamically adds the .delay() method to task functions at runtime,
    # which static type checkers don't recognize, hence the type ignore
    async_send_email.delay(**payload, html_body=html_body)  # type: ignore[attr-defined]
