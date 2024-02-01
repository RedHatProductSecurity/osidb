import logging

from bugzilla import Bugzilla
from django.contrib.auth.models import User
from django.db.models.signals import m2m_changed, post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from jira import JIRA

from osidb.helpers import get_env
from osidb.models import Affect, AffectCVSS, Flaw, FlawCVSS, Profile, Tracker

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


@receiver(post_save, sender=User)
def auto_create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(
            user=instance,
            bz_user_id=get_bz_user_id(instance.email),
            jira_user_id=get_jira_user_id(instance.email),
        ).save()


@receiver(pre_save, sender=FlawCVSS)
@receiver(pre_save, sender=AffectCVSS)
def populate_cvss_score(sender, instance, **kwargs):
    instance.score = instance.cvss_object.scores()[0]


@receiver(pre_save, sender=Flaw)
def update_local_updated_dt_flaw(sender, instance, **kwargs):
    instance.local_updated_dt = timezone.now()


@receiver(post_save, sender=Affect)
def update_local_updated_dt_affect(sender, instance, **kwargs):
    instance.flaw.save(auto_timestamps=False, raise_validation_error=False)


@receiver(post_save, sender=Tracker)
@receiver(m2m_changed, sender=Tracker.affects.through)
def update_local_updated_dt_tracker(sender, instance, **kwargs):
    flaws = set()
    for affect in instance.affects.all():
        flaws.add(affect.flaw)
    for flaw in list(flaws):
        flaw.save(auto_timestamps=False, raise_validation_error=False)
