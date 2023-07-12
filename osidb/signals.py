import logging

from bugzilla import Bugzilla
from django.contrib.auth.models import User
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from jira import JIRA

from osidb.helpers import get_env
from osidb.models import AffectCVSS, FlawCVSS, Profile

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
            {
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
