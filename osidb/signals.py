import os

from bugzilla import Bugzilla
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from jira import JIRA

from osidb.models import Profile


def get_bz_user_id(email: str) -> str:
    api_key = os.getenv("BZIMPORT_BZ_API_KEY")
    bz_url = os.getenv("BZIMPORT_BZ_URL", "https://bugzilla.redhat.com")
    bz_api = Bugzilla(
        bz_url,
        api_key=api_key,
        force_rest=True,
    )
    users = bz_api.searchusers([email])
    if users:
        return users[0].name
    return ""


def get_jira_user_id(email: str) -> str:
    auth_token = os.getenv("JIRA_AUTH_TOKEN")
    jira_url = os.getenv("JIRA_URL", "https://issues.redhat.com")
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
