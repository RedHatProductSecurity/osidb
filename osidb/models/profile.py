from django.contrib.auth.models import User
from django.db import models

from osidb.exceptions import JiraUserMappingException
from osidb.helpers import get_jira_cloud_id


class Profile(models.Model):
    user = models.OneToOneField(
        User,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    bz_user_id = models.CharField(max_length=100, blank=True)
    jira_user_id = models.CharField(max_length=100, blank=True)
    atlassian_cloud_id = models.CharField(max_length=255, blank=True, default="")

    def __str__(self):
        return self.username

    @property
    def username(self):
        return self.user.username

    @classmethod
    def kerberos_to_cloud_id(cls, kerberos_id: str) -> str:
        """
        return Atlassian Cloud ID for a user
        """
        try:
            profile = cls.objects.get(user__username=kerberos_id)
        except cls.DoesNotExist:
            raise JiraUserMappingException(
                f"No profile found for Kerberos ID:{kerberos_id}"
            )
        if not profile.atlassian_cloud_id:
            profile.atlassian_cloud_id = get_jira_cloud_id(kerberos_id)
            profile.save(update_fields=["atlassian_cloud_id"])
        return profile.atlassian_cloud_id
