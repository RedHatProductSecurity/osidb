from django.db import models


class FlawTask(models.Model):
    flaw = models.OneToOneField(
        "osidb.Flaw",
        on_delete=models.CASCADE,
        related_name="+",
    )

    def __str__(self):
        return str(self.pk)


class TaskOwner(models.Model):
    """
    Proxy model for connecting an OSIDB profile to a set of tasks.

    This allows us to have a m2o relationship between a Profile and a set of
    tasks without polluting the OSIDB codebase.
    """

    profile = models.OneToOneField(
        "osidb.Profile",
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="+",
    )
    tasks = models.ForeignKey(
        FlawTask,
        on_delete=models.SET_NULL,
        null=True,
        related_name="owner",
    )

    @property
    def user(self):
        return self.profile.user

    @property
    def bz_user_id(self):
        return self.profile.bz_user_id

    @property
    def jira_user_id(self):
        return self.profile.jira_user_id

    def __str__(self):
        return str(self.pk)
