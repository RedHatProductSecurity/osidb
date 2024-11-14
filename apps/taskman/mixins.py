from django.db import models

from .constants import JIRA_TASKMAN_AUTO_SYNC_FLAW


class JiraTaskSyncMixin(models.Model):
    """
    mixin for syncing the model to the Jira
    this mixin does not perform validation thus it should be
    inherited after other mixins that performs it to ensire data
    correctedness before syncing it
    """

    class Meta:
        abstract = True

    def save(self, *args, diff=None, jira_token=None, **kwargs):
        """
        save the model and sync it to Jira

        Jira sync is conditional based on environment variable
        """
        # complete the save before the sync
        super().save(*args, **kwargs)

        # check taskman conditions are met
        # and eventually perform the sync
        if JIRA_TASKMAN_AUTO_SYNC_FLAW and jira_token is not None:
            self.tasksync(*args, diff=diff, jira_token=jira_token, **kwargs)

    def tasksync(self, *args, jira_token, force_creation=False, **kwargs):
        """
        Jira sync of a specific class instance
        """
        raise NotImplementedError(
            "Inheritants of JiraTaskSyncMixin must implement the tasksync method"
        )
