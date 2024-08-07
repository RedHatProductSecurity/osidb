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

    def save(self, *args, jira_token=None, **kwargs):
        """
        save the model by storing to Jira and then persisting in database
        Jira sync is conditional based on environment variable so
        development environment not enforces it
        """
        if JIRA_TASKMAN_AUTO_SYNC_FLAW and jira_token is not None:
            self.tasksync(*args, jira_token=jira_token, **kwargs)
        else:
            super().save(*args, **kwargs)

    def tasksync(self, *args, jira_token, force_creation=False, **kwargs):
        """
        Jira sync of a specific class instance
        """
        raise NotImplementedError(
            "Inheritants of JiraTaskSyncMixin must implement the tasksync method"
        )
