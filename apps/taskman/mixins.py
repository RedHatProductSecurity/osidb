from django.db import models

from .constants import JIRA_AUTH_TOKEN, JIRA_EMAIL, JIRA_TASKMAN_AUTO_SYNC_FLAW


class JiraTaskSyncMixin(models.Model):
    """
    mixin for syncing the model to the Jira
    this mixin does not perform validation thus it should be
    inherited after other mixins that performs it to ensure data
    correctedness before syncing it
    """

    class Meta:
        abstract = True

    def save(
        self,
        *args,
        diff=None,
        force_creation=False,
        jira_token=None,
        jira_email=None,
        **kwargs,
    ):
        """
        save the model and sync it to Jira

        Jira sync is conditional based on environment variable
        """
        old_workflow_state = self.workflow_state

        # complete the save before the sync
        super().save(*args, **kwargs)

        # check taskman conditions are met
        # and eventually perform the sync
        if self.workflow_state != old_workflow_state:
            diff = dict(diff or {})
            diff["workflow_state"] = {
                "old": old_workflow_state,
                "new": self.workflow_state,
            }

        if (
            jira_token is None
            and old_workflow_state
            and self.task_key
            and diff
            and "workflow_state" in diff
        ):
            jira_token, jira_email = JIRA_AUTH_TOKEN, JIRA_EMAIL

        if JIRA_TASKMAN_AUTO_SYNC_FLAW and jira_token is not None:
            self.tasksync(
                *args,
                diff=diff,
                force_creation=force_creation,
                jira_token=jira_token,
                jira_email=jira_email,
                **kwargs,
            )

    def tasksync(self, *args, jira_token, jira_email, force_creation=False, **kwargs):
        """
        Jira sync of a specific class instance
        """
        raise NotImplementedError(
            "Inheritants of JiraTaskSyncMixin must implement the tasksync method"
        )
