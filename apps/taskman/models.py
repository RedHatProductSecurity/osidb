from django.db import models


class ScheduledClosingTask(models.Model):
    """This instance represents when a Jira task should be closed if there are no changes"""

    task_key = models.CharField(max_length=50)
    scheduled_dt = models.DateTimeField()

    def __str__(self):
        return f"{self.task_key}: {self.scheduled_dt}"
