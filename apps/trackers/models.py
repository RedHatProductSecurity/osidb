from django.db import models


class JiraProjectFields(models.Model):
    """JIRA project fields"""

    project_key = models.CharField(max_length=50)
    field_id = models.CharField(max_length=50)
    field_name = models.CharField(max_length=50)
    allowed_values = models.JSONField(default=list)

    class Meta:
        unique_together = ("project_key", "field_name")

    def __str__(self):
        return self.field_name
