from django.contrib.auth.models import User
from django.db import models


class Profile(models.Model):
    user = models.OneToOneField(
        User,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    bz_user_id = models.CharField(max_length=100, blank=True)
    jira_user_id = models.CharField(max_length=100, blank=True)

    @property
    def username(self):
        return self.user.username

    def __str__(self):
        return self.username
