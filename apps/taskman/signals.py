from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.taskman.models import TaskOwner
from osidb.models import Profile


@receiver(post_save, sender=Profile)
def auto_create_task_owner(sender, instance, created, **kwargs):
    if created:
        TaskOwner.objects.create(profile=instance).save()
