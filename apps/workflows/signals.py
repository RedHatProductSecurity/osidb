from django.db.models.signals import pre_save
from django.dispatch import receiver

from apps.workflows.workflow import WorkflowModel


@receiver(pre_save)
def auto_adjust_classification(sender, instance, **kwargs):
    if issubclass(sender, WorkflowModel):
        if not all([instance.workflow_name, instance.workflow_state]):
            instance.adjust_classification(save=False)
