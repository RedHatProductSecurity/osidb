from django.db.models.signals import pre_save
from django.dispatch import Signal, receiver

from apps.workflows.workflow import WorkflowModel

# Custom signal emitted when workflow classification changes.
# Arguments: sender (model class), instance, old_classification (dict), new_classification (dict)
classification_changed = Signal()


@receiver(pre_save)
def auto_adjust_classification(sender, instance, **kwargs):
    if issubclass(sender, WorkflowModel):
        instance.adjust_classification(save=False)
