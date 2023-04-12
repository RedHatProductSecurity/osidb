"""
Taskman - Task Management module

This django application works on a layer above OSIDB in order to provide
models and other abstractions that handle the management of Flaw and FlawDraft
objects.
"""
from django.apps import AppConfig


class TaskmanConfig(AppConfig):
    name = "apps.taskman"

    def ready(self):
        from . import signals  # noqa: F401
