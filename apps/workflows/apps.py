"""

Workflows Manager

"""

from django.apps import AppConfig


class Workflows(AppConfig):
    """django name"""

    name = "apps.workflows"

    def ready(self):
        from . import signals  # noqa: F401
