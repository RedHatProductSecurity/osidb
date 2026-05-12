"""
Affect Creation Engine (ACE)
"""

from django.apps import AppConfig


class ACEConfig(AppConfig):
    name = "apps.ace"
    verbose_name = "Affect Creation Engine"

    def ready(self):
        from . import signals  # noqa: F401
