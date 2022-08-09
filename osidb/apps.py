"""
    osidb-service
"""

from django.apps import AppConfig


class OSIDBConfig(AppConfig):
    name = "osidb"

    def ready(self):
        from . import signals  # noqa: F401
