"""
    osidb-service
"""

from django.apps import AppConfig


class OSIDBConfig(AppConfig):
    name = "osidb"

    def ready(self):
        from . import signals  # pylint: disable=unused-import # noqa: F401
