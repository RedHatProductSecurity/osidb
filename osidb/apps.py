"""
osidb-service
"""

from django.apps import AppConfig


class OSIDBConfig(AppConfig):
    name = "osidb"

    def ready(self):
        from . import signals  # noqa: F401
        from .watermark_triggers import register_all_watermark_triggers

        register_all_watermark_triggers()
