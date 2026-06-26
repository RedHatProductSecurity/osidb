from django.apps import AppConfig


class RegulatoryReportingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "regulatory_reporting"

    def ready(self):
        from . import signals  # noqa: F401
