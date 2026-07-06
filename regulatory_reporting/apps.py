from django.apps import AppConfig
from django.conf import settings


class RegulatoryReportingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "regulatory_reporting"

    def ready(self):
        if settings.CRA_NOTIFICATIONS_ENABLED or settings.CRA_REPORTING_ENABLED:
            from django.db.models.signals import post_save

            from osidb.models import Flaw

        if settings.CRA_NOTIFICATIONS_ENABLED:
            from .signals import check_upstream_notifiable

            post_save.connect(check_upstream_notifiable, sender=Flaw)

        if settings.CRA_REPORTING_ENABLED:
            from .signals import create_srp_report

            post_save.connect(create_srp_report, sender=Flaw)
