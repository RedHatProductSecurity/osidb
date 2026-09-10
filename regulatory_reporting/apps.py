from django.apps import AppConfig

from regulatory_reporting.settings import regulatory_reporting_settings


class RegulatoryReportingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "regulatory_reporting"

    def ready(self):
        if (
            regulatory_reporting_settings.notifications_enabled
            or regulatory_reporting_settings.enabled
        ):
            from django.db.models.signals import post_save

            from osidb.models import Flaw

            from .models.upstream import FlawUpstreamMapping
            from .signals import link_mapping_to_notification

        if regulatory_reporting_settings.notifications_enabled:
            from .signals import check_upstream_notifiable

            post_save.connect(check_upstream_notifiable, sender=Flaw)
            post_save.connect(link_mapping_to_notification, sender=FlawUpstreamMapping)
