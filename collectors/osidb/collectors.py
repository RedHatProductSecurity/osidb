"""
OSIDB Collectors
"""
from celery.utils.log import get_task_logger

from osidb.mixins import Alert
from django.contrib.contenttypes.models import ContentType

from collectors.framework.models import Collector

logger = get_task_logger(__name__)


class StaleAlertCollector(Collector):
    """
    Stale Alert Collector
    """

    def collect(self):
        """
        collector run handler

        On every run, this collector will check if the alert is
        still valid by comparing the validation version of the alert
        with the validation version of the instance.

        If the validation version of the alert is different 
        from the validation version of the instance,
        the alert is considered stale and will be deleted.
        """
        logger.info("Collecting Stale Alerts")

        alerts = Alert.objects.all()
        stale_alerts_count = 0

        for alert in alerts:
            instance = alert.content_type.get_object_for_this_type(pk=alert.object_id)
            if alert.validation_version != instance.validation_version:
                alert.delete()
                stale_alerts_count += 1
        
        logger.info("Stale alerts deleted successfully")

        return f"Deleted {stale_alerts_count} Stale Alerts"
