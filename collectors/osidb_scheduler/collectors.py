"""
OSIDB Collectors
"""
from celery.utils.log import get_task_logger

from collectors.framework.models import Collector
from osidb.mixins import Alert

logger = get_task_logger(__name__)


class StaleAlertCollector(Collector):
    """
    Stale Alert Collector
    """

    def collect(self):
        """
        collector run handler

        On every run, this collector will check if the alert is
        still valid by comparing the creation time of the alert
        with the validation time of the Model.

        If the creation time of the alert is older than
        the validation time of the Model,
        the alert is considered stale and will be deleted.
        """
        logger.info("Collecting Stale Alerts")

        alerts = Alert.objects.all()
        stale_alerts_count = 0

        for alert in alerts:
            instance = alert.content_type.get_object_for_this_type(pk=alert.object_id)
            if alert.created_dt < instance.last_validated_dt:
                alert.delete()
                stale_alerts_count += 1

        logger.info("Stale alerts deleted successfully")

        return f"Deleted {stale_alerts_count} Stale Alerts"
