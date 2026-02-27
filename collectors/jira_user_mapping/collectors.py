"""
Jira user mapping collector
"""

import requests
from celery.utils.log import get_task_logger
from django.conf import settings

from collectors.framework.models import Collector
from osidb.core import set_user_acls
from osidb.models.jira_user_mapping import JiraUserMapping

from .constants import jira_user_mapping_collector_settings

logger = get_task_logger(__name__)


class JiraUserMappingCollector(Collector):
    def collect(self) -> str:
        set_user_acls(settings.ALL_GROUPS)

        url = f"{jira_user_mapping_collector_settings.url}/jira_id/"
        response = requests.get(url, timeout=settings.DEFAULT_REQUEST_TIMEOUT)
        response.raise_for_status()
        entries = response.json()

        created_count = 0
        updated_count = 0

        for entry in entries:
            _, created = JiraUserMapping.objects.update_or_create(
                associate_uuid=entry["associate_uuid"],
                defaults={
                    "associate_kerberos_id": entry["associate_kerberos_id"],
                    "atlassian_cloud_id": entry["atlassian_cloud_id"],
                    "is_employed": entry.get("is_employed", True),
                    "name": entry.get("name", ""),
                },
            )
            if created:
                created_count += 1
            else:
                updated_count += 1

        msg = (
            f"{self.name} finished: "
            f"created {created_count}, updated {updated_count} mappings"
        )
        logger.info(msg)
        return msg
