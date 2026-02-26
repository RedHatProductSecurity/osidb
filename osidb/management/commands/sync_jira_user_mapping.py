from django.core.management.base import BaseCommand
from django.utils import timezone

from collectors.framework.models import CollectorMetadata
from collectors.jira_user_mapping.collectors import JiraUserMappingCollector


class Command(BaseCommand):
    help = "Synchronizes Jira user mapping to OSIDB"

    def handle(self, *args, **options):
        now = timezone.now()
        mc = JiraUserMappingCollector()
        mc.collect()

        cm = CollectorMetadata.objects.get(
            name="collectors.jira_user_mapping.tasks.jira_user_mapping_collector"
        )
        cm.updated_until_dt = now
        cm.data_state = "COMPLETE"
        cm.save()
