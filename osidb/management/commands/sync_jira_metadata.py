from django.core.management.base import BaseCommand
from django.utils import timezone

from collectors.framework.models import CollectorMetadata
from collectors.jiraffe.collectors import MetadataCollector


class Command(BaseCommand):
    help = "Synchronizes Jira metadata to OSIDB"

    def handle(self, *args, **options):
        now = timezone.now()
        mc = MetadataCollector()
        mc.collect()

        cm = CollectorMetadata.objects.get(
            name="collectors.jiraffe.tasks.metadata_collector"
        )
        cm.updated_until_dt = now
        cm.data_state = "COMPLETE"
        cm.save()
