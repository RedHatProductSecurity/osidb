from django.core.management.base import BaseCommand
from django.utils import timezone

from collectors.flaw_labels.core import fetch_flaw_labels, sync_flaw_labels
from collectors.flaw_labels.tasks import FLAW_LABELS_URL
from collectors.framework.models import CollectorMetadata


class Command(BaseCommand):
    help = "Synchronizes flaw labels definitions to OSIDB"

    def handle(self, *args, **options):
        now = timezone.now()
        context_based, product_based = fetch_flaw_labels(FLAW_LABELS_URL)

        sync_flaw_labels(context_based, product_based)
        cm = CollectorMetadata.objects.get(
            name="collectors.flaw_labels.tasks.flaw_labels_collector"
        )
        cm.updated_until_dt = now
        cm.data_state = "COMPLETE"
        cm.save()
