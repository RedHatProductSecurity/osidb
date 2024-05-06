from django.core.management.base import BaseCommand
from django.utils import timezone

from collectors.framework.models import CollectorMetadata
from collectors.product_definitions.core import (
    fetch_product_definitions,
    sanitize_product_definitions,
    sync_ps_contacts,
    sync_ps_products_modules,
    sync_ps_update_streams,
)


class Command(BaseCommand):
    help = "Synchronizes product definitions to OSIDB"

    def handle(self, *args, **options):
        now = timezone.now()
        raw_data = fetch_product_definitions()

        (
            ps_products,
            ps_modules,
            ps_update_streams,
            ps_contacts,
        ) = sanitize_product_definitions(raw_data)

        sync_ps_contacts(ps_contacts)
        sync_ps_update_streams(ps_update_streams)
        sync_ps_products_modules(ps_products, ps_modules)

        cm = CollectorMetadata.objects.get(
            name="collectors.product_definitions.tasks.product_definitions_collector"
        )
        cm.updated_until_dt = now
        cm.data_state = "COMPLETE"
        cm.save()
