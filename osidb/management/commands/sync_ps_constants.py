from django.core.management.base import BaseCommand
from django.utils import timezone

from collectors.framework.models import CollectorMetadata
from collectors.ps_constants.tasks import collect_step_1_fetch, collect_step_2_sync


class Command(BaseCommand):
    help = "Synchronizes ps-constants to OSIDB"

    def handle(self, *args, **options):
        now = timezone.now()

        (
            cveorg_keywords,
            sc_packages,
            sla_policies,
            jira_bug_issuetype,
        ) = collect_step_1_fetch()

        collect_step_2_sync(
            cveorg_keywords,
            sc_packages,
            sla_policies,
            jira_bug_issuetype,
        )

        cm = CollectorMetadata.objects.get(
            name="collectors.ps_constants.tasks.ps_constants_collector"
        )
        cm.updated_until_dt = now
        cm.data_state = "COMPLETE"
        cm.save()
