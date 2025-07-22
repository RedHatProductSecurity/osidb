from django.core.management.base import BaseCommand
from django.db import transaction

from collectors.bzimport.constants import BZ_API_KEY
from collectors.jiraffe.constants import JIRA_TOKEN
from osidb.helpers import bypass_rls
from osidb.models import Affect


class Command(BaseCommand):
    help = "Migrates a PsModule, PsComponent combination to another."

    def add_arguments(self, parser):
        parser.add_argument("ps_module", type=str, help="PsModule")
        parser.add_argument("from_component", type=str, help="Existing PsComponent")
        parser.add_argument("to_component", type=str, help="New PsComponent")
        parser.add_argument("--bz-api-key", type=str, help="Custom BZ API Key")
        parser.add_argument("--jira-token", type=str, help="Custom JIRA Token")

    @bypass_rls
    def handle(self, *args, **options):
        affects_to_change = Affect.objects.select_for_update().filter(
            ps_module=options["ps_module"],
            ps_component=options["from_component"],
        )
        count = affects_to_change.count()

        if not count:
            self.stdout.write(
                self.style.WARNING(
                    "No affects with the given PsModule / PsComponent combination were found."
                )
            )
            return

        self.stdout.write(f"Migrating {count} affects.")
        bz_api_key = options.get("bz_api_key") or BZ_API_KEY
        jira_token = options.get("jira_token") or JIRA_TOKEN

        with transaction.atomic():
            for affect in affects_to_change:
                self.stdout.write(f"Updating Affect ({affect.uuid})...", ending="")
                affect.ps_component = options["to_component"]
                affect.save(raise_validation_error=False)
                self.stdout.write(self.style.SUCCESS("OK"))

                trackers = affect.trackers.select_for_update().all()
                for tracker in trackers:
                    self.stdout.write(
                        f" => Updating related Tracker ({tracker.uuid}, {tracker.external_system_id})...",
                        ending="",
                    )
                    tracker.save(
                        bz_api_key=bz_api_key,
                        jira_token=jira_token,
                        raise_validation_error=False,
                    )
                    self.stdout.write(self.style.SUCCESS("OK"))
