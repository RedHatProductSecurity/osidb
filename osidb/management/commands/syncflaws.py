import logging
import traceback

from django.core.management.base import BaseCommand

from collectors.bzimport.collectors import FlawCollector


class Command(BaseCommand):
    help = "Synchronizes a list of Bugzilla IDs to OSIDB"

    def add_arguments(self, parser):
        parser.add_argument(
            "bz_ids", nargs="+", type=str, help="List of bugzilla IDs or CVEs"
        )

    def handle(self, *args, **options):
        if options["verbosity"] != 3:
            logging.disable(logging.CRITICAL)
        fc = FlawCollector()
        for bz_id in options["bz_ids"]:
            self.stdout.write(
                f"Synchronizing {bz_id}...",
                ending="",
            )
            try:
                fc.sync_flaw(bz_id)
            except Exception as e:
                self.stdout.write(self.style.ERROR("FAIL"))
                if options["verbosity"] == 2:
                    self.stdout.write(f"Exception: {e}")
                elif options["verbosity"] == 3:
                    self.stdout.write(traceback.format_exc())
            else:
                self.stdout.write(self.style.SUCCESS("OK"))
        logging.disable(logging.NOTSET)
