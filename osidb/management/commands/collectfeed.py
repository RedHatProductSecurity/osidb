import logging
import traceback

from django.core.management.base import BaseCommand

from collectors.feed.collectors import FeedCollector


class Command(BaseCommand):
    help = "Runs feed collector to create new Snippets and draft Flaws in OSIDB"

    def handle(self, *args, **options):
        if options["verbosity"] != 3:
            logging.disable(logging.CRITICAL)
        collector = FeedCollector()
        self.stdout.write("Fetching feeds...", ending="")
        try:
            collector.collect()
        except Exception as e:
            self.stdout.write(self.style.ERROR("FAIL"))
            if options["verbosity"] == 2:
                self.stdout.write(f"Exception: {e}")
            elif options["verbosity"] == 3:
                self.stdout.write(traceback.format_exc())
        else:
            self.stdout.write(self.style.SUCCESS("OK"))
        logging.disable(logging.NOTSET)
