import json

from django.core.management.base import BaseCommand

from osidb.change_log import compact_change_events
from osidb.helpers import bypass_rls


class Command(BaseCommand):
    help = "Compact internal change records in short batches; default retains only live heads"

    def add_arguments(self, parser):
        parser.add_argument("--batch-size", type=int, default=1000)
        parser.add_argument("--history-days", type=int, default=0)
        parser.add_argument("--max-batches", type=int, default=1000)
        parser.add_argument("--seconds", type=float, default=60)

    @bypass_rls
    def handle(self, *args, **options):
        self.stdout.write(
            json.dumps(
                compact_change_events(
                    **{
                        key: options[key]
                        for key in (
                            "batch_size",
                            "history_days",
                            "max_batches",
                            "seconds",
                        )
                    }
                )
            )
        )
