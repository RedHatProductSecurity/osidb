from django.core.management.base import BaseCommand

from osidb.models import Flaw, Tracker
from osidb.sync_manager import (
    BZTrackerDownloadManager,
    BZTrackerLinkManager,
    FlawDownloadManager,
    JiraTrackerLinkManager,
)


class Command(BaseCommand):
    def handle(self, *args, **options):
        print(f"Flaws: {Flaw.objects.count()}")
        print(f"Trackers: {Tracker.objects.count()}")
        print()

        print(
            "Type                 Scheduled   Started  Finished    "
            "Failed   ...cons   ...perm  Resched.   ...cons"
        )
        for object_class in [
            FlawDownloadManager,
            BZTrackerDownloadManager,
            BZTrackerLinkManager,
            JiraTrackerLinkManager,
        ]:
            print(
                f"{object_class.__name__[:-7]:20}"
                f"{object_class.objects.filter(last_scheduled_dt__isnull=False).count():10}"
                f"{object_class.objects.filter(last_started_dt__isnull=False).count():10}"
                f"{object_class.objects.filter(last_finished_dt__isnull=False).count():10}"
                f"{object_class.objects.filter(last_failed_dt__isnull=False).count():10}"
                f"{object_class.objects.filter(last_consecutive_failures__gt=0).count():10}"
                f"{object_class.objects.filter(permanently_failed=True).count():10}"
                f"{object_class.objects.filter(last_rescheduled_dt__isnull=False).count():10}"
                f"{object_class.objects.filter(last_consecutive_reschedules__gt=0).count():10}"
            )
