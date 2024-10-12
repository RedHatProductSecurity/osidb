from django.conf import settings
from django.core.management.base import BaseCommand

from osidb.core import set_user_acls
from osidb.models import Flaw, Tracker
from osidb.sync_manager import SyncManager


class Command(BaseCommand):
    def handle(self, *args, **options):
        set_user_acls(settings.ALL_GROUPS)

        print(f"Flaws: {Flaw.objects.count()}")
        print(f"Trackers: {Tracker.objects.count()}")
        print()

        print(
            "Type                 Scheduled   Started  Finished    "
            "Failed   ...cons   ...perm  Resched.   ...cons"
        )
        for object_class in SyncManager.__subclasses__():
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
