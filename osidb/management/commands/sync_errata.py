from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from collectors.errata.core import get_erratum, link_bugs_to_errata
from osidb.core import set_user_acls


class Command(BaseCommand):
    help = "Synchronize a list of errata by id to OSIDB"

    def add_arguments(self, parser):
        parser.add_argument(
            "errata_id", nargs="*", type=str, help="errata id list (e.g. 1234 5678)"
        )

    def handle(self, *args, **options):
        if not args:
            raise CommandError("You must provide a list of IDs.")
        set_user_acls(settings.ALL_GROUPS)
        erratum_json_list = [get_erratum(errata_id) for errata_id in args]
        link_bugs_to_errata(erratum_json_list)
