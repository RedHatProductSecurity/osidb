from django.core.management.base import BaseCommand

from collectors.cveorg.collectors import CVEorgCollector


class Command(BaseCommand):
    help = "Manual run of the CVEorg collector to create given flaws"

    def add_arguments(self, parser):
        parser.add_argument(
            "cve_ids",
            nargs="+",
            type=str,
            help="List of CVE IDs for which flaws should be created",
        )

    def handle(self, *args, **options):
        cveorg_collector = CVEorgCollector()
        # to ignore date restriction
        cveorg_collector.snippet_creation_start_date = None
        # to ignore keywords restriction
        cveorg_collector.keywords_check_enabled = False

        for cve_id in options["cve_ids"]:
            try:
                self.stdout.write(f"\nCreating a flaw for '{cve_id}'...")
                result = cveorg_collector.collect_cve(cve_id)
                self.stdout.write(result)
            except Exception as exc:
                self.stderr.write(str(exc))
