import json
import re
from io import BytesIO
from typing import Union
from zipfile import ZipFile

import requests
from celery.utils.log import get_task_logger
from django.conf import settings
from django.utils import dateparse, timezone

from apps.taskman.constants import JIRA_AUTH_TOKEN
from collectors.constants import SNIPPET_CREATION_ENABLED, SNIPPET_CREATION_START_DATE
from collectors.framework.models import Collector
from collectors.utils import handle_urls
from osidb.core import set_user_acls
from osidb.models import FlawCVSS, FlawReference, Snippet
from osidb.validators import CVE_RE_STR

logger = get_task_logger(__name__)


class OSVCollector(Collector):
    # Snippet creation is disabled for now
    snippet_creation_enabled = None

    # When the start date is set to None, all snippets are collected
    # When set to a datetime object, only snippets created after that date are collected
    snippet_creation_start_date = SNIPPET_CREATION_START_DATE

    SUPPORTED_OSV_ECOSYSTEMS = (
        "Bitnami",  # General purpose Vulnerability Database: https://github.com/bitnami/vulndb
        "Go",
        # "Hackage",  # TODO: do we ship any Haskell packages?
        # "Hex",  # TODO: do we ship any Erlang packages?
        "Linux",  # Linux kernel vulnerabilities
        "Maven",  # Java package ecosystem
        "NuGet",  # .NET package ecosystem
        "Packagist",  # Do we ship any PHP packages (besides PHP itself?)
        # "Pub",  # TODO: Do we ship any Dart packages?
        "PyPI",  # Python package ecosystem
        "RubyGems",  # Ruby package ecosystem
        "crates.io",  # Rust package ecosystem
        "npm",  # JavaScript package ecosystem
    )

    # On top of fetching vulnerabilities for certain ecosystems only (see above), we also need to
    # filter individual OSV vulnerabilities by their ID prefix. For example, we are not
    # interested in reported malicious packages (in any ecosystem) that have a prefix of "MAL-".
    OSV_VULN_ID_SKIPLIST = (
        # Malicious packages as recorded in https://github.com/ossf/malicious-packages
        "MAL",
        # Global Security Database: https://github.com/cloudsecurityalliance/gsd-database
        # Too noisy; every single kernel commit seems to get an auto-assigned GSD identifier
        # without actually determining if it fixes a security issue.
        "GSD",
    )

    # Browseable web UI: https://console.cloud.google.com/storage/browser/osv-vulnerabilities
    OSV_DATA_SNAPSHOT_URL = "https://storage.googleapis.com/osv-vulnerabilities"
    # API docs: https://google.github.io/osv.dev/api/
    OSV_VULNS_API_URL = "https://api.osv.dev/v1/vulns"

    def __init__(self):
        """initiate collector"""
        super().__init__()
        if self.snippet_creation_enabled is None:
            self.snippet_creation_enabled = SNIPPET_CREATION_ENABLED

    def fetch_osv_vulns_for_ecosystem(self, ecosystem: str) -> dict:
        # Download the ZIP file from the URL
        url = f"{self.OSV_DATA_SNAPSHOT_URL}/{ecosystem}/all.zip"
        response = requests.get(url, timeout=settings.DEFAULT_REQUEST_TIMEOUT)
        response.raise_for_status()

        zip_archive = BytesIO(response.content)
        with ZipFile(zip_archive) as z:
            file_list = z.namelist()
            for file_name in file_list:
                file_content = z.read(file_name).decode("utf-8")
                try:
                    data = json.loads(file_content)
                except json.JSONDecodeError as exc:
                    logger.error(
                        f"Failed to read JSON from {ecosystem}/{file_name}: {exc}"
                    )
                    continue
                yield data

    def fetch_osv_vuln_by_id(self, osv_id: str) -> dict:
        url = f"{self.OSV_VULNS_API_URL}/{osv_id}"
        response = requests.get(url, timeout=settings.DEFAULT_REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def collect(self, osv_id: Union[str, None] = None) -> str:
        """Collect vulnerability data for each supported ecosystem."""
        # Set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # Celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

        logger.info("Starting OSV data collection")
        new_count, updated_count = 0, 0

        if osv_id is not None:
            # Surface an exception when collecting an individual OSV vulnerability
            osv_vuln = self.fetch_osv_vuln_by_id(osv_id)
            osv_id, cve_ids, content = self.extract_content(osv_vuln)
            self.save_snippet(osv_id, cve_ids, content)
            return f"OSV collection for {osv_id} was successful."

        for ecosystem in self.SUPPORTED_OSV_ECOSYSTEMS:
            # Catch and report exceptions for individual ecosystems that we fail to download data
            # for, but continue for others that work.
            logger.info(f"Fetching and processing data for {ecosystem} OSV ecosystem")
            try:
                for osv_vuln in self.fetch_osv_vulns_for_ecosystem(ecosystem):
                    try:
                        osv_id, cve_ids, content = self.extract_content(osv_vuln)
                    except Exception as exc:
                        logger.error(
                            f"Failed to parse data from {osv_vuln['id']} vulnerability: {exc}"
                        )
                        continue

                    if any(
                        osv_id.startswith(prefix)
                        for prefix in self.OSV_VULN_ID_SKIPLIST
                    ):
                        continue
                    try:
                        created, updated = self.save_snippet(osv_id, cve_ids, content)
                    except Exception as exc:
                        logger.error(
                            f"Failed to save snippet data for {osv_id} (error: {exc}): {content}"
                        )
                        continue
                    new_count += created
                    updated_count += updated
            except requests.exceptions.RequestException as exc:
                logger.error(f"Failed to fetch OSV vulns for {ecosystem}: {exc}")
                continue

        updated_until = timezone.now()
        self.store(complete=True, updated_until_dt=updated_until)
        msg = (
            f"{self.name} is updated until {updated_until}."
            f"New snippets saved: {new_count}; updated snippets: {updated_count}"
        )
        logger.info("OSV sync was successful.")
        return msg

    def save_snippet(
        self, osv_id: str, cve_ids: list, content: dict
    ) -> tuple[int, int]:
        """Save one snippet per CVE and return numbers of updated or created snippets.

        Creating each snippet per CVE allows us to link them to unique Flaws (which also contain
        single CVE IDs), and reuse their data for the creation of those flaws.
        """
        if not self.snippet_creation_enabled:
            return 0, 0

        if self.snippet_creation_start_date and (
            self.snippet_creation_start_date
            >= dateparse.parse_datetime(content["published_in_osv"])
        ):
            return 0, 0

        if not cve_ids:
            # This keeps the structure consistent and ease snippets filtering without cve_id
            content["cve_id"] = None
            snippet, created = Snippet.objects.update_or_create(
                source=Snippet.Source.OSV,
                external_id=osv_id,
                defaults={"content": content},
            )
            if created:
                snippet.convert_snippet_to_flaw(jira_token=JIRA_AUTH_TOKEN)
                return 1, 0
            else:
                return 0, 1
        else:
            created, updated = 0, 0
            for cve_id in cve_ids:
                snippet_content = content.copy()
                snippet_content["cve_id"] = cve_id
                # We need a unique ID and because we're creating a separate snippet for each
                # CVE ID we can create a unique ID by appending that CVE ID to the OSV ID.
                external_id = f"{osv_id}/{cve_id}"
                snippet, created = Snippet.objects.update_or_create(
                    source=Snippet.Source.OSV,
                    external_id=external_id,
                    defaults={"content": snippet_content},
                )
                if created:
                    snippet.convert_snippet_to_flaw(jira_token=JIRA_AUTH_TOKEN)
                    created += 1
                else:
                    updated += 1
            return created, updated

    @staticmethod
    def extract_content(osv_vuln: dict) -> tuple[str, list, dict]:
        """Extract data from an OSV vuln and normalize to Flaw model fields.

        Fields that don't have their equivalents in the Flaw model can be used as well if we
        think they may be useful in the future.
        """
        cve_ids = [
            alias
            for alias in osv_vuln.get("aliases", [])
            if re.match(CVE_RE_STR, alias)
        ]
        osv_id = osv_vuln["id"]

        def get_refs(data: dict) -> list:
            #  https://ossf.github.io/osv-schema/#references-field
            refs = [
                {
                    "type": FlawReference.FlawReferenceType.SOURCE,
                    "url": f"https://osv.dev/vulnerability/{osv_id}",
                }
            ]
            refs.extend(
                handle_urls(
                    [r["url"] for r in data.get("references", [])], refs[0]["url"]
                )
            )

            return refs

        def get_comment_zero(data: dict) -> str:
            #  https://ossf.github.io/osv-schema/#summary-details-fields
            return data.get("details", "")

        def get_title(data: dict) -> str:
            #  https://ossf.github.io/osv-schema/#summary-details-fields
            return data.get("summary", "From OSV collector")

        def get_cvss(data: dict) -> list:
            # https://ossf.github.io/osv-schema/#severity-field
            scores = []
            mapping = {
                "CVSS_V2": FlawCVSS.CVSSVersion.VERSION2,
                "CVSS_V3": FlawCVSS.CVSSVersion.VERSION3,
            }
            for cvss in data.get("severity", []):
                if not cvss["type"] in mapping:
                    # Skip unsupported score types
                    continue
                scores.append(
                    {
                        "issuer": FlawCVSS.CVSSIssuer.OSV,
                        "version": mapping[cvss["type"]],
                        # OSV "score" attribute is really a vector string
                        "vector": cvss["score"],
                        # Actual score is generated automatically when FlawCVSS is saved
                    }
                )
            return scores

        def get_cwes(data: dict) -> str:
            #  https://ossf.github.io/osv-schema/#database_specific-field
            ids = [
                cwe_id
                for cwe_id in data.get("database_specific", {}).get("cwe_ids", [])
            ]
            if len(ids) > 1:
                return "(" + "|".join(sorted(ids)) + ")"
            elif len(ids) == 1:
                return ids[0]
            else:
                return ""

        content = {
            "comment_zero": get_comment_zero(osv_vuln),
            "title": get_title(osv_vuln),
            "cvss_scores": get_cvss(osv_vuln),
            "cwe_id": get_cwes(osv_vuln),
            "references": get_refs(osv_vuln),
            "source": Snippet.Source.OSV,
            # Unused fields that we may extract additional data from later.
            "osv_id": osv_id,
            "osv_affected": osv_vuln.get("affected"),
            "osv_acknowledgments": osv_vuln.get("credits"),
            # Required for ignoring historical data
            "published_in_osv": osv_vuln.get("published"),
        }

        return osv_id, cve_ids, content
