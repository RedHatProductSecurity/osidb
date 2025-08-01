import json
import re
from decimal import Decimal
from io import BytesIO
from time import sleep
from typing import Union
from zipfile import ZipFile

import requests
from celery.utils.log import get_task_logger
from cvss import CVSS2, CVSS3, CVSS4
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.taskman.constants import JIRA_AUTH_TOKEN
from collectors.constants import SNIPPET_CREATION_ENABLED
from collectors.framework.models import Collector
from collectors.osv.constants import OSV_START_DATE
from collectors.utils import convert_cvss_score_to_impact, handle_urls
from osidb.core import set_user_acls
from osidb.models import Flaw, FlawCVSS, FlawReference, Snippet
from osidb.validators import CVE_RE_STR

logger = get_task_logger(__name__)


class OSVCollectorException(Exception):
    """exception for OSV Collector"""


class OSVCollector(Collector):
    # Snippet creation is disabled for now
    snippet_creation_enabled = None

    # When the start date is set to None, all snippets are collected
    # When set to a datetime object, only snippets created after that date are collected
    snippet_creation_start_date = OSV_START_DATE

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

    CVSS_TO_FLAWCVSS = {
        "CVSS_V2": FlawCVSS.CVSSVersion.VERSION2,
        "CVSS_V3": FlawCVSS.CVSSVersion.VERSION3,
        "CVSS_V4": FlawCVSS.CVSSVersion.VERSION4,
    }

    CVSS_TO_CVSSLIB = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}

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
        if not self.snippet_creation_enabled:
            msg = "Snippet creation is disabled. The OSV collector is not running."
            logger.error(msg)
            return msg

        # Set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # Celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

        logger.info("Starting OSV data collection")
        new_snippets = []
        new_flaws = []

        # Collection of one osv_id is currently used only in tests
        if osv_id is not None:
            # Surface an exception when collecting an individual OSV vulnerability
            osv_vuln = self.fetch_osv_vuln_by_id(osv_id)
            osv_id, cve_ids, content = self.extract_content(osv_vuln)
            try:
                with transaction.atomic():
                    self.save_snippet_and_flaw(osv_id, cve_ids, content)
            except Exception as exc:
                message = f"Failed to save snippet and flaw for {osv_id}. Error: {exc}."
                logger.error(message)
                raise OSVCollectorException(message) from exc
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
                        with transaction.atomic():
                            (
                                created_snippets,
                                created_flaws,
                            ) = self.save_snippet_and_flaw(osv_id, cve_ids, content)
                            new_snippets.extend(created_snippets)
                            new_flaws.extend(created_flaws)
                        # introduce a small delay after each transaction to not hit the Jira rate limit
                        if created_flaws:
                            sleep(1)
                    except Exception as exc:
                        message = f"Failed to save snippet and flaw for {osv_id}. Error: {exc}."
                        logger.error(message)
                        raise OSVCollectorException(message) from exc
            except requests.exceptions.RequestException as exc:
                logger.error(f"Failed to fetch OSV vulns for {ecosystem}: {exc}")
                continue

        updated_until = timezone.now()
        self.store(complete=True, updated_until_dt=updated_until)
        msg = (
            f"{self.name} is updated until {updated_until}."
            f"Created snippets: {f'{len(new_snippets)} {tuple(new_snippets)}' if new_snippets else '0'}. "
            f"Created CVEs from snippets: {f'{len(new_flaws)} {tuple(new_flaws)}' if new_flaws else '0'}."
        )
        logger.info("OSV sync was successful.")
        return msg

    def save_snippet_and_flaw(
        self, osv_id: str, cve_ids: list[str], content: dict
    ) -> tuple[list[str], list[str]]:
        """Save snippet(s) and flaw per OSV vuln and return IDs of created snippets and flaws.

        If vuln does not contain CVE ID, one snippet and flaw are created.
        If vuln contains CVE ID(s), a snippet is created for each CVE ID whose flaw already exists in DB.

        Creating each snippet per CVE allows us to link them to unique Flaws (which also contain
        single CVE IDs), and reuse their data for the creation of those flaws.
        """
        if self.snippet_creation_start_date and (
            self.snippet_creation_start_date >= parse_datetime(content["unembargo_dt"])
        ):
            return [], []

        created_snippets = []
        created_flaws = []

        if not cve_ids:
            # This keeps the structure consistent and ease snippets filtering without cve_id
            content["cve_id"] = None
            snippet, snippet_created = Snippet.objects.update_or_create(
                source=Snippet.Source.OSV,
                external_id=osv_id,
                defaults={"content": content},
            )
            if snippet_created:
                created_snippets.append(osv_id)
                # We store flaw uuid as CVE ID is not present
                if flaw := snippet.convert_snippet_to_flaw(jira_token=JIRA_AUTH_TOKEN):
                    created_flaws.append(flaw.uuid)
        else:
            for cve_id in cve_ids:
                # Snippet is created only if a flaw with the given CVE iD already exists
                if not Flaw.objects.filter(cve_id=cve_id):
                    continue
                snippet_content = content.copy()
                snippet_content["cve_id"] = cve_id
                # We need a unique ID and because we're creating a separate snippet for each
                # CVE ID we can create a unique ID by appending that CVE ID to the OSV ID.
                external_id = f"{osv_id}/{cve_id}"
                snippet, snippet_created = Snippet.objects.update_or_create(
                    source=Snippet.Source.OSV,
                    external_id=external_id,
                    defaults={"content": snippet_content},
                )
                if snippet_created:
                    created_snippets.append(external_id)
                    # Only links snippet to already existing flaw
                    snippet.convert_snippet_to_flaw(jira_token=JIRA_AUTH_TOKEN)

        return created_snippets, created_flaws

    def extract_content(self, osv_vuln: dict) -> tuple[str, list, dict]:
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

        def get_cvss_and_impact(data: dict) -> tuple[list, str]:
            # https://ossf.github.io/osv-schema/#severity-field

            # Create resulted CVSS and get the highest score for Impact calculation
            cvss_data = []
            highest_score = Decimal("0.0")
            for cvss in data.get("severity", []):
                if cvss["type"] not in self.CVSS_TO_FLAWCVSS:
                    # Skip unsupported score types
                    continue
                vector = cvss["score"]
                try:
                    score = self.CVSS_TO_CVSSLIB[cvss["type"]](vector).base_score
                except Exception as exc:
                    logger.error(f"Failed to proces CVSS for {cvss}. Error: {exc}.")
                    # TODO: Recheck invalid CVSS once SyncManager gets implemented
                    continue
                cvss_data.append(
                    {
                        "issuer": FlawCVSS.CVSSIssuer.OSV,
                        "version": self.CVSS_TO_FLAWCVSS[cvss["type"]],
                        "vector": vector,
                        # Actual score is generated automatically when FlawCVSS is saved
                    }
                )
                if score > highest_score:
                    highest_score = score

            # Create resulted Impact
            highest_impact = convert_cvss_score_to_impact(highest_score)

            return cvss_data, highest_impact

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

        cvss_scores, impact = get_cvss_and_impact(osv_vuln)
        content = {
            "comment_zero": get_comment_zero(osv_vuln),
            "title": get_title(osv_vuln),
            "cvss_scores": cvss_scores,
            "cwe_id": get_cwes(osv_vuln),
            "impact": impact,
            "references": get_refs(osv_vuln),
            "source": Snippet.Source.OSV,
            "unembargo_dt": osv_vuln.get("published"),
            # Unused fields that we may extract additional data from later.
            "osv_id": osv_id,
            "osv_affected": osv_vuln.get("affected"),
            "osv_acknowledgments": osv_vuln.get("credits"),
        }

        return osv_id, cve_ids, content
