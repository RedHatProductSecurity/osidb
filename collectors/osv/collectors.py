import copy
import json
import re
from collections.abc import Callable
from decimal import Decimal
from io import BytesIO
from time import sleep
from typing import Any, Union
from zipfile import ZipFile

import requests
from celery.utils.log import get_task_logger
from cvss import CVSS2, CVSS3, CVSS4
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.taskman.constants import JIRA_AUTH_TOKEN, JIRA_EMAIL
from collectors.constants import SNIPPET_CREATION_ENABLED
from collectors.framework.models import Collector
from collectors.osv.constants import OSV_START_DATE
from collectors.utils import convert_cvss_score_to_impact, handle_urls
from osidb.core import set_user_acls
from osidb.models import Flaw, FlawCVSS, FlawReference, Snippet, UpstreamData
from osidb.validators import CVE_RE_STR

logger = get_task_logger(__name__)


def _osv_upstream_purl_dedupe_key(item: Any) -> str | None:
    """Stable id for get_upstream_purls entries: {\"purl\", \"ranges\", \"versions\"}."""
    if isinstance(item, dict) and item.get("purl"):
        return str(item["purl"])
    return None


def _osv_upstream_description_dedupe_key(item: Any) -> str | None:
    """FlawSerializer upstream_descriptions uses ArrayField(TextField)."""
    if not isinstance(item, str):
        return None
    stripped = item.strip()
    return stripped or None


def _osv_upstream_severity_dedupe_key(item: Any) -> str:
    """JSON-shaped entries from get_upstream_severities; compare by canonical JSON."""
    return json.dumps(item, sort_keys=True, default=str)


def _merge_osv_upstream_lists(
    existing: list[Any],
    additions: list[Any],
    dedupe_key: Callable[[Any], Any],
) -> list[Any]:
    """Append additions onto existing, skipping rows whose dedupe_key already appeared."""
    out = list(existing)
    seen: set[Any] = set()
    for row in out:
        k = dedupe_key(row)
        if k is not None:
            seen.add(k)
    for row in additions:
        k = dedupe_key(row)
        if k is None or k in seen:
            continue
        seen.add(k)
        out.append(row)
    return out


_OSV_UPSTREAM_MERGE_SPECS: tuple[tuple[str, Callable[[Any], Any]], ...] = (
    ("upstream_purls", _osv_upstream_purl_dedupe_key),
    ("upstream_descriptions", _osv_upstream_description_dedupe_key),
    ("upstream_severities", _osv_upstream_severity_dedupe_key),
)


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

    def _append_osv_upstream_to_flaw(self, flaw: Flaw, content: dict) -> None:
        """Append OSV-derived upstream_* lists onto UpstreamData (deduped per field)."""
        upstream = UpstreamData.objects.ensure_for_flaw(flaw, source="OSV")

        changed = False
        for field, key_fn in _OSV_UPSTREAM_MERGE_SPECS:
            additions = list(content.get(field) or [])
            if not additions:
                continue
            prior = list(getattr(upstream, field) or [])
            merged = _merge_osv_upstream_lists(prior, additions, key_fn)
            if merged != prior:
                setattr(upstream, field, merged)
                changed = True
        if changed:
            upstream.save(raise_validation_error=False)

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
                if flaw := snippet.convert_snippet_to_flaw(
                    jira_token=JIRA_AUTH_TOKEN, jira_email=JIRA_EMAIL
                ):
                    created_flaws.append(flaw.uuid)
        else:
            for cve_id in cve_ids:
                # Snippet is created only if a flaw with the given CVE iD already exists
                if not Flaw.objects.filter(cve_id=cve_id).exists():
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
                    snippet.convert_snippet_to_flaw(
                        jira_token=JIRA_AUTH_TOKEN, jira_email=JIRA_EMAIL
                    )

                    # The idea is to add upstream info for newly collected OSV vulns
                    flaw = (
                        Flaw.objects.select_for_update().filter(cve_id=cve_id).first()
                    )

                    if flaw:
                        self._append_osv_upstream_to_flaw(flaw, snippet_content)

        return created_snippets, created_flaws

    def extract_content(self, osv_vuln: dict) -> tuple[str, list, dict]:
        """Extract data from an OSV vuln and normalize to Flaw model fields.

        Fields that don't have their equivalents in the Flaw model can be used as well if we
        think they may be useful in the future.
        """

        def get_cve_ids_from_osv_vuln(osv_vuln: dict) -> list[str]:
            # Try to get CVE ID from aliases first (it was the original field to get from)
            vln_aliases_ids = osv_vuln.get("aliases", [])
            vln_aliases_ids.append(osv_vuln.get("id"))

            CVE_ids = {
                alias
                for alias in vln_aliases_ids
                if alias and re.match(CVE_RE_STR, alias)
            }

            return list(CVE_ids)

        cve_ids = get_cve_ids_from_osv_vuln(osv_vuln)
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

        def get_upstream_purls(
            data: dict,
        ) -> list[dict[str, Any]]:
            # https://ossf.github.io/osv-schema/#affected-fields

            affected = data.get("affected", [])
            affected_data = []

            for affect in affected:
                package = affect.get("package") or {}
                upstream_purl = package.get("purl", None)

                # Skip filling in the field if there is no purl
                if not upstream_purl:
                    continue

                # https://ossf.github.io/osv-schema/#affectedranges-field
                ranges = copy.deepcopy(affect.get("ranges", []))

                # https://ossf.github.io/osv-schema/#affectedversions-field
                val = affect.get("versions", [])
                versions = list(val) if val else []

                affected_data.append(
                    {
                        "purl": upstream_purl,
                        "ranges": ranges,
                        "versions": versions,
                    }
                )

            return affected_data

        def get_upstream_severities(data: dict) -> list[Any]:
            # https://ossf.github.io/osv-schema/#severity-field
            # https://ossf.github.io/osv-schema/#affectedseverity-field

            # https://ossf.github.io/osv-schema/#database_specific-field
            # https://ossf.github.io/osv-schema/#affecteddatabase_specific-field

            severities = []

            severity_field = {}
            # Severities are set either at the vulnerability level or the
            # affected level. Databases might also have their own specific
            # severity fields under database_specific; that is independent of
            # whether the standard severity array is present or empty.
            severity = data.get("severity") or []
            if severity:
                severity_field["severity"] = copy.deepcopy(severity)

            if db_specific := data.get("database_specific", None):
                if db_severity := db_specific.get("severity", None):
                    severity_field["db_severity"] = copy.deepcopy(db_severity)

            if not severity:
                # If top-level severity isn't set, check specific affected severities
                affected = data.get("affected", [])
                affect_severities = []

                for affect in affected:
                    affect_severity_field = {}

                    if affect_severity := affect.get("severity", []):
                        affect_severity_field["affect_severity"] = copy.deepcopy(
                            affect_severity
                        )

                    if affect_db_specific := affect.get("database_specific", None):
                        if affect_db_severity := affect_db_specific.get(
                            "severity", None
                        ):
                            affect_severity_field["affect_db_severity"] = copy.deepcopy(
                                affect_db_severity
                            )

                    if affect_severity_field:
                        affect_severities.append(affect_severity_field)

                # Add affected severities to the list
                if affect_severities:
                    severities.append(affect_severities)

            # Add top-level severities to the list
            if severity_field:
                severities.append(severity_field)

            return severities

        cvss_scores, impact = get_cvss_and_impact(osv_vuln)
        comment_zero = get_comment_zero(osv_vuln)
        content = {
            "comment_zero": comment_zero,
            "title": get_title(osv_vuln),
            "cvss_scores": cvss_scores,
            "impact": impact,
            "references": get_refs(osv_vuln),
            "source": Snippet.Source.OSV,
            "unembargo_dt": osv_vuln.get("published"),
            "upstream_purls": get_upstream_purls(osv_vuln),
            "upstream_descriptions": [comment_zero] if comment_zero else [],
            "upstream_severities": get_upstream_severities(osv_vuln),
            # Unused fields that we may extract additional data from later.
            "osv_id": osv_id,
            "osv_affected": osv_vuln.get("affected"),
            "osv_acknowledgments": osv_vuln.get("credits"),
        }

        return osv_id, cve_ids, content
