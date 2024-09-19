import json
import os
import re
from typing import Union

from celery.utils.log import get_task_logger
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.taskman.constants import JIRA_AUTH_TOKEN
from collectors.cmd import Cmd
from collectors.constants import SNIPPET_CREATION_ENABLED, SNIPPET_CREATION_START_DATE
from collectors.cveorg.constants import CELERY_PVC_PATH
from collectors.framework.models import Collector
from collectors.keywords import should_create_snippet
from collectors.utils import handle_urls
from osidb.core import set_user_acls
from osidb.dmodels.snippet import Snippet
from osidb.models import FlawCVSS, FlawReference

logger = get_task_logger(__name__)


class CVEorgCollectorException(Exception):
    pass


class CVEorgCollector(Collector):
    # Snippet creation is disabled for now
    snippet_creation_enabled = None

    # When the start date is set to None, all snippets are collected
    # When set to a datetime object, only snippets created after that date are collected
    snippet_creation_start_date = SNIPPET_CREATION_START_DATE

    BEGINNING = timezone.datetime(2024, 7, 1, tzinfo=timezone.get_current_timezone())

    REPO_URL = "https://github.com/CVEProject/cvelistV5.git"

    REPO_PATH = f"{CELERY_PVC_PATH}/cvelistV5"
    # Matches e.g. cves/2023/21xxx/CVE-2023-0001.json, cves/2023/22xxx/CVE-2023-22688.json
    CVE_PATH = r"cves/(?:19|20)\d{2}/.*/CVE-(?:1999|2\d{3})-(?!0{4})(?:0\d{3}|[1-9]\d{3,}).json$"

    # From https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_containers_cna_descriptions_contains_lang
    EN_LANG = r"^en([_-][A-Za-z]{4})?([_-]([A-Za-z]{2}|[0-9]{3}))?$"

    def __init__(self) -> None:
        super().__init__()

        if self.snippet_creation_enabled is None:
            self.snippet_creation_enabled = SNIPPET_CREATION_ENABLED

    # Notes for Cmd.run(...) in clone_repo(), update_repo(), get_repo_changes() methods:
    # - shell=False is used to run the command directly, so that Bash injection is not possible.
    # - fail_silently=True is used to ignore stderr output. This does not indicate a real failure, but Cmd.run()
    #   will treat it like one. So we disable this behavior, then check only the return code here instead.

    def clone_repo(self) -> None:
        """
        Clone the cvelistV5 repository if it does not exist.
        """
        if os.path.isdir(self.REPO_PATH):
            return

        logger.info("Cloning the cvelistV5 repository...")

        cmd_parts = ("/usr/bin/git", "clone", self.REPO_URL, self.REPO_PATH)
        result = Cmd.run(
            cmd_parts, cwd=CELERY_PVC_PATH, fail_silently=True, shell=False
        )
        logger.debug(result.stdout)

        if result.returncode == 0:
            logger.info("The repository was successfully cloned.")
        else:
            msg = f"Failed to clone the repository. Returned code: {result.returncode}."
            logger.error(msg)
            raise CVEorgCollectorException(msg)

    def update_repo(self) -> None:
        """
        Update the already existing cvelistV5 repository.
        """
        logger.info("Updating the cvelistV5 repository...")

        cmd_parts = (
            "/usr/bin/git",
            # Our namespaced user is trying to update files on a PVC
            # which we have write access to, but git complains the owner doesn't match
            "-c",
            f"safe.directory={self.REPO_PATH}",
            "pull",
        )
        result = Cmd.run(cmd_parts, cwd=self.REPO_PATH, fail_silently=True, shell=False)
        logger.debug(result.stdout)

        if result.returncode == 0:
            logger.info("The repository was successfully updated.")
        else:
            msg = (
                f"Failed to update the repository. Returned code: {result.returncode}."
            )
            logger.error(msg)
            raise CVEorgCollectorException(msg)

    def get_repo_changes(self) -> tuple[str, timezone.datetime]:
        """
        Fetch recent changes from the cvelistV5 repository specified by timestamps.
        """
        period_start = self.metadata.updated_until_dt or self.BEGINNING
        period_end = timezone.now()

        logger.info("Fetching changes from the cvelistV5 repository...")

        cmd_parts = (
            "/usr/bin/git",
            # Our namespaced user is trying to fetch data on a PVC
            # which we have write access to, but git complains the owner doesn't match
            "-c",
            f"safe.directory={self.REPO_PATH}",
            "log",
            "--after",
            str(period_start),
            "--before",
            str(period_end),
            "--name-only",
            "--pretty=format:",
        )
        result = Cmd.run(cmd_parts, cwd=self.REPO_PATH, fail_silently=True, shell=False)
        logger.debug(result.stdout)

        if result.returncode == 0:
            logger.info("The repository changes were successfully fetched.")
        else:
            msg = f"Failed to fetch the repository changes. Returned code: {result.returncode}."
            logger.error(msg)
            raise CVEorgCollectorException(msg)

        return result.stdout, period_end

    def collect(self) -> str:
        """
        Collect vulnerability data from the cvelistV5 repository and store them in OSIDB.
        """
        if not self.snippet_creation_enabled:
            msg = "Snippet creation is disabled. The CVEorg collector is not running."
            logger.error(msg)
            return msg

        # Set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # Celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

        logger.info("Starting CVEorg data collection.")
        new_snippets = []
        new_flaws = []

        self.clone_repo()
        self.update_repo()
        changes, period_end = self.get_repo_changes()

        file_paths = set(
            f"{self.REPO_PATH}/{f}"
            for f in changes.split("\n")
            if re.search(self.CVE_PATH, f)
        )
        for file_path in file_paths:
            with open(file_path) as file:
                file_content = json.load(file)
                if file_content["cveMetadata"]["state"] == "PUBLISHED":
                    try:
                        content = self.extract_content(file_content)
                    except Exception as exc:
                        msg = f"Failed to parse data from the {file_path} file: {exc}"
                        logger.error(msg)
                        continue

                    try:
                        with transaction.atomic():
                            new_snippet, new_flaw = self.save_snippet_and_flaw(content)
                            if new_snippet:
                                new_snippets.append(content["cve_id"])
                            if new_flaw:
                                new_flaws.append(content["cve_id"])
                    except Exception as exc:
                        message = f"Failed to save snippet and flaw for {content['cve_id']}. Error: {exc}."
                        logger.error(message)
                        raise CVEorgCollectorException(message) from exc

        updated_until = period_end
        self.store(complete=True, updated_until_dt=updated_until)
        msg = (
            f"{self.name} is updated until {updated_until}."
            f"Created snippets: {', '.join(new_snippets) if new_snippets else 'none'}. "
            f"Created CVEs from snippets: {', '.join(new_flaws) if new_flaws else 'none'}."
        )
        logger.info("CVEorg sync was successful.")
        return msg

    def save_snippet_and_flaw(self, content: dict) -> tuple[bool, bool]:
        """
        Create and save snippet with flaw from normalized `content` if they do not already exist.
        The creation is restricted by the published date and allowed keywords.
        """
        snippet_created = False
        flaw_created = False

        # If unembargo_dt is missing, a flaw is always created to avoid missing anything important
        if self.snippet_creation_start_date and content["unembargo_dt"]:
            if self.snippet_creation_start_date >= parse_datetime(
                content["unembargo_dt"]
            ):
                return False, False

        if should_create_snippet(content["comment_zero"]):
            snippet, snippet_created = Snippet.objects.get_or_create(
                source=Snippet.Source.CVEORG,
                external_id=content["cve_id"],
                defaults={"content": content},
            )
            if snippet_created:
                flaw_created = bool(
                    snippet.convert_snippet_to_flaw(jira_token=JIRA_AUTH_TOKEN)
                )

        return snippet_created, flaw_created

    def extract_content(self, content: dict) -> dict:
        """
        Extract data from raw `content` and normalize to Flaw model fields.
        CVE format is described in https://cveproject.github.io/cve-schema/schema/docs.
        """

        def get_comment_zero(data: dict) -> str:
            return [
                d["value"]
                for d in data["containers"]["cna"]["descriptions"]
                if re.match(self.EN_LANG, d["lang"])
            ][0]

        def get_cvss(data: dict) -> list:
            scores = []
            mapping = {
                "cvssV2_0": FlawCVSS.CVSSVersion.VERSION2,
                "cvssV3_0": FlawCVSS.CVSSVersion.VERSION3,
                "cvssV3_1": FlawCVSS.CVSSVersion.VERSION3,
                "cvssV4_0": FlawCVSS.CVSSVersion.VERSION4,
            }

            if metrics := data["containers"]["cna"].get("metrics"):
                # Keep only data we are interested in
                cvss_pairs = {
                    version: cvss_data["vectorString"]
                    for cvss in metrics
                    for version, cvss_data in cvss.items()
                    if version in list(mapping.keys())
                }
                # Only one CVSS v3 can be stored
                if bool(cvss_pairs.get("cvssV3_0") and cvss_pairs.get("cvssV3_1")):
                    cvss_pairs.pop("cvssV3_0")

                for version, vector in cvss_pairs.items():
                    scores.append(
                        {
                            "issuer": FlawCVSS.CVSSIssuer.CVEORG,
                            "version": mapping[version],
                            "vector": vector,
                            # Actual score is generated automatically when FlawCVSS is saved
                        }
                    )
            return scores

        def get_cwes(data: dict) -> str:
            if problem_types := data["containers"]["cna"].get("problemTypes"):
                ids = [
                    d.get("cweId")
                    for problem in problem_types
                    for d in problem["descriptions"]
                    if d.get("type") == "CWE" and d.get("cweId")
                ]
                if len(ids) == 1:
                    return ids[0]
                elif len(ids) > 1:
                    return f"({'|'.join(sorted(ids))})"
            return ""

        def get_refs(data: dict) -> list:
            references = [
                {
                    "type": FlawReference.FlawReferenceType.SOURCE,
                    "url": f"https://www.cve.org/CVERecord?id={data['cveMetadata']['cveId']}",
                }
            ]
            external = list(
                set([r["url"] for r in data["containers"]["cna"]["references"]])
            )
            references.extend(handle_urls(external, references[0]["url"]))
            return references

        def get_title(data: dict) -> str:
            return data["containers"]["cna"].get("title", "From CVEorg collector")

        def get_unembargo_dt(data: dict) -> Union[str, None]:
            if published := data["cveMetadata"].get("datePublished"):
                return published if published.endswith("Z") else f"{published}Z"
            # If datePublished is missing, check dateUpdated as it has a similar meaning
            if updated := data["containers"]["cna"]["providerMetadata"].get(
                "dateUpdated"
            ):
                return updated if updated.endswith("Z") else f"{updated}Z"
            return None

        return {
            "comment_zero": get_comment_zero(content),
            "cve_id": content["cveMetadata"]["cveId"],
            "cvss_scores": get_cvss(content),
            "cwe_id": get_cwes(content),
            "references": get_refs(content),
            "source": Snippet.Source.CVEORG,
            "title": get_title(content),
            "unembargo_dt": get_unembargo_dt(content),
        }