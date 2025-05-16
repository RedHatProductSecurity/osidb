import json
import os
import re
from collections import defaultdict
from decimal import Decimal
from time import sleep
from typing import Any, Union

from celery.utils.log import get_task_logger
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.taskman.constants import JIRA_AUTH_TOKEN
from collectors.cmd import Cmd
from collectors.constants import SNIPPET_CREATION_ENABLED
from collectors.cveorg.constants import (
    CELERY_PVC_PATH,
    CISA_ORG_ID,
    CVEORG_START_DATE,
    KEYWORDS_CHECK_ENABLED,
)
from collectors.cveorg.keywords import should_create_snippet
from collectors.framework.models import Collector
from collectors.utils import convert_cvss_score_to_impact, handle_urls
from osidb.core import set_user_acls
from osidb.models import Flaw, FlawCVSS, FlawReference, Snippet
from osidb.validators import CVE_RE_STR

logger = get_task_logger(__name__)


class CVEorgCollectorException(Exception):
    pass


class CVEorgCollector(Collector):
    # Controls whether the collector is enabled, default to True
    snippet_creation_enabled = SNIPPET_CREATION_ENABLED

    # Restricts the snippet and flaw creation by published date, default to "2024-10-01"
    # If set to a string date, CVEs older than that date will be ignored; if set to None, the restriction is disabled
    snippet_creation_start_date = CVEORG_START_DATE

    # Restricts the snippet and flaw creation by keywords, default to True
    # If set to True, CVEs not complying with keywords will be ignored; if set to False, the restriction is disabled
    keywords_check_enabled = KEYWORDS_CHECK_ENABLED

    BEGINNING = timezone.datetime(2024, 10, 1, tzinfo=timezone.get_current_timezone())

    REPO_URL = "https://github.com/CVEProject/cvelistV5.git"

    REPO_PATH = f"{CELERY_PVC_PATH}/cvelistV5"
    # Matches e.g. cves/2023/21xxx/CVE-2023-0001.json, cves/2023/22xxx/CVE-2023-22688.json
    CVE_PATH = r"cves/(?:19|20)\d{2}/.*/CVE-(?:1999|2\d{3})-(?!0{4})(?:0\d{3}|[1-9]\d{3,}).json$"

    # From https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_containers_cna_descriptions_contains_lang
    EN_LANG = r"^en([_-][A-Za-z]{4})?([_-]([A-Za-z]{2}|[0-9]{3}))?$"

    CVSS_TO_FLAWCVSS = {
        "cvssV2_0": FlawCVSS.CVSSVersion.VERSION2,
        "cvssV3_0": FlawCVSS.CVSSVersion.VERSION3,
        "cvssV3_1": FlawCVSS.CVSSVersion.VERSION3,
        "cvssV4_0": FlawCVSS.CVSSVersion.VERSION4,
    }

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

    def get_cve_file_path(self, cve: str) -> str:
        """
        Retrieve the CVE file path from the cvelistV5 repository for a given `cve`.
        """
        # Create a path where the CVE file should be stored
        # E. g. CVE-2024-35339 is stored as "<repo_path>/cves/2024/35xxx/CVE-2024-35339.json"
        _, year, number = cve.split("-")
        file_path = f"{self.REPO_PATH}/cves/{year}/{number[:-3]}xxx/{cve}.json"

        if not os.path.isfile(file_path):
            msg = f"Did not find a file for '{cve}' in the cvelistV5 repository."
            raise CVEorgCollectorException(msg)

        return file_path

    def collect_cve(self, cve: str) -> str:
        """
        Collect vulnerability data for a given `cve` from the cvelistV5 repository and store it in OSIDB.
        This method is intended for a manual collector run via the `create_cveorg_flaw` command.
        """
        if not re.match(CVE_RE_STR, cve):
            msg = f"Provided '{cve}' is not a valid CVE string."
            raise CVEorgCollectorException(msg)

        # Set osidb.acl to be able to CRUD database properly and essentially bypass ACLs as
        # Celery workers should be able to read/write any information in order to fulfill their jobs
        set_user_acls(settings.ALL_GROUPS)

        self.clone_repo()
        self.update_repo()
        file_path = self.get_cve_file_path(cve)

        with open(file_path) as file:
            file_content = json.load(file)

        if file_content["cveMetadata"]["state"] != "PUBLISHED":
            return f"Cannot create '{cve}' because it was rejected by CVE Program."

        try:
            content = self.extract_content(file_content)
        except Exception as exc:
            msg = f"Failed to parse data from the {file_path} file: {exc}"
            raise CVEorgCollectorException(msg) from exc

        try:
            with transaction.atomic():
                _, new_flaw = self.save_snippet_and_flaw(content)
        except Exception as exc:
            message = (
                f"Failed to save snippet and flaw for {content['cve_id']}. Error: {exc}"
            )
            raise CVEorgCollectorException(message) from exc

        if new_flaw:
            return f"Flaw for {cve} was created successfully."
        else:
            return f"Flaw for {cve} was not created because it already exist."

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
                        self.upsert_cvss_scores(
                            content["cve_id"], content["cvss_scores"]
                        )
                    # introduce a small delay after each transaction to not hit the Jira rate limit
                    if new_flaw:
                        sleep(1)
                except Exception as exc:
                    message = f"Failed to save snippet and flaw for {content['cve_id']}. Error: {exc}"
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

    def upsert_cvss_scores(
        self, cve_id: str, cvss_scores: list[dict[str, Any]]
    ) -> None:
        if not cve_id:
            return
        try:
            flaw = Flaw.objects.get(cve_id=cve_id)
        except Flaw.DoesNotExist:
            return
        for score in cvss_scores:
            FlawCVSS.objects.update_or_create(
                flaw=flaw,
                issuer=score["issuer"],
                version=score["version"],
                defaults={
                    "vector": score["vector"],
                    "acl_read": flaw.acl_read,
                    "acl_write": flaw.acl_write,
                },
            )

    def save_snippet_and_flaw(self, content: dict) -> tuple[bool, bool]:
        """
        Create and save snippet with flaw from normalized `content` if they do not already exist.
        The creation may be restricted by the published date and checked keywords.
        """
        if self.snippet_creation_start_date:
            # If unembargo_dt is missing, a flaw is always historical
            if not content["unembargo_dt"] or (
                self.snippet_creation_start_date
                > parse_datetime(content["unembargo_dt"])
            ):
                return False, False

        if self.keywords_check_enabled:
            if not should_create_snippet(content["comment_zero"]) or (
                not should_create_snippet(content["title"])
                and content["title"] != "From CVEorg collector"
            ):
                return False, False

        snippet, snippet_created = Snippet.objects.get_or_create(
            source=Snippet.Source.CVEORG,
            external_id=content["cve_id"],
            defaults={"content": content},
        )
        flaw_created = (
            bool(snippet.convert_snippet_to_flaw(jira_token=JIRA_AUTH_TOKEN))
            if snippet_created
            else False
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

        def get_cvss_and_impact(data: dict) -> tuple[list, str]:
            # Keep only data we are interested in (provider, version, vector, score)
            cvss_scores = defaultdict(dict)
            containers = [data["containers"]["cna"]] + data["containers"].get("adp", [])
            for adp in containers:
                provider = adp["providerMetadata"]["orgId"]
                metrics = adp.get("metrics", [])
                for metric in metrics:
                    for k, v in metric.items():
                        if k in self.CVSS_TO_FLAWCVSS:
                            cvss_scores[provider][k] = (
                                v["baseScore"],
                                v["vectorString"],
                            )

            # Only one CVSS v3 can be stored per provider
            for provider, scores in cvss_scores.items():
                if bool(scores.get("cvssV3_0") and scores.get("cvssV3_1")):
                    cvss_scores[provider].pop("cvssV3_0")

            # Create resulted CVSS and get the highest score for Impact calculation
            cvss_data = []
            highest_score = Decimal("0.0")
            for provider, scores in cvss_scores.items():
                for version, values in scores.items():
                    score, vector = values
                    cvss_data.append(
                        {
                            "issuer": FlawCVSS.CVSSIssuer.CISA
                            if provider == CISA_ORG_ID
                            else FlawCVSS.CVSSIssuer.CVEORG,
                            "version": self.CVSS_TO_FLAWCVSS[version],
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
            # Collect all problem types from CNA and ADP containers
            all_problem_types = data["containers"]["cna"].get("problemTypes", [])
            for a in data["containers"].get("adp", []):
                all_problem_types.extend(a.get("problemTypes", []))

            # Keep only data we are interested in (CWE id)
            ids = set()
            for problem in all_problem_types:
                for d in problem["descriptions"]:
                    if d.get("type") == "CWE" and d.get("cweId"):
                        ids.add(d.get("cweId"))

            ids = sorted(ids)
            if len(ids) == 1:
                return ids[0]
            elif len(ids) > 1:
                return f"({'|'.join(ids)})"
            return ""

        def get_refs(data: dict) -> list:
            references = [
                {
                    "type": FlawReference.FlawReferenceType.SOURCE,
                    "url": f"https://www.cve.org/CVERecord?id={data['cveMetadata']['cveId']}",
                }
            ]

            # Collect all references from CNA and ADP containers
            all_references = data["containers"]["cna"]["references"]
            for a in data["containers"].get("adp", []):
                all_references.extend(a.get("references", []))

            # Keep only data we are interested in (url)
            external = list(set([r["url"] for r in all_references]))

            references.extend(handle_urls(external, references[0]["url"]))
            return references

        def get_title(data: dict) -> str:
            return data["containers"]["cna"].get("title", "From CVEorg collector")

        def get_unembargo_dt(data: dict) -> Union[str, None]:
            if published := data["cveMetadata"].get("datePublished"):
                return published if published.endswith("Z") else f"{published}Z"
            return None

        cvss_scores, impact = get_cvss_and_impact(content)
        return {
            "comment_zero": get_comment_zero(content),
            "cve_id": content["cveMetadata"]["cveId"],
            "cvss_scores": cvss_scores,
            "cwe_id": get_cwes(content),
            "impact": impact,
            "references": get_refs(content),
            "source": Snippet.Source.CVEORG,
            "title": get_title(content),
            "unembargo_dt": get_unembargo_dt(content),
        }
