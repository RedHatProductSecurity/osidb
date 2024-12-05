import re

from celery.utils.log import get_task_logger

from collectors.ps_constants.constants import (
    PS_CONSTANTS_REPO_BRANCH,
    PS_CONSTANTS_REPO_URL,
)
from collectors.ps_constants.core import fetch_ps_constants

logger = get_task_logger(__name__)


def fetch_keywords_from_ps_constants():
    url = f"{PS_CONSTANTS_REPO_URL}/-/raw/{PS_CONSTANTS_REPO_BRANCH}/data/cveorg_keywords.yml"
    logger.info(f"Fetching CVEorg keywords from '{url}'")
    keywords = fetch_ps_constants(url)

    try:
        allowlist = keywords["allowlist"]
        allowlist_special_cases = keywords["allowlist_special_cases"]
        blocklist = keywords["blocklist"]
        blocklist_special_cases = keywords["blocklist_special_cases"]
    except KeyError:
        raise KeyError(
            "The ps-constants repository does not contain the expected CVEorg keyword lists."
        )

    return allowlist, allowlist_special_cases, blocklist, blocklist_special_cases


def check_keywords(text):
    """
    Checks if a specified text is relevant or not based on found keywords.

    Returns tuple of matched blocklisted and allowlisted keywords.
    """
    (
        allowlist,
        allowlist_special_cases,
        blocklist,
        blocklist_special_cases,
    ) = fetch_keywords_from_ps_constants()

    allowlisted_keywords = [
        re.compile(rf"\b{keyword}\b", re.IGNORECASE) for keyword in allowlist
    ] + [re.compile(keyword) for keyword in allowlist_special_cases]

    blocklisted_keywords = [
        re.compile(rf"\b{keyword}\b", re.IGNORECASE) for keyword in blocklist
    ] + [re.compile(rf"\b{keyword}\b") for keyword in blocklist_special_cases]

    in_allowlist = []
    for word in (regex.search(text) for regex in allowlisted_keywords):
        if word is not None:
            in_allowlist.append(word.group().strip())

    in_blocklist = []
    for word in (regex.search(text) for regex in blocklisted_keywords):
        if word is not None:
            in_blocklist.append(word.group())

    return sorted(in_blocklist), sorted(in_allowlist)


def should_create_snippet(text):
    """
    Returns True if a snippet should be created, False otherwise.

    Snippet should be created if:
        words in `text` are in both allowlist and blocklist ([x], [x])
        words in `text` are in allowlist only               ([x], [])
        words in `text` are not in allowlist or blocklist   ([], [])

    Snippet should not be created if:
        words in `text` are in blocklist only               ([], [x])
        `text` is empty
    """
    if not text:
        return False

    blocklist, allowlist = check_keywords(text)

    return False if (blocklist and not allowlist) else True
