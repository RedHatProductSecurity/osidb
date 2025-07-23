import re

from django.db.models import QuerySet

from collectors.cveorg.models import Keyword


class MissingKeywordsException(Exception):
    pass

def get_keywords(_type: Keyword.Type) -> QuerySet:
        return Keyword.objects.filter(type=_type).values_list("keyword", flat=True)

def check_keywords(text):
    """
    Checks if a specified text is relevant or not based on found keywords.

    Returns tuple of matched blocklisted and allowlisted keywords.
    """

    allowlisted_keywords = [
        re.compile(rf"\b{keyword}\b", re.IGNORECASE)
        for keyword in get_keywords(Keyword.Type.ALLOWLIST)
    ] + [
        re.compile(keyword)
        for keyword in get_keywords(Keyword.Type.ALLOWLIST_SPECIAL_CASE)
    ]

    blocklisted_keywords = [
        re.compile(rf"\b{keyword}\b", re.IGNORECASE)
        for keyword in get_keywords(Keyword.Type.BLOCKLIST)
    ] + [
        re.compile(rf"\b{keyword}\b")
        for keyword in get_keywords(Keyword.Type.BLOCKLIST_SPECIAL_CASE)
    ]

    if not allowlisted_keywords or not blocklisted_keywords:
        raise MissingKeywordsException(
            "Allowlisted or blocklisted keywords are not present in the database. "
            "Check if the ps-constants collector ran successfully."
        )

    allowlist = []
    for word in (regex.search(text) for regex in allowlisted_keywords):
        if word is not None:
            allowlist.append(word.group().strip())

    blocklist = []
    for word in (regex.search(text) for regex in blocklisted_keywords):
        if word is not None:
            blocklist.append(word.group())

    return sorted(blocklist), sorted(allowlist)


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
