import re

from collectors.cveorg.models import (
    Allowlist,
    AllowlistSpecialCase,
    Blocklist,
    BlocklistSpecialCase,
)


def check_keywords(text):
    """
    Checks if a specified text is relevant or not based on found keywords.

    Returns tuple of matched blocklisted and allowlisted keywords.
    """

    def get_value(model):
        return model.objects.all().values_list("keyword", flat=True)

    allowlisted_keywords = [
        re.compile(rf"\b{keyword}\b", re.IGNORECASE) for keyword in get_value(Allowlist)
    ] + [re.compile(keyword) for keyword in get_value(AllowlistSpecialCase)]

    blocklisted_keywords = [
        re.compile(rf"\b{keyword}\b", re.IGNORECASE) for keyword in get_value(Blocklist)
    ] + [re.compile(rf"\b{keyword}\b") for keyword in get_value(BlocklistSpecialCase)]

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
