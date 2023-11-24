import re
from subprocess import check_output  # nosec

import braceexpand
from cvss import CVSS3
from cvss.parser import parse_cvss_from_text

from .constants import CWE_RE_STR, PHRASE_TO_CWE_MAP


def find_cves(text):
    """Find all CVEs in a block of text and expand those that use shorthands such as {1..3}.

    Allowed shorthands:
      CVE-2000-123[1-3]      -- expands to 1231, 1232, 1233
      CVE-2000-123[13]       -- expands to 1231, 1233
      CVE-2000-123[1,3]      -- expands to 1231, 1233
      CVE-2000-{1231,1233}   -- expands to 1231, 1233
      CVE-2000-{1231..1233}  -- expands to 1231, 1232, 1233
    """
    if not text:
        return []

    max_cve_expand = 50
    cve_regex = (
        r"(CVE-[12][0-9]{3}-(?:"
        r"\{[0-9]{4,},(?:,?[0-9]{4,})*\}|"
        r"\{[0-9]{4,}\.\.[0-9]{4,}\}|"
        r"[0-9]*\[[0-9]+-[0-9]+\][0-9]*|"
        r"[0-9]*\[[0-9,]+\][0-9]*|"
        r"[0-9]{4,}))"
    )

    # all matched CVEs including non-expanded ones
    found_cves = list(re.compile(cve_regex).findall(text))

    # normalize expansion syntax to match braceexpand's notation
    for idx, cve_id in enumerate(found_cves):
        # rewrite [123] -> {1,2,3}
        m = re.match(r"(.*?)\[([0-9]*)\](.*)", cve_id)
        if m:
            m = m.groups()
            cve_id = "%s{%s}%s" % (m[0], ",".join([x for x in m[1]]), m[2])
            found_cves[idx] = cve_id

        # rewrite [1,2,3] -> {1,2,3}
        m = re.match(r"(.*?)\[([0-9,]*)\](.*)", cve_id)
        if m:
            m = m.groups()
            cve_id = "%s{%s}%s" % (
                m[0],
                ",".join([x for x in m[1].split(",") if x]),
                m[2],
            )
            found_cves[idx] = cve_id

        # rewrite [1-3] -> {1..3}
        m = re.match(r"(.*?)\[([0-9]*-[0-9]*)\](.*)", cve_id)
        if m:
            m = m.groups()
            cve_id = "%s{%s}%s" % (m[0], "..".join(m[1].split("-", 1)), m[2])
            found_cves[idx] = cve_id

    # expand {1,2,3} | {1..3}
    all_cves = []
    for cve in found_cves:
        expanded_cves = enumerate(braceexpand.braceexpand(cve))
        for index, expanded_cve in expanded_cves:
            if index > max_cve_expand:
                continue
            if not re.match(r"^CVE-[12]\d{3}-\d{4,}$", expanded_cve):
                continue
            all_cves.append(expanded_cve)

    return sorted(list(set(all_cves)))


def find_cvss(text):
    """Find CVSS version 3 vector in text.

    Returns cleaned vector with score in Red Hat notation, e.g. score/vector.
    If more than one vector found, returns vector with the highest score.
    """
    if not text:
        return ""

    found_cvss_objects = parse_cvss_from_text(text)

    if not found_cvss_objects:
        return ""

    # We are interested in CVSS version 3 vectors
    cvss3_objects = [cvss for cvss in found_cvss_objects if isinstance(cvss, CVSS3)]

    if not cvss3_objects:
        return ""

    # Find CVSS with highest base score
    result = max(cvss3_objects, key=lambda cvss: cvss.base_score)

    return result.rh_vector()


def find_cwes(text, impact=None):
    """Find all CWEs in a block of text.

    If none found, guess CWEs using common phrases in text.
    Return a string in a format described in:
    https://docs.prodsec.redhat.com/workflow/howtos/cwe.html#_cwe_tutorial
    """
    if not text:
        return

    cwes = CWE_RE_STR.findall(text)
    cwes = set(map(str.upper, cwes))

    if not cwes:
        # Guess CWEs using common phrases in text
        text = text.lower()
        for phrase, cwe in PHRASE_TO_CWE_MAP.items():
            if phrase in text:
                cwes.add(cwe)

        if "integer overflow" in text:
            if impact == "important":
                cwes.add("CWE-190->CWE-120")
            else:
                cwes.add("CWE-190")

    # Return in specified format
    if not cwes:
        return
    elif len(cwes) == 1:
        return cwes.pop()
    else:
        cwes = sorted(cwes)
        return "(" + "|".join(cwes) + ")"


def html_to_text(html):
    """Use elinks to convert HTML to plain text.

    Other HTML->text solutions were either too heavy weight, returned ugly text, or failed to
    parse certain parts of the HTML. (BeautifulSoup is great at scraping but not so good at
    rendering plain text; html2text had terrible output if the parsed HTML included a table.)

    Update 2018-08-27: Research was done in various options of rendering website contents as plain
    text in bug https://bugzilla.redhat.com/show_bug.cgi?id=1558705.
    """
    cmd = [
        "elinks",
        "-no-home",
        "-dump",
        "-dump-width",
        "80",
        "-no-numbering",
        "-no-references",
    ]

    output = check_output(cmd, input=bytes(html, "utf-8"))  # nosec

    return output.decode("utf-8").replace("\xa0", " ")
