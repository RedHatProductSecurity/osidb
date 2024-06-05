"""
    flaw validators confirm flaw model data is correct
"""
import re
from datetime import datetime

from cvss import CVSS2, CVSS3
from cvss.exceptions import CVSSError
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils import timezone

# regex validation patterns
CVE_RE_STR = re.compile(r"CVE-(?:1999|2\d{3})-(?!0{4})(?:0\d{3}|[1-9]\d{3,})")
# TODO CWE syntax is a lot more complicated so this captures only the basic ones
CWE_RE_STR = re.compile(r"CWE-[1-9]\d*(\[auto\])?", flags=re.IGNORECASE)


def restrict_regex(regex):
    """restrict regex so it accepts no prefix or suffix"""
    return re.compile(rf"^{regex.pattern}$")


def validate_cve_id(value: str):
    """check cve_id"""
    RegexValidator(restrict_regex(CVE_RE_STR), "Malformed CVE or alias.")(value)


def validate_cwe_id(value: str):
    """check cwe_id"""
    # RegexValidator(restrict_regex(CWE_RE_STR), "Invalid CWE.")(value)
    # TODO complete CWE syntax is a context free language
    # which obviously cannot be captured by regex
    # turning off the validation for now
    # needs to be fixed in the future
    pass


def check_cvss(cvss_str, CVSS=CVSS3):
    """CVSS validation is non-trivial so we use cvss library for this purpose"""
    cvss_version = "CVSSv3" if CVSS is CVSS3 else "CVSSv2"

    try:
        score, vector = cvss_str.split("/", 1)
    except ValueError:
        return f"Malformed {cvss_version} string: {cvss_str}"

    try:
        score = float(score)
    except ValueError:
        return f"{cvss_version} score is expected to be a float number: {score}"

    # Try calculating correct score from the vector
    try:
        cvss_obj = CVSS(vector)
        correct_score = cvss_obj.scores()[0]
    except CVSSError as e:
        return f"Malformed {cvss_version} string: {e}"

    if score != correct_score:
        return (
            f"{cvss_version} string has an incorrectly calculated score: "
            f"{score} (expected value: {correct_score})"
        )


def validate_cvss2(value: str):
    """check cvss2"""
    if not value:
        return

    result = check_cvss(value, CVSS=CVSS2)
    if not result:
        return

    raise ValidationError(f"Invalid CVSS2: {result}")


def validate_cvss3(value: str):
    """check cvss3"""
    if not value:
        return

    result = check_cvss(value, CVSS=CVSS3)
    if not result:
        return

    raise ValidationError(f"Invalid CVSS3: {result}")


def no_future_date(value: datetime) -> None:
    """ensure date does not occur in the future"""
    if value > timezone.now():
        raise ValidationError(
            f"'{value}' is an Invalid datetime, cannot be set in the future."
        )


# check flaw cve_description is present and contains required metadata

# check that a flaw with a Red Hat-assigned CVE contains all necessary metadata

# check cve_description does not contain the word EMBARGOED if the flaw is public.

# check cve_description contains the word EMBARGOED if the flaw is embargoed.

# check that an embargoed flaw is not linked to any public tracker.

# check that a flaw has affects
