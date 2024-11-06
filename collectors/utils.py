import re
from decimal import Decimal
from typing import Optional, Union

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

from osidb.models import FlawReference, Impact, PsUpdateStream

TRACKER_COMPONENT_UPDATE_STREAM_RE = re.compile(
    r"^(?:\s*EMBARGOED\s+)?"  # Embargoed keyword
    r"(?:\[(?:(?:(?:CISA\s)?Major|Minor)\sIncident|0-day)\]\s+)?"  # Major Incident
    r"(?:\s*TRIAGE)?(?:-|\s*)?"  # TRIAGE keyword or prefix
    r"(?:CVE-[0-9]+-[0-9]+,?\s*)*"  # list of CVEs
    r"(?:\.+\s+)?"  # dots, when too many CVEs are present
    r"(?P<component>.+?):\s"  # PSComponent (might contain spaces or rhel module)
    r".*"  # text part summary
    r"\[(?P<stream>.*)\]\s*$",  # + PSUpdateStream in brackets
    re.VERBOSE,
)

BACKOFF_KWARGS = {"max_tries": 5, "jitter": None}


def fatal_code(e):
    """Do not retry on 4xx responses."""
    # Handle requests.exceptions.RequestException
    # 408 is "Request Timeout" that Brew sometimes returns, which can be retried safely
    # Note http.client.RemoteDisconnected errors have a response attr, but it's set to None / doesn't have a status code
    # so hasattr doesn't work, and getattr without "is not None" doesn't work either
    # because response objects are True for 200ish codes, False for 400ish codes
    if getattr(e, "response", None) is not None:
        return 400 <= e.response.status_code < 500 and e.response.status_code != 408
    # Handle xmlrpc.client.ProtocolError
    elif getattr(e, "errcode", None) is not None:
        return 400 <= e.errcode < 500 and e.errcode != 408


def tracker_parse_update_stream_component(
    summary: str,
) -> tuple[Optional[str], Optional[str]]:
    """
    parse component and update stream from summary

    this function is taken from SFM2
    """
    match = TRACKER_COMPONENT_UPDATE_STREAM_RE.match(summary)
    if match:
        return match.group("stream"), match.group("component")
    return None, None


def tracker_summary2module_component(
    summary: str,
) -> tuple[Optional[str], Optional[str]]:
    """returns a ps_module, ps_component pair by parsing a tracker summary/title line"""
    ps_update_stream, ps_component = tracker_parse_update_stream_component(summary)
    if not ps_update_stream or not ps_component:
        return None, None

    ps_update_stream_obj = PsUpdateStream.objects.filter(name=ps_update_stream).first()

    return (
        ps_update_stream_obj.ps_module.name
        if ps_update_stream_obj and ps_update_stream_obj.ps_module is not None
        else None,
        ps_component,
    )


def handle_urls(references: list, source_ref: str) -> list:
    """
    This function creates a list of external references matching FlawReference fields. References matching
    "source_ref" are ignored because they would cause ValidationError in later validation.

    Also, it ensures that only valid URL strings are converted.
    The logic tries to fix a URL in a simple way. If the fix is not successful, a URL is ignored.
    """
    urls = []

    for reference in references:
        try:
            # URL scheme can be missing, so try to fix it first
            if not reference.startswith(("http", "https", "ftp", "ftps")):
                reference = f"http://{reference}"

            validate = URLValidator()
            validate(reference)

            if reference != source_ref:
                urls.append(
                    {
                        "type": FlawReference.FlawReferenceType.EXTERNAL,
                        "url": reference,
                    }
                )
        except ValidationError:
            # Ignore the URL if it is invalid (e.g. due to a typo)
            pass

    return urls


CVSS_SCORE_TO_IMPACT = {
    # Ordering: Impact, Score, Severity
    Impact.NOVALUE: (Decimal("0.0"), Decimal("0.0")),  # NONE
    Impact.LOW: (Decimal("0.1"), Decimal("3.9")),  # LOW
    Impact.MODERATE: (Decimal("4.0"), Decimal("6.9")),  # MEDIUM
    Impact.IMPORTANT: (Decimal("7.0"), Decimal("8.9")),  # HIGH
    Impact.CRITICAL: (Decimal("9.0"), Decimal("10.0")),  # CRITICAL
}


def convert_cvss_score_to_impact(score: Union[Decimal, float]) -> Impact:
    """
    This function converts CVSS score to Flaw Impact.
    Flaw Impact matches CVSS severity, which is defined by CVSS score ranges.
    """
    # Ensure the score is always of Decimal type rounded to 1 decimal place
    score = round(Decimal(score), 1)

    impact = Impact.NOVALUE
    for key, value in CVSS_SCORE_TO_IMPACT.items():
        lower, upper = value
        if lower <= score <= upper:
            impact = key
            break
    return impact
