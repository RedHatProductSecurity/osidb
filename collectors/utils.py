import re
from typing import Optional

from osidb.models import PsUpdateStream

TRACKER_COMPONENT_UPDATE_STREAM_RE = re.compile(
    r"^(?:\s*EMBARGOED\s+)?"  # Embargoed keyword
    r"(?:\[(?:CISA\s)?Major\sIncident\]\s+)?"  # Major Incident
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
