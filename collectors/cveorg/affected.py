"""CVE JSON 5 affected-version ranges, normalized to OSV upstream_purls."""

import logging
import re

import requests
from packageurl import PackageURL

from collectors.cveorg.constants import CVEAWG_API_BASE, CVEAWG_API_TIMEOUT
from osidb.models import Flaw
from osidb.models.flaw.upstream import UpstreamData

logger = logging.getLogger(__name__)

# Bounds that do not identify a version. "0" is a real open lower bound.
# lessThan "*" is unbounded. lessThan "2.*" is rewritten to the next version.
_SENTINELS = frozenset(
    {"", "unspecified", "n/a", "na", "unknown", "*", "-", "none", "see"}
)

_VERSION_TYPE_ECOSYSTEM = {
    "semver": "generic",
    "npm": "npm",
    "maven": "maven",
    "python": "pypi",
    "pypi": "pypi",
    "rpm": "rpm",
    "go": "golang",
    "golang": "golang",
    "gem": "gem",
    "rubygems": "gem",
    "nuget": "nuget",
    "cargo": "cargo",
    "ecosystem": "generic",
    "custom": "generic",
}


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def _bound(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _range_bound(value) -> str:
    """A comparable version bound, or "" when the CVE value is a placeholder."""
    bound = _bound(value)
    if bound.lower() in _SENTINELS:
        return ""
    return bound


_BOUND_FIELDS = ("version", "lessThan", "lessThanOrEqual")


def _star_series_bound(bound: str) -> str:
    """Turn lessThan "2.*" into "3", the first version after that series."""
    match = re.fullmatch(r"(\d+(?:\.\d+)*)\.\*", bound)
    if not match:
        return bound
    parts = match.group(1).split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def _is_range_expression(value) -> bool:
    """True when a bound is a comparison phrase rather than a plain version."""
    return any(char in _bound(value) for char in "<=>,")


def _version_status(version, default_status: str) -> str:
    if not isinstance(version, dict):
        return ""
    return _bound(version.get("status") or default_status).lower()


def _has_range_expression(version: dict) -> bool:
    return any(_is_range_expression(version.get(field)) for field in _BOUND_FIELDS)


def _events_for_version(version: dict, default_status: str) -> list[dict] | None:
    """Convert one CVE version object into OSV introduced/fixed events."""
    if _version_status(version, default_status) != "affected":
        return None
    if _bound(version.get("versionType")).lower() == "git":
        return None
    if _has_range_expression(version):
        return None

    start = _range_bound(version.get("version"))
    # "*" is infinity: affected from the start version onward, with no fix.
    raw_less_than = _bound(version.get("lessThan"))
    if raw_less_than == "*":
        if not start:
            return None
        return [{"introduced": start}]

    less_than = _star_series_bound(_range_bound(raw_less_than))
    less_than_or_equal = _range_bound(version.get("lessThanOrEqual"))
    if not (start or less_than or less_than_or_equal):
        return None

    introduced = start or "0"
    if less_than:
        return [{"introduced": introduced}, {"fixed": less_than}]
    if less_than_or_equal:
        return [{"introduced": introduced}, {"last_affected": less_than_or_equal}]
    return [{"introduced": introduced}, {"last_affected": introduced}]


def _outside_status(default_status: str, versions: list) -> str:
    """Status CVE assigns to versions outside the converted intervals.

    An omitted default is unknown. Unaffected applies outside when every
    listed version is affected or unaffected. Affected applies outside
    when every listed version is affected.
    """
    status = _bound(default_status).lower()
    if status not in ("affected", "unaffected"):
        return "unknown"
    compatible = (
        {"", "affected", "unaffected"} if status == "unaffected" else {"", "affected"}
    )
    if any(
        _version_status(version, default_status) not in compatible
        for version in versions
    ):
        return "unknown"
    return status


def _platforms(product: dict) -> list[str]:
    """Platforms a CVE range applies to. An empty list means every platform.

    A value that is not a list of names is restricted, but has no usable name.
    """
    if "platforms" not in product:
        return []
    raw = product["platforms"]
    if not isinstance(raw, list):
        return [""]
    names = []
    for item in raw:
        name = _bound(item)
        if name:
            names.append(name)
    return names


def _purl_ecosystem(purl: str) -> str:
    """Ecosystem named by a package URL, or "" when the URL has no type."""
    if not purl:
        return ""
    try:
        purl_type = (PackageURL.from_string(purl).type or "").lower()
    except Exception:
        return ""
    if not purl_type:
        return ""
    return _VERSION_TYPE_ECOSYSTEM.get(purl_type, "generic")


def _entry_name(product: dict, purl: str) -> str:
    name = _bound(product.get("packageName") or product.get("product"))
    if name or not purl:
        return name
    try:
        return PackageURL.from_string(purl).name or ""
    except Exception:
        logger.debug("Skipping malformed CVE packageURL %r", purl)
        return ""


def _products_to_entries(affected: list) -> list[dict]:
    entries: list[dict] = []
    for product in affected:
        if not isinstance(product, dict):
            continue
        default_status = _bound(product.get("defaultStatus"))
        versions = _as_list(product.get("versions"))
        events_by_type: dict[str, list[dict]] = {}
        for version in versions:
            # One unconverted affected phrase makes the remaining bounds incomplete.
            if _version_status(
                version, default_status
            ) == "affected" and _has_range_expression(version):
                events_by_type = {}
                break
            events = _events_for_version(version, default_status)
            if not events:
                continue
            version_type = _bound(version.get("versionType")).lower() or "custom"
            events_by_type.setdefault(version_type, []).extend(events)
        if not events_by_type:
            continue

        purl = _bound(product.get("packageURL") or product.get("purl"))
        package_ecosystem = _purl_ecosystem(purl)
        name = _entry_name(product, purl)
        if not name:
            continue
        product_name = _bound(product.get("product"))
        product_alias = product_name if product_name.lower() != name.lower() else ""
        outside_status = _outside_status(default_status, versions)
        for version_type, events in events_by_type.items():
            entries.append(
                {
                    "purl": purl,
                    "name": name,
                    "product": product_alias,
                    "ecosystem": package_ecosystem
                    or _VERSION_TYPE_ECOSYSTEM.get(version_type, "generic"),
                    "ranges": [{"type": "ECOSYSTEM", "events": events}],
                    "versions": [],
                    "outside_status": outside_status,
                    "platforms": _platforms(product),
                }
            )
    return entries


def affected_to_upstream_purls(record: dict) -> list[dict]:
    """
    Normalize CVE JSON 5 affected versions to the OSV upstream_purls shape.

    CNA affected products are used when they contain a comparable range.
    ADP affected products are used only when the CNA block does not.
    """
    if not isinstance(record, dict):
        return []
    containers = record.get("containers") or {}
    if not isinstance(containers, dict):
        return []
    cna = containers.get("cna") or {}
    if isinstance(cna, dict):
        entries = _products_to_entries(_as_list(cna.get("affected")))
        if entries:
            return entries
    entries = []
    for adp in _as_list(containers.get("adp")):
        if isinstance(adp, dict):
            entries.extend(_products_to_entries(_as_list(adp.get("affected"))))
    return entries


def fetch_cve_record(cve_id: str) -> dict | None:
    """Fetch one CVE record from the CVE Services API. Return None on failure."""
    url = f"{CVEAWG_API_BASE.rstrip('/')}/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=CVEAWG_API_TIMEOUT)
    except requests.RequestException as exc:
        logger.warning("CVE Services request failed for %s: %s", cve_id, exc)
        return None
    if response.status_code != 200:
        logger.warning("CVE Services returned %s for %s", response.status_code, cve_id)
        return None
    try:
        payload = response.json()
    except ValueError:
        logger.warning("CVE Services returned non-JSON for %s", cve_id)
        return None
    if not isinstance(payload, dict) or "containers" not in payload:
        logger.warning("CVE Services payload for %s has no containers", cve_id)
        return None
    return payload


def store_cveorg_upstream(flaw: Flaw, purls: list[dict]) -> None:
    """Replace the flaw's CVEORG upstream_purls with ``purls``."""
    upstream = UpstreamData.objects.ensure_for_flaw(
        flaw, source=UpstreamData.Source.CVEORG
    )
    if list(upstream.upstream_purls or []) == purls:
        return
    upstream.upstream_purls = purls
    upstream.save(raise_validation_error=False)


def upsert_affected_from_record(cve_id: str, record: dict) -> None:
    """Store affected ranges from a CVE record onto the flaw with that CVE ID."""
    if not cve_id:
        return
    try:
        flaw = Flaw.objects.get(cve_id=cve_id)
    except Flaw.DoesNotExist:
        return
    store_cveorg_upstream(flaw, affected_to_upstream_purls(record))
