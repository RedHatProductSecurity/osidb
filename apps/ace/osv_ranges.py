"""
osv_ranges.py — Match Flaw components to OSV upstream version ranges.

Adapts the OsvPackageInfo / _extract_osv_packages logic from vulncli/intake.py
to work directly on the upstream_purls list stored in UpstreamData (no HTTP
fetch needed — the data is already present in the database).

Depends on apps/ace/version.py for version comparison.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from packageurl import PackageURL

log = logging.getLogger(__name__)

# OSV ecosystem strings → version.py ecosystem flags (mirrors vulncli intake.py)
_OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "maven": "maven",
    "pypi": "pypi",
    "npm": "npm",
    "crates.io": "cargo",
    "go": "golang",
    "rubygems": "gem",
    "nuget": "nuget",
    "packagist": "generic",
    "hex": "generic",
    "pub": "generic",
    "hackage": "generic",
    "bioconductor": "generic",
    "cran": "generic",
    "github actions": "generic",
}

# Only SEMVER and ECOSYSTEM range types yield meaningful version bounds.
# GIT ranges (commit hashes) are skipped — version comparison is not possible.
_RANGE_TYPES = {"semver", "ecosystem"}


@dataclass
class OsvPackageInfo:
    """A single package entry extracted from an OSV upstream_purls record."""

    name: str
    ecosystem: str  # normalised (e.g. "cargo", "maven", "rpm")
    purl: str
    introduced: str  # "" means "from the beginning"
    fixed: str  # "" means "no fix yet / unknown"
    last_affected: str  # alternative to fixed (inclusive upper bound)

    def affected_range(self) -> str | None:
        """
        Convert OSV events to a version.py range expression string.

        Returns ``None`` when no meaningful range can be expressed (no fixed/last_affected
        events were present in the OSV record).

        Examples:
          introduced="0",       fixed="2.15.0"           →  "< 2.15.0"
          introduced="2.0-b9",  fixed="2.15.0"           →  ">= 2.0-b9, < 2.15.0"
          introduced="0.1.0",   last_affected="0.10.65"  →  ">= 0.1.0, <= 0.10.65"
          (no events)                                     →  None
        """
        parts = []
        intro = self.introduced.strip()
        fixed = self.fixed.strip()
        last = self.last_affected.strip()

        if intro and intro not in ("0", "0.0", "0.0.0", ""):
            parts.append(f">= {intro}")

        if fixed:
            parts.append(f"< {fixed}")
        elif last:
            parts.append(f"<= {last}")

        return ", ".join(parts) or None


def osv_entry_to_package_info(entry: dict) -> OsvPackageInfo:
    """
    Convert one upstream_purls dict entry to an OsvPackageInfo.

    upstream_purls entries are produced by the OSV collector
    (collectors/osv/collectors.py::get_upstream_purls) and have the shape:
      {
        "purl":      "pkg:nuget/Magick.NET-Q16-AnyCPU",
        "name":      "Magick.NET-Q16-AnyCPU",
        "ecosystem": "NuGet",
        "ranges":    [{"type": "ECOSYSTEM", "events": [...]}],
        "versions":  ["10.0.0", ...],
      }
    """
    raw_eco = (entry.get("ecosystem") or "").lower()
    ecosystem = _OSV_ECOSYSTEM_MAP.get(raw_eco, raw_eco)

    introduced = ""
    fixed = ""
    last_affected = ""

    for r in entry.get("ranges", []):
        if r.get("type", "").lower() not in _RANGE_TYPES:
            continue
        for evt in r.get("events", []):
            if "introduced" in evt and not introduced:
                introduced = evt["introduced"]
            if "fixed" in evt and not fixed:
                fixed = evt["fixed"]
            if "last_affected" in evt and not last_affected:
                last_affected = evt["last_affected"]

    return OsvPackageInfo(
        name=entry.get("name", ""),
        ecosystem=ecosystem,
        purl=entry.get("purl", ""),
        introduced=introduced,
        fixed=fixed,
        last_affected=last_affected,
    )


def match_component_to_upstream(
    component: str,
    upstream_purls: list[dict],
) -> OsvPackageInfo | None:
    """
    Find the upstream_purls entry whose package name matches ``component``.

    Matching is case-insensitive and tries two strategies in order:
      1. ``entry["name"]`` directly
      2. The ``name`` part of ``entry["purl"]`` (via PackageURL)

    Returns the first matching OsvPackageInfo, or None if no entry matches.
    """
    needle = component.strip().lower()
    if not needle:
        return None

    for entry in upstream_purls or []:
        entry_name = (entry.get("name") or "").strip().lower()
        if entry_name and entry_name == needle:
            return osv_entry_to_package_info(entry)

        purl_str = entry.get("purl") or ""
        if purl_str:
            try:
                purl_name = PackageURL.from_string(purl_str).name.lower()
            except Exception:
                log.debug("Skipping malformed upstream PURL %r", purl_str)
                continue
            if purl_name == needle:
                return osv_entry_to_package_info(entry)

    return None
