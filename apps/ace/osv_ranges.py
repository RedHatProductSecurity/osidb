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

from apps.ace.constants import OSV_ECOSYSTEM_MAP

log = logging.getLogger(__name__)

# Only SEMVER and ECOSYSTEM range types yield meaningful version bounds.
# GIT ranges (commit hashes) are skipped — version comparison is not possible.
_RANGE_TYPES = {"semver", "ecosystem"}


@dataclass
class _RangeGroup:
    """A single (introduced, fixed/last_affected) pair from an OSV range."""

    introduced: str
    fixed: str
    last_affected: str

    def to_expr(self) -> str | None:
        parts = []
        intro = self.introduced.strip()
        fixed = self.fixed.strip()
        last = self.last_affected.strip()

        is_zero_intro = intro in ("0", "0.0", "0.0.0")

        if intro and not is_zero_intro:
            parts.append(f">= {intro}")

        if fixed:
            parts.append(f"< {fixed}")
        elif last:
            parts.append(f"<= {last}")
        elif is_zero_intro:
            # Unbounded: introduced from zero with no fix — all versions affected.
            # Return ">= 0" so the group is not silently filtered out.
            return ">= 0"

        return ", ".join(parts) or None


@dataclass
class OsvPackageInfo:
    """Package info extracted from one or more OSV upstream_purls records.

    Supports multiple disjoint version ranges (e.g. jackson-core has ranges
    across 2.15.x, 2.19.x, and 3.x branches).  ``affected_range()`` emits
    ``||``-separated OR groups that ``parse_version_range_or()`` can parse.
    """

    name: str
    ecosystem: str  # normalised (e.g. "cargo", "maven", "rpm")
    purl: str
    # Legacy single-range fields kept for backward compatibility
    introduced: str  # "" means "from the beginning"
    fixed: str  # "" means "no fix yet / unknown"
    last_affected: str  # alternative to fixed (inclusive upper bound)
    range_groups: list[_RangeGroup] | None = None

    def affected_range(self) -> str | None:
        """
        Convert OSV events to a version.py range expression string.

        When multiple range groups exist, they are joined with ``||`` so that
        ``parse_version_range_or()`` treats them as OR groups.

        Examples:
          Single:    introduced="0",   fixed="2.15.0"       →  "< 2.15.0"
          Disjoint:  [2.15.0-<2.18.6, 2.19.0-<2.21.1]      →  ">= 2.15.0, < 2.18.6 || >= 2.19.0, < 2.21.1"
          (no events)                                        →  None
        """
        if self.range_groups:
            exprs = []
            for rg in self.range_groups:
                expr = rg.to_expr()
                if expr:
                    exprs.append(expr)
            return " || ".join(exprs) or None

        # Fallback: legacy single-range fields — reuse _RangeGroup.to_expr()
        return _RangeGroup(
            introduced=self.introduced,
            fixed=self.fixed,
            last_affected=self.last_affected,
        ).to_expr()


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

    Each OSV range object can contain multiple introduced/fixed pairs
    representing disjoint vulnerable intervals.  All pairs are collected
    into separate ``_RangeGroup`` instances so that ``affected_range()``
    emits OR groups.
    """
    raw_eco = (entry.get("ecosystem") or "").lower()
    ecosystem = OSV_ECOSYSTEM_MAP.get(raw_eco, raw_eco)

    range_groups: list[_RangeGroup] = []

    for r in entry.get("ranges", []):
        if r.get("type", "").lower() not in _RANGE_TYPES:
            continue
        # OSV events are ordered pairs: introduced → fixed/last_affected.
        # Walk events and emit a _RangeGroup for each complete pair.
        # An introduced without a subsequent fixed/last_affected represents
        # an open-ended range (no fix released yet) — emit it as well.
        current_intro = ""
        has_intro = False
        for evt in r.get("events", []):
            if "introduced" in evt:
                # Flush a pending open-ended introduced before starting a new one
                if has_intro:
                    range_groups.append(
                        _RangeGroup(
                            introduced=current_intro, fixed="", last_affected=""
                        )
                    )
                current_intro = evt["introduced"]
                has_intro = True
            elif "fixed" in evt:
                range_groups.append(
                    _RangeGroup(
                        introduced=current_intro,
                        fixed=evt["fixed"],
                        last_affected="",
                    )
                )
                current_intro = ""
                has_intro = False
            elif "last_affected" in evt:
                range_groups.append(
                    _RangeGroup(
                        introduced=current_intro,
                        fixed="",
                        last_affected=evt["last_affected"],
                    )
                )
                current_intro = ""
                has_intro = False
        # Flush trailing open-ended introduced (no fix released)
        if has_intro:
            range_groups.append(
                _RangeGroup(introduced=current_intro, fixed="", last_affected="")
            )

    # Legacy single-range fields from the first group (backward compat)
    first = range_groups[0] if range_groups else _RangeGroup("", "", "")

    return OsvPackageInfo(
        name=entry.get("name", ""),
        ecosystem=ecosystem,
        purl=entry.get("purl", ""),
        introduced=first.introduced,
        fixed=first.fixed,
        last_affected=first.last_affected,
        range_groups=range_groups or None,
    )


def _entry_matches(needle: str, entry: dict, parsed_purl, ecosystem: str) -> bool:
    """Check if an upstream_purls entry matches the component name and ecosystem."""
    if ecosystem:
        if parsed_purl:
            purl_type = parsed_purl.type
        else:
            raw_eco = (entry.get("ecosystem") or "").lower()
            purl_type = OSV_ECOSYSTEM_MAP.get(raw_eco, raw_eco)
        if purl_type != ecosystem:
            return False

    entry_name = (entry.get("name") or "").strip().lower()
    if entry_name and entry_name == needle:
        return True

    if parsed_purl and parsed_purl.name.lower() == needle:
        return True

    return False


def match_component_to_upstream(
    component: str,
    upstream_purls: list[dict],
    ecosystem: str = "",
) -> OsvPackageInfo | None:
    """
    Find upstream_purls entries whose package name matches ``component``.

    When multiple entries match (e.g. disjoint version ranges for the same
    component across different ``affected[]`` blocks), their ranges are merged
    into a single ``OsvPackageInfo`` with OR-group support.

    When ``ecosystem`` is provided, only entries whose PURL type matches the
    ecosystem are considered. This prevents selecting the wrong OSV range when
    the same component exists in multiple ecosystems.

    Matching is case-insensitive and tries two strategies in order:
      1. ``entry["name"]`` directly
      2. The ``name`` part of ``entry["purl"]`` (via PackageURL)

    Returns a merged OsvPackageInfo, or None if no entry matches.
    """
    needle = component.strip().lower()
    if not needle:
        return None

    matches: list[OsvPackageInfo] = []

    for entry in upstream_purls or []:
        purl_str = entry.get("purl") or ""
        parsed_purl = None
        if purl_str:
            try:
                parsed_purl = PackageURL.from_string(purl_str)
            except Exception:
                log.debug("Skipping malformed upstream PURL %r", purl_str)
                continue

        if _entry_matches(needle, entry, parsed_purl, ecosystem):
            matches.append(osv_entry_to_package_info(entry))

    if not matches:
        return None

    # Multiple matches may span different ecosystems even when an explicit
    # ecosystem is passed (e.g. purl type vs entry ecosystem can disagree).
    # Only merge entries that share the same normalized ecosystem as the
    # first match, so that version comparison uses the correct algorithm.
    first = matches[0]
    matches = [m for m in matches if m.ecosystem == first.ecosystem]

    if len(matches) == 1:
        return matches[0]

    # Merge ranges from all matching entries into a single OsvPackageInfo.
    # Every entry contributes its range_groups (or a single-range fallback).
    # Introduced-only entries (no fix yet) are included — they represent
    # open-ended "still vulnerable" intervals.
    all_groups: list[_RangeGroup] = []
    for info in matches:
        if info.range_groups:
            all_groups.extend(info.range_groups)
        else:
            all_groups.append(
                _RangeGroup(
                    introduced=info.introduced,
                    fixed=info.fixed,
                    last_affected=info.last_affected,
                )
            )

    # Derive legacy fields from the first collected group
    first_group = all_groups[0] if all_groups else _RangeGroup("", "", "")
    return OsvPackageInfo(
        name=first.name,
        ecosystem=first.ecosystem,
        purl=first.purl,
        introduced=first_group.introduced,
        fixed=first_group.fixed,
        last_affected=first_group.last_affected,
        range_groups=all_groups or None,
    )
