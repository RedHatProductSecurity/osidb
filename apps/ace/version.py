"""
version.py — Version range parsing and comparison engine.

Supports all major package ecosystems used in Red Hat products:

  RPM (Fedora/RHEL):
    Format  : E:V-R  e.g. "1:3.0.7-18.el9_2"
    Engine  : rpmvercmp (pure Python; uses rpm.labelCompare if installed)
    Special : ~ (pre-release), ^ (snapshot), numeric integer comparison

  PyPI (Python):
    Format  : PEP 440  e.g. "1.2.0", "1.2.0rc1", "1.2.0.post1", "1.2.0a1"
    Engine  : packaging.version.Version (handles epoch, pre/post/dev)
    Special : ~= compatible-release operator  e.g. "~= 1.4" → ">= 1.4, < 2.0"

  npm (Node.js):  https://docs.npmjs.com/about-semantic-versioning
    Format  : SemVer 2.0  e.g. "4.1.0", "1.0.0-beta.1"
    Engine  : packaging.version.Version (semver-compatible)
    Special : ~ tilde  "~ 1.2.3" → ">= 1.2.3, < 1.3.0"
              ^ caret  "^ 1.2.3" → ">= 1.2.3, < 2.0.0"
                       "^ 0.2.3" → ">= 0.2.3, < 0.3.0"  (0.x rule)
                       "^ 0.0.3" → ">= 0.0.3, < 0.0.4"  (0.0.x rule)

  Maven (Java):   https://maven.apache.org/enforcer/enforcer-rules/versionRanges.html
    Format  : "1.0", "1.0-SNAPSHOT", "1.0-alpha-1", "1.0.Final"
    Engine  : _maven_compare() — qualifier ordering per Maven spec
    Ranges  : [1.0,2.0)  (,1.0]  [1.0,)  [1.0]  (Maven interval notation)
    Special : SNAPSHOT < release; qualifier rank: alpha<beta<milestone<rc<""<sp

  Golang:         https://go.dev/doc/modules/version-numbers
    Format  : "v1.21.0", "go1.21.0", pseudo "v0.0.0-20170915032832-14c0d48ead0c"
    Engine  : packaging.version.Version; fallback segment comparator
    Special : "v" and "go" prefixes stripped; pseudo-versions compared by base

  RubyGems:       https://guides.rubygems.org/specification-reference/
    Format  : "1.0.0", "1.0.0.pre", "1.0.0.rc1"
    Engine  : packaging.version.Version (semver-compatible)
    Special : ~> pessimistic constraint  "~> 1.2.3" → ">= 1.2.3, < 1.3.0"
                                         "~> 1.2"   → ">= 1.2,   < 2.0"

  cargo (Rust), gem, nuget, composer, generic:
    Engine  : packaging.version.Version (semver-compatible fallback)

Version range expression syntax accepted by vulncli:
  Standard  : "< 3.0.9"             single operator constraint
  Compound  : ">= 2.0, < 2.17.1"    AND logic (comma-separated)
  Exact     : "== 3.0.7"            exact match
  MITRE     : "[2.0, 3.0)"          interval notation (incl/excl)
  Dash      : "2.0-3.0"             → ">= 2.0, < 3.0"
  npm ~     : "~ 1.2.3"             → ">= 1.2.3, < 1.3.0"
  npm ^     : "^ 1.2.3"             → ">= 1.2.3, < 2.0.0"
  Python ~= : "~= 1.4"              → ">= 1.4, < 2.0"
  Ruby  ~>  : "~> 1.2.3"            → ">= 1.2.3, < 1.3.0"
  Maven open: "(,1.0]"              → "<= 1.0"
              "[1.0,)"              → ">= 1.0"
              "[1.0]"               → "== 1.0"

Operators: <  <=  >  >=  ==  =  !=
"""

from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

RPM_ECOSYSTEM = "rpm"
GOLANG_ECOSYSTEM = "golang"
MAVEN_ECOSYSTEM = "maven"
SEMVER_ECOSYSTEMS = frozenset(
    {"npm", "cargo", "gem", "pypi", "nuget", "maven", "composer", "generic", "github"}
)


class OsvStatus(enum.Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"
    NO_MATCH = "no_match"  # no upstream_purls entry matched the component
    NO_RANGE = "no_range"  # matched entry has no meaningful range expression
    NO_VERSION = "no_version"  # result purl carries no version to compare


# ── Version extraction ─────────────────────────────────────────────────────────


def extract_upstream_version(
    version_str: str | None, ecosystem: str = ""
) -> str | None:
    """
    Return just the upstream version component, stripping packaging-specific suffixes.

    Returns ``None`` when ``version_str`` is ``None`` or empty.

    RPM EVR examples:
      "3.0.7-18.el9_2"    → "3.0.7"    (release stripped)
      "1:1.1.1k-6.el8_5"  → "1.1.1k"   (epoch + release stripped)

    Golang:
      "v0.40.0"           → "0.40.0"   (leading 'v' stripped)
      "go1.21.0"          → "1.21.0"   (leading 'go' stripped)
      "v0.0.0-20170915032832-14c0d48ead0c" → "0.0.0-20170915032832-14c0d48ead0c"

    Others (cargo, npm, pypi, maven, gem…):
      "0.10.63"           → "0.10.63"  (unchanged)
      None / ""           → None
    """
    if not version_str:
        return None

    v = version_str.strip()

    is_rpm = ecosystem == RPM_ECOSYSTEM or (
        not ecosystem and re.search(r"-\d+\.\w+\d+", v)
    )

    if is_rpm:
        # Strip epoch
        if ":" in v:
            v = v.split(":", 1)[1]
        # Strip release (everything after last "-")
        if "-" in v:
            v = v.rsplit("-", 1)[0]
        return v

    if ecosystem == GOLANG_ECOSYSTEM or (
        not ecosystem and (v.startswith("v") or v.startswith("go"))
    ):
        # Strip 'v' or 'go' prefix (e.g. v1.21.0 → 1.21.0, go1.21.0 → 1.21.0)
        if v.startswith("go"):
            v = v[2:]
        else:
            v = v.lstrip("v")
        return v

    return v


# ── RPM version comparison ─────────────────────────────────────────────────────


def _split_evr(evr: str) -> tuple[str, str, str]:
    """Split "epoch:version-release" into (epoch, version, release)."""
    epoch, release = "0", ""
    v = evr.strip()
    if ":" in v:
        epoch, v = v.split(":", 1)
    if "-" in v:
        v, release = v.rsplit("-", 1)
    return epoch, v, release


def _rpmvercmp(a: str, b: str) -> int:
    """
    Pure-Python implementation of the RPM C library rpmvercmp() algorithm.
    Returns -1, 0, or 1.

    Handles all Fedora Packaging Guideline cases:
      ~  tilde  — sorts BEFORE everything (pre-releases): 1.0~rc1 < 1.0
      ^  caret  — sorts AFTER base but BEFORE .next (snapshots): 1.0 < 1.0^snap < 1.1
      numeric   — compared as integers: 9 < 10
      alpha     — compared lexicographically
    """
    if a == b:
        return 0

    ia, ib = 0, 0
    la, lb = len(a), len(b)

    while ia < la or ib < lb:
        # ── Skip non-alphanumeric, non-tilde, non-caret characters ──────────
        while ia < la and not (a[ia].isalnum() or a[ia] in ("~", "^")):
            ia += 1
        while ib < lb and not (b[ib].isalnum() or b[ib] in ("~", "^")):
            ib += 1

        # ── Tilde: sorts before EVERYTHING, even empty string ───────────────
        # "1.0~rc1" < "1.0"  (pre-release comes before release)
        a_tilde = ia < la and a[ia] == "~"
        b_tilde = ib < lb and b[ib] == "~"
        if a_tilde or b_tilde:
            if not a_tilde:
                return 1  # b has tilde → b is pre-release → a > b
            if not b_tilde:
                return -1  # a has tilde → a is pre-release → a < b
            ia += 1
            ib += 1
            continue

        # ── End of string handling ───────────────────────────────────────────
        if ia >= la and ib >= lb:
            return 0
        if ia >= la:
            # a ended; if b continues with caret → b is snapshot → b > a
            # otherwise b has more version → b > a
            return -1
        if ib >= lb:
            return 1

        # ── Caret: sorts AFTER base but BEFORE next release ─────────────────
        # "1.0" < "1.0^20210101g" < "1.0.1"
        a_caret = a[ia] == "^"
        b_caret = b[ib] == "^"
        if a_caret or b_caret:
            if not a_caret:
                return 1  # b is snapshot, a is release → a > b
            if not b_caret:
                return -1  # a is snapshot, b is release → a < b
            ia += 1
            ib += 1
            continue

        # ── Collect next segment: digits or alpha (never mixed) ─────────────
        a_is_num = a[ia].isdigit()
        b_is_num = ib < lb and b[ib].isdigit()

        if a_is_num != b_is_num:
            return 1 if a_is_num else -1

        if a_is_num:
            ja = ia
            while ja < la and a[ja].isdigit():
                ja += 1
            jb = ib
            while jb < lb and b[jb].isdigit():
                jb += 1
            seg_a = a[ia:ja].lstrip("0") or "0"
            seg_b = b[ib:jb].lstrip("0") or "0"
            ia, ib = ja, jb
            # Longer numeric string wins (both stripped of leading zeros)
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        else:
            # Alpha segment
            ja = ia
            while ja < la and a[ja].isalpha():
                ja += 1
            jb = ib
            while jb < lb and b[jb].isalpha():
                jb += 1
            seg_a, seg_b = a[ia:ja], b[ib:jb]
            ia, ib = ja, jb
            if not seg_b:
                return 1
            if not seg_a:
                return -1

        # ── Lexicographic comparison of the segment ──────────────────────────
        if seg_a < seg_b:
            return -1
        if seg_a > seg_b:
            return 1

    return 0


def _rpm_compare(v1: str, v2: str) -> int:
    """
    Full RPM EVR comparison (epoch:version-release).
    Prefers the rpm C extension; falls back to pure Python.
    Returns -1, 0, or 1.
    """
    try:
        import rpm as _rpm_mod

        return _rpm_mod.labelCompare(_split_evr(v1), _split_evr(v2))
    except ImportError:
        pass

    e1, ver1, rel1 = _split_evr(v1)
    e2, ver2, rel2 = _split_evr(v2)

    r = (int(e1) > int(e2)) - (int(e1) < int(e2))
    if r:
        return r
    r = _rpmvercmp(ver1, ver2)
    if r:
        return r
    # Empty release should sort before non-empty release (e.g. 1.0 < 1.0-1)
    if not rel1 and not rel2:
        return 0
    if not rel1:
        return -1
    if not rel2:
        return 1
    return _rpmvercmp(rel1, rel2)


# ── Semver comparison ──────────────────────────────────────────────────────────


def _semver_compare(v1: str, v2: str) -> int:
    """
    Compare two semver-ish version strings.
    Returns -1, 0, or 1.
    Uses the `packaging` library if available.
    """
    try:
        from packaging.version import InvalidVersion, Version

        try:
            pv1, pv2 = Version(v1), Version(v2)
            return (pv1 > pv2) - (pv1 < pv2)
        except InvalidVersion:
            pass
    except ImportError:
        pass

    # Numeric-segment fallback
    def _segs(s: str) -> list:
        parts = []
        for p in re.split(r"[.\-_]", s):
            try:
                parts.append((0, int(p)))
            except ValueError:
                parts.append((1, p.lower()))
        return parts

    a_segs, b_segs = _segs(v1), _segs(v2)
    for a, b in zip(a_segs, b_segs):
        if a < b:
            return -1
        if a > b:
            return 1
    return (len(a_segs) > len(b_segs)) - (len(a_segs) < len(b_segs))


# ── Maven version comparison ───────────────────────────────────────────────────
# Spec: https://maven.apache.org/enforcer/enforcer-rules/versionRanges.html
#
# Maven qualifier ordering (lowest → highest):
#   alpha/a  <  beta/b  <  milestone/m  <  rc/cr  <  snapshot  <  (none/ga/final)  <  sp
#
# Examples:
#   1.0-alpha-1  <  1.0-beta-1  <  1.0-rc-1  <  1.0-SNAPSHOT  <  1.0  <  1.0-sp1

_MAVEN_QUALIFIER_RANK: dict[str, int] = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "rc": 3,
    "cr": 3,
    "snapshot": 4,
    "": 5,
    "ga": 5,
    "final": 5,
    "release": 5,
    "sp": 6,
}


def _parse_maven_version(version: str) -> tuple[list[int], int, int]:
    """
    Parse a Maven version string into (numeric_parts, qualifier_rank, qualifier_number).

    Examples:
      "1.2.3"            → ([1,2,3], 5, 0)
      "1.0-SNAPSHOT"     → ([1,0],   4, 0)
      "1.0-alpha-2"      → ([1,0],   0, 2)
      "1.0-sp1"          → ([1,0],   6, 1)
      "2.0.Final"        → ([2,0],   5, 0)
    """
    v = version.strip()

    # Separate numeric prefix from qualifier
    # Handles: 1.2.3-alpha-1, 1.2.3.Final, 1.2.3-SNAPSHOT
    qualifier_num = 0

    m = re.match(r"^([\d.]+)[.\-](.+)$", v)
    if m:
        num_part = m.group(1)
        qualifier_raw = m.group(2).lower()

        # Check if the rest is purely numeric (e.g. 1.0.1 → qualifier is just another segment)
        if qualifier_raw.isdigit():
            num_part = v  # no qualifier, all numeric
            qualifier_raw = ""
        else:
            # Extract trailing number from qualifier: "alpha-2" → ("alpha", 2)
            qm = re.match(r"^([a-z]+)[.\-]?(\d+)?$", qualifier_raw)
            if qm:
                qualifier_raw = qm.group(1)
                qualifier_num = int(qm.group(2)) if qm.group(2) else 0
    else:
        num_part = v
        qualifier_raw = ""

    numeric_parts = [int(x) for x in num_part.split(".") if x.isdigit()]
    rank = _MAVEN_QUALIFIER_RANK.get(
        qualifier_raw.lower(), 5
    )  # unknown → treat as release

    return numeric_parts, rank, qualifier_num


def _maven_compare(v1: str, v2: str) -> int:
    """
    Compare two Maven version strings per the Maven version ordering spec.
    Returns -1, 0, or 1.

    Falls back to _semver_compare if parsing fails.
    """
    try:
        nums1, rank1, qnum1 = _parse_maven_version(v1)
        nums2, rank2, qnum2 = _parse_maven_version(v2)

        # Pad numeric parts to same length
        length = max(len(nums1), len(nums2))
        nums1 += [0] * (length - len(nums1))
        nums2 += [0] * (length - len(nums2))

        for a, b in zip(nums1, nums2):
            if a < b:
                return -1
            if a > b:
                return 1

        # Numeric parts equal — compare qualifier rank
        if rank1 < rank2:
            return -1
        if rank1 > rank2:
            return 1

        # Same qualifier — compare qualifier number
        if qnum1 < qnum2:
            return -1
        if qnum1 > qnum2:
            return 1

        return 0
    except Exception:
        return _semver_compare(v1, v2)


# ── VersionConstraint ──────────────────────────────────────────────────────────

_OP_CHECK: dict = {
    "<": lambda c: c < 0,
    "<=": lambda c: c <= 0,
    ">": lambda c: c > 0,
    ">=": lambda c: c >= 0,
    "=": lambda c: c == 0,
    "==": lambda c: c == 0,
    "!=": lambda c: c != 0,
}
_RANGE_RE = re.compile(r"^\s*(<=|>=|!=|==|<|>|=)\s*(\S+)\s*$")


@dataclass
class VersionConstraint:
    """A single version constraint: operator + bound + comparison mode."""

    operator: str
    bound: str
    ecosystem: str = "semver"  # "rpm" or "semver"

    def check(self, version: str) -> Optional[bool]:
        """
        Returns True  if the constraint is satisfied,
                False if it is violated,
                None  if the comparison cannot be determined.
        """
        if not version or not self.bound:
            return None
        try:
            if self.ecosystem == RPM_ECOSYSTEM:
                cmp_result = _rpm_compare(version, self.bound)
            elif self.ecosystem == MAVEN_ECOSYSTEM:
                cmp_result = _maven_compare(version, self.bound)
            else:
                cmp_result = _semver_compare(version, self.bound)
            return _OP_CHECK[self.operator](cmp_result)
        except Exception as exc:
            log.debug(
                "Version comparison failed (%r %s %r): %s",
                version,
                self.operator,
                self.bound,
                exc,
            )
            return None


_DASH_RANGE_RE = re.compile(
    r"^([0-9][^\s-]*)-([0-9].*)$"  # "4.1-8.1", "1.1.1k-1.1.1m"
)


def _compatible_release_bounds(version: str, op: str) -> str:
    """
    Expand a compatible-release expression to a '>= lo, < hi' pair.

    Used for:
      ~=  (Python PEP 440 compatible release)
      ~>  (Ruby pessimistic constraint)
      ~   (npm tilde)
      ^   (npm caret)

    Args:
        version : the version string after the operator (e.g. "1.2.3")
        op      : one of "~=", "~>", "~", "^"

    Returns a normalized range string like ">= 1.2.3, < 1.3.0".
    """
    parts = [p for p in re.split(r"[.\-]", version) if p.isdigit()]
    if not parts:
        return f">= {version}"

    nums = [int(p) for p in parts]

    if op in ("~=", "~>"):
        # Drop last segment, increment second-to-last → upper bound
        # ~= 1.2.3 → >= 1.2.3, < 1.3.0
        # ~= 1.2   → >= 1.2,   < 2.0
        # ~> 1.2.3 → >= 1.2.3, < 1.3.0  (Ruby same as Python for 3-part)
        # ~> 1.2   → >= 1.2,   < 2.0    (Ruby: increment first part)
        if len(nums) >= 2:
            upper = list(nums[:-1])
            upper[-1] += 1
        else:
            upper = [nums[0] + 1]
        # Pad upper to same number of dotted parts as the original version
        while len(upper) < len(nums):
            upper.append(0)
        upper_str = ".".join(str(x) for x in upper)
        lower_str = ".".join(str(x) for x in nums)
        return f">= {lower_str}, < {upper_str}"

    elif op == "~":
        # npm tilde: allows patch-level changes
        # ~ 1.2.3 → >= 1.2.3, < 1.3.0  (patch range)
        # ~ 1.2   → >= 1.2.0, < 1.3.0  (patch range within minor)
        # ~ 1     → >= 1.0.0, < 2.0.0  (minor range within major)
        if len(nums) >= 2:
            upper = list(nums[:2])
            upper[1] += 1
            upper_str = ".".join(str(x) for x in upper) + ".0"
        else:
            upper_str = f"{nums[0] + 1}.0.0"
        lower_str = ".".join(str(x) for x in nums)
        return f">= {lower_str}, < {upper_str}"

    elif op == "^":
        # npm caret: allows changes that don't modify left-most non-zero digit
        # ^ 1.2.3 → >= 1.2.3, < 2.0.0
        # ^ 0.2.3 → >= 0.2.3, < 0.3.0
        # ^ 0.0.3 → >= 0.0.3, < 0.0.4
        lower_str = ".".join(str(x) for x in nums)
        # Find left-most non-zero position
        pivot = next((i for i, n in enumerate(nums) if n != 0), len(nums) - 1)
        upper = list(nums)
        upper[pivot] += 1
        for j in range(pivot + 1, len(upper)):
            upper[j] = 0
        upper_str = ".".join(str(x) for x in upper)
        # Pad to 3 parts
        missing = max(0, 3 - len(upper))
        if missing:
            upper_str += ".0" * missing
        return f">= {lower_str}, < {upper_str}"

    return f">= {version}"


def _normalize_range_expr(expr: str) -> str:
    """
    Normalize alternative range formats to the standard operator syntax.

    Supported input formats:
      Standard  : "< 3.0.9"              → unchanged
      Compound  : ">= 2.0, < 2.17.1"    → unchanged
      MITRE     : "[4.1, 8.1)"           → ">= 4.1, < 8.1"
                  "(4.1, 8.1]"           → "> 4.1, <= 8.1"
      Dash      : "4.1-8.1"             → ">= 4.1, < 8.1"
      Maven     : "(,1.0]"              → "<= 1.0"     (open-ended upper)
                  "[1.0,)"              → ">= 1.0"     (open-ended lower)
                  "[1.0]"               → "== 1.0"     (exact)
      npm ~     : "~ 1.2.3"             → ">= 1.2.3, < 1.3.0"
      npm ^     : "^ 1.2.3"             → ">= 1.2.3, < 2.0.0"
      Python ~= : "~= 1.4"              → ">= 1.4, < 2.0"
      Ruby  ~>  : "~> 1.2.3"            → ">= 1.2.3, < 1.3.0"
    """
    expr = expr.strip()
    if not expr:
        return expr

    # Already starts with a standard operator — return as-is
    if _RANGE_RE.match(expr.split(",")[0].strip()):
        return expr

    # ── Compatible-release / pessimistic operators ────────────────────────────
    # ~= (Python), ~> (Ruby), ~ (npm tilde), ^ (npm caret)
    for op_str in ("~=", "~>", "~", "^"):
        if expr.startswith(op_str):
            ver = expr[len(op_str) :].strip()
            if ver:
                result = _compatible_release_bounds(ver, op_str)
                log.debug("Expanded %r %r → %r", op_str, ver, result)
                return result

    # ── Maven open-ended interval notation ────────────────────────────────────
    # "(,1.0]" → "<= 1.0"    "[1.0,)" → ">= 1.0"    "[1.0]" → "== 1.0"
    maven_open_re = re.compile(
        r"^([\[\(])\s*([^,\]\)]*)\s*,?\s*([^,\]\)]*)\s*([\]\)])$"
    )
    m = maven_open_re.match(expr)
    if m:
        lo_bracket = m.group(1)
        lo_val = m.group(2).strip()
        hi_val = m.group(3).strip()
        hi_bracket = m.group(4)

        # [1.0] — exact match (no comma, both lo and hi are same)
        if not hi_val and lo_val and lo_bracket == "[" and hi_bracket == "]":
            return f"== {lo_val}"

        # (,1.0] or (,1.0) — upper bound only
        if not lo_val and hi_val:
            hi_op = "<=" if hi_bracket == "]" else "<"
            return f"{hi_op} {hi_val}"

        # [1.0,) or (1.0,) — lower bound only
        if lo_val and not hi_val:
            lo_op = ">=" if lo_bracket == "[" else ">"
            return f"{lo_op} {lo_val}"

        # [1.0, 2.0) — full interval (both bounds present)
        if lo_val and hi_val:
            lo_op = ">=" if lo_bracket == "[" else ">"
            hi_op = "<=" if hi_bracket == "]" else "<"
            return f"{lo_op} {lo_val}, {hi_op} {hi_val}"

    # ── Dash range: "4.1-8.1" → ">= 4.1, < 8.1" ─────────────────────────────
    m = _DASH_RANGE_RE.match(expr)
    if m:
        lo, hi = m.group(1), m.group(2)
        normalized = f">= {lo}, < {hi}"
        log.debug("Normalized dash range %r → %r", expr, normalized)
        return normalized

    return expr


def _parse_single_range(
    expr: str, ecosystem: str = "semver"
) -> list[VersionConstraint]:
    """Parse a single AND-group of constraints (no ``||``)."""
    constraints: list[VersionConstraint] = []
    if not expr:
        return constraints
    expr = _normalize_range_expr(expr)
    for part in expr.split(","):
        m = _RANGE_RE.match(part.strip())
        if m:
            constraints.append(
                VersionConstraint(m.group(1), m.group(2).strip(), ecosystem)
            )
        else:
            log.warning("Could not parse version range part: %r", part.strip())
    return constraints


def parse_version_range(
    expr: str, ecosystem: str = "semver"
) -> list[VersionConstraint]:
    """
    Parse a version range expression into a list of VersionConstraints.

    Supports OR groups separated by ``||``.  Within each group, constraints
    are comma-separated (AND logic).  A version matches if it satisfies
    ALL constraints in ANY group.

    Supported formats:
      Operator  : "< 3.0.9"                          →  < 3.0.9
      Compound  : ">= 2.0, < 2.17.1"                 →  >= 2.0 AND < 2.17.1
      OR groups : "< 4.2.1 || >= 4.1.0, < 4.1.6"     →  (< 4.2.1) OR (>= 4.1.0 AND < 4.1.6)
      Exact     : "== 3.0.7"                          →  exactly 3.0.7
      Dash      : "4.1-8.1"                           →  >= 4.1 AND < 8.1
      Interval  : "[4.1, 8.1)"                        →  >= 4.1 AND < 8.1 (MITRE notation)

    Operators:  <  <=  >  >=  ==  =  !=

    When ``||`` is present the returned list is a *flat merge* of all
    groups — the OR boundary info is kept internally for
    ``version_in_range`` / ``determine_status`` which accept the
    ``or_groups`` form via ``parse_version_range_or``.

    For backward compatibility this still returns ``list[VersionConstraint]``
    (the first group when ``||`` is absent, or a flat merge).  Use
    ``parse_version_range_or`` when OR semantics are needed.
    """
    if "||" not in (expr or ""):
        return _parse_single_range(expr, ecosystem)
    # Flat merge for callers that don't understand OR groups
    all_constraints: list[VersionConstraint] = []
    for group_expr in expr.split("||"):
        all_constraints.extend(_parse_single_range(group_expr.strip(), ecosystem))
    return all_constraints


def parse_version_range_or(
    expr: str, ecosystem: str = "semver"
) -> list[list[VersionConstraint]]:
    """
    Parse a version range expression into OR groups.

    Each group is a ``list[VersionConstraint]`` where all constraints
    must be satisfied (AND).  A version is affected if it matches
    **any** group (OR).

    Examples::

        "< 4.2.1"                        → [[< 4.2.1]]
        ">= 2.0, < 2.17.1"              → [[>= 2.0, < 2.17.1]]
        "< 4.2.1 || >= 4.1.0, < 4.1.6"  → [[< 4.2.1], [>= 4.1.0, < 4.1.6]]
    """
    if not expr:
        return []
    groups: list[list[VersionConstraint]] = []
    for group_expr in expr.split("||"):
        parsed = _parse_single_range(group_expr.strip(), ecosystem)
        if parsed:
            groups.append(parsed)
    return groups


def version_in_range(
    version: str,
    constraints: list[VersionConstraint] | list[list[VersionConstraint]],
) -> Optional[bool]:
    """
    Check whether *version* falls within the given constraints.

    Accepts two forms:

    - ``list[VersionConstraint]`` — single AND group (legacy).
      Returns True if ALL constraints are satisfied.
    - ``list[list[VersionConstraint]]`` — OR groups (from
      ``parse_version_range_or``).  Returns True if ALL constraints
      in ANY group are satisfied.

    Returns None if any comparison could not be determined.
    """
    if not constraints:
        return None

    # Detect OR-groups form: list of lists
    if constraints and isinstance(constraints[0], list):
        or_groups: list[list[VersionConstraint]] = constraints  # type: ignore[assignment]
        any_true = False
        for group in or_groups:
            results = [c.check(version) for c in group]
            if any(r is None for r in results):
                continue
            if all(results):
                any_true = True
                break
        if any_true:
            return True
        # If no group matched, check if any had unknown results
        all_known = True
        for group in or_groups:
            results = [c.check(version) for c in group]
            if any(r is None for r in results):
                all_known = False
        return None if not all_known else False

    # Single AND group (legacy path)
    results = [c.check(version) for c in constraints]
    if any(r is None for r in results):
        return None
    return all(results)


def determine_status(
    version: str,
    constraints: list[VersionConstraint] | list[list[VersionConstraint]],
) -> OsvStatus:
    """
    Determine affectedness status for a single version string.

    Accepts both single AND group and OR groups (list of lists).

    Returns:
        OsvStatus.AFFECTED     — version falls within the vulnerable range
        OsvStatus.NOT_AFFECTED — version is outside the vulnerable range
        OsvStatus.UNKNOWN      — version is missing or comparison failed
    """
    # version_in_range is tri-state: True (in range), False (out of range), None (unknown).
    result = version_in_range(version, constraints)
    if result is None:
        return OsvStatus.UNKNOWN
    return OsvStatus.AFFECTED if result else OsvStatus.NOT_AFFECTED
