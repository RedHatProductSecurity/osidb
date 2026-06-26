"""Smoke tests for apps.ace.version (copied from vulncli).

The comprehensive test suite lives in ~/Projects/vulncli/tests/. These smoke
tests verify that the copy is functional and covers the ecosystems used in ACE.
"""

import pytest

from apps.ace.version import (
    OsvStatus,
    _rpm_compare,
    determine_status,
    extract_upstream_version,
    parse_version_range_or,
)

pytestmark = pytest.mark.unit


# ── extract_upstream_version ──────────────────────────────────────────────────


def test_rpm_strips_release():
    assert extract_upstream_version("3.0.7-18.el9_2", "rpm") == "3.0.7"


def test_rpm_strips_epoch_and_release():
    assert extract_upstream_version("1:1.1.1k-6.el8_5", "rpm") == "1.1.1k"


def test_golang_strips_v_prefix():
    assert extract_upstream_version("v0.40.0", "golang") == "0.40.0"


def test_semver_unchanged():
    assert extract_upstream_version("14.10.3", "nuget") == "14.10.3"


def test_empty_version():
    assert extract_upstream_version("", "rpm") is None


# ── determine_status ──────────────────────────────────────────────────────────


def test_determine_affected_semver():
    constraints = parse_version_range_or("< 14.10.3", "nuget")
    assert determine_status("10.0.0", constraints) == OsvStatus.AFFECTED


def test_determine_not_affected_semver():
    constraints = parse_version_range_or("< 14.10.3", "nuget")
    assert determine_status("14.10.3", constraints) == OsvStatus.NOT_AFFECTED


def test_determine_not_affected_fixed_version():
    constraints = parse_version_range_or("< 3.0.9", "nuget")
    assert determine_status("3.5.6", constraints) == OsvStatus.NOT_AFFECTED


def test_determine_affected_with_lower_bound():
    constraints = parse_version_range_or(">= 2.0, < 2.15.0", "maven")
    assert determine_status("2.13.0", constraints) == OsvStatus.AFFECTED


def test_determine_not_affected_below_lower_bound():
    constraints = parse_version_range_or(">= 2.0, < 2.15.0", "maven")
    assert determine_status("1.9.9", constraints) == OsvStatus.NOT_AFFECTED


def test_determine_affected_rpm():
    constraints = parse_version_range_or("< 3.0.9", "rpm")
    assert determine_status("3.0.7", constraints) == OsvStatus.AFFECTED


def test_determine_not_affected_rpm():
    constraints = parse_version_range_or("< 3.0.9", "rpm")
    assert determine_status("3.0.9", constraints) == OsvStatus.NOT_AFFECTED


# ── _rpm_compare edge cases ──────────────────────────────────────────────────


def test_rpm_empty_release_sorts_before_nonempty():
    assert _rpm_compare("1.0", "1.0-1") == -1


def test_rpm_nonempty_release_sorts_after_empty():
    assert _rpm_compare("1.0-1", "1.0") == 1


def test_rpm_both_releases_empty_equal():
    assert _rpm_compare("1.0", "1.0") == 0


def test_rpm_numeric_segment_beats_alpha():
    assert _rpm_compare("1.1", "1a") == 1
    assert _rpm_compare("1a", "1.1") == -1


# ── caret all-zeros ─────────────────────────────────────────────────────────


def test_caret_all_zeros():
    constraints = parse_version_range_or("^ 0.0.0", "npm")
    assert determine_status("0.0.0", constraints) == OsvStatus.AFFECTED


def test_caret_all_zeros_upper_bound():
    constraints = parse_version_range_or("^ 0.0.0", "npm")
    assert determine_status("0.0.1", constraints) == OsvStatus.NOT_AFFECTED


# ── determine_status ────────────────────────────────────────────────────────


def test_determine_unknown_no_constraints():
    assert determine_status("1.0.0", []) == OsvStatus.UNKNOWN


def test_determine_unknown_no_version():
    constraints = parse_version_range_or("< 3.0.9", "nuget")
    assert determine_status("", constraints) == OsvStatus.UNKNOWN
