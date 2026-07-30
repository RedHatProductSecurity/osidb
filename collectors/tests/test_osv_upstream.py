import pytest

from collectors.osv.collectors import (
    OSVCollector,
    _merge_osv_upstream_lists,
    _osv_upstream_purl_dedupe_key,
)
from osidb.models import Flaw, UpstreamData
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestMergeOsvUpstreamLists:
    def test_merge_purls_dedupes_identical_entries(self):
        """Test that upstream purl rows with the same dedupe key are skipped."""
        entry = {
            "purl": "pkg:npm/a",
            "name": "a",
            "ecosystem": "npm",
            "ranges": [],
            "versions": ["1"],
        }
        existing = [entry]
        additions = [
            dict(entry),
            {
                "purl": "pkg:npm/b",
                "name": "b",
                "ecosystem": "npm",
                "ranges": [],
                "versions": [],
            },
        ]
        merged = _merge_osv_upstream_lists(
            existing, additions, _osv_upstream_purl_dedupe_key
        )
        assert len(merged) == 2
        assert merged[0] == entry
        assert merged[1]["purl"] == "pkg:npm/b"

    def test_merge_purls_keeps_same_purl_with_different_ranges(self):
        """Same purl but different ranges/versions are separate rows."""
        existing = [
            {
                "purl": "pkg:npm/a",
                "name": "a",
                "ecosystem": "npm",
                "ranges": [],
                "versions": ["1"],
            }
        ]
        additions = [
            {
                "purl": "pkg:npm/a",
                "name": "a",
                "ecosystem": "npm",
                "ranges": [{"type": "SEMVER"}],
                "versions": [],
            },
        ]
        merged = _merge_osv_upstream_lists(
            existing, additions, _osv_upstream_purl_dedupe_key
        )
        assert len(merged) == 2

    def test_merge_purls_includes_purl_less_entries(self):
        """Purl-less entries with name+ecosystem are merged, not dropped."""
        existing = [
            {
                "purl": "",
                "name": "linux",
                "ecosystem": "Linux",
                "ranges": [],
                "versions": [],
            }
        ]
        additions = [
            dict(existing[0]),
            {
                "purl": "",
                "name": "linux",
                "ecosystem": "Linux",
                "ranges": [{"type": "ECOSYSTEM"}],
                "versions": [],
            },
            {
                "purl": "pkg:npm/foo",
                "name": "foo",
                "ecosystem": "npm",
                "ranges": [],
                "versions": [],
            },
        ]
        merged = _merge_osv_upstream_lists(
            existing, additions, _osv_upstream_purl_dedupe_key
        )
        # exact duplicate removed, distinct-range purl-less + npm kept
        assert len(merged) == 3
        assert merged[0]["name"] == "linux"
        assert merged[0]["ranges"] == []
        assert merged[1]["name"] == "linux"
        assert merged[1]["ranges"] == [{"type": "ECOSYSTEM"}]
        assert merged[2]["purl"] == "pkg:npm/foo"


class TestOSVCollectorExtractUpstreamFields:
    def test_extract_content_upstream_purls(self):
        """Test purl extraction from OSV vulnerabilities"""
        osv_vuln = {
            "id": "GHSA-test",
            "aliases": [],
            "summary": "short title",
            "details": "longer narrative",
            "published": "2020-01-02T00:00:00Z",
            "affected": [
                {
                    "package": {"purl": "pkg:npm/foo"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                    "versions": ["1.0.0"],
                },
                {"package": {}, "ranges": [], "versions": []},
            ],
            "severity": [],
            "references": [],
        }
        _osv_id, _cve_ids, content = OSVCollector().extract_content(osv_vuln)
        assert content["upstream_purls"] == [
            {
                "purl": "pkg:npm/foo",
                "name": None,
                "ecosystem": None,
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                "versions": ["1.0.0"],
            }
        ]

    def test_extract_content_upstream_purls_includes_package_name_and_ecosystem(self):
        """Test OSV package name and ecosystem are stored alongside purl when present."""
        osv_vuln = {
            "id": "PKG-1",
            "aliases": [],
            "summary": "s",
            "details": "",
            "published": None,
            "affected": [
                {
                    "package": {
                        "name": "example-lib",
                        "ecosystem": "npm",
                        "purl": "pkg:npm/example-lib",
                    },
                    "ranges": [],
                    "versions": [],
                }
            ],
            "references": [],
        }
        _osv_id, _cve_ids, content = OSVCollector().extract_content(osv_vuln)
        assert content["upstream_purls"] == [
            {
                "purl": "pkg:npm/example-lib",
                "name": "example-lib",
                "ecosystem": "npm",
                "ranges": [],
                "versions": [],
            }
        ]

    def test_extract_content_upstream_purls_accepts_purl_less_entries(self):
        """Test entries with name+ecosystem but no purl are accepted."""
        osv_vuln = {
            "id": "CVE-2026-64189",
            "aliases": [],
            "summary": "Linux kernel vulnerability",
            "details": "",
            "published": None,
            "affected": [
                {
                    "package": {
                        "name": "Kernel",
                        "ecosystem": "Linux",
                    },
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    "versions": [],
                },
                {
                    "package": {
                        "purl": "pkg:npm/foo",
                        "name": "foo",
                        "ecosystem": "npm",
                    },
                    "ranges": [],
                    "versions": [],
                },
                {
                    "package": {},
                    "ranges": [],
                    "versions": [],
                },
            ],
            "references": [],
        }
        _osv_id, _cve_ids, content = OSVCollector().extract_content(osv_vuln)
        # Should include purl-less entry with name+ecosystem, and entry with purl
        # Should skip entry with no purl and no name+ecosystem
        assert len(content["upstream_purls"]) == 2
        assert content["upstream_purls"][0] == {
            "purl": "",
            "name": "Kernel",
            "ecosystem": "Linux",
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            "versions": [],
        }
        assert content["upstream_purls"][1]["purl"] == "pkg:npm/foo"


@pytest.mark.django_db
class TestOsvUpstreamContentWrittenToFlaw:
    """
    Test OSV snippet content is merged onto Flaw via _append_osv_upstream_to_flaw when a snippet
    is collected for an existing CVE.
    """

    def test_append_osv_upstream_to_flaw_merges_from_content(self):
        flaw = FlawFactory(embargoed=False)
        UpstreamData.objects.create(
            flaw=flaw,
            source="OSV",
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
            upstream_purls=[
                {
                    "purl": "pkg:npm/keep",
                    "name": "keep",
                    "ecosystem": "npm",
                    "ranges": [],
                    "versions": ["1"],
                }
            ],
        )
        content = {
            "upstream_purls": [
                {
                    "purl": "pkg:npm/keep",
                    "name": "keep",
                    "ecosystem": "npm",
                    "ranges": [],
                    "versions": ["1"],
                },
                {
                    "purl": "pkg:pypi/newpkg",
                    "name": "newpkg",
                    "ecosystem": "PyPI",
                    "ranges": [],
                    "versions": ["0.1"],
                },
            ],
        }
        OSVCollector()._append_osv_upstream_to_flaw(flaw, content)
        flaw.refresh_from_db()
        upstream = flaw.upstream_data.first()
        assert upstream.upstream_purls == [
            {
                "purl": "pkg:npm/keep",
                "name": "keep",
                "ecosystem": "npm",
                "ranges": [],
                "versions": ["1"],
            },
            {
                "purl": "pkg:pypi/newpkg",
                "name": "newpkg",
                "ecosystem": "PyPI",
                "ranges": [],
                "versions": ["0.1"],
            },
        ]

    def test_extract_content_end_to_end_on_flaw_via_append(self):
        """Test that extract_content output shape is persisted on Flaw through the merge helper."""
        osv_vuln = {
            "id": "GHSA-e2e",
            "aliases": ["CVE-2099-7001"],
            "summary": "sum",
            "details": "detailed text",
            "published": "2019-06-01T00:00:00Z",
            "affected": [
                {
                    "package": {
                        "name": "merge-test",
                        "ecosystem": "npm",
                        "purl": "pkg:npm/merge-test",
                    },
                    "ranges": [],
                    "versions": ["2.0.0"],
                }
            ],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                }
            ],
            "references": [],
        }
        _osv_id, _cve_ids, content = OSVCollector().extract_content(osv_vuln)
        flaw = FlawFactory(embargoed=False, cve_id="CVE-2099-7001")
        OSVCollector()._append_osv_upstream_to_flaw(flaw, content)
        flaw.refresh_from_db()
        upstream = flaw.upstream_data.first()
        assert upstream.upstream_purls == content["upstream_purls"]
        assert Flaw.objects.filter(uuid=flaw.uuid).count() == 1

    def test_append_osv_upstream_to_flaw_preserves_purl_less_entries(self):
        """Test that purl-less entries with name survive the append/merge process."""
        flaw = FlawFactory(embargoed=False)
        content = {
            "upstream_purls": [
                {
                    "purl": "",
                    "name": "linux",
                    "ecosystem": "Linux",
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    "versions": [],
                }
            ],
        }
        OSVCollector()._append_osv_upstream_to_flaw(flaw, content)
        flaw.refresh_from_db()
        upstream = flaw.upstream_data.first()
        assert len(upstream.upstream_purls) == 1
        assert upstream.upstream_purls[0]["name"] == "linux"
        assert upstream.upstream_purls[0]["ecosystem"] == "Linux"
        assert upstream.upstream_purls[0]["purl"] == ""
