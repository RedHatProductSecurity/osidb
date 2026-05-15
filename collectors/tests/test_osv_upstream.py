import pytest

from collectors.osv.collectors import (
    OSVCollector,
    _merge_osv_upstream_lists,
    _osv_upstream_description_dedupe_key,
    _osv_upstream_purl_dedupe_key,
    _osv_upstream_severity_dedupe_key,
)
from osidb.models import Flaw, UpstreamData
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestMergeOsvUpstreamLists:
    def test_merge_purls_dedupes_by_purl(self):
        """Test that upstream purls are deduplicated"""
        existing = [{"purl": "pkg:npm/a", "ranges": [], "versions": ["1"]}]
        additions = [
            {"purl": "pkg:npm/a", "ranges": [{"type": "SEMVER"}], "versions": []},
            {"purl": "pkg:npm/b", "ranges": [], "versions": []},
        ]
        merged = _merge_osv_upstream_lists(
            existing, additions, _osv_upstream_purl_dedupe_key
        )
        assert len(merged) == 2
        assert merged[0]["purl"] == "pkg:npm/a"
        assert merged[0]["versions"] == ["1"]
        assert merged[1]["purl"] == "pkg:npm/b"

    def test_merge_descriptions_dedupes_by_trimmed_text(self):
        """Test that upstream descriptions are deduplicated"""
        existing = ["first"]
        additions = ["  first  ", "second", "", "   "]
        merged = _merge_osv_upstream_lists(
            existing, additions, _osv_upstream_description_dedupe_key
        )
        assert merged == ["first", "second"]

    def test_merge_severities_dedupes_by_canonical_json(self):
        """Test that upstream severities are dedeuplicated"""
        a = {
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                }
            ]
        }
        b = {
            "severity": [
                {
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    "type": "CVSS_V3",
                }
            ]
        }
        merged = _merge_osv_upstream_lists([a], [b], _osv_upstream_severity_dedupe_key)
        assert len(merged) == 1


class TestOSVCollectorExtractUpstreamFields:
    def test_extract_content_upstream_purls_and_descriptions(self):
        """Test purl and description extraction from OSV vulnerabilities"""
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
        assert content["upstream_descriptions"] == ["longer narrative"]
        assert content["upstream_purls"] == [
            {
                "purl": "pkg:npm/foo",
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                "versions": ["1.0.0"],
            }
        ]

    def test_extract_content_upstream_severities_top_level(self):
        """Test severity extraction from OSV vulnerabilities at the top level"""
        osv_vuln = {
            "id": "CVE-2099-1",
            "aliases": ["CVE-2099-1"],
            "summary": "s",
            "details": "",
            "published": None,
            "affected": [],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                }
            ],
            "database_specific": {"severity": 7.5},
            "references": [],
        }
        _osv_id, _cve_ids, content = OSVCollector().extract_content(osv_vuln)
        assert content["upstream_descriptions"] == []
        assert content["upstream_severities"] == [
            {
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    }
                ],
                "db_severity": 7.5,
            }
        ]

    def test_extract_content_upstream_severities_top_level_db_only(self):
        """database_specific.severity is captured even when severity array is empty."""
        osv_vuln = {
            "id": "CVE-2099-2",
            "aliases": ["CVE-2099-2"],
            "summary": "s",
            "details": "",
            "published": None,
            "affected": [],
            "severity": [],
            "database_specific": {"severity": 8.0},
            "references": [],
        }
        _osv_id, _cve_ids, content = OSVCollector().extract_content(osv_vuln)
        assert content["upstream_severities"] == [{"db_severity": 8.0}]

    def test_extract_content_upstream_severities_per_affected(self):
        """Test severity extraction from OSV vulnerabilities at the affected level"""
        osv_vuln = {
            "id": "PKG-1",
            "aliases": [],
            "summary": "s",
            "details": "d",
            "published": None,
            "severity": [],
            "affected": [
                {
                    "package": {"name": "x"},
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "database_specific": {"severity": "HIGH"},
                }
            ],
            "references": [],
        }
        _osv_id, _cve_ids, content = OSVCollector().extract_content(osv_vuln)
        assert content["upstream_descriptions"] == ["d"]
        assert content["upstream_severities"] == [
            [
                {
                    "affect_severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "affect_db_severity": "HIGH",
                }
            ]
        ]


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
            upstream_purls=[{"purl": "pkg:npm/keep", "ranges": [], "versions": ["1"]}],
            upstream_descriptions=["already stored"],
            upstream_severities=[{"existing": True}],
        )
        content = {
            "upstream_purls": [
                {
                    "purl": "pkg:npm/keep",
                    "ranges": [{"type": "ECOSYSTEM"}],
                    "versions": [],
                },
                {"purl": "pkg:pypi/newpkg", "ranges": [], "versions": ["0.1"]},
            ],
            "upstream_descriptions": ["  already stored  ", "from new osv record"],
            "upstream_severities": [{"new": "row"}, {"existing": True}],
        }
        OSVCollector()._append_osv_upstream_to_flaw(flaw, content)
        flaw.refresh_from_db()
        upstream = flaw.upstream_data.first()
        assert upstream.upstream_purls == [
            {"purl": "pkg:npm/keep", "ranges": [], "versions": ["1"]},
            {"purl": "pkg:pypi/newpkg", "ranges": [], "versions": ["0.1"]},
        ]
        assert upstream.upstream_descriptions == [
            "already stored",
            "from new osv record",
        ]
        assert upstream.upstream_severities == [
            {"existing": True},
            {"new": "row"},
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
                    "package": {"purl": "pkg:npm/merge-test"},
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
        assert upstream.upstream_descriptions == content["upstream_descriptions"]
        assert upstream.upstream_severities == content["upstream_severities"]
        assert Flaw.objects.filter(uuid=flaw.uuid).count() == 1
