import pytest

from osidb.models.flaw.upstream import UpstreamData
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestComponentEcosystems:
    def test_component_ecosystems_from_purl_type(self):
        """PURL type strings are used as ecosystem identifiers."""
        flaw = FlawFactory()
        upstream = UpstreamData(
            flaw=flaw,
            source=UpstreamData.Source.OSV,
            upstream_purls=[
                {"purl": "pkg:npm/express", "name": "express", "ecosystem": "npm"},
                {"purl": "pkg:pypi/requests", "name": "requests", "ecosystem": "PyPI"},
                {
                    "purl": "pkg:maven/org.apache/log4j",
                    "name": "log4j",
                    "ecosystem": "Maven",
                },
            ],
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        result = upstream.component_ecosystems

        assert result == {
            "express": ["npm"],
            "requests": ["pypi"],
            "log4j": ["maven"],
        }

    def test_component_ecosystems_no_entries(self):
        """Empty upstream_purls returns an empty dict."""
        flaw = FlawFactory()
        upstream = UpstreamData(
            flaw=flaw,
            source=UpstreamData.Source.OSV,
            upstream_purls=[],
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        result = upstream.component_ecosystems

        assert result == {}

    def test_component_ecosystems_malformed_purl_fallback(self):
        """Malformed PURL falls back to _OSV_ECOSYSTEM_MAP lookup."""
        flaw = FlawFactory()
        upstream = UpstreamData(
            flaw=flaw,
            source=UpstreamData.Source.OSV,
            upstream_purls=[
                {
                    "purl": "not-a-valid-purl",
                    "name": "mygolib",
                    "ecosystem": "Go",
                },
            ],
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        result = upstream.component_ecosystems

        assert result == {"mygolib": ["golang"]}

    def test_component_ecosystems_unknown_ecosystem_skipped(self):
        """Entry with unrecognized ecosystem and no valid PURL is skipped."""
        flaw = FlawFactory()
        upstream = UpstreamData(
            flaw=flaw,
            source=UpstreamData.Source.OSV,
            upstream_purls=[
                {
                    "purl": "not-a-valid-purl",
                    "name": "some-package",
                    "ecosystem": "UnknownEcosystem",
                },
            ],
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        result = upstream.component_ecosystems

        assert result == {}

    def test_component_ecosystems_multiple_ecosystems(self):
        """When two entries share a component name, both ecosystems are collected."""
        flaw = FlawFactory()
        upstream = UpstreamData(
            flaw=flaw,
            source=UpstreamData.Source.OSV,
            upstream_purls=[
                {"purl": "pkg:npm/redis", "name": "redis", "ecosystem": "npm"},
                {"purl": "pkg:pypi/redis", "name": "redis", "ecosystem": "PyPI"},
            ],
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        result = upstream.component_ecosystems

        assert result == {"redis": ["npm", "pypi"]}
