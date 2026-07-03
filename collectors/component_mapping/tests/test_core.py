import pytest

from ..core import (
    _dedup_lower,
    _dedup_lower_list,
    fetch_component_mapping,
    sync_component_mapping,
)
from ..models import (
    AmbiguousNpmPackage,
    BlocklistEntry,
    ComponentMapEntry,
    CrossEcosystemName,
    RejectedComponent,
    SemiStrictReviewEntry,
    StrictNpmPackage,
    StrictPackage,
    VerifiedMapping,
)

pytestmark = pytest.mark.unit


SAMPLE_DATA = {
    "metadata": {"version": 1, "generated_at": "2026-06-23T00:00:00Z"},
    "blocklist": {
        "gitlab": "Not shipped by Red Hat",
        "WordPress": "Third-party CMS",
    },
    "component_map": {
        "Django": "python-django",
        "Vault": "github.com/hashicorp/vault",
    },
    "strict_packages": {
        "openssl": ["rhel-9", "rhel-8"],
        "curl": ["rhel-9"],
    },
    "strict_npm_packages": ["express", "lodash"],
    "ambiguous_npm_packages": ["uuid", "debug"],
    "cross_ecosystem_names": {
        "redis": ["npm", "pypi", "golang"],
        "uuid": ["npm", "cargo"],
    },
    "verified_mappings": {
        "Vault": "github.com/hashicorp/vault",
    },
    "semi_strict_review": {
        "accelerator": {"candidates": ["pkg-a", "pkg-b"], "pick": ""},
    },
    "rejected_components": {},
}


class TestDedup:
    def test_dedup_lower_keeps_first(self):
        data = {"GitLab": "reason1", "gitlab": "reason2", "other": "reason3"}
        result = _dedup_lower(data)
        assert result == {"gitlab": "reason1", "other": "reason3"}

    def test_dedup_lower_empty(self):
        assert _dedup_lower({}) == {}

    def test_dedup_lower_list_keeps_first(self):
        data = ["Express", "express", "lodash"]
        result = _dedup_lower_list(data)
        assert result == ["express", "lodash"]

    def test_dedup_lower_list_empty(self):
        assert _dedup_lower_list([]) == []


@pytest.mark.django_db
class TestSyncComponentMapping:
    def test_sync_populates_all_models(self):
        counts = sync_component_mapping(SAMPLE_DATA)

        assert counts["blocklist"] == 2
        assert counts["component_map"] == 2
        assert counts["strict_packages"] == 2
        assert counts["strict_npm_packages"] == 2
        assert counts["ambiguous_npm_packages"] == 2
        assert counts["cross_ecosystem_names"] == 2
        assert counts["verified_mappings"] == 1
        assert counts["semi_strict_review"] == 1
        assert counts["rejected_components"] == 0

    def test_sync_replaces_data(self):
        sync_component_mapping(SAMPLE_DATA)
        assert BlocklistEntry.objects.count() == 2

        modified = {**SAMPLE_DATA, "blocklist": {"only-one": "reason"}}
        sync_component_mapping(modified)
        assert BlocklistEntry.objects.count() == 1
        assert BlocklistEntry.objects.get().name == "only-one"

    def test_sync_idempotent(self):
        sync_component_mapping(SAMPLE_DATA)
        first_counts = {
            m.__name__: m.objects.count()
            for m in [
                BlocklistEntry,
                ComponentMapEntry,
                StrictPackage,
                StrictNpmPackage,
                AmbiguousNpmPackage,
                CrossEcosystemName,
                VerifiedMapping,
                SemiStrictReviewEntry,
                RejectedComponent,
            ]
        }

        sync_component_mapping(SAMPLE_DATA)
        second_counts = {
            m.__name__: m.objects.count()
            for m in [
                BlocklistEntry,
                ComponentMapEntry,
                StrictPackage,
                StrictNpmPackage,
                AmbiguousNpmPackage,
                CrossEcosystemName,
                VerifiedMapping,
                SemiStrictReviewEntry,
                RejectedComponent,
            ]
        }

        assert first_counts == second_counts

    def test_blocklist_lookup_case_insensitive(self):
        sync_component_mapping(SAMPLE_DATA)
        assert BlocklistEntry.objects.filter(name="wordpress").exists()
        assert not BlocklistEntry.objects.filter(name="WordPress").exists()

    def test_component_map_lowercases_name(self):
        sync_component_mapping(SAMPLE_DATA)
        entry = ComponentMapEntry.objects.get(name="django")
        assert entry.upstream_packages == "python-django"

    def test_cross_ecosystem_stores_ecosystems(self):
        sync_component_mapping(SAMPLE_DATA)
        entry = CrossEcosystemName.objects.get(name="redis")
        assert entry.ecosystems == ["npm", "pypi", "golang"]

    def test_strict_packages_stores_repos(self):
        sync_component_mapping(SAMPLE_DATA)
        entry = StrictPackage.objects.get(name="openssl")
        assert entry.repos == ["rhel-9", "rhel-8"]

    def test_sync_handles_empty_sections(self):
        minimal = {
            "metadata": {"version": 1},
            "blocklist": {},
            "component_map": {},
            "strict_packages": {},
            "strict_npm_packages": [],
            "ambiguous_npm_packages": [],
            "cross_ecosystem_names": {},
            "verified_mappings": {},
            "semi_strict_review": {},
            "rejected_components": {},
        }
        counts = sync_component_mapping(minimal)
        assert all(v == 0 for v in counts.values())

    def test_blocklist_dedup_on_case_collision(self):
        data = {
            **SAMPLE_DATA,
            "blocklist": {"GitLab": "reason1", "gitlab": "reason2"},
        }
        sync_component_mapping(data)
        assert BlocklistEntry.objects.count() == 1
        assert BlocklistEntry.objects.get().reason == "reason1"


COMPONENT_MAPPING_CASSETTE = "TestComponentMappingCollection.component_mapping.yaml"


@pytest.mark.django_db
class TestComponentMappingCollection:
    @pytest.mark.default_cassette(COMPONENT_MAPPING_CASSETTE)
    @pytest.mark.vcr
    def test_fetch_component_mapping(self, component_mapping_url):
        data = fetch_component_mapping(url=component_mapping_url)

        assert data["metadata"]["version"] == 1
        assert "blocklist" in data
        assert "component_map" in data
        assert "strict_packages" in data
        assert "strict_npm_packages" in data

    @pytest.mark.default_cassette(COMPONENT_MAPPING_CASSETTE)
    @pytest.mark.vcr
    def test_fetch_and_sync(self, component_mapping_url):
        data = fetch_component_mapping(url=component_mapping_url)
        counts = sync_component_mapping(data)

        assert counts["blocklist"] > 0
        assert counts["component_map"] > 0
        assert counts["strict_packages"] > 0
        assert counts["strict_npm_packages"] > 0
        assert BlocklistEntry.objects.filter(name="gitlab").exists()
        assert ComponentMapEntry.objects.filter(name="django").exists()
        assert StrictPackage.objects.filter(name="openssl").exists()
