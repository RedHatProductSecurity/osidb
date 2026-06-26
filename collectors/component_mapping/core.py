import requests
from django.conf import settings
from django.db import transaction
from requests_gssapi import HTTPSPNEGOAuth

from .constants import COMPONENT_MAPPING_REPO_BRANCH, COMPONENT_MAPPING_REPO_URL
from .models import (
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

COMPONENT_MAPPING_URL = "/".join(
    (
        COMPONENT_MAPPING_REPO_URL,
        "-",
        "jobs",
        "artifacts",
        COMPONENT_MAPPING_REPO_BRANCH,
        "raw",
        "component_mapping.json",
    )
)


def fetch_component_mapping(url=COMPONENT_MAPPING_URL):
    response = requests.get(
        url=url,
        params={"job": "build"},
        auth=HTTPSPNEGOAuth(),
        timeout=settings.DEFAULT_REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _dedup_lower(data: dict) -> dict:
    """Deduplicate dict keys by lowercase, keeping the first occurrence."""
    seen: set[str] = set()
    result: dict = {}
    for key, value in data.items():
        lower = key.lower()
        if lower not in seen:
            seen.add(lower)
            result[lower] = value
    return result


def _dedup_lower_list(data: list) -> list[str]:
    """Deduplicate list values by lowercase, keeping the first occurrence."""
    seen: set[str] = set()
    result: list[str] = []
    for item in data:
        lower = item.lower()
        if lower not in seen:
            seen.add(lower)
            result.append(lower)
    return result


def _sync_blocklist(data: dict) -> int:
    BlocklistEntry.objects.all().delete()
    deduped = _dedup_lower(data)
    entries = [
        BlocklistEntry(name=name, reason=reason) for name, reason in deduped.items()
    ]
    BlocklistEntry.objects.bulk_create(entries)
    return len(entries)


def _sync_component_map(data: dict) -> int:
    ComponentMapEntry.objects.all().delete()
    deduped = _dedup_lower(data)
    entries = [
        ComponentMapEntry(name=name, upstream_packages=upstream)
        for name, upstream in deduped.items()
    ]
    ComponentMapEntry.objects.bulk_create(entries)
    return len(entries)


def _sync_strict_packages(data: dict) -> int:
    StrictPackage.objects.all().delete()
    deduped = _dedup_lower(data)
    entries = [StrictPackage(name=name, repos=repos) for name, repos in deduped.items()]
    StrictPackage.objects.bulk_create(entries)
    return len(entries)


def _sync_strict_npm_packages(data: list) -> int:
    StrictNpmPackage.objects.all().delete()
    deduped = _dedup_lower_list(data)
    entries = [StrictNpmPackage(name=name) for name in deduped]
    StrictNpmPackage.objects.bulk_create(entries)
    return len(entries)


def _sync_ambiguous_npm_packages(data: list) -> int:
    AmbiguousNpmPackage.objects.all().delete()
    deduped = _dedup_lower_list(data)
    entries = [AmbiguousNpmPackage(name=name) for name in deduped]
    AmbiguousNpmPackage.objects.bulk_create(entries)
    return len(entries)


def _sync_cross_ecosystem_names(data: dict) -> int:
    CrossEcosystemName.objects.all().delete()
    deduped = _dedup_lower(data)
    entries = [
        CrossEcosystemName(name=name, ecosystems=ecosystems)
        for name, ecosystems in deduped.items()
    ]
    CrossEcosystemName.objects.bulk_create(entries)
    return len(entries)


def _sync_verified_mappings(data: dict) -> int:
    VerifiedMapping.objects.all().delete()
    deduped = _dedup_lower(data)
    entries = [
        VerifiedMapping(name=name, upstream_package=upstream)
        for name, upstream in deduped.items()
    ]
    VerifiedMapping.objects.bulk_create(entries)
    return len(entries)


def _sync_semi_strict_review(data: dict) -> int:
    SemiStrictReviewEntry.objects.all().delete()
    deduped = _dedup_lower(data)
    entries = [
        SemiStrictReviewEntry(name=name, data=entry_data)
        for name, entry_data in deduped.items()
    ]
    SemiStrictReviewEntry.objects.bulk_create(entries)
    return len(entries)


def _sync_rejected_components(data: dict) -> int:
    RejectedComponent.objects.all().delete()
    if not data:
        return 0
    deduped = _dedup_lower(data)
    entries = [
        RejectedComponent(
            name=name, data=entry_data if isinstance(entry_data, dict) else {}
        )
        for name, entry_data in deduped.items()
    ]
    RejectedComponent.objects.bulk_create(entries)
    return len(entries)


@transaction.atomic
def sync_component_mapping(data: dict) -> dict[str, int]:
    return {
        "blocklist": _sync_blocklist(data.get("blocklist", {})),
        "component_map": _sync_component_map(data.get("component_map", {})),
        "strict_packages": _sync_strict_packages(data.get("strict_packages", {})),
        "strict_npm_packages": _sync_strict_npm_packages(
            data.get("strict_npm_packages", [])
        ),
        "ambiguous_npm_packages": _sync_ambiguous_npm_packages(
            data.get("ambiguous_npm_packages", [])
        ),
        "cross_ecosystem_names": _sync_cross_ecosystem_names(
            data.get("cross_ecosystem_names", {})
        ),
        "verified_mappings": _sync_verified_mappings(data.get("verified_mappings", {})),
        "semi_strict_review": _sync_semi_strict_review(
            data.get("semi_strict_review", {})
        ),
        "rejected_components": _sync_rejected_components(
            data.get("rejected_components", {})
        ),
    }
