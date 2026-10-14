"""Validation and lookups for the RHEL 6 ELS inclusion list."""

import re

from django.db.models import Exists

from .models import Rhel6ElsPackage


def _package_name(value: str) -> str:
    """Validate the catalog's ASCII RPM names and normalize their case."""
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9+._-]+", value) is None:
        raise ValueError("Invalid RHEL 6 ELS package name")
    normalized = value.lower()
    if len(normalized) > 512:
        raise ValueError("Invalid RHEL 6 ELS package name")
    return normalized


def rhel6_els_names(data: dict) -> set[str]:
    """Expand only published families using release-specific RPM relationships.

    Do not use ComponentMapEntry: its cross-release aliases can resolve RHEL 6
    packages to unrelated newer replacements (for example yum -> dnf).
    """
    if not isinstance(data, dict):
        raise ValueError("Invalid RHEL 6 ELS section")
    packages = data.get("packages")
    aliases = data.get("source_package_aliases")
    if not isinstance(packages, list) or not packages or not isinstance(aliases, dict):
        raise ValueError(
            "RHEL 6 ELS requires non-empty packages and RPM source aliases"
        )
    published = {_package_name(name) for name in packages}
    normalized = {}
    for name, source in aliases.items():
        name, source = _package_name(name), _package_name(source)
        if name in normalized and normalized[name] != source:
            raise ValueError("Conflicting RHEL 6 ELS RPM source aliases")
        normalized[name] = source
    if any(
        source in normalized and normalized[source] != source
        for source in normalized.values()
    ):
        raise ValueError("RHEL 6 ELS aliases must point directly to source packages")
    sources = {normalized.get(name, name) for name in published}
    siblings = {name for name, source in normalized.items() if source in sources}
    return published | sources | siblings


def rhel6_els_in_scope(component: str) -> bool | None:
    """None means the list is unavailable, not that all packages are excluded."""
    if not component:
        return None
    packages = Rhel6ElsPackage.objects.all()
    # The outer row distinguishes an empty catalog from a non-match. Keeping
    # both checks in one statement avoids inconsistent snapshots during sync.
    return (
        packages.annotate(in_scope=Exists(packages.filter(name=component.lower())))
        .values_list("in_scope", flat=True)
        .first()
    )
