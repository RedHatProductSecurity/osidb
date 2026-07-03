import importlib.metadata
from dataclasses import dataclass, field
from typing import Any

from celery.utils.log import get_task_logger
from django.db import transaction
from packageurl import PackageURL

from apps.ace.constants import (
    CHROMIUM_NAMES,
    GO_STDLIB_PACKAGES,
    LABEL_AUTO_AFFECTS,
    LABEL_AUTO_REJECTED,
    LABEL_MANUAL_TRIAGE,
    LABEL_POTENTIAL_REJECTION,
)
from apps.ace.osv_ranges import OsvPackageInfo, match_component_to_upstream
from apps.ace.version import (
    OsvStatus,
    determine_status,
    extract_upstream_version,
    parse_version_range_or,
)
from collectors.component_mapping.models import (
    AmbiguousNpmPackage,
    BlocklistEntry,
    ComponentMapEntry,
    CrossEcosystemName,
    SemiStrictReviewEntry,
    StrictNpmPackage,
    StrictPackage,
    VerifiedMapping,
)
from config.celery import app
from osidb.helpers import bypass_rls
from osidb.models import Flaw
from osidb.models.affect import Affect, AffectSettings, NotAffectedJustification
from osidb.models.flaw.label import FlawCollaborator, FlawLabel
from osidb.models.flaw.upstream import UpstreamData

logger = get_task_logger(__name__)

try:
    from lib_newtopia import NewtopiaQuerier  # type: ignore[import-untyped]

    HAS_LIB_NEWTOPIA = True
except ImportError:
    NewtopiaQuerier = None  # type: ignore[assignment,misc]
    HAS_LIB_NEWTOPIA = False


def _flaw_components(flaw: Flaw) -> list[str]:
    components = [c for c in (flaw.components or []) if c and str(c).strip()]
    if not components:
        raise ValueError(f"Flaw {flaw.uuid} has no non-empty components to search")
    return components


@dataclass
class PreFilterResult:
    action: str
    label: str = ""
    resolved_names: list[str] = field(default_factory=list)
    reason: str = ""


def _resolve_component(component: str) -> tuple[list[str], bool]:
    """
    Translate an OSIDB component name to upstream package identifier.

    Checks the ComponentMapEntry table (populated by the component_mapping
    collector) with case-insensitive lookup. Falls back to "space to dash"
    normalization if no mapping exists.

    Returns ``(resolved_names, has_mapping)`` where ``has_mapping`` is True
    when the component was found in the ComponentMapEntry table.
    """
    component = component.strip()
    entry = ComponentMapEntry.objects.filter(name__iexact=component).first()
    if entry:
        pkgs = entry.upstream_packages
        resolved = pkgs if isinstance(pkgs, list) else [pkgs]
        return resolved, True
    return [component.replace(" ", "-")], False


def _is_go_stdlib(components: list[str]) -> bool:
    """
    Check if any component is a Go stdlib package.
    """
    has_golang = any(c.lower() == "golang" for c in components)
    if not has_golang:
        return False
    for c in components:
        first_seg = c.split("/")[0]
        if (
            "." not in first_seg
            and "-" not in first_seg
            and first_seg.lower() in GO_STDLIB_PACKAGES
        ):
            return True
    return False


def _is_verified_mapping(component: str, resolved: list[str]) -> bool:
    """
    Check if the component has a verified mapping using the table collected
    by the component_mapping collector.
    """
    # List mappings (e.g. ["a2wsgi", "python-a2wsgi"]) are convention-based,
    # auto-generated from SBOM data, and always trusted.
    if isinstance(resolved, list) and len(resolved) > 1:
        return True
    if VerifiedMapping.objects.filter(name__iexact=component).exists():
        return True
    return False


def _apply_label(flaw: Flaw, label: str) -> None:
    if not label:
        return
    FlawCollaborator.objects.get_or_create(
        flaw=flaw,
        label=label,
        defaults={
            "type": FlawLabel.FlawLabelType.CONTEXT_BASED,
            "state": FlawCollaborator.FlawCollaboratorState.NEW,
        },
    )


def _pre_filter_component(
    flaw: Flaw, component: str, ecosystem: str
) -> PreFilterResult:
    """
    Check a component against mapping data (source-component-mapping)
    before querying lib-newtopia.

    Decision tree (checks run in order, first match wins):
      1. Blocklist -> skip
      2. Go stdlib -> manual triage
      3. Chromium -> manual triage
      4. Resolve component name
      5. Verified mapping guard -> manual triage if unverified
      6. Cross-ecosystem guard -> manual triage if ambiguous
      7. Semi-strict review -> manual triage if unresolved
      8. Confidence check -> potential-rejection if low confidence
      9. All checks pass -> auto-affects, the rest of the process continues
    """
    component_lower = component.strip().lower()

    # Blocklist check
    block = BlocklistEntry.objects.filter(name=component_lower).first()
    if block:
        return PreFilterResult(
            action="skip",
            label=LABEL_AUTO_REJECTED,
            reason=f"Blocked: {block.reason}",
        )

    # Go stdlib check
    if _is_go_stdlib(flaw.components or []):
        return PreFilterResult(
            action="manual",
            label=LABEL_MANUAL_TRIAGE,
            reason="Go stdlib CVE, requires specialized workflow",
        )

    # Chromium check
    if component_lower in CHROMIUM_NAMES:
        return PreFilterResult(
            action="manual",
            label=LABEL_MANUAL_TRIAGE,
            reason="Chromium CVE, requires specialized workflow",
        )

    resolved, has_custom_mapping = _resolve_component(component)

    # Verified mapping guard
    if has_custom_mapping and not _is_verified_mapping(component, resolved):
        return PreFilterResult(
            action="manual",
            label=LABEL_MANUAL_TRIAGE,
            resolved_names=resolved,
            reason=f"Mapping '{component}' is not verified",
        )

    # Cross-ecosystem guard
    cross_eco = CrossEcosystemName.objects.filter(name=component_lower).first()
    if cross_eco and not ecosystem:
        return PreFilterResult(
            action="manual",
            label=LABEL_MANUAL_TRIAGE,
            resolved_names=resolved,
            reason=(
                f"'{component}' exists in ecosystems: {cross_eco.ecosystems}. "
                "Ecosystem must be specified to proceed."
            ),
        )

    # Semi-strict review
    semi_strict = SemiStrictReviewEntry.objects.filter(name=component_lower).first()
    if semi_strict:
        pick = (
            semi_strict.data.get("pick", "")
            if isinstance(semi_strict.data, dict)
            else ""
        )
        if not pick:
            return PreFilterResult(
                action="manual",
                label=LABEL_MANUAL_TRIAGE,
                resolved_names=resolved,
                reason=f"'{component}' has ambiguous SBOM matches requiring review",
            )
        resolved = [pick]

    # Strict package check
    resolved_lower = [r.lower() for r in resolved]
    is_strict = StrictPackage.objects.filter(name__in=resolved_lower).exists()
    is_strict_npm = StrictNpmPackage.objects.filter(name__in=resolved_lower).exists()
    is_ambiguous_npm = AmbiguousNpmPackage.objects.filter(
        name__in=resolved_lower
    ).exists()

    if not (is_strict or is_strict_npm or (is_ambiguous_npm and ecosystem == "npm")):
        return PreFilterResult(
            action="search",
            label=LABEL_POTENTIAL_REJECTION,
            resolved_names=resolved,
            reason="Low confidence, component not in strict package lists",
        )

    # Continue with auto-affects process
    return PreFilterResult(
        action="search",
        label=LABEL_AUTO_AFFECTS,
        resolved_names=resolved,
    )


def _query_newtopia(
    flaw_component: str, ps_modules: list[str], ecosystem: str = ""
) -> list:
    nq = NewtopiaQuerier()  # type: ignore[misc]
    return (
        nq.search([flaw_component], strict=True, ecosystem=ecosystem)
        .filter(products=ps_modules)
        .all()
    )


def _ace_tool_name() -> str:
    try:
        osidb_version = importlib.metadata.version("osidb")
    except importlib.metadata.PackageNotFoundError:
        osidb_version = "unknown"
    try:
        newtopia_version = importlib.metadata.version("lib-newtopia")
        return f"osidb {osidb_version} (lib-newtopia {newtopia_version})"
    except importlib.metadata.PackageNotFoundError:
        return f"osidb {osidb_version}"


def _osv_version_status(
    purl_str: str,
    pkg_info: OsvPackageInfo | None,
) -> tuple[OsvStatus, str | None, str | None]:
    """
    Determine the OSV affectedness status for a single lib_newtopia result purl.

    Returns ``(status, range_str, version_checked)`` where:
      - ``status`` is an :class:`OsvStatus` member
      - ``range_str`` is the range expression derived from upstream_purls, or ``None``
        when no range could be determined (NO_MATCH / NO_RANGE)
      - ``version_checked`` is the upstream version extracted from the result purl, or
        ``None`` when no version was available (NO_MATCH / NO_RANGE / NO_VERSION)
    """
    if pkg_info is None:
        return OsvStatus.NO_MATCH, None, None

    range_str = pkg_info.affected_range()
    if range_str is None:
        return OsvStatus.NO_RANGE, None, None

    try:
        purl_version = PackageURL.from_string(purl_str).version
    except Exception:
        purl_version = None

    upstream_version = extract_upstream_version(purl_version, pkg_info.ecosystem)
    if upstream_version is None:
        return OsvStatus.NO_VERSION, range_str, None

    status = determine_status(
        upstream_version, parse_version_range_or(range_str, pkg_info.ecosystem)
    )
    return status, range_str, upstream_version


def _sync_affects_from_results(
    flaw: Flaw,
    results: list,
    flaw_component: str = "",
    ps_modules: list[str] | None = None,
    ecosystem: str = "",
    upstream_purls: list[dict] | None = None,
) -> dict[str, int]:
    """Create affects on ``flaw`` for each entry in ``results``.

    Each entry is a ``NewcliBuildResult`` or ``NewcliDepResult`` from lib_newtopia.
    Existing affects matching ``(flaw, ps_update_stream, ps_component)`` are skipped.

    When ``upstream_purls`` is provided (from ``UpstreamData``), each result's purl
    version is checked against the OSV version range for the matched component.
    Results whose version falls outside the range are created as NOTAFFECTED affects.
    """
    created = 0
    skipped = 0
    skipped_existing = 0
    marked_notaffected = 0
    flaw_has_high_cvss_score = flaw.has_high_cvss_score
    tool_name = _ace_tool_name()

    pkg_info = match_component_to_upstream(
        flaw_component, upstream_purls or [], ecosystem=ecosystem
    )

    with transaction.atomic():
        for result in results:
            ps_update_stream = getattr(result, "ps_update_stream", None)
            purls = getattr(result, "purls", None) or []
            purl_str = purls[0] if purls else None

            if not ps_update_stream or not purl_str:
                logger.warning(
                    "Skipping lib_newtopia result missing ps_update_stream or purls: %s",
                    getattr(result, "build_nvr", None),
                )
                skipped += 1
                continue

            ps_component = Affect(purl=purl_str).ps_component_from_purl()

            if (
                ps_component
                and Affect.objects.filter(
                    flaw=flaw,
                    ps_update_stream=ps_update_stream,
                    ps_component=ps_component,
                ).exists()
            ):
                skipped_existing += 1
                continue

            osv_status, range_str, version_checked = _osv_version_status(
                purl_str, pkg_info
            )

            affect = Affect(
                flaw=flaw,
                ps_update_stream=ps_update_stream,
                purl=purl_str,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
                impact=flaw.impact,
                created_by="AffectCreationEngine",
                updated_by="AffectCreationEngine",
                assist_meta={
                    "tool_name": tool_name,
                    "tool_input": (
                        f"NewtopiaQuerier().search([{flaw_component!r}], ecosystem={ecosystem!r}, strict=True)"
                        f".filter(products={ps_modules!r}).all()"
                    ),
                    "tool_output": repr(result),
                    "tool_trigger": (
                        f"flaw.components updated (component: {flaw_component!r})"
                    ),
                    "osv_range_used": range_str,
                    "osv_version_checked": version_checked,
                    "osv_status": osv_status.value,
                },
            )

            if osv_status is OsvStatus.NOT_AFFECTED:
                affect.affectedness = Affect.AffectAffectedness.NOTAFFECTED
                affect.resolution = Affect.AffectResolution.NOVALUE
                affect.not_affected_justification = (
                    NotAffectedJustification.VULN_CODE_NOT_PRESENT
                )
                marked_notaffected += 1
            else:
                affect.auto_resolve(flaw_has_high_cvss_score=flaw_has_high_cvss_score)

            affect.save(raise_validation_error=False)
            created += 1

    return {
        "created": created,
        "skipped": skipped,
        "skipped_existing": skipped_existing,
        "marked_notaffected": marked_notaffected,
    }


@app.task
@bypass_rls
def sync_flaw_affects_from_newcli(flaw_id: str) -> dict[str, Any]:
    """
    For each entry in ``Flaw.components``, query lib_newtopia and create affects for each
    result: ``ps_update_stream`` and ``purl`` are taken from the result objects returned by
    ``NewtopiaQuerier``. Existing affects for the same flaw, stream, and ``ps_component``
    (inferred from the purl) are left unchanged.

    The set of PS modules queried is controlled by
    :attr:`osidb.models.affect.AffectSettings.auto_create_ps_modules`
    (``OSIDB_AFFECTS_AUTO_CREATE_PS_MODULES``, JSON list; default ``["hummingbird-1"]``).

    When :attr:`osidb.models.affect.AffectSettings.auto_create` is true
    (``OSIDB_AFFECTS_AUTO_CREATE``), changes to :attr:`~osidb.models.flaw.flaw.Flaw.components`
    register this task on :func:`django.db.transaction.on_commit` from a ``pre_save`` signal
    on :class:`~osidb.models.flaw.flaw.Flaw`.

    If ``lib_newtopia`` is not installed this task is a no-op — it logs a warning and returns
    without creating any affects. Install the package from the internal Nexus repository
    (``PRODSEC_PYPI_INDEX_URL``) to enable automatic affect creation.
    """
    if not HAS_LIB_NEWTOPIA:
        logger.warning(
            "lib_newtopia is not installed; skipping automatic affect creation for flaw %s. "
            "Install lib-newtopia from the internal Nexus repository to enable this feature.",
            flaw_id,
        )
        return {"skipped_reason": "lib_newtopia not installed"}

    flaw = Flaw.objects.get(uuid=flaw_id)
    components = _flaw_components(flaw)
    ps_modules = AffectSettings().auto_create_ps_modules
    totals: dict[str, int] = {
        "created": 0,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 0,
        "pre_filtered": 0,
    }

    osv_data = flaw.upstream_data.filter(source=UpstreamData.Source.OSV).first()
    upstream_purls: list[dict] = osv_data.upstream_purls if osv_data else []
    component_ecosystems = osv_data.component_ecosystems if osv_data else {}

    # Pre-filter all components first. If any component triggers a skip
    # (e.g. blocklist), the entire flaw is skipped — matching vulncli behavior.
    pre_filter_results: list[tuple[str, str, PreFilterResult]] = []
    for flaw_component in components:
        ecosystems = component_ecosystems.get(flaw_component.strip().lower(), [""])
        for ecosystem in ecosystems:
            pf = _pre_filter_component(flaw, flaw_component, ecosystem)
            pre_filter_results.append((flaw_component, ecosystem, pf))

    skip_result = next(
        (pf for _, _, pf in pre_filter_results if pf.action == "skip"), None
    )
    if skip_result:
        _apply_label(flaw, skip_result.label)
        logger.info(
            "Pre-filter skip for flaw=%s: %s",
            flaw_id,
            skip_result.reason,
        )
        totals["pre_filtered"] += 1
        return totals

    for flaw_component, ecosystem, pre_filter in pre_filter_results:
        _apply_label(flaw, pre_filter.label)

        if pre_filter.action != "search":
            logger.info(
                "Pre-filter %s for flaw=%s component=%r: %s",
                pre_filter.action,
                flaw_id,
                flaw_component,
                pre_filter.reason,
            )
            totals["pre_filtered"] += 1
            continue

        for resolved_name in pre_filter.resolved_names:
            results = _query_newtopia(resolved_name, ps_modules, ecosystem=ecosystem)
            stats = _sync_affects_from_results(
                flaw,
                results,
                flaw_component,
                ps_modules,
                ecosystem=ecosystem,
                upstream_purls=upstream_purls,
            )
            for key in stats:
                totals[key] += stats[key]

    logger.info(
        "sync_flaw_affects_from_newcli flaw=%s components=%s %s",
        flaw_id,
        components,
        totals,
    )
    return totals
