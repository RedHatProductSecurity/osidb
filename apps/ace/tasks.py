import enum
import importlib.metadata
from dataclasses import dataclass, field
from typing import Any

from celery.utils.log import get_task_logger
from django.db import transaction
from packageurl import PackageURL

from apps.ace.constants import (
    CHROMIUM_CVSS_TABLE,
    CHROMIUM_NAMES,
    CHROMIUM_STATEMENT,
    CHROMIUM_STREAMS,
    GO_STDLIB_BUILDER_PRODUCTS,
    GO_STDLIB_BUILDER_PURL,
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
from osidb.models import Flaw, FlawCVSS, PsModule
from osidb.models.affect import Affect, AffectSettings, NotAffectedJustification
from osidb.models.flaw.label_v2 import WorkflowLabel
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


class PreFilterAction(enum.Enum):
    SEARCH = "search"
    SKIP = "skip"
    MANUAL = "manual"
    SPECIAL = "special"


class SpecialWorkflow(enum.Enum):
    NONE = ""
    CHROMIUM = "chromium"
    GO_STDLIB = "go_stdlib"


@dataclass
class PreFilterResult:
    action: PreFilterAction
    label: str = ""
    resolved_names: list[str] = field(default_factory=list)
    reason: str = ""
    workflow: SpecialWorkflow = SpecialWorkflow.NONE


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


def _is_go_stdlib_component(component: str, all_components: list[str]) -> bool:
    """
    Check if ``component`` is part of a Go stdlib CVE.

    Returns True when ``component`` is either "golang" or a stdlib package
    path (e.g., "net/http"), AND "golang" is present in the flaw's components.
    """
    if component.lower() == "golang":
        return True
    if not any(c.lower() == "golang" for c in all_components):
        return False
    first_seg = component.split("/")[0]
    return (
        "." not in first_seg
        and "-" not in first_seg
        and first_seg.lower() in GO_STDLIB_PACKAGES
    )


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
    WorkflowLabel.objects.get_or_create(flaw=flaw, name=label)


def _pre_filter_component(
    flaw: Flaw, component: str, ecosystem: str
) -> PreFilterResult:
    """
    Check a component against mapping data (source-component-mapping)
    before querying lib-newtopia.

    Decision tree (checks run in order, first match wins):
      1. Blocklist -> skip (auto-rejected)
      2. Go stdlib -> special workflow
      3. Chromium -> special workflow
      4. Resolve component name
      5. Verified mapping guard -> manual triage if unverified
      6. Cross-ecosystem guard -> manual triage if ambiguous
      7. Semi-strict review -> manual triage if unresolved
      8. Confidence check -> potential-rejection if low confidence
      9. All checks pass -> search (auto-affects)
    """
    component_lower = component.strip().lower()

    # Blocklist check
    block = BlocklistEntry.objects.filter(name=component_lower).first()
    if block:
        return PreFilterResult(
            action=PreFilterAction.SKIP,
            label=LABEL_AUTO_REJECTED,
            reason=f"Blocked: {block.reason}",
        )

    # Go stdlib check: the handler runs per stdlib subcomponent path.
    # "golang" component itself is skipped here as it's automatically handled later.
    if _is_go_stdlib_component(component, flaw.components or []):
        if component_lower == "golang":
            return PreFilterResult(
                action=PreFilterAction.MANUAL,
                reason="Go stdlib CVE: golang component handled by go stdlib workflow",
            )
        return PreFilterResult(
            action=PreFilterAction.SPECIAL,
            label=LABEL_AUTO_AFFECTS,
            workflow=SpecialWorkflow.GO_STDLIB,
        )

    # Chromium check
    if component_lower in CHROMIUM_NAMES:
        return PreFilterResult(
            action=PreFilterAction.SPECIAL,
            label=LABEL_AUTO_AFFECTS,
            workflow=SpecialWorkflow.CHROMIUM,
        )

    resolved, has_custom_mapping = _resolve_component(component)

    # Verified mapping guard
    if has_custom_mapping and not _is_verified_mapping(component, resolved):
        return PreFilterResult(
            action=PreFilterAction.MANUAL,
            label=LABEL_MANUAL_TRIAGE,
            resolved_names=resolved,
            reason=f"Mapping '{component}' is not verified",
        )

    # Cross-ecosystem guard
    cross_eco = CrossEcosystemName.objects.filter(name=component_lower).first()
    if cross_eco and not ecosystem:
        return PreFilterResult(
            action=PreFilterAction.MANUAL,
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
                action=PreFilterAction.MANUAL,
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
            action=PreFilterAction.SEARCH,
            label=LABEL_POTENTIAL_REJECTION,
            resolved_names=resolved,
            reason="Low confidence, component not in strict package lists",
        )

    # Continue with auto-affects process
    return PreFilterResult(
        action=PreFilterAction.SEARCH,
        label=LABEL_AUTO_AFFECTS,
        resolved_names=resolved,
    )


def _parse_chrome_advisory(advisory_url: str, cve_id: str) -> dict:
    """
    Fetch and parse a Chrome release blog post containing CVE information,
    returning per-CVE metadata.

    Returns a dict with keys: title, cve_description, impact (or empty dict on failure)
    """
    if not advisory_url:
        return {}
    try:
        from advisory_parser import Parser

        flaws, _ = Parser.parse_from_url(advisory_url)
        for flaw in flaws:
            if cve_id in (flaw.cves or []):
                # advisory-parser returns summary as "chromium-browser: <issue>"
                # and impact is equivalent to lowercase RH impact (e.g., "important") as
                # the parser explicitly converts the impacts in that way (e.g. "medium" -> "moderate")
                return {
                    "title": flaw.summary or "",
                    "cve_description": getattr(flaw, "description", "") or "",
                    "impact": (getattr(flaw, "impact", "") or "").upper(),
                }
    except Exception as exc:
        logger.warning("Could not parse Chrome advisory %s: %s", advisory_url, exc)
    return {}


def _handle_chromium(flaw: Flaw) -> dict[str, int]:
    """
    Handle Chromium CVEs: create fedora-all + epel-all affects, parse the
    Chrome advisory for CVE information, update flaw fields, and add CVSS estimate.
    """
    created = 0
    tool_name = _ace_tool_name()

    for ps_update_stream, ps_component in CHROMIUM_STREAMS:
        if Affect.objects.filter(
            flaw=flaw,
            ps_update_stream=ps_update_stream,
            ps_component=ps_component,
        ).exists():
            continue

        affect = Affect(
            flaw=flaw,
            ps_update_stream=ps_update_stream,
            ps_component=ps_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
            impact=flaw.impact,
            created_by="AffectCreationEngine",
            updated_by="AffectCreationEngine",
            assist_meta={
                "tool_name": tool_name,
                "workflow": "chromium",
            },
        )
        affect.save(raise_validation_error=False)
        created += 1

    # Extract advisory URL from references
    advisory_url = ""
    cve_id = flaw.cve_id or ""
    for ref in flaw.references.all():
        url = ref.url or ""
        if "chromereleases.googleblog.com" in url:
            advisory_url = url
            break

    advisory = _parse_chrome_advisory(advisory_url, cve_id)

    # If no advisory is found (URL not found or parsing failed) we don't need to go further
    if not advisory:
        logger.info(
            "Chromium workflow flaw=%s: created=%d, no advisory URL found",
            flaw.uuid,
            created,
        )
        return {
            "created": created,
            "skipped": 0,
            "skipped_existing": 0,
            "marked_notaffected": 0,
        }

    # Update flaw with advisory information
    flaw.statement = CHROMIUM_STATEMENT
    if advisory.get("title"):
        flaw.title = advisory["title"]
    if advisory.get("cve_description"):
        flaw.cve_description = advisory["cve_description"]
    flaw.save(raise_validation_error=False)

    # Impact is only used for CVSS calculation, but ACE should not set the flaw's impact directly
    cvss_added = False
    impact = advisory.get("impact") or flaw.impact or ""
    if (
        impact
        and not flaw.cvss_scores.filter(
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION3,
        ).exists()
    ):
        vector = CHROMIUM_CVSS_TABLE.get(impact)
        if vector:
            cvss = FlawCVSS.objects.create_cvss(
                flaw=flaw,
                issuer=FlawCVSS.CVSSIssuer.REDHAT,
                version=FlawCVSS.CVSSVersion.VERSION3,
                vector=vector,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
            )
            cvss.save()
            cvss_added = True

    logger.info(
        "Chromium workflow flaw=%s: created=%d, cvss_added=%s, advisory=%s",
        flaw.uuid,
        created,
        cvss_added,
        advisory_url,
    )

    return {
        "created": created,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 0,
    }


def _handle_go_stdlib(
    flaw: Flaw,
    component: str,
    ps_modules: list[str],
    upstream_purls: list[dict],
) -> dict[str, int]:
    """
    Handle Go stdlib CVEs with a 4-phase affect creation workflow.

    Phase 1: golang compiler builds
    Phase 2: component RPM affects
    Phase 3: component container affects (one per product)
    Phase 4: openshift-golang-builder-container for OCP/CNV/OSSM active streams
    """
    totals: dict[str, int] = {
        "created": 0,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 0,
    }

    def _run_phase(phase_description, results):
        stats = _sync_affects_from_results(
            flaw,
            results,
            component,
            ps_modules,
            ecosystem="golang",
            upstream_purls=upstream_purls,
        )
        for key in stats:
            totals[key] += stats[key]
        logger.info(
            "Go stdlib %s flaw=%s: created=%d",
            phase_description,
            flaw.uuid,
            stats["created"],
        )

    # Phase 1: golang compiler builds
    try:
        results = _query_newtopia(
            "golang",
            ps_modules,
            builds_only=True,
            no_community=True,
        )
        _run_phase("Phase 1 (golang builds)", results)
    except Exception as exc:
        logger.warning("Go stdlib Phase 1 failed for flaw=%s: %s", flaw.uuid, exc)

    # Phase 2: component RPM affects
    try:
        results = _query_newtopia(
            component,
            ps_modules,
            ecosystem="golang",
            build_type="rpm",
            no_community=True,
        )
        _run_phase("Phase 2 (RPMs)", results)
    except Exception as exc:
        logger.warning("Go stdlib Phase 2 failed for flaw=%s: %s", flaw.uuid, exc)

    # Phase 3: component container affects (one per product)
    try:
        results = _query_newtopia(
            component,
            ps_modules,
            ecosystem="golang",
            build_type="container",
            one_component=True,
            no_community=True,
        )
        _run_phase("Phase 3 (containers)", results)
    except Exception as exc:
        logger.warning("Go stdlib Phase 3 failed for flaw=%s: %s", flaw.uuid, exc)

    # Phase 4: openshift-golang-builder-container for active streams
    tool_name = _ace_tool_name()
    phase4_created = 0
    for product_name in GO_STDLIB_BUILDER_PRODUCTS:
        try:
            ps_module = PsModule.objects.get(name=product_name)
        except PsModule.DoesNotExist:
            logger.warning(
                "Go stdlib Phase 4: PsModule %r not found",
                product_name,
            )
            continue

        for stream in ps_module.active_ps_update_streams.all():
            if Affect.objects.filter(
                flaw=flaw,
                ps_update_stream=stream.name,
                ps_component="openshift-golang-builder-container",
            ).exists():
                totals["skipped_existing"] += 1
                continue

            affect = Affect(
                flaw=flaw,
                ps_update_stream=stream.name,
                purl=GO_STDLIB_BUILDER_PURL,
                ps_component="openshift-golang-builder-container",
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
                impact=flaw.impact,
                created_by="AffectCreationEngine",
                updated_by="AffectCreationEngine",
                assist_meta={
                    "tool_name": tool_name,
                    "workflow": "go_stdlib",
                    "phase": "4-builder-container",
                },
            )
            affect.save(raise_validation_error=False)
            phase4_created += 1

    totals["created"] += phase4_created
    logger.info(
        "Go stdlib Phase 4 (builder-container) flaw=%s: created=%d",
        flaw.uuid,
        phase4_created,
    )

    return totals


def _query_newtopia(
    flaw_component: str,
    ps_modules: list[str],
    ecosystem: str = "",
    builds_only: bool = False,
    build_type: str = "",
    one_component: bool = False,
    no_community: bool = False,
) -> list:
    nq = NewtopiaQuerier()  # type: ignore[misc]
    qs = nq.search(
        [flaw_component],
        strict=True,
        ecosystem=ecosystem,
        builds_only=builds_only,
        no_community=no_community,
    )
    if build_type:
        qs = qs.filter(build_type=build_type)
    qs = qs.filter(products=ps_modules)
    if one_component:
        qs = qs.deduplicate(aggressive=True)
    return qs.all()


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
        (pf for _, _, pf in pre_filter_results if pf.action is PreFilterAction.SKIP),
        None,
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

        if pre_filter.action is PreFilterAction.SPECIAL:
            # Special workflow handling
            if pre_filter.workflow is SpecialWorkflow.CHROMIUM:
                stats = _handle_chromium(flaw)
            elif pre_filter.workflow is SpecialWorkflow.GO_STDLIB:
                stats = _handle_go_stdlib(
                    flaw,
                    flaw_component,
                    ps_modules,
                    upstream_purls,
                )
            else:
                stats = {}
            for key in stats:
                totals[key] += stats[key]
            continue

        if pre_filter.action is not PreFilterAction.SEARCH:
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
