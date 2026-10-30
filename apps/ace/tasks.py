import enum
import importlib.metadata
import re
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from celery.utils.log import get_task_logger
from django.db import transaction
from packageurl import PackageURL

from apps.ace.constants import (
    CHROMIUM_CVSS_TABLE,
    CHROMIUM_NAMES,
    CHROMIUM_STATEMENT,
    CHROMIUM_STREAMS,
    DOWNSTREAM_BUILD_TYPES,
    GO_STDLIB_BUILDER_PRODUCTS,
    GO_STDLIB_BUILDER_PURL,
    GO_STDLIB_PACKAGES,
    LABEL_AUTO_AFFECTS,
    LABEL_AUTO_REJECTED,
    LABEL_MANUAL_TRIAGE,
    LABEL_POTENTIAL_REJECTION,
    NEWTOPIA_ECOSYSTEMS,
    OPENSHIFT_PS_MODULES,
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
from osidb.models.flaw.label import WorkflowLabel
from osidb.models.flaw.upstream import UpstreamData

logger = get_task_logger(__name__)

try:
    from lib_newtopia import (  # type: ignore[import-untyped]
        BomqSearchService,
        NewtopiaQuerier,
        is_rhcos_node_build,
        rhcos_search,
        to_affect_purl,
    )

    HAS_LIB_NEWTOPIA = True
except ImportError:
    BomqSearchService = None  # type: ignore[assignment,misc]
    NewtopiaQuerier = None  # type: ignore[assignment,misc]
    is_rhcos_node_build = None  # type: ignore[assignment,misc]
    rhcos_search = None  # type: ignore[assignment,misc]
    to_affect_purl = None  # type: ignore[assignment,misc]
    HAS_LIB_NEWTOPIA = False

_DOWNSTREAM_MODES = ("build_type", "ecosystem", "rhcos")
_SKIPPED_BOT_TYPE = "AI-Bot-Skipped"


def _latest_downstream_value(aegis_meta) -> list | None:
    """Return the latest usable ``_downstream`` catalog, or None.

    Aegis appends newest entries last. Only that last entry is considered.
    A usable catalog is a list (including an empty list) on an entry whose
    ``type`` is not ``AI-Bot-Skipped``. Missing, malformed, or skipped
    metadata returns None so ACE keeps the component search.
    """
    if not isinstance(aegis_meta, dict):
        return None
    entries = aegis_meta.get("_downstream")
    if not isinstance(entries, list) or not entries:
        return None
    last = entries[-1]
    if not isinstance(last, dict) or last.get("type") == _SKIPPED_BOT_TYPE:
        return None
    value = last.get("value")
    if not isinstance(value, list):
        return None
    return value


def _ps_module_regex(patterns: list[str] | None):
    """Compile ACE product filters the same way lib-newtopia ``keep_included`` does."""
    cleaned = [p.strip() for p in (patterns or []) if isinstance(p, str) and p.strip()]
    if not cleaned:
        return None
    return re.compile("|".join(cleaned))


def _ps_module_selected(
    ps_module: str | None,
    include: list[str] | None,
    exclude: list[str] | None,
) -> bool:
    module = ps_module or ""
    include_re = _ps_module_regex(include)
    exclude_re = _ps_module_regex(exclude)
    if include_re is not None and include_re.match(module) is None:
        return False
    if exclude_re is not None and exclude_re.match(module) is not None:
        return False
    return True


def _openshift_modules_selected(include: list[str] | None) -> bool:
    """True when an empty include list (all products) or a pattern matches OpenShift."""
    include_re = _ps_module_regex(include)
    if include_re is None:
        return True
    return any(include_re.match(module) for module in OPENSHIFT_PS_MODULES)


def _downstream_search(record: dict) -> tuple[str, str, str] | None:
    """Return ``(name, mode, mode_value)`` for one catalog query, or None to skip."""
    if not isinstance(record, dict):
        return None
    name = record.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    present = [
        key for key in _DOWNSTREAM_MODES if key in record and record[key] is not None
    ]
    if len(present) != 1:
        return None
    mode = present[0]
    raw = record[mode]
    if not isinstance(raw, str):
        return None
    if mode == "ecosystem":
        if not raw.strip():
            return None
        # Pass the catalog string through; do not restrict the value set.
        return name.strip(), mode, raw.strip()
    normalized = raw.strip().lower()
    if mode == "build_type":
        if normalized not in DOWNSTREAM_BUILD_TYPES:
            return None
        return name.strip(), mode, normalized
    if normalized != "rpm":
        return None
    return name.strip(), "rhcos", "rpm"


def _aegis_ecosystems(flaw: Flaw) -> list[str]:
    """
    Extract ecosystem suggestions from aegis_meta._ecosystems.

    AEGIS populates this field early in the flaw lifecycle — typically before
    OSV upstream_data is available — so it serves as a fallback when
    component_ecosystems (derived from UpstreamData) is empty.

    Multiple entries may exist (e.g. from different AEGIS runs); their values
    are combined.
    """
    ecosystems = []
    entries = (flaw.aegis_meta or {}).get("_ecosystems", [])
    if not isinstance(entries, list):
        return ecosystems
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        value = entry.get("value")
        if isinstance(value, list):
            ecosystems.extend(
                v.strip().lower() for v in value if isinstance(v, str) and v.strip()
            )
    return ecosystems


def _resolve_ecosystems(
    component: str,
    component_ecosystems: dict[str, list[str]],
    aegis_ecosystems: list[str],
) -> list[str]:
    """
    Determine the ecosystem(s) for a component using OSV data with AEGIS fallback.

    Resolution order:
    1. OSV component_ecosystems (from UpstreamData)
    2. AEGIS ecosystems (if OSV data is unavailable)
    3. Empty string (ecosystem-agnostic query)

    Normalizes ecosystems to NEWTOPIA_ECOSYSTEMS, converting unknown values to "".
    """
    ecosystems = component_ecosystems.get(component.strip().lower())
    if not ecosystems and aegis_ecosystems:
        ecosystems = aegis_ecosystems
    if not ecosystems:
        ecosystems = [""]
    return list(set(e if e in NEWTOPIA_ECOSYSTEMS else "" for e in ecosystems))


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


def _is_manual_triage_component(resolved: list[str], ecosystem: str) -> bool:
    """
    Check whether any of the resolved upstream names is configured
    (via ``OSIDB_AFFECTS_MANUAL_TRIAGE_COMPONENTS``) to require manual
    triage, optionally restricted to specific ecosystems.
    """
    manual_triage_components = AffectSettings().manual_triage_components
    ecosystem_lower = ecosystem.strip().lower()
    for name in resolved:
        allowed_ecosystems = manual_triage_components.get(name.strip().lower())
        if allowed_ecosystems is None:
            continue
        if not allowed_ecosystems:
            return True
        if ecosystem_lower in (eco.lower() for eco in allowed_ecosystems):
            return True
    return False


def _apply_label(flaw: Flaw, label: str, reason: str = "") -> None:
    if not label:
        return
    WorkflowLabel.objects.get_or_create(
        flaw=flaw, name=label, defaults={"reason": reason}
    )


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
      5. Manual-triage guard -> manual triage if configured (e.g. kernel)
      6. Verified mapping guard -> manual triage if unverified
      7. Cross-ecosystem guard -> manual triage if ambiguous
      8. Semi-strict review -> manual triage if unresolved
      9. Confidence check -> potential-rejection if low confidence
      10. All checks pass -> search (auto-affects)
    """
    component_lower = component.strip().lower()

    # Blocklist check
    block = BlocklistEntry.objects.filter(name=component_lower).first()
    if block:
        return PreFilterResult(
            action=PreFilterAction.SKIP,
            label=LABEL_AUTO_REJECTED,
            reason=f"Flaws affected by {component} are configured to be auto-rejected: {block.reason}",
        )

    # Go stdlib check: the handler runs per stdlib subcomponent path.
    # "golang" component itself is skipped here as it's automatically handled later.
    if _is_go_stdlib_component(component, flaw.components or []):
        if component_lower == "golang":
            return PreFilterResult(
                action=PreFilterAction.MANUAL,
                reason="Flaws affecting the Go programming language require manual processing.",
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

    # Manual-triage guard (e.g. Linux kernel: ACE is not equipped yet
    # for its special handling), configurable via
    # OSIDB_AFFECTS_MANUAL_TRIAGE_COMPONENTS.
    if _is_manual_triage_component(resolved, ecosystem):
        return PreFilterResult(
            action=PreFilterAction.MANUAL,
            label=LABEL_MANUAL_TRIAGE,
            resolved_names=resolved,
            reason=f"Flaws affecting '{component}' are configured for manual triage.",
        )

    # Verified mapping guard
    if has_custom_mapping and not _is_verified_mapping(component, resolved):
        return PreFilterResult(
            action=PreFilterAction.MANUAL,
            label=LABEL_MANUAL_TRIAGE,
            resolved_names=resolved,
            reason=f"The component '{component}' has no verified source component mapping, requiring manual triage.",
        )

    # Cross-ecosystem guard
    cross_eco = CrossEcosystemName.objects.filter(name=component_lower).first()
    if cross_eco and not ecosystem:
        return PreFilterResult(
            action=PreFilterAction.MANUAL,
            label=LABEL_MANUAL_TRIAGE,
            resolved_names=resolved,
            reason=(
                f"The '{component}' component exists in ecosystems: {cross_eco.ecosystems}. "
                "Ecosystem could not be automatically determined in order to narrow down query, requiring manual triage."
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
                reason=f"The '{component}' component has ambiguous SBOM matches, requiring manual triage.",
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
            reason=f"The '{component}' component is not in the strict package list, low confidence, results could contain false positives.",
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
    update_fields = ["statement", "updated_dt"]
    flaw.statement = CHROMIUM_STATEMENT
    if advisory.get("title"):
        flaw.title = advisory["title"]
        update_fields.append("title")
    if advisory.get("cve_description"):
        flaw.cve_description = advisory["cve_description"]
        update_fields.append("cve_description")
    flaw.save(raise_validation_error=False, update_fields=update_fields)

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
    exclude_products: list[str] | None = None,
    trigger: str = "unknown",
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
    query_log: list[dict] = []

    def _run_phase(phase_description, results, query_name=""):
        stats = _sync_affects_from_results(
            flaw,
            results,
            component,
            ps_modules,
            ecosystem="golang",
            upstream_purls=upstream_purls,
            resolved_name=query_name or component,
            exclude_products=exclude_products,
            trigger=trigger,
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
            exclude_products=exclude_products,
            query_log=query_log,
        )
        _run_phase("Phase 1 (golang builds)", results, query_name="golang")
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
            exclude_products=exclude_products,
            query_log=query_log,
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
            exclude_products=exclude_products,
            query_log=query_log,
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

    if query_log or phase4_created:
        _write_flaw_assist_meta(
            flaw,
            "go_stdlib",
            {
                "tool_name": tool_name,
                "trigger": trigger,
                "queries": query_log,
                "phase4_created": phase4_created,
            },
        )

    return totals


def _write_flaw_assist_meta(flaw: Flaw, workflow: str, data: dict) -> None:
    """Store data under `workflow` in flaw.assist_meta, keeping other workflows' keys."""
    with transaction.atomic():
        locked = Flaw.objects.select_for_update(no_key=True).get(uuid=flaw.uuid)
        assist_meta = dict(locked.assist_meta or {})
        assist_meta[workflow] = data
        Flaw.objects.filter(uuid=flaw.uuid).update(
            assist_meta=assist_meta, auto_timestamps=False
        )
    flaw.assist_meta = assist_meta


def _query_newtopia(
    flaw_component: str,
    ps_modules: list[str],
    ecosystem: str = "",
    builds_only: bool = False,
    build_type: str = "",
    one_component: bool = False,
    no_community: bool = False,
    exclude_products: list[str] | None = None,
    query_log: list | None = None,
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
    if exclude_products:
        qs = qs.exclude(products=exclude_products)
    if one_component:
        qs = qs.deduplicate(aggressive=True)
    desc = (
        f"NewtopiaQuerier().search([{flaw_component!r}], strict=True, "
        f"ecosystem={ecosystem!r}, builds_only={builds_only!r}, "
        f"no_community={no_community!r})"
    )
    if build_type:
        desc += f".filter(build_type={build_type!r})"
    desc += f".filter(products={ps_modules!r})"
    if exclude_products:
        desc += f".exclude(products={exclude_products!r})"
    if one_component:
        desc += ".deduplicate(aggressive=True)"
    desc += ".all()"
    results = list(qs.all())
    if query_log is not None:
        query_log.append({"tool_input": desc, "results": [repr(r) for r in results]})
    return results


def _query_rhcos(
    name: str,
    ps_modules: list[str],
    exclude_products: list[str] | None,
    query_log: list | None = None,
) -> list:
    """Search RHCOS node builds in bomq and return parent-image affects.

    The search term is the bundled component. Each hit's affect purl is the
    RHCOS image (``ose-rhel-coreos``), taken from bomq's canonical purl.
    """
    if not _openshift_modules_selected(ps_modules):
        desc = (
            f"rhcos_search skipped for {name!r}: "
            f"OpenShift modules not selected by products={ps_modules!r}"
        )
        if query_log is not None:
            query_log.append({"tool_input": desc, "results": []})
        logger.info(desc)
        return []

    config = NewtopiaQuerier().config  # type: ignore[misc]
    bomq = config.bomq
    service = BomqSearchService(bomq.url, bomq.ca_cert, debug=bomq.debug)  # type: ignore[misc]
    desc = f"rhcos_search(BomqSearchService({bomq.url!r}), {name!r}, strict=True)"
    response = rhcos_search(service, name, True)  # type: ignore[misc]
    deps = list(getattr(response, "deps", None) or [])
    kept = []
    for dep in deps:
        module = getattr(dep, "ps_module", None)
        if not _ps_module_selected(module, ps_modules, exclude_products):
            continue
        raw_purl = getattr(dep, "purl", None) or ""
        purl = to_affect_purl(raw_purl) if raw_purl else None  # type: ignore[misc]
        kept.append(
            SimpleNamespace(
                ps_update_stream=getattr(dep, "ps_update_stream", None),
                purls=[purl] if purl else [],
                build_nvr=getattr(dep, "build_nvr", None),
                build_name=getattr(dep, "build_name", None),
                ps_module=module,
            )
        )
    if query_log is not None:
        query_log.append({"tool_input": desc, "results": [repr(r) for r in kept]})
    return kept


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


def _extract_version_from_result(
    purl_str: str, result, query_component: str = ""
) -> str | None:
    """Extract a meaningful package version from a lib_newtopia result.

    Priority:
      1. PURL version — used for every PURL type that carries an explicit version
         (rpm, npm, pypi, maven, generic, github, etc.).  Only OCI PURLs are
         expected to lack a meaningful package version.
      2. ``sources[].dependencies[].version`` — for container/OCI PURLs where the
         real dependency version lives inside the build manifest.  When
         *query_component* is given, only the dependency whose name matches is
         used (prevents picking an unrelated dependency's version).
      3. ``build_nvr`` minus ``build_name`` prefix — last-resort heuristic

    Returns ``None`` when no version can be determined.
    """
    try:
        purl_obj = PackageURL.from_string(purl_str)
        purl_type = purl_obj.type
        purl_version = purl_obj.version
    except Exception:
        return None

    if purl_version and purl_type != "oci":
        return purl_version

    # Container/build PURLs — recover version from sources.dependencies
    _arch_suffixes = (".x86_64", ".aarch64", ".ppc64le", ".s390x", ".noarch", ".i686")
    needle = query_component.strip().lower()
    sources = getattr(result, "sources", None) or []
    for src in sources:
        for dep in getattr(src, "dependencies", None) or []:
            # When we know the query component, only match that dependency
            if needle:
                dep_name = (getattr(dep, "name", "") or "").strip().lower()
                if dep_name != needle:
                    continue
            raw_ver = getattr(dep, "version", "") or ""
            if not raw_ver:
                continue
            for suf in _arch_suffixes:
                if raw_ver.endswith(suf):
                    raw_ver = raw_ver[: -len(suf)]
                    break
            return raw_ver

    # Fallback: build_nvr minus build_name prefix.
    # Only trust build_nvr when the build describes the queried component,
    # otherwise the version belongs to an unrelated container build.
    build_name = getattr(result, "build_name", "") or ""
    build_nvr = getattr(result, "build_nvr", "") or ""
    if build_nvr and build_name and build_nvr.startswith(build_name + "-"):
        if not needle or build_name.strip().lower() == needle:
            return build_nvr[len(build_name) + 1 :]

    return None


def _osv_version_status(
    purl_str: str,
    pkg_info: OsvPackageInfo | None,
    result=None,
    query_component: str = "",
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

    version_str = _extract_version_from_result(
        purl_str, result, query_component=query_component
    )
    upstream_version = extract_upstream_version(version_str, pkg_info.ecosystem)
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
    resolved_name: str = "",
    apply_labels: bool = True,
    exclude_products: list[str] | None = None,
    trigger: str = "unknown",
) -> dict[str, int]:
    """Create affects on ``flaw`` for each entry in ``results``.

    Each entry is a ``NewcliBuildResult`` or ``NewcliDepResult`` from lib_newtopia.
    Existing affects matching ``(flaw, ps_update_stream, ps_component)`` are skipped.

    When ``upstream_purls`` is provided (from ``UpstreamData``), each result's purl
    version is checked against the OSV version range for the matched component.
    Results whose version falls outside the range are created as NOTAFFECTED affects.

    When ``apply_labels`` is False, no labels are applied to the flaw (used by
    hummingbird workflow).
    """
    created = 0
    skipped = 0
    skipped_existing = 0
    marked_notaffected = 0
    flaw_has_high_cvss_score = flaw.has_high_cvss_score

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
                purl_str,
                pkg_info,
                result=result,
                query_component=resolved_name or flaw_component,
            )

            affect = Affect(
                flaw=flaw,
                ps_update_stream=ps_update_stream,
                purl=purl_str,
                ps_component=ps_component,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
                created_by="AffectCreationEngine",
                updated_by="AffectCreationEngine",
                assist_meta={
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
                affect.affectedness_explanation = (
                    "OSV data indicates the vulnerable code is not present in this version. "
                    "Affectedness set to NOTAFFECTED with justification 'Vulnerable Code not Present'."
                )
                affect._auto_resolved = True
                marked_notaffected += 1
            elif osv_status is OsvStatus.NO_VERSION:
                affect.affectedness = Affect.AffectAffectedness.NEW
                affect.resolution = Affect.AffectResolution.NOVALUE
                if apply_labels:
                    _apply_label(flaw, LABEL_MANUAL_TRIAGE)
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


def _apply_downstream_verdict(
    flaw: Flaw,
    affect: Affect,
    record: dict,
    *,
    apply_labels: bool,
    flaw_has_high_cvss_score: bool,
) -> str:
    """Set affectedness from a catalog record. Returns a stats bucket name."""
    verdict = record["affectedness"] if "affectedness" in record else None
    name = record.get("name")
    if verdict == "AFFECTED":
        affect.auto_resolve(flaw_has_high_cvss_score=flaw_has_high_cvss_score)
        return "affected"
    if verdict == "NOTAFFECTED":
        affect.affectedness = Affect.AffectAffectedness.NOTAFFECTED
        affect.resolution = Affect.AffectResolution.NOVALUE
        affect.not_affected_justification = (
            NotAffectedJustification.VULN_CODE_NOT_PRESENT
        )
        affect.affectedness_explanation = (
            "Downstream catalog marked this package NOTAFFECTED. "
            "Affectedness set to NOTAFFECTED with justification "
            "'Vulnerable Code not Present'."
        )
        affect._auto_resolved = True
        return "notaffected"
    affect.affectedness = Affect.AffectAffectedness.NEW
    affect.resolution = Affect.AffectResolution.NOVALUE
    if apply_labels:
        _apply_label(
            flaw,
            LABEL_MANUAL_TRIAGE,
            reason=(
                f"Downstream catalog affectedness for {name} is {verdict!r}; "
                "left NEW for manual triage."
            ),
        )
    return "new"


def _sync_downstream_affects(
    flaw: Flaw,
    results: list,
    record: dict,
    mode: str,
    mode_value: str,
) -> dict[str, int]:
    """Create affects for one catalog query, then apply its verdict.

    OSV version ranges are not consulted. The first save is ``NEW`` so a
    failed verdict still leaves a reviewable affect.
    """
    created = 0
    skipped = 0
    skipped_existing = 0
    marked_notaffected = 0
    verdict = record["affectedness"] if "affectedness" in record else None
    evidence = record.get("evidence")
    name = record.get("name")
    flaw_has_high_cvss_score = flaw.has_high_cvss_score

    with transaction.atomic():
        for result in results:
            ps_update_stream = getattr(result, "ps_update_stream", None)
            purls = getattr(result, "purls", None) or []
            purl_str = purls[0] if purls else None
            if not ps_update_stream or not purl_str:
                logger.warning(
                    "Skipping _downstream result missing ps_update_stream or purl: %s",
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

            affect = Affect(
                flaw=flaw,
                ps_update_stream=ps_update_stream,
                purl=purl_str,
                ps_component=ps_component,
                affectedness=Affect.AffectAffectedness.NEW,
                resolution=Affect.AffectResolution.NOVALUE,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
                created_by="AffectCreationEngine",
                updated_by="AffectCreationEngine",
                assist_meta={
                    "downstream_affectedness": verdict,
                    "downstream_evidence": evidence,
                    "downstream_name": name,
                    "downstream_query": f"{mode}:{mode_value}",
                },
            )
            affect.save(raise_validation_error=False)
            created += 1
            try:
                # Savepoint so a failed verdict update keeps the NEW affect.
                with transaction.atomic():
                    outcome = _apply_downstream_verdict(
                        flaw,
                        affect,
                        record,
                        apply_labels=True,
                        flaw_has_high_cvss_score=flaw_has_high_cvss_score,
                    )
                    affect.save(raise_validation_error=False)
            except Exception:
                logger.exception(
                    "Failed to apply _downstream verdict for flaw=%s stream=%s component=%s",
                    flaw.uuid,
                    ps_update_stream,
                    ps_component,
                )
                continue
            if outcome == "notaffected":
                marked_notaffected += 1

    return {
        "created": created,
        "skipped": skipped,
        "skipped_existing": skipped_existing,
        "marked_notaffected": marked_notaffected,
    }


def _query_downstream_record(
    name: str,
    mode: str,
    mode_value: str,
    ps_modules: list[str],
    exclude_products: list[str],
    query_log: list,
) -> list:
    if mode == "build_type":
        return _query_newtopia(
            name,
            ps_modules,
            builds_only=True,
            build_type=mode_value,
            exclude_products=exclude_products,
            query_log=query_log,
        )
    if mode == "ecosystem":
        results = _query_newtopia(
            name,
            ps_modules,
            ecosystem=mode_value,
            exclude_products=exclude_products,
            query_log=query_log,
        )
        if is_rhcos_node_build is None:
            return results
        return [
            result
            for result in results
            if not is_rhcos_node_build(getattr(result, "build_name", None))
        ]
    return _query_rhcos(name, ps_modules, exclude_products, query_log)


def _sync_downstream_catalog(
    flaw: Flaw,
    catalog: list,
    settings: AffectSettings,
    trigger: str,
) -> dict[str, int]:
    """Run typed catalog searches and do not walk ``Flaw.components``."""
    ps_modules = settings.auto_create_ps_modules
    exclude_ps_modules = settings.exclude_ps_modules
    totals: dict[str, int] = {
        "created": 0,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 0,
        "pre_filtered": 0,
    }
    query_log: list[dict] = []
    for record in catalog:
        parsed = _downstream_search(record)
        if parsed is None:
            logger.warning(
                "Skipping invalid _downstream record for flaw=%s: %s",
                flaw.uuid,
                record,
            )
            continue
        name, mode, mode_value = parsed
        results = _query_downstream_record(
            name,
            mode,
            mode_value,
            ps_modules,
            exclude_ps_modules,
            query_log,
        )
        stats = _sync_downstream_affects(flaw, results, record, mode, mode_value)
        for key in stats:
            totals[key] += stats[key]

    if query_log:
        _write_flaw_assist_meta(
            flaw,
            "ace",
            {
                "tool_name": _ace_tool_name(),
                "trigger": trigger,
                "queries": query_log,
            },
        )
    logger.info(
        "sync_flaw_affects_from_newcli flaw=%s downstream_records=%s %s",
        flaw.uuid,
        len(catalog),
        totals,
    )
    return totals


@app.task(queue="high")
@bypass_rls
def sync_flaw_affects_from_newcli(
    flaw_id: str, trigger: str = "unknown"
) -> dict[str, Any]:
    """
    When the latest ``aegis_meta["_downstream"]`` entry is a usable catalog, each
    record is one typed lib-newtopia or RHCOS search and ``Flaw.components`` is not
    searched. Otherwise, for each entry in ``Flaw.components``, query lib_newtopia
    and create affects for each result: ``ps_update_stream`` and ``purl`` are taken
    from the result objects returned by ``NewtopiaQuerier``. Existing affects for
    the same flaw, stream, and ``ps_component`` (inferred from the purl) are left
    unchanged.

    The set of PS modules queried is controlled by
    :attr:`osidb.models.affect.AffectSettings.auto_create_ps_modules`
    (``OSIDB_AFFECTS_AUTO_CREATE_PS_MODULES``, JSON list; default ``[]``).

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

    if flaw.workflow_name != "DEFAULT" or flaw.workflow_state in ("", "NEW", "DONE"):
        logger.info(
            "Skipping auto-affect creation for flaw %s: "
            "workflow_name=%r, workflow_state=%r (requires DEFAULT workflow, not NEW or DONE)",
            flaw_id,
            flaw.workflow_name,
            flaw.workflow_state,
        )
        return {"skipped_reason": "workflow gate: not eligible"}

    catalog = _latest_downstream_value(flaw.aegis_meta)
    if catalog is not None:
        return _sync_downstream_catalog(flaw, catalog, AffectSettings(), trigger)

    components = _flaw_components(flaw)
    settings = AffectSettings()
    ps_modules = settings.auto_create_ps_modules
    exclude_ps_modules = settings.exclude_ps_modules
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
    aegis_ecosystems = _aegis_ecosystems(flaw)

    # Pre-filter all components first. If any component triggers a skip
    # (e.g. blocklist), the entire flaw is skipped — matching vulncli behavior.
    pre_filter_results: list[tuple[str, str, PreFilterResult]] = []
    for flaw_component in components:
        ecosystems = _resolve_ecosystems(
            flaw_component, component_ecosystems, aegis_ecosystems
        )
        for ecosystem in ecosystems:
            pf = _pre_filter_component(flaw, flaw_component, ecosystem)
            pre_filter_results.append((flaw_component, ecosystem, pf))

    skip_result = next(
        (pf for _, _, pf in pre_filter_results if pf.action is PreFilterAction.SKIP),
        None,
    )
    if skip_result:
        _apply_label(flaw, skip_result.label, reason=skip_result.reason)
        logger.info(
            "Pre-filter skip for flaw=%s: %s",
            flaw_id,
            skip_result.reason,
        )
        totals["pre_filtered"] += 1
        return totals
    query_log: list[dict] = []

    for flaw_component, ecosystem, pre_filter in pre_filter_results:
        _apply_label(flaw, pre_filter.label, reason=pre_filter.reason)

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
                    exclude_products=exclude_ps_modules,
                    trigger=trigger,
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
            results = _query_newtopia(
                resolved_name,
                ps_modules,
                ecosystem=ecosystem,
                exclude_products=exclude_ps_modules,
                query_log=query_log,
            )
            stats = _sync_affects_from_results(
                flaw,
                results,
                flaw_component,
                ps_modules,
                ecosystem=ecosystem,
                upstream_purls=upstream_purls,
                resolved_name=resolved_name,
                exclude_products=exclude_ps_modules,
                trigger=trigger,
            )
            for key in stats:
                totals[key] += stats[key]

    if query_log:
        _write_flaw_assist_meta(
            flaw,
            "ace",
            {
                "tool_name": _ace_tool_name(),
                "trigger": trigger,
                "queries": query_log,
            },
        )

    logger.info(
        "sync_flaw_affects_from_newcli flaw=%s components=%s %s",
        flaw_id,
        components,
        totals,
    )
    return totals


@app.task(queue="high")
@bypass_rls
def sync_hummingbird_affects(flaw_id: str, trigger: str = "unknown") -> dict[str, Any]:
    """
    Create hummingbird affects for a flaw based on its components.

    Unlike the main ACE task (:func:`sync_flaw_affects_from_newcli`), this task:
    - Has no workflow gate (runs regardless of workflow type/state)
    - Has minimal pre-filtering (blocklist only; no manual-triage guards)
    - Only queries hummingbird ps_modules
    - Never applies labels

    The set of PS modules queried is controlled by
    :attr:`osidb.models.affect.AffectSettings.hummingbird_ps_modules`
    (``OSIDB_AFFECTS_HUMMINGBIRD_PS_MODULES``, JSON list; default ``["hummingbird-1"]``).

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
            "lib_newtopia is not installed; skipping hummingbird affect creation for flaw %s. "
            "Install lib-newtopia from the internal Nexus repository to enable this feature.",
            flaw_id,
        )
        return {"skipped_reason": "lib_newtopia not installed"}

    flaw = Flaw.objects.get(uuid=flaw_id)
    settings = AffectSettings()
    hummingbird_ps_modules = settings.hummingbird_ps_modules

    if not hummingbird_ps_modules:
        logger.info(
            "Skipping hummingbird affect creation for flaw %s: no hummingbird ps_modules configured",
            flaw_id,
        )
        return {"skipped_reason": "no hummingbird ps_modules configured"}

    components = _flaw_components(flaw)
    totals: dict[str, int] = {
        "created": 0,
        "skipped": 0,
        "skipped_existing": 0,
        "marked_notaffected": 0,
        "blocklisted": 0,
    }

    osv_data = flaw.upstream_data.filter(source=UpstreamData.Source.OSV).first()
    upstream_purls: list[dict] = osv_data.upstream_purls if osv_data else []
    component_ecosystems = osv_data.component_ecosystems if osv_data else {}
    aegis_ecosystems = _aegis_ecosystems(flaw)
    query_log: list[dict] = []

    for flaw_component in components:
        component_lower = flaw_component.strip().lower()

        # Blocklist check - skip this component if blocklisted, but continue processing others
        block = BlocklistEntry.objects.filter(name=component_lower).first()
        if block:
            logger.info(
                "Hummingbird: skipping blocklisted component %r for flaw=%s (reason: %s)",
                flaw_component,
                flaw_id,
                block.reason,
            )
            totals["blocklisted"] += 1
            continue

        # Determine ecosystem
        ecosystems = _resolve_ecosystems(
            flaw_component, component_ecosystems, aegis_ecosystems
        )

        # Resolve component name
        resolved, _ = _resolve_component(flaw_component)

        for ecosystem in ecosystems:
            for resolved_name in resolved:
                results = _query_newtopia(
                    resolved_name,
                    hummingbird_ps_modules,
                    ecosystem=ecosystem,
                    query_log=query_log,
                )
                stats = _sync_affects_from_results(
                    flaw,
                    results,
                    flaw_component,
                    hummingbird_ps_modules,
                    ecosystem=ecosystem,
                    upstream_purls=upstream_purls,
                    resolved_name=resolved_name,
                    apply_labels=False,
                    trigger=trigger,
                )
                for key in stats:
                    totals[key] += stats[key]

    if query_log:
        _write_flaw_assist_meta(
            flaw,
            "hummingbird",
            {
                "tool_name": _ace_tool_name(),
                "trigger": trigger,
                "queries": query_log,
            },
        )

    logger.info(
        "sync_hummingbird_affects flaw=%s components=%s %s",
        flaw_id,
        components,
        totals,
    )
    return totals
