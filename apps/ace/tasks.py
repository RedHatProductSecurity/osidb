from typing import Any

from celery.utils.log import get_task_logger
from django.db import transaction

from config.celery import app
from osidb.helpers import bypass_rls
from osidb.models import Flaw
from osidb.models.affect import Affect, AffectSettings

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


def _query_newtopia(flaw_component: str, ps_modules: list[str]) -> list:
    nq = NewtopiaQuerier()  # type: ignore[misc]
    return nq.search([flaw_component], strict=True).filter(products=ps_modules).all()


def _sync_affects_from_results(flaw: Flaw, results: list) -> dict[str, int]:
    """Create affects on ``flaw`` for each entry in ``results``.

    Each entry is a ``NewcliBuildResult`` or ``NewcliDepResult`` from lib_newtopia.
    Existing affects matching ``(flaw, ps_update_stream, ps_component)`` are skipped.
    """
    created = 0
    skipped = 0
    skipped_existing = 0
    flaw_has_high_cvss_score = flaw.has_high_cvss_score

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

            affect = Affect(
                flaw=flaw,
                ps_update_stream=ps_update_stream,
                purl=purl_str,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
                impact=flaw.impact,
            )
            affect.auto_resolve(flaw_has_high_cvss_score=flaw_has_high_cvss_score)
            affect.save(raise_validation_error=False)
            created += 1

    return {
        "created": created,
        "skipped": skipped,
        "skipped_existing": skipped_existing,
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
    totals: dict[str, int] = {"created": 0, "skipped": 0, "skipped_existing": 0}

    for flaw_component in components:
        results = _query_newtopia(flaw_component, ps_modules)
        stats = _sync_affects_from_results(flaw, results)
        for key in totals:
            totals[key] += stats[key]

    logger.info(
        "sync_flaw_affects_from_newcli flaw=%s components=%s %s",
        flaw_id,
        components,
        totals,
    )
    return totals
