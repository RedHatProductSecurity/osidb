from celery.utils.log import get_task_logger
from django.db import transaction

from apps.ace.client import AffectAutomationQuerier
from osidb.models import Flaw
from osidb.models.affect import Affect, AffectSettings
from osidb.models.flaw.label_v2 import WorkflowLabel
from osidb.models.flaw.upstream import UpstreamData

logger = get_task_logger(__name__)


def _build_payload(flaw: Flaw, ps_modules: list[str]) -> dict:
    osv_data = flaw.upstream_data.filter(source=UpstreamData.Source.OSV).first()

    references = [{"url": ref.url or ""} for ref in flaw.references.all()]

    return {
        "flaw_id": str(flaw.uuid),
        "cve_id": flaw.cve_id or "",
        "components": list(flaw.components or []),
        "ps_modules": ps_modules,
        "upstream_purls": osv_data.upstream_purls if osv_data else [],
        "component_ecosystems": osv_data.component_ecosystems if osv_data else {},
        "impact": flaw.impact or "",
        "references": references,
    }


def _persist_affects(flaw: Flaw, response: dict) -> dict:
    created = 0
    skipped_existing = 0

    with transaction.atomic():
        for affect_data in response.get("affects", []):
            ps_update_stream = affect_data.get("ps_update_stream", "")
            ps_component = affect_data.get("ps_component", "")

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
                purl=affect_data.get("purl", ""),
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
                impact=affect_data.get("impact", flaw.impact or ""),
                created_by="AffectCreationEngine",
                updated_by="AffectCreationEngine",
                assist_meta=affect_data.get("assist_meta", {}),
            )

            affectedness = affect_data.get("affectedness", "")
            if affectedness:
                affect.affectedness = affectedness

            resolution = affect_data.get("resolution", "")
            if resolution:
                affect.resolution = resolution

            justification = affect_data.get("not_affected_justification", "")
            if justification:
                affect.not_affected_justification = justification

            affect.save(raise_validation_error=False)
            created += 1

    for label_name in response.get("labels", []):
        if label_name:
            WorkflowLabel.objects.get_or_create(flaw=flaw, name=label_name)

    return {"created": created, "skipped_existing": skipped_existing}


def dispatch_to_microservice(flaw_id: str) -> dict:
    flaw = Flaw.objects.get(uuid=flaw_id)
    ps_modules = AffectSettings().auto_create_ps_modules

    payload = _build_payload(flaw, ps_modules)
    client = AffectAutomationQuerier()
    response = client.request_affects(flaw_id, payload)

    stats = _persist_affects(flaw, response)
    logger.info("Affect automation microservice flaw=%s: %s", flaw_id, stats)
    return {**stats, "affects": response.get("affects", [])}
