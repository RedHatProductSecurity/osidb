"""
Data migration to bulk-add the "approved" workflow label to public flaws
created before the Argus release (2026-08-03).

Flaws in SECONDARY_ASSESSMENT get the label so they reclassify back to DONE.
Flaws already in DONE get the label to prevent future regression.
"""

import logging
import uuid as uuid_mod

from django.conf import settings
from django.db import migrations
from django.db.models import Exists, OuterRef
from django.utils import timezone

from osidb.core import restore_user_acl_session, set_user_acls, snapshot_user_acl_session

logger = logging.getLogger(__name__)

ARGUS_RELEASE = "2026-08-03T00:08:00+00:00"
BATCH_SIZE = 1000


def bulk_approve_pre_argus_flaws(apps, schema_editor):
    # Snapshot and restore ACLs so later migrations in the same run
    # are not affected by our session state change
    previous_acl = snapshot_user_acl_session()
    set_user_acls(settings.PUBLIC_READ_GROUPS + settings.PUBLIC_WRITE_GROUPS)
    try:
        _bulk_approve(apps, schema_editor)
    finally:
        restore_user_acl_session(previous_acl)


def _bulk_approve(apps, schema_editor):
    ContentType = apps.get_model("contenttypes", "ContentType")
    Flaw = apps.get_model("osidb", "Flaw")
    FlawLabelV2 = apps.get_model("osidb", "FlawLabelV2")

    workflow_ct, _ = ContentType.objects.get_or_create(
        app_label="osidb", model="workflowlabel"
    )

    has_approved_label = FlawLabelV2.objects.filter(
        flaw=OuterRef("pk"),
        name="approved",
    )

    flaws = (
        Flaw.objects.filter(
            created_dt__lt=ARGUS_RELEASE,
            workflow_name__in=["DEFAULT", "MANUAL"],
            workflow_state__in=["SECONDARY_ASSESSMENT", "DONE"],
        )
        .exclude(Exists(has_approved_label))
        .values_list("uuid", "acl_read", "acl_write", "workflow_state", "workflow_name")
    )

    now = timezone.now()
    now_iso = now.isoformat()
    label_count = 0
    batch = []
    reclassify_uuids = []

    for flaw_uuid, acl_read, acl_write, wf_state, wf_name in flaws.iterator(
        chunk_size=BATCH_SIZE
    ):
        batch.append((uuid_mod.uuid4(), flaw_uuid, acl_read, acl_write))
        if wf_state == "SECONDARY_ASSESSMENT":
            reclassify_uuids.append((flaw_uuid, wf_name))

        if len(batch) >= BATCH_SIZE:
            label_count += _flush_batch(schema_editor, batch, workflow_ct.pk, now)
            batch = []

    if batch:
        label_count += _flush_batch(schema_editor, batch, workflow_ct.pk, now)

    if label_count:
        logger.info("Added 'approved' workflow label to %d pre-Argus flaws", label_count)

    # Reclassify SECONDARY_ASSESSMENT flaws to DONE now that they have the
    # approved label. Raw SQL label inserts bypass Django signals so the
    # workflow state must be advanced explicitly.
    wf_name_by_uuid = {uuid: wf for uuid, wf in reclassify_uuids}
    reclassify_count = 0

    for i in range(0, len(reclassify_uuids), BATCH_SIZE):
        chunk_uuids = [u for u, _ in reclassify_uuids[i : i + BATCH_SIZE]]
        chunk_flaws = list(Flaw.objects.filter(uuid__in=chunk_uuids))

        for flaw in chunk_flaws:
            if flaw.classification_meta is None:
                flaw.classification_meta = []
            flaw.classification_meta.append(
                {
                    "timestamp": now_iso,
                    "change_type": "STATE_PROGRESSION",
                    "workflow": wf_name_by_uuid[flaw.uuid],
                    "state": "DONE",
                    "reason": {
                        "explanation": (
                            "State progressed from SECONDARY_ASSESSMENT to DONE:"
                            " data migration adding approved label to pre-Argus flaws"
                        ),
                    },
                }
            )
            flaw.workflow_state = "DONE"
            flaw.updated_dt = now
            flaw.local_updated_dt = now

        Flaw.objects.bulk_update(
            chunk_flaws,
            ["workflow_state", "classification_meta", "updated_dt", "local_updated_dt"],
        )
        reclassify_count += len(chunk_flaws)

    if reclassify_count:
        logger.info(
            "Reclassified %d flaws from SECONDARY_ASSESSMENT to DONE",
            reclassify_count,
        )


def _flush_batch(schema_editor, batch, workflow_ct_id, now):
    """Insert a batch of approved labels into both base and child tables."""
    with schema_editor.connection.cursor() as cursor:
        # Base table (FlawLabelV2) rows
        cursor.executemany(
            """
            INSERT INTO osidb_flawlabelv2
                (uuid, flaw_id, name, acl_read, acl_write,
                 created_dt, updated_dt, polymorphic_ctype_id)
            VALUES (%s, %s, 'approved', %s, %s, %s, %s, %s)
            """,
            [
                (str(uid), str(flaw_id), acl_r, acl_w, now, now, workflow_ct_id)
                for uid, flaw_id, acl_r, acl_w in batch
            ],
        )
        # Child pointer table (WorkflowLabel)
        cursor.executemany(
            """
            INSERT INTO osidb_workflowlabel (flawlabelv2_ptr_id) VALUES (%s)
            """,
            [(str(uid),) for uid, _, _, _ in batch],
        )
    return len(batch)


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("osidb", "0256_fix_manual_triage_label_type"),
    ]

    operations = [
        migrations.RunPython(
            code=bulk_approve_pre_argus_flaws,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
