"""
Data migration to add the "manual-triage" workflow label to kernel-related
flaws that are not yet DONE and are still classified in the DEFAULT workflow,
then reclassify them into the MANUAL workflow.

Rationale: the automation does not handle the kernel well, so kernel flaws
belong in the MANUAL workflow. A large number of old but unresolved kernel
flaws predate ACE and therefore never received the "manual-triage" label,
leaving them stuck in DEFAULT.

Kernel flaws are identified via the ACE component resolution: a flaw is
considered kernel if any of its ``components`` resolves - through the
component_mapping (ComponentMapEntry) data - to the same upstream package(s)
as the canonical "kernel" component. The resolved component names are
precomputed into a set and used for a single bulk ``components__overlap``
query.

Both embargoed and non-embargoed flaws are processed: the migration's
session is granted full ACLs so Row-Level Security does not hide any
mis-classified kernel flaws.

NOTE: this migration uses the real ``Flaw`` model and the workflow framework
(rather than only historical models) because kernel identification and
workflow classification are runtime business logic that only exists on the
concrete models. Labels are inserted with raw SQL (bypassing signals) and the
workflow state is therefore advanced explicitly via ``bulk_update``.
"""

import logging
import uuid as uuid_mod

from django.conf import settings
from django.db import migrations
from django.db.models import BooleanField, Exists, OuterRef
from django.db.models.expressions import RawSQL
from django.utils import timezone

from osidb.core import (
    restore_user_acl_session,
    set_user_acls,
    snapshot_user_acl_session,
)

logger = logging.getLogger(__name__)

MANUAL_TRIAGE_LABEL = "manual-triage"
MANUAL_TRIAGE_REASON = (
    "Applied by data migration: pre-ACE kernel flaw moved to the MANUAL workflow "
    "because the automation does not handle the kernel."
)
BATCH_SIZE = 1000


def add_manual_triage_to_kernel_flaws(apps, schema_editor):
    # Snapshot and restore ACLs so later migrations in the same run
    # are not affected by our session state change.
    previous_acl = snapshot_user_acl_session()
    # Grant full ACLs so Row-Level Security does not hide any flaws:
    # both embargoed and non-embargoed kernel flaws must be reclassified.
    set_user_acls(settings.ALL_GROUPS)
    try:
        _run(apps, schema_editor)
    finally:
        restore_user_acl_session(previous_acl)


def _kernel_component_names():
    """
    Build the set of OSIDB component names that resolve to the kernel.

    Mirrors the ACE ``_resolve_component`` logic: resolve the canonical
    "kernel" component to its upstream package(s), then collect every
    ComponentMapEntry whose upstream packages intersect that set. The
    literal "kernel" is always included as a fallback (it self-resolves
    even when no mapping exists).

    All names are returned lower-cased; the flaw ``components`` are matched
    case-insensitively (the same way ACE does via ``name__iexact``), so the
    caller must compare against lower-cased component values too.
    """
    from collectors.component_mapping.models import ComponentMapEntry

    def _as_list(pkgs):
        return pkgs if isinstance(pkgs, list) else [pkgs]

    # Determine the upstream package(s) that identify the kernel, the same
    # way ACE resolves the "kernel" component.
    kernel_entry = ComponentMapEntry.objects.filter(name__iexact="kernel").first()
    kernel_upstreams = {"kernel"}
    if kernel_entry:
        kernel_upstreams |= {
            str(p).strip().lower() for p in _as_list(kernel_entry.upstream_packages)
        }

    names = {"kernel"}
    for name, pkgs in ComponentMapEntry.objects.values_list(
        "name", "upstream_packages"
    ).iterator(chunk_size=BATCH_SIZE):
        if any(str(p).strip().lower() in kernel_upstreams for p in _as_list(pkgs)):
            names.add(name.lower())

    return names, kernel_upstreams


def _run(apps, schema_editor):
    from apps.workflows.tracking import add_classification_change, create_change_record
    from apps.workflows.workflow import WorkflowFramework
    from osidb.models import Flaw
    from osidb.models.flaw.label import FlawLabel, WorkflowLabel

    ContentType = apps.get_model("contenttypes", "ContentType")

    # Polymorphic content type stamped onto the raw-SQL label inserts below.
    # get_for_model (as in migration 0245) creates the row if it is missing:
    # on a fresh database the contenttypes are only populated by the
    # post_migrate signal after all migrations run, so a bare get() could fail.
    workflow_ct = ContentType.objects.get_for_model(WorkflowLabel)

    kernel_names, kernel_upstreams = _kernel_component_names()
    logger.info(
        "Identified %d kernel component name(s) resolving to upstream package(s) %s",
        len(kernel_names),
        sorted(kernel_upstreams),
    )

    has_manual_triage = FlawLabel.objects.filter(
        flaw=OuterRef("pk"),
        name=MANUAL_TRIAGE_LABEL,
    )

    # Not-yet-DONE kernel flaws still stuck in the DEFAULT workflow and
    # lacking the manual-triage label. Both embargoed and non-embargoed
    # flaws are included (the session holds full ACLs).
    #
    # The kernel match is case-insensitive on both sides (mirroring ACE's
    # ``name__iexact``): each element of the ``components`` array is lower-cased
    # in SQL and compared against the lower-cased kernel name set. The plain
    # ArrayField ``__overlap`` lookup is case-sensitive and would miss
    # components that differ only in letter case.
    is_kernel = RawSQL(
        "EXISTS (SELECT 1 FROM unnest(components) AS comp WHERE lower(comp) = ANY(%s))",
        (list(kernel_names),),
        output_field=BooleanField(),
    )

    target_flaws = (
        Flaw.objects.annotate(_is_kernel=is_kernel)
        .filter(
            _is_kernel=True,
            workflow_name="DEFAULT",
        )
        .exclude(workflow_state="DONE")
        .exclude(Exists(has_manual_triage))
        .values_list("uuid", "acl_read", "acl_write")
    )

    now = timezone.now()
    label_count = 0
    batch = []
    flaw_uuids = []

    for flaw_uuid, acl_read, acl_write in target_flaws.iterator(chunk_size=BATCH_SIZE):
        batch.append((uuid_mod.uuid4(), flaw_uuid, acl_read, acl_write))
        flaw_uuids.append(flaw_uuid)
        if len(batch) >= BATCH_SIZE:
            label_count += _flush_label_batch(schema_editor, batch, workflow_ct.pk, now)
            batch = []

    if batch:
        label_count += _flush_label_batch(schema_editor, batch, workflow_ct.pk, now)

    if label_count:
        logger.info(
            "Added '%s' workflow label to %d kernel flaw(s)",
            MANUAL_TRIAGE_LABEL,
            label_count,
        )

    # Reclassify the flaws now that they carry the manual-triage label.
    # Raw SQL label inserts bypass Django signals, so the workflow state
    # must be advanced explicitly. The real Flaw instances re-read the
    # freshly inserted label via has_label(), so classify() sees it.
    framework = WorkflowFramework()
    reclassify_count = 0

    for i in range(0, len(flaw_uuids), BATCH_SIZE):
        chunk_uuids = flaw_uuids[i : i + BATCH_SIZE]
        chunk_flaws = list(Flaw.objects.filter(uuid__in=chunk_uuids))
        to_update = []

        for flaw in chunk_flaws:
            result = framework.classify(flaw)
            if result is None:
                # Flaw without a Jira task - cannot be classified.
                continue
            workflow, state = result
            new_classification = {"workflow": workflow.name, "state": state.name}
            old_classification = flaw.classification

            if new_classification == old_classification:
                continue

            add_classification_change(
                flaw,
                create_change_record(
                    old_classification,
                    new_classification,
                    instance=flaw,
                    framework=framework,
                ),
            )
            flaw.classification = new_classification
            flaw.updated_dt = now
            flaw.local_updated_dt = now
            to_update.append(flaw)

        if to_update:
            Flaw.objects.bulk_update(
                to_update,
                [
                    "workflow_name",
                    "workflow_state",
                    "classification_meta",
                    "updated_dt",
                    "local_updated_dt",
                ],
            )
            reclassify_count += len(to_update)

    if reclassify_count:
        logger.info(
            "Reclassified %d kernel flaw(s) out of the DEFAULT workflow",
            reclassify_count,
        )


def _flush_label_batch(schema_editor, batch, workflow_ct_id, now):
    """Insert a batch of manual-triage labels into both base and child tables."""
    with schema_editor.connection.cursor() as cursor:
        # Base table (FlawLabelV2) rows
        cursor.executemany(
            """
            INSERT INTO osidb_flawlabelv2
                (uuid, flaw_id, name, acl_read, acl_write,
                 created_dt, updated_dt, polymorphic_ctype_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            [
                (
                    str(uid),
                    str(flaw_id),
                    MANUAL_TRIAGE_LABEL,
                    acl_r,
                    acl_w,
                    now,
                    now,
                    workflow_ct_id,
                )
                for uid, flaw_id, acl_r, acl_w in batch
            ],
        )
        # Child pointer table (WorkflowLabel). The ``reason`` column is NOT NULL
        # (added in migration 0265_workflowlabel_reason), so it must be set here.
        cursor.executemany(
            "INSERT INTO osidb_workflowlabel (flawlabelv2_ptr_id, reason) "
            "VALUES (%s, %s)",
            [(str(uid), MANUAL_TRIAGE_REASON) for uid, _, _, _ in batch],
        )
    return len(batch)


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        # ComponentMapEntry is queried in _kernel_component_names(); its table
        # is created by the component_mapping initial migration.
        ("component_mapping", "0001_initial"),
        ("osidb", "0265_workflowlabel_reason"),
    ]

    operations = [
        migrations.RunPython(
            code=add_manual_triage_to_kernel_flaws,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
