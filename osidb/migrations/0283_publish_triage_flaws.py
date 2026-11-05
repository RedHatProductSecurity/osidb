"""
Data migration accompanying the move of the PUBLIC visibility gate from
PRE_SECONDARY_ASSESSMENT to TRIAGE in the DEFAULT and MANUAL workflows.

Previously a non-embargoed flaw became public once it reached
PRE_SECONDARY_ASSESSMENT; now it becomes public as soon as it reaches TRIAGE.
Because ``get_effective_visibility`` is cumulative, every post-NEW state in
these workflows (TRIAGE, ANALYSIS, PRE_SECONDARY_ASSESSMENT,
SECONDARY_ASSESSMENT, DONE) now carries an effective visibility of PUBLIC.

This migration therefore widens to PUBLIC every DEFAULT/MANUAL flaw that is
past NEW and currently INTERNAL, together with its related context (affects,
trackers, CVSS scores, etc.) via ``set_acls_nested``. Flaws already public are
not selected.

The scope intentionally covers all post-NEW states rather than only
TRIAGE/ANALYSIS: 0281_realign_manual_embargoed_workflows may have promoted a
previously-stuck INTERNAL flaw directly into PRE_SECONDARY_ASSESSMENT or
beyond, and such a flaw must also be published.

Embargoed flaws belong to the EMBARGOED workflow (which keeps no PUBLIC gate),
but this migration does not rely on that alone: it matches only INTERNAL
``acl_read`` values, so even an embargoed flaw stale-classified under
DEFAULT/MANUAL is never widened to PUBLIC. This matters because ``widen_acls``
only refuses to narrow visibility and EMBARGO sorts below PUBLIC, so a bare
"not already public" filter would otherwise leak such a flaw.

NOTE: ACL propagation is done via ``widen_acls``/``set_acls_nested`` on the
real model (queryset ``.update()`` under the hood), never ``save()``, to avoid
firing the Bugzilla/Jira sync signals.
"""

import logging

from django.db import migrations
from django.utils import timezone

from osidb.acls import ACL
from osidb.helpers import bypass_rls

logger = logging.getLogger(__name__)

WORKFLOWS = ["DEFAULT", "MANUAL"]
BATCH_SIZE = 500


@bypass_rls
def publish_post_new_flaws(apps, schema_editor):
    import pghistory
    from django.contrib.contenttypes.models import ContentType

    from osidb.mixins import Alert
    from osidb.models import Flaw

    target = ACL.PUBLIC
    flaw_ctype = ContentType.objects.get_for_model(Flaw)

    # Post-NEW INTERNAL flaws in the publishing workflows. Selecting INTERNAL
    # explicitly (rather than merely "not already public") is a safety guard:
    # it excludes EMBARGO ACLs, so an embargoed flaw that is stale-classified
    # under DEFAULT/MANUAL can never be widened to PUBLIC here - widen_acls
    # only refuses to *narrow*, and EMBARGO < PUBLIC, so without this filter it
    # would happily leak. Already-public flaws are excluded for free too.
    # Unclassified flaws (empty workflow_state) behave like NEW and stay
    # internal, so they are excluded alongside NEW itself.
    target_flaws = Flaw.objects.filter(
        workflow_name__in=WORKFLOWS,
        acl_read=ACL.INTERNAL.uuid_read,
    ).exclude(workflow_state__in=["", "NEW"])

    published = 0
    # Attribute the pghistory audit events that the DB triggers record for the
    # flaw and nested ACL updates to this migration; mass publication is the
    # most sensitive change in this set, so the events must not be left with an
    # empty user/source/action.
    with pghistory.context(
        user="OSIDB data migration 0283_publish_triage_flaws",
        source="migration",
        action="publish_post_new_flaws",
    ):
        for flaw in target_flaws.iterator(chunk_size=BATCH_SIZE):
            now = timezone.now()
            flaw.widen_acls(target)

            # Persist the root flaw's widened ACLs and bump its timestamps so
            # incremental consumers (changed_after reads local_updated_dt)
            # notice. updated_dt is stored with whole-second precision to match
            # the codebase convention (TrackingMixin.save truncates
            # microseconds) and its exact mid-air collision comparison, so a
            # client truncating updated_dt to seconds does not hit a false
            # collision. set_acls_nested() below already truncates for nested
            # objects.
            Flaw.objects.filter(pk=flaw.pk).update(
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
                updated_dt=now.replace(microsecond=0),
                local_updated_dt=now,
            )

            # set_acls_nested() skips the root Flaw (updated separately above),
            # so Alerts attached directly to the Flaw are not repointed and
            # would keep their INTERNAL ACLs after the Flaw becomes PUBLIC.
            # Update them explicitly, mirroring the Alert propagation
            # set_acls_nested() performs for the nested objects it collects.
            Alert.objects.filter(
                content_type=flaw_ctype,
                object_id=str(flaw.pk),
            ).update(acl_read=flaw.acl_read, acl_write=flaw.acl_write)

            # Propagate to the related context (affects, trackers, CVSS, ...).
            # auto_timestamps=True bumps the nested objects' updated_dt too.
            flaw.set_acls_nested(auto_timestamps=True)
            published += 1

    if published:
        logger.info(
            "Published %d post-NEW flaw(s) in the %s workflow(s)",
            published,
            ", ".join(WORKFLOWS),
        )


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0282_default_secondary_assessment_done"),
    ]

    operations = [
        migrations.RunPython(
            code=publish_post_new_flaws,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
