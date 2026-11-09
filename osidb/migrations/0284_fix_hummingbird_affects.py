"""Resolve Hummingbird affects left NEW by the OSIDB-5870 regression.

Use the live model deliberately: historical migration models do not implement
Affect.save(), validation, or its signals. Those side effects refresh the flaw
and timestamps used by downstream tracker automation. This migration does not
directly create trackers; tracker-automanager discovers the updated affects.
"""

import logging
from datetime import UTC, datetime

import pghistory
from django.db import migrations, transaction

from osidb.helpers import bypass_rls

logger = logging.getLogger(__name__)
START = datetime(2026, 11, 5, tzinfo=UTC)
BATCH_SIZE = 500


@bypass_rls
def fix_hummingbird_affects(apps, schema_editor):
    from osidb.models import Affect, PsUpdateStream

    db = schema_editor.connection.alias
    hum_streams = PsUpdateStream.objects.using(db).filter(ps_module__bts_key="HUM")
    candidates = Affect.objects.using(db).filter(
        ps_update_stream__in=hum_streams.values("name"),
        created_dt__gte=START,
        affectedness="NEW",
        resolution="",
    )

    fixed = 0
    for pk in candidates.values_list("pk", flat=True).iterator(chunk_size=BATCH_SIZE):
        # Recheck under a row lock so a concurrent analyst decision is not
        # overwritten. Each save commits separately instead of holding locks
        # for the whole migration, and a retry safely skips completed rows.
        with transaction.atomic(using=db):
            with pghistory.context(
                user="OSIDB data migration 0284_fix_hummingbird_affects",
                source="migration",
                action="fix_hummingbird_affects",
            ):
                affect = candidates.select_for_update().filter(pk=pk).first()
                if affect is None:
                    continue
                affect.affectedness = "AFFECTED"
                affect.resolution = "DELEGATED"
                affect.affectedness_explanation = (
                    "Hummingbird affect was NEW/NOVALUE in the OSIDB-5870 remediation window. "
                    "Set to AFFECTED/DELEGATED under Hummingbird policy so a tracker can be filed."
                )
                affect._auto_resolved = True
                affect.updated_by = "OSIDB data migration 0284_fix_hummingbird_affects"
                affect.save(using=db, raise_validation_error=False)
                fixed += 1

    logger.info("Resolved %d Hummingbird affect(s) for OSIDB-5870", fixed)


class Migration(migrations.Migration):
    atomic = False

    dependencies = [("osidb", "0283_publish_triage_flaws")]

    operations = [
        migrations.RunPython(fix_hummingbird_affects, migrations.RunPython.noop),
    ]
