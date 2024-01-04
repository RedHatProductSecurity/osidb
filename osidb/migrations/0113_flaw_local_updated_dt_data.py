import logging

from django.conf import settings
from django.db import migrations
from django.db.models import Max

from osidb.core import set_user_acls


logger = logging.getLogger(__name__)


BATCH_SIZE = 1000


def forwards_func(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)
    Flaw = apps.get_model("osidb", "Flaw")

    flaws = (
        Flaw
        .objects
        .prefetch_related("affects", "affects__trackers")
        .all()
        .iterator(chunk_size=BATCH_SIZE)
    )

    batch = []
    for i, flaw in enumerate(flaws, 1):
        max_updated_dt = flaw.updated_dt

        affects_max = list(
            flaw
            .affects
            .all()
            .aggregate(Max("updated_dt"))
            .values()
        )[0]

        if affects_max and affects_max > max_updated_dt:
            max_updated_dt = affects_max

        for affect in flaw.affects.all().iterator():
            trackers_max = list(
                affect
                .trackers
                .all()
                .aggregate(Max("updated_dt"))
                .values()
            )[0]
            if trackers_max and trackers_max > max_updated_dt:
                max_updated_dt = trackers_max

        flaw.local_updated_dt = max_updated_dt
        batch.append(flaw)

        if i % BATCH_SIZE == 0:
            Flaw.objects.bulk_update(batch, ["local_updated_dt"])
            logger.warning(f"Updated flaws: {len(batch)}")
            batch = []
    if batch:
        Flaw.objects.bulk_update(batch, ["local_updated_dt"])
        logger.warning(f"Updated flaws: {len(batch)}")


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0112_flaw_local_updated_dt")
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True)
    ]
