import logging
import re

import django.contrib.postgres.fields
from django.db import migrations, models

BATCH_SIZE = 1000

logger = logging.getLogger(__name__)

def get_components(title) -> None:
    title = re.sub(r"^EMBARGOED\s*", "", title)
    title = re.sub(r"^TRIAGE(-|\s*)", "", title)
    title = re.sub(r"^(CVE-[0-9]{4}-[0-9]+\s*)+\.*\s*", "", title)

    component_res = re.search(r"^([^\s]+:)", title)
    components = []
    while component_res:
        title = title[component_res.span()[1]:].lstrip()
        components.append(component_res.group()[:-1])
        component_res = re.search(r"^([^\s]+:)", title)

    return components


def forwards_func(apps, schema_editor):
    Flaw = apps.get_model("osidb", "Flaw")

    flaws = (
        Flaw
        .objects
        .all()
        .iterator(chunk_size=BATCH_SIZE)
    )

    batch = []
    for i, flaw in enumerate(flaws, 1):
        title = flaw.meta_attr.get("bz_summary", "")
        if title:
            # flaw have bz_summary; parse it again
            flaw.components = get_components(title)
            batch.append(flaw)
        elif flaw.component:
            # flaw don't have bz_summary; default to current value if present
            flaw.components = [flaw.component]

        if i % BATCH_SIZE == 0:
            Flaw.objects.bulk_update(batch, ["components"])
            logger.warning(f"Updated flaws: {len(batch)}")
            batch = []
    if batch:
        Flaw.objects.bulk_update(batch, ["components"])
        logger.warning(f"Updated flaws: {len(batch)}")


class Migration(migrations.Migration):
    dependencies = [
        ('osidb', '0121_fix_workflow_state'),
    ]

    operations = [
        migrations.AddField(
            model_name='flaw',
            name='components',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(blank=True, max_length=100), default=list, blank=True, size=None),
        ),
        migrations.RunPython(forwards_func),
        migrations.AlterField(
            model_name='flaw',
            name='component',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
