"""
Written manually on 2024-05-16

The flaw meta_attr hstore field contains number dumps of Python structured data.
However, when done without using json.dumps, they contain single quotes which
are not considered correct by the json.loads and it just fails to convert then.
This migration is to correct the meta_attr data so it is json lib compatible.
"""
from json import JSONDecodeError
import ast
import logging
import json

from django.conf import settings
from django.db import migrations

from osidb.core import set_user_acls


BATCH_SIZE = 1000

logger = logging.getLogger(__name__)


def requote(meta_attr):
    """
    switch single quotes to double
    """
    for key, value in meta_attr.items():
        for key, value in meta_attr.items():
            # Try to fix only things that are JSON or
            # Python dict/list string representations
            if value and (
                (value.startswith("'") and value.endswith("'"))
                or (value.startswith('"') and value.endswith('"'))
                or (value.startswith("{") and value.endswith("}"))
                or (value.startswith("[") and value.endswith("]"))
            ):
                try:
                    _ = json.loads(value)
                    # It's a valid JSON already, don't do anything else with it
                    continue
                except JSONDecodeError:
                    new_value = json.dumps(ast.literal_eval(value))
                    # Don't catch an exception, if we have unprocessable data,
                    # we should improve the algorithm. That being said, it seems
                    # to work on current prod and stage data fine.
                    meta_attr[key] = new_value
    return meta_attr


def forwards_func(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)
    Flaw = apps.get_model("osidb", "Flaw")

    flaws = Flaw.objects.all().iterator(chunk_size=BATCH_SIZE)

    batch = []
    for i, flaw in enumerate(flaws, 1):
        flaw.meta_attr = requote(flaw.meta_attr)
        batch.append(flaw)

        if i % BATCH_SIZE == 0:
            Flaw.objects.bulk_update(batch, ["meta_attr"])
            logger.warning(f"Updated flaws: {len(batch)}")
            batch = []
    if batch:
        Flaw.objects.bulk_update(batch, ["meta_attr"])
        logger.warning(f"Updated flaws: {len(batch)}")


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0127_alert_refactor"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True)
    ]
