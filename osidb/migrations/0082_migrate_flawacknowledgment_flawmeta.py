"""
Written manually on 2023-07-14

Copy FlawMeta ACKNOWLEDGMENT into FlawAcknowledgment.

To prevent out of memory issues, FlawMeta are iterated using .iterator()
so that FlawMeta instances are not cached. To prevent further out of
memory issues and runtime efficiency, the migration uses a generator,
islice and bulk_create as recommended by
https://docs.djangoproject.com/en/3.2/ref/models/querysets/#bulk-create

This makes the DB data consistent and ready for FlawAcknowledgment bbsync.
Without this consistency, FlawAcknowledgment manipulation and bbsync would be
either too complex or nonfunctional, because it wouldn't be clear whether to
assemble srtnotes acknowledgments based on FlawMeta or FlawAcknowledgment, or
would make acks disappear if a Flaw without populated FlawAcknowledgment was
bbsynced.
"""

from django.db import migrations
from ast import literal_eval
from itertools import islice


def generate_flaw_acknowledgments(apps):
    FlawMeta = apps.get_model("osidb", "FlawMeta")
    FlawAcknowledgment = apps.get_model("osidb", "FlawAcknowledgment")
    for meta_ack in FlawMeta.objects.filter(type="ACKNOWLEDGMENT").iterator():
        flaw = meta_ack.flaw
        name = meta_ack.meta_attr["name"]
        # Convert None to empty string.
        affiliation = meta_ack.meta_attr.get("affiliation") or ""
        # hstore holds bolean values as strings containing True|False
        # so we need to explicitly convert it to the bolean value
        from_upstream = literal_eval(meta_ack.meta_attr["from_upstream"])
        # FlawAcknowledgment that already exist are skipped because they
        # are exactly as up-to-date as FlawMeta ACKNOWLEDGMENT.
        yield FlawAcknowledgment(
            flaw=flaw,
            name=name,
            affiliation=affiliation,
            from_upstream=from_upstream,
            meta_attr=meta_ack.meta_attr,
            acl_read=meta_ack.acl_read,
            acl_write=meta_ack.acl_write,
            created_dt=meta_ack.created_dt,
            updated_dt=meta_ack.updated_dt,
        )


def forwards_func(apps, schema_editor):
    batch_size = 1000

    FlawAcknowledgment = apps.get_model("osidb", "FlawAcknowledgment")
    generator = generate_flaw_acknowledgments(apps)
    while True:
        # Limiting memory usage by using a generator and slicing recommended in
        # https://docs.djangoproject.com/en/3.2/ref/models/querysets/#bulk-create
        batch = list(islice(generator, batch_size))
        if not batch:
            break

        # There shouldn't be many existing FlawAcknowledgment instances. Those that
        # do exist are identical to those that would be created by this migration,
        # therefore ignoring conflicts.
        FlawAcknowledgment.objects.bulk_create(batch, batch_size, ignore_conflicts=True)


# About reversing the migration:
# forwards_func() creates FlawAcknowledgment instances that mirror
# FlawMeta ACKNOWLEDGMENT instances that are identical to FlawAcknowledgment
# that would be created using Flaw bzimport, and that could have already
# been created during Flaw bzimport before forwards_func() executed.
# No way to revert, and no reason to revert.
# You might consider reverting back to 0078 which is before FlawAcknowledgment
# was created.


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0081_cvss"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
    ]
