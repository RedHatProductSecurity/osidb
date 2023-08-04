"""
Written manually on 2023-07-17

Copy FlawMeta NIST_CVSS_VALIDATION into Flaw field nist_cvss_validation.

To prevent out of memory issues, FlawMeta are iterated using .iterator()
so that FlawMeta instances are not cached. To prevent further out of
memory issues and runtime efficiency, the migration uses a generator,
islice and bulk_update in the way recommended by
https://docs.djangoproject.com/en/3.2/ref/models/querysets/#bulk-create

"""

from django.db import migrations
from itertools import islice

BATCH_SIZE = 1000

# maps BZ flags to OSIDB values
MAPPING = {
    "": "",
    "?": "REQUESTED",
    "+": "APPROVED",
    "-": "REJECTED",
}


def generate_flag_values(apps):
    """
    Generates pairs of (Flaw instance, value of flag nist_cvss_validation for that Flaw).
    """
    FlawMeta = apps.get_model("osidb", "FlawMeta")
    for flawmeta in FlawMeta.objects.filter(type="NIST_CVSS_VALIDATION").iterator():
        flaw = flawmeta.flaw
        flag_value = flawmeta.meta_attr["status"]
        yield flaw, flag_value


def forwards_func(apps, schema_editor):
    """
    For all Flaws that have the bugzilla flag nist_cvss_validation set, this
    migration sets the value of the field nist_cvss_validation to be identical
    to existing FlawMeta NIST_CVSS_VALIDATION.
    """
    flag_val_generator = generate_flag_values(apps)
    Flaw = apps.get_model("osidb", "Flaw")

    while True:
        batch_flaws_flags = list(islice(flag_val_generator, BATCH_SIZE))
        if not batch_flaws_flags:
            break

        flaws = []
        for flaw, flag in batch_flaws_flags:
            flaw.nist_cvss_validation = MAPPING[flag]
            flaws.append(flaw)
        Flaw.objects.bulk_update(flaws, ["nist_cvss_validation"])


def backwards_func(apps, schema_editor):
    """
    Reverts value of the field nist_cvss_validation to empty string for all Flaws.
    """
    Flaw = apps.get_model("osidb", "Flaw")
    all_flaws = (
        Flaw.objects.exclude(nist_cvss_validation="")
        .only("uuid", "nist_cvss_validation")
        .iterator()
    )
    while True:
        batch = list(islice(all_flaws, BATCH_SIZE))
        if not batch:
            break
        for flaw in batch:
            flaw.nist_cvss_validation = ""
        Flaw.objects.bulk_update(batch, ["nist_cvss_validation"])


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0086_osidb_flawdraft"),
    ]

    operations = [
        migrations.RunPython(forwards_func, backwards_func, atomic=True),
    ]
