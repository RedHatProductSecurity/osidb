"""
Written manually on 2023-10-20.
This fixes migration 0092, which was missing the correct ACLs.
"""

from osidb.core import set_user_acls

from django.conf import settings
from django.db import migrations
from itertools import islice

BATCH_SIZE = 1000


def generate_flawcvss(apps):
    Flaw = apps.get_model("osidb", "Flaw")
    FlawCVSS = apps.get_model("osidb", "FlawCVSS")

    for flaw in Flaw.objects.iterator():
        # Default values
        nist_cvss2_score, nist_cvss2_vector = 0.0, ""
        nist_cvss3_score, nist_cvss3_vector = 0.0, ""
        rh_cvss2_score, rh_cvss2_vector = 0.0, ""
        rh_cvss3_score, rh_cvss3_vector, rh_cvss3_comment = 0.0, "", ""

        other_fields = {
            "acl_read": flaw.acl_read,
            "acl_write": flaw.acl_write,
            "created_dt": flaw.created_dt,
            "updated_dt": flaw.updated_dt,
        }

        if flaw.nvd_cvss2:
            nist_cvss2_score, nist_cvss2_vector = flaw.nvd_cvss2.split("/", 1)

        if flaw.nvd_cvss3:
            nist_cvss3_score, nist_cvss3_vector = flaw.nvd_cvss3.split("/", 1)

        if flaw.cvss2:
            rh_cvss2_score, rh_cvss2_vector = flaw.cvss2.split("/", 1)

        if flaw.cvss3:
            rh_cvss3_score, rh_cvss3_vector = flaw.cvss3.split("/", 1)

        if flaw.meta_attr.get("cvss3_comment"):
            rh_cvss3_comment = flaw.meta_attr.get("cvss3_comment")

        for issuer, version, vector, score, comment in [
            ("RH", "V3", rh_cvss3_vector, float(rh_cvss3_score), rh_cvss3_comment),
            ("RH", "V2", rh_cvss2_vector, float(rh_cvss2_score), ""),
            ("NIST", "V3", nist_cvss3_vector, float(nist_cvss3_score), ""),
            ("NIST", "V2", nist_cvss2_vector, float(nist_cvss2_score), ""),
        ]:
            if vector:
                yield FlawCVSS(
                    flaw=flaw,
                    issuer=issuer,
                    version=version,
                    vector=vector,
                    score=score,
                    comment=comment,
                    **other_fields,
                )


def forwards_func(apps, schema_editor):
    set_user_acls(
        settings.PUBLIC_READ_GROUPS
        + [
            settings.PUBLIC_WRITE_GROUP,
            settings.EMBARGO_READ_GROUP,
            settings.EMBARGO_WRITE_GROUP,
        ]
    )

    FlawCVSS = apps.get_model("osidb", "FlawCVSS")
    # to ensure that everything will be migrated again with correct ACLs
    FlawCVSS.objects.all().delete()

    generator = generate_flawcvss(apps)
    while True:
        # Limiting memory usage by using a generator and slicing recommended in
        # https://docs.djangoproject.com/en/3.2/ref/models/querysets/#bulk-create
        batch = list(islice(generator, BATCH_SIZE))
        if not batch:
            break

        FlawCVSS.objects.bulk_create(batch, BATCH_SIZE, ignore_conflicts=False)


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0098_ps_contact_blank"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
    ]
