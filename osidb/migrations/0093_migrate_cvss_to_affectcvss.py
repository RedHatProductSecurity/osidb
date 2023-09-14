"""
Written manually on 2023-09-13
"""

from django.db import migrations
from itertools import islice

BATCH_SIZE = 1000


def generate_affectcvss(apps):
    Affect = apps.get_model("osidb", "Affect")
    AffectCVSS = apps.get_model("osidb", "AffectCVSS")

    for affect in Affect.objects.iterator():
        # Default values
        cvss2_score, cvss2_vector = 0.0, ""
        cvss3_score, cvss3_vector = 0.0, ""

        other_fields = {
            "acl_read": affect.acl_read,
            "acl_write": affect.acl_write,
            "created_dt": affect.created_dt,
            "updated_dt": affect.updated_dt,
        }

        if affect.cvss2:
            cvss2_score, cvss2_vector = affect.cvss2.split("/", 1)

        if affect.cvss3:
            cvss3_score, cvss3_vector = affect.cvss3.split("/", 1)

        for version, vector, score in [
            ("V3", cvss3_vector, float(cvss3_score)),
            ("V2", cvss2_vector, float(cvss2_score)),
        ]:
            if vector:
                yield AffectCVSS(
                    affect=affect,
                    issuer="RH",
                    version=version,
                    vector=vector,
                    score=score,
                    comment="",
                    **other_fields,
                )


def forwards_func(apps, schema_editor):
    AffectCVSS = apps.get_model("osidb", "AffectCVSS")
    generator = generate_affectcvss(apps)
    while True:
        # Limiting memory usage by using a generator and slicing recommended in
        # https://docs.djangoproject.com/en/3.2/ref/models/querysets/#bulk-create
        batch = list(islice(generator, BATCH_SIZE))
        if not batch:
            break

        AffectCVSS.objects.bulk_create(batch, BATCH_SIZE, ignore_conflicts=False)


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0092_migrate_cvss_to_flawcvss"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
    ]
