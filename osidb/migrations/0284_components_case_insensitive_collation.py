"""
Create case_insensitive collation for component filtering.

"""

from django.contrib.postgres.operations import CreateCollation
from django.db import migrations

class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0283_publish_triage_flaws"),
    ]

    operations = [
        CreateCollation(
            name="case_insensitive",
            provider="icu",
            locale="und-u-ks-level2",
            deterministic=False,
        ),
    ]
