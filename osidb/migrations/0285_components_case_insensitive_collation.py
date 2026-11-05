"""
Create case_insensitive collation for component filtering.

Collation enables comparison between strings where the case
of individual letters is not important (i.e. ExampleTest == exampletest)

Used for filters on things like Flaw components where incorrect casing
shouldn't matter.
"""

from django.contrib.postgres.operations import CreateCollation
from django.db import migrations

class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0284_fix_hummingbird_affects"),
    ]

    operations = [
        CreateCollation(
            name="case_insensitive",
            provider="icu",
            locale="und-u-ks-level2",
            deterministic=False,
        ),
    ]
