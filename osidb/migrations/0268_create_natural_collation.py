"""
Create natural sort collation for version string sorting.

This collation enables natural/numeric sorting where '9.9' < '9.10'
instead of lexicographic sorting where '9.10' < '9.9'.

Used for sorting ps_update_stream names like rhel-9.9, rhel-9.10, etc.
"""

from django.contrib.postgres.operations import CreateCollation
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0267_psproduct_team"),
    ]

    operations = [
        CreateCollation(
            name="natural",
            provider="icu",
            locale="en-u-kn-true",
            deterministic=False,
        ),
    ]
