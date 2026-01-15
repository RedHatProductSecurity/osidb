"""
Data migration to remove [auto] suffix from cwe_id field.

The [auto] suffix exists in some legacy records imports from
Bugzilla and is now obsolete.
"""

import re

from django.conf import settings
from django.db import migrations

from osidb.core import set_user_acls

BATCH_SIZE = 1000

def remove_auto_suffix_from_cwe(apps, schema_editor):
    """Remove [auto] suffix from all cwe_id fields in Flaw model."""

    set_user_acls(settings.ALL_GROUPS)
    Flaw = apps.get_model("osidb", "Flaw")
    flaws_with_auto = Flaw.objects.filter(cwe_id__icontains="[auto]")

    batch = []
    for flaw in flaws_with_auto.iterator(chunk_size=BATCH_SIZE):
        cwe_id = flaw.cwe_id
        if "[auto]" in cwe_id.lower():
            flaw.cwe_id = re.sub(r'\[auto\]', '', cwe_id, flags=re.IGNORECASE)
            batch.append(flaw)

            if len(batch) >= BATCH_SIZE:
                Flaw.objects.bulk_update(batch, ["cwe_id"])
                batch = []

    if batch:
        Flaw.objects.bulk_update(batch, ["cwe_id"])

class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0216_delete_trackerlinkmanagers"),
    ]

    operations = [
        migrations.RunPython(
            remove_auto_suffix_from_cwe, 
            reverse_code=migrations.RunPython.noop,
            atomic=True
        )
    ]
