from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0279_flaw_bz_id"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="flaw",
            index=models.Index(
                fields=["bz_id"],
                condition=models.Q(bz_id__isnull=False),
                name="osidb_flaw_bz_id_idx",
            ),
        ),
    ]
