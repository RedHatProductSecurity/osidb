from django.db import migrations
from django.db.models import F

from osidb.helpers import bypass_rls

BATCH_SIZE = 5000


@bypass_rls
def backfill_search_vector(apps, schema_editor):
    """
    Populate search_vector for rows that existed before the trigger from migration
    0251 was created. Re-assigning `title` to itself is a no-op that still fires the
    "UPDATE OF title" trigger, so the vector is (re)computed by the same code the
    trigger uses for every future write, instead of duplicating the formula here.
    """
    Flaw = apps.get_model("osidb", "Flaw")
    qs = Flaw.objects.filter(search_vector__isnull=True)
    while True:
        ids = list(qs.values_list("uuid", flat=True)[:BATCH_SIZE])
        if not ids:
            break
        Flaw.objects.filter(uuid__in=ids).update(title=F("title"))


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0251_flaw_search_vector"),
    ]

    operations = [
        migrations.RunPython(
            code=backfill_search_vector,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
