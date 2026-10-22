from django.conf import settings
from django.db import migrations
from django.db.models import F

from osidb.core import set_user_acls


def forwards_func(apps, schema_editor):
    """
    Backfill resolved_dt for AFFECTED:DELEGATED affects.

    These affects were considered unresolved under the old definition and had
    their resolved_dt nulled by migration 0189. With the unified definition an
    affect is unresolved only while still in the initial NEW:NOVALUE state, so
    AFFECTED:DELEGATED now counts as resolved and should carry a resolved_dt.
    The exact delegation time is not recorded, so updated_dt is used as the best
    available approximation.
    """
    set_user_acls(settings.ALL_GROUPS)

    Affect = apps.get_model("osidb", "Affect")
    Affect.objects.filter(
        affectedness="AFFECTED",
        resolution="DELEGATED",
        resolved_dt__isnull=True,
    ).update(resolved_dt=F("updated_dt"))


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0277_rls_audit_delegation"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop),
    ]
