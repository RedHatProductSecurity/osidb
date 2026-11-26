from django.conf import settings
from django.db import migrations
from osidb.core import set_user_acls

def forwards_func(apps, schema_editor):
    """
    Backfill the team of existing affects from their PS product.
    """
    set_user_acls(settings.ALL_GROUPS)

    PsModule = apps.get_model("osidb", "PsModule")
    Affect = apps.get_model("osidb", "Affect")

    modules_by_team = {}
    for name, team in PsModule.objects.exclude(ps_product__team="").values_list(
        "name", "ps_product__team"
    ):
        modules_by_team.setdefault(team, []).append(name)

    for team, modules in modules_by_team.items():
        Affect.objects.filter(ps_module__in=modules).update(team=team)

class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0292_affect_team"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop),
    ]