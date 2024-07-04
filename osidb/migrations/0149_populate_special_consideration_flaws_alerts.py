# Written manually on 2024-07-03
# This migration has two goals:
#   1. delete special_handling_flaw_missing_cve_description and special_handling_flaw_missing_statement alerts
#   2. populate special_consideration_flaw_missing_cve_description and special_consideration_flaw_missing_statement alerts

from django.conf import settings
from django.db import migrations
from itertools import islice

from osidb.core import set_user_acls

BATCH_SIZE = 1000


def generate_special_consideration_flaws_alerts(apps):
    set_user_acls(settings.ALL_GROUPS)
    Alert = apps.get_model("osidb", "Alert")
    Flaw = apps.get_model("osidb", "Flaw")
    SpecialConsiderationPackage = apps.get_model("osidb", "SpecialConsiderationPackage")
    ContentType = apps.get_model("contenttypes", "ContentType")

    special_consideration_packages = SpecialConsiderationPackage.objects.values_list(
        "name", flat=True
    )

    for field_name in ("cve_description", "statement"):

        flaws_missing_field = (
            Flaw.objects.filter(**{field_name: ""})
            .filter(affects__ps_component__in=special_consideration_packages)
            .distinct()
            .iterator()
        )

        for flaw in flaws_missing_field:
            affected_special_consideration_packages = (
                special_consideration_packages.intersection(
                    flaw.affects.values_list("ps_component", flat=True)
                )
            )
            yield Alert(
                name=f"special_consideration_flaw_missing_{field_name}",
                description="Flaw affecting special consideration package(s) "
                f"{', '.join(affected_special_consideration_packages)} is missing {field_name}.",
                alert_type="WARNING",
                resolution_steps="",
                content_type=ContentType.objects.get_for_model(flaw),
                object_id=flaw.uuid,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
            )


def forwards_func(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)
    Alert = apps.get_model("osidb", "Alert")

    Alert.objects.filter(name="special_handling_flaw_missing_cve_description").delete()
    Alert.objects.filter(name="special_handling_flaw_missing_statement").delete()

    generator = generate_special_consideration_flaws_alerts(apps)
    while batch := list(islice(generator, BATCH_SIZE)):
        Alert.objects.bulk_create(batch, BATCH_SIZE)


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0148_alter_workflow_state"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True)
    ]
