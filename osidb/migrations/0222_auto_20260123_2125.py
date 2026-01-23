"""
Data migration to fix affects that have invalid PS modules

These are affects that have set the PS update stream as 
a PS module. This migration finds the correct module from
product definitions and updates the affects.
"""

from django.conf import settings
from django.db import migrations

from osidb.core import set_user_acls
from osidb.helpers import ps_update_stream_natural_keys


PS_MODULES_LIST = [
    "amq-6.2.1", "bpms-6.3.0", "brms-5.3.1", "brms-6.3.0", "cfme-5.2",
    "cfme-5.3", "cfme-5.4", "cfme-5.5", "cfme-5.6", "cfme-5.7",
    "dts-3.1", "dts-4.1", "eap-5.2.0", "eap-6.3.z", "eap-6.4.0",
    "eap-6.4.4", "eap-6.4.z", "eap-7.0.7", "eap-7.0.9", "eap-7.1.0",
    "fsw-6.0.0", "fsw-6.0.x", "fsw-6.2.1", "fuse-6.2.1", "jbcs-1.0.0",
    "jdg-6.3.1", "jdv-6.0.0", "jdv-6.2.4", "jon-3.1", "jon-3.3.0",
    "jon-3.3.x", "jpp-6.2.0", "jpp-6.2.x", "mrg-m-3.0.0", "openstack-5-rhel6",
    "openstack-5-rhel7", "rhel-4.7.z", "rhel-4.8.z", "rhel-5.3.z", "rhel-5.4.z",
    "rhel-5.5.z", "rhel-5.6.z", "rhel-5.7.z", "rhel-5.8.z", "rhel-5.9.z",
    "rhel-6.0.z", "rhel-6.1.z", "rhel-6.2.z", "rhel-6.3.z", "rhel-6.4.z",
    "rhel-6.5.z", "rhel-6.6.z", "rhel-6.7.z", "rhel-6.8.z", "rhel-7.0.z",
    "rhel-7.1.z", "rhel-7.2.z", "rhel-7.3.z", "rhes-2.0", "rhes-2.1",
    "rhes-3.0", "rhes-3.1", "rhmap-4.1.0", "rhn_satellite_5.6", "rhn_satellite_5.7",
    "rhscl-1.1", "rhscl-1.1.z", "rhscl-1.2", "rhscl-2.2", "rhscl-2.3",
    "soap-4.2", "soap-4.3",
]


def fix_ps_module(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)

    Affect = apps.get_model("osidb", "Affect")
    PsUpdateStream = apps.get_model("osidb", "PsUpdateStream")

    for module in PS_MODULES_LIST:
        affects_to_update = Affect.objects.filter(ps_module=module).all()

        if not affects_to_update.exists():
            continue

        for affect in affects_to_update:
           stream = PsUpdateStream.objects.filter(name=affect.ps_update_stream).first()
           if not stream:
               continue
           affect.ps_module = stream.ps_module.name

        Affect.objects.bulk_update(affects_to_update, ["ps_module"])


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0221_recreate_affect_v1_indexes"),
    ]

    operations = [
        migrations.RunPython(
            fix_ps_module, reverse_code=migrations.RunPython.noop, atomic=True
        )
    ]
