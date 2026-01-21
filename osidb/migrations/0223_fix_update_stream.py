"""
Data migration to fix affects that have invalid PS update stream

The PS update streams for these invalid affects are the PS modules
from before the affects v2 migration. This migration updates the
PS update streams of these affects to be the latest streams of the 
corresponding module (based on product definitions)
"""


from django.conf import settings
from django.db import migrations

from osidb.core import set_user_acls
from osidb.helpers import ps_update_stream_natural_keys


PS_UPDATE_STREAM_LIST = [
    'amq-on', 'amq-st', 'cnv-1', 'cnv-2', 'codeready_ws-2', 'distributed-tracing-2', 
    'dts-3', 'dts-4', 'dts-8', 'dts-9', 'eap-5', 'eap-cd', 'jaeger-operator-1', 
    'jbews-1', 'jbews-3', 'maistra-0', 'mrg-1', 'mtr-1', 'openshift-enterprise-2', 
    'openstack-5', 'ossm-1', 'quay-2', 'rhcam-1', 'rhel-4', 'rhel-5', 'rhelsa-7', 'rhes-2', 
    'rhev-m-2', 'rhmi-all', 'rhmi-v2', 'rhscl-1', 'rhscl-2', 'rhui-3', 
    'services-ansible-automation-analytics', 'services-ansible-on-aws', 
    'services-ansible-on-gcp', 'services-automation-service-catalog', 
    'services-database-as-a-service', 'services-drift', 'services-edge-fleet-management', 
    'services-insights-essentials', 'services-managed-kafka', 'services-migration-analytics',
    'services-notifications', 'services-odf', 'services-openshift-connectors', 
    'services-rhacm', 'services-rhoc', 'services-service-registry', 'services-sources', 
    'services-topological-inventory', 'vertx-4'
]

def fix_update_stream(apps, schema_editor):
    set_user_acls(settings.ALL_GROUPS)

    Affect = apps.get_model("osidb", "Affect")
    PsModule = apps.get_model("osidb", "PsModule")

    for stream in PS_UPDATE_STREAM_LIST:
        affects_to_update = Affect.objects.filter(ps_update_stream=stream).all()

        if not affects_to_update.exists():
            continue
        
        ps_module = PsModule.objects.get(name=stream)
        streams = ps_module.ps_update_streams.all()
        
        if not streams.exists():
            continue
        
        # Update the ps_update_stream of the affect using the
        # latest ps_update_stream. This is an approximation to avoid having
        # to manually update each affect (thus, the stream could be wrong).
        ps_update_stream = max(list(streams), key=ps_update_stream_natural_keys)

        for affect in affects_to_update:
            affect.ps_update_stream = ps_update_stream.name

        Affect.objects.bulk_update(affects_to_update, ["ps_update_stream"])

class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0222_auto_20260123_2125"),
    ]

    operations = [
        migrations.RunPython(
            fix_update_stream, 
            reverse_code=migrations.RunPython.noop,
            atomic=True
        )
    ]