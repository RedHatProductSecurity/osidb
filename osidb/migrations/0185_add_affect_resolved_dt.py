from django.conf import settings
from django.db import migrations, models
from itertools import islice
from osidb.core import set_user_acls

import pgtrigger.compiler
import pgtrigger.migrations

def forwards_func(apps, schema_editor):
    """
    Best effort to estimate resolved_dt for affects resolved in the past
    based on audit logs, in case affect is too old to have audit logs
    use last updated date for resolved_dt
    """
    BATCH_SIZE = 10000
    set_user_acls(settings.ALL_GROUPS)

    # Events are not available during migrations, using dumped instance from audit instead
    AffectAudit = apps.get_model("osidb", "affectaudit")
    Affect = apps.get_model("osidb", "Affect")

    resolved_affects = Affect.objects.exclude(
        resolution="", affectedness__in=["NEW", ""]
    )

    total = resolved_affects.count()
    resolved_affects = resolved_affects.iterator()
    print(f"\n    Found {total} resolved affects.")

    history_count = 0
    batch_pointer = 0
    while True:
        batch = list(islice(resolved_affects, BATCH_SIZE))
        if not batch:
            break
        print(f"      Working from {batch_pointer} to {batch_pointer + len(batch)}.")
        batch_pointer += len(batch)
        
        for affect in batch:
            # get the latest audit event that changed from
            # unresolved to a resolved state
            resolved_event = AffectAudit.objects.filter(
                resolution="",
                affectedness="NEW",
                pgh_obj_id=affect.uuid,
            ).order_by("-pgh_created_at").first()

            resolved_dt = affect.updated_dt
            if resolved_event:
                resolved_dt = resolved_event.pgh_created_at
                history_count += 1
            affect.resolved_dt = resolved_dt
        
        Affect.objects.bulk_update(batch, ["resolved_dt"])
    print(f"    Found {history_count} resolved_dt from audit logs. {total-history_count} defaulted to affect.updated_dt.")


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0184_tracker_not_affected_justification'),
    ]

    operations = [
        pgtrigger.migrations.RemoveTrigger(
            model_name='affect',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='affect',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='affect',
            name='delete_delete',
        ),
        migrations.AddField(
            model_name='affect',
            name='resolved_dt',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='affectaudit',
            name='resolved_dt',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affectedness", NEW."created_dt", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", NEW."not_affected_justification", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."purl", NEW."resolution", NEW."resolved_dt", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='c3091ecede2b467c3d7b3bc5ba0e375d7deec805', operation='INSERT', pgid='pgtrigger_insert_insert_0d1b1', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."acl_read" IS DISTINCT FROM (NEW."acl_read") OR OLD."acl_write" IS DISTINCT FROM (NEW."acl_write") OR OLD."affectedness" IS DISTINCT FROM (NEW."affectedness") OR OLD."created_dt" IS DISTINCT FROM (NEW."created_dt") OR OLD."flaw_id" IS DISTINCT FROM (NEW."flaw_id") OR OLD."impact" IS DISTINCT FROM (NEW."impact") OR OLD."last_validated_dt" IS DISTINCT FROM (NEW."last_validated_dt") OR OLD."not_affected_justification" IS DISTINCT FROM (NEW."not_affected_justification") OR OLD."ps_component" IS DISTINCT FROM (NEW."ps_component") OR OLD."ps_module" IS DISTINCT FROM (NEW."ps_module") OR OLD."purl" IS DISTINCT FROM (NEW."purl") OR OLD."resolution" IS DISTINCT FROM (NEW."resolution") OR OLD."resolved_dt" IS DISTINCT FROM (NEW."resolved_dt") OR OLD."updated_dt" IS DISTINCT FROM (NEW."updated_dt") OR OLD."uuid" IS DISTINCT FROM (NEW."uuid"))', func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affectedness", NEW."created_dt", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", NEW."not_affected_justification", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."purl", NEW."resolution", NEW."resolved_dt", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='20478c48735abce37e10a181039f0ea18ea0c096', operation='UPDATE', pgid='pgtrigger_update_update_fdef6', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."affectedness", OLD."created_dt", OLD."flaw_id", OLD."impact", OLD."last_validated_dt", OLD."not_affected_justification", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."ps_component", OLD."ps_module", OLD."purl", OLD."resolution", OLD."resolved_dt", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='d4d791f32656966fbb8aa84fb1c8f8dbe727f299', operation='DELETE', pgid='pgtrigger_delete_delete_cc8c5', table='osidb_affect', when='AFTER')),
        ),
    ]







