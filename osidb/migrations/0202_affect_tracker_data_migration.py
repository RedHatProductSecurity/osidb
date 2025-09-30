from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import pgtrigger.compiler
import pgtrigger.migrations
from osidb.core import set_user_acls
from osidb.helpers import bypass_rls


BATCH_SIZE = 1000

@bypass_rls
def forwards_func(apps, schema_editor):
    """
    Migrate the old m2m affect-tracker relationship to the new m2o relationship.
    """
    Affect = apps.get_model("osidb", "Affect")
    Tracker = apps.get_model("osidb", "Tracker")

    batch = []
    for tracker in Tracker.objects.all().iterator(chunk_size=BATCH_SIZE):
        for affect in tracker.affects.all():
            affect.tracker = tracker
            batch.append(affect)
            if len(batch) >= BATCH_SIZE:
                Affect.objects.bulk_update(batch, ["tracker"])
                batch.clear()

    if batch:
        Affect.objects.bulk_update(batch, ["tracker"])
        batch.clear()


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0201_update_affect_tracker_relationship'),
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
        migrations.RunPython(forwards_func, migrations.RunPython.noop),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "cve_id", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "tracker_id", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affectedness", NEW."created_dt", NEW."cve_id", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", NEW."not_affected_justification", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."ps_update_stream", NEW."purl", NEW."resolution", NEW."resolved_dt", NEW."tracker_id", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='ab5e24d1e11ea55bbc1ea1bf63801accf09f16ac', operation='INSERT', pgid='pgtrigger_insert_insert_0d1b1', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."acl_read" IS DISTINCT FROM (NEW."acl_read") OR OLD."acl_write" IS DISTINCT FROM (NEW."acl_write") OR OLD."affectedness" IS DISTINCT FROM (NEW."affectedness") OR OLD."created_dt" IS DISTINCT FROM (NEW."created_dt") OR OLD."cve_id" IS DISTINCT FROM (NEW."cve_id") OR OLD."flaw_id" IS DISTINCT FROM (NEW."flaw_id") OR OLD."impact" IS DISTINCT FROM (NEW."impact") OR OLD."last_validated_dt" IS DISTINCT FROM (NEW."last_validated_dt") OR OLD."not_affected_justification" IS DISTINCT FROM (NEW."not_affected_justification") OR OLD."ps_component" IS DISTINCT FROM (NEW."ps_component") OR OLD."ps_module" IS DISTINCT FROM (NEW."ps_module") OR OLD."ps_update_stream" IS DISTINCT FROM (NEW."ps_update_stream") OR OLD."purl" IS DISTINCT FROM (NEW."purl") OR OLD."resolution" IS DISTINCT FROM (NEW."resolution") OR OLD."resolved_dt" IS DISTINCT FROM (NEW."resolved_dt") OR OLD."tracker_id" IS DISTINCT FROM (NEW."tracker_id") OR OLD."updated_dt" IS DISTINCT FROM (NEW."updated_dt") OR OLD."uuid" IS DISTINCT FROM (NEW."uuid"))', func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "cve_id", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "tracker_id", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affectedness", NEW."created_dt", NEW."cve_id", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", NEW."not_affected_justification", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."ps_update_stream", NEW."purl", NEW."resolution", NEW."resolved_dt", NEW."tracker_id", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='7c0148fdedbe867f38f5b60bef9ff8bdc98f1ec0', operation='UPDATE', pgid='pgtrigger_update_update_fdef6', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "cve_id", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "tracker_id", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."affectedness", OLD."created_dt", OLD."cve_id", OLD."flaw_id", OLD."impact", OLD."last_validated_dt", OLD."not_affected_justification", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."ps_component", OLD."ps_module", OLD."ps_update_stream", OLD."purl", OLD."resolution", OLD."resolved_dt", OLD."tracker_id", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='b6b110fae0af85f93f5b83cdd80bf30f952c895b', operation='DELETE', pgid='pgtrigger_delete_delete_cc8c5', table='osidb_affect', when='AFTER')),
        ),
    ]
