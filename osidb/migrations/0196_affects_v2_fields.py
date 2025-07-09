import django.contrib.postgres.fields
from django.conf import settings
from django.db import migrations, models
import pgtrigger.compiler
import pgtrigger.migrations
import psqlextra.fields.hstore_field
from osidb.core import set_user_acls


BATCH_SIZE = 1000

def forwards_func(apps, schema_editor):
    """
    Initialize ps_update_stream to ps_module to avoid it being empty as it is a
    required field. It will be filled correctly in the data migration.
    """
    set_user_acls(settings.ALL_GROUPS)
    Affect = apps.get_model("osidb", "Affect")

    batch = []
    for affect in Affect.objects.all():
        affect.ps_update_stream = affect.ps_module
        batch.append(affect)
        if len(batch) >= BATCH_SIZE:
            Affect.objects.bulk_update(batch, ["ps_update_stream"])
            batch.clear()
    
    if batch:
        Affect.objects.bulk_update(batch, ["ps_update_stream"])
        batch.clear()


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0195_alter_psproduct_team'),
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
        migrations.RemoveIndex(
            model_name='affect',
            name='osidb_affec_flaw_id_1a7b76_idx',
        ),
        migrations.AlterUniqueTogether(
            name='affect',
            unique_together=set(),
        ),
        migrations.AddField(
            model_name='affect',
            name='ps_update_stream',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='affectaudit',
            name='ps_update_stream',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='affect',
            name='ps_module',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='affectaudit',
            name='ps_module',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.RunPython(forwards_func),
        migrations.AlterUniqueTogether(
            name='affect',
            unique_together={('flaw', 'ps_update_stream', 'ps_component')},
        ),
        migrations.AddIndex(
            model_name='affect',
            index=models.Index(fields=['flaw', 'ps_update_stream'], name='osidb_affec_flaw_id_72f059_idx'),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affectedness", NEW."created_dt", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", NEW."not_affected_justification", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."ps_update_stream", NEW."purl", NEW."resolution", NEW."resolved_dt", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='f60db220c5aff3bb318e925aa239d678aa842f35', operation='INSERT', pgid='pgtrigger_insert_insert_0d1b1', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."acl_read" IS DISTINCT FROM (NEW."acl_read") OR OLD."acl_write" IS DISTINCT FROM (NEW."acl_write") OR OLD."affectedness" IS DISTINCT FROM (NEW."affectedness") OR OLD."created_dt" IS DISTINCT FROM (NEW."created_dt") OR OLD."flaw_id" IS DISTINCT FROM (NEW."flaw_id") OR OLD."impact" IS DISTINCT FROM (NEW."impact") OR OLD."last_validated_dt" IS DISTINCT FROM (NEW."last_validated_dt") OR OLD."not_affected_justification" IS DISTINCT FROM (NEW."not_affected_justification") OR OLD."ps_component" IS DISTINCT FROM (NEW."ps_component") OR OLD."ps_module" IS DISTINCT FROM (NEW."ps_module") OR OLD."ps_update_stream" IS DISTINCT FROM (NEW."ps_update_stream") OR OLD."purl" IS DISTINCT FROM (NEW."purl") OR OLD."resolution" IS DISTINCT FROM (NEW."resolution") OR OLD."resolved_dt" IS DISTINCT FROM (NEW."resolved_dt") OR OLD."updated_dt" IS DISTINCT FROM (NEW."updated_dt") OR OLD."uuid" IS DISTINCT FROM (NEW."uuid"))', func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affectedness", NEW."created_dt", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", NEW."not_affected_justification", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."ps_update_stream", NEW."purl", NEW."resolution", NEW."resolved_dt", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='f00a094c31e0f064600627a98b260e7962227136', operation='UPDATE', pgid='pgtrigger_update_update_fdef6', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."affectedness", OLD."created_dt", OLD."flaw_id", OLD."impact", OLD."last_validated_dt", OLD."not_affected_justification", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."ps_component", OLD."ps_module", OLD."ps_update_stream", OLD."purl", OLD."resolution", OLD."resolved_dt", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='843d6a7b22286153cb41a5862b198614c3b8141c', operation='DELETE', pgid='pgtrigger_delete_delete_cc8c5', table='osidb_affect', when='AFTER')),
        ),
    ]
