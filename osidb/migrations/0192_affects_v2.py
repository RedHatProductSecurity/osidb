from django.conf import settings
from django.db import migrations, models
from osidb.core import set_user_acls
import pgtrigger.compiler
import pgtrigger.migrations


BATCH_SIZE = 1000


def initial_populate_ps_update_stream(apps, schema_editor):
    # Populate ps_update_stream fields for current affects (which will be the v1 affects after the
    # data migration) with its own UUID. This is a hack to avoid errors due to empty or duplicate
    # ps_update_stream, this field is not used by v1 affects anyway.
    set_user_acls(settings.ALL_GROUPS)
    Affect = apps.get_model("osidb", "Affect")
    update_batch = []
    for affect in Affect.objects.all():
        affect.ps_update_stream = str(affect.uuid)
        update_batch.append(affect)
        if len(update_batch) >= BATCH_SIZE:
            Affect.objects.bulk_update(update_batch, ["ps_update_stream"])
            update_batch.clear()
    if update_batch:
        Affect.objects.bulk_update(update_batch, ["ps_update_stream"])


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0191_cisa_cvss_data_migration'),
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
            name='affect_v1',
            field=models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name='affects_v2', to='osidb.affect'),
        ),
        migrations.AddField(
            model_name='affect',
            name='ps_update_stream',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='affect',
            name='ps_module',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='affectaudit',
            name='ps_module',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='affectaudit',
            name='affect_v1',
            field=models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=models.deletion.DO_NOTHING, related_name='+', related_query_name='+', to='osidb.affect'),
        ),
        migrations.AddField(
            model_name='affectaudit',
            name='ps_update_stream',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
        migrations.RunPython(initial_populate_ps_update_stream, migrations.RunPython.noop),
        migrations.AddIndex(
            model_name='affect',
            index=models.Index(fields=['flaw', 'ps_update_stream'], name='osidb_affec_flaw_id_72f059_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='affect',
            unique_together={('flaw', 'ps_update_stream', 'ps_component')},
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affect_v1_id", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affect_v1_id", NEW."affectedness", NEW."created_dt", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", NEW."not_affected_justification", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."ps_update_stream", NEW."purl", NEW."resolution", NEW."resolved_dt", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='25ccad7f89a855c4a83e78ecf7acf66c8b41134f', operation='INSERT', pgid='pgtrigger_insert_insert_0d1b1', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."acl_read" IS DISTINCT FROM (NEW."acl_read") OR OLD."acl_write" IS DISTINCT FROM (NEW."acl_write") OR OLD."affect_v1_id" IS DISTINCT FROM (NEW."affect_v1_id") OR OLD."affectedness" IS DISTINCT FROM (NEW."affectedness") OR OLD."created_dt" IS DISTINCT FROM (NEW."created_dt") OR OLD."flaw_id" IS DISTINCT FROM (NEW."flaw_id") OR OLD."impact" IS DISTINCT FROM (NEW."impact") OR OLD."last_validated_dt" IS DISTINCT FROM (NEW."last_validated_dt") OR OLD."not_affected_justification" IS DISTINCT FROM (NEW."not_affected_justification") OR OLD."ps_component" IS DISTINCT FROM (NEW."ps_component") OR OLD."ps_module" IS DISTINCT FROM (NEW."ps_module") OR OLD."ps_update_stream" IS DISTINCT FROM (NEW."ps_update_stream") OR OLD."purl" IS DISTINCT FROM (NEW."purl") OR OLD."resolution" IS DISTINCT FROM (NEW."resolution") OR OLD."resolved_dt" IS DISTINCT FROM (NEW."resolved_dt") OR OLD."updated_dt" IS DISTINCT FROM (NEW."updated_dt") OR OLD."uuid" IS DISTINCT FROM (NEW."uuid"))', func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affect_v1_id", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affect_v1_id", NEW."affectedness", NEW."created_dt", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", NEW."not_affected_justification", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."ps_update_stream", NEW."purl", NEW."resolution", NEW."resolved_dt", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='54c82f489964fa66d8704794e4bb97e7053cd8e7', operation='UPDATE', pgid='pgtrigger_update_update_fdef6', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affect_v1_id", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "not_affected_justification", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "ps_update_stream", "purl", "resolution", "resolved_dt", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."affect_v1_id", OLD."affectedness", OLD."created_dt", OLD."flaw_id", OLD."impact", OLD."last_validated_dt", OLD."not_affected_justification", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."ps_component", OLD."ps_module", OLD."ps_update_stream", OLD."purl", OLD."resolution", OLD."resolved_dt", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='2aab5f842ee51cd16fb38be896c133ab246543eb', operation='DELETE', pgid='pgtrigger_delete_delete_cc8c5', table='osidb_affect', when='AFTER')),
        ),
    ]
