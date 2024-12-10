# Generated by Django 4.2.16 on 2024-12-10 09:07

from django.db import migrations, models
import django.utils.timezone
from django.utils.timezone import timedelta
import pgtrigger.compiler
import pgtrigger.migrations


def forwards_func(apps, schema_editor):
    Alerts = apps.get_model("osidb", "Alert")

    # We assume that all the alerts on the database are valid
    # and we update the created_dt to be 1 hour in the future
    # to avoid missing some of them during the migration
    Alerts.objects.all().update(created_dt=django.utils.timezone.now() + timedelta(hours=1))

class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0176_delete_ubipackage'),
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
        pgtrigger.migrations.RemoveTrigger(
            model_name='affectcvss',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='affectcvss',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='affectcvss',
            name='delete_delete',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flaw',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flaw',
            name='delete_delete',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flaw',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawacknowledgment',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawacknowledgment',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawacknowledgment',
            name='delete_delete',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawcomment',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawcomment',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawcomment',
            name='delete_delete',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawcvss',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawcvss',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawcvss',
            name='delete_delete',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawreference',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawreference',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='flawreference',
            name='delete_delete',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='snippet',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='snippet',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='snippet',
            name='delete_delete',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='tracker',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='tracker',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='tracker',
            name='delete_delete',
        ),
        migrations.AddField(
            model_name='affect',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='affectaudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='affectcvss',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='affectcvssaudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flaw',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawacknowledgment',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawacknowledgmentaudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawaudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawcomment',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawcommentaudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawcvss',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawcvssaudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawreference',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='flawreferenceaudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='package',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='snippet',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='snippetaudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='tracker',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='trackeraudit',
            name='last_validated_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='alert',
            name='created_dt',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now),
        ),
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "purl", "resolution", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affectedness", NEW."created_dt", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."purl", NEW."resolution", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='3a87fcfb62d8eca1fa3da212ef7d7c554552c276', operation='INSERT', pgid='pgtrigger_insert_insert_0d1b1', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."acl_read" IS DISTINCT FROM (NEW."acl_read") OR OLD."acl_write" IS DISTINCT FROM (NEW."acl_write") OR OLD."affectedness" IS DISTINCT FROM (NEW."affectedness") OR OLD."created_dt" IS DISTINCT FROM (NEW."created_dt") OR OLD."flaw_id" IS DISTINCT FROM (NEW."flaw_id") OR OLD."impact" IS DISTINCT FROM (NEW."impact") OR OLD."last_validated_dt" IS DISTINCT FROM (NEW."last_validated_dt") OR OLD."ps_component" IS DISTINCT FROM (NEW."ps_component") OR OLD."ps_module" IS DISTINCT FROM (NEW."ps_module") OR OLD."purl" IS DISTINCT FROM (NEW."purl") OR OLD."resolution" IS DISTINCT FROM (NEW."resolution") OR OLD."updated_dt" IS DISTINCT FROM (NEW."updated_dt") OR OLD."uuid" IS DISTINCT FROM (NEW."uuid"))', func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "purl", "resolution", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affectedness", NEW."created_dt", NEW."flaw_id", NEW."impact", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."ps_component", NEW."ps_module", NEW."purl", NEW."resolution", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='038fc57ac665fe8b90660f75a1c5092c46d248bf', operation='UPDATE', pgid='pgtrigger_update_update_fdef6', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affect',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectaudit" ("acl_read", "acl_write", "affectedness", "created_dt", "flaw_id", "impact", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_component", "ps_module", "purl", "resolution", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."affectedness", OLD."created_dt", OLD."flaw_id", OLD."impact", OLD."last_validated_dt", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."ps_component", OLD."ps_module", OLD."purl", OLD."resolution", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='e9ecb4a38c3515b2dc892ed48e5a6188ccad5971', operation='DELETE', pgid='pgtrigger_delete_delete_cc8c5', table='osidb_affect', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affectcvss',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectcvssaudit" ("acl_read", "acl_write", "affect_id", "comment", "created_dt", "issuer", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "score", "updated_dt", "uuid", "vector", "version") VALUES (NEW."acl_read", NEW."acl_write", NEW."affect_id", NEW."comment", NEW."created_dt", NEW."issuer", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."score", NEW."updated_dt", NEW."uuid", NEW."vector", NEW."version"); RETURN NULL;', hash='9be2075d24a78e18b4f8a4a8efe7f618d06588fa', operation='INSERT', pgid='pgtrigger_insert_insert_b9f93', table='osidb_affectcvss', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affectcvss',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD.* IS DISTINCT FROM NEW.*)', func='INSERT INTO "osidb_affectcvssaudit" ("acl_read", "acl_write", "affect_id", "comment", "created_dt", "issuer", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "score", "updated_dt", "uuid", "vector", "version") VALUES (NEW."acl_read", NEW."acl_write", NEW."affect_id", NEW."comment", NEW."created_dt", NEW."issuer", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."score", NEW."updated_dt", NEW."uuid", NEW."vector", NEW."version"); RETURN NULL;', hash='14771b87b0a63e138cb1df2e2234d37ad841979e', operation='UPDATE', pgid='pgtrigger_update_update_2bc7b', table='osidb_affectcvss', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='affectcvss',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_affectcvssaudit" ("acl_read", "acl_write", "affect_id", "comment", "created_dt", "issuer", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "score", "updated_dt", "uuid", "vector", "version") VALUES (OLD."acl_read", OLD."acl_write", OLD."affect_id", OLD."comment", OLD."created_dt", OLD."issuer", OLD."last_validated_dt", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."score", OLD."updated_dt", OLD."uuid", OLD."vector", OLD."version"); RETURN NULL;', hash='f0b025d5c80db71f099cfee1a65f9b699be6a672', operation='DELETE', pgid='pgtrigger_delete_delete_5e2a9', table='osidb_affectcvss', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flaw',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawaudit" ("acl_read", "acl_write", "bzsync_manager_id", "comment_zero", "components", "created_dt", "cve_description", "cve_id", "cwe_id", "download_manager_id", "group_key", "impact", "last_validated_dt", "major_incident_start_dt", "major_incident_state", "mitigation", "nist_cvss_validation", "owner", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "reported_dt", "requires_cve_description", "source", "statement", "task_download_manager_id", "task_key", "task_updated_dt", "team_id", "title", "unembargo_dt", "uuid", "workflow_name", "workflow_state") VALUES (NEW."acl_read", NEW."acl_write", NEW."bzsync_manager_id", NEW."comment_zero", NEW."components", NEW."created_dt", NEW."cve_description", NEW."cve_id", NEW."cwe_id", NEW."download_manager_id", NEW."group_key", NEW."impact", NEW."last_validated_dt", NEW."major_incident_start_dt", NEW."major_incident_state", NEW."mitigation", NEW."nist_cvss_validation", NEW."owner", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."reported_dt", NEW."requires_cve_description", NEW."source", NEW."statement", NEW."task_download_manager_id", NEW."task_key", NEW."task_updated_dt", NEW."team_id", NEW."title", NEW."unembargo_dt", NEW."uuid", NEW."workflow_name", NEW."workflow_state"); RETURN NULL;', hash='676136597a1d68ca4b1b2877831a3962376e4f79', operation='INSERT', pgid='pgtrigger_insert_insert_4e668', table='osidb_flaw', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flaw',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."acl_read" IS DISTINCT FROM (NEW."acl_read") OR OLD."acl_write" IS DISTINCT FROM (NEW."acl_write") OR OLD."bzsync_manager_id" IS DISTINCT FROM (NEW."bzsync_manager_id") OR OLD."comment_zero" IS DISTINCT FROM (NEW."comment_zero") OR OLD."components" IS DISTINCT FROM (NEW."components") OR OLD."created_dt" IS DISTINCT FROM (NEW."created_dt") OR OLD."cve_description" IS DISTINCT FROM (NEW."cve_description") OR OLD."cve_id" IS DISTINCT FROM (NEW."cve_id") OR OLD."cwe_id" IS DISTINCT FROM (NEW."cwe_id") OR OLD."download_manager_id" IS DISTINCT FROM (NEW."download_manager_id") OR OLD."group_key" IS DISTINCT FROM (NEW."group_key") OR OLD."impact" IS DISTINCT FROM (NEW."impact") OR OLD."last_validated_dt" IS DISTINCT FROM (NEW."last_validated_dt") OR OLD."major_incident_start_dt" IS DISTINCT FROM (NEW."major_incident_start_dt") OR OLD."major_incident_state" IS DISTINCT FROM (NEW."major_incident_state") OR OLD."mitigation" IS DISTINCT FROM (NEW."mitigation") OR OLD."nist_cvss_validation" IS DISTINCT FROM (NEW."nist_cvss_validation") OR OLD."owner" IS DISTINCT FROM (NEW."owner") OR OLD."reported_dt" IS DISTINCT FROM (NEW."reported_dt") OR OLD."requires_cve_description" IS DISTINCT FROM (NEW."requires_cve_description") OR OLD."source" IS DISTINCT FROM (NEW."source") OR OLD."statement" IS DISTINCT FROM (NEW."statement") OR OLD."task_download_manager_id" IS DISTINCT FROM (NEW."task_download_manager_id") OR OLD."task_key" IS DISTINCT FROM (NEW."task_key") OR OLD."task_updated_dt" IS DISTINCT FROM (NEW."task_updated_dt") OR OLD."team_id" IS DISTINCT FROM (NEW."team_id") OR OLD."title" IS DISTINCT FROM (NEW."title") OR OLD."unembargo_dt" IS DISTINCT FROM (NEW."unembargo_dt") OR OLD."uuid" IS DISTINCT FROM (NEW."uuid") OR OLD."workflow_name" IS DISTINCT FROM (NEW."workflow_name") OR OLD."workflow_state" IS DISTINCT FROM (NEW."workflow_state"))', func='INSERT INTO "osidb_flawaudit" ("acl_read", "acl_write", "bzsync_manager_id", "comment_zero", "components", "created_dt", "cve_description", "cve_id", "cwe_id", "download_manager_id", "group_key", "impact", "last_validated_dt", "major_incident_start_dt", "major_incident_state", "mitigation", "nist_cvss_validation", "owner", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "reported_dt", "requires_cve_description", "source", "statement", "task_download_manager_id", "task_key", "task_updated_dt", "team_id", "title", "unembargo_dt", "uuid", "workflow_name", "workflow_state") VALUES (NEW."acl_read", NEW."acl_write", NEW."bzsync_manager_id", NEW."comment_zero", NEW."components", NEW."created_dt", NEW."cve_description", NEW."cve_id", NEW."cwe_id", NEW."download_manager_id", NEW."group_key", NEW."impact", NEW."last_validated_dt", NEW."major_incident_start_dt", NEW."major_incident_state", NEW."mitigation", NEW."nist_cvss_validation", NEW."owner", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."reported_dt", NEW."requires_cve_description", NEW."source", NEW."statement", NEW."task_download_manager_id", NEW."task_key", NEW."task_updated_dt", NEW."team_id", NEW."title", NEW."unembargo_dt", NEW."uuid", NEW."workflow_name", NEW."workflow_state"); RETURN NULL;', hash='6c72668f9929d79bd2f9e4719e9e5147b5055a12', operation='UPDATE', pgid='pgtrigger_update_update_96595', table='osidb_flaw', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flaw',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawaudit" ("acl_read", "acl_write", "bzsync_manager_id", "comment_zero", "components", "created_dt", "cve_description", "cve_id", "cwe_id", "download_manager_id", "group_key", "impact", "last_validated_dt", "major_incident_start_dt", "major_incident_state", "mitigation", "nist_cvss_validation", "owner", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "reported_dt", "requires_cve_description", "source", "statement", "task_download_manager_id", "task_key", "task_updated_dt", "team_id", "title", "unembargo_dt", "uuid", "workflow_name", "workflow_state") VALUES (OLD."acl_read", OLD."acl_write", OLD."bzsync_manager_id", OLD."comment_zero", OLD."components", OLD."created_dt", OLD."cve_description", OLD."cve_id", OLD."cwe_id", OLD."download_manager_id", OLD."group_key", OLD."impact", OLD."last_validated_dt", OLD."major_incident_start_dt", OLD."major_incident_state", OLD."mitigation", OLD."nist_cvss_validation", OLD."owner", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."reported_dt", OLD."requires_cve_description", OLD."source", OLD."statement", OLD."task_download_manager_id", OLD."task_key", OLD."task_updated_dt", OLD."team_id", OLD."title", OLD."unembargo_dt", OLD."uuid", OLD."workflow_name", OLD."workflow_state"); RETURN NULL;', hash='4f868a927b16ce88e645b7f19be0a61eeab8111b', operation='DELETE', pgid='pgtrigger_delete_delete_f2e13', table='osidb_flaw', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawacknowledgment',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawacknowledgmentaudit" ("acl_read", "acl_write", "affiliation", "created_dt", "flaw_id", "from_upstream", "last_validated_dt", "name", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affiliation", NEW."created_dt", NEW."flaw_id", NEW."from_upstream", NEW."last_validated_dt", NEW."name", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='60a7b911a359948728c2d0db54c5b4e730f29395', operation='INSERT', pgid='pgtrigger_insert_insert_8d8ea', table='osidb_flawacknowledgment', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawacknowledgment',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD.* IS DISTINCT FROM NEW.*)', func='INSERT INTO "osidb_flawacknowledgmentaudit" ("acl_read", "acl_write", "affiliation", "created_dt", "flaw_id", "from_upstream", "last_validated_dt", "name", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."affiliation", NEW."created_dt", NEW."flaw_id", NEW."from_upstream", NEW."last_validated_dt", NEW."name", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='1c37dce90b1304271898dd3d2dcacbd14d6b674e', operation='UPDATE', pgid='pgtrigger_update_update_3f509', table='osidb_flawacknowledgment', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawacknowledgment',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawacknowledgmentaudit" ("acl_read", "acl_write", "affiliation", "created_dt", "flaw_id", "from_upstream", "last_validated_dt", "name", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."affiliation", OLD."created_dt", OLD."flaw_id", OLD."from_upstream", OLD."last_validated_dt", OLD."name", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='429903f36bd28b5949f7c9e3e8362283fb95df85', operation='DELETE', pgid='pgtrigger_delete_delete_c737c', table='osidb_flawacknowledgment', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawcomment',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawcommentaudit" ("acl_read", "acl_write", "created_dt", "creator", "external_system_id", "flaw_id", "is_private", "last_validated_dt", "order", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "synced_to_bz", "text", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."created_dt", NEW."creator", NEW."external_system_id", NEW."flaw_id", NEW."is_private", NEW."last_validated_dt", NEW."order", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."synced_to_bz", NEW."text", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='f287186e44f74ea6ff9f4513618931e92c15ef4f', operation='INSERT', pgid='pgtrigger_insert_insert_5fac1', table='osidb_flawcomment', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawcomment',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD.* IS DISTINCT FROM NEW.*)', func='INSERT INTO "osidb_flawcommentaudit" ("acl_read", "acl_write", "created_dt", "creator", "external_system_id", "flaw_id", "is_private", "last_validated_dt", "order", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "synced_to_bz", "text", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."created_dt", NEW."creator", NEW."external_system_id", NEW."flaw_id", NEW."is_private", NEW."last_validated_dt", NEW."order", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."synced_to_bz", NEW."text", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='6553cf55093d15892d502d12700b91369001afca', operation='UPDATE', pgid='pgtrigger_update_update_165cb', table='osidb_flawcomment', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawcomment',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawcommentaudit" ("acl_read", "acl_write", "created_dt", "creator", "external_system_id", "flaw_id", "is_private", "last_validated_dt", "order", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "synced_to_bz", "text", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."created_dt", OLD."creator", OLD."external_system_id", OLD."flaw_id", OLD."is_private", OLD."last_validated_dt", OLD."order", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."synced_to_bz", OLD."text", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='c92ee5fcbd1da649db2854d15361d5d7cb38ffa8', operation='DELETE', pgid='pgtrigger_delete_delete_09c05', table='osidb_flawcomment', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawcvss',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawcvssaudit" ("acl_read", "acl_write", "comment", "created_dt", "flaw_id", "issuer", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "score", "updated_dt", "uuid", "vector", "version") VALUES (NEW."acl_read", NEW."acl_write", NEW."comment", NEW."created_dt", NEW."flaw_id", NEW."issuer", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."score", NEW."updated_dt", NEW."uuid", NEW."vector", NEW."version"); RETURN NULL;', hash='cce994e80ce9387b4640c3b5e5efcdd7e93a53a2', operation='INSERT', pgid='pgtrigger_insert_insert_c1c4a', table='osidb_flawcvss', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawcvss',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD.* IS DISTINCT FROM NEW.*)', func='INSERT INTO "osidb_flawcvssaudit" ("acl_read", "acl_write", "comment", "created_dt", "flaw_id", "issuer", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "score", "updated_dt", "uuid", "vector", "version") VALUES (NEW."acl_read", NEW."acl_write", NEW."comment", NEW."created_dt", NEW."flaw_id", NEW."issuer", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."score", NEW."updated_dt", NEW."uuid", NEW."vector", NEW."version"); RETURN NULL;', hash='69cb9c04d3a1a3aed115c0fb6c707efcba74da0a', operation='UPDATE', pgid='pgtrigger_update_update_6038c', table='osidb_flawcvss', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawcvss',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawcvssaudit" ("acl_read", "acl_write", "comment", "created_dt", "flaw_id", "issuer", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "score", "updated_dt", "uuid", "vector", "version") VALUES (OLD."acl_read", OLD."acl_write", OLD."comment", OLD."created_dt", OLD."flaw_id", OLD."issuer", OLD."last_validated_dt", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."score", OLD."updated_dt", OLD."uuid", OLD."vector", OLD."version"); RETURN NULL;', hash='8b07c49a17b9d88acda5c8c5f06385a96918c876', operation='DELETE', pgid='pgtrigger_delete_delete_608c3', table='osidb_flawcvss', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawreference',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawreferenceaudit" ("acl_read", "acl_write", "created_dt", "description", "flaw_id", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "type", "updated_dt", "url", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."created_dt", NEW."description", NEW."flaw_id", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."type", NEW."updated_dt", NEW."url", NEW."uuid"); RETURN NULL;', hash='481ddfe397e35b191a7ab4b6fce48e2ec55e74d2', operation='INSERT', pgid='pgtrigger_insert_insert_7df8e', table='osidb_flawreference', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawreference',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD.* IS DISTINCT FROM NEW.*)', func='INSERT INTO "osidb_flawreferenceaudit" ("acl_read", "acl_write", "created_dt", "description", "flaw_id", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "type", "updated_dt", "url", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."created_dt", NEW."description", NEW."flaw_id", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."type", NEW."updated_dt", NEW."url", NEW."uuid"); RETURN NULL;', hash='8aaa34955ebeb651896bf57b89bbc19e3a0e1789', operation='UPDATE', pgid='pgtrigger_update_update_5bc43', table='osidb_flawreference', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='flawreference',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_flawreferenceaudit" ("acl_read", "acl_write", "created_dt", "description", "flaw_id", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "type", "updated_dt", "url", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."created_dt", OLD."description", OLD."flaw_id", OLD."last_validated_dt", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."type", OLD."updated_dt", OLD."url", OLD."uuid"); RETURN NULL;', hash='da45f3bdd15ee2a4b7c6f0c30fa1d1b52e9343fa', operation='DELETE', pgid='pgtrigger_delete_delete_8fa4c', table='osidb_flawreference', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='snippet',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_snippetaudit" ("acl_read", "acl_write", "content", "created_dt", "external_id", "flaw_id", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "source", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."content", NEW."created_dt", NEW."external_id", NEW."flaw_id", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."source", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='51e2c753a1d005c3d272bfff6f5525c876aaef15', operation='INSERT', pgid='pgtrigger_insert_insert_e56b3', table='osidb_snippet', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='snippet',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD.* IS DISTINCT FROM NEW.*)', func='INSERT INTO "osidb_snippetaudit" ("acl_read", "acl_write", "content", "created_dt", "external_id", "flaw_id", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "source", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."content", NEW."created_dt", NEW."external_id", NEW."flaw_id", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."source", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='fb98a95d7a0d5082bbdc26bc17058c18b502e762', operation='UPDATE', pgid='pgtrigger_update_update_ff792', table='osidb_snippet', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='snippet',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_snippetaudit" ("acl_read", "acl_write", "content", "created_dt", "external_id", "flaw_id", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "source", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."content", OLD."created_dt", OLD."external_id", OLD."flaw_id", OLD."last_validated_dt", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."source", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='c5876c97b643e8c59d24b68d16a53b3c3620cd7b', operation='DELETE', pgid='pgtrigger_delete_delete_56a33', table='osidb_snippet', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='tracker',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_trackeraudit" ("acl_read", "acl_write", "bz_download_manager_id", "bz_link_manager_id", "created_dt", "external_system_id", "jira_download_manager_id", "jira_link_manager_id", "last_impact_increase_dt", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_update_stream", "resolution", "status", "type", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."bz_download_manager_id", NEW."bz_link_manager_id", NEW."created_dt", NEW."external_system_id", NEW."jira_download_manager_id", NEW."jira_link_manager_id", NEW."last_impact_increase_dt", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."ps_update_stream", NEW."resolution", NEW."status", NEW."type", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='b8b217796d2b1c9b695a76f4e6122fd207638293', operation='INSERT', pgid='pgtrigger_insert_insert_781c0', table='osidb_tracker', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='tracker',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."acl_read" IS DISTINCT FROM (NEW."acl_read") OR OLD."acl_write" IS DISTINCT FROM (NEW."acl_write") OR OLD."bz_download_manager_id" IS DISTINCT FROM (NEW."bz_download_manager_id") OR OLD."bz_link_manager_id" IS DISTINCT FROM (NEW."bz_link_manager_id") OR OLD."created_dt" IS DISTINCT FROM (NEW."created_dt") OR OLD."external_system_id" IS DISTINCT FROM (NEW."external_system_id") OR OLD."jira_download_manager_id" IS DISTINCT FROM (NEW."jira_download_manager_id") OR OLD."jira_link_manager_id" IS DISTINCT FROM (NEW."jira_link_manager_id") OR OLD."last_impact_increase_dt" IS DISTINCT FROM (NEW."last_impact_increase_dt") OR OLD."last_validated_dt" IS DISTINCT FROM (NEW."last_validated_dt") OR OLD."ps_update_stream" IS DISTINCT FROM (NEW."ps_update_stream") OR OLD."resolution" IS DISTINCT FROM (NEW."resolution") OR OLD."status" IS DISTINCT FROM (NEW."status") OR OLD."type" IS DISTINCT FROM (NEW."type") OR OLD."updated_dt" IS DISTINCT FROM (NEW."updated_dt") OR OLD."uuid" IS DISTINCT FROM (NEW."uuid"))', func='INSERT INTO "osidb_trackeraudit" ("acl_read", "acl_write", "bz_download_manager_id", "bz_link_manager_id", "created_dt", "external_system_id", "jira_download_manager_id", "jira_link_manager_id", "last_impact_increase_dt", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_update_stream", "resolution", "status", "type", "updated_dt", "uuid") VALUES (NEW."acl_read", NEW."acl_write", NEW."bz_download_manager_id", NEW."bz_link_manager_id", NEW."created_dt", NEW."external_system_id", NEW."jira_download_manager_id", NEW."jira_link_manager_id", NEW."last_impact_increase_dt", NEW."last_validated_dt", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."ps_update_stream", NEW."resolution", NEW."status", NEW."type", NEW."updated_dt", NEW."uuid"); RETURN NULL;', hash='16c6ab69cad7bcf2dff4fd79ec80c42cb8cabc4d', operation='UPDATE', pgid='pgtrigger_update_update_4b400', table='osidb_tracker', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='tracker',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "osidb_trackeraudit" ("acl_read", "acl_write", "bz_download_manager_id", "bz_link_manager_id", "created_dt", "external_system_id", "jira_download_manager_id", "jira_link_manager_id", "last_impact_increase_dt", "last_validated_dt", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "ps_update_stream", "resolution", "status", "type", "updated_dt", "uuid") VALUES (OLD."acl_read", OLD."acl_write", OLD."bz_download_manager_id", OLD."bz_link_manager_id", OLD."created_dt", OLD."external_system_id", OLD."jira_download_manager_id", OLD."jira_link_manager_id", OLD."last_impact_increase_dt", OLD."last_validated_dt", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."ps_update_stream", OLD."resolution", OLD."status", OLD."type", OLD."updated_dt", OLD."uuid"); RETURN NULL;', hash='872cd307b8e792e0177db2f32a345cbb2ef7d00d', operation='DELETE', pgid='pgtrigger_delete_delete_d12e8', table='osidb_tracker', when='AFTER')),
        ),
    ]