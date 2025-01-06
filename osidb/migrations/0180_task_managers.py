# Generated by Django 4.2.17 on 2025-01-06 14:50

from django.db import migrations, models
import django.db.models.deletion
import pgtrigger.compiler
import pgtrigger.migrations


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0179_flawcollaborator_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="JiraTaskSyncManager",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("sync_id", models.CharField(max_length=100, unique=True)),
                ("last_scheduled_dt", models.DateTimeField(blank=True, null=True)),
                ("last_started_dt", models.DateTimeField(blank=True, null=True)),
                ("last_finished_dt", models.DateTimeField(blank=True, null=True)),
                ("last_failed_dt", models.DateTimeField(blank=True, null=True)),
                ("last_failed_reason", models.TextField(blank=True, null=True)),
                ("last_consecutive_failures", models.IntegerField(default=0)),
                ("permanently_failed", models.BooleanField(default=False)),
                ("last_rescheduled_dt", models.DateTimeField(blank=True, null=True)),
                ("last_rescheduled_reason", models.TextField(blank=True, null=True)),
                ("last_consecutive_reschedules", models.IntegerField(default=0)),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="JiraTaskTransitionManager",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("sync_id", models.CharField(max_length=100, unique=True)),
                ("last_scheduled_dt", models.DateTimeField(blank=True, null=True)),
                ("last_started_dt", models.DateTimeField(blank=True, null=True)),
                ("last_finished_dt", models.DateTimeField(blank=True, null=True)),
                ("last_failed_dt", models.DateTimeField(blank=True, null=True)),
                ("last_failed_reason", models.TextField(blank=True, null=True)),
                ("last_consecutive_failures", models.IntegerField(default=0)),
                ("permanently_failed", models.BooleanField(default=False)),
                ("last_rescheduled_dt", models.DateTimeField(blank=True, null=True)),
                ("last_rescheduled_reason", models.TextField(blank=True, null=True)),
                ("last_consecutive_reschedules", models.IntegerField(default=0)),
            ],
            options={
                "abstract": False,
            },
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name="flaw",
            name="insert_insert",
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name="flaw",
            name="update_update",
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name="flaw",
            name="delete_delete",
        ),
        migrations.AddField(
            model_name="flaw",
            name="task_sync_manager",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="osidb.jiratasksyncmanager",
            ),
        ),
        migrations.AddField(
            model_name="flaw",
            name="task_transition_manager",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="osidb.jiratasktransitionmanager",
            ),
        ),
        migrations.AddField(
            model_name="flawaudit",
            name="task_sync_manager",
            field=models.ForeignKey(
                blank=True,
                db_constraint=False,
                null=True,
                on_delete=django.db.models.deletion.DO_NOTHING,
                related_name="+",
                related_query_name="+",
                to="osidb.jiratasksyncmanager",
            ),
        ),
        migrations.AddField(
            model_name="flawaudit",
            name="task_transition_manager",
            field=models.ForeignKey(
                blank=True,
                db_constraint=False,
                null=True,
                on_delete=django.db.models.deletion.DO_NOTHING,
                related_name="+",
                related_query_name="+",
                to="osidb.jiratasktransitionmanager",
            ),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name="flaw",
            trigger=pgtrigger.compiler.Trigger(
                name="insert_insert",
                sql=pgtrigger.compiler.UpsertTriggerSql(
                    func='INSERT INTO "osidb_flawaudit" ("acl_read", "acl_write", "bzsync_manager_id", "comment_zero", "components", "created_dt", "cve_description", "cve_id", "cwe_id", "download_manager_id", "group_key", "impact", "last_validated_dt", "major_incident_start_dt", "major_incident_state", "mitigation", "nist_cvss_validation", "owner", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "reported_dt", "requires_cve_description", "source", "statement", "task_download_manager_id", "task_key", "task_sync_manager_id", "task_transition_manager_id", "task_updated_dt", "team_id", "title", "unembargo_dt", "uuid", "workflow_name", "workflow_state") VALUES (NEW."acl_read", NEW."acl_write", NEW."bzsync_manager_id", NEW."comment_zero", NEW."components", NEW."created_dt", NEW."cve_description", NEW."cve_id", NEW."cwe_id", NEW."download_manager_id", NEW."group_key", NEW."impact", NEW."last_validated_dt", NEW."major_incident_start_dt", NEW."major_incident_state", NEW."mitigation", NEW."nist_cvss_validation", NEW."owner", _pgh_attach_context(), NOW(), \'insert\', NEW."uuid", NEW."reported_dt", NEW."requires_cve_description", NEW."source", NEW."statement", NEW."task_download_manager_id", NEW."task_key", NEW."task_sync_manager_id", NEW."task_transition_manager_id", NEW."task_updated_dt", NEW."team_id", NEW."title", NEW."unembargo_dt", NEW."uuid", NEW."workflow_name", NEW."workflow_state"); RETURN NULL;',
                    hash="98c46c01aeb71bf2ebc387e4cc337d1cca5ac319",
                    operation="INSERT",
                    pgid="pgtrigger_insert_insert_4e668",
                    table="osidb_flaw",
                    when="AFTER",
                ),
            ),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name="flaw",
            trigger=pgtrigger.compiler.Trigger(
                name="update_update",
                sql=pgtrigger.compiler.UpsertTriggerSql(
                    condition='WHEN (OLD."acl_read" IS DISTINCT FROM (NEW."acl_read") OR OLD."acl_write" IS DISTINCT FROM (NEW."acl_write") OR OLD."bzsync_manager_id" IS DISTINCT FROM (NEW."bzsync_manager_id") OR OLD."comment_zero" IS DISTINCT FROM (NEW."comment_zero") OR OLD."components" IS DISTINCT FROM (NEW."components") OR OLD."created_dt" IS DISTINCT FROM (NEW."created_dt") OR OLD."cve_description" IS DISTINCT FROM (NEW."cve_description") OR OLD."cve_id" IS DISTINCT FROM (NEW."cve_id") OR OLD."cwe_id" IS DISTINCT FROM (NEW."cwe_id") OR OLD."download_manager_id" IS DISTINCT FROM (NEW."download_manager_id") OR OLD."group_key" IS DISTINCT FROM (NEW."group_key") OR OLD."impact" IS DISTINCT FROM (NEW."impact") OR OLD."last_validated_dt" IS DISTINCT FROM (NEW."last_validated_dt") OR OLD."major_incident_start_dt" IS DISTINCT FROM (NEW."major_incident_start_dt") OR OLD."major_incident_state" IS DISTINCT FROM (NEW."major_incident_state") OR OLD."mitigation" IS DISTINCT FROM (NEW."mitigation") OR OLD."nist_cvss_validation" IS DISTINCT FROM (NEW."nist_cvss_validation") OR OLD."owner" IS DISTINCT FROM (NEW."owner") OR OLD."reported_dt" IS DISTINCT FROM (NEW."reported_dt") OR OLD."requires_cve_description" IS DISTINCT FROM (NEW."requires_cve_description") OR OLD."source" IS DISTINCT FROM (NEW."source") OR OLD."statement" IS DISTINCT FROM (NEW."statement") OR OLD."task_download_manager_id" IS DISTINCT FROM (NEW."task_download_manager_id") OR OLD."task_key" IS DISTINCT FROM (NEW."task_key") OR OLD."task_sync_manager_id" IS DISTINCT FROM (NEW."task_sync_manager_id") OR OLD."task_transition_manager_id" IS DISTINCT FROM (NEW."task_transition_manager_id") OR OLD."task_updated_dt" IS DISTINCT FROM (NEW."task_updated_dt") OR OLD."team_id" IS DISTINCT FROM (NEW."team_id") OR OLD."title" IS DISTINCT FROM (NEW."title") OR OLD."unembargo_dt" IS DISTINCT FROM (NEW."unembargo_dt") OR OLD."uuid" IS DISTINCT FROM (NEW."uuid") OR OLD."workflow_name" IS DISTINCT FROM (NEW."workflow_name") OR OLD."workflow_state" IS DISTINCT FROM (NEW."workflow_state"))',
                    func='INSERT INTO "osidb_flawaudit" ("acl_read", "acl_write", "bzsync_manager_id", "comment_zero", "components", "created_dt", "cve_description", "cve_id", "cwe_id", "download_manager_id", "group_key", "impact", "last_validated_dt", "major_incident_start_dt", "major_incident_state", "mitigation", "nist_cvss_validation", "owner", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "reported_dt", "requires_cve_description", "source", "statement", "task_download_manager_id", "task_key", "task_sync_manager_id", "task_transition_manager_id", "task_updated_dt", "team_id", "title", "unembargo_dt", "uuid", "workflow_name", "workflow_state") VALUES (NEW."acl_read", NEW."acl_write", NEW."bzsync_manager_id", NEW."comment_zero", NEW."components", NEW."created_dt", NEW."cve_description", NEW."cve_id", NEW."cwe_id", NEW."download_manager_id", NEW."group_key", NEW."impact", NEW."last_validated_dt", NEW."major_incident_start_dt", NEW."major_incident_state", NEW."mitigation", NEW."nist_cvss_validation", NEW."owner", _pgh_attach_context(), NOW(), \'update\', NEW."uuid", NEW."reported_dt", NEW."requires_cve_description", NEW."source", NEW."statement", NEW."task_download_manager_id", NEW."task_key", NEW."task_sync_manager_id", NEW."task_transition_manager_id", NEW."task_updated_dt", NEW."team_id", NEW."title", NEW."unembargo_dt", NEW."uuid", NEW."workflow_name", NEW."workflow_state"); RETURN NULL;',
                    hash="e07b784137a91bf5747030b2d1b558ea0e1ba12f",
                    operation="UPDATE",
                    pgid="pgtrigger_update_update_96595",
                    table="osidb_flaw",
                    when="AFTER",
                ),
            ),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name="flaw",
            trigger=pgtrigger.compiler.Trigger(
                name="delete_delete",
                sql=pgtrigger.compiler.UpsertTriggerSql(
                    func='INSERT INTO "osidb_flawaudit" ("acl_read", "acl_write", "bzsync_manager_id", "comment_zero", "components", "created_dt", "cve_description", "cve_id", "cwe_id", "download_manager_id", "group_key", "impact", "last_validated_dt", "major_incident_start_dt", "major_incident_state", "mitigation", "nist_cvss_validation", "owner", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "reported_dt", "requires_cve_description", "source", "statement", "task_download_manager_id", "task_key", "task_sync_manager_id", "task_transition_manager_id", "task_updated_dt", "team_id", "title", "unembargo_dt", "uuid", "workflow_name", "workflow_state") VALUES (OLD."acl_read", OLD."acl_write", OLD."bzsync_manager_id", OLD."comment_zero", OLD."components", OLD."created_dt", OLD."cve_description", OLD."cve_id", OLD."cwe_id", OLD."download_manager_id", OLD."group_key", OLD."impact", OLD."last_validated_dt", OLD."major_incident_start_dt", OLD."major_incident_state", OLD."mitigation", OLD."nist_cvss_validation", OLD."owner", _pgh_attach_context(), NOW(), \'delete\', OLD."uuid", OLD."reported_dt", OLD."requires_cve_description", OLD."source", OLD."statement", OLD."task_download_manager_id", OLD."task_key", OLD."task_sync_manager_id", OLD."task_transition_manager_id", OLD."task_updated_dt", OLD."team_id", OLD."title", OLD."unembargo_dt", OLD."uuid", OLD."workflow_name", OLD."workflow_state"); RETURN NULL;',
                    hash="3918295961736ccfe51016ab42ea22c9a315ade2",
                    operation="DELETE",
                    pgid="pgtrigger_delete_delete_f2e13",
                    table="osidb_flaw",
                    when="AFTER",
                ),
            ),
        ),
    ]
