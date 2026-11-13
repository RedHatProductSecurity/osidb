"""Keep Django's automatic FK indexes and remove equivalent explicit indexes."""

from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("regulatory_reporting", "0030_rls_audit_delegation"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    "DROP INDEX CONCURRENTLY IF EXISTS regulatory__flaw_id_13d5c7_idx",
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
                    "regulatory__flaw_id_13d5c7_idx "
                    "ON regulatory_reporting_srpreport (flaw_id)",
                ),
            ],
            state_operations=[
                migrations.RemoveIndex(
                    model_name="srpreport", name="regulatory__flaw_id_13d5c7_idx"
                ),
            ],
        ),
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    "DROP INDEX CONCURRENTLY IF EXISTS regulatory__srp_rep_22bfc9_idx",
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
                    "regulatory__srp_rep_22bfc9_idx "
                    "ON regulatory_reporting_srpreportmilestone (srp_report_id)",
                ),
            ],
            state_operations=[
                migrations.RemoveIndex(
                    model_name="srpreportmilestone",
                    name="regulatory__srp_rep_22bfc9_idx",
                ),
            ],
        ),
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    "DROP INDEX CONCURRENTLY IF EXISTS regulatory__flaw_id_bf4d9d_idx",
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
                    "regulatory__flaw_id_bf4d9d_idx "
                    "ON regulatory_reporting_upstreamnotification (flaw_id)",
                ),
            ],
            state_operations=[
                migrations.RemoveIndex(
                    model_name="upstreamnotification",
                    name="regulatory__flaw_id_bf4d9d_idx",
                ),
            ],
        ),
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    "DROP INDEX CONCURRENTLY IF EXISTS regulatory__upstrea_b432a4_idx",
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
                    "regulatory__upstrea_b432a4_idx "
                    "ON regulatory_reporting_upstreamnotification (upstream_project_id)",
                ),
            ],
            state_operations=[
                migrations.RemoveIndex(
                    model_name="upstreamnotification",
                    name="regulatory__upstrea_b432a4_idx",
                ),
            ],
        ),
    ]
