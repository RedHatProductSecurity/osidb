# Generated manually for OSIDB-4999.

from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0266_manual_triage_kernel_flaws"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affectaudit_flaw_history
                ON osidb_affectaudit (flaw_id, pgh_created_at DESC, pgh_id DESC)
                WHERE flaw_id IS NOT NULL
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_affectaudit_flaw_history
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affectaudit_flaw_tracker_history
                ON osidb_affectaudit (
                    flaw_id, tracker_id, pgh_created_at DESC, pgh_id DESC
                )
                WHERE flaw_id IS NOT NULL AND tracker_id IS NOT NULL
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_affectaudit_flaw_tracker_history
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affectaudit_obj_prev
                ON osidb_affectaudit (pgh_obj_id, pgh_id DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_affectaudit_obj_prev
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_trackeraudit_obj_prev
                ON osidb_trackeraudit (pgh_obj_id, pgh_id DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_trackeraudit_obj_prev
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_trackeraudit_obj_history
                ON osidb_trackeraudit (pgh_obj_id, pgh_created_at DESC, pgh_id DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_trackeraudit_obj_history
            """,
        ),
    ]
