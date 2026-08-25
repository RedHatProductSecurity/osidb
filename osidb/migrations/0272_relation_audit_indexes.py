# Generated manually for OSIDB-4999.

from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0271_recalculate_cvssv4_scores"),
    ]

    operations = [
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
    ]
