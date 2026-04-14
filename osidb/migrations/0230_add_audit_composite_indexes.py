# backfill index for existing pghistory audit tables, new audit models
# should inherit CustomHistoryBase automatically via PGHISTORY_BASE_MODEL settings

from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0229_deprecate_requires_cve_description"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affectaudit_obj_lookup
                ON osidb_affectaudit (pgh_obj_id, pgh_created_at DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_affectaudit_obj_lookup
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flawaudit_obj_lookup
                ON osidb_flawaudit (pgh_obj_id, pgh_created_at DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_flawaudit_obj_lookup
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affectcvssaudit_obj_lookup
                ON osidb_affectcvssaudit (pgh_obj_id, pgh_created_at DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_affectcvssaudit_obj_lookup
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flawacknowledgmentaudit_obj_lookup
                ON osidb_flawacknowledgmentaudit (pgh_obj_id, pgh_created_at DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_flawacknowledgmentaudit_obj_lookup
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flawcommentaudit_obj_lookup
                ON osidb_flawcommentaudit (pgh_obj_id, pgh_created_at DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_flawcommentaudit_obj_lookup
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flawcvssaudit_obj_lookup
                ON osidb_flawcvssaudit (pgh_obj_id, pgh_created_at DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_flawcvssaudit_obj_lookup
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flawreferenceaudit_obj_lookup
                ON osidb_flawreferenceaudit (pgh_obj_id, pgh_created_at DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_flawreferenceaudit_obj_lookup
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_trackeraudit_obj_lookup
                ON osidb_trackeraudit (pgh_obj_id, pgh_created_at DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_trackeraudit_obj_lookup
            """,
        ),
    ]
