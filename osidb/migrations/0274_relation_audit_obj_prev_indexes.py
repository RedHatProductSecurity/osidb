from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("osidb", "0273_psupdatestream_minimal_impact"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affectcvssaudit_obj_prev
                ON osidb_affectcvssaudit (pgh_obj_id, pgh_id DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_affectcvssaudit_obj_prev
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flawcvssaudit_obj_prev
                ON osidb_flawcvssaudit (pgh_obj_id, pgh_id DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_flawcvssaudit_obj_prev
            """,
        ),
        migrations.RunSQL(
            sql="""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flawlabelv2audit_obj_prev
                ON osidb_flawlabelv2audit (pgh_obj_id, pgh_id DESC)
            """,
            reverse_sql="""
                DROP INDEX CONCURRENTLY IF EXISTS idx_flawlabelv2audit_obj_prev
            """,
        ),
    ]
