# This is a MANUAL migration, it overrides Django's default migration
# to leverage PostgreSQL's fast default values, it will essentially
# set Affect._alerts to always have a default value of {} in the
# database instead of python code which would be very slow in a production
# database.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0057_remove_pghistory_event_tables'),
    ]

    operations = [
        migrations.RunSQL(
            """
            ALTER TABLE "osidb_affect"
            ADD COLUMN "_alerts" JSONB
            NOT NULL
            DEFAULT '{}'::JSONB
            """,
            reverse_sql="""
            ALTER TABLE "osidb_affect"
            DROP COLUMN "_alerts"
            """,
            state_operations=[
                migrations.AddField(
                    model_name='affect',
                    name='_alerts',
                    field=models.JSONField(blank=True, default=dict),
                ),
            ],
        ),
    ]
