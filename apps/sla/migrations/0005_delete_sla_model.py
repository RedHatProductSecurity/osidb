# This is necessary for cleaning up relationship names since
# renaming operation doesn't change it and when recreating SLA
# model will conflict names of relationships.
# Also this is safe since SLA are deleted and recollected everytime.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('sla', '0004_make_sla_nullable'),
    ]

    operations = [
        migrations.DeleteModel(
            name='SLA',
        ),
        migrations.DeleteModel(
            name='SLAPolicy',
        ),
    ]