# Generated by Django 3.2.23 on 2024-01-04 11:39

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0111_gin_indexes_for_RBS_perf'),
    ]

    operations = [
        migrations.AddField(
            model_name='flaw',
            name='local_updated_dt',
            field=models.DateTimeField(null=True, default=django.utils.timezone.now),
        ),
        migrations.AddIndex(
            model_name='flaw',
            index=models.Index(fields=['-local_updated_dt'], name='osidb_flaw_local_u_9d468b_idx'),
        ),
    ]