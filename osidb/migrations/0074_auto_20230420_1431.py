# Generated by Django 3.2.18 on 2023-04-20 14:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0073_alter_flawmeta_type'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='affect',
            index=models.Index(fields=['flaw', 'ps_module'], name='osidb_affec_flaw_id_1a7b76_idx'),
        ),
        migrations.AddIndex(
            model_name='affect',
            index=models.Index(fields=['flaw', 'ps_component'], name='osidb_affec_flaw_id_50ba3c_idx'),
        ),
    ]
