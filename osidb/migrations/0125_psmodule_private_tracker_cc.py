# Generated by Django 3.2.25 on 2024-04-16 11:38

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0124_add_trigram_extension'),
    ]

    operations = [
        migrations.AddField(
            model_name='psmodule',
            name='private_tracker_cc',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=50), blank=True, default=list, size=None),
        ),
    ]
