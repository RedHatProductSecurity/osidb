# Generated by Django 3.2.13 on 2022-04-22 18:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0034_remove_affect_cve_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tracker',
            name='affects',
            field=models.ManyToManyField(blank=True, related_name='trackers', to='osidb.Affect'),
        ),
    ]
