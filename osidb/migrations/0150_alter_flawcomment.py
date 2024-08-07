# Generated by Django 3.2.25 on 2024-07-04 17:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0149_populate_special_consideration_flaws_alerts'),
    ]

    operations = [
        migrations.AddField(
            model_name='flawcomment',
            name='synced_to_bz',
            field=models.BooleanField(default=False),
        ),
        migrations.AddConstraint(
            model_name='flawcomment',
            constraint=models.UniqueConstraint(fields=('flaw', 'order'), name='unique_per_flaw_comment_nums'),
        ),
    ]
