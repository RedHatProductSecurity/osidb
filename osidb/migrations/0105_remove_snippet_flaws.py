# Generated by Django 3.2.20 on 2023-11-30 07:43

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0104_auto_20231120_2049'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='snippet',
            name='flaws',
        ),
    ]
