# Generated by Django 3.2.25 on 2024-05-31 10:43

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0136_remove_affect_cvss_fields'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='flawcomment',
            name='type',
        ),
    ]
