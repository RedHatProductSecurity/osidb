# Generated by Django 3.2.24 on 2024-06-05 14:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('osidb', '0138_delete_flawmeta'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='flaw',
            name='is_major_incident',
        ),
    ]