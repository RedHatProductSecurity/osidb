# Generated by Django 3.2.12 on 2022-04-12 14:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("bzimport", "0002_rename_attr_job_meta_attr"),
        ("jiraffe", "0002_remove_job_models"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Job",
        ),
        migrations.DeleteModel(
            name="JobItem",
        ),
    ]
