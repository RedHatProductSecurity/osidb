# Generated by Django 3.2.9 on 2021-12-04 09:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0018_add_tracker_status_resolution"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="affect",
            name="component",
        ),
        migrations.RemoveField(
            model_name="affect",
            name="module_name",
        ),
        migrations.RemoveField(
            model_name="affect",
            name="module_stream",
        ),
        migrations.RemoveField(
            model_name="affectevent",
            name="component",
        ),
        migrations.RemoveField(
            model_name="affectevent",
            name="module_name",
        ),
        migrations.RemoveField(
            model_name="affectevent",
            name="module_stream",
        ),
    ]
