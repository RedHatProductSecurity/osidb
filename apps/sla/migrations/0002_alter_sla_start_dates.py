# Generated by Django 3.2.25 on 2024-08-09 11:19

import json

from django.db import migrations, models


def convert_array_to_json(apps, schema_editor):
    SLA = apps.get_model("sla", "SLA")
    for instance in SLA.objects.all():
        instance.temp_json_field["flaw"] = instance.start_dates
        instance.save()


class Migration(migrations.Migration):

    dependencies = [
        ("sla", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="sla",
            name="temp_json_field",
            field=models.JSONField(default=dict),
        ),
        migrations.RunPython(convert_array_to_json),
        migrations.RemoveField(
            model_name="sla",
            name="start_dates",
        ),
        migrations.RenameField(
            model_name="sla",
            old_name="temp_json_field",
            new_name="start_dates",
        ),
    ]
