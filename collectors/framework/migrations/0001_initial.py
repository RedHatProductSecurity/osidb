# Generated by Django 3.2.9 on 2021-12-21 13:28

import django.contrib.postgres.fields
import psqlextra.fields.hstore_field
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="CollectorMetadata",
            fields=[
                (
                    "name",
                    models.CharField(
                        editable=False,
                        max_length=200,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "data_state",
                    models.CharField(
                        choices=[
                            ("EMPTY", "Empty"),
                            ("PARTIAL", "Partial"),
                            ("COMPLETE", "Complete"),
                        ],
                        default="EMPTY",
                        max_length=10,
                    ),
                ),
                ("updated_until_dt", models.DateTimeField(blank=True, null=True)),
                (
                    "meta_attr",
                    psqlextra.fields.hstore_field.HStoreField(blank=True, null=True),
                ),
                (
                    "collector_state",
                    models.CharField(
                        choices=[
                            ("PENDING", "Pending"),
                            ("BLOCKED", "Blocked"),
                            ("READY", "Ready"),
                            ("RUNNING", "Running"),
                        ],
                        default="PENDING",
                        max_length=10,
                    ),
                ),
                (
                    "crontab",
                    models.CharField(blank=True, max_length=100, null=True),
                ),
                (
                    "depends_on",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.CharField(max_length=200),
                        blank=True,
                        default=list,
                        null=True,
                        size=None,
                    ),
                ),
                (
                    "error",
                    models.TextField(blank=True, default=None, null=True),
                ),
                (
                    "model",
                    models.CharField(blank=True, max_length=100, null=True),
                ),
            ],
        ),
    ]
