"""
Written manually on 2026-06-08.

Converts workflow_state from a choices-constrained CharField to a free-form
CharField, allowing workflow YAML definitions to use arbitrary state names.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("osidb", "0241_rejected_workflow_redesign"),
    ]

    operations = [
        migrations.AlterField(
            model_name="flaw",
            name="workflow_state",
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AlterField(
            model_name="flawaudit",
            name="workflow_state",
            field=models.CharField(blank=True, max_length=50),
        ),
    ]
