from django.db import migrations
from django.contrib.auth.models import User


def forwards_func(apps, schema_editor):

    context_model = next(
        (
            model
            for model in apps.get_models("osidb")
            if model._meta.model_name == "context"
        ),
        None,
    )

    if not context_model:
        return

    context_entries = context_model.objects.all().iterator()
    for entry in context_entries:
        if "user" in entry.metadata and isinstance(entry.metadata["user"], int):
            user_id = entry.metadata["user"]
            user = User.objects.get(id=user_id)
            if user and (user.email or user.username):
                entry.metadata["user"] = user.email or user.username
                entry.metadata["user_id"] = user_id
                entry.save()


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0187_add_tracker_special_handling"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop),
    ]
