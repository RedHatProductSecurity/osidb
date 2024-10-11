"""
Written manually on 2024-10-08

Change existing alert messages adding details of an affect in tracker's alert.
"""

from django.conf import settings
from django.db import migrations
from osidb.core import set_user_acls

def description_notaffected_open_tracker(tracker):
    affect = tracker.affects.filter(
        affectedness="NOTAFFECTED"
    ).first()
    if not tracker.status.upper() == "CLOSED" and affect:
        return (
            "The tracker is associated with a NOTAFFECTED affect: "
            f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
        )
    return ""

def description_ooss_open_tracker(tracker):
    affect = tracker.affects.filter(resolution="OOSS").first()
    if not tracker.status.upper() == "CLOSED" and affect:
        return (
            "The tracker is associated with an OOSS affect: "
            f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
        )
    return ""

def description_wontfix_open_tracker(tracker):
    affect = tracker.affects.filter(resolution="WONTFIX").first()
    if not tracker.status.upper() == "CLOSED" and affect:
        return (
            "The tracker is associated with a WONTFIX affect: "
            f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
        )
    return ""

def description_defer_open_tracker(tracker):
    affect = tracker.affects.filter(resolution="DEFER").first()
    if not tracker.status.upper() == "CLOSED" and affect:
        return (
            "The tracker is associated with a DEFER affect: "
            f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
        )
    return ""

def description_tracker_duplicate(tracker):
    for affect in tracker.affects.all():
        if (
            affect.trackers.filter(ps_update_stream=tracker.ps_update_stream).count()
            > 1
        ):
            return (
                f"Tracker with the update stream {tracker.ps_update_stream} "
                "is already associated with the affect "
                f"{affect.ps_module}/{affect.ps_component} ({affect.uuid})"
            )
    return ""

def forwards_func(apps, schema_editor):
    # changed alerts
    names = [
        "_validate_notaffected_open_tracker",
        "_validate_ooss_open_tracker",
        "_validate_wontfix_open_tracker",
        "_validate_defer_open_tracker",
        "_validate_tracker_duplicate",
    ]
    batch_size = 1000

    set_user_acls(settings.ALL_GROUPS)
    Alert = apps.get_model("osidb", "Alert")
    Tracker = apps.get_model("osidb", "Tracker")
    ContentType = apps.get_model("contenttypes", "ContentType")
    tracker_type = ContentType.objects.get_for_model(Tracker)

    alerts_queryset = (
        Alert.objects.filter(name__in=names, content_type=tracker_type)
    )

    for start in range(0, alerts_queryset.count(), batch_size):
        alerts_batch = alerts_queryset[start:start + batch_size]
        batch = []
        for alert in alerts_batch:
            description = ""
            tracker = Tracker.objects.get(uuid=alert.object_id)
            if alert.name == "_validate_notaffected_open_tracker":
                description = description_notaffected_open_tracker(tracker)
            elif alert.name == "_validate_ooss_open_tracker":
                description = description_ooss_open_tracker(tracker)
            elif alert.name == "_validate_wontfix_open_tracker":
                description = description_wontfix_open_tracker(tracker)
            elif alert.name == "_validate_defer_open_tracker":
                description = description_defer_open_tracker(tracker)
            elif alert.name == "_validate_tracker_duplicate":
                description = description_tracker_duplicate(tracker)

            if description:
                alert.description = description
                batch.append(alert)
        if batch:
            Alert.objects.bulk_update(batch, ['description'])


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0171_remove_flawcomment_unique_per_flaw_comment_nums_and_more"),
    ]

    operations = [
        migrations.RunPython(forwards_func, migrations.RunPython.noop, atomic=True),
    ]
