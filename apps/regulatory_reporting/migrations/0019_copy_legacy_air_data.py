from django.db import migrations


def copy_legacy_air_data(apps, schema_editor):
    SRPReportMilestone = apps.get_model("regulatory_reporting", "SRPReportMilestone")
    AdditionalInformationRequest = apps.get_model(
        "regulatory_reporting", "AdditionalInformationRequest"
    )

    legacy_air_milestones = SRPReportMilestone.objects.filter(
        milestone_type="additional_information_response"
    )

    for legacy in legacy_air_milestones:
        parent = (
            SRPReportMilestone.objects.filter(srp_report=legacy.srp_report)
            .exclude(milestone_type="additional_information_response")
            .order_by("created_dt")
            .first()
        )
        if parent is None:
            raise RuntimeError(
                f"Legacy AIR milestone {legacy.uuid} on report "
                f"{legacy.srp_report_id} has no sibling milestone to attach to. "
                "Manual intervention required before this migration can proceed."
            )

        AdditionalInformationRequest.objects.create(
            milestone=parent,
            acl_read=parent.acl_read,
            acl_write=parent.acl_write,
            request_received_at=legacy.request_received_at,
            request_source=legacy.request_source or "",
            request_text=legacy.request_text or "",
        )
        legacy.delete()


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("regulatory_reporting", "0018_additionalinformationrequest_acl_read_and_more"),
    ]

    operations = [
        migrations.RunPython(copy_legacy_air_data, noop_reverse),
    ]