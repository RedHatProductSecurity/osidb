# Generated manually for ReportableEventType → Flaw.FlawMajorIncident values

from django.db import migrations, models


OLD_TO_NEW = {
    "actively_exploited_vulnerability": "EXPLOITS_KEV_APPROVED",
    "severe_incident": "MAJOR_INCIDENT_APPROVED",
    "additional_information_request": "ADDITIONAL_INFORMATION_REQUEST",
}

NEW_TO_OLD = {v: k for k, v in OLD_TO_NEW.items()}


def forwards_remap_event_types(apps, schema_editor):
    SRPReport = apps.get_model("regulatory_reporting", "SRPReport")
    SRPReportAudit = apps.get_model("regulatory_reporting", "SRPReportAudit")
    for old, new in OLD_TO_NEW.items():
        SRPReport.objects.filter(reportable_event_type=old).update(
            reportable_event_type=new
        )
        SRPReportAudit.objects.filter(reportable_event_type=old).update(
            reportable_event_type=new
        )


def backwards_remap_event_types(apps, schema_editor):
    SRPReport = apps.get_model("regulatory_reporting", "SRPReport")
    SRPReportAudit = apps.get_model("regulatory_reporting", "SRPReportAudit")
    for new, old in NEW_TO_OLD.items():
        SRPReport.objects.filter(reportable_event_type=new).update(
            reportable_event_type=old
        )
        SRPReportAudit.objects.filter(reportable_event_type=new).update(
            reportable_event_type=old
        )


class Migration(migrations.Migration):

    dependencies = [
        ("regulatory_reporting", "0006_remove_srpreport_insert_insert_and_more"),
    ]

    operations = [
        migrations.RunPython(forwards_remap_event_types, backwards_remap_event_types),
        migrations.AlterField(
            model_name="srpreport",
            name="reportable_event_type",
            field=models.CharField(
                choices=[
                    ("EXPLOITS_KEV_APPROVED", "Actively Exploited Vulnerability"),
                    ("MAJOR_INCIDENT_APPROVED", "Severe Incident"),
                    (
                        "ADDITIONAL_INFORMATION_REQUEST",
                        "Additional Information Request",
                    ),
                ],
                help_text="Type of event being reported to ENISA",
                max_length=50,
            ),
        ),
        migrations.AlterField(
            model_name="srpreportaudit",
            name="reportable_event_type",
            field=models.CharField(
                choices=[
                    ("EXPLOITS_KEV_APPROVED", "Actively Exploited Vulnerability"),
                    ("MAJOR_INCIDENT_APPROVED", "Severe Incident"),
                    (
                        "ADDITIONAL_INFORMATION_REQUEST",
                        "Additional Information Request",
                    ),
                ],
                help_text="Type of event being reported to ENISA",
                max_length=50,
            ),
        ),
        migrations.AddConstraint(
            model_name="srpreport",
            constraint=models.UniqueConstraint(
                fields=("flaw", "reportable_event_type"),
                name="unique_srp_report_flaw_event_type",
            ),
        ),
    ]
