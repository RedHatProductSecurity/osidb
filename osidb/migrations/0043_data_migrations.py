from django.db import migrations

from osidb.core import generate_acls


def null_to_empty(app, model, field):
    return migrations.RunSQL(
        f"UPDATE {app}_{model} SET {field}='' WHERE {field} IS NULL;",
        migrations.RunSQL.noop,
    )


ACLS = ",".join(
    generate_acls(
        [
            "osidb-prod-public-read",
            "osidb-prod-embargo-read",
            "osidb-prod-public-write",
            "osidb-prod-embargo-write",
            "osidb-stage-public-read",
            "osidb-stage-embargo-read",
            "osidb-stage-public-write",
            "osidb-stage-embargo-write",
        ]
    )
)


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0042_dt_no_auto"),
    ]

    operations = [
        migrations.RunSQL(f"SET osidb.acl='{ACLS}';", migrations.RunSQL.noop),
        null_to_empty("osidb", "flaw", "cvss2"),
        null_to_empty("osidb", "flaw", "cvss3"),
        null_to_empty("osidb", "flaw", "cwe_id"),
        null_to_empty("osidb", "flaw", "description"),
        null_to_empty("osidb", "flaw", "impact"),
        null_to_empty("osidb", "flaw", "mitigated_by"),
        null_to_empty("osidb", "flaw", "nvd_cvss2"),
        null_to_empty("osidb", "flaw", "nvd_cvss3"),
        null_to_empty("osidb", "flaw", "resolution"),
        null_to_empty("osidb", "flaw", "source"),
        null_to_empty("osidb", "flaw", "state"),
        null_to_empty("osidb", "flaw", "statement"),
        null_to_empty("osidb", "flaw", "summary"),
        null_to_empty("osidb", "flaw", "type"),
        null_to_empty("osidb", "flawevent", "cvss2"),
        null_to_empty("osidb", "flawevent", "cvss3"),
        null_to_empty("osidb", "flawevent", "cwe_id"),
        null_to_empty("osidb", "flawevent", "description"),
        null_to_empty("osidb", "flawevent", "impact"),
        null_to_empty("osidb", "flawevent", "mitigated_by"),
        null_to_empty("osidb", "flawevent", "nvd_cvss2"),
        null_to_empty("osidb", "flawevent", "nvd_cvss3"),
        null_to_empty("osidb", "flawevent", "resolution"),
        null_to_empty("osidb", "flawevent", "source"),
        null_to_empty("osidb", "flawevent", "state"),
        null_to_empty("osidb", "flawevent", "statement"),
        null_to_empty("osidb", "flawevent", "summary"),
        null_to_empty("osidb", "flawevent", "type"),
        null_to_empty("osidb", "flawhistory", "impact"),
        null_to_empty("osidb", "flawhistory", "source"),
        null_to_empty("osidb", "flawhistory", "cve_id"),
        null_to_empty("osidb", "flawhistory", "cvss2"),
        null_to_empty("osidb", "flawhistory", "cvss3"),
        null_to_empty("osidb", "flawhistory", "cwe_id"),
        null_to_empty("osidb", "flawhistory", "description"),
        null_to_empty("osidb", "flawhistory", "impact"),
        null_to_empty("osidb", "flawhistory", "mitigated_by"),
        null_to_empty("osidb", "flawhistory", "resolution"),
        null_to_empty("osidb", "flawhistory", "source"),
        null_to_empty("osidb", "flawhistory", "state"),
        null_to_empty("osidb", "flawhistory", "statement"),
        null_to_empty("osidb", "flawhistory", "summary"),
        null_to_empty("osidb", "flawhistory", "type"),
        null_to_empty("osidb", "affect", "affectedness"),
        null_to_empty("osidb", "affect", "cvss2"),
        null_to_empty("osidb", "affect", "cvss3"),
        null_to_empty("osidb", "affect", "impact"),
        null_to_empty("osidb", "affect", "ps_component"),
        null_to_empty("osidb", "affect", "ps_module"),
        null_to_empty("osidb", "affect", "resolution"),
        null_to_empty("osidb", "affect", "resolution"),
        null_to_empty("osidb", "affectevent", "affectedness"),
        null_to_empty("osidb", "affectevent", "cvss2"),
        null_to_empty("osidb", "affectevent", "cvss3"),
        null_to_empty("osidb", "affectevent", "impact"),
        null_to_empty("osidb", "affectevent", "ps_component"),
        null_to_empty("osidb", "affectevent", "ps_module"),
        null_to_empty("osidb", "affectevent", "resolution"),
        null_to_empty("osidb", "affectevent", "type"),
        null_to_empty("osidb", "tracker", "external_system_id"),
        null_to_empty("osidb", "tracker", "ps_update_stream"),
        null_to_empty("osidb", "tracker", "resolution"),
        null_to_empty("osidb", "tracker", "status"),
        null_to_empty("osidb", "tracker", "type"),
        null_to_empty("osidb", "trackerevent", "external_system_id"),
        null_to_empty("osidb", "trackerevent", "ps_update_stream"),
        null_to_empty("osidb", "trackerevent", "resolution"),
        null_to_empty("osidb", "trackerevent", "status"),
        null_to_empty("osidb", "trackerevent", "type"),
        # special case, defined in osim but subclassed in osidb
        null_to_empty("osidb", "flaw", "osim_state"),
        null_to_empty("osidb", "flaw", "osim_workflow"),
        null_to_empty("osidb", "flawevent", "osim_state"),
        null_to_empty("osidb", "flawevent", "osim_workflow"),
        null_to_empty("osidb", "flawcomment", "external_system_id"),
        null_to_empty("osidb", "flawmeta", "type"),
        null_to_empty("osidb", "flawmetaevent", "type"),
        null_to_empty("osidb", "psmodule", "default_component"),
        null_to_empty("osidb", "psmodule", "public_description"),
        null_to_empty("osidb", "psmodule", "unacked_ps_update_stream"),
        null_to_empty("osidb", "psupdatestream", "version"),
        null_to_empty("osidb", "psupdatestream", "target_release"),
        null_to_empty("osidb", "pscontact", "bz_username"),
        null_to_empty("osidb", "pscontact", "jboss_username"),
        null_to_empty("osidb", "profile", "bz_user_id"),
        null_to_empty("osidb", "profile", "jira_user_id"),
        null_to_empty("osidb", "flaw", "source"),
        null_to_empty("osidb", "flawevent", "source"),
        null_to_empty("osidb", "flawhistory", "source"),
    ]
