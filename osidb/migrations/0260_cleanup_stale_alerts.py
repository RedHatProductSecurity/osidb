"""
One-time cleanup of alerts for validators that no longer exist.

Optimized version that uses a single DELETE statement with WHERE NOT IN
for better performance while staying transactional.
"""

import logging

from django.db import migrations

from osidb.helpers import bypass_rls

logger = logging.getLogger(__name__)

# Explicit alert name strings passed to self.alert() in current validators
EXPLICIT_ALERT_NAMES = {
    "bzsync_failed",
    "cvss3_missing",
    "embargoed_source_public",
    "exploits_kev_cve_description_missing",
    "exploits_kev_statement_missing",
    "flaw_affects_rhscl_collection_only",
    "flaw_affects_rhscl_invalid_collection",
    "flaw_affects_unknown_component",
    "flaw_historical_affect_status",
    "mi_article_missing",
    "mi_cve_description_missing",
    "mi_mitigation_missing",
    "mi_statement_missing",
    "old_flaw_affect_ps_module",
    "private_source_no_ack",
    "public_source_no_ack",
    "request_nist_cvss_validation",
    "rh_nist_cvss_score_diff",
    "rh_nist_cvss_severity_diff",
    "set_impact_with_zero_CVSSv3_score",
    "special_consideration_flaw_missing_cve_description",
    "special_consideration_flaw_missing_statement",
    "unset_impact_with_nonzero_CVSSv3_score",
    "unsupported_impact_change",
}

# @validator method names (frozen snapshot, 2026-08-06).
# The AlertMixin fallback converts ValidationError into an alert whose
# name is the validator method name, so these are also valid alert names.
VALIDATOR_METHOD_NAMES = {
    "_validate_acl_duplicite",
    "_validate_acl_expected",
    "_validate_acl_identical_to_parent",
    "_validate_acl_identical_to_parent_flaw",
    "_validate_acl_read_meaningful",
    "_validate_acl_write_meaningful",
    "_validate_acls_known",
    "_validate_affect_status_resolution",
    "_validate_allowed_source",
    "_validate_article_link",
    "_validate_article_links_count_via_flaw",
    "_validate_article_links_count_via_flawreferences",
    "_validate_cvss3",
    "_validate_cvss_comment",
    "_validate_cvss_not_affected",
    "_validate_cvss_scores_and_nist_cvss_validation",
    "_validate_cvss_string",
    "_validate_defer_open_tracker",
    "_validate_defer_open_trackers",
    "_validate_either_purl_or_ps_component_provided",
    "_validate_embargoed_source",
    "_validate_embargoing_public_flaw",
    "_validate_exploits_kev_fields",
    "_validate_future_unembargo_date",
    "_validate_historical_affectedness_resolution",
    "_validate_major_incident_fields",
    "_validate_major_incident_state_reset",
    "_validate_multi_flaw_tracker",
    "_validate_nist_rh_cvss_feedback_loop",
    "_validate_no_placeholder",
    "_validate_not_affected_justification",
    "_validate_notaffected_open_tracker",
    "_validate_ooss_open_tracker",
    "_validate_pre_registration",
    "_validate_private_source_no_ack",
    "_validate_ps_module_new_flaw",
    "_validate_ps_module_old_flaw",
    "_validate_ps_update_stream",
    "_validate_public_source_no_ack",
    "_validate_public_unembargo_date",
    "_validate_purl_and_ps_component",
    "_validate_purl_existence",
    "_validate_rh_cvss3_and_impact",
    "_validate_rh_nist_cvss_score_diff",
    "_validate_rh_nist_cvss_severity_diff",
    "_validate_rh_products_in_affects",
    "_validate_sofware_collection",
    "_validate_special_consideration_flaw",
    "_validate_tracker_affect",
    "_validate_tracker_affect_ps_update_stream",
    "_validate_tracker_bts_match",
    "_validate_tracker_flaw_accesses",
    "_validate_tracker_ps_update_stream",
    "_validate_unknown_component",
    "_validate_unsupported_impact_change",
    "_validate_wontfix_open_tracker",
    "_validate_wontreport_products",
    "_validate_wontreport_severity",
}

VALID_ALERT_NAMES = EXPLICIT_ALERT_NAMES | VALIDATOR_METHOD_NAMES


@bypass_rls
def cleanup_stale_alerts(apps, schema_editor):
    """
    Delete alerts with names not in VALID_ALERT_NAMES.

    Uses a single DELETE with WHERE NOT IN clause for better performance.
    Still runs in a transaction, so it's atomic despite being a single statement.
    """
    Alert = apps.get_model("osidb", "Alert")

    # Use raw SQL for better performance - single DELETE statement
    # Django ORM's exclude(name__in=...) would work but generates a subquery
    with schema_editor.connection.cursor() as cursor:
        # First, check how many stale alerts exist
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM osidb_alert
            WHERE name NOT IN %s
            """,
            [tuple(VALID_ALERT_NAMES)]
        )
        stale_count = cursor.fetchone()[0]

        if stale_count == 0:
            logger.info("No stale alerts found")
            return

        logger.info(f"Found {stale_count} stale alerts to delete")

        # Delete all stale alerts in one statement
        # PostgreSQL will still do this transactionally
        cursor.execute(
            """
            DELETE FROM osidb_alert
            WHERE name NOT IN %s
            RETURNING name
            """,
            [tuple(VALID_ALERT_NAMES)]
        )

        # Fetch just the unique names that were deleted (for logging)
        deleted_names = {row[0] for row in cursor.fetchall()}

        logger.info(
            f"Deleted {stale_count} stale alerts for validators: {deleted_names}"
        )


class Migration(migrations.Migration):

    dependencies = [
        ("osidb", "0259_remove_flawlabel_insert_insert_and_more"),
    ]

    operations = [
        migrations.RunPython(
            code=cleanup_stale_alerts,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
