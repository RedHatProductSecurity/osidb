from django.template.loader import render_to_string


class TestUpstreamMaintainerNotificationTemplate:
    """Tests for the upstream maintainer email template"""

    REQUIRED_CONTEXT = {
        "flaw_id": "CVE-2026-12345",
        "vulnerability_summary": "Test summary",
        "upstream_component": "test-component",
        "impact": "Moderate",
        "corrective_measure": "Upgrade to 1.2.3",
        "contact_info": "test@example.com",
    }

    def test_txt_renders_required_fields(self):
        rendered = render_to_string(
            "email/upstream_maintainer_notification.txt", self.REQUIRED_CONTEXT
        )
        assert "CVE-2026-12345" in rendered
        assert "Test summary" in rendered
        assert "test-component" in rendered
        assert "Moderate" in rendered
        assert "Upgrade to 1.2.3" in rendered
        assert "test@example.com" in rendered

    def test_txt_omits_confidentiality_notice_when_not_passed(self):
        rendered = render_to_string(
            "email/upstream_maintainer_notification.txt", self.REQUIRED_CONTEXT
        )
        assert "confidential" not in rendered.lower()

    def test_txt_includes_confidentiality_notice_when_passed(self):
        context = {
            **self.REQUIRED_CONTEXT,
            "confidentiality_notice": "This information is confidential until public disclosure.",
        }
        rendered = render_to_string(
            "email/upstream_maintainer_notification.txt", context
        )
        assert "confidential until public disclosure" in rendered

    def test_html_renders_required_fields(self):
        rendered = render_to_string(
            "email/upstream_maintainer_notification.html", self.REQUIRED_CONTEXT
        )
        assert "CVE-2026-12345" in rendered
        assert "Test summary" in rendered
        assert "test-component" in rendered
        assert "Moderate" in rendered
        assert "Upgrade to 1.2.3" in rendered
        assert "test@example.com" in rendered

    def test_html_omits_confidentiality_notice_when_not_passed(self):
        rendered = render_to_string(
            "email/upstream_maintainer_notification.html", self.REQUIRED_CONTEXT
        )
        assert "confidential" not in rendered.lower()

    def test_html_includes_confidentiality_notice_when_passed(self):
        context = {
            **self.REQUIRED_CONTEXT,
            "confidentiality_notice": "This information is confidential until public disclosure.",
        }
        rendered = render_to_string(
            "email/upstream_maintainer_notification.html", context
        )
        assert "confidential until public disclosure" in rendered

    def test_renders_for_common_flaw_states(self):
        for state in ["NEW", "TRIAGE", "DONE", "REJECTED"]:
            context = {**self.REQUIRED_CONTEXT, "flaw_id": f"CVE-2026-{state}"}
            rendered = render_to_string(
                "email/upstream_maintainer_notification.txt", context
            )
            assert f"CVE-2026-{state}" in rendered
