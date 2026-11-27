"""
Tests of Jira Task Manager service (Taskman)
This class uses VCR in order to not call real Jira endpoints
during regular tests, and it is recommendend to use Stage Jira
instance for generating new cassettes.
"""

import pytest
from django.contrib.auth.models import User

from apps.taskman.constants import JIRA_SUMMARY_MAX_LENGTH
from apps.taskman.service import JiraTaskmanQuerier
from apps.trackers.jira.constants import JIRA_EMBARGO_SECURITY_LEVEL_NAME
from osidb.exceptions import JiraConnectionException, JiraUserMappingException
from osidb.models import Affect, BULabel, BULabelDefinition, Flaw, Profile
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestTaskmanService(object):
    @pytest.mark.vcr
    @pytest.mark.enable_signals
    def test_create_or_update_task(self, jira_token, jira_email):
        """
        Test that service is able to create and update regular fields, team, assignment and status
        """
        # Remove randomness to reuse VCR every possible time
        user, _ = User.objects.get_or_create(username="concosta")
        Profile.objects.filter(user=user).update(atlassian_cloud_id="test=cloud-id")
        flaw = FlawFactory(embargoed=False, cwe_id="CWE-79")
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1 == "OSIM-14332"
        flaw.adjust_classification()

        old_title = flaw.title
        new_title = f"{old_title} edited title"

        flaw.title = new_title
        flaw.owner = "concosta@redhat.com"
        flaw.save()

        response2 = taskman.create_or_update_task(flaw=flaw)
        status, _ = flaw.jira_status()
        assert response2 is None

        # NOTAFFECTED:NOVALUE is resolved and needs no trackers, so the flaw
        # advances past ANALYSIS and, since DONE has no requirements, to DONE
        assert flaw.workflow_state == "DONE"
        flaw.save(raise_validation_error=False)
        response3 = taskman.create_or_update_task(flaw=flaw)
        assert response3 is None
        status, _ = flaw.jira_status()

        # test unassign
        flaw.owner = ""
        flaw.save(raise_validation_error=False)
        response4 = taskman.create_or_update_task(flaw=flaw)
        assert response4 is None
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert flaw.owner == ""
        issue = taskman.jira_conn.issue(flaw.task_key).raw
        assert not issue["fields"]["assignee"]

    @pytest.mark.vcr
    def test_comments(self, jira_token, jira_email):
        """
        Test that service is able to create comment in Jira
        """
        # Remove randomness to reuse VCR every possible time
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1 == "OSIM-421"

        response2 = taskman.create_comment(response1, "New comment")
        assert response2.status_code == 201

    @pytest.mark.vcr
    def test_add_link(self, jira_token, jira_email):
        """
        Test that service is able to create remote links in Jira issues.
        """
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1 == "OSIM-11643"

        response2 = taskman.add_link(
            response1, "https://www.redhat.com", "Red Hat Webpage"
        )
        assert response2.status_code == 201

    @pytest.mark.vcr
    def test_update_link(self, jira_token, jira_email, monkeypatch):
        """
        Test that service is able to update remote links in Jira issues.
        """
        url = "https://www.redhat.com"
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)

        issue_key = taskman.create_or_update_task(flaw=flaw)
        assert issue_key == "OSIM-16568"

        response = taskman.add_link(issue_key, url, "Red Hat Webpage")

        link_id = response.data["id"]
        response = taskman.update_link(issue_key, link_id, url, "Red Hat Homepage")
        assert response.status_code == 204

    def test_long_summary(self, jira_token, jira_email):
        """
        Test that the summary in a Jira task is trimmed when the flaw's cve_id
        and title exceed the maximum allowed length of 255 characters.
        """
        flaw = FlawFactory(
            cve_id="CVE-2024-7142",
            title="On Arista CloudVision Appliance (CVA) affected releases running on appliances that support "
            "hardware disk encryption (DCA-350E-CV only), the disk encryption might not be successfully "
            "performed. This results in the disks remaining unsecured and data on them",
        )
        AffectFactory(flaw=flaw)
        assert len(flaw.cve_id) + len(flaw.title) > JIRA_SUMMARY_MAX_LENGTH

        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)
        issue_data = taskman._generate_task_data(flaw)
        assert len(issue_data["fields"]["summary"]) == JIRA_SUMMARY_MAX_LENGTH
        assert issue_data["fields"]["summary"].endswith("...")

    def test_flaw_embargo(self, jira_token, jira_email):
        """
        Test that a just-created flaw has the right security level
        name depending on if it's embargoed or not.
        """
        flaw = FlawFactory(
            embargoed=True,
            cve_id="CVE-2024-7142",
            title="On Arista CloudVision Appliance (CVA) affected releases running on appliances that support "
            "hardware disk encryption (DCA-350E-CV only), the disk encryption might not be successfully "
            "performed. This results in the disks remaining unsecured and data on them",
        )

        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)
        issue_data = taskman._generate_task_data(flaw)
        assert (
            issue_data["fields"]["security"]["name"] == JIRA_EMBARGO_SECURITY_LEVEL_NAME
        )

        flaw = FlawFactory(
            embargoed=False,
            cve_id="CVE-2024-7143",
            title="On Arista CloudVision Appliance (CVA) affected releases running on appliances that support "
            "hardware disk encryption (DCA-350E-CV only), the disk encryption might not be successfully "
            "performed. This results in the disks remaining unsecured and data on them",
        )

        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)
        issue_data = taskman._generate_task_data(flaw)
        assert issue_data["fields"]["security"] is None

    def test_bu_contributor_ids(self, jira_token, jira_email, monkeypatch):
        """
        Test the BU label owners are collected without duplicates and
        empty owners and that owners unknown to Jira are skipped.
        """

        def fake_cloud_id(kerberos_id):
            if kerberos_id == "unknown":
                raise JiraUserMappingException("no such user")
            return f"cloud-{kerberos_id}"

        monkeypatch.setattr(
            Profile, "kerberos_to_cloud_id", staticmethod(fake_cloud_id)
        )
        flaw = FlawFactory()
        owners = {
            "team_a": "abc@redhat.com",
            "team_b": "xyz",
            "team_c": "abc",
            "team_d": "",
            "team_e": "unknown",
        }
        for name, owner in owners.items():
            BULabelDefinition.objects.create(name=name)
            BULabel.objects.create(flaw=flaw, name=name, contributor=owner)
        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)
        assert taskman._get_bu_contributor_ids(flaw) == ["cloud-abc", "cloud-xyz"]

    def test_bu_contributor_ids_connection_failure(
        self, jira_token, jira_email, monkeypatch
    ):
        """
        Test a Jira connection failure is not treated as an unknown user
        so that the sync can be retried instead of losing the owner.
        """

        def fake_cloud_id(kerberos_id):
            raise JiraConnectionException("no connection")

        monkeypatch.setattr(
            Profile, "kerberos_to_cloud_id", staticmethod(fake_cloud_id)
        )
        flaw = FlawFactory()
        BULabelDefinition.objects.create(name="team_a")
        BULabel.objects.create(flaw=flaw, name="team_a", contributor="bob")
        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)
        with pytest.raises(JiraConnectionException):
            taskman._get_bu_contributor_ids(flaw)

    def test_contributors_field(self, jira_token, jira_email, monkeypatch):
        """
        Test the BU label owners are sent as the Jira Contributors field
        and that the field is left out when its id is not configured.
        """
        monkeypatch.setattr(
            Profile,
            "kerberos_to_cloud_id",
            staticmethod(lambda kerberos_id: f"cloud-{kerberos_id}"),
        )
        flaw = FlawFactory()
        BULabelDefinition.objects.create(name="team_a")
        BULabel.objects.create(flaw=flaw, name="team_a", contributor="bob")
        taskman = JiraTaskmanQuerier(token=jira_token, email=jira_email)
        monkeypatch.setattr(
            "apps.taskman.service.JIRA_TASKMAN_CONTRIBUTORS_FIELD_ID", "customfield_1"
        )
        data = taskman._generate_task_data(flaw)
        assert data["fields"]["customfield_1"] == [{"accountId": "cloud-bob"}]
        monkeypatch.setattr(
            "apps.taskman.service.JIRA_TASKMAN_CONTRIBUTORS_FIELD_ID", ""
        )
        data = taskman._generate_task_data(flaw)
        assert "customfield_1" not in data["fields"]
