import uuid

import pytest

from apps.workflows.workflow import WorkflowModel
from osidb.models import Flaw, FlawCollaborator, FlawLabel, FlawSource, Impact

from .factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestSearch:
    def test_search_flaws_on_create(self, auth_client, test_api_uri):
        """Test Flaw text-search vectors for each text field are created when Flaw is inserted"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="CVE-2022-1234 kernel: TITLE",
            comment_zero="COMMENT_ZERO",
            cve_description="CVE_DESCRIPTION",
            statement="STATEMENT",
            embargoed=False,
        )

        response = auth_client().get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?search=comment_zero")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?search=cve_description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?search=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

    def test_search_flaws_on_update(
        self,
        auth_client,
        test_api_uri,
        good_cve_id,
        datetime_with_tz,
    ):
        """Test Flaw text-search vectors are updated when corresponding fields are updated"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        acl_read = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]
        acl_write = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]
        meta_attr = {"test": 1}

        flaw = Flaw(
            cve_id=good_cve_id,
            cwe_id="CWE-1",
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            title="TITLE",
            comment_zero="COMMENT_ZERO",
            impact=Impact.CRITICAL,
            components=["kernel"],
            source=FlawSource.INTERNET,
            cve_description="CVE_DESCRIPTION",
            statement="STATEMENT",
            acl_read=acl_read,
            acl_write=acl_write,
            # META
            meta_attr=meta_attr,
        )

        assert flaw.save() is None
        AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.title = "NOMORETITLE"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client().get(f"{test_api_uri}/flaws?search=comment_zero")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.comment_zero = "NOMORECOMMENT_ZERO"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=comment_zero")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client().get(f"{test_api_uri}/flaws?search=cve_description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.cve_description = "NOMORECVEDESCRIPTION"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=cve_description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client().get(f"{test_api_uri}/flaws?search=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.statement = "NOMORESTATEMENT"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

    def test_search_flaws_rankings(self, auth_client, test_api_uri):
        """Test Flaw search results are ranked based on relevance, weighted based on which field matched"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="CVE-2022-1234 kernel: words",
            comment_zero="words",
            cve_description="words",
            statement="words",
            embargoed=False,
        )

        FlawFactory(embargoed=False, title="CVE-2022-1234 kernel: words")

        FlawFactory(comment_zero="words", embargoed=False)

        FlawFactory(cve_description="words")

        FlawFactory(statement="words")

        response = auth_client().get(
            f"{test_api_uri}/flaws?search=word"  # Full-text search for "word" in any text field
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["count"] == 5
        )  # 5 Flaws have "words" in a text field, "word" should match due to stemming
        # First / most relevant match should be the Flaw with "words" in every field (most number of matches)
        assert body["results"][0]["title"] == "CVE-2022-1234 kernel: words"
        assert body["results"][0]["comment_zero"] == "words"
        assert body["results"][0]["cve_description"] == "words"
        assert body["results"][0]["statement"] == "words"

        # Following results are ranked based on what field "word" appears in
        # Matches in title are weighted highest (1.0), followed by comment_zero (0.4), cve_description (0.2), and statement (0.1)
        assert body["results"][1]["title"] == "CVE-2022-1234 kernel: words"
        assert body["results"][2]["comment_zero"] == "words"
        assert body["results"][3]["cve_description"] == "words"
        assert body["results"][4]["statement"] == "words"

    def test_search_flaws_on_particular_columns(self, auth_client, test_api_uri):
        """Test Flaws can be searched based on a specified text column instead of all text columns"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="title",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            team_id=1234,
            owner="example@redhat.com",
            workflow_state="TRIAGE",
        )

        FlawFactory(
            title="other summary",
            comment_zero="this is a flaw",
            cve_description="spooky flaw",
            embargoed=False,
            statement="other",
            team_id=1235,
            owner="example_two@redhat.com",
            workflow_state="NEW",
        )

        # Full-text search only in title column
        response = auth_client().get(f"{test_api_uri}/flaws?title=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?comment_zero=comment_zero")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(
            f"{test_api_uri}/flaws?cve_description=cve_description"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?statement=statement")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?team_id=1234")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?owner=example@redhat.com")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?workflow_state=TRIAGE")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?workflow_state=NEW,TRIAGE")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2

    def test_search_flaws_by_similar_cve(self, auth_client, test_api_uri):
        """Test searching flaws by similar or partial CVEs."""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="title",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0414",
        )
        FlawFactory(
            title="other flaw",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0489",
        )
        FlawFactory(
            title="flaw with different CVE",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2008-0514",
        )

        # Search with partial CVE
        response = auth_client().get(f"{test_api_uri}/flaws?search=CVE-2001-04")
        assert response.status_code == 200
        body = response.json()
        # The third flaw should not be found with this query
        assert body["count"] == 2
        assert body["results"][0]["cve_id"] == "CVE-2001-0414"
        assert body["results"][1]["cve_id"] == "CVE-2001-0489"

        # Search with similar CVE
        response = auth_client().get(f"{test_api_uri}/flaws?search=CVE-2001-0417")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == "CVE-2001-0414"

    def test_search_flaws_by_query(self, auth_client, test_api_uri):
        """Test searching flaws by djangoql query."""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="title",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0414",
        )
        FlawFactory(
            title="other flaw",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0489",
        )
        FlawFactory(
            title="other flaw",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=True,
            statement="statement",
            cve_id="CVE-2001-0494",
        )
        FlawFactory(
            title="flaw with different CVE",
            comment_zero="comment_zero",
            cve_description="cve_description",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2008-0514",
        )

        # Search with djangoql query
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=title startswith "flaw"'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == "CVE-2008-0514"

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=cve_id startswith "CVE-2001" and title = "title"'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == "CVE-2001-0414"

        # Combine djangoql query with search
        response = auth_client().get(
            f'{test_api_uri}/flaws?embargoed=False&order=cve_id&query=cve_id startswith "CVE-2001"'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert body["results"][0]["cve_id"] == "CVE-2001-0414"
        assert body["results"][1]["cve_id"] == "CVE-2001-0489"

    def test_search_flaws_by_labels_query(self, auth_client, test_api_uri):
        """Test searching flaws by labels using djangoql query"""
        label_a = FlawLabel.objects.create(
            name="label_a", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )
        label_b = FlawLabel.objects.create(
            name="label_b", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )
        label_c = FlawLabel.objects.create(
            name="label_c", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        flaw1.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw1.save()
        FlawCollaborator.objects.create(
            flaw=flaw1,
            label=label_a.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        flaw2.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw2.save()
        FlawCollaborator.objects.create(
            flaw=flaw2,
            label=label_a.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )
        FlawCollaborator.objects.create(
            flaw=flaw2,
            label=label_b.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        flaw3 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw3)
        flaw3.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw3.save()
        FlawCollaborator.objects.create(
            flaw=flaw3,
            label=label_a.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )
        FlawCollaborator.objects.create(
            flaw=flaw3,
            label=label_b.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )
        FlawCollaborator.objects.create(
            flaw=flaw3,
            label=label_c.name,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            type=FlawLabel.FlawLabelType.CONTEXT_BASED,
        )

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=flaw_labels in ("label_a")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 3
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw1.cve_id,
            flaw2.cve_id,
            flaw3.cve_id,
        }

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=flaw_labels in ("label_a","label_b")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw2.cve_id,
            flaw3.cve_id,
        }

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=flaw_labels in ("label_a","label_b","label_c")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == flaw3.cve_id

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=flaw_labels in ("label_a","label_c")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == flaw3.cve_id

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=flaw_labels != "label_a"'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0
