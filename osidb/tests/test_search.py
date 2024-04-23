import uuid

import pytest

from osidb.models import Flaw, FlawSource, FlawType, Impact

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
            description="DESCRIPTION",
            summary="SUMMARY",
            statement="STATEMENT",
            embargoed=False,
        )

        response = auth_client().get(f"{test_api_uri}/flaws?search=title")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?search=description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?search=summary")
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
            type=FlawType.VULNERABILITY,
            title="TITLE",
            description="DESCRIPTION",
            impact=Impact.CRITICAL,
            components=["kernel"],
            source=FlawSource.INTERNET,
            summary="SUMMARY",
            statement="STATEMENT",
            acl_read=acl_read,
            acl_write=acl_write,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
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

        response = auth_client().get(f"{test_api_uri}/flaws?search=description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.description = "NOMOREDESCRIPTION"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        response = auth_client().get(f"{test_api_uri}/flaws?search=summary")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        flaw.summary = "NOMORESUMMARY"
        assert flaw.save() is None

        response = auth_client().get(f"{test_api_uri}/flaws?search=summary")
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
            description="words",
            summary="words",
            statement="words",
            embargoed=False,
        )

        FlawFactory(embargoed=False, title="CVE-2022-1234 kernel: words")

        FlawFactory(description="words", embargoed=False)

        FlawFactory(summary="words")

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
        assert body["results"][0]["description"] == "words"
        assert body["results"][0]["summary"] == "words"
        assert body["results"][0]["statement"] == "words"

        # Following results are ranked based on what field "word" appears in
        # Matches in title are weighted highest (1.0), followed by description (0.4), summary (0.2), and statement (0.1)
        assert body["results"][1]["title"] == "CVE-2022-1234 kernel: words"
        assert body["results"][2]["description"] == "words"
        assert body["results"][3]["summary"] == "words"
        assert body["results"][4]["statement"] == "words"

    def test_search_flaws_on_particular_columns(self, auth_client, test_api_uri):
        """Test Flaws can be searched based on a specified text column instead of all text columns"""
        response = auth_client().get(f"{test_api_uri}/flaws")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        FlawFactory(
            title="title",
            description="description",
            summary="summary",
            embargoed=False,
            statement="statement",
            team_id=1234,
            owner="example@redhat.com",
            workflow_state="TRIAGE",
        )

        FlawFactory(
            title="other summary",
            description="this is a flaw",
            summary="spooky flaw",
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

        response = auth_client().get(f"{test_api_uri}/flaws?description=description")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1

        response = auth_client().get(f"{test_api_uri}/flaws?summary=summary")
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
            description="description",
            summary="summary",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0414",
        )
        FlawFactory(
            title="other flaw",
            description="description",
            summary="summary",
            embargoed=False,
            statement="statement",
            cve_id="CVE-2001-0489",
        )
        FlawFactory(
            title="flaw with different CVE",
            description="description",
            summary="summary",
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
