import uuid

import pytest

from osidb.models import (
    AliasLabel,
    BULabel,
    BULabelDefinition,
    CollaboratorLabel,
    CollaboratorLabelDefinition,
    Flaw,
    FlawSource,
    Impact,
    ProductFamilyLabel,
)

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
            owner="example@redhat.com",
            workflow_state="TRIAGE",
        )

        FlawFactory(
            title="other summary",
            comment_zero="this is a flaw",
            cve_description="spooky flaw",
            embargoed=False,
            statement="other",
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
        CollaboratorLabelDefinition.objects.create(name="label_a")
        CollaboratorLabelDefinition.objects.create(name="label_b")
        CollaboratorLabelDefinition.objects.create(name="label_c")

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        flaw1.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw1.save()
        CollaboratorLabel.objects.create(
            flaw=flaw1,
            name="label_a",
            state=CollaboratorLabel.State.NEW,
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        flaw2.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw2.save()
        CollaboratorLabel.objects.create(
            flaw=flaw2,
            name="label_a",
            state=CollaboratorLabel.State.NEW,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw2,
            name="label_b",
            state=CollaboratorLabel.State.NEW,
        )

        flaw3 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw3)
        flaw3.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw3.save()
        CollaboratorLabel.objects.create(
            flaw=flaw3,
            name="label_a",
            state=CollaboratorLabel.State.NEW,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw3,
            name="label_b",
            state=CollaboratorLabel.State.NEW,
        )
        CollaboratorLabel.objects.create(
            flaw=flaw3,
            name="label_c",
            state=CollaboratorLabel.State.NEW,
        )

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a")'
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
            f'{test_api_uri}/flaws?query=labels in ("label_a","label_b")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw2.cve_id,
            flaw3.cve_id,
        }

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a","label_b","label_c")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == flaw3.cve_id

        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a","label_c")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert body["results"][0]["cve_id"] == flaw3.cve_id

        response = auth_client().get(f'{test_api_uri}/flaws?query=labels != "label_a"')
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0

        # Repeated operands must not inflate the required label count.
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels in ("label_a","label_a")'
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
            f'{test_api_uri}/flaws?query=labels not in ("label_c","label_c")'
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2
        assert {flaw["cve_id"] for flaw in body["results"]} == {
            flaw1.cve_id,
            flaw2.cve_id,
        }

    def test_search_labels_not_exposed(self, auth_client, test_api_uri):
        """Fields not whitelisted in FLAW_LABEL_PROPERTY_FIELDS stay unreachable via dotted access"""
        FlawFactory(embargoed=False)

        # Note: this must be a name that also doesn't happen to be a real
        # field on Flaw itself. resolve_name()'s fallback for dotted access
        # doesn't treat the flat "labels" field as a relation, so on the 2nd
        # segment it re-checks against Flaw's own fields (e.g. "labels.foo"
        # would wrongly resolve to Flaw.foo if such a field existed). "uuid"
        # is whitelisted precisely to avoid that trap (see FlawLabelUuidField).
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels.nonexistent = "test"'
        )
        assert response.status_code == 400
        assert "Unknown field: nonexistent" in response.json()["detail"]

    def test_search_flaws_by_label_name_and_type(self, auth_client, test_api_uri):
        """
        "labels.name" and "labels.type" are queryable via dotted access, same as
        "labels.contributor"/"labels.state"/"labels.relevant". Unlike those,
        "name" and "type" live on the base FlawLabel rather than a subclass:
        "name" behaves exactly like the bare "labels" field, and "type" maps
        the LabelType enum value (e.g. "context_based") to the polymorphic
        content type of the matching subclass, since it isn't a real column.
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        CollaboratorLabel.objects.create(
            flaw=flaw1, name="collab-a", state=CollaboratorLabel.State.NEW
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        alias_label = AliasLabel.objects.create(flaw=flaw2, name="CVE-1234-ALIAS")

        cases = [
            ('labels.name = "collab-a"', {flaw1.cve_id}),
            ('labels.type = "context_based"', {flaw1.cve_id}),
            ('labels.type = "alias"', {flaw2.cve_id}),
            ('labels.type != "alias"', {flaw1.cve_id}),
            (f'labels.uuid = "{alias_label.uuid}"', {flaw2.cve_id}),
        ]
        for query, expected_cve_ids in cases:
            response = auth_client().get(f"{test_api_uri}/flaws?query={query}")
            assert response.status_code == 200, (query, response.json())
            body = response.json()
            assert {flaw["cve_id"] for flaw in body["results"]} == expected_cve_ids, (
                query,
                body,
            )

        # Values outside the LabelType enum are rejected rather than
        # silently matching nothing.
        response = auth_client().get(
            f'{test_api_uri}/flaws?query=labels.type = "bogus"'
        )
        assert response.status_code == 400

    def test_search_flaws_by_labels_query_operators(self, auth_client, test_api_uri):
        """
        The "labels" DjangoQL field is a StrField, so the UI/schema legally offers
        the full set of string operators (~, !~, startswith, endswith and their
        "not" variants), not just "=", "!=", "in" and "not in".

        FlawLabelsField.get_lookup() routes all of them through the shared
        StrField operator mapping, so each must filter by label name correctly.
        """
        CollaboratorLabelDefinition.objects.create(name="kernel-fix")
        CollaboratorLabelDefinition.objects.create(name="other")

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        CollaboratorLabel.objects.create(
            flaw=flaw1, name="kernel-fix", state=CollaboratorLabel.State.NEW
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        CollaboratorLabel.objects.create(
            flaw=flaw2, name="other", state=CollaboratorLabel.State.NEW
        )

        cases = [
            ('labels ~ "kernel"', {flaw1.cve_id}),
            ('labels !~ "kernel"', {flaw2.cve_id}),
            ('labels startswith "kernel"', {flaw1.cve_id}),
            ('labels not startswith "kernel"', {flaw2.cve_id}),
            ('labels endswith "fix"', {flaw1.cve_id}),
            ('labels not endswith "fix"', {flaw2.cve_id}),
        ]
        for query, expected_cve_ids in cases:
            response = auth_client().get(f"{test_api_uri}/flaws?query={query}")
            assert response.status_code == 200, (query, response.json())
            body = response.json()
            assert {flaw["cve_id"] for flaw in body["results"]} == expected_cve_ids, (
                query,
                body,
            )

    def test_search_flaws_by_label_properties(self, auth_client, test_api_uri):
        """
        Fields that only exist on FlawLabel subclasses (contributor, state, relevant)
        are queryable via DjangoQL through dotted access on the flat "labels"
        field, e.g. "labels.contributor = ...", including their "!=" negation.

        FlawQLSchema.resolve_name() routes these dotted names to
        FlawLabelPropertyField, which OR's the lookup across whichever FlawLabel
        subclasses actually define the property. "labels.name" and
        "labels.type" are covered separately in
        test_search_flaws_by_label_name_and_type; fields not whitelisted at
        all stay unreachable (see test_search_labels_not_exposed).
        """
        CollaboratorLabelDefinition.objects.create(name="collab-a")
        CollaboratorLabelDefinition.objects.create(name="collab-b")

        flaw1 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        CollaboratorLabel.objects.create(
            flaw=flaw1,
            name="collab-a",
            contributor="alice@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )
        # A second matching label on the same flaw, so a query joining
        # through "labels" fans out to multiple rows before dedup.
        CollaboratorLabel.objects.create(
            flaw=flaw1,
            name="collab-b",
            contributor="alice@example.com",
            state=CollaboratorLabel.State.NEW,
            relevant=True,
        )

        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw2)
        CollaboratorLabel.objects.create(
            flaw=flaw2,
            name="collab-a",
            contributor="bob@example.com",
            state=CollaboratorLabel.State.DONE,
            relevant=False,
        )

        # A flaw with no CollaboratorLabel at all, only BULabel and
        # ProductFamilyLabel, so the OR-across-subclasses lookup in
        # FlawLabelPropertyField is actually exercised for those subclasses
        # too, not just CollaboratorLabel.
        BULabelDefinition.objects.create(name="bu-a")
        flaw3 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw3)
        BULabel.objects.create(
            flaw=flaw3,
            name="bu-a",
            contributor="carol@example.com",
            state=BULabel.State.REQ,
            relevant=True,
        )
        ProductFamilyLabel.objects.create(flaw=flaw3, name="pf-a", relevant=True)

        cases = [
            ('labels.contributor = "alice@example.com"', {flaw1.cve_id}),
            ('labels.contributor = "bob@example.com"', {flaw2.cve_id}),
            # BULabel-only flaw: proves the "bulabel" branch of the OR works.
            ('labels.contributor = "carol@example.com"', {flaw3.cve_id}),
            ('labels.state = "DONE"', {flaw2.cve_id}),
            ('labels.state = "REQ"', {flaw3.cve_id}),
            # flaw3 is relevant via its BULabel/ProductFamilyLabel rows.
            ("labels.relevant = True", {flaw1.cve_id, flaw3.cve_id}),
            ("labels.relevant = False", {flaw2.cve_id}),
            # "!=" exercises the invert branch of
            # FlawLabelPropertyField.get_lookup(). flaw3 has no
            # CollaboratorLabel/BULabel contributor/state equal to the
            # excluded value, so it satisfies these negations too.
            ('labels.contributor != "alice@example.com"', {flaw2.cve_id, flaw3.cve_id}),
            ('labels.state != "DONE"', {flaw1.cve_id, flaw3.cve_id}),
            ("labels.relevant != True", {flaw2.cve_id}),
        ]
        for query, expected_cve_ids in cases:
            response = auth_client().get(f"{test_api_uri}/flaws?query={query}")
            assert response.status_code == 200, (query, response.json())
            body = response.json()
            assert {flaw["cve_id"] for flaw in body["results"]} == expected_cve_ids, (
                query,
                body,
            )
            # flaw1 has two matching labels for some of these queries; make
            # sure the fan-out join is deduplicated before pagination.
            assert body["count"] == len(expected_cve_ids), (query, body)

    def test_search_websearch_exclusion(self, auth_client, test_api_uri):
        """websearch_to_tsquery supports -exclusion, verify it works after query refactor."""
        flaw = FlawFactory(
            title="kernel buffer overflow",
            embargoed=False,
        )
        flaw.refresh_from_db()
        assert flaw.search_vector is not None, "DB trigger must populate search_vector"
        FlawFactory(
            title="userspace buffer overflow",
            embargoed=False,
        )

        response = auth_client().get(
            f"{test_api_uri}/flaws?search=buffer overflow -kernel"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        assert "userspace" in body["results"][0]["title"]

    def test_search_fts_no_match_returns_empty(self, auth_client, test_api_uri):
        """Verify no false positives from either FTS or trigram path."""
        FlawFactory(title="something else entirely", embargoed=False)

        response = auth_client().get(
            f"{test_api_uri}/flaws?search=nonexistent xyzzy zzzzz"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 0

    def test_search_trigram_partial_cve(self, auth_client, test_api_uri):
        """A partial CVE-ID matches via trigram similarity but not unrelated CVEs."""
        FlawFactory(
            title="Apache Traffic Server vulnerability",
            cve_id="CVE-2024-99999",
            embargoed=False,
        )
        FlawFactory(
            title="unrelated flaw",
            cve_id="CVE-2024-12345",
            embargoed=False,
        )

        response = auth_client().get(f"{test_api_uri}/flaws?search=CVE-2024-1234")
        assert response.status_code == 200
        cve_ids = [r["cve_id"] for r in response.json()["results"]]
        assert "CVE-2024-12345" in cve_ids
        assert "CVE-2024-99999" not in cve_ids

    def test_search_helper_rejects_model_without_search_vector(self):
        """search_helper raises ValueError when called with falsy field_names on a non-Flaw model."""
        from osidb.filters import search_helper
        from osidb.models import Affect

        with pytest.raises(ValueError, match="has no search_vector column"):
            search_helper(Affect.objects.get_queryset(), (), "kernel")
