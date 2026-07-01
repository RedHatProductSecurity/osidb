import pytest
from rest_framework import status

from osidb.models import (
    AliasLabel,
    BULabel,
    BULabelDefinition,
    CollaboratorLabel,
    CollaboratorLabelDefinition,
    Flaw,
    FlawLabelV2,
    ProductFamilyLabel,
    ProductFamilyLabelDefinition,
    WorkflowLabel,
)
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestEndpointsFlawsLabels:
    """Tests specific to /flaws/.../labels endpoint"""

    @pytest.fixture(autouse=True)
    def setup(self):
        CollaboratorLabelDefinition.objects.create(name="test_context")
        CollaboratorLabelDefinition.objects.create(name="other_context")
        ProductFamilyLabelDefinition.objects.create(name="test_product")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        flaw.workflow_state = "PRE_SECONDARY_ASSESSMENT"
        flaw.save()

    def test_get_labels(self, auth_client, test_api_uri):
        response = auth_client().get(f"{test_api_uri}/labels")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["results"] == [
            {"name": "test_context", "type": "context_based"},
            {"name": "other_context", "type": "context_based"},
            {"name": "test_product", "type": "product_family"},
        ]

    def test_get_flaw_labels(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()
        label = CollaboratorLabel.objects.create(
            name="test_context",
            flaw=flaw,
            state=CollaboratorLabel.State.NEW,
        )

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}/labels")

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["results"] == [
            {
                "uuid": f"{label.uuid}",
                "label": "test_context",
                "state": "NEW",
                "contributor": "",
                "type": "context_based",
                "relevant": True,
            }
        ]

    def test_create_context_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "test_context", "state": "NEW", "contributor": "skynet"},
        )

        assert response.status_code == status.HTTP_201_CREATED

        label = CollaboratorLabel.objects.first()

        assert label.name == "test_context"
        assert label.type == "context_based"
        assert label.state == CollaboratorLabel.State.NEW
        assert label.contributor == "skynet"

    def test_create_product_label(self, auth_client, test_api_uri):
        """Product family labels cannot be manually created via API.
        With explicit type=product_family, it's rejected by the serializer choices.
        Without type (defaults to context_based), it fails pre-registration validation.
        """
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "test_product", "state": "NEW", "contributor": "skynet"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_update_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()

        label = CollaboratorLabel.objects.create(
            name="test_context",
            flaw=flaw,
            state=CollaboratorLabel.State.NEW,
        )

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{label.uuid}",
            {"state": "SKIP", "contributor": "skynet", "label": "test_context"},
        )
        label.refresh_from_db()

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["state"] == CollaboratorLabel.State.SKIP
        assert response.json()["contributor"] == "skynet"
        assert label.state == CollaboratorLabel.State.SKIP
        assert label.contributor == "skynet"

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{label.uuid}",
            {"state": "SKIP", "contributor": "skynet", "label": "other_context"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["label"] == "Label name cannot be changed."

    def test_delete_context_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()
        label = CollaboratorLabel.objects.create(
            name="test_context",
            flaw=flaw,
            state=CollaboratorLabel.State.NEW,
        )

        response = auth_client().delete(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert FlawLabelV2.objects.count() == 0

    def test_delete_product_label(self, auth_client, test_api_uri):
        flaw = Flaw.objects.first()
        label = ProductFamilyLabel.objects.create(
            name="test_product",
            flaw=flaw,
        )
        response = auth_client().delete(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["label"] == "Product family labels cannot be deleted."
        assert FlawLabelV2.objects.count() == 1

    def test_create_alias_label(self, auth_client, test_api_uri):
        """Test creating an alias label with free-form text (no pre-definition needed)"""
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {
                "label": "my-custom-alias-name",
                "type": "alias",
                "state": "NEW",
                "contributor": "test-user",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED

        alias = AliasLabel.objects.first()
        assert alias.name == "my-custom-alias-name"
        assert alias.type == "alias"

    def test_create_alias_label_any_text(self, auth_client, test_api_uri):
        """Test that alias labels can be any free-form text"""
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "incident-12345", "type": "alias", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert AliasLabel.objects.filter(name="incident-12345").exists()

        # Test that alias labels can be set in other workflow state
        flaw_workflow = FlawFactory(embargoed=False)
        flaw_workflow.workflow_state = "TRIAGE"
        flaw_workflow.save()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw_workflow.uuid}/labels",
            {"label": "incident-12346", "type": "alias", "state": "NEW"},
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert AliasLabel.objects.filter(name="incident-12346").exists()

        flaw_workflow = FlawFactory(embargoed=False)
        flaw_workflow.workflow_state = "SECONDARY_ASSESSMENT"
        flaw_workflow.save()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw_workflow.uuid}/labels",
            {"label": "incident-12347", "type": "alias", "state": "NEW"},
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert AliasLabel.objects.filter(name="incident-12347").exists()

    def test_delete_alias_label(self, auth_client, test_api_uri):
        """Test that alias labels can be deleted like context-based labels"""
        flaw = Flaw.objects.first()
        label = AliasLabel.objects.create(
            name="my-alias",
            flaw=flaw,
        )

        response = auth_client().delete(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not AliasLabel.objects.filter(uuid=label.uuid).exists()

    def test_update_alias_label_state(self, auth_client, test_api_uri):
        """Test updating an alias label - state/contributor are silently ignored"""
        flaw = Flaw.objects.first()
        label = AliasLabel.objects.create(
            name="my-alias",
            flaw=flaw,
        )

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels/{label.uuid}",
            {"state": "DONE", "label": "my-alias", "contributor": "test"},
        )

        assert response.status_code == status.HTTP_200_OK

    def test_create_duplicate_alias_label(self, auth_client, test_api_uri):
        """Test creating a duplicate alias label"""
        flaw = Flaw.objects.first()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "my-alias", "type": "alias", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert AliasLabel.objects.filter(name="my-alias").exists()

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "my-alias", "type": "alias", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["label"][0] == "Label 'my-alias' already exists."

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "test_context", "type": "context_based", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_201_CREATED

        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/labels",
            {"label": "test_context", "type": "alias", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["label"][0] == "Label 'test_context' already exists."


class TestWorkflowLabels:
    """Tests for WORKFLOW label type - comprehensive coverage"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    def test_create_workflow_label_via_api(self, auth_client, test_api_uri):
        """Test creating a workflow label through API"""
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "approved",
                "type": "workflow",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        assert data["state"] == "NEW"
        assert data["relevant"] is True
        assert data["type"] == "workflow"

        # Verify in database
        label = WorkflowLabel.objects.get(uuid=data["uuid"])
        assert label.name == "approved"

    def test_workflow_label_ignores_state_parameter(self, auth_client, test_api_uri):
        """Test that workflow labels ignore provided state"""
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "manual-triage",
                "type": "workflow",
                "state": "SKIP",  # Should be ignored
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        assert data["state"] == "NEW"

    def test_workflow_label_no_preregistration_required(
        self, auth_client, test_api_uri
    ):
        """Test that workflow labels don't need pre-registration"""
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "custom-workflow-label",
                "type": "workflow",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert WorkflowLabel.objects.filter(name="custom-workflow-label").exists()

    def test_update_workflow_label_contributor(self, auth_client, test_api_uri):
        """Test that workflow label updates are accepted (contributor is silently ignored)"""
        label = WorkflowLabel.objects.create(
            flaw=self.flaw,
            name="rejected",
        )

        response = auth_client().put(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}",
            {
                "label": "rejected",
                "state": "DONE",
                "contributor": "test-user",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["state"] == "NEW"

    def test_delete_workflow_label(self, auth_client, test_api_uri):
        """Test that workflow labels can be deleted"""
        label = WorkflowLabel.objects.create(
            flaw=self.flaw,
            name="approved",
        )

        response = auth_client().delete(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not WorkflowLabel.objects.filter(uuid=label.uuid).exists()


class TestBULabels:
    """Tests for BU (Business Unit) label type"""

    @pytest.fixture(autouse=True)
    def setup(self):
        BULabelDefinition.objects.create(name="test_bu_label")

        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    def test_create_bu_label_via_api(self, auth_client, test_api_uri):
        """Test creating a BU label through API"""
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "test_bu_label",
                "type": "bu",
                "state": "NEW",
                "contributor": "test-user",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["type"] == "bu"
        assert data["label"] == "test_bu_label"

    def test_create_bu_label_without_definition_fails(self, auth_client, test_api_uri):
        """Test that BU labels require pre-registration in BULabelDefinition"""
        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": "undefined_bu_label",
                "type": "bu",
                "state": "NEW",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_delete_bu_label(self, auth_client, test_api_uri):
        """Test that BU labels can be deleted like context-based labels"""
        label = BULabel.objects.create(
            flaw=self.flaw,
            name="test_bu_label",
            state=BULabel.State.NEW,
        )

        response = auth_client().delete(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not BULabel.objects.filter(uuid=label.uuid).exists()

    def test_update_bu_label(self, auth_client, test_api_uri):
        """Test updating BU label state and contributor"""
        label = BULabel.objects.create(
            flaw=self.flaw,
            name="test_bu_label",
            state=BULabel.State.NEW,
        )

        response = auth_client().put(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}",
            {
                "label": "test_bu_label",
                "state": "DONE",
                "contributor": "updated-user",
            },
        )

        assert response.status_code == status.HTTP_200_OK
        label.refresh_from_db()
        assert label.state == BULabel.State.DONE
        assert label.contributor == "updated-user"


class TestLabelSerialization:
    """Tests for label serialization in flaw responses"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

        # Create labels of different types
        CollaboratorLabelDefinition.objects.create(name="context-label")
        CollaboratorLabel.objects.create(
            flaw=self.flaw,
            name="context-label",
            state=CollaboratorLabel.State.NEW,
            contributor="user1",
        )
        WorkflowLabel.objects.create(
            flaw=self.flaw,
            name="workflow-label",
        )
        AliasLabel.objects.create(
            flaw=self.flaw,
            name="alias-label",
        )

    def test_labels_in_flaw_detail_response(self, auth_client, test_api_uri):
        """Test that labels are serialized in flaw detail GET"""
        response = auth_client().get(f"{test_api_uri}/flaws/{self.flaw.uuid}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "labels" in data
        assert len(data["labels"]) == 3

        # Verify all label types are present
        label_types = {label["type"] for label in data["labels"]}
        assert "context_based" in label_types
        assert "workflow" in label_types
        assert "alias" in label_types

    def test_labels_in_flaw_list_response(self, auth_client, test_api_uri):
        """Test that labels are serialized in flaw list GET"""
        response = auth_client().get(f"{test_api_uri}/flaws")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Find our flaw in the list
        flaw_data = next(
            (f for f in data["results"] if f["uuid"] == str(self.flaw.uuid)), None
        )

        assert flaw_data is not None
        assert "labels" in flaw_data
        assert len(flaw_data["labels"]) == 3

    def test_label_fields_in_response(self, auth_client, test_api_uri):
        """Test that all expected label fields are present"""
        response = auth_client().get(f"{test_api_uri}/flaws/{self.flaw.uuid}")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        context_label = next(
            lb for lb in data["labels"] if lb["type"] == "context_based"
        )

        # Verify all fields present
        assert "uuid" in context_label
        assert "label" in context_label
        assert "type" in context_label
        assert "state" in context_label
        assert "contributor" in context_label
        assert "relevant" in context_label

        assert context_label["label"] == "context-label"
        assert context_label["state"] == "NEW"
        assert context_label["contributor"] == "user1"
        assert context_label["relevant"] is True


class TestLabelValidation:
    """Tests for label validation and edge cases"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    def test_create_label_with_max_length_name(self, auth_client, test_api_uri):
        """Test creating label with 255 character name (max allowed)"""
        long_name = "a" * 255

        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": long_name,
                "type": "alias",
                "state": "NEW",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["label"] == long_name

    def test_create_label_with_special_characters(self, auth_client, test_api_uri):
        """Test creating label with special characters"""
        special_name = "label-with_special.chars@123"

        response = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "label": special_name,
                "type": "alias",
                "state": "NEW",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["label"] == special_name

    def test_label_state_transitions(self, auth_client, test_api_uri):
        """Test all valid state transitions on a label type that supports state"""
        CollaboratorLabelDefinition.objects.create(name="test-label")
        label = CollaboratorLabel.objects.create(
            flaw=self.flaw,
            name="test-label",
            state=CollaboratorLabel.State.NEW,
        )

        states = ["REQ", "SKIP", "DONE", "NEW"]

        for state_value in states:
            response = auth_client().put(
                f"{test_api_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}",
                {
                    "label": "test-label",
                    "state": state_value,
                    "contributor": "test",
                },
            )

            assert response.status_code == status.HTTP_200_OK
            assert response.json()["state"] == state_value

            label.refresh_from_db()
            assert label.state == state_value

    def test_multiple_labels_same_type_different_names(self, auth_client, test_api_uri):
        """Test that a flaw can have multiple labels of the same type"""
        response1 = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {"label": "alias1", "type": "alias", "state": "NEW"},
        )

        response2 = auth_client().post(
            f"{test_api_uri}/flaws/{self.flaw.uuid}/labels",
            {"label": "alias2", "type": "alias", "state": "NEW"},
        )

        assert response1.status_code == status.HTTP_201_CREATED
        assert response2.status_code == status.HTTP_201_CREATED

        # Verify both exist
        assert AliasLabel.objects.filter(flaw=self.flaw).count() == 2

    def test_label_persists_across_flaw_updates(self):
        """Test that labels persist when flaw is updated (model level)"""
        label = AliasLabel.objects.create(
            flaw=self.flaw,
            name="persistent-label",
        )

        # Update the flaw directly (model level)
        self.flaw.title = "Updated Title"
        self.flaw.save()

        # Verify label still exists
        assert AliasLabel.objects.filter(uuid=label.uuid).exists()
        label.refresh_from_db()
        assert label.name == "persistent-label"
        assert label.flaw == self.flaw


class TestLabelFiltering:
    """Tests for filtering flaws by labels"""

    @pytest.fixture(autouse=True)
    def setup(self):
        # Create flaws with different labels
        self.flaw1 = FlawFactory(embargoed=False, cve_id="CVE-2024-0001")
        AffectFactory(flaw=self.flaw1)
        AliasLabel.objects.create(
            flaw=self.flaw1,
            name="critical-bug",
        )

        self.flaw2 = FlawFactory(embargoed=False, cve_id="CVE-2024-0002")
        AffectFactory(flaw=self.flaw2)
        WorkflowLabel.objects.create(
            flaw=self.flaw2,
            name="approved",
        )

        self.flaw3 = FlawFactory(embargoed=False, cve_id="CVE-2024-0003")
        AffectFactory(flaw=self.flaw3)
        # No labels

    def test_count_labels_in_response(self, auth_client, test_api_uri):
        """Test that label counts are correct for each flaw"""
        response = auth_client().get(f"{test_api_uri}/flaws")

        assert response.status_code == status.HTTP_200_OK

        flaws_by_cve = {
            f["cve_id"]: f
            for f in response.json()["results"]
            if f["cve_id"] in ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
        }

        assert len(flaws_by_cve["CVE-2024-0001"]["labels"]) == 1
        assert len(flaws_by_cve["CVE-2024-0002"]["labels"]) == 1
        assert len(flaws_by_cve["CVE-2024-0003"]["labels"]) == 0
