import pytest
from rest_framework import status

from osidb.models import (
    AliasLabel,
    BULabel,
    BULabelDefinition,
    CollaboratorLabel,
    CollaboratorLabelDefinition,
    FlawLabelV2,
    ProductFamilyLabel,
    ProductFamilyLabelDefinition,
    WorkflowLabel,
)
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestFlawLabelsV2CRUD:
    """Basic CRUD operations on /api/v2/flaws/{id}/labels"""

    @pytest.fixture(autouse=True)
    def setup(self):
        CollaboratorLabelDefinition.objects.create(name="context-label")
        CollaboratorLabelDefinition.objects.create(name="other-context")
        BULabelDefinition.objects.create(name="bu-label")
        ProductFamilyLabelDefinition.objects.create(name="pf-label")

        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    def test_list_labels(self, auth_client, test_api_v2_uri):
        CollaboratorLabel.objects.create(
            flaw=self.flaw, name="context-label", state="NEW"
        )
        AliasLabel.objects.create(flaw=self.flaw, name="my-alias")

        response = auth_client().get(f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels")

        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 2

    def test_get_label_detail(self, auth_client, test_api_v2_uri):
        label = CollaboratorLabel.objects.create(
            flaw=self.flaw, name="context-label", state="NEW", contributor="user1"
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["uuid"] == str(label.uuid)
        assert data["name"] == "context-label"
        assert data["type"] == "context_based"
        assert data["state"] == "NEW"
        assert data["contributor"] == "user1"

    def test_create_context_label(self, auth_client, test_api_v2_uri):
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {
                "name": "context-label",
                "type": "context_based",
                "state": "NEW",
                "contributor": "skynet",
            },
        )

        assert response.status_code == status.HTTP_201_CREATED
        label = CollaboratorLabel.objects.first()
        assert label.name == "context-label"
        assert label.state == "NEW"
        assert label.contributor == "skynet"

    def test_create_alias_label(self, auth_client, test_api_v2_uri):
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "incident-123", "type": "alias"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert AliasLabel.objects.filter(name="incident-123").exists()

    def test_create_bu_label(self, auth_client, test_api_v2_uri):
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "bu-label", "type": "bu", "state": "NEW"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["type"] == "bu"
        assert data["state"] == "NEW"

    def test_create_workflow_label(self, auth_client, test_api_v2_uri):
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "approved", "type": "workflow"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert WorkflowLabel.objects.filter(name="approved").exists()

    def test_update_context_label(self, auth_client, test_api_v2_uri):
        label = CollaboratorLabel.objects.create(
            flaw=self.flaw, name="context-label", state="NEW"
        )

        response = auth_client().put(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}",
            {"name": "context-label", "state": "DONE", "contributor": "skynet"},
        )

        assert response.status_code == status.HTTP_200_OK
        label.refresh_from_db()
        assert label.state == "DONE"
        assert label.contributor == "skynet"

    def test_update_bu_label(self, auth_client, test_api_v2_uri):
        label = BULabel.objects.create(flaw=self.flaw, name="bu-label", state="NEW")

        response = auth_client().put(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}",
            {"name": "bu-label", "state": "SKIP", "contributor": "user"},
        )

        assert response.status_code == status.HTTP_200_OK
        label.refresh_from_db()
        assert label.state == "SKIP"
        assert label.contributor == "user"

    def test_delete_context_label(self, auth_client, test_api_v2_uri):
        label = CollaboratorLabel.objects.create(
            flaw=self.flaw, name="context-label", state="NEW"
        )

        response = auth_client().delete(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not FlawLabelV2.objects.filter(uuid=label.uuid).exists()

    def test_delete_alias_label(self, auth_client, test_api_v2_uri):
        label = AliasLabel.objects.create(flaw=self.flaw, name="my-alias")

        response = auth_client().delete(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not AliasLabel.objects.filter(uuid=label.uuid).exists()

    def test_delete_workflow_label(self, auth_client, test_api_v2_uri):
        label = WorkflowLabel.objects.create(flaw=self.flaw, name="approved")

        response = auth_client().delete(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not WorkflowLabel.objects.filter(uuid=label.uuid).exists()

    def test_delete_product_family_label_blocked(self, auth_client, test_api_v2_uri):
        label = ProductFamilyLabel.objects.create(flaw=self.flaw, name="pf-label")

        response = auth_client().delete(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["name"] == "Product family labels cannot be deleted."
        assert FlawLabelV2.objects.filter(uuid=label.uuid).exists()


class TestFlawLabelsV2ResponseShape:
    """Verify type-specific field inclusion in responses"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    @staticmethod
    def _label_keys(data):
        return {k for k in data if k not in ("dt", "env", "revision", "version")}

    def test_alias_label_minimal_fields(self, auth_client, test_api_v2_uri):
        label = AliasLabel.objects.create(flaw=self.flaw, name="my-alias")

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        data = response.json()
        assert self._label_keys(data) == {"uuid", "name", "type"}
        assert data["type"] == "alias"
        assert "state" not in data
        assert "contributor" not in data
        assert "relevant" not in data

    def test_workflow_label_minimal_fields(self, auth_client, test_api_v2_uri):
        label = WorkflowLabel.objects.create(flaw=self.flaw, name="approved")

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        data = response.json()
        assert self._label_keys(data) == {"uuid", "name", "type"}
        assert data["type"] == "workflow"
        assert "state" not in data

    def test_collaborator_label_full_fields(self, auth_client, test_api_v2_uri):
        CollaboratorLabelDefinition.objects.create(name="collab")
        label = CollaboratorLabel.objects.create(
            flaw=self.flaw, name="collab", state="REQ", contributor="user1"
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        data = response.json()
        assert self._label_keys(data) == {
            "uuid",
            "name",
            "type",
            "state",
            "contributor",
            "relevant",
        }
        assert data["type"] == "context_based"
        assert data["state"] == "REQ"
        assert data["contributor"] == "user1"
        assert data["relevant"] is True

    def test_bu_label_full_fields(self, auth_client, test_api_v2_uri):
        BULabelDefinition.objects.create(name="bu-test")
        label = BULabel.objects.create(
            flaw=self.flaw, name="bu-test", state="DONE", contributor="admin"
        )

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        data = response.json()
        assert self._label_keys(data) == {
            "uuid",
            "name",
            "type",
            "state",
            "contributor",
            "relevant",
        }
        assert data["type"] == "bu"
        assert data["state"] == "DONE"

    def test_product_family_label_relevant_only(self, auth_client, test_api_v2_uri):
        label = ProductFamilyLabel.objects.create(flaw=self.flaw, name="pf-test")

        response = auth_client().get(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}"
        )

        data = response.json()
        assert self._label_keys(data) == {"uuid", "name", "type", "relevant"}
        assert data["type"] == "product_family"
        assert data["relevant"] is True
        assert "state" not in data
        assert "contributor" not in data


class TestFlawLabelsV2Validation:
    """Validation and edge cases"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=self.flaw)

    def test_bu_label_requires_pre_registration(self, auth_client, test_api_v2_uri):
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "unregistered-bu", "type": "bu"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_context_label_requires_pre_registration(
        self, auth_client, test_api_v2_uri
    ):
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "unregistered-context", "type": "context_based"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_product_family_cannot_be_created(self, auth_client, test_api_v2_uri):
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "pf-manual", "type": "product_family"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_duplicate_label_name(self, auth_client, test_api_v2_uri):
        AliasLabel.objects.create(flaw=self.flaw, name="dup-name")

        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "dup-name", "type": "alias"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response.json()["name"][0]

    def test_name_cannot_be_changed(self, auth_client, test_api_v2_uri):
        label = AliasLabel.objects.create(flaw=self.flaw, name="original")

        response = auth_client().put(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}",
            {"name": "changed"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["name"] == "Label name cannot be changed."

    def test_name_max_length(self, auth_client, test_api_v2_uri):
        long_name = "a" * 255

        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": long_name, "type": "alias"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["name"] == long_name

    def test_state_transitions(self, auth_client, test_api_v2_uri):
        CollaboratorLabelDefinition.objects.create(name="stateful")
        label = CollaboratorLabel.objects.create(
            flaw=self.flaw, name="stateful", state="NEW"
        )

        for state_value in ["REQ", "SKIP", "DONE", "NEW"]:
            response = auth_client().put(
                f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}",
                {"name": "stateful", "state": state_value},
            )

            assert response.status_code == status.HTTP_200_OK
            assert response.json()["state"] == state_value
            label.refresh_from_db()
            assert label.state == state_value

    def test_update_alias_ignores_unsupported_fields(
        self, auth_client, test_api_v2_uri
    ):
        """Updating an alias label with state/contributor succeeds but ignores them"""
        label = AliasLabel.objects.create(flaw=self.flaw, name="my-alias")

        response = auth_client().put(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels/{label.uuid}",
            {"name": "my-alias", "state": "DONE", "contributor": "test"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "state" not in data
        assert "contributor" not in data

    def test_multiple_labels_same_type(self, auth_client, test_api_v2_uri):
        response1 = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "alias1", "type": "alias"},
        )
        response2 = auth_client().post(
            f"{test_api_v2_uri}/flaws/{self.flaw.uuid}/labels",
            {"name": "alias2", "type": "alias"},
        )

        assert response1.status_code == status.HTTP_201_CREATED
        assert response2.status_code == status.HTTP_201_CREATED
        assert AliasLabel.objects.filter(flaw=self.flaw).count() == 2
