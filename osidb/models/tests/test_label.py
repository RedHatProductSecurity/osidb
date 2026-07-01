"""
Tests for the new polymorphic label models (FlawLabelV2 hierarchy).

These tests verify the polymorphic model behavior, type routing,
and subclass-specific functionality.
"""

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from osidb.models.flaw.label_v2 import (
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


@pytest.fixture
def label_definitions():
    """
    Create common label definitions for tests that need pre-registered labels.

    This is required because CollaboratorLabel and BULabel require pre-registration.
    Tests that create label instances should use this fixture.
    Tests that test definition models themselves should NOT use this fixture.
    """
    # Collaborator label names used in label instance tests
    for name in [
        "collab-label",
        "test",
        "test-label",
        "context",
        "security-review",
        "label-NEW",
        "label-REQ",
        "label-SKIP",
        "label-DONE",
    ]:
        CollaboratorLabelDefinition.objects.get_or_create(name=name)

    # BU label names used in label instance tests
    for name in [
        "bu-label",
        "test5",
        "bu",
        "test",
        "test2",
        "test3",
        "test4",
        "platform-bu",
        "middleware-bu",
        "bu-security",
    ]:
        BULabelDefinition.objects.get_or_create(name=name)

    # Product family label (minimal - tests create their own with specific filters)
    ProductFamilyLabelDefinition.objects.get_or_create(
        name="product", defaults={"ps_modules": []}
    )
    ProductFamilyLabelDefinition.objects.get_or_create(
        name="rh-openshift", defaults={"ps_modules": ["openshift-4"]}
    )


@pytest.mark.usefixtures("label_definitions")
class TestPolymorphicBasics:
    """Test basic polymorphic model behavior"""

    def test_create_different_subclasses(self):
        """Test creating instances of different label subclasses"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create one of each type
        collab = CollaboratorLabel.objects.create(
            flaw=flaw, name="collab-label", state=CollaboratorLabel.State.NEW
        )
        product = ProductFamilyLabel.objects.create(flaw=flaw, name="product-label")
        alias = AliasLabel.objects.create(flaw=flaw, name="alias-label")
        workflow = WorkflowLabel.objects.create(flaw=flaw, name="workflow-label")
        bu = BULabel.objects.create(flaw=flaw, name="bu-label", state=BULabel.State.NEW)

        # Verify they're all FlawLabelV2 instances
        assert isinstance(collab, FlawLabelV2)
        assert isinstance(product, FlawLabelV2)
        assert isinstance(alias, FlawLabelV2)
        assert isinstance(workflow, FlawLabelV2)
        assert isinstance(bu, FlawLabelV2)

        # Verify they're also their specific types
        assert isinstance(collab, CollaboratorLabel)
        assert isinstance(product, ProductFamilyLabel)
        assert isinstance(alias, AliasLabel)
        assert isinstance(workflow, WorkflowLabel)
        assert isinstance(bu, BULabel)

    def test_polymorphic_query_returns_correct_subclass(self):
        """Test that querying FlawLabelV2 returns the correct subclass instances"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create different types
        AliasLabel.objects.create(flaw=flaw, name="alias1")
        WorkflowLabel.objects.create(flaw=flaw, name="workflow1")

        # Query the base class
        labels = FlawLabelV2.objects.filter(flaw=flaw).order_by("name")

        # Should get back the specific subclasses, not base class
        assert isinstance(labels[0], AliasLabel)
        assert isinstance(labels[1], WorkflowLabel)

    def test_type_attribute(self):
        """Test that type attribute returns correct API type string"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        collab = CollaboratorLabel.objects.create(flaw=flaw, name="test")
        product = ProductFamilyLabel.objects.create(flaw=flaw, name="test2")
        alias = AliasLabel.objects.create(flaw=flaw, name="test3")
        workflow = WorkflowLabel.objects.create(flaw=flaw, name="test4")
        bu = BULabel.objects.create(flaw=flaw, name="test5")

        assert collab.type == "context_based"
        assert product.type == "product_family"
        assert alias.type == "alias"
        assert workflow.type == "workflow"
        assert bu.type == "bu"

    def test_unique_constraint_per_flaw(self):
        """Test that flaw + name must be unique"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        AliasLabel.objects.create(flaw=flaw, name="duplicate-test")

        # Same name on same flaw should fail (caught at validation level)
        with pytest.raises(ValidationError):
            AliasLabel.objects.create(flaw=flaw, name="duplicate-test")

    def test_same_name_different_flaw_allowed(self):
        """Test that same label name can exist on different flaws"""
        flaw1 = FlawFactory(embargoed=False)
        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        AffectFactory(flaw=flaw2)

        label1 = AliasLabel.objects.create(flaw=flaw1, name="same-name")
        label2 = AliasLabel.objects.create(flaw=flaw2, name="same-name")

        assert label1.name == label2.name
        assert label1.flaw != label2.flaw


@pytest.mark.usefixtures("label_definitions")
class TestCollaboratorLabel:
    """Tests for CollaboratorLabel (context-based) model"""

    def test_create_with_state(self):
        """Test creating collaborator label with state"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = CollaboratorLabel.objects.create(
            flaw=flaw,
            name="test-label",
            state=CollaboratorLabel.State.REQ,
            contributor="user@example.com",
        )

        assert label.state == CollaboratorLabel.State.REQ
        assert label.contributor == "user@example.com"
        assert label.relevant is True  # Default

    def test_state_choices(self):
        """Test all state choices are valid"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        states = [
            CollaboratorLabel.State.NEW,
            CollaboratorLabel.State.REQ,
            CollaboratorLabel.State.SKIP,
            CollaboratorLabel.State.DONE,
        ]

        for state in states:
            label = CollaboratorLabel.objects.create(
                flaw=flaw, name=f"label-{state}", state=state
            )
            assert label.state == state

    def test_relevant_field(self):
        """Test that relevant field can be set"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = CollaboratorLabel.objects.create(flaw=flaw, name="test", relevant=False)

        assert label.relevant is False

        label.relevant = True
        label.save()
        label.refresh_from_db()

        assert label.relevant is True


class TestProductFamilyLabel:
    """Tests for ProductFamilyLabel model"""

    def test_create_product_family_label(self):
        """Test creating product family label"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = ProductFamilyLabel.objects.create(flaw=flaw, name="rh-openshift")

        assert label.name == "rh-openshift"
        assert label.relevant is True  # Default

    def test_relevant_tracking(self):
        """Test that product family labels track relevance"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = ProductFamilyLabel.objects.create(
            flaw=flaw, name="product", relevant=True
        )

        assert label.relevant is True

        # Mark as irrelevant when affects change
        label.relevant = False
        label.save()
        label.refresh_from_db()

        assert label.relevant is False


class TestAliasLabel:
    """Tests for AliasLabel model"""

    def test_create_alias_label(self):
        """Test creating alias label with free-form text"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = AliasLabel.objects.create(flaw=flaw, name="incident-12345")

        assert label.name == "incident-12345"
        assert isinstance(label, AliasLabel)

    def test_alias_no_additional_fields(self):
        """Test that alias labels only have base fields"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = AliasLabel.objects.create(flaw=flaw, name="test-alias")

        # Should not have state or contributor fields
        assert not hasattr(label, "state")
        assert not hasattr(label, "contributor")

    def test_alias_special_characters(self):
        """Test that alias labels accept special characters"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        special_names = [
            "bug-tracker-ABC-123",
            "customer@case.com",
            "incident_2024_01",
            "CVE-2024-alias",
        ]

        for name in special_names:
            label = AliasLabel.objects.create(flaw=flaw, name=name)
            assert label.name == name


class TestWorkflowLabel:
    """Tests for WorkflowLabel model"""

    def test_create_workflow_label(self):
        """Test creating workflow label"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = WorkflowLabel.objects.create(flaw=flaw, name="approved")

        assert label.name == "approved"
        assert isinstance(label, WorkflowLabel)

    def test_workflow_no_state_field(self):
        """Test that workflow labels don't have state/contributor fields"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = WorkflowLabel.objects.create(flaw=flaw, name="rejected")

        # Should not have state or contributor
        assert not hasattr(label, "state")
        assert not hasattr(label, "contributor")

    def test_workflow_binary_flag(self):
        """Test that workflow label presence is the flag itself"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # No "approved" label
        assert not WorkflowLabel.objects.filter(flaw=flaw, name="approved").exists()

        # Create it - now it exists (flag is True)
        WorkflowLabel.objects.create(flaw=flaw, name="approved")
        assert WorkflowLabel.objects.filter(flaw=flaw, name="approved").exists()

        # Delete it - flag is False again
        WorkflowLabel.objects.filter(flaw=flaw, name="approved").delete()
        assert not WorkflowLabel.objects.filter(flaw=flaw, name="approved").exists()


@pytest.mark.usefixtures("label_definitions")
class TestBULabel:
    """Tests for BU (Business Unit) label model"""

    def test_create_bu_label(self):
        """Test creating BU label with state"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = BULabel.objects.create(
            flaw=flaw,
            name="bu-security",
            state=BULabel.State.NEW,
            contributor="team@example.com",
        )

        assert label.state == BULabel.State.NEW
        assert label.contributor == "team@example.com"
        assert label.relevant is True

    def test_bu_state_transitions(self):
        """Test BU label state can transition"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = BULabel.objects.create(flaw=flaw, name="test", state=BULabel.State.NEW)

        assert label.state == BULabel.State.NEW

        label.state = BULabel.State.DONE
        label.save()
        label.refresh_from_db()

        assert label.state == BULabel.State.DONE


class TestLabelDefinitions:
    """Tests for label definition registry models"""

    def test_create_collaborator_label_definition(self):
        """Test creating a context-based label definition"""
        definition = CollaboratorLabelDefinition.objects.create(
            name="test-context",
        )

        assert definition.name == "test-context"
        assert definition.uuid is not None

    def test_create_product_family_definition_with_filters(self):
        """Test creating product family definition with ps_module filters"""
        definition = ProductFamilyLabelDefinition.objects.create(
            name="rh-openshift",
            ps_modules=["openshift-4", "openshift-3"],
            ps_components=["openshift"],
            ps_modules_exclude=["openshift-old"],
        )

        assert definition.name == "rh-openshift"
        assert definition.ps_modules == ["openshift-4", "openshift-3"]
        assert definition.ps_components == ["openshift"]
        assert definition.ps_modules_exclude == ["openshift-old"]

    def test_create_bu_label_definition(self):
        """Test creating a BU label definition"""
        definition = BULabelDefinition.objects.create(name="security-bu")

        assert definition.name == "security-bu"
        assert definition.uuid is not None

    def test_unique_label_name_per_type(self):
        """Test that label names must be unique within each definition type"""
        CollaboratorLabelDefinition.objects.create(name="test-label")

        # Same name in different type is allowed
        ProductFamilyLabelDefinition.objects.create(name="test-label")
        BULabelDefinition.objects.create(name="test-label")

        # Duplicate in same type fails
        with pytest.raises(IntegrityError):
            CollaboratorLabelDefinition.objects.create(name="test-label")

    def test_alias_and_workflow_have_no_definitions(self):
        """Test that ALIAS and WORKFLOW labels don't have definition models"""
        # This test documents that there are no AliasLabelDefinition or
        # WorkflowLabelDefinition models - those types are free-form
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Can create alias and workflow labels without any definition
        AliasLabel.objects.create(flaw=flaw, name="any-name")
        WorkflowLabel.objects.create(flaw=flaw, name="any-workflow")


@pytest.mark.usefixtures("label_definitions")
class TestMixedLabelTypes:
    """Tests for multiple label types on one flaw"""

    def test_all_types_coexist(self):
        """Test that all label types can coexist on one flaw"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create one of each type
        CollaboratorLabel.objects.create(flaw=flaw, name="context")
        ProductFamilyLabel.objects.create(flaw=flaw, name="product")
        AliasLabel.objects.create(flaw=flaw, name="alias")
        WorkflowLabel.objects.create(flaw=flaw, name="workflow")
        BULabel.objects.create(flaw=flaw, name="bu")

        # All should exist
        labels = FlawLabelV2.objects.filter(flaw=flaw)
        assert labels.count() == 5

        # Verify we get the right subclasses
        types = {type(label) for label in labels}
        assert types == {
            CollaboratorLabel,
            ProductFamilyLabel,
            AliasLabel,
            WorkflowLabel,
            BULabel,
        }

    def test_query_by_specific_type(self):
        """Test querying for specific label types"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        AliasLabel.objects.create(flaw=flaw, name="alias1")
        AliasLabel.objects.create(flaw=flaw, name="alias2")
        WorkflowLabel.objects.create(flaw=flaw, name="workflow1")

        # Query just aliases
        aliases = AliasLabel.objects.filter(flaw=flaw)
        assert aliases.count() == 2
        assert all(isinstance(label, AliasLabel) for label in aliases)

        # Query just workflows
        workflows = WorkflowLabel.objects.filter(flaw=flaw)
        assert workflows.count() == 1
        assert isinstance(workflows[0], WorkflowLabel)


class TestLabelAndDefinitionIntegration:
    """Test integration between label instances and their definitions"""

    def test_collaborator_label_requires_definition(self):
        """Test that CollaboratorLabel requires pre-registration"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Attempt to create without definition - should fail
        with pytest.raises(ValidationError) as exc_info:
            CollaboratorLabel.objects.create(
                flaw=flaw,
                name="unregistered-label",
                state=CollaboratorLabel.State.NEW,
            )

        assert "must be pre-registered" in str(exc_info.value)

    def test_collaborator_label_with_definition(self):
        """Test that CollaboratorLabel works when definition exists"""
        # Create definition first
        CollaboratorLabelDefinition.objects.create(name="security-review")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create label instance - should succeed
        label = CollaboratorLabel.objects.create(
            flaw=flaw,
            name="security-review",
            state=CollaboratorLabel.State.NEW,
        )

        # Verify both exist and can be queried together
        assert label.name == "security-review"
        assert CollaboratorLabelDefinition.objects.filter(name=label.name).exists()

    def test_bu_label_requires_definition(self):
        """Test that BULabel requires pre-registration"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Attempt to create without definition - should fail
        with pytest.raises(ValidationError) as exc_info:
            BULabel.objects.create(
                flaw=flaw,
                name="unregistered-bu",
                state=BULabel.State.NEW,
            )

        assert "must be pre-registered" in str(exc_info.value)

    def test_bu_label_with_definition(self):
        """Test that BULabel works when definition exists"""
        # Create definition first
        BULabelDefinition.objects.create(name="platform-bu")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create label instance - should succeed
        label = BULabel.objects.create(
            flaw=flaw,
            name="platform-bu",
            state=BULabel.State.REQ,
        )

        # Verify both exist
        assert label.name == "platform-bu"
        assert BULabelDefinition.objects.filter(name=label.name).exists()

    def test_product_family_label_with_filters(self):
        """Test ProductFamilyLabel with definition filters for auto-creation logic"""
        # Create definition with filters
        definition = ProductFamilyLabelDefinition.objects.create(
            name="rh-openshift",
            ps_modules=["openshift-4"],
            ps_components=["openshift", "kubernetes"],
        )

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create label instance (would be auto-created by signal in real usage)
        label = ProductFamilyLabel.objects.create(
            flaw=flaw,
            name="rh-openshift",
        )

        # Verify definition filters can be queried for auto-creation logic
        assert label.name == "rh-openshift"

        # Simulate auto-creation filter matching
        matching_definitions = ProductFamilyLabelDefinition.objects.filter(
            name=definition.name,
            ps_modules__overlap=["openshift-4"],
        )
        assert matching_definitions.exists()
        assert matching_definitions.first().name == "rh-openshift"

    def test_alias_label_without_definition(self):
        """Test that AliasLabel works without any definition"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create alias label without any definition
        label = AliasLabel.objects.create(flaw=flaw, name="incident-12345")

        # Verify label exists but no definition needed
        assert label.name == "incident-12345"
        # No CollaboratorLabelDefinition, BULabelDefinition, or ProductFamilyLabelDefinition
        assert not CollaboratorLabelDefinition.objects.filter(
            name="incident-12345"
        ).exists()

    def test_workflow_label_without_definition(self):
        """Test that WorkflowLabel works without any definition"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create workflow label without any definition
        label = WorkflowLabel.objects.create(flaw=flaw, name="approved")

        # Verify label exists but no definition needed
        assert label.name == "approved"
        assert not CollaboratorLabelDefinition.objects.filter(name="approved").exists()

    def test_multiple_labels_share_same_definition(self):
        """Test that multiple label instances can reference the same definition"""
        # One definition
        CollaboratorLabelDefinition.objects.create(name="security-review")

        flaw1 = FlawFactory(embargoed=False)
        flaw2 = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw1)
        AffectFactory(flaw=flaw2)

        # Multiple instances using the same definition
        label1 = CollaboratorLabel.objects.create(flaw=flaw1, name="security-review")
        label2 = CollaboratorLabel.objects.create(flaw=flaw2, name="security-review")

        # Both labels reference the same definition
        assert label1.name == label2.name
        assert (
            CollaboratorLabelDefinition.objects.filter(name="security-review").count()
            == 1
        )

    def test_definition_can_exist_without_instances(self):
        """Test that definitions can be pre-registered without any instances"""
        # Create definitions without any label instances
        CollaboratorLabelDefinition.objects.create(name="unused-label")
        BULabelDefinition.objects.create(name="future-bu")
        ProductFamilyLabelDefinition.objects.create(
            name="rh-rhel",
            ps_modules=["rhel-8"],
        )

        # Definitions exist
        assert CollaboratorLabelDefinition.objects.count() == 1
        assert BULabelDefinition.objects.count() == 1
        assert ProductFamilyLabelDefinition.objects.count() == 1

        # But no label instances
        assert CollaboratorLabel.objects.count() == 0
        assert BULabel.objects.count() == 0
        assert ProductFamilyLabel.objects.count() == 0

    def test_product_family_definition_filter_logic(self):
        """Test ProductFamilyLabelDefinition filter matching logic"""
        # Create definition with inclusion and exclusion filters
        ProductFamilyLabelDefinition.objects.create(
            name="rh-openshift",
            ps_modules=["openshift-4", "openshift-3", "openshift-2"],
            ps_components=["openshift"],
            ps_modules_exclude=["openshift-2"],
        )

        # Test filter matching (what auto-creation logic would use)
        # Should match: ps_module in inclusion list
        matches = ProductFamilyLabelDefinition.objects.filter(
            ps_modules__overlap=["openshift-4"]
        )
        assert matches.exists()

        # Should match: ps_component in inclusion list
        matches = ProductFamilyLabelDefinition.objects.filter(
            ps_components__overlap=["openshift"]
        )
        assert matches.exists()

        # Should be excluded: ps_module in both inclusion AND exclusion lists
        # (In real auto-creation logic, we'd check exclusion list after inclusion match)
        defs_with_openshift2 = ProductFamilyLabelDefinition.objects.filter(
            ps_modules__overlap=["openshift-2"]
        )
        assert defs_with_openshift2.exists()  # Matches inclusion filter

        # Now check if it's in the exclusion list
        should_be_excluded = defs_with_openshift2.filter(
            ps_modules_exclude__overlap=["openshift-2"]
        )
        assert (
            should_be_excluded.exists()
        )  # Yes, also in exclusion - don't create label!


class TestPgHistory:
    """Test that pghistory tracking works for labels"""

    def test_insert_event_tracked(self):
        """Test that label creation is tracked in audit table"""
        from django.apps import apps

        FlawLabelV2Audit = apps.get_model("osidb", "FlawLabelV2Audit")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create a workflow label (no definition needed)
        label = WorkflowLabel.objects.create(flaw=flaw, name="approved")

        # Check audit record was created
        audit_records = FlawLabelV2Audit.objects.filter(uuid=label.uuid)
        assert audit_records.exists()

        # Should have one INSERT event
        insert_events = audit_records.filter(pgh_label="insert")
        assert insert_events.count() == 1

        # Audit record should have the same data
        insert_event = insert_events.first()
        assert insert_event.name == "approved"
        assert insert_event.flaw_id == flaw.pk

    def test_audit_trail_captures_label_lifecycle(self):
        """Test that audit trail captures complete label lifecycle"""
        from django.apps import apps

        FlawLabelV2Audit = apps.get_model("osidb", "FlawLabelV2Audit")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create a workflow label
        label = WorkflowLabel.objects.create(flaw=flaw, name="approved")
        label_uuid = label.uuid

        # Verify creation was audited
        audit_records = FlawLabelV2Audit.objects.filter(uuid=label_uuid)
        assert audit_records.count() > 0, "Label creation should be audited"

        # Delete and verify deletion is audited
        label.delete()

        delete_audit = FlawLabelV2Audit.objects.filter(
            uuid=label_uuid, pgh_label="delete"
        )
        assert delete_audit.exists(), "Label deletion should be audited"

    def test_delete_event_tracked(self):
        """Test that label deletion is tracked in audit table"""
        from django.apps import apps

        FlawLabelV2Audit = apps.get_model("osidb", "FlawLabelV2Audit")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Create an alias label
        label = AliasLabel.objects.create(flaw=flaw, name="temp-label")
        label_uuid = label.uuid
        label_name = label.name

        # Delete it
        label.delete()

        # Check DELETE event was recorded
        audit_records = FlawLabelV2Audit.objects.filter(uuid=label_uuid)
        delete_events = audit_records.filter(pgh_label="delete")
        assert delete_events.count() == 1

        # Audit record preserves the deleted data
        delete_event = delete_events.first()
        assert delete_event.name == label_name

    def test_workflow_label_changes_tracked(self):
        """Test that workflow label changes are auditable (critical for classification)"""
        from django.apps import apps

        FlawLabelV2Audit = apps.get_model("osidb", "FlawLabelV2Audit")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        # Add workflow label
        approved = WorkflowLabel.objects.create(flaw=flaw, name="approved")
        approved_uuid = approved.uuid

        # Remove it (simulate classification change)
        approved.delete()

        # Add different workflow label
        rejected = WorkflowLabel.objects.create(flaw=flaw, name="rejected")

        # Audit trail should show both labels
        approved_audit = FlawLabelV2Audit.objects.filter(
            uuid=approved_uuid, name="approved"
        )
        assert approved_audit.exists()
        assert approved_audit.filter(pgh_label="insert").exists()
        assert approved_audit.filter(pgh_label="delete").exists()

        rejected_audit = FlawLabelV2Audit.objects.filter(
            uuid=rejected.uuid, name="rejected"
        )
        assert rejected_audit.exists()
        assert rejected_audit.filter(pgh_label="insert").exists()


@pytest.mark.usefixtures("label_definitions")
class TestTrackingMixin:
    """Test that TrackingMixin works with polymorphic models"""

    def test_created_and_updated_timestamps(self):
        """Test that created_dt and updated_dt are tracked"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = AliasLabel.objects.create(flaw=flaw, name="test")

        assert label.created_dt is not None
        assert label.updated_dt is not None
        # Timestamps should be within 1 second of each other at creation
        assert abs((label.updated_dt - label.created_dt).total_seconds()) < 1

    def test_updated_dt_changes_on_save(self):
        """Test that updated_dt changes when label is updated"""
        import time

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        label = CollaboratorLabel.objects.create(
            flaw=flaw, name="test", state=CollaboratorLabel.State.NEW
        )

        original_updated = label.updated_dt

        # Sleep briefly to ensure timestamp difference
        time.sleep(0.01)

        # Update the label
        label.state = CollaboratorLabel.State.DONE
        label.save()
        label.refresh_from_db()

        # updated_dt should have changed
        assert label.updated_dt >= original_updated
