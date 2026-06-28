import pytest
from django.core.exceptions import ValidationError

from osidb.models import (
    CollaboratorLabel,
    CollaboratorLabelDefinition,
    ProductFamilyLabel,
    ProductFamilyLabelDefinition,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
)

pytestmark = pytest.mark.unit


class TestFlawLabelsV2:
    def test_unique_constraint(self):
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        CollaboratorLabelDefinition.objects.create(name="test_label")
        CollaboratorLabel.objects.create(
            flaw=flaw,
            name="test_label",
            state=CollaboratorLabel.State.NEW,
            contributor="test_contributor",
        )

        with pytest.raises(ValidationError):
            CollaboratorLabel.objects.create(
                flaw=flaw,
                name="test_label",
                state=CollaboratorLabel.State.NEW,
                contributor="another_contributor",
            )

    @pytest.mark.enable_signals
    def test_create_labels_on_affect_create(self):
        ps_module = PsModuleFactory()
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module)
        ProductFamilyLabelDefinition.objects.create(
            name="test_component_label",
            ps_components=["test_component"],
        )
        ProductFamilyLabelDefinition.objects.create(
            name="test_module_label",
            ps_modules=[ps_module.name],
        )
        # Context-based definitions should not be auto-created
        CollaboratorLabelDefinition.objects.create(name="test_context_label")

        flaw = FlawFactory(embargoed=False)
        assert flaw.labels_v2.count() == 0

        AffectFactory(
            flaw=flaw,
            ps_component="test_component",
            ps_update_stream=ps_update_stream1.name,
        )
        assert flaw.labels_v2.count() == 2

        AffectFactory(
            flaw=flaw,
            ps_component="test_component",
            ps_update_stream=ps_update_stream2.name,
        )
        assert flaw.labels_v2.count() == 2

    @pytest.mark.enable_signals
    def test_update_label_on_affect_update(self):
        ps_module = PsModuleFactory()
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        ps_update_stream2 = PsUpdateStreamFactory()
        ProductFamilyLabelDefinition.objects.create(
            name="test_component_label",
            ps_components=["test_component"],
        )
        ProductFamilyLabelDefinition.objects.create(
            name="test_module_label",
            ps_modules=[ps_module.name],
        )

        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_component="test_component",
            ps_update_stream=ps_update_stream1.name,
        )
        assert flaw.labels_v2.count() == 2

        affect.ps_update_stream = ps_update_stream2.name
        affect.save()

        assert flaw.labels_v2.count() == 2
        assert ProductFamilyLabel.objects.filter(flaw=flaw, relevant=False).count() == 1

    @pytest.mark.enable_signals
    def test_legacy_label(self):
        """Test that product family labels can be updated after their definition is removed."""
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        definition = ProductFamilyLabelDefinition.objects.create(
            name="test_module_label",
            ps_modules=[ps_module.name],
        )

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, ps_update_stream=ps_update_stream.name)
        assert flaw.labels_v2.count() == 1

        definition.delete()
        label = ProductFamilyLabel.objects.first()
        label.relevant = False
        label.save()

        # Verify the change was actually persisted
        label.refresh_from_db()
        assert label.relevant is False

    def test_update_relevance(self):
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False)
        ProductFamilyLabelDefinition.objects.create(
            name="test_module_label",
            ps_modules=[ps_module.name],
        )

        ProductFamilyLabel.update_relevance(flaw)
        assert ProductFamilyLabel.objects.count() == 0

        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="test_component",
        )
        ProductFamilyLabel.update_relevance(flaw)
        assert ProductFamilyLabel.objects.count() == 1

    @pytest.mark.parametrize(
        "workflow_state",
        [
            "",
            "NEW",
            "TRIAGE",
            "PRE_SECONDARY_ASSESSMENT",
            "SECONDARY_ASSESSMENT",
            "DONE",
        ],
    )
    def test_labels_can_be_created_in_any_workflow_state(self, workflow_state):
        """Test that labels can be created in any workflow state"""
        CollaboratorLabelDefinition.objects.create(name="test_label")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        flaw.workflow_state = workflow_state
        flaw.save()

        label = CollaboratorLabel.objects.create(
            flaw=flaw,
            name="test_label",
            state=CollaboratorLabel.State.NEW,
            contributor="test_contributor",
        )
        assert label.pk is not None
