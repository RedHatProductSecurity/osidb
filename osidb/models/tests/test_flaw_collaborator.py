import pytest
from django.core.exceptions import ValidationError

from osidb.models import FlawCollaborator, FlawLabel
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestFlawCollaborator:
    def test_unique_constraint(self):
        flaw = FlawFactory(embargoed=False)
        label = FlawLabel.objects.create(
            name="test_label", type=FlawLabel.FlawLabelType.CONTEXT_BASED
        )

        FlawCollaborator.objects.create(
            flaw=flaw,
            label=label,
            state=FlawCollaborator.FlawCollaboratorState.NEW,
            contributor="test_contributor",
        )

        with pytest.raises(ValidationError):
            FlawCollaborator.objects.create(
                flaw=flaw,
                label=label,
                state=FlawCollaborator.FlawCollaboratorState.NEW,
                contributor="another_contributor",
            )
