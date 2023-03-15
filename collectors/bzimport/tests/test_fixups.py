import pytest

from collectors.bzimport.fixups import AffectFixer

pytestmark = pytest.mark.unit


class TestAffectFixer:
    def test_affect_ps_module_fixup(self):
        """
        test affect PS module fixup when the
        PS update stream was put in by mistake
        """
        correct_module = "rhel-6"
        incorrect_module = "rhel-6.3"

        # should fixup the affect with incorrect module
        assert correct_module == AffectFixer.fixplace_ps_module(incorrect_module)

        # should not change the affect with correct module at all
        assert correct_module == AffectFixer.fixplace_ps_module(correct_module)
