import pytest

from collectors.bzimport.fixups import AffectFixer, FlawFixer
from osidb.models import Flaw

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


class TestFlawFixer:
    @pytest.mark.parametrize(
        "summary,title,component",
        [
            (
                "carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
            (
                "EMBARGOED carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
            (
                "CVE-2000-12345 CVE-3000-12345 carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
            (
                "EMBARGOED CVE-3000-12345 carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
            (
                "radioactive carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
            (
                "radioactive carbon : cheesecake",
                "radioactive carbon : cheesecake",
                "",
            ),
            (
                "carbon cheesecake:",
                "",
                "cheesecake",
            ),
            (
                "carbon cheesecake",
                "carbon cheesecake",
                "",
            ),
            (
                "EMBARGOED",
                "",
                "",
            ),
            (
                "CVE-2000-12345 CVE-3000-12345",
                "",
                "",
            ),
            (
                "EMBARGOED CVE-2000-12345 CVE-3000-12345",
                "",
                "",
            ),
            (
                "EMBARGOED:",
                ":",
                "",
            ),
            (
                "radioactive: carbon: cheesecake:",
                "",
                "cheesecake",
            ),
            (
                "radioactive: carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
            (
                "   carbon:   cheesecake   ",
                "cheesecake",
                "carbon",
            ),
            (
                "TRIAGE carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
            (
                "TRIAGE-CVE-2000-12345 carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
            (
                "EMBARGOED TRIAGE carbon: cheesecake",
                "cheesecake",
                "carbon",
            ),
        ],
    )
    def test_fix_title(self, summary, title, component):
        """
        test title fixup which performs mapping from Bugzilla summary
        it not only sets the correct flaw title but also the component
        """
        flaw = Flaw()
        flaw_fixer = FlawFixer(flaw, {"summary": summary}, None)
        flaw_fixer.fix_title()
        assert flaw.title == title
        assert flaw.component == component
