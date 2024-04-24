from osidb.cc import (
    BugzillaAffectCCBuilder,
    BugzillaFlawCCBuilder,
    RHSCLBugzillaAffectCCBuilder,
)


class AffectCCBuilder(BugzillaAffectCCBuilder):
    """
    Deprecated class. Use BugzillaAffectCCBuilder.

    The reason is that BugzillaAffectCCBuilder is in a collection of classes
    with much clearer intended use.

    TODO: Refactor AffectCCBuilder away and use BugzillaAffectCCBuilder.
          At the time of writing this (2024-04), there was not enough
          resources to do that.

    affect CC list builder
    """

    pass


class RHSCLAffectCCBuilder(RHSCLBugzillaAffectCCBuilder):
    """
    Deprecated class. Use BugzillaAffectCCBuilder.

    The reason is that RHSCLBugzillaAffectCCBuilder is in a collection of classes
    with much clearer intended use.

    TODO: Refactor RHSCLAffectCCBuilder away and use RHSCLBugzillaAffectCCBuilder.
          At the time of writing this (2024-04), there was not enough
          resources to do that.

    Red Hat Software Collections affect CC list builder
    introduces special differences from the base class
    """

    pass


class CCBuilder(BugzillaFlawCCBuilder):
    """
    Deprecated class. Use BugzillaFlawCCBuilder.

    The reason is that BugzillaFlawCCBuilder is in a collection of classes
    with much clearer intended use.

    TODO: Refactor CCBuilder away and use BugzillaFlawCCBuilder.
          At the time of writing this (2024-04), there was not enough
          resources to do that.

    Bugzilla flaw CC list array builder
    """

    pass
