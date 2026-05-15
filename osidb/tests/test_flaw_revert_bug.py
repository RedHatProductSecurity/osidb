"""
Test to reproduce OSIDB-4985: Flaw fields revert after PUT with many affects
"""

import pghistory.models
import pytest

from osidb.models import Affect
from osidb.tests.factories import AffectFactory, FlawFactory, PsUpdateStreamFactory


def get_flaw_story(flaw):
    return pghistory.models.Events.objects.tracks(flaw).order_by("pgh_created_at")


def print_differences(differences):
    for field, difference in differences.items():
        print(f"\t{field}: {difference['old']} -> {difference['new']}")


def print_audit(audit):
    print("**************INITIAL OF AUDIT************************************")
    for line in audit:
        print(line)
    print("**************END OF AUDIT************************************")


def arrange_event_diffs(flaw_story):
    data_list = []
    for s in flaw_story:
        text = f"************{s.pgh_data['task_key']} - {s.pgh_created_at}******************"
        text += f"\n{s.pgh_context}"
        text += f"\n{s.pgh_diff}"
        text += "**************************************************"
        data_list.append(text)
    return data_list


def get_flaw_audit(flaw):
    history = get_flaw_story(flaw)
    data_list = arrange_event_diffs(history)
    return data_list


@pytest.mark.enable_signals
class TestFlawRevertBug:
    """
    Reproduce the bug where flaw.statement reverts to empty string
    after a PUT request with many affects.

    Based on real-world evidence from CVE-2026-39892:
    - PUT with 152 affects
    - statement changes from '' to 'In default configurations...'
    - ~400ms-1.2s later, statement reverts to ''
    - pg_history shows revert with no user/path (internal operation)
    """

    def test_flaw_statement_does_not_revert_with_many_affects(self, db):
        """
        Test that updating a flaw with many affects doesn't cause statement to revert.

        Steps:
        1. Create a flaw with empty statement
        2. Create 152 affects for that flaw (matching real scenario)
        3. Update flaw.statement to a non-empty value
        4. Save the flaw
        5. Trigger signals by saving affects
        6. Verify statement hasn't reverted
        """
        # Step 1: Create flaw with empty statement
        flaw = FlawFactory(
            cve_id="CVE-2026-39892",
            statement="",
            impact="IMPORTANT",
        )

        print(f"\n1. Created flaw {flaw.uuid} with empty statement")

        # Step 2: Create 152 affects (matching the real scenario)
        affects = []
        for i in range(152):
            ps_update_stream = PsUpdateStreamFactory()
            affect = AffectFactory(
                flaw=flaw,
                ps_module=ps_update_stream.ps_module.name,
                ps_update_stream=ps_update_stream.name,
                ps_component=f"component-{i}",
            )
            affects.append(affect)

        print(f"2. Created {len(affects)} affects for the flaw")

        # Step 3: Update flaw statement (simulating user PUT)
        new_statement = (
            "In default configurations Red Hat products isolate service processes "
            "from total system access. Should an attacker be able to exploit this "
            "vulnerability their impact will be limited to that service account and "
            "they will not have access to the broader system."
        )

        flaw.statement = new_statement
        flaw.save()

        print(f"3. Updated flaw.statement to: {new_statement[:50]}...")

        # Step 4: Reload flaw from DB to verify it was saved
        flaw.refresh_from_db()
        assert flaw.statement == new_statement, "Statement should be saved correctly"
        print("4. Verified statement is saved in DB")

        # Step 5: Trigger the signals by re-saving some affects
        # This simulates what happens during a PUT request with nested affects
        print("5. Re-saving affects to trigger signals...")
        for i, affect in enumerate(affects[:10]):  # Save first 10 to trigger signals
            affect.save()
            if i % 5 == 0:
                # Check if statement has reverted after each batch
                flaw.refresh_from_db()
                print(
                    f"   After saving affect {i}: statement = '{flaw.statement[:50] if flaw.statement else '(empty)'}...'"
                )

        # Step 6: Final verification - has the statement reverted?
        flaw.refresh_from_db()

        print("\n6. FINAL CHECK:")
        print(f"   Expected: {new_statement[:80]}...")
        print(
            f"   Actual:   {flaw.statement[:80] if flaw.statement else '(EMPTY - BUG REPRODUCED!)'}..."
        )

        audit = get_flaw_audit(flaw)
        print_audit(audit)

        # This is the assertion that should pass if the bug is fixed
        assert flaw.statement == new_statement, (
            f"BUG REPRODUCED: Flaw statement reverted! "
            f"Expected: '{new_statement[:100]}...' "
            f"Got: '{flaw.statement}'"
        )

    def test_flaw_statement_with_real_payload_structure(self, db):
        """
        Test using a structure closer to the actual payload.json
        This simulates updating a flaw with affects in a single transaction.
        """
        # Create initial flaw
        flaw = FlawFactory(
            cve_id="CVE-2026-39892",
            statement="",
            impact="IMPORTANT",
        )

        # Create affects (fewer for faster test, but same pattern)
        affects = []
        for i in range(50):
            ps_update_stream = PsUpdateStreamFactory()
            affect = AffectFactory(
                flaw=flaw,
                ps_module=ps_update_stream.ps_module.name,
                ps_update_stream=ps_update_stream.name,
                ps_component=f"component-{i}",
            )
            affects.append(affect)

        # Simulate what happens when Django processes a nested serializer update:
        # 1. Affects are loaded (they have references to the OLD flaw)
        loaded_affects = list(Affect.objects.filter(flaw=flaw).select_related("flaw"))

        # 2. Flaw is updated
        new_statement = "This is the new statement that should not revert"
        flaw.statement = new_statement
        flaw.save()

        # 3. Loaded affects are saved (triggering signals with OLD flaw references)
        for affect in loaded_affects[:10]:
            # The affect's flaw reference might be stale here
            affect.save()

        # 4. Check if statement reverted
        flaw.refresh_from_db()

        audit = get_flaw_audit(flaw)
        print_audit(audit)

        assert flaw.statement == new_statement, (
            "BUG REPRODUCED: Statement reverted when affects were saved! "
            "This proves the bug is in the signals using stale flaw references."
        )
