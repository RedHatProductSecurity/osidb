import pytest

from collectors.utils import handle_urls, tracker_parse_update_stream_component
from osidb.models import FlawReference

pytestmark = pytest.mark.unit


class TestParseUpdateStreamComponent:
    @pytest.mark.parametrize(
        "title,stream,component",
        [
            ("component: [stream]", "stream", "component"),
            ("component: random text [stream]", "stream", "component"),
            ("CVE-123-123 component: random text [stream]", "stream", "component"),
            (
                "CVE-123-123,CVE-5-897976 component: random text [stream]",
                "stream",
                "component",
            ),
            ("CVE-123-123,... component: random text [stream]", "stream", "component"),
            ("EMBARGOED component: random text [stream]", "stream", "component"),
            (
                "EMBARGOED CVE-123-123 component: text [stream]",
                "stream",
                "component",
            ),
            (
                "EMBARGOED \tCVE-1-1 \n   component:   \t text    [stream]   ",
                "stream",
                "component",
            ),
            ("EMBARGOED ... component: random text [stream]", "stream", "component"),
            (
                "abc12:::3>12387/.*@#$~đĐ: random text [82sfłvø→{$~|#{]",
                "82sfłvø→{$~|#{",
                "abc12:::3>12387/.*@#$~đĐ",
            ),
            ("component: anotherone: something: [stream]", "stream", "component"),
            (
                "[Major Incident] CVE-2222-1111 component: text [stream]",
                "stream",
                "component",
            ),
            (
                "[CISA Major Incident] CVE-2222-1111 component: another: text [stream]",
                "stream",
                "component",
            ),
            (
                "TRIAGE component: text [stream]",
                "stream",
                "component",
            ),
            (
                "TRIAGE-CVE-2222-1111 component: text [stream]",
                "stream",
                "component",
            ),
            (
                "EMBARGOED TRIAGE component: text [stream]",
                "stream",
                "component",
            ),
            (
                "[CISA Major Incident] TRIAGECVE-2222-1111 component: another: text [stream]",
                "stream",
                "component",
            ),
            (
                "[Minor Incident] CVE-2222-1111 component: another: text [stream]",
                "stream",
                "component",
            ),
            (
                "[0-day] component: text [stream]",
                "stream",
                "component",
            ),
        ],
    )
    def test_correct(self, title, stream, component):
        """
        test parsing of update stream and component from a correct summary
        """
        assert (stream, component) == tracker_parse_update_stream_component(title)

    @pytest.mark.parametrize(
        "title",
        [
            "component:[stream]",
            "component:text [stream]",
            "text [stream]",
            "component: text",
        ],
    )
    def test_incorrect(self, title):
        """
        test parsing of update stream and component from an incorrect summary
        """
        assert (None, None) == tracker_parse_update_stream_component(title)


class TestHandleURLs:
    def test_handle_urls(self):
        result = handle_urls(
            [
                "https://www.google1.com",
                "google2.com",
                "htt://www.google3.com",
                "https://www.source.com",
            ],
            "https://www.source.com",
        )

        assert len(result) == 2
        assert {
            "type": FlawReference.FlawReferenceType.EXTERNAL,
            "url": "https://www.google1.com",
        } in result
        assert {
            "type": FlawReference.FlawReferenceType.EXTERNAL,
            "url": "http://google2.com",
        } in result
