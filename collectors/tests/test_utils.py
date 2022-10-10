import pytest

from collectors.utils import tracker_parse_update_stream_component

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
