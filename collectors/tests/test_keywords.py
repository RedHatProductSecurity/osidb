import pytest

from collectors.keywords import check_keywords, should_create_snippet


@pytest.mark.parametrize(
    "text, expected_output",
    [
        ("Internet is a great thing!", ([], [])),
        ("IBM Tivoli is blue and red.", (["IBM Tivoli"], [])),
        ("we want to whitelist kernel", ([], ["kernel"])),
    ],
)
def test_check_keywords(text, expected_output):
    assert check_keywords(text) == expected_output


@pytest.mark.parametrize(
    "text, expected_output",
    [
        ("qh_core in Nagios Core 4.4.1 and earlier", ([], [])),
        ("new iOS is released", (["iOS"], [])),
    ],
)
def test_check_keywords_case_sensitive(text, expected_output):
    assert check_keywords(text) == expected_output


@pytest.mark.parametrize(
    "text, expected_output",
    [
        ("something noCiscono else", ([], [])),
        ("left side Ciscono else", ([], [])),
        ("right side noCisco else", ([], [])),
        ("some Cisco update", (["Cisco"], [])),
        ("something noiOSno else", ([], [])),
        ("left side iOSno else", ([], [])),
        ("right side noiOS else", ([], [])),
        ("new iOS is released", (["iOS"], [])),
    ],
)
def test_check_keywords_word_boundary(text, expected_output):
    assert check_keywords(text) == expected_output


@pytest.mark.parametrize(
    "text, expected_output",
    [
        ("www.web.net", ([], [])),
        ("space .NET is a programming language.", ([], [".NET"])),
        ("no space.NET is a programming language.", ([], [])),
        ("ASP.NET", ([], [])),
        (".NET iTunes", (["iTunes"], [".NET"])),
        ("end of sentence .NET. new sentence", ([], [".NET"])),
    ],
)
def test_check_keywords_dotnet_special_case(text, expected_output):
    assert check_keywords(text) == expected_output


@pytest.mark.parametrize(
    "text, expected_output",
    [
        (
            "The xo-security plugin before 1.5.3 for WordPress has XSS.",
            (["The xo-security plugin before 1.5.3 for WordPress"], []),
        ),
        ("The xo-security before 1.5.3 for WordPress has XSS.", ([], [])),
        ("The plugin before 1.5.3 for", ([], [])),
        (
            "The 404-to-301 plugin before 2.0.3 for WordPress has SQL injection.",
            (["The 404-to-301 plugin before 2.0.3 for WordPress"], []),
        ),
        (
            "The profile-builder plugin before 2.1.4 for WordPress has no access "
            "control for activating or deactivating addons via AJAX.",
            (["The profile-builder plugin before 2.1.4 for WordPress"], []),
        ),
    ],
)
def test_check_keywords_wordpress(text, expected_output):
    assert check_keywords(text) == expected_output


@pytest.mark.parametrize(
    "text, should_create",
    [
        # in both blacklist and whitelist
        ("kernel and iOS in description", True),
        # in whitelist only
        ("kernel and ios in description", True),
        # not in whitelist or blacklist
        ("something else in description", True),
        # in blacklist only
        ("iOS in description", False),
        # nothing to check
        (None, False),
    ],
)
def test_should_create_snippet(text, should_create):
    """
    Check whether a snippet should be created based on keywords in `text`.
    """
    assert should_create_snippet(text) == should_create
