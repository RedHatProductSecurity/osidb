import pytest

from ..utils import find_cves, find_cvss, find_cwes, html_to_text


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("xxxCVE-2016-1234 yyy", ["CVE-2016-1234"]),
        ("CVE-2016-1000001 yyy", ["CVE-2016-1000001"]),
        ("CVE-2016-123[4-6]", ["CVE-2016-1234", "CVE-2016-1235", "CVE-2016-1236"]),
        ("CVE-2016-123[4,6]", ["CVE-2016-1234", "CVE-2016-1236"]),
        ("CVE-2016-123[46]", ["CVE-2016-1234", "CVE-2016-1236"]),
        ("CVE-2016-{1234..1236}", ["CVE-2016-1234", "CVE-2016-1235", "CVE-2016-1236"]),
        ("CVE-2016-{1234,1236}", ["CVE-2016-1234", "CVE-2016-1236"]),
        (
            "[mageia] libwmf new security issues CVE-2016-1016[6-8], CVE-2016-6912, CVE-2016-9317",
            [
                "CVE-2016-10166",
                "CVE-2016-10167",
                "CVE-2016-10168",
                "CVE-2016-6912",
                "CVE-2016-9317",
            ],
        ),
    ],
)
def test_find_cves_valid(test_input, expected):
    assert find_cves(test_input) == expected


@pytest.mark.parametrize(
    "test_input",
    [
        "xxxCVE-2016-yyy",
        "CVE-2016-13[4-6]",
        "CVE-2016-[]",
        "CVE-2016-{1234....1236}",
        "CVE-2016-{1234,1236,}",
        "CVE-2016-{1234}",
        "CVE-2016-{1234-1236}",
    ],
)
def test_find_cves_invalid(test_input):
    assert find_cves(test_input) == []


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("integer overflow", "CWE-190->CWE-120"),
        ("integer overflow, xss", "(CWE-190->CWE-120|CWE-79)"),
        ("integer overflow CWE-119", "CWE-119"),
    ],
)
def test_find_cwes_impact(test_input, expected):
    impact = "important"
    assert find_cwes(text=test_input, impact=impact) == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("CWE-1", "CWE-1"),
        ("CWE-10", "CWE-10"),
        ("CWE-100", "CWE-100"),
        ("CWE-1000", "CWE-1000"),
        ("end of sentence without space.CWE-100", "CWE-100"),
        ("xxx CWE-100", "CWE-100"),
        ("CWE-100xxx", "CWE-100"),
        ("CWE-100 xxx", "CWE-100"),
        ("1xx CWE-100 xxx CWE-1000 43", "(CWE-100|CWE-1000)"),
        ("xxx CWE-100 xxx CWE-100 xxx CWE", "CWE-100"),
        ("xxx cwe-100 yyy", "CWE-100"),
        ("CWE-", None),
        ("xxxCWE-xxx", None),
        ("xxx CWE xxx", None),
        ("CWE-007", None),
        ("NVD-CWE-noinfo", None),
        (None, None),
        ("", None),
        (" ".join(["CWE-119", "CWE-110"]), "(CWE-110|CWE-119)"),
        (" ".join(["CWE-119", "CWE-110", "CWE-119"]), "(CWE-110|CWE-119)"),
        ("integer overflow", "CWE-190"),
        ("integer overflow CWE-119", "CWE-119"),
        ("text load local content text protection bypass", "(CWE-552|CWE-829)"),
    ],
)
def test_find_cwes(test_input, expected):
    assert find_cwes(test_input) == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("CWE-190->CWE-120", "(CWE-120|CWE-190)"),
        (" ".join(["CWE-190->CWE-120", "CWE-110"]), "(CWE-110|CWE-120|CWE-190)"),
    ],
)
def test_find_cwes_leads_to_not_supported(test_input, expected):
    assert find_cwes(test_input) == expected


@pytest.mark.parametrize(
    "test_input, expected",
    [
        ("", ""),
        (None, ""),
        ("text", ""),
        (
            "CVSS v3 CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N ",
            "4.3/CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
        ),
        (
            "CVSS v3 CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N    CVSS v2 AV:A/AC:M/Au:S/C:N/I:P/A:N",
            "4.3/CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
        ),
        (
            "Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N (V3 legend) "
            "Source: https://nvd.nist.gov/vuln/detail/CVE-2018-11456 Malformed CVSSv3. Missing prefix.",
            "",
        ),
        ("CVSS v2 AV:A/AC:M/Au:S/C:N/I:P/A:N", ""),
        (
            "CVSS v3 	CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 	Base Score: 9.8\n"
            "CVSS v2 	AV:N/AC:L/Au:N/C:P/I:P/A:P 	Base Score: 7.5\n"
            "CVSS v3 	CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L 	Base Score: 6.3\n"
            "CVSS v2 	AV:N/AC:L/Au:S/C:P/I:P/A:P 	Base Score: 6.5\n"
            "CVSS v3 	CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H 	Base Score: 8.8\n"
            "CVSS v2 	AV:N/AC:L/Au:S/C:P/I:P/A:P 	Base Score: 6.5\n"
            "Source: https://jvn.jp/en/jp/JVN00344155/",
            "9.8/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    ],
)
def test_find_cvss(test_input, expected):
    assert find_cvss(test_input) == expected


def test_html_to_text():
    html_text = (
        """<ol>\n"""
        """<li>Lorem ipsum dolor sit amet, ✔.</li>\n"""
        """<li><a href="https://www.cvedetails.com/cve/CVE-2014-0160"><i>WE <b>REMEMBER</b></i></a>.</li>\n"""
        """<li><small>Žluťoučký kůň úpěl ďábelské ódy</small>.</li>\n"""
        """<li>Zażółć gęślą jaźń.</li>\n"""
        """<li>Єхидна, ґава, їжак ще й шиплячі плазуни бігцем форсують Янцзи.</li>\n"""
        """<li>以呂波耳本部止<br>\n"""
        """    千利奴流乎和加<br>\n"""
        """    餘多連曽津祢那<br>\n"""
        """    良牟有為能於久<br>\n"""
        """    耶万計不己衣天<br>\n"""
        """    阿佐伎喩女美之<br>\n"""
        """    恵比毛勢須</li>\n"""
        """</ol>"""
    )

    expected_output = (
        """    1. Lorem ipsum dolor sit amet, ✔.\n"""
        """    2. WE REMEMBER.\n"""
        """    3. Žluťoučký kůň úpěl ďábelské ódy.\n"""
        """    4. Zażółć gęślą jaźń.\n"""
        """    5. Єхидна, ґава, їжак ще й шиплячі плазуни бігцем форсують Янцзи.\n"""
        """    6. 以呂波耳本部止\n"""
        """       千利奴流乎和加\n"""
        """       餘多連曽津祢那\n"""
        """       良牟有為能於久\n"""
        """       耶万計不己衣天\n"""
        """       阿佐伎喩女美之\n"""
        """       恵比毛勢須\n"""
    )

    assert html_to_text(html_text) == expected_output
