import time

import pytest
from feedparser import FeedParserDict

from collectors.feed.collectors import ConfigDict, ConfigFile, FeedCollector
from osidb.models import Snippet

pytestmark = pytest.mark.integration

# Fixed subset of config.yml for testing.
# - Allows changes to config.yml without having to re-record VCRs and still have working tests.
# - Serves as a sanity check for included regexps (each language and string type has different special chars).
FEED_CONFIG_1 = [
    {
        "url": "https://rss.packetstormsecurity.com/files/tags/advisory",
        "name": "Packet Storm Advisory Files",
        "entry_url_replace": [["/files", "/files/download"]],
        "entry_separate_links": True,
        "source": "internet",
        "meta": [
            {
                "description": "The Packet Storm Advisory Files feed includes security advisories of various other Linux vendors."
            },
            {
                "reason": "This list is a single source of all vendor advisories. Rather than subscribing to feeds of all the vendors, we use this feed."
            },
        ],
    },
    {
        "url": "https://nodejs.org/en/feed/vulnerability.xml",
        "name": "Node.js Vulnerability Reports",
        "entry_text_in_html": True,
        "entry_separate_links": True,
        "source": "internet",
        "components": ["nodejs", "nodejs010-nodejs"],
        "meta": [
            {
                "description": "The Node.js Vulnerability Reports feed contains advisories released for Node.js by the Node.js Foundation."
            },
            {
                "reason": "This feed is the best source of information to learn of new Node.js vulnerabilities since we do not have a member of Product Security in the Node.js upstream community."
            },
        ],
    },
    {
        "url": "https://feeds.feedburner.com/GoogleChromeReleases?format=xml",
        "name": "Google Chrome Releases",
        "entry_text_in_html": True,
        # Google Chrome Releases: receives posts for all Chrome products and branches,
        # but we're only interested in the Stable Channel updates. Skip the rest.
        "skip_entry_title_regex": r"^((?!(.*?Stable Channel Update))|.*?Stable Channel Update for Chrome OS)",
        "source": "internet",
        "components": ["chromium-browser"],
        "meta": [
            {
                "description": "The Google Chrome Releases feed is a collection of release notes that also include security advisories. It includes advisories for various Google products; we are only interesting in the Stable Channel Chrome updates."
            },
            {
                "reason": "This feed is the best source of information to learn of new Chrome vulnerabilities."
            },
        ],
    },
    {
        "url": "https://discuss.elastic.co/c/announcements/security-announcements.rss",
        "name": "Elastic.co Security Announcements",
        "entry_text_in_html": True,
        "source": "internet",
        "components": ["elasticsearch", "kibana"],
        "meta": [
            {"description": "Elastic security announcements"},
            {
                "reason": "Elastic components are included in OpenShift and possibly other products"
            },
            {"contact": "security@elastic.co"},
            {"last_contacted": "N/A"},
        ],
    },
]


class TestFeedCollector:
    """
    Feed collector tests
    """

    def test_configuration(self):
        config_adapter_config = ConfigFile().get_config()

        for i in range(len(config_adapter_config)):
            # Make sure the regex is correct.
            # When editing regexes, double-check that it is what you expect.
            assert config_adapter_config[i].get(
                "skip_entry_title_regex"
            ) == FEED_CONFIG_1[i].get("skip_entry_title_regex")

        # Might make sense to remove this test if the config is expected to change often.
        assert config_adapter_config == FEED_CONFIG_1

    @pytest.mark.default_cassette("TestFeedCollector.test_smoke_test.yaml")
    @pytest.mark.vcr
    def test_smoke_test(self):
        assert 0 == Snippet.objects.all().count()

        collector = FeedCollector(configuration_adapter=ConfigDict(FEED_CONFIG_1))
        collector.collect()

        assert 134 == Snippet.objects.all().count()
        assert 103 == Snippet.objects.filter(content__create_flaws=True).count()
        assert 31 == Snippet.objects.filter(content__create_flaws=False).count()

    @pytest.mark.default_cassette("TestFeedCollector.test_smoke_test.yaml")
    @pytest.mark.vcr
    def test_collect_feed(self):
        collector = FeedCollector()

        feed_data = FEED_CONFIG_1[2]

        # Sanity check that the test runs with the expected config entry
        assert (
            feed_data["url"]
            == "https://feeds.feedburner.com/GoogleChromeReleases?format=xml"
        )

        expected_ret = 25, 5

        assert 0 == Snippet.objects.all().count()

        ret = collector.collect_feed(feed_data)

        assert ret == expected_ret

        assert 25 == Snippet.objects.all().count()
        assert 5 == Snippet.objects.filter(content__create_flaws=True).count()
        assert 20 == Snippet.objects.filter(content__create_flaws=False).count()
        assert (
            3
            == Snippet.objects.filter(content__create_flaws=True)
            .exclude(content__cve_ids=[])
            .count()
        )

        expected_content = {
            "cve_ids": [
                "CVE-2023-21216",
                "CVE-2023-35685",
                "CVE-2023-40109",
                "CVE-2023-40110",
                "CVE-2023-40112",
                "CVE-2023-40113",
                "CVE-2023-40114",
                "CVE-2023-40118",
                "CVE-2023-4244",
                "CVE-2023-5197",
                "CVE-2023-5996",
            ],
            "title": "Stable Channel Update for ChromeOS/ChromeOS Flex",
            "description": "ChromeOS M119 Stable\n\n   The Stable channel is being updated to OS version: 15633.44.0 Browser\n   version: 119.0.6045.158 for most ChromeOS devices.\n\n   If you find new issues, please let us know one of the following ways\n\n    1. File a bug\n    2. Visit our ChromeOS communities\n\n         1. General: Chromebook Help Community\n         2. Beta Specific: ChromeOS Beta Help Community\n\n    3. Report an issue or send feedback on Chrome\n\n   Interested in switching channels? Find out how.\n\n   Security Fixes and Rewards\n   ChromeOS Vulnerabiltity Rewards Program Reported Bug Fixes:\n   [$TBD] [1477932] Medium CVE-2023-21216 Use-after-free in PowerVR GPU\n   Driver. Reported by lovepink on 2023-09-07\n   We would like to thank the security researchers that report\n   vulnerabilities to us via bughunters.google.com to keep ChromeOS and the\n   entire open source ecosystem secure.\n   Chrome Browser Security Fixes:\n   [N/A] [1497859] High CVE-2023-5996: Use after free in WebAudio. Reported\n   by Huang Xilin of Ant Group Light-Year Security Lab via Tianfu Cup 2023 on\n   2023-10-30\n   Other 3rd Party Security Fixes Included:\n   [NA]  High Fixes CVE-2023-35685 on impacted platforms\n   [NA]  Medium Fixes CVE-2023-4244 in Linux Kernel\n   [NA]  Medium Fixes CVE-2023-5197 in Linux Kernel\n   Android Runtime Container Security Fixes:\n   [NA]  Critical Fixes CVE-2023-40113 on impacted platforms\n   [NA]  High Fixes CVE-2023-40109 on impacted platforms\n   [NA]  High Fixes CVE-2023-40114 on impacted platforms\n   [NA]  High Fixes CVE-2023-40110 on impacted platforms\n   [NA]  High Fixes CVE-2023-40112 on impacted platforms\n   [NA]  Medium Fixes CVE-2023-40118 on impacted platforms\n   Users who are pinned to a specific release of ChromeOS will not receive\n   these security fixes or any other security fixes. We recommend updating to\n   the latest version of Stable to ensure you are protected against\n   exploitation of known vulnerabilities. \n   To see fixes included in the Long Term Stable channel, see the release\n   notes.\n   Daniel Gagnon,\n   Google ChromeOS",
            "cwe_id": "CWE-416",
            "url": "http://chromereleases.googleblog.com/2023/11/stable-channel-update-for.html",
            "references": [
                {
                    "url": "http://chromereleases.googleblog.com/2023/11/stable-channel-update-for.html",
                    "type": "SOURCE",
                }
            ],
            "components": ["chromium-browser"],
            "create_flaws": True,
        }
        a_valuable_snippet = Snippet.objects.filter(
            content__url="http://chromereleases.googleblog.com/2023/11/stable-channel-update-for.html"
        )
        assert 1 == a_valuable_snippet.count()
        assert a_valuable_snippet.first().content == expected_content
        assert a_valuable_snippet.first().source == Snippet.Source.FEED_CHROME

        expected_content = {
            "url": "http://chromereleases.googleblog.com/2023/11/chrome-for-android-update_0123862072.html",
            "create_flaws": False,
        }
        a_deduplication_prevention_snippet = Snippet.objects.filter(
            content__url="http://chromereleases.googleblog.com/2023/11/chrome-for-android-update_0123862072.html"
        )
        assert 1 == a_deduplication_prevention_snippet.count()
        assert a_deduplication_prevention_snippet.first().content == expected_content
        assert (
            a_deduplication_prevention_snippet.first().source
            == Snippet.Source.FEED_CHROME
        )

    @pytest.mark.default_cassette("TestFeedCollector.test_smoke_test.yaml")
    @pytest.mark.vcr
    def test_fetch_new_feed_entries(self):
        collector = FeedCollector()

        url = "https://rss.packetstormsecurity.com/files/tags/advisory"
        expected_ret = [
            {
                "title": "Ubuntu Security Notice USN-6492-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6492-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175820/USN-6492-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175820/USN-6492-1.txt",
                "id": "https://packetstormsecurity.com/files/175820/USN-6492-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175820/Ubuntu-Security-Notice-USN-6492-1.html",
                "published": "Tue, 21 Nov 2023 16:01:29 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 16, 1, 29, 1, 325, 0)
                ),
                "summary": "Ubuntu Security Notice 6492-1 - Kathrin Kleinhammer discovered that Mosquitto incorrectly handled certain inputs. If a user or an automated system were provided with a specially crafted input, a remote attacker could possibly use this issue to cause a denial of service. This issue only affected Ubuntu 20.04 LTS. Zhanxiang Song discovered that Mosquitto incorrectly handled certain inputs. If a user or an automated system were provided with a specially crafted input, a remote attacker could possibly use this issue to cause an authorisation bypass. This issue only affected Ubuntu 22.04 LTS and Ubuntu 23.04.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6492-1 - Kathrin Kleinhammer discovered that Mosquitto incorrectly handled certain inputs. If a user or an automated system were provided with a specially crafted input, a remote attacker could possibly use this issue to cause a denial of service. This issue only affected Ubuntu 20.04 LTS. Zhanxiang Song discovered that Mosquitto incorrectly handled certain inputs. If a user or an automated system were provided with a specially crafted input, a remote attacker could possibly use this issue to cause an authorisation bypass. This issue only affected Ubuntu 22.04 LTS and Ubuntu 23.04.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6493-2",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6493-2",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175819/USN-6493-2.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175819/USN-6493-2.txt",
                "id": "https://packetstormsecurity.com/files/175819/USN-6493-2.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175819/Ubuntu-Security-Notice-USN-6493-2.html",
                "published": "Tue, 21 Nov 2023 16:01:15 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 16, 1, 15, 1, 325, 0)
                ),
                "summary": "Ubuntu Security Notice 6493-2 - USN-6493-1 fixed a vulnerability in hibagent. This update provides the corresponding update for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. On Ubuntu 18.04 LTS and Ubuntu 16.04 LTS, the hibagent package has been updated to add IMDSv2 support, as IMDSv1 uses an insecure protocol and is no longer recommended.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6493-2 - USN-6493-1 fixed a vulnerability in hibagent. This update provides the corresponding update for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. On Ubuntu 18.04 LTS and Ubuntu 16.04 LTS, the hibagent package has been updated to add IMDSv2 support, as IMDSv1 uses an insecure protocol and is no longer recommended.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6493-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6493-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175818/USN-6493-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175818/USN-6493-1.txt",
                "id": "https://packetstormsecurity.com/files/175818/USN-6493-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175818/Ubuntu-Security-Notice-USN-6493-1.html",
                "published": "Tue, 21 Nov 2023 16:01:01 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 16, 1, 1, 1, 325, 0)
                ),
                "summary": "Ubuntu Security Notice 6493-1 - On Ubuntu 20.04 LTS and Ubuntu 22.04 LTS, the hibagent package has been updated to add IMDSv2 support, as IMDSv1 uses an insecure protocol and is no longer recommended. In addition, on all releases, hibagent has been updated to do nothing if ODH is configured.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6493-1 - On Ubuntu 20.04 LTS and Ubuntu 22.04 LTS, the hibagent package has been updated to add IMDSv2 support, as IMDSv1 uses an insecure protocol and is no longer recommended. In addition, on all releases, hibagent has been updated to do nothing if ODH is configured.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6491-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6491-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175817/USN-6491-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175817/USN-6491-1.txt",
                "id": "https://packetstormsecurity.com/files/175817/USN-6491-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175817/Ubuntu-Security-Notice-USN-6491-1.html",
                "published": "Tue, 21 Nov 2023 16:00:44 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 16, 0, 44, 1, 325, 0)
                ),
                "summary": "Ubuntu Security Notice 6491-1 - Axel Chong discovered that Node.js incorrectly handled certain inputs. If a user or an automated system were tricked into opening a specially crafted input file, a remote attacker could possibly use this issue to execute arbitrary code. Zeyu Zhang discovered that Node.js incorrectly handled certain inputs. If a user or an automated system were tricked into opening a specially crafted input file, a remote attacker could possibly use this issue to execute arbitrary code. This issue only affected Ubuntu 22.04 LTS.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6491-1 - Axel Chong discovered that Node.js incorrectly handled certain inputs. If a user or an automated system were tricked into opening a specially crafted input file, a remote attacker could possibly use this issue to execute arbitrary code. Zeyu Zhang discovered that Node.js incorrectly handled certain inputs. If a user or an automated system were tricked into opening a specially crafted input file, a remote attacker could possibly use this issue to execute arbitrary code. This issue only affected Ubuntu 22.04 LTS.",
                },
                "tags": [],
            },
            {
                "title": "Debian Security Advisory 5560-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Debian Security Advisory 5560-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175816/dsa-5560-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175816/dsa-5560-1.txt",
                "id": "https://packetstormsecurity.com/files/175816/dsa-5560-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175816/Debian-Security-Advisory-5560-1.html",
                "published": "Tue, 21 Nov 2023 16:00:24 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 16, 0, 24, 1, 325, 0)
                ),
                "summary": "Debian Linux Security Advisory 5560-1 - Florian Picca reported a bug the charon-tkm daemon in strongSwan an IKE/IPsec suite.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Debian Linux Security Advisory 5560-1 - Florian Picca reported a bug the charon-tkm daemon in strongSwan an IKE/IPsec suite.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6490-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6490-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175815/USN-6490-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175815/USN-6490-1.txt",
                "id": "https://packetstormsecurity.com/files/175815/USN-6490-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175815/Ubuntu-Security-Notice-USN-6490-1.html",
                "published": "Tue, 21 Nov 2023 16:00:12 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 16, 0, 12, 1, 325, 0)
                ),
                "summary": "Ubuntu Security Notice 6490-1 - Several security issues were discovered in the WebKitGTK Web and JavaScript engines. If a user were tricked into viewing a malicious website, a remote attacker could exploit a variety of issues related to web browser security, including cross-site scripting attacks, denial of service attacks, and arbitrary code execution.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6490-1 - Several security issues were discovered in the WebKitGTK Web and JavaScript engines. If a user were tricked into viewing a malicious website, a remote attacker could exploit a variety of issues related to web browser security, including cross-site scripting attacks, denial of service attacks, and arbitrary code execution.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6488-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6488-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175814/USN-6488-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175814/USN-6488-1.txt",
                "id": "https://packetstormsecurity.com/files/175814/USN-6488-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175814/Ubuntu-Security-Notice-USN-6488-1.html",
                "published": "Tue, 21 Nov 2023 15:59:57 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 15, 59, 57, 1, 325, 0)
                ),
                "summary": "Ubuntu Security Notice 6488-1 - Florian Picca discovered that strongSwan incorrectly handled certain DH public values. A remote attacker could use this issue to cause strongSwan to crash, resulting in a denial of service, or possibly execute arbitrary code.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6488-1 - Florian Picca discovered that strongSwan incorrectly handled certain DH public values. A remote attacker could use this issue to cause strongSwan to crash, resulting in a denial of service, or possibly execute arbitrary code.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6489-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6489-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175813/USN-6489-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175813/USN-6489-1.txt",
                "id": "https://packetstormsecurity.com/files/175813/USN-6489-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175813/Ubuntu-Security-Notice-USN-6489-1.html",
                "published": "Tue, 21 Nov 2023 15:59:44 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 15, 59, 44, 1, 325, 0)
                ),
                "summary": "Ubuntu Security Notice 6489-1 - Brian McDermott discovered that Tang incorrectly handled permissions when creating/rotating keys. A local attacker could possibly use this issue to read the keys.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6489-1 - Brian McDermott discovered that Tang incorrectly handled permissions when creating/rotating keys. A local attacker could possibly use this issue to read the keys.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-7379-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7379-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175812/RHSA-2023-7379-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175812/RHSA-2023-7379-01.txt",
                "id": "https://packetstormsecurity.com/files/175812/RHSA-2023-7379-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175812/Red-Hat-Security-Advisory-2023-7379-01.html",
                "published": "Tue, 21 Nov 2023 15:59:28 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 15, 59, 28, 1, 325, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-7379-01 - An update for kernel-rt is now available for Red Hat Enterprise Linux 9.2 Extended Update Support. Issues addressed include a use-after-free vulnerability.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7379-01 - An update for kernel-rt is now available for Red Hat Enterprise Linux 9.2 Extended Update Support. Issues addressed include a use-after-free vulnerability.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-7361-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7361-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175811/RHSA-2023-7361-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175811/RHSA-2023-7361-01.txt",
                "id": "https://packetstormsecurity.com/files/175811/RHSA-2023-7361-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175811/Red-Hat-Security-Advisory-2023-7361-01.html",
                "published": "Tue, 21 Nov 2023 15:59:17 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 15, 59, 17, 1, 325, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-7361-01 - An update for ncurses is now available for Red Hat Enterprise Linux 9.2 Extended Update Support.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7361-01 - An update for ncurses is now available for Red Hat Enterprise Linux 9.2 Extended Update Support.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6497-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6497-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175810/USN-6497-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175810/USN-6497-1.txt",
                "id": "https://packetstormsecurity.com/files/175810/USN-6497-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175810/Ubuntu-Security-Notice-USN-6497-1.html",
                "published": "Tue, 21 Nov 2023 15:58:56 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 21, 15, 58, 56, 1, 325, 0)
                ),
                "summary": "Ubuntu Security Notice 6497-1 - Evgeny Vereshchagin discovered that Avahi contained several reachable assertions, which could lead to intentional assertion failures when specially crafted user input was given. An attacker could possibly use this issue to cause a denial of service.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6497-1 - Evgeny Vereshchagin discovered that Avahi contained several reachable assertions, which could lead to intentional assertion failures when specially crafted user input was given. An attacker could possibly use this issue to cause a denial of service.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6486-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6486-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175809/USN-6486-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175809/USN-6486-1.txt",
                "id": "https://packetstormsecurity.com/files/175809/USN-6486-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175809/Ubuntu-Security-Notice-USN-6486-1.html",
                "published": "Mon, 20 Nov 2023 16:28:03 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 20, 16, 28, 3, 0, 324, 0)
                ),
                "summary": "Ubuntu Security Notice 6486-1 - It was discovered that iniParser incorrectly handled certain files. An attacker could possibly use this issue to cause a crash.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6486-1 - It was discovered that iniParser incorrectly handled certain files. An attacker could possibly use this issue to cause a crash.",
                },
                "tags": [],
            },
            {
                "title": "Debian Security Advisory 5559-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Debian Security Advisory 5559-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175808/dsa-5559-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175808/dsa-5559-1.txt",
                "id": "https://packetstormsecurity.com/files/175808/dsa-5559-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175808/Debian-Security-Advisory-5559-1.html",
                "published": "Mon, 20 Nov 2023 16:27:50 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 20, 16, 27, 50, 0, 324, 0)
                ),
                "summary": "Debian Linux Security Advisory 5559-1 - A vulnerability was discovered in the SSH dissector of Wireshark, a network protocol analyzer, which could result in denial of service or potentially the execution of arbitrary code.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Debian Linux Security Advisory 5559-1 - A vulnerability was discovered in the SSH dissector of Wireshark, a network protocol analyzer, which could result in denial of service or potentially the execution of arbitrary code.",
                },
                "tags": [],
            },
            {
                "title": "Debian Security Advisory 5558-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Debian Security Advisory 5558-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175807/dsa-5558-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175807/dsa-5558-1.txt",
                "id": "https://packetstormsecurity.com/files/175807/dsa-5558-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175807/Debian-Security-Advisory-5558-1.html",
                "published": "Mon, 20 Nov 2023 16:25:51 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 20, 16, 25, 51, 0, 324, 0)
                ),
                "summary": "Debian Linux Security Advisory 5558-1 - Two security vulnerabilities have been discovered in Netty, a Java NIO client/server socket framework.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Debian Linux Security Advisory 5558-1 - Two security vulnerabilities have been discovered in Netty, a Java NIO client/server socket framework.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-7345-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7345-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175799/RHSA-2023-7345-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175799/RHSA-2023-7345-01.txt",
                "id": "https://packetstormsecurity.com/files/175799/RHSA-2023-7345-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175799/Red-Hat-Security-Advisory-2023-7345-01.html",
                "published": "Mon, 20 Nov 2023 16:06:05 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 20, 16, 6, 5, 0, 324, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-7345-01 - An update is now available for Red Hat OpenShift GitOps 1.9. Issues addressed include a denial of service vulnerability.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7345-01 - An update is now available for Red Hat OpenShift GitOps 1.9. Issues addressed include a denial of service vulnerability.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-7344-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7344-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175798/RHSA-2023-7344-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175798/RHSA-2023-7344-01.txt",
                "id": "https://packetstormsecurity.com/files/175798/RHSA-2023-7344-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175798/Red-Hat-Security-Advisory-2023-7344-01.html",
                "published": "Mon, 20 Nov 2023 16:05:52 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 20, 16, 5, 52, 0, 324, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-7344-01 - An update for openshift-gitops-kam is now available for Red Hat OpenShift GitOps 1.9. Issues addressed include a denial of service vulnerability.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7344-01 - An update for openshift-gitops-kam is now available for Red Hat OpenShift GitOps 1.9. Issues addressed include a denial of service vulnerability.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-6837-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-6837-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175797/RHSA-2023-6837-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175797/RHSA-2023-6837-01.txt",
                "id": "https://packetstormsecurity.com/files/175797/RHSA-2023-6837-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175797/Red-Hat-Security-Advisory-2023-6837-01.html",
                "published": "Mon, 20 Nov 2023 16:05:28 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 20, 16, 5, 28, 0, 324, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-6837-01 - Red Hat OpenShift Container Platform release 4.14.2 is now available with updates to packages and images that fix several bugs and add enhancements. Issues addressed include a cross site scripting vulnerability.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-6837-01 - Red Hat OpenShift Container Platform release 4.14.2 is now available with updates to packages and images that fix several bugs and add enhancements. Issues addressed include a cross site scripting vulnerability.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6485-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6485-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175795/USN-6485-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175795/USN-6485-1.txt",
                "id": "https://packetstormsecurity.com/files/175795/USN-6485-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175795/Ubuntu-Security-Notice-USN-6485-1.html",
                "published": "Fri, 17 Nov 2023 15:10:05 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 17, 15, 10, 5, 4, 321, 0)
                ),
                "summary": "Ubuntu Security Notice 6485-1 - Benoit Morgan, Paul Grosen, Thais Moreira Hamasaki, Ke Sun, Alyssa Milburn, Hisham Shafi, Nir Shlomovich, Tavis Ormandy, Daniel Moghimi, Josh Eads, Salman Qazi, Alexandra Sandulescu, Andy Nguyen, Eduardo Vela, Doug Kwan, and Kostik Shtoyk discovered that some Intel Processors did not properly handle certain sequences of processor instructions. A local attacker could possibly use this to cause a core hang , gain access to sensitive information or possibly escalate their privileges.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6485-1 - Benoit Morgan, Paul Grosen, Thais Moreira Hamasaki, Ke Sun, Alyssa Milburn, Hisham Shafi, Nir Shlomovich, Tavis Ormandy, Daniel Moghimi, Josh Eads, Salman Qazi, Alexandra Sandulescu, Andy Nguyen, Eduardo Vela, Doug Kwan, and Kostik Shtoyk discovered that some Intel Processors did not properly handle certain sequences of processor instructions. A local attacker could possibly use this to cause a core hang , gain access to sensitive information or possibly escalate their privileges.",
                },
                "tags": [],
            },
            {
                "title": "Debian Security Advisory 5557-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Debian Security Advisory 5557-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175794/dsa-5557-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175794/dsa-5557-1.txt",
                "id": "https://packetstormsecurity.com/files/175794/dsa-5557-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175794/Debian-Security-Advisory-5557-1.html",
                "published": "Fri, 17 Nov 2023 15:09:01 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 17, 15, 9, 1, 4, 321, 0)
                ),
                "summary": "Debian Linux Security Advisory 5557-1 - WebKitGTK has vulnerabilities. Junsung Lee discovered that processing web content may lead to a denial-of-service. An anonymous researcher discovered that processing web content may lead to arbitrary code execution.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Debian Linux Security Advisory 5557-1 - WebKitGTK has vulnerabilities. Junsung Lee discovered that processing web content may lead to a denial-of-service. An anonymous researcher discovered that processing web content may lead to arbitrary code execution.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-7342-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7342-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175792/RHSA-2023-7342-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175792/RHSA-2023-7342-01.txt",
                "id": "https://packetstormsecurity.com/files/175792/RHSA-2023-7342-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175792/Red-Hat-Security-Advisory-2023-7342-01.html",
                "published": "Fri, 17 Nov 2023 15:06:09 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 17, 15, 6, 9, 4, 321, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-7342-01 - An update for cnf-tests-container, dpdk-base-container and performance-addon-operator-must-gather-rhel8-container is now available for Red Hat OpenShift Container Platform 4.11. Secondary scheduler builds and numaresources-operator are also available for technical preview with this release, however they are not intended for production.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7342-01 - An update for cnf-tests-container, dpdk-base-container and performance-addon-operator-must-gather-rhel8-container is now available for Red Hat OpenShift Container Platform 4.11. Secondary scheduler builds and numaresources-operator are also available for technical preview with this release, however they are not intended for production.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-7335-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7335-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175791/RHSA-2023-7335-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175791/RHSA-2023-7335-01.txt",
                "id": "https://packetstormsecurity.com/files/175791/RHSA-2023-7335-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175791/Red-Hat-Security-Advisory-2023-7335-01.html",
                "published": "Fri, 17 Nov 2023 15:05:50 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 17, 15, 5, 50, 4, 321, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-7335-01 - An update is now available for Red Hat Process Automation Manager including images for Red Hat OpenShift Container Platform. Issues addressed include a denial of service vulnerability.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7335-01 - An update is now available for Red Hat Process Automation Manager including images for Red Hat OpenShift Container Platform. Issues addressed include a denial of service vulnerability.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-7334-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7334-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175790/RHSA-2023-7334-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175790/RHSA-2023-7334-01.txt",
                "id": "https://packetstormsecurity.com/files/175790/RHSA-2023-7334-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175790/Red-Hat-Security-Advisory-2023-7334-01.html",
                "published": "Fri, 17 Nov 2023 15:05:32 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 17, 15, 5, 32, 4, 321, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-7334-01 - An update for rh-varnish6-varnish is now available for Red Hat Software Collections. Issues addressed include a denial of service vulnerability.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-7334-01 - An update for rh-varnish6-varnish is now available for Red Hat Software Collections. Issues addressed include a denial of service vulnerability.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-6842-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-6842-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175789/RHSA-2023-6842-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175789/RHSA-2023-6842-01.txt",
                "id": "https://packetstormsecurity.com/files/175789/RHSA-2023-6842-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175789/Red-Hat-Security-Advisory-2023-6842-01.html",
                "published": "Fri, 17 Nov 2023 15:05:17 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 17, 15, 5, 17, 4, 321, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-6842-01 - Red Hat OpenShift Container Platform release 4.12.43 is now available with updates to packages and images that fix several bugs and add enhancements.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-6842-01 - Red Hat OpenShift Container Platform release 4.12.43 is now available with updates to packages and images that fix several bugs and add enhancements.",
                },
                "tags": [],
            },
            {
                "title": "Red Hat Security Advisory 2023-6841-01",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-6841-01",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175788/RHSA-2023-6841-01.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175788/RHSA-2023-6841-01.txt",
                "id": "https://packetstormsecurity.com/files/175788/RHSA-2023-6841-01.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175788/Red-Hat-Security-Advisory-2023-6841-01.html",
                "published": "Fri, 17 Nov 2023 15:05:03 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 17, 15, 5, 3, 4, 321, 0)
                ),
                "summary": "Red Hat Security Advisory 2023-6841-01 - An update is now available for Red Hat OpenShift Container Platform 4.12.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Red Hat Security Advisory 2023-6841-01 - An update is now available for Red Hat OpenShift Container Platform 4.12.",
                },
                "tags": [],
            },
            {
                "title": "Ubuntu Security Notice USN-6484-1",
                "title_detail": {
                    "type": "text/plain",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice USN-6484-1",
                },
                "links": [
                    {
                        "rel": "alternate",
                        "type": "text/html",
                        "href": "https://packetstormsecurity.com/files/175786/USN-6484-1.txt",
                    }
                ],
                "link": "https://packetstormsecurity.com/files/175786/USN-6484-1.txt",
                "id": "https://packetstormsecurity.com/files/175786/USN-6484-1.txt",
                "guidislink": False,
                "comments": "https://packetstormsecurity.com/files/175786/Ubuntu-Security-Notice-USN-6484-1.html",
                "published": "Thu, 16 Nov 2023 14:53:07 GMT",
                "published_parsed": time.struct_time(
                    (2023, 11, 16, 14, 53, 7, 3, 320, 0)
                ),
                "summary": "Ubuntu Security Notice 6484-1 - It was discovered that OpenVPN incorrectly handled the --fragment option in certain configurations. A remote attacker could possibly use this issue to cause OpenVPN to crash, resulting in a denial of service. It was discovered that OpenVPN incorrectly handled certain memory operations. A remote attacker could use this issue to cause OpenVPN to crash, obtain sensitive information, or possibly execute arbitrary code.",
                "summary_detail": {
                    "type": "text/html",
                    "language": None,
                    "base": "",
                    "value": "Ubuntu Security Notice 6484-1 - It was discovered that OpenVPN incorrectly handled the --fragment option in certain configurations. A remote attacker could possibly use this issue to cause OpenVPN to crash, resulting in a denial of service. It was discovered that OpenVPN incorrectly handled certain memory operations. A remote attacker could use this issue to cause OpenVPN to crash, obtain sensitive information, or possibly execute arbitrary code.",
                },
                "tags": [],
            },
        ]

        ret = collector.fetch_new_feed_entries(url, Snippet.Source.FEED_PACKETSTORM)
        assert len(expected_ret) == len(ret)
        ret = [dict(x) for x in ret]
        assert ret == expected_ret

    def test_prune_new_raw_feed_entries(self):
        collector = FeedCollector()

        raw_feed_entries = [
            FeedParserDict(
                {
                    "title": "Entry With Summary",
                    "summary": "Lorem <b>Ipsum</b>",
                    "title_detail": {
                        "type": "text/plain",
                        "language": None,
                        "base": "",
                        "value": "OpenSSL Recent Security Patches",
                    },
                    "links": [
                        {
                            "rel": "alternate",
                            "type": "text/html",
                            "href": "https://nodejs.org/en/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                        }
                    ],
                    "link": "https://nodejs.org/en/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                    "id": "/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                    "guidislink": False,
                    "published": "Thu, 26 Oct 2023 17:00:15 GMT",
                }
            ),
            FeedParserDict(
                {
                    "title": "Entry Without Summary",
                    "title_detail": {
                        "type": "text/plain",
                        "language": None,
                        "base": "",
                        "value": "Friday October 13 2023 Security Releases",
                    },
                    "links": [
                        {
                            "rel": "alternate",
                            "type": "text/html",
                            "href": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                        }
                    ],
                    "link": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                    "id": "/blog/vulnerability/october-2023-security-releases",
                    "guidislink": False,
                    "published": "Fri, 13 Oct 2023 13:30:00 GMT",
                }
            ),
            FeedParserDict(
                {
                    "title": "Lorem Red Hat Security Advisory Ipsum",
                    "title_detail": {
                        "type": "text/plain",
                        "language": None,
                        "base": "",
                        "value": "Friday October 13 2023 Security Releases",
                    },
                    "links": [
                        {
                            "rel": "alternate",
                            "type": "text/html",
                            "href": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                        }
                    ],
                    "link": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                    "id": "/blog/vulnerability/october-2023-security-releases",
                    "guidislink": False,
                    "published": "Fri, 13 Oct 2023 13:30:00 GMT",
                }
            ),
        ]

        expected_ret = raw_feed_entries[:2]
        assert (
            collector.prune_new_raw_feed_entries(
                raw_feed_entries, skip_entry_title_regex=None
            )
            == expected_ret
        )

        expected_ret = raw_feed_entries[:1]
        assert (
            collector.prune_new_raw_feed_entries(
                raw_feed_entries, skip_entry_title_regex="out S.m"
            )
            == expected_ret
        )

    @pytest.mark.default_cassette("TestFeedCollector.test_smoke_test.yaml")
    @pytest.mark.vcr
    def test_get_summaries_for_raw_feed_entries(self):
        collector = FeedCollector()

        pruned_raw_feed_entries = [
            FeedParserDict(
                {
                    "title": "Entry With Summary",
                    "summary": "Lorem <b>Ipsum</b>",
                    "title_detail": {
                        "type": "text/plain",
                        "language": None,
                        "base": "",
                        "value": "OpenSSL Recent Security Patches",
                    },
                    "links": [
                        {
                            "rel": "alternate",
                            "type": "text/html",
                            "href": "https://nodejs.org/en/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                        }
                    ],
                    "link": "https://nodejs.org/en/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                    "id": "/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                    "guidislink": False,
                    "published": "Thu, 26 Oct 2023 17:00:15 GMT",
                }
            ),
            FeedParserDict(
                {
                    "title": "Entry Without Summary",
                    "title_detail": {
                        "type": "text/plain",
                        "language": None,
                        "base": "",
                        "value": "Friday October 13 2023 Security Releases",
                    },
                    "links": [
                        {
                            "rel": "alternate",
                            "type": "text/html",
                            "href": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                        }
                    ],
                    "link": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                    "id": "/blog/vulnerability/october-2023-security-releases",
                    "guidislink": False,
                    "published": "Fri, 13 Oct 2023 13:30:00 GMT",
                }
            ),
        ]

        expected_ret = [
            (pruned_raw_feed_entries[0], "Lorem <b>Ipsum</b>"),
            (pruned_raw_feed_entries[1], None),
        ]
        assert (
            collector.get_summaries_for_raw_feed_entries(
                pruned_raw_feed_entries,
                entry_url_replace=[],
                entry_separate_links=False,
                entry_text_in_html=False,
            )
            == expected_ret
        )

        expected_ret = [
            (pruned_raw_feed_entries[0], "Lorem Ipsum"),
            (pruned_raw_feed_entries[1], None),
        ]
        assert (
            collector.get_summaries_for_raw_feed_entries(
                pruned_raw_feed_entries,
                entry_url_replace=[],
                entry_separate_links=False,
                entry_text_in_html=True,
            )
            == expected_ret
        )

        expected_cutout_1 = " OpenSSL Security Advisories of:\n\n     * OpenSSL 3.0.11 - Tuesday 19th September 2023\n     * OpenSSL 3.0.12 - Tuesday 24th October 2023\n\n   Node.js (Windows) is affected by one vulnerability rated as LOW.\n   Therefore, these patches will be released "
        expected_cutout_2 = "lable\n\n   Updates are now available for the v18.x and v20.x Node.js release lines\n   for the following issues.\n\nundici - Cookie headers are not cleared in cross-domain redirect in undici-fetch\n(Low) - (CVE-2023-45143)\n\n   Undici did not always clear "
        ret = collector.get_summaries_for_raw_feed_entries(
            pruned_raw_feed_entries,
            entry_url_replace=[],
            entry_separate_links=True,
            entry_text_in_html=True,
        )
        assert ret[0][0] == pruned_raw_feed_entries[0]
        assert ret[0][1][500:750] == expected_cutout_1
        assert ret[1][0] == pruned_raw_feed_entries[1]
        assert ret[1][1][500:750] == expected_cutout_2

    def test_filter_feed_entries_with_summaries(self):
        collector = FeedCollector()

        raw_entries_w_summaries = [
            (
                FeedParserDict(
                    {
                        "title": "Entry With Allowed Summary",
                        "title_detail": {
                            "type": "text/plain",
                            "language": None,
                            "base": "",
                            "value": "OpenSSL Recent Security Patches",
                        },
                        "links": [
                            {
                                "rel": "alternate",
                                "type": "text/html",
                                "href": "https://nodejs.org/en/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                            }
                        ],
                        "link": "https://nodejs.org/en/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                        "id": "/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                        "guidislink": False,
                        "published": "Thu, 26 Oct 2023 17:00:15 GMT",
                    }
                ),
                "Lorem Ipsum",
            ),
            (
                FeedParserDict(
                    {
                        "title": "Entry With Disallowed Summary",
                        "title_detail": {
                            "type": "text/plain",
                            "language": None,
                            "base": "",
                            "value": "Friday October 13 2023 Security Releases",
                        },
                        "links": [
                            {
                                "rel": "alternate",
                                "type": "text/html",
                                "href": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                            }
                        ],
                        "link": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                        "id": "/blog/vulnerability/october-2023-security-releases",
                        "guidislink": False,
                        "published": "Fri, 13 Oct 2023 13:30:00 GMT",
                    }
                ),
                "Lorem IBM Notes Ipsum",
            ),
        ]
        expected_ret = raw_entries_w_summaries[:1]

        assert (
            collector.filter_feed_entries_with_summaries(raw_entries_w_summaries)
            == expected_ret
        )

    def test_prepare_data_for_eligible_feed_entries(self):

        collector = FeedCollector()

        filtered_raw_entries_w_summaries = [
            (
                FeedParserDict(
                    {
                        "title": "Entry With No Summary",
                        "title_detail": {
                            "type": "text/plain",
                            "language": None,
                            "base": "",
                            "value": "OpenSSL Recent Security Patches",
                        },
                        "links": [
                            {
                                "rel": "alternate",
                                "type": "text/html",
                                "href": "https://nodejs.org/en/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                            }
                        ],
                        "link": "https://nodejs.org/en/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                        "id": "/blog/vulnerability/openssl-fixes-in-regular-releases-oct2023",
                        "guidislink": False,
                        "published": "Thu, 26 Oct 2023 17:00:15 GMT",
                    }
                ),
                "",
            ),
            (
                FeedParserDict(
                    {
                        "title": "Entry With Summary",
                        "title_detail": {
                            "type": "text/plain",
                            "language": None,
                            "base": "",
                            "value": "Friday October 13 2023 Security Releases",
                        },
                        "links": [
                            {
                                "rel": "alternate",
                                "type": "text/html",
                                "href": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                            }
                        ],
                        "link": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                        "id": "/blog/vulnerability/october-2023-security-releases",
                        "guidislink": False,
                        "published": "Fri, 13 Oct 2023 13:30:00 GMT",
                    }
                ),
                """Summary Test Content Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla dapibus diam vitae orci pretium, at laoreet lectus laoreet. Foobar buffer overflow generator doesn't sufficiently sanitize url spoofing permission check bypass when performing out-of-bounds write to local file with no warning to test PHRASE_TO_CWE_MAP as well. Sed sit amet CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N lectus CVE-2021-34363 turpis. Morbi ut felis ac orci posuere tempus. Curabitur vehicula ligula ac ipsum gravida tristique.""",
            ),
        ]

        expected_ret = [
            {
                "cve_ids": ["CVE-2021-34363"],
                "title": "Entry With Summary",
                "description": "Summary Test Content Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla dapibus diam vitae orci pretium, at laoreet lectus laoreet. Foobar buffer overflow generator doesn't sufficiently sanitize url spoofing permission check bypass when performing out-of-bounds write to local file with no warning to test PHRASE_TO_CWE_MAP as well. Sed sit amet CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N lectus CVE-2021-34363 turpis. Morbi ut felis ac orci posuere tempus. Curabitur vehicula ligula ac ipsum gravida tristique.",
                "cwe_id": "(CWE-120|CWE-451|CWE-552|CWE-787|CWE-829)",
                "cvss3": {
                    "score": "4.4",
                    "vector": "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N",
                },
                "references": [
                    {
                        "url": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                        "type": "SOURCE",
                    }
                ],
                "components": ["nodejs", "nodejs010 - nodejs"],
                "url": "https://nodejs.org/en/blog/vulnerability/october-2023-security-releases",
                "create_flaws": True,
            }
        ]

        assert (
            collector.prepare_data_for_eligible_feed_entries(
                filtered_raw_entries_w_summaries,
                components=["nodejs", "nodejs010 - nodejs"],
            )
            == expected_ret
        )

    @pytest.mark.default_cassette("TestFeedCollector.test_smoke_test.yaml")
    @pytest.mark.vcr
    def test_get_linked_text(self):
        collector = FeedCollector()
        entry_url = "https://packetstormsecurity.com/files/175820/USN-6492-1.txt"
        entry_url_replace = [["/files", "/files/download"]]
        entry_separate_links = True
        expected_ret_150 = "==========================================================================\nUbuntu Security Notice USN-6492-1\nNovember 21, 2023\n\nmosquitto vulnerabilit"
        assert (
            collector.get_linked_text(
                entry_url, entry_url_replace, entry_separate_links
            )[:150]
            == expected_ret_150
        )
