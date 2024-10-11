import pytest
from rest_framework import status

from osidb.models.package_versions import Package, PackageVer
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PackageFactory,
    PackageVerFactory,
)

pytestmark = pytest.mark.unit


class TestEndpointsFlawsPackageVersions:
    """
    tests specific to /flaws/.../package_versions endpoint
    """

    def test_packageversions_filter(self, auth_client, test_api_uri):
        """
        Test the non-trivial parts of FlawPackageVersionFilter via REST API GET requests.
        """
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)

        package_versions1 = PackageFactory(package="foobar", flaw=flaw)
        package_versions2 = PackageFactory(package="bazfoo", flaw=flaw)
        version1a = PackageVerFactory(package=package_versions1, version="1.2.3.4")
        version2a = PackageVerFactory(package=package_versions1, version="2.3.4.5")
        version1b = PackageVerFactory(package=package_versions2, version="1.2.3.4")
        version2b = PackageVerFactory(package=package_versions2, version="2.3.4.5")
        package_versions3 = PackageFactory(package="fobr", flaw=flaw)
        version3 = PackageVerFactory(package=package_versions3, version="3.4.5.6")

        # Only the package matching the filtered version is returned
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions?versions__version={version3.version}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["package"] == package_versions3.package
        assert len(response.data["results"][0]["versions"]) == 1
        assert response.data["results"][0]["versions"][0]["version"] == version3.version

        # The whole Package object including all linked versions is returned for the matching
        # filter, even if the filter is for a single version.
        # Filters are chained with logical AND (only 1 package is returned even though that version
        # matches 2 packages).
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions?package={package_versions1.package}&versions__version={version1a.version}"
        )
        assert response.status_code == status.HTTP_200_OK
        expected_vers = {version1a.version, version2a.version}
        response_vers = set()
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["package"] == package_versions1.package
        assert len(response.data["results"][0]["versions"]) == 2
        response_vers.add(response.data["results"][0]["versions"][0]["version"])
        response_vers.add(response.data["results"][0]["versions"][1]["version"])
        assert response_vers == expected_vers
        assert (
            response.data["results"][0]["versions"]
            == [
                {
                    "version": version1a.version,
                },
                {
                    "version": version2a.version,
                },
            ]
        ) or (
            response.data["results"][0]["versions"]
            == [
                {
                    "version": version2a.version,
                },
                {
                    "version": version1a.version,
                },
            ]
        )

        # All packages that have the specified version are returned, including their other versions.
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions?versions__version={version2b.version}"
        )
        assert response.status_code == status.HTTP_200_OK
        expected_pkgs = set([package_versions1.package, package_versions2.package])
        response_pkgs = set()
        expected_vers = set([version1b.version, version2b.version])
        response_vers1 = set()
        response_vers2 = set()

        assert len(response.data["results"]) == 2
        response_pkgs.add(response.data["results"][0]["package"])
        response_pkgs.add(response.data["results"][1]["package"])
        assert expected_pkgs == response_pkgs

        assert len(response.data["results"][0]["versions"]) == 2
        response_vers1.add(response.data["results"][0]["versions"][0]["version"])
        response_vers1.add(response.data["results"][0]["versions"][1]["version"])
        assert response_vers1 == expected_vers

        assert len(response.data["results"][1]["versions"]) == 2
        response_vers2.add(response.data["results"][1]["versions"][0]["version"])
        response_vers2.add(response.data["results"][1]["versions"][1]["version"])
        assert response_vers2 == expected_vers

    def test_packageversions_create(self, auth_client, test_api_uri):
        """
        Test the creation of Package and PackageVer records via a REST API PUT request.
        """
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)

        packageversions_data = {
            "package": "foobar",
            "versions": [
                {
                    "version": "1",
                },
                {
                    "version": "2.2",
                },
                {
                    "version": "3.3-3.3",
                },
            ],
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/package_versions
        response = auth_client().post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions",
            packageversions_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        packageversion_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/package_versions
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/package_versions/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions/{packageversion_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == packageversion_uuid

        assert response.data["package"] == "foobar"
        expected_vers = {"1", "2.2", "3.3-3.3"}
        response_vers = {v["version"] for v in response.data["versions"]}
        assert expected_vers == response_vers

    @pytest.mark.parametrize(
        "correct_timestamp",
        [
            True,
            False,
        ],
    )
    def test_packageversions_update(self, auth_client, test_api_uri, correct_timestamp):
        """
        Test the update of Package and PackageVer records via a REST API PUT request.
        """
        GROUND_STATE = {
            "foobar": {"1.2.3.4", "2.3.4.5"},
            "bazfoo": {"1.2.3.4", "2.3.4.5"},
            "fobr": {"3.4.5.6"},
        }

        def extract_packages_versions(response):
            return {
                response.data["results"][i]["package"]: {
                    x["version"] for x in response.data["results"][i]["versions"]
                }
                for i in range(len(response.data["results"]))
            }

        flaw = FlawFactory()
        AffectFactory(flaw=flaw)

        package_versions1 = PackageFactory(package="foobar", flaw=flaw)
        package_versions2 = PackageFactory(package="bazfoo", flaw=flaw)
        PackageVerFactory(package=package_versions1, version="1.2.3.4")
        PackageVerFactory(package=package_versions1, version="2.3.4.5")
        PackageVerFactory(package=package_versions2, version="1.2.3.4")
        PackageVerFactory(package=package_versions2, version="2.3.4.5")
        package_versions3 = PackageFactory(package="fobr", flaw=flaw)
        PackageVerFactory(package=package_versions3, version="3.4.5.6")

        # Ensure that when TrackingMixin.save() runs, db_self is not None.
        flaw.save()
        package_versions1.save()
        package_versions2.save()
        package_versions3.save()

        # Test that the ground state before modifications is correctly represented via API
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 3
        returned_data = extract_packages_versions(response)
        assert returned_data == GROUND_STATE

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions/{package_versions3.uuid}"

        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Reusing the response for the next query so as to get the correct updated_dt
        updated_data = {
            k: v for k, v in response.json().items() if k in ["embargoed", "updated_dt"]
        }
        if not correct_timestamp:
            updated_data["updated_dt"] = "2023-09-14T11:28:33Z"
        updated_data["package"] = "foobar"  # Note the change of the package name.
        updated_data["versions"] = [
            {
                "version": "4.5.6.7",
            },
        ]

        # Tests "PUT" on flaws/{uuid}/package_versions
        response = auth_client().put(
            url,
            {**updated_data},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        if correct_timestamp:
            assert response.status_code == status.HTTP_200_OK
            packageversion_uuid = response.data["uuid"]

            # Test that the "fobr" package was deleted and the version list
            # of the "foobar" package was replaced according to the request.
            response = auth_client().get(
                f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
            )
            assert response.status_code == status.HTTP_200_OK
            assert len(response.data["results"]) == 2
            returned_data = extract_packages_versions(response)
            assert returned_data == {
                "foobar": {"4.5.6.7"},
                "bazfoo": {"1.2.3.4", "2.3.4.5"},
            }

            # Test that the UUID of the Package changed to the UUID of the foobar package.
            assert packageversion_uuid == str(package_versions1.uuid)
        else:  # if not correct_timestamp:
            assert response.status_code == status.HTTP_400_BAD_REQUEST

            # Test that no changes were made
            response = auth_client().get(
                f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
            )
            assert response.status_code == status.HTTP_200_OK
            assert len(response.data["results"]) == 3
            returned_data = extract_packages_versions(response)
            assert returned_data == GROUND_STATE

    def test_packageversions_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of Package and PackageVer records via a REST API PUT request.
        """
        flaw = FlawFactory()

        # Necessary for Flaw validation
        AffectFactory(flaw=flaw)

        package_versions1 = PackageFactory(package="foobar", flaw=flaw)
        PackageVerFactory(package=package_versions1, version="1.2.3.4")
        PackageVerFactory(package=package_versions1, version="2.3.4.5")

        # Tests "GET" on flaws/{uuid}/package_versions
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        assert Package.objects.all().count() == 1
        assert PackageVer.objects.all().count() == 2

        # Tests "DELETE" on flaws/{uuid}/package_versions/{uuid}
        response = auth_client().delete(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/package_versions/{package_versions1.uuid}",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert Package.objects.all().count() == 0
        assert PackageVer.objects.all().count() == 0
