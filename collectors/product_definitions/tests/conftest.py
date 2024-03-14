import pytest


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    pass


@pytest.fixture(autouse=True)
def pin_envs(monkeypatch) -> None:
    """
    the tests should be immune to what .env you build the testrunner with
    """
    monkeypatch.setenv(
        "PRODUCT_DEF_URL", "https://example.com/prodsec/product-definitions"
    )


@pytest.fixture
def product_definition_url():
    return "https://example.com/prodsec/product-definitions/-/jobs/artifacts/master/raw/products.json"
