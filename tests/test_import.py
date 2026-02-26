from clouddicted_keycloak_config_operator.constants import OPERATOR_NAME


def test_package_imports() -> None:
    assert OPERATOR_NAME == "clouddicted-keycloak-config-operator"
