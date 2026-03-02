import base64
from dataclasses import dataclass

import pytest

from clouddicted_keycloak_config_operator.secrets import (
    DEFAULT_PASSWORD_KEY,
    DEFAULT_USERNAME_KEY,
    SecretCredentials,
    SecretDataMissingError,
    SecretKeyMissingError,
    SecretRefNameMissingError,
    SecretRefNamespaceMissingError,
    SecretValueDecodeError,
    load_secret_credentials,
)


@dataclass
class FakeSecret:
    data: dict[str, str] | None


class FakeCoreV1Api:
    def __init__(self, secrets: dict[tuple[str, str], FakeSecret]) -> None:
        self.secrets = secrets
        self.calls: list[tuple[str, str]] = []

    def read_namespaced_secret(self, *, name: str, namespace: str) -> FakeSecret:
        self.calls.append((namespace, name))
        return self.secrets[(namespace, name)]


def test_load_secret_credentials_uses_resource_namespace_and_default_keys() -> None:
    client = FakeCoreV1Api(
        {
            ("apps", "keycloak-admin"): FakeSecret(
                data={
                    DEFAULT_USERNAME_KEY: _b64("admin"),
                    DEFAULT_PASSWORD_KEY: _b64("secret-password"),
                },
            ),
        }
    )

    credentials = load_secret_credentials(
        client,
        "apps",
        {"name": "keycloak-admin"},
    )

    assert credentials == SecretCredentials(
        username="admin",
        password="secret-password",
        secret_namespace="apps",
        secret_name="keycloak-admin",
        username_key=DEFAULT_USERNAME_KEY,
        password_key=DEFAULT_PASSWORD_KEY,
    )
    assert client.calls == [("apps", "keycloak-admin")]


def test_load_secret_credentials_uses_explicit_namespace_and_keys() -> None:
    client = FakeCoreV1Api(
        {
            ("security", "keycloak-admin"): FakeSecret(
                data={
                    "admin-user": _b64("kc-admin"),
                    "admin-password": _b64("kc-password"),
                },
            ),
        }
    )

    credentials = load_secret_credentials(
        client,
        "apps",
        {
            "name": "keycloak-admin",
            "namespace": "security",
            "usernameKey": "admin-user",
            "passwordKey": "admin-password",
        },
    )

    assert credentials.username == "kc-admin"
    assert credentials.password == "kc-password"
    assert credentials.secret_namespace == "security"
    assert credentials.username_key == "admin-user"
    assert credentials.password_key == "admin-password"
    assert client.calls == [("security", "keycloak-admin")]


def test_load_secret_credentials_requires_secret_name() -> None:
    client = FakeCoreV1Api({})

    with pytest.raises(SecretRefNameMissingError, match="secretRef.name is required"):
        load_secret_credentials(client, "apps", {})


def test_load_secret_credentials_requires_namespace_when_resource_namespace_missing() -> None:
    client = FakeCoreV1Api({})

    with pytest.raises(SecretRefNamespaceMissingError, match="resource namespace is missing"):
        load_secret_credentials(client, None, {"name": "keycloak-admin"})


def test_load_secret_credentials_requires_secret_data() -> None:
    client = FakeCoreV1Api({("apps", "keycloak-admin"): FakeSecret(data=None)})

    with pytest.raises(SecretDataMissingError, match="apps/keycloak-admin"):
        load_secret_credentials(client, "apps", {"name": "keycloak-admin"})


def test_load_secret_credentials_requires_username_key() -> None:
    client = FakeCoreV1Api(
        {
            ("apps", "keycloak-admin"): FakeSecret(
                data={DEFAULT_PASSWORD_KEY: _b64("secret-password")},
            ),
        }
    )

    with pytest.raises(SecretKeyMissingError, match="'username'"):
        load_secret_credentials(client, "apps", {"name": "keycloak-admin"})


def test_load_secret_credentials_requires_password_key() -> None:
    client = FakeCoreV1Api(
        {
            ("apps", "keycloak-admin"): FakeSecret(
                data={DEFAULT_USERNAME_KEY: _b64("admin")},
            ),
        }
    )

    with pytest.raises(SecretKeyMissingError, match="'password'"):
        load_secret_credentials(client, "apps", {"name": "keycloak-admin"})


def test_load_secret_credentials_rejects_invalid_base64() -> None:
    client = FakeCoreV1Api(
        {
            ("apps", "keycloak-admin"): FakeSecret(
                data={
                    DEFAULT_USERNAME_KEY: "not-base64",
                    DEFAULT_PASSWORD_KEY: _b64("secret-password"),
                },
            ),
        }
    )

    with pytest.raises(SecretValueDecodeError, match="'username'"):
        load_secret_credentials(client, "apps", {"name": "keycloak-admin"})


def test_load_secret_credentials_rejects_non_utf8_secret_value() -> None:
    client = FakeCoreV1Api(
        {
            ("apps", "keycloak-admin"): FakeSecret(
                data={
                    DEFAULT_USERNAME_KEY: base64.b64encode(b"\xff").decode("ascii"),
                    DEFAULT_PASSWORD_KEY: _b64("secret-password"),
                },
            ),
        }
    )

    with pytest.raises(SecretValueDecodeError, match="base64 UTF-8"):
        load_secret_credentials(client, "apps", {"name": "keycloak-admin"})


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")
