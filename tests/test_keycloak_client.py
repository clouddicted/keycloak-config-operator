from collections.abc import Callable
from urllib.parse import parse_qs

import httpx
import pytest

from clouddicted_keycloak_config_operator.keycloak_client import (
    AUTH_METHOD_CLIENT_CREDENTIALS,
    DEFAULT_CLIENT_ID,
    KeycloakAdminClient,
    KeycloakAuthenticationError,
    KeycloakNotAuthenticatedError,
    KeycloakRequestError,
    KeycloakResourceNotFoundError,
    KeycloakTokenResponseError,
)


def test_authenticate_stores_token_from_default_master_realm_endpoint() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert str(request.url) == (
            "https://keycloak.example.test/realms/master/protocol/openid-connect/token"
        )
        assert request.method == "POST"
        assert _form_data(request) == {
            "grant_type": ["password"],
            "client_id": [DEFAULT_CLIENT_ID],
            "username": ["admin"],
            "password": ["secret-password"],
        }
        return httpx.Response(200, json={"access_token": "access-token"})

    client = _client(handler, base_url="https://keycloak.example.test/")

    client.authenticate()

    assert client.base_url == "https://keycloak.example.test"
    assert len(requests) == 1


def test_authenticate_supports_client_credentials_grant() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert str(request.url) == (
            "https://keycloak.example.test/realms/master/protocol/openid-connect/token"
        )
        assert request.method == "POST"
        assert _form_data(request) == {
            "grant_type": ["client_credentials"],
            "client_id": ["operator-client"],
            "client_secret": ["client-secret-value"],
        }
        return httpx.Response(200, json={"access_token": "access-token"})

    client = _client(
        handler,
        auth_method=AUTH_METHOD_CLIENT_CREDENTIALS,
        client_id="operator-client",
        client_secret="client-secret-value",
    )

    client.authenticate()

    assert len(requests) == 1


def test_authenticate_rejects_malformed_token_response() -> None:
    client = _client(lambda _request: httpx.Response(200, json={"token_type": "Bearer"}))

    with pytest.raises(KeycloakTokenResponseError, match="access_token") as exc_info:
        client.authenticate()

    assert "secret-password" not in str(exc_info.value)


def test_authenticate_raises_clear_error_for_http_failure() -> None:
    client = _client(lambda _request: httpx.Response(401, json={"error": "invalid_grant"}))

    with pytest.raises(KeycloakAuthenticationError, match="HTTP 401") as exc_info:
        client.authenticate()

    assert "admin" not in str(exc_info.value)
    assert "secret-password" not in str(exc_info.value)


def test_request_requires_authentication_first() -> None:
    client = _client(lambda _request: httpx.Response(500))

    with pytest.raises(KeycloakNotAuthenticatedError, match="authenticate"):
        client.request("GET", "realms/master")


def test_request_sends_authorized_admin_api_get_and_returns_json() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "access-token"})

        assert request.method == "GET"
        assert str(request.url) == "https://keycloak.example.test/admin/realms/master"
        assert request.headers["authorization"] == "Bearer access-token"
        return httpx.Response(200, json={"realm": "master", "enabled": True})

    client = _client(handler)
    client.authenticate()

    payload = client.request("GET", "realms/master")

    assert payload == {"realm": "master", "enabled": True}
    assert len(requests) == 2


def test_request_returns_none_for_empty_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "access-token"})

        return httpx.Response(204)

    client = _client(handler)
    client.authenticate()

    assert client.request("DELETE", "/admin/realms/master/users/user-id") is None


def test_request_raises_clear_error_for_http_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "secret-token"})

        return httpx.Response(500, json={"error": "server failed"})

    client = _client(handler)
    client.authenticate()

    with pytest.raises(KeycloakRequestError, match="HTTP 500") as exc_info:
        client.request("GET", "realms/master")

    assert "secret-token" not in str(exc_info.value)
    assert "server failed" not in str(exc_info.value)


def test_request_raises_distinct_error_for_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "secret-token"})

        return httpx.Response(404, json={"error": "realm not found"})

    client = _client(handler)
    client.authenticate()

    with pytest.raises(KeycloakResourceNotFoundError, match="HTTP 404") as exc_info:
        client.request("GET", "realms/missing")

    assert "secret-token" not in str(exc_info.value)
    assert "realm not found" not in str(exc_info.value)


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    base_url: str = "https://keycloak.example.test",
    auth_method: str = "Password",
    client_id: str = DEFAULT_CLIENT_ID,
    client_secret: str | None = None,
) -> KeycloakAdminClient:
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    return KeycloakAdminClient(
        base_url=base_url,
        username="admin",
        password="secret-password",
        client_id=client_id,
        client_secret=client_secret,
        auth_method=auth_method,
        http_client=http_client,
    )


def _form_data(request: httpx.Request) -> dict[str, list[str]]:
    return parse_qs(request.content.decode("utf-8"))
