"""Small Keycloak Admin API client."""

from __future__ import annotations

from typing import Any

import httpx

DEFAULT_REALM = "master"
DEFAULT_CLIENT_ID = "admin-cli"


class KeycloakClientError(RuntimeError):
    """Base error raised by the Keycloak Admin API client."""


class KeycloakAuthenticationError(KeycloakClientError):
    """Raised when Keycloak token acquisition fails."""


class KeycloakRequestError(KeycloakClientError):
    """Raised when a Keycloak Admin API request fails."""


class KeycloakTokenResponseError(KeycloakClientError):
    """Raised when Keycloak returns an unusable token response."""


class KeycloakNotAuthenticatedError(KeycloakClientError):
    """Raised when an Admin API request is attempted before authentication."""


class KeycloakAdminClient:
    """Minimal synchronous wrapper for Keycloak Admin API requests."""

    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        realm: str = DEFAULT_REALM,
        client_id: str = DEFAULT_CLIENT_ID,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = _normalize_base_url(base_url)
        self.username = username
        self.password = password
        self.realm = realm
        self.client_id = client_id
        self._http_client = http_client or httpx.Client(timeout=10.0)
        self._token: str | None = None

    def authenticate(self) -> None:
        """Authenticate with username/password and store the bearer token in memory."""
        try:
            response = self._http_client.post(
                self._url(
                    f"realms/{self.realm}/protocol/openid-connect/token",
                ),
                data={
                    "grant_type": "password",
                    "client_id": self.client_id,
                    "username": self.username,
                    "password": self.password,
                },
            )
        except httpx.HTTPError as exc:
            raise KeycloakAuthenticationError("Keycloak authentication request failed") from exc

        if response.is_error:
            raise KeycloakAuthenticationError(
                f"Keycloak authentication failed with HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise KeycloakTokenResponseError("Keycloak token response was not valid JSON") from exc

        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise KeycloakTokenResponseError(
                "Keycloak token response did not include access_token"
            )

        self._token = token

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Any | None:
        """Send an authenticated request to the Keycloak Admin API."""
        if self._token is None:
            raise KeycloakNotAuthenticatedError(
                "authenticate() must be called before Keycloak Admin API requests"
            )

        request_headers = {"Authorization": f"Bearer {self._token}"}
        if headers:
            request_headers.update(headers)

        try:
            response = self._http_client.request(
                method,
                self._admin_url(path),
                headers=request_headers,
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise KeycloakRequestError("Keycloak Admin API request failed") from exc

        if response.is_error:
            raise KeycloakRequestError(
                f"Keycloak Admin API request failed with HTTP {response.status_code}"
            )

        if not response.content or not response.text.strip():
            return None

        try:
            return response.json()
        except ValueError as exc:
            raise KeycloakRequestError("Keycloak Admin API response was not valid JSON") from exc

    def _admin_url(self, path: str) -> str:
        clean_path = path.lstrip("/")
        if clean_path == "admin" or clean_path.startswith("admin/"):
            return self._url(clean_path)

        return self._url(f"admin/{clean_path}")

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"


def _normalize_base_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    if not normalized:
        raise ValueError("base_url is required")

    return normalized
