"""Kubernetes Secret loading helpers."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

DEFAULT_USERNAME_KEY = "username"
DEFAULT_PASSWORD_KEY = "password"
DEFAULT_CLIENT_SECRET_KEY = "clientSecret"


class SecretRefError(ValueError):
    """Base error for invalid or unreadable Secret references."""


class SecretRefNameMissingError(SecretRefError):
    """Raised when a Secret reference does not include a Secret name."""


class SecretRefNamespaceMissingError(SecretRefError):
    """Raised when neither the Secret reference nor resource has a namespace."""


class SecretDataMissingError(SecretRefError):
    """Raised when the referenced Secret has no data mapping."""


class SecretKeyMissingError(SecretRefError):
    """Raised when the referenced Secret data does not include a required key."""


class SecretValueDecodeError(SecretRefError):
    """Raised when a Secret value cannot be decoded from base64 UTF-8."""


@dataclass(frozen=True)
class SecretCredentials:
    """Decoded username/password credentials from a Kubernetes Secret."""

    username: str
    password: str
    secret_namespace: str
    secret_name: str
    username_key: str
    password_key: str


@dataclass(frozen=True)
class SecretValue:
    """Decoded single value from a Kubernetes Secret."""

    value: str
    secret_namespace: str
    secret_name: str
    secret_key: str


def load_secret_credentials(
    core_v1_api: Any,
    resource_namespace: str | None,
    secret_ref: Mapping[str, Any],
) -> SecretCredentials:
    """Load and decode username/password credentials from a Kubernetes Secret."""
    secret_name = _required_string(secret_ref.get("name"))
    if secret_name is None:
        raise SecretRefNameMissingError("secretRef.name is required")

    secret_namespace = _optional_string(secret_ref.get("namespace"))
    if secret_namespace is None:
        secret_namespace = _optional_string(resource_namespace)
    if secret_namespace is None:
        raise SecretRefNamespaceMissingError(
            "secretRef.namespace is required when the resource namespace is missing"
        )

    username_key = _optional_string(secret_ref.get("usernameKey")) or DEFAULT_USERNAME_KEY
    password_key = _optional_string(secret_ref.get("passwordKey")) or DEFAULT_PASSWORD_KEY

    secret = core_v1_api.read_namespaced_secret(name=secret_name, namespace=secret_namespace)
    data = _secret_data(secret)
    if not data:
        raise SecretDataMissingError(
            f"Secret {secret_namespace}/{secret_name} does not contain data"
        )

    username = _decode_secret_value(
        data,
        key=username_key,
        secret_namespace=secret_namespace,
        secret_name=secret_name,
    )
    password = _decode_secret_value(
        data,
        key=password_key,
        secret_namespace=secret_namespace,
        secret_name=secret_name,
    )

    return SecretCredentials(
        username=username,
        password=password,
        secret_namespace=secret_namespace,
        secret_name=secret_name,
        username_key=username_key,
        password_key=password_key,
    )


def load_secret_value(
    core_v1_api: Any,
    resource_namespace: str | None,
    secret_ref: Mapping[str, Any],
    *,
    default_key: str,
) -> SecretValue:
    """Load and decode one value from a Kubernetes Secret."""
    secret_name = _required_string(secret_ref.get("name"))
    if secret_name is None:
        raise SecretRefNameMissingError("secretRef.name is required")

    secret_namespace = _optional_string(secret_ref.get("namespace"))
    if secret_namespace is None:
        secret_namespace = _optional_string(resource_namespace)
    if secret_namespace is None:
        raise SecretRefNamespaceMissingError(
            "secretRef.namespace is required when the resource namespace is missing"
        )

    secret_key = _optional_string(secret_ref.get("secretKey")) or default_key

    secret = core_v1_api.read_namespaced_secret(name=secret_name, namespace=secret_namespace)
    data = _secret_data(secret)
    if not data:
        raise SecretDataMissingError(
            f"Secret {secret_namespace}/{secret_name} does not contain data"
        )

    return SecretValue(
        value=_decode_secret_value(
            data,
            key=secret_key,
            secret_namespace=secret_namespace,
            secret_name=secret_name,
        ),
        secret_namespace=secret_namespace,
        secret_name=secret_name,
        secret_key=secret_key,
    )


def _secret_data(secret: Any) -> Mapping[str, str | None] | None:
    if isinstance(secret, Mapping):
        data = secret.get("data")
    else:
        data = getattr(secret, "data", None)

    return data if isinstance(data, Mapping) else None


def _decode_secret_value(
    data: Mapping[str, str | None],
    *,
    key: str,
    secret_namespace: str,
    secret_name: str,
) -> str:
    encoded_value = data.get(key)
    if encoded_value is None:
        raise SecretKeyMissingError(
            f"Secret {secret_namespace}/{secret_name} is missing required key {key!r}"
        )

    try:
        decoded_bytes = base64.b64decode(encoded_value, validate=True)
        return decoded_bytes.decode("utf-8")
    except (binascii.Error, TypeError, UnicodeDecodeError, ValueError) as exc:
        raise SecretValueDecodeError(
            f"Secret {secret_namespace}/{secret_name} key {key!r} is not valid base64 UTF-8"
        ) from exc


def _required_string(value: Any) -> str | None:
    parsed = _optional_string(value)
    return parsed if parsed else None


def _optional_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    stripped = value.strip()
    return stripped or None
