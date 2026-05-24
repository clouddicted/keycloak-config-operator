from copy import deepcopy

from clouddicted_keycloak_config_operator.redaction import (
    REDACTED_VALUE,
    redact_data,
    redact_text,
)


def test_redact_text_removes_configured_sensitive_values() -> None:
    message = "Keycloak request failed with password=secret-password"

    redacted = redact_text(message, ["secret-password"])

    assert redacted == f"Keycloak request failed with password={REDACTED_VALUE}"
    assert "secret-password" not in redacted


def test_redact_data_removes_nested_configured_sensitive_values() -> None:
    data = {
        "message": "failed with token nested-secret",
        "details": [
            "plain",
            ("nested-secret",),
            {"errors": {"prefix nested-secret suffix"}},
        ],
        "seen": {"nested-secret"},
    }

    redacted = redact_data(data, ["nested-secret"])

    assert redacted == {
        "message": f"failed with token {REDACTED_VALUE}",
        "details": [
            "plain",
            (REDACTED_VALUE,),
            {"errors": {f"prefix {REDACTED_VALUE} suffix"}},
        ],
        "seen": {REDACTED_VALUE},
    }
    assert "nested-secret" not in repr(redacted)


def test_redact_data_removes_values_for_sensitive_keys() -> None:
    data = {
        "password": "plain-password",
        "clientSecret": "client-secret-value",
        "authorization": "Bearer access-token-value",
        "nested": {
            "access_token": "access-token-value",
            "refresh_token": "refresh-token-value",
            "credentials": {"value": "credential-value", "temporary": False},
        },
    }

    redacted = redact_data(data)

    assert redacted == {
        "password": REDACTED_VALUE,
        "clientSecret": REDACTED_VALUE,
        "authorization": REDACTED_VALUE,
        "nested": {
            "access_token": REDACTED_VALUE,
            "refresh_token": REDACTED_VALUE,
            "credentials": {"value": REDACTED_VALUE, "temporary": REDACTED_VALUE},
        },
    }
    assert "plain-password" not in repr(redacted)
    assert "client-secret-value" not in repr(redacted)
    assert "access-token-value" not in repr(redacted)
    assert "refresh-token-value" not in repr(redacted)
    assert "credential-value" not in repr(redacted)


def test_redact_data_keeps_non_sensitive_values() -> None:
    data = {
        "realm": "master",
        "username": "admin",
        "enabled": True,
        "count": 3,
    }

    assert redact_data(data, ["missing-secret"]) == data


def test_redact_data_ignores_empty_sensitive_values() -> None:
    data = {
        "message": "public text",
        "password": "",
    }

    redacted = redact_data(data, [""])

    assert redact_text("public text", [""]) == "public text"
    assert redacted == data


def test_redact_data_does_not_mutate_input() -> None:
    data = {
        "message": "contains original-secret",
        "nested": [{"password": "plain-password"}],
    }
    original = deepcopy(data)

    redacted = redact_data(data, ["original-secret"])

    assert data == original
    assert redacted is not data
    assert redacted["nested"] is not data["nested"]
    assert redacted["nested"][0] is not data["nested"][0]
