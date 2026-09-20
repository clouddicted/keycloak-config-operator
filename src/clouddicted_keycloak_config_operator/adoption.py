"""Read-only discovery and deterministic rendering for existing Keycloak realms."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import ssl
import sys
import unicodedata
from collections import Counter
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, TextIO
from urllib.parse import quote

import httpx
import yaml

from clouddicted_keycloak_config_operator.constants import API_GROUP, API_VERSION
from clouddicted_keycloak_config_operator.keycloak_client import (
    AUTH_METHOD_CLIENT_CREDENTIALS,
    KeycloakAdminClient,
    KeycloakClientError,
)

MASKED_VALUE = "**********"
MAX_RESULTS = 10_000
DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
DNS_SUBDOMAIN_PATTERN = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$"
)
KIND_ORDER = {
    "KeycloakRealm": 0,
    "KeycloakRole": 10,
    "KeycloakClientScope": 20,
    "KeycloakClient": 30,
    "KeycloakClientRole": 40,
    "KeycloakGroup": 50,
    "KeycloakIdentityProvider": 60,
    "KeycloakIdentityProviderMapper": 70,
    "KeycloakProtocolMapper": 80,
    "KeycloakGroupRoleMapping": 90,
}
BUILTIN_CLIENTS = frozenset(
    {
        "account",
        "account-console",
        "admin-cli",
        "broker",
        "realm-management",
        "security-admin-console",
    }
)
BUILTIN_REALM_ROLES = frozenset(
    {"offline_access", "uma_authorization"}
)
BUILTIN_CLIENT_SCOPES = frozenset(
    {
        "acr",
        "address",
        "basic",
        "email",
        "microprofile-jwt",
        "offline_access",
        "organization",
        "phone",
        "profile",
        "roles",
        "web-origins",
    }
)
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:^|[._-])(secret|password|private[._-]?key|credential)(?:$|[._-])",
    re.IGNORECASE,
)
CLIENT_ATTRIBUTE_FIELDS = {
    "pkce.code.challenge.method": ("pkceCodeChallengeMethod", "string"),
    "post.logout.redirect.uris": ("postLogoutRedirectUris", "redirects"),
    "backchannel.logout.url": ("backchannelLogoutUrl", "string"),
    "backchannel.logout.session.required": (
        "backchannelLogoutSessionRequired",
        "boolean",
    ),
    "backchannel.logout.revoke.offline.tokens": (
        "backchannelLogoutRevokeOfflineTokens",
        "boolean",
    ),
    "use.refresh.tokens": ("useRefreshTokens", "boolean"),
    "client_credentials.use_refresh_token": (
        "useRefreshTokensForClientCredentials",
        "boolean",
    ),
}
CLIENT_SCOPE_ATTRIBUTE_FIELDS = {
    "display.on.consent.screen": ("displayOnConsentScreen", "boolean"),
    "consent.screen.text": ("consentScreenText", "string"),
    "include.in.token.scope": ("includeInTokenScope", "boolean"),
}
CLIENT_AUTHENTICATOR_SIGNED_JWT = "client-jwt"
ATTRIBUTE_USE_JWKS_URL = "use.jwks.url"
ATTRIBUTE_JWKS_URL = "jwks.url"
ATTRIBUTE_JWT_CERTIFICATE = "jwt.credential.certificate"
ATTRIBUTE_TOKEN_ENDPOINT_AUTH_SIGNING_ALGORITHM = "token.endpoint.auth.signing.alg"
CLIENT_AUTHENTICATION_ATTRIBUTES = frozenset(
    {
        ATTRIBUTE_USE_JWKS_URL,
        ATTRIBUTE_JWKS_URL,
        ATTRIBUTE_JWT_CERTIFICATE,
        ATTRIBUTE_TOKEN_ENDPOINT_AUTH_SIGNING_ALGORITHM,
    }
)


class AdoptionClient(Protocol):
    """Subset of the Keycloak client used by discovery."""

    def request(self, method: str, path: str, **kwargs: Any) -> Any | None:
        """Send an authenticated Admin API request."""


class AdoptionError(RuntimeError):
    """A safe user-facing adoption failure."""


@dataclass(frozen=True, order=True)
class AdoptionWarning:
    code: str
    message: str


@dataclass(frozen=True)
class RenderedResource:
    order: int
    kind: str
    name: str
    identity: str
    document: dict[str, Any]


@dataclass
class AdoptionResult:
    realm: str
    resources: list[RenderedResource] = field(default_factory=list)
    discovered: Counter[str] = field(default_factory=Counter)
    skipped_builtins: Counter[str] = field(default_factory=Counter)
    warnings: set[AdoptionWarning] = field(default_factory=set)
    errors: set[str] = field(default_factory=set)

    @property
    def documents(self) -> list[dict[str, Any]]:
        return [
            resource.document
            for resource in sorted(
                self.resources,
                key=lambda item: (item.order, item.name, item.identity),
            )
        ]

    @property
    def rendered(self) -> Counter[str]:
        return Counter(resource.kind for resource in self.resources)

    def warn(self, code: str, message: str) -> None:
        self.warnings.add(AdoptionWarning(code, message))


class NameRegistry:
    def __init__(self, result: AdoptionResult) -> None:
        self._result = result
        self._identities: dict[tuple[str, str], str] = {}

    def assign(self, kind: str, natural_name: str, identity: str) -> str:
        name = kubernetes_name(natural_name, identity=identity)
        key = (kind, name)
        previous = self._identities.get(key)
        if previous is not None:
            self._result.errors.add(
                f"Kubernetes name collision for {kind}/{name}: {previous!r} and {identity!r}"
            )
        else:
            self._identities[key] = identity
        return name


def kubernetes_name(value: str, *, identity: str | None = None) -> str:
    """Return a stable DNS-label name, adding a hash only when truncation is needed."""
    ascii_value = (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode().lower()
    )
    normalized = re.sub(r"[^a-z0-9]+", "-", ascii_value).strip("-")
    identity_value = identity or value
    if not normalized:
        normalized = "resource"
    if len(normalized) <= 63:
        return normalized
    suffix = hashlib.sha256(identity_value.encode()).hexdigest()[:8]
    return f"{normalized[:54].rstrip('-')}-{suffix}"


def discover_realm(
    client: AdoptionClient,
    *,
    realm: str,
    namespace: str,
    target_ref: str,
) -> AdoptionResult:
    """Discover one realm and render every safely representable resource."""
    _validate_namespace(namespace)
    _validate_target_ref(target_ref)
    result = AdoptionResult(realm=realm)
    names = NameRegistry(result)
    encoded_realm = _segment(realm)

    realm_payload = _mapping(client.request("GET", f"realms/{encoded_realm}"), "realm")
    _discover_realm_resource(result, names, realm_payload, realm, namespace, target_ref)

    scopes = _list(
        client.request(
            "GET",
            f"realms/{encoded_realm}/client-scopes",
            params={"first": 0, "max": MAX_RESULTS},
        ),
        "client scopes",
    )
    scope_refs = _discover_client_scopes(
        result, names, scopes, realm, namespace, target_ref
    )

    clients = _list(
        client.request(
            "GET",
            f"realms/{encoded_realm}/clients",
            params={"first": 0, "max": MAX_RESULTS},
        ),
        "clients",
    )
    client_refs = _discover_clients(
        client,
        result,
        names,
        clients,
        realm,
        namespace,
        target_ref,
    )

    roles = _list(
        client.request(
            "GET",
            f"realms/{encoded_realm}/roles",
            params={"first": 0, "max": MAX_RESULTS},
        ),
        "realm roles",
    )
    role_refs = _discover_realm_roles(
        result, names, roles, realm, namespace, target_ref
    )

    client_role_refs = _discover_client_roles(
        client, result, names, client_refs, realm, namespace, target_ref
    )
    _discover_protocol_mappers(
        client,
        result,
        names,
        client_refs,
        scope_refs,
        realm,
        namespace,
        target_ref,
    )

    providers = _list(
        client.request("GET", f"realms/{encoded_realm}/identity-provider/instances"),
        "identity providers",
    )
    provider_refs = _discover_identity_providers(
        result, names, providers, realm, namespace, target_ref
    )
    _discover_identity_provider_mappers(
        client,
        result,
        names,
        provider_refs,
        realm,
        namespace,
        target_ref,
    )

    groups = _list(
        client.request(
            "GET",
            f"realms/{encoded_realm}/groups",
            params={"first": 0, "max": MAX_RESULTS, "briefRepresentation": "false"},
        ),
        "groups",
    )
    group_refs = _discover_groups(
        result, names, groups, realm, namespace, target_ref
    )
    _discover_group_role_mappings(
        client,
        result,
        names,
        group_refs,
        role_refs,
        client_refs,
        client_role_refs,
        realm,
        namespace,
        target_ref,
    )
    return result


def render_yaml(result: AdoptionResult) -> str:
    """Render a complete deterministic YAML stream or refuse unsafe partial output."""
    if result.errors:
        raise AdoptionError("render blocked: " + "; ".join(sorted(result.errors)))
    documents = result.documents
    if not documents:
        return ""
    return yaml.safe_dump_all(
        documents,
        explicit_start=True,
        sort_keys=False,
        default_flow_style=False,
    )


def format_report(result: AdoptionResult) -> str:
    """Build the human-readable plan and render report."""
    lines = [f"Adoption plan for Keycloak realm {result.realm!r}", "", "Discovered:"]
    lines.extend(_counter_lines(result.discovered))
    lines.extend(("", "Rendered:"))
    lines.extend(_counter_lines(result.rendered))
    lines.extend(("", "Built-in objects skipped:"))
    lines.extend(_counter_lines(result.skipped_builtins))
    lines.extend(("", f"Warnings: {len(result.warnings)}"))
    lines.extend(f"  [{warning.code}] {warning.message}" for warning in sorted(result.warnings))
    lines.extend(("", f"Errors: {len(result.errors)}"))
    lines.extend(f"  {error}" for error in sorted(result.errors))
    return "\n".join(lines) + "\n"


def _counter_lines(values: Counter[str]) -> list[str]:
    if not values:
        return ["  none"]
    return [f"  {kind}: {values[kind]}" for kind in sorted(values)]


def _discover_realm_resource(
    result: AdoptionResult,
    names: NameRegistry,
    payload: Mapping[str, Any],
    realm: str,
    namespace: str,
    target_ref: str,
) -> None:
    result.discovered["KeycloakRealm"] += 1
    spec = _base_spec(realm, target_ref, deletion=False)
    display_name = _non_empty_string(payload.get("displayName"))
    if display_name is not None:
        spec["displayName"] = display_name
    _add_resource(
        result,
        names,
        kind="KeycloakRealm",
        natural_name=realm,
        identity=f"realm:{realm}",
        namespace=namespace,
        spec=spec,
    )
    _warn_unsupported_fields(
        result,
        "KeycloakRealm",
        realm,
        payload,
        supported={"realm", "displayName"},
        ignored={"id"},
    )


def _discover_client_scopes(
    result: AdoptionResult,
    names: NameRegistry,
    payloads: Sequence[Any],
    realm: str,
    namespace: str,
    target_ref: str,
) -> dict[str, tuple[str, str]]:
    refs: dict[str, tuple[str, str]] = {}
    for raw in payloads:
        payload = _object_or_warning(result, "KeycloakClientScope", raw)
        if payload is None:
            continue
        result.discovered["KeycloakClientScope"] += 1
        name = _non_empty_string(payload.get("name"))
        internal_id = _non_empty_string(payload.get("id"))
        if name is None or internal_id is None:
            result.warn("unsupported-object", "Client scope without id or name was skipped.")
            continue
        if name in BUILTIN_CLIENT_SCOPES:
            result.skipped_builtins["KeycloakClientScope"] += 1
            continue
        spec = _base_spec(realm, target_ref)
        spec["name"] = name
        protocol = _non_empty_string(payload.get("protocol"))
        if protocol is not None:
            spec["protocol"] = protocol
        description = _non_empty_string(payload.get("description"))
        if description is not None:
            spec["description"] = description
        _copy_attribute_fields(
            result,
            "KeycloakClientScope",
            name,
            payload.get("attributes"),
            CLIENT_SCOPE_ATTRIBUTE_FIELDS,
            spec,
        )
        resource_name = _add_resource(
            result,
            names,
            kind="KeycloakClientScope",
            natural_name=name,
            identity=f"client-scope:{name}",
            namespace=namespace,
            spec=spec,
        )
        refs[internal_id] = (name, resource_name)
        _warn_unsupported_fields(
            result,
            "KeycloakClientScope",
            name,
            payload,
            supported={"id", "name", "protocol", "description", "attributes"},
        )
    return refs


def _discover_clients(
    client: AdoptionClient,
    result: AdoptionResult,
    names: NameRegistry,
    payloads: Sequence[Any],
    realm: str,
    namespace: str,
    target_ref: str,
) -> dict[str, tuple[str, str]]:
    refs: dict[str, tuple[str, str]] = {}
    encoded_realm = _segment(realm)
    for raw in payloads:
        summary = _object_or_warning(result, "KeycloakClient", raw)
        if summary is None:
            continue
        result.discovered["KeycloakClient"] += 1
        client_id = _non_empty_string(summary.get("clientId"))
        internal_id = _non_empty_string(summary.get("id"))
        if client_id is None or internal_id is None:
            result.warn("unsupported-object", "Client without id or clientId was skipped.")
            continue
        if client_id in BUILTIN_CLIENTS:
            result.skipped_builtins["KeycloakClient"] += 1
            continue
        detail = _mapping(
            client.request(
                "GET", f"realms/{encoded_realm}/clients/{_segment(internal_id)}"
            ),
            f"client {client_id}",
        )
        protocol = _non_empty_string(detail.get("protocol")) or "openid-connect"
        if protocol != "openid-connect":
            result.warn(
                "unsupported-object",
                f"KeycloakClient {client_id!r} uses unsupported protocol "
                f"{protocol!r} and was skipped.",
            )
            continue
        spec = _base_spec(realm, target_ref)
        spec["clientId"] = client_id
        is_public = detail.get("publicClient") is True
        spec["clientType"] = "Public" if is_public else "Confidential"
        _copy_fields(
            detail,
            spec,
            {
                "enabled": "enabled",
                "name": "displayName",
                "description": "description",
                "rootUrl": "rootUrl",
                "baseUrl": "baseUrl",
                "adminUrl": "adminUrl",
                "standardFlowEnabled": "standardFlowEnabled",
                "implicitFlowEnabled": "implicitFlowEnabled",
                "directAccessGrantsEnabled": "directAccessGrantsEnabled",
                "serviceAccountsEnabled": "serviceAccountsEnabled",
                "fullScopeAllowed": "fullScopeAllowed",
                "frontchannelLogout": "frontchannelLogout",
                "consentRequired": "consentRequired",
                "redirectUris": "redirectUris",
                "webOrigins": "webOrigins",
            },
        )
        _copy_attribute_fields(
            result,
            "KeycloakClient",
            client_id,
            detail.get("attributes"),
            CLIENT_ATTRIBUTE_FIELDS,
            spec,
            ignored=CLIENT_AUTHENTICATION_ATTRIBUTES if not is_public else frozenset(),
        )
        _add_client_authentication(result, detail, client_id, is_public, spec)
        _add_client_scopes(client, result, detail, encoded_realm, internal_id, client_id, spec)
        resource_name = _add_resource(
            result,
            names,
            kind="KeycloakClient",
            natural_name=client_id,
            identity=f"client:{client_id}",
            namespace=namespace,
            spec=spec,
        )
        refs[internal_id] = (client_id, resource_name)
        _warn_unsupported_fields(
            result,
            "KeycloakClient",
            client_id,
            detail,
            supported={
                "id",
                "clientId",
                "protocol",
                "publicClient",
                "enabled",
                "name",
                "description",
                "rootUrl",
                "baseUrl",
                "adminUrl",
                "standardFlowEnabled",
                "implicitFlowEnabled",
                "directAccessGrantsEnabled",
                "serviceAccountsEnabled",
                "fullScopeAllowed",
                "frontchannelLogout",
                "consentRequired",
                "redirectUris",
                "webOrigins",
                "attributes",
                "clientAuthenticatorType",
                "defaultClientScopes",
                "optionalClientScopes",
            },
            ignored={
                "access",
                "authenticationFlowBindingOverrides",
                "nodeReRegistrationTimeout",
                "secret",
            },
        )
    return refs


def _add_client_authentication(
    result: AdoptionResult,
    detail: Mapping[str, Any],
    client_id: str,
    is_public: bool,
    spec: dict[str, Any],
) -> None:
    if is_public:
        return

    authenticator = _non_empty_string(detail.get("clientAuthenticatorType"))
    raw_attributes = detail.get("attributes")
    attributes = raw_attributes if isinstance(raw_attributes, Mapping) else {}
    if authenticator == CLIENT_AUTHENTICATOR_SIGNED_JWT:
        uses_jwks = _keycloak_bool(attributes.get(ATTRIBUTE_USE_JWKS_URL)) is True
        jwks_url = _non_empty_string(attributes.get(ATTRIBUTE_JWKS_URL))
        if uses_jwks and jwks_url is not None:
            signed_jwt: dict[str, Any] = {"jwksUrl": jwks_url}
            signature_algorithm = _non_empty_string(
                attributes.get(ATTRIBUTE_TOKEN_ENDPOINT_AUTH_SIGNING_ALGORITHM)
            )
            if signature_algorithm is not None:
                signed_jwt["signatureAlgorithm"] = signature_algorithm
            spec["authentication"] = {
                "method": "SignedJwt",
                "signedJwt": signed_jwt,
            }
            return

        result.warn(
            "secret-omitted",
            f"KeycloakClient {client_id!r} uses Signed JWT without a reusable JWKS URL; "
            "authentication was omitted and requires a user-supplied certificate Secret.",
        )
        return

    result.warn(
        "secret-omitted",
        f"KeycloakClient {client_id!r} is confidential; authentication secrets were omitted.",
    )


def _add_client_scopes(
    client: AdoptionClient,
    result: AdoptionResult,
    detail: Mapping[str, Any],
    encoded_realm: str,
    internal_id: str,
    client_id: str,
    spec: dict[str, Any],
) -> None:
    for endpoint, field_name in (
        ("default-client-scopes", "defaultClientScopes"),
        ("optional-client-scopes", "optionalClientScopes"),
    ):
        payload = client.request(
            "GET",
            f"realms/{encoded_realm}/clients/{_segment(internal_id)}/{endpoint}",
        )
        scopes = _list(payload, f"{client_id} {endpoint}")
        names = sorted(
            scope_name
            for scope in scopes
            if isinstance(scope, Mapping)
            for scope_name in [_non_empty_string(scope.get("name"))]
            if scope_name is not None
        )
        if names:
            spec[field_name] = names


def _discover_realm_roles(
    result: AdoptionResult,
    names: NameRegistry,
    payloads: Sequence[Any],
    realm: str,
    namespace: str,
    target_ref: str,
) -> dict[str, str]:
    refs: dict[str, str] = {}
    builtin_names = BUILTIN_REALM_ROLES | {f"default-roles-{realm}"}
    for raw in payloads:
        payload = _object_or_warning(result, "KeycloakRole", raw)
        if payload is None:
            continue
        result.discovered["KeycloakRole"] += 1
        name = _non_empty_string(payload.get("name"))
        if name is None:
            result.warn("unsupported-object", "Realm role without name was skipped.")
            continue
        if name in builtin_names:
            result.skipped_builtins["KeycloakRole"] += 1
            continue
        spec = _base_spec(realm, target_ref)
        spec["name"] = name
        description = _non_empty_string(payload.get("description"))
        if description is not None:
            spec["description"] = description
        resource_name = _add_resource(
            result,
            names,
            kind="KeycloakRole",
            natural_name=name,
            identity=f"realm-role:{name}",
            namespace=namespace,
            spec=spec,
        )
        refs[name] = resource_name
        if payload.get("composite") is True:
            result.warn(
                "unsupported-field",
                f"KeycloakRole {name!r} is composite; composite members were not rendered.",
            )
        _warn_unsupported_fields(
            result,
            "KeycloakRole",
            name,
            payload,
            supported={"id", "name", "description"},
            ignored={"composite", "clientRole", "containerId"},
        )
    return refs


def _discover_client_roles(
    client: AdoptionClient,
    result: AdoptionResult,
    names: NameRegistry,
    client_refs: Mapping[str, tuple[str, str]],
    realm: str,
    namespace: str,
    target_ref: str,
) -> dict[tuple[str, str], str]:
    refs: dict[tuple[str, str], str] = {}
    encoded_realm = _segment(realm)
    for internal_id, (client_id, client_resource_name) in sorted(
        client_refs.items(), key=lambda item: item[1][0]
    ):
        roles = _list(
            client.request(
                "GET",
                f"realms/{encoded_realm}/clients/{_segment(internal_id)}/roles",
                params={"first": 0, "max": MAX_RESULTS},
            ),
            f"roles for client {client_id}",
        )
        for raw in roles:
            payload = _object_or_warning(result, "KeycloakClientRole", raw)
            if payload is None:
                continue
            result.discovered["KeycloakClientRole"] += 1
            role_name = _non_empty_string(payload.get("name"))
            if role_name is None:
                result.warn(
                    "unsupported-object", f"Client role without name on {client_id!r} was skipped."
                )
                continue
            spec = _base_spec(realm, target_ref)
            spec.update(
                {
                    "clientRef": {"name": client_resource_name},
                    "name": role_name,
                }
            )
            description = _non_empty_string(payload.get("description"))
            if description is not None:
                spec["description"] = description
            resource_name = _add_resource(
                result,
                names,
                kind="KeycloakClientRole",
                natural_name=f"{client_id}-{role_name}",
                identity=f"client-role:{client_id}:{role_name}",
                namespace=namespace,
                spec=spec,
            )
            refs[(client_id, role_name)] = resource_name
            if payload.get("composite") is True:
                result.warn(
                    "unsupported-field",
                    f"KeycloakClientRole {client_id}/{role_name} is composite; "
                    "members were not rendered.",
                )
            _warn_unsupported_fields(
                result,
                "KeycloakClientRole",
                f"{client_id}/{role_name}",
                payload,
                supported={"id", "name", "description"},
                ignored={"composite", "clientRole", "containerId"},
            )
    return refs


def _discover_protocol_mappers(
    client: AdoptionClient,
    result: AdoptionResult,
    names: NameRegistry,
    client_refs: Mapping[str, tuple[str, str]],
    scope_refs: Mapping[str, tuple[str, str]],
    realm: str,
    namespace: str,
    target_ref: str,
) -> None:
    encoded_realm = _segment(realm)
    parents = [
        ("Client", internal_id, natural, resource_name, "clients")
        for internal_id, (natural, resource_name) in client_refs.items()
    ] + [
        ("ClientScope", internal_id, natural, resource_name, "client-scopes")
        for internal_id, (natural, resource_name) in scope_refs.items()
    ]
    for parent_type, internal_id, parent_name, resource_name, endpoint in sorted(parents):
        payloads = _list(
            client.request(
                "GET",
                f"realms/{encoded_realm}/{endpoint}/{_segment(internal_id)}/protocol-mappers/models",
            ),
            f"protocol mappers for {parent_type} {parent_name}",
        )
        for raw in payloads:
            payload = _object_or_warning(result, "KeycloakProtocolMapper", raw)
            if payload is None:
                continue
            result.discovered["KeycloakProtocolMapper"] += 1
            mapper_name = _non_empty_string(payload.get("name"))
            mapper_type = _non_empty_string(payload.get("protocolMapper"))
            if mapper_name is None or mapper_type is None:
                result.warn(
                    "unsupported-object",
                    f"Protocol mapper on {parent_type} {parent_name!r} without "
                    "name or type was skipped.",
                )
                continue
            spec = _base_spec(realm, target_ref)
            spec.update(
                {
                    "name": mapper_name,
                    "mapperType": mapper_type,
                    "parent": {
                        "type": parent_type,
                        f"{'client' if parent_type == 'Client' else 'clientScope'}Ref": {
                            "name": resource_name
                        },
                    },
                }
            )
            protocol = _non_empty_string(payload.get("protocol"))
            if protocol is not None:
                spec["protocol"] = protocol
            config = _safe_config(
                result,
                "KeycloakProtocolMapper",
                f"{parent_name}/{mapper_name}",
                payload.get("config"),
            )
            if config:
                spec["config"] = config
            _add_resource(
                result,
                names,
                kind="KeycloakProtocolMapper",
                natural_name=f"{parent_type}-{parent_name}-{mapper_name}",
                identity=f"protocol-mapper:{parent_type}:{parent_name}:{mapper_name}",
                namespace=namespace,
                spec=spec,
            )
            _warn_unsupported_fields(
                result,
                "KeycloakProtocolMapper",
                f"{parent_name}/{mapper_name}",
                payload,
                supported={"id", "name", "protocol", "protocolMapper", "config"},
            )


def _discover_identity_providers(
    result: AdoptionResult,
    names: NameRegistry,
    payloads: Sequence[Any],
    realm: str,
    namespace: str,
    target_ref: str,
) -> dict[str, str]:
    refs: dict[str, str] = {}
    for raw in payloads:
        payload = _object_or_warning(result, "KeycloakIdentityProvider", raw)
        if payload is None:
            continue
        result.discovered["KeycloakIdentityProvider"] += 1
        alias = _non_empty_string(payload.get("alias"))
        provider_id = _non_empty_string(payload.get("providerId"))
        if alias is None or provider_id is None:
            result.warn(
                "unsupported-object", "Identity provider without alias or providerId was skipped."
            )
            continue
        spec = _base_spec(realm, target_ref)
        spec.update({"alias": alias, "providerId": provider_id})
        _copy_fields(
            payload,
            spec,
            {
                "enabled": "enabled",
                "displayName": "displayName",
                "trustEmail": "trustEmail",
                "storeToken": "storeToken",
                "linkOnly": "linkOnly",
                "hideOnLogin": "hideOnLogin",
                "authenticateByDefault": "authenticateByDefault",
                "updateProfileFirstLoginMode": "updateProfileFirstLoginMode",
                "firstBrokerLoginFlowAlias": "firstBrokerLoginFlowAlias",
            },
        )
        config = _safe_config(
            result, "KeycloakIdentityProvider", alias, payload.get("config")
        )
        if config:
            spec["config"] = config
        resource_name = _add_resource(
            result,
            names,
            kind="KeycloakIdentityProvider",
            natural_name=alias,
            identity=f"identity-provider:{alias}",
            namespace=namespace,
            spec=spec,
        )
        refs[alias] = resource_name
        _warn_unsupported_fields(
            result,
            "KeycloakIdentityProvider",
            alias,
            payload,
            supported={
                "internalId",
                "id",
                "alias",
                "providerId",
                "enabled",
                "displayName",
                "trustEmail",
                "storeToken",
                "linkOnly",
                "hideOnLogin",
                "authenticateByDefault",
                "updateProfileFirstLoginMode",
                "firstBrokerLoginFlowAlias",
                "config",
            },
        )
    return refs


def _discover_identity_provider_mappers(
    client: AdoptionClient,
    result: AdoptionResult,
    names: NameRegistry,
    provider_refs: Mapping[str, str],
    realm: str,
    namespace: str,
    target_ref: str,
) -> None:
    encoded_realm = _segment(realm)
    for alias, provider_resource_name in sorted(provider_refs.items()):
        payloads = _list(
            client.request(
                "GET",
                f"realms/{encoded_realm}/identity-provider/instances/{_segment(alias)}/mappers",
            ),
            f"mappers for identity provider {alias}",
        )
        for raw in payloads:
            payload = _object_or_warning(result, "KeycloakIdentityProviderMapper", raw)
            if payload is None:
                continue
            result.discovered["KeycloakIdentityProviderMapper"] += 1
            mapper_name = _non_empty_string(payload.get("name"))
            mapper_type = _non_empty_string(payload.get("identityProviderMapper"))
            if mapper_name is None or mapper_type is None:
                result.warn(
                    "unsupported-object",
                    f"Identity-provider mapper on {alias!r} without name or type was skipped.",
                )
                continue
            spec = _base_spec(realm, target_ref)
            spec.update(
                {
                    "name": mapper_name,
                    "identityProviderRef": {"name": provider_resource_name},
                    "identityProviderMapper": mapper_type,
                }
            )
            config = _safe_config(
                result,
                "KeycloakIdentityProviderMapper",
                f"{alias}/{mapper_name}",
                payload.get("config"),
            )
            if config:
                spec["config"] = config
            _add_resource(
                result,
                names,
                kind="KeycloakIdentityProviderMapper",
                natural_name=f"{alias}-{mapper_name}",
                identity=f"identity-provider-mapper:{alias}:{mapper_name}",
                namespace=namespace,
                spec=spec,
            )
            _warn_unsupported_fields(
                result,
                "KeycloakIdentityProviderMapper",
                f"{alias}/{mapper_name}",
                payload,
                supported={
                    "id",
                    "name",
                    "identityProviderAlias",
                    "identityProviderMapper",
                    "config",
                },
            )


def _discover_groups(
    result: AdoptionResult,
    names: NameRegistry,
    payloads: Sequence[Any],
    realm: str,
    namespace: str,
    target_ref: str,
) -> dict[str, tuple[str, str]]:
    refs: dict[str, tuple[str, str]] = {}
    for raw in payloads:
        payload = _object_or_warning(result, "KeycloakGroup", raw)
        if payload is None:
            continue
        result.discovered["KeycloakGroup"] += 1
        group_name = _non_empty_string(payload.get("name"))
        group_id = _non_empty_string(payload.get("id"))
        if group_name is None or group_id is None:
            result.warn("unsupported-object", "Group without id or name was skipped.")
            continue
        subgroups = payload.get("subGroups")
        if isinstance(subgroups, Sequence) and not isinstance(subgroups, str | bytes):
            nested_count = _count_nested_groups(subgroups)
            if nested_count:
                result.discovered["KeycloakGroup"] += nested_count
                result.warn(
                    "unsupported-object",
                    f"KeycloakGroup {group_name!r} has {nested_count} nested group(s); "
                    "nested groups were skipped.",
                )
        spec = _base_spec(realm, target_ref)
        spec["name"] = group_name
        attributes = _string_list_mapping(payload.get("attributes"))
        if attributes:
            spec["attributes"] = attributes
        resource_name = _add_resource(
            result,
            names,
            kind="KeycloakGroup",
            natural_name=group_name,
            identity=f"group:{group_name}",
            namespace=namespace,
            spec=spec,
        )
        refs[group_id] = (group_name, resource_name)
        _warn_unsupported_fields(
            result,
            "KeycloakGroup",
            group_name,
            payload,
            supported={"id", "name", "attributes", "subGroups"},
            ignored={"path", "access", "clientRoles", "realmRoles"},
        )
    return refs


def _discover_group_role_mappings(
    client: AdoptionClient,
    result: AdoptionResult,
    names: NameRegistry,
    group_refs: Mapping[str, tuple[str, str]],
    role_refs: Mapping[str, str],
    client_refs: Mapping[str, tuple[str, str]],
    client_role_refs: Mapping[tuple[str, str], str],
    realm: str,
    namespace: str,
    target_ref: str,
) -> None:
    encoded_realm = _segment(realm)
    client_refs_by_name = {natural: resource for natural, resource in client_refs.values()}
    builtin_role_names = BUILTIN_REALM_ROLES | {f"default-roles-{realm}"}
    for group_id, (group_name, group_resource_name) in sorted(
        group_refs.items(), key=lambda item: item[1][0]
    ):
        mappings = _mapping(
            client.request(
                "GET",
                f"realms/{encoded_realm}/groups/{_segment(group_id)}/role-mappings",
            ),
            f"role mappings for group {group_name}",
        )
        realm_mappings = mappings.get("realmMappings", [])
        if isinstance(realm_mappings, Sequence) and not isinstance(
            realm_mappings, str | bytes
        ):
            for raw_role in realm_mappings:
                if not isinstance(raw_role, Mapping):
                    continue
                role_name = _non_empty_string(raw_role.get("name"))
                if role_name is None:
                    continue
                result.discovered["KeycloakGroupRoleMapping"] += 1
                if role_name in builtin_role_names:
                    result.skipped_builtins["KeycloakGroupRoleMapping"] += 1
                    continue
                role_resource_name = role_refs.get(role_name)
                if role_resource_name is None:
                    result.errors.add(
                        f"Group {group_name!r} references unresolved realm role {role_name!r}"
                    )
                    continue
                spec = _base_spec(realm, target_ref)
                spec.update(
                    {
                        "groupRef": {"name": group_resource_name},
                        "role": {
                            "type": "RealmRole",
                            "roleRef": {"name": role_resource_name},
                        },
                    }
                )
                _add_resource(
                    result,
                    names,
                    kind="KeycloakGroupRoleMapping",
                    natural_name=f"{group_name}-realm-{role_name}",
                    identity=f"group-role:{group_name}:realm:{role_name}",
                    namespace=namespace,
                    spec=spec,
                )
        client_mappings = mappings.get("clientMappings", {})
        if not isinstance(client_mappings, Mapping):
            continue
        for mapping_key, raw_mapping in sorted(client_mappings.items()):
            if not isinstance(raw_mapping, Mapping):
                continue
            client_name = _non_empty_string(raw_mapping.get("client")) or str(mapping_key)
            role_payloads = raw_mapping.get("mappings", [])
            if not isinstance(role_payloads, Sequence) or isinstance(
                role_payloads, str | bytes
            ):
                continue
            for raw_role in role_payloads:
                if not isinstance(raw_role, Mapping):
                    continue
                role_name = _non_empty_string(raw_role.get("name"))
                if role_name is None:
                    continue
                result.discovered["KeycloakGroupRoleMapping"] += 1
                if client_name in BUILTIN_CLIENTS:
                    result.skipped_builtins["KeycloakGroupRoleMapping"] += 1
                    continue
                client_resource_name = client_refs_by_name.get(client_name)
                if client_resource_name is None:
                    result.errors.add(
                        f"Group {group_name!r} references unresolved client {client_name!r}"
                    )
                    continue
                role_resource_name = client_role_refs.get((client_name, role_name))
                if role_resource_name is None:
                    result.errors.add(
                        f"Group {group_name!r} references unresolved client role "
                        f"{client_name}/{role_name}"
                    )
                    continue
                spec = _base_spec(realm, target_ref)
                spec.update(
                    {
                        "groupRef": {"name": group_resource_name},
                        "role": {
                            "type": "ClientRole",
                            "clientRef": {"name": client_resource_name},
                            "roleRef": {"name": role_resource_name},
                        },
                    }
                )
                _add_resource(
                    result,
                    names,
                    kind="KeycloakGroupRoleMapping",
                    natural_name=f"{group_name}-{client_name}-{role_name}",
                    identity=f"group-role:{group_name}:client:{client_name}:{role_name}",
                    namespace=namespace,
                    spec=spec,
                )


def _base_spec(realm: str, target_ref: str, *, deletion: bool = True) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "targetRef": {"name": target_ref},
        "realm": realm,
        "managementPolicy": "ObserveOnly",
    }
    if deletion:
        spec["deletionPolicy"] = "Orphan"
    return spec


def _add_resource(
    result: AdoptionResult,
    names: NameRegistry,
    *,
    kind: str,
    natural_name: str,
    identity: str,
    namespace: str,
    spec: dict[str, Any],
) -> str:
    name = names.assign(kind, natural_name, identity)
    result.resources.append(
        RenderedResource(
            order=KIND_ORDER[kind],
            kind=kind,
            name=name,
            identity=identity,
            document={
                "apiVersion": f"{API_GROUP}/{API_VERSION}",
                "kind": kind,
                "metadata": {"name": name, "namespace": namespace},
                "spec": spec,
            },
        )
    )
    return name


def _copy_fields(
    source: Mapping[str, Any], target: dict[str, Any], fields: Mapping[str, str]
) -> None:
    for remote_name, spec_name in fields.items():
        value = source.get(remote_name)
        if isinstance(value, bool):
            target[spec_name] = value
        elif isinstance(value, str) and value.strip():
            target[spec_name] = value.strip()
        elif (
            isinstance(value, Sequence)
            and not isinstance(value, str | bytes)
            and all(isinstance(item, str) and item for item in value)
            and value
        ):
            target[spec_name] = sorted(set(value))


def _copy_attribute_fields(
    result: AdoptionResult,
    kind: str,
    name: str,
    raw_attributes: Any,
    fields: Mapping[str, tuple[str, str]],
    spec: dict[str, Any],
    *,
    ignored: Collection[str] = (),
) -> None:
    if raw_attributes is None:
        return
    if not isinstance(raw_attributes, Mapping):
        result.warn("unsupported-field", f"{kind} {name!r} has non-object attributes.")
        return
    for key, value in sorted(raw_attributes.items()):
        if key in ignored:
            continue
        field_info = fields.get(str(key))
        if field_info is None:
            result.warn(
                "unsupported-field",
                f"{kind} {name!r} attribute {key!r} is not modeled and was omitted.",
            )
            continue
        spec_name, value_type = field_info
        if value_type == "boolean":
            parsed = _keycloak_bool(value)
            if parsed is None:
                result.warn(
                    "unsupported-field",
                    f"{kind} {name!r} attribute {key!r} is not a Keycloak boolean.",
                )
            else:
                spec[spec_name] = parsed
        elif value_type == "redirects" and isinstance(value, str):
            redirects = sorted(item for item in value.split("##") if item)
            if redirects:
                spec[spec_name] = redirects
        elif isinstance(value, str) and value:
            spec[spec_name] = value


def _safe_config(
    result: AdoptionResult,
    kind: str,
    name: str,
    raw_config: Any,
) -> dict[str, str]:
    if raw_config is None:
        return {}
    if not isinstance(raw_config, Mapping):
        result.warn("unsupported-field", f"{kind} {name!r} has non-object config.")
        return {}
    config: dict[str, str] = {}
    for raw_key, raw_value in sorted(raw_config.items(), key=lambda item: str(item[0])):
        key = str(raw_key)
        if _is_sensitive_key(key) or raw_value == MASKED_VALUE:
            result.warn(
                "secret-omitted",
                f"{kind} {name!r} config field {key!r} requires a user-supplied Secret reference.",
            )
            continue
        if not key or not isinstance(raw_value, str):
            result.warn(
                "unsupported-field",
                f"{kind} {name!r} config field {key!r} is not a string and was omitted.",
            )
            continue
        config[key] = raw_value
    return config


def _is_sensitive_key(key: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    return (
        bool(SENSITIVE_KEY_PATTERN.search(key))
        or compact.endswith(
            (
                "secret",
                "password",
                "privatekey",
                "credential",
                "passphrase",
                "accesstoken",
                "refreshtoken",
            )
        )
        or compact in {"apikey", "clientassertionsigningkey", "signingkey"}
    )


def _warn_unsupported_fields(
    result: AdoptionResult,
    kind: str,
    name: str,
    payload: Mapping[str, Any],
    *,
    supported: set[str],
    ignored: set[str] | None = None,
) -> None:
    unsupported = sorted(set(payload) - supported - (ignored or set()))
    if unsupported:
        result.warn(
            "unsupported-field",
            f"{kind} {name!r} fields were not modeled: {', '.join(unsupported)}.",
        )


def _object_or_warning(
    result: AdoptionResult, kind: str, value: Any
) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    result.warn("unsupported-object", f"{kind} response entry was not an object and was skipped.")
    return None


def _mapping(value: Any, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AdoptionError(f"Keycloak {description} response was not an object")
    return value


def _list(value: Any, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise AdoptionError(f"Keycloak {description} response was not a list")
    return value


def _non_empty_string(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _keycloak_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return None


def _string_list_mapping(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, list[str]] = {}
    for key, values in sorted(value.items(), key=lambda item: str(item[0])):
        if not isinstance(key, str) or not key:
            continue
        if isinstance(values, Sequence) and not isinstance(values, str | bytes):
            parsed = sorted(
                item.strip() for item in values if isinstance(item, str) and item.strip()
            )
            if parsed:
                result[key] = parsed
    return result


def _count_nested_groups(groups: Sequence[Any]) -> int:
    count = 0
    for group in groups:
        if not isinstance(group, Mapping):
            continue
        count += 1
        children = group.get("subGroups")
        if isinstance(children, Sequence) and not isinstance(children, str | bytes):
            count += _count_nested_groups(children)
    return count


def _segment(value: str) -> str:
    return quote(value, safe="")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keycloak-config-operator adopt")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "render"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--url", required=True)
        command_parser.add_argument("--auth-realm", required=True)
        command_parser.add_argument("--client-id", required=True)
        command_parser.add_argument("--client-secret-file", required=True, type=Path)
        command_parser.add_argument("--realm", required=True)
        command_parser.add_argument("--ca-file", type=Path)
        if command == "render":
            command_parser.add_argument("--namespace", required=True)
            command_parser.add_argument("--target-ref", required=True)
            command_parser.add_argument("--output", required=True, choices=("-",))
    return parser


def _validate_namespace(value: str) -> None:
    if len(value) > 63 or not DNS_LABEL_PATTERN.fullmatch(value):
        raise AdoptionError(
            f"namespace {value!r} must be a valid Kubernetes DNS label of at most 63 characters"
        )


def _validate_target_ref(value: str) -> None:
    if len(value) > 253 or not DNS_SUBDOMAIN_PATTERN.fullmatch(value):
        raise AdoptionError(
            f"target reference {value!r} must be a valid Kubernetes DNS subdomain name"
        )


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Run ``adopt plan`` or ``adopt render``."""
    args = _parser().parse_args(argv)
    try:
        secret = _read_secret_file(args.client_secret_file)
        context = ssl.create_default_context(
            cafile=os.fspath(args.ca_file) if args.ca_file else None
        )
        with httpx.Client(timeout=30.0, verify=context, trust_env=False) as http_client:
            client = KeycloakAdminClient(
                base_url=args.url,
                username="",
                password="",
                realm=args.auth_realm,
                client_id=args.client_id,
                client_secret=secret,
                auth_method=AUTH_METHOD_CLIENT_CREDENTIALS,
                http_client=http_client,
            )
            client.authenticate()
            result = discover_realm(
                client,
                realm=args.realm,
                namespace=getattr(args, "namespace", "adoption-plan"),
                target_ref=getattr(args, "target_ref", "adoption-plan"),
            )
    except (AdoptionError, KeycloakClientError, OSError, ValueError, ssl.SSLError) as exc:
        print(f"adoption failed: {exc}", file=stderr)
        return 2

    report = format_report(result)
    if args.command == "plan":
        stdout.write(report)
        return 3 if result.errors else 0

    stderr.write(report)
    if result.errors:
        print("render produced no YAML because the plan contains errors", file=stderr)
        return 3
    try:
        stdout.write(render_yaml(result))
    except AdoptionError as exc:
        print(f"adoption failed: {exc}", file=stderr)
        return 3
    return 0


def _read_secret_file(path: Path) -> str:
    value = path.read_text().strip()
    if not value:
        raise AdoptionError(f"client secret file {path} is empty")
    return value
