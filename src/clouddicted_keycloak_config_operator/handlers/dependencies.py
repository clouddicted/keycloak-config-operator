"""Dependency indexes and event handlers for prompt reconciliation fan-out."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any

import kopf
from kubernetes import client as kubernetes_client
from kubernetes.client.exceptions import ApiException

from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_CLIENT_PLURAL,
    KEYCLOAK_CLIENT_ROLE_PLURAL,
    KEYCLOAK_CLIENT_SCOPE_PLURAL,
    KEYCLOAK_GROUP_PLURAL,
    KEYCLOAK_GROUP_ROLE_MAPPING_PLURAL,
    KEYCLOAK_IDENTITY_PROVIDER_PLURAL,
    KEYCLOAK_PROTOCOL_MAPPER_PLURAL,
    KEYCLOAK_RESOURCE_PLURALS,
    KEYCLOAK_ROLE_PLURAL,
    KEYCLOAK_TARGET_PLURAL,
)

CORE_API_GROUP = ""
SECRET_PLURAL = "secrets"
DEPENDENCY_TRIGGER_ANNOTATION = f"{API_GROUP}/dependency-trigger"

DependencyKey = tuple[str, str, str, str]


@dataclass(frozen=True)
class SourceResource:
    group: str
    version: str
    plural: str


@dataclass(frozen=True)
class DependentResource:
    namespace: str
    plural: str
    name: str
    current_trigger: str | None = None


CUSTOM_RESOURCES = tuple(
    SourceResource(API_GROUP, API_VERSION, plural) for plural in KEYCLOAK_RESOURCE_PLURALS
)
SECRET_RESOURCE = SourceResource(CORE_API_GROUP, "v1", SECRET_PLURAL)
DEPENDENCY_INDEX_IDS = tuple(
    f"{resource.plural}_dependencies" for resource in CUSTOM_RESOURCES
)


def _resource(resource: SourceResource) -> dict[str, str]:
    return {
        "group": resource.group,
        "version": resource.version,
        "plural": resource.plural,
    }


@kopf.index(
    **_resource(CUSTOM_RESOURCES[0]),
    id=DEPENDENCY_INDEX_IDS[0],
    param=CUSTOM_RESOURCES[0],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[1]),
    id=DEPENDENCY_INDEX_IDS[1],
    param=CUSTOM_RESOURCES[1],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[2]),
    id=DEPENDENCY_INDEX_IDS[2],
    param=CUSTOM_RESOURCES[2],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[3]),
    id=DEPENDENCY_INDEX_IDS[3],
    param=CUSTOM_RESOURCES[3],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[4]),
    id=DEPENDENCY_INDEX_IDS[4],
    param=CUSTOM_RESOURCES[4],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[5]),
    id=DEPENDENCY_INDEX_IDS[5],
    param=CUSTOM_RESOURCES[5],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[6]),
    id=DEPENDENCY_INDEX_IDS[6],
    param=CUSTOM_RESOURCES[6],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[7]),
    id=DEPENDENCY_INDEX_IDS[7],
    param=CUSTOM_RESOURCES[7],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[8]),
    id=DEPENDENCY_INDEX_IDS[8],
    param=CUSTOM_RESOURCES[8],
)
@kopf.index(
    **_resource(CUSTOM_RESOURCES[9]),
    id=DEPENDENCY_INDEX_IDS[9],
    param=CUSTOM_RESOURCES[9],
)
def index_resource_dependencies(
    body: Mapping[str, Any],
    spec: Mapping[str, Any] | None,
    namespace: str | None,
    name: str,
    param: SourceResource,
    **_: Any,
) -> Mapping[DependencyKey, DependentResource]:
    """Index one CR by every Secret or operator CR it references."""
    if not namespace or not name:
        return {}

    metadata = _mapping(body.get("metadata"))
    annotations = _mapping(metadata.get("annotations"))
    dependent = DependentResource(
        namespace=namespace,
        plural=param.plural,
        name=name,
        current_trigger=_non_empty_string(annotations.get(DEPENDENCY_TRIGGER_ANNOTATION)),
    )
    return {
        dependency: dependent
        for dependency in dependency_keys_for_resource(
            plural=param.plural,
            spec=spec,
            namespace=namespace,
        )
    }


def dependency_keys_for_resource(
    *,
    plural: str,
    spec: Mapping[str, Any] | None,
    namespace: str,
) -> set[DependencyKey]:
    """Return the Kubernetes resources whose changes should reconcile one CR."""
    if not isinstance(spec, Mapping):
        return set()

    dependencies: set[DependencyKey] = set()
    if plural != KEYCLOAK_TARGET_PLURAL:
        _add_custom_resource_ref(
            dependencies,
            KEYCLOAK_TARGET_PLURAL,
            namespace,
            spec.get("targetRef"),
        )

    if plural == KEYCLOAK_TARGET_PLURAL:
        _add_target_secret_dependencies(dependencies, spec, namespace)
    elif plural == KEYCLOAK_CLIENT_PLURAL:
        _add_secret_ref(dependencies, spec.get("secretRef"), namespace)
        for scope_name in _string_values(spec.get("defaultClientScopes")):
            dependencies.add(
                _dependency_key(API_GROUP, KEYCLOAK_CLIENT_SCOPE_PLURAL, namespace, scope_name)
            )
        for scope_name in _string_values(spec.get("optionalClientScopes")):
            dependencies.add(
                _dependency_key(API_GROUP, KEYCLOAK_CLIENT_SCOPE_PLURAL, namespace, scope_name)
            )
    elif plural == KEYCLOAK_CLIENT_ROLE_PLURAL:
        _add_custom_resource_ref(
            dependencies,
            KEYCLOAK_CLIENT_PLURAL,
            namespace,
            spec.get("clientRef"),
        )
    elif plural == KEYCLOAK_GROUP_ROLE_MAPPING_PLURAL:
        _add_group_role_mapping_dependencies(dependencies, spec, namespace)
    elif plural == KEYCLOAK_IDENTITY_PROVIDER_PLURAL:
        config_secret_refs = _mapping(spec.get("configSecretRefs"))
        for secret_ref in config_secret_refs.values():
            _add_secret_ref(dependencies, secret_ref, namespace)
    elif plural == KEYCLOAK_PROTOCOL_MAPPER_PLURAL:
        _add_protocol_mapper_dependency(dependencies, spec, namespace)

    return dependencies


def _add_target_secret_dependencies(
    dependencies: set[DependencyKey],
    spec: Mapping[str, Any],
    namespace: str,
) -> None:
    admin_credentials = _mapping(spec.get("adminCredentials"))
    _add_secret_ref(dependencies, admin_credentials.get("secretRef"), namespace)

    auth = _mapping(spec.get("auth"))
    for credentials_field in (
        "password",
        "bootstrapAdminCredentials",
        "clientCredentials",
    ):
        credentials = _mapping(auth.get(credentials_field))
        _add_secret_ref(dependencies, credentials.get("secretRef"), namespace)


def _add_group_role_mapping_dependencies(
    dependencies: set[DependencyKey],
    spec: Mapping[str, Any],
    namespace: str,
) -> None:
    _add_custom_resource_ref(
        dependencies,
        KEYCLOAK_GROUP_PLURAL,
        namespace,
        spec.get("groupRef"),
    )
    role = _mapping(spec.get("role"))
    role_type = _non_empty_string(role.get("type"))
    if role_type == "ClientRole":
        _add_custom_resource_ref(
            dependencies,
            KEYCLOAK_CLIENT_ROLE_PLURAL,
            namespace,
            role.get("roleRef"),
        )
        _add_custom_resource_ref(
            dependencies,
            KEYCLOAK_CLIENT_PLURAL,
            namespace,
            role.get("clientRef"),
        )
    elif role_type == "RealmRole":
        _add_custom_resource_ref(
            dependencies,
            KEYCLOAK_ROLE_PLURAL,
            namespace,
            role.get("roleRef"),
        )


def _add_protocol_mapper_dependency(
    dependencies: set[DependencyKey],
    spec: Mapping[str, Any],
    namespace: str,
) -> None:
    parent = _mapping(spec.get("parent"))
    parent_type = _non_empty_string(parent.get("type"))
    if parent_type == "Client":
        _add_custom_resource_ref(
            dependencies,
            KEYCLOAK_CLIENT_PLURAL,
            namespace,
            parent.get("clientRef"),
        )
    elif parent_type == "ClientScope":
        _add_custom_resource_ref(
            dependencies,
            KEYCLOAK_CLIENT_SCOPE_PLURAL,
            namespace,
            parent.get("clientScopeRef"),
        )


def _add_custom_resource_ref(
    dependencies: set[DependencyKey],
    plural: str,
    namespace: str,
    reference: Any,
) -> None:
    name = _non_empty_string(_mapping(reference).get("name"))
    if name:
        dependencies.add(_dependency_key(API_GROUP, plural, namespace, name))


def _add_secret_ref(
    dependencies: set[DependencyKey],
    reference: Any,
    resource_namespace: str,
) -> None:
    secret_ref = _mapping(reference)
    name = _non_empty_string(secret_ref.get("name"))
    namespace = _non_empty_string(secret_ref.get("namespace")) or resource_namespace
    if name:
        dependencies.add(_dependency_key(CORE_API_GROUP, SECRET_PLURAL, namespace, name))


def _dependency_key(group: str, plural: str, namespace: str, name: str) -> DependencyKey:
    return (group, plural, namespace, name)


DEPENDENCY_SOURCES = (
    SECRET_RESOURCE,
    SourceResource(API_GROUP, API_VERSION, KEYCLOAK_TARGET_PLURAL),
    SourceResource(API_GROUP, API_VERSION, KEYCLOAK_CLIENT_PLURAL),
    SourceResource(API_GROUP, API_VERSION, KEYCLOAK_CLIENT_ROLE_PLURAL),
    SourceResource(API_GROUP, API_VERSION, KEYCLOAK_GROUP_PLURAL),
    SourceResource(API_GROUP, API_VERSION, KEYCLOAK_ROLE_PLURAL),
    SourceResource(API_GROUP, API_VERSION, KEYCLOAK_CLIENT_SCOPE_PLURAL),
)


@kopf.on.event(**_resource(DEPENDENCY_SOURCES[0]), param=DEPENDENCY_SOURCES[0])
@kopf.on.event(**_resource(DEPENDENCY_SOURCES[1]), param=DEPENDENCY_SOURCES[1])
@kopf.on.event(**_resource(DEPENDENCY_SOURCES[2]), param=DEPENDENCY_SOURCES[2])
@kopf.on.event(**_resource(DEPENDENCY_SOURCES[3]), param=DEPENDENCY_SOURCES[3])
@kopf.on.event(**_resource(DEPENDENCY_SOURCES[4]), param=DEPENDENCY_SOURCES[4])
@kopf.on.event(**_resource(DEPENDENCY_SOURCES[5]), param=DEPENDENCY_SOURCES[5])
@kopf.on.event(**_resource(DEPENDENCY_SOURCES[6]), param=DEPENDENCY_SOURCES[6])
def enqueue_dependents(
    body: Mapping[str, Any],
    namespace: str | None,
    name: str,
    param: SourceResource,
    custom_objects_api: Any | None = None,
    **indices: Any,
) -> int:
    """Patch dependent CR annotations so their normal update handlers reconcile them."""
    if not namespace or not name:
        return 0

    source_keys = source_dependency_keys(
        source=param,
        body=body,
        namespace=namespace,
        name=name,
    )
    dependents = _dependents_for_keys(source_keys, indices)
    trigger = _dependency_trigger_value(param, body, namespace, name)
    api = custom_objects_api or kubernetes_client.CustomObjectsApi()
    patched = 0
    for dependent in dependents:
        if dependent.current_trigger == trigger:
            continue
        try:
            api.patch_namespaced_custom_object(
                group=API_GROUP,
                version=API_VERSION,
                namespace=dependent.namespace,
                plural=dependent.plural,
                name=dependent.name,
                body={
                    "metadata": {
                        "annotations": {DEPENDENCY_TRIGGER_ANNOTATION: trigger},
                    }
                },
            )
        except ApiException as exc:
            if exc.status == 404:
                continue
            raise
        patched += 1

    return patched


def source_dependency_keys(
    *,
    source: SourceResource,
    body: Mapping[str, Any],
    namespace: str,
    name: str,
) -> set[DependencyKey]:
    """Return source keys, including supported Keycloak natural-key aliases."""
    names = {name}
    spec = _mapping(body.get("spec"))
    natural_key_field = {
        KEYCLOAK_CLIENT_PLURAL: "clientId",
        KEYCLOAK_CLIENT_ROLE_PLURAL: "name",
        KEYCLOAK_GROUP_PLURAL: "name",
        KEYCLOAK_ROLE_PLURAL: "name",
        KEYCLOAK_CLIENT_SCOPE_PLURAL: "name",
    }.get(source.plural)
    if natural_key_field:
        natural_key = _non_empty_string(spec.get(natural_key_field))
        if natural_key:
            names.add(natural_key)

    return {
        _dependency_key(source.group, source.plural, namespace, source_name)
        for source_name in names
    }


def _dependents_for_keys(
    source_keys: Collection[DependencyKey],
    indices: Mapping[str, Any],
) -> set[DependentResource]:
    dependents: set[DependentResource] = set()
    for index_id in DEPENDENCY_INDEX_IDS:
        index = indices.get(index_id)
        if index is None:
            continue
        for source_key in source_keys:
            if source_key in index:
                dependents.update(index[source_key])
    return dependents


def _dependency_trigger_value(
    source: SourceResource,
    body: Mapping[str, Any],
    namespace: str,
    name: str,
) -> str:
    metadata = _mapping(body.get("metadata"))
    resource_version = _non_empty_string(metadata.get("resourceVersion")) or "unknown"
    group = source.group or "core"
    return f"{group}/{source.plural}/{namespace}/{name}@{resource_version}"


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _non_empty_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _string_values(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
