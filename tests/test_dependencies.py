from typing import Any

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
    KEYCLOAK_ROLE_PLURAL,
    KEYCLOAK_TARGET_PLURAL,
)
from clouddicted_keycloak_config_operator.handlers import dependencies


class FakeCustomObjectsApi:
    def __init__(self, error: ApiException | None = None) -> None:
        self.error = error
        self.patches: list[dict[str, Any]] = []

    def patch_namespaced_custom_object(self, **kwargs: Any) -> None:
        if self.error is not None:
            raise self.error
        self.patches.append(kwargs)


def _key(group: str, plural: str, namespace: str, name: str) -> dependencies.DependencyKey:
    return (group, plural, namespace, name)


def test_target_dependencies_include_all_credential_secret_shapes() -> None:
    keys = dependencies.dependency_keys_for_resource(
        plural=KEYCLOAK_TARGET_PLURAL,
        namespace="apps",
        spec={
            "adminCredentials": {"secretRef": {"name": "legacy"}},
            "auth": {
                "password": {"secretRef": {"name": "password"}},
                "bootstrapAdminCredentials": {
                    "secretRef": {"name": "bootstrap", "namespace": "platform"}
                },
                "clientCredentials": {"secretRef": {"name": "client"}},
            },
        },
    )

    assert keys == {
        _key("", "secrets", "apps", "legacy"),
        _key("", "secrets", "apps", "password"),
        _key("", "secrets", "platform", "bootstrap"),
        _key("", "secrets", "apps", "client"),
    }


def test_client_dependencies_include_target_secret_and_client_scopes() -> None:
    keys = dependencies.dependency_keys_for_resource(
        plural=KEYCLOAK_CLIENT_PLURAL,
        namespace="apps",
        spec={
            "targetRef": {"name": "keycloak"},
            "secretRef": {"name": "client-secret"},
            "defaultClientScopes": ["profile", "email"],
            "optionalClientScopes": ["offline_access", "profile"],
        },
    )

    assert keys == {
        _key(API_GROUP, KEYCLOAK_TARGET_PLURAL, "apps", "keycloak"),
        _key("", "secrets", "apps", "client-secret"),
        _key(API_GROUP, KEYCLOAK_CLIENT_SCOPE_PLURAL, "apps", "profile"),
        _key(API_GROUP, KEYCLOAK_CLIENT_SCOPE_PLURAL, "apps", "email"),
        _key(API_GROUP, KEYCLOAK_CLIENT_SCOPE_PLURAL, "apps", "offline_access"),
    }


def test_group_role_mapping_dependencies_include_managed_references() -> None:
    keys = dependencies.dependency_keys_for_resource(
        plural=KEYCLOAK_GROUP_ROLE_MAPPING_PLURAL,
        namespace="apps",
        spec={
            "targetRef": {"name": "keycloak"},
            "groupRef": {"name": "developers"},
            "role": {
                "type": "ClientRole",
                "clientRef": {"name": "console"},
                "roleRef": {"name": "admin"},
            },
        },
    )

    assert keys == {
        _key(API_GROUP, KEYCLOAK_TARGET_PLURAL, "apps", "keycloak"),
        _key(API_GROUP, KEYCLOAK_GROUP_PLURAL, "apps", "developers"),
        _key(API_GROUP, KEYCLOAK_CLIENT_PLURAL, "apps", "console"),
        _key(API_GROUP, KEYCLOAK_CLIENT_ROLE_PLURAL, "apps", "admin"),
    }


def test_identity_provider_and_protocol_mapper_dependencies() -> None:
    provider_keys = dependencies.dependency_keys_for_resource(
        plural=KEYCLOAK_IDENTITY_PROVIDER_PLURAL,
        namespace="apps",
        spec={
            "targetRef": {"name": "keycloak"},
            "configSecretRefs": {
                "clientSecret": {"name": "oidc-secret"},
                "signingKey": {"name": "signing-key", "namespace": "platform"},
            },
        },
    )
    mapper_keys = dependencies.dependency_keys_for_resource(
        plural=KEYCLOAK_PROTOCOL_MAPPER_PLURAL,
        namespace="apps",
        spec={
            "targetRef": {"name": "keycloak"},
            "parent": {
                "type": "ClientScope",
                "clientScopeRef": {"name": "profile"},
            },
        },
    )

    assert provider_keys == {
        _key(API_GROUP, KEYCLOAK_TARGET_PLURAL, "apps", "keycloak"),
        _key("", "secrets", "apps", "oidc-secret"),
        _key("", "secrets", "platform", "signing-key"),
    }
    assert mapper_keys == {
        _key(API_GROUP, KEYCLOAK_TARGET_PLURAL, "apps", "keycloak"),
        _key(API_GROUP, KEYCLOAK_CLIENT_SCOPE_PLURAL, "apps", "profile"),
    }


def test_index_resource_dependencies_records_dependent_and_trigger() -> None:
    result = dependencies.index_resource_dependencies(
        body={
            "metadata": {
                "annotations": {
                    dependencies.DEPENDENCY_TRIGGER_ANNOTATION: "existing-trigger"
                }
            }
        },
        spec={"targetRef": {"name": "keycloak"}},
        namespace="apps",
        name="example-realm",
        param=dependencies.SourceResource(API_GROUP, API_VERSION, "keycloakrealms"),
    )

    assert result == {
        _key(API_GROUP, KEYCLOAK_TARGET_PLURAL, "apps", "keycloak"): (
            dependencies.DependentResource(
                namespace="apps",
                plural="keycloakrealms",
                name="example-realm",
                current_trigger="existing-trigger",
            )
        )
    }


def test_enqueue_dependents_patches_each_resource_once_and_supports_natural_keys() -> None:
    source = dependencies.SourceResource(API_GROUP, API_VERSION, KEYCLOAK_CLIENT_PLURAL)
    dependent = dependencies.DependentResource(
        namespace="apps",
        plural=KEYCLOAK_CLIENT_ROLE_PLURAL,
        name="reader",
    )
    api = FakeCustomObjectsApi()
    source_by_metadata = _key(API_GROUP, KEYCLOAK_CLIENT_PLURAL, "apps", "client-cr")
    source_by_client_id = _key(API_GROUP, KEYCLOAK_CLIENT_PLURAL, "apps", "console")
    index = {
        source_by_metadata: [dependent],
        source_by_client_id: [dependent],
    }

    patched = dependencies.enqueue_dependents(
        body={
            "metadata": {"resourceVersion": "42"},
            "spec": {"clientId": "console"},
        },
        namespace="apps",
        name="client-cr",
        param=source,
        custom_objects_api=api,
        **{f"{KEYCLOAK_CLIENT_ROLE_PLURAL}_dependencies": index},
    )

    assert patched == 1
    assert api.patches == [
        {
            "group": API_GROUP,
            "version": API_VERSION,
            "namespace": "apps",
            "plural": KEYCLOAK_CLIENT_ROLE_PLURAL,
            "name": "reader",
            "body": {
                "metadata": {
                    "annotations": {
                        dependencies.DEPENDENCY_TRIGGER_ANNOTATION: (
                            f"{API_GROUP}/{KEYCLOAK_CLIENT_PLURAL}/apps/client-cr@42"
                        )
                    }
                }
            },
        }
    ]


def test_enqueue_dependents_skips_current_trigger_and_deleted_resources() -> None:
    source = dependencies.SECRET_RESOURCE
    trigger = "core/secrets/apps/credentials@12"
    current = dependencies.DependentResource(
        namespace="apps",
        plural=KEYCLOAK_TARGET_PLURAL,
        name="keycloak",
        current_trigger=trigger,
    )
    missing = dependencies.DependentResource(
        namespace="apps",
        plural=KEYCLOAK_CLIENT_PLURAL,
        name="deleted-client",
    )
    key = _key("", "secrets", "apps", "credentials")

    current_api = FakeCustomObjectsApi()
    assert (
        dependencies.enqueue_dependents(
            body={"metadata": {"resourceVersion": "12"}},
            namespace="apps",
            name="credentials",
            param=source,
            custom_objects_api=current_api,
            **{f"{KEYCLOAK_TARGET_PLURAL}_dependencies": {key: [current]}},
        )
        == 0
    )
    assert current_api.patches == []

    missing_api = FakeCustomObjectsApi(ApiException(status=404))
    assert (
        dependencies.enqueue_dependents(
            body={"metadata": {"resourceVersion": "12"}},
            namespace="apps",
            name="credentials",
            param=source,
            custom_objects_api=missing_api,
            **{f"{KEYCLOAK_CLIENT_PLURAL}_dependencies": {key: [missing]}},
        )
        == 0
    )


def test_realm_role_mapping_tracks_realm_role_dependency() -> None:
    keys = dependencies.dependency_keys_for_resource(
        plural=KEYCLOAK_GROUP_ROLE_MAPPING_PLURAL,
        namespace="apps",
        spec={
            "role": {"type": "RealmRole", "roleRef": {"name": "viewer"}},
        },
    )

    assert _key(API_GROUP, KEYCLOAK_ROLE_PLURAL, "apps", "viewer") in keys
