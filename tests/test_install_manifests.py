from pathlib import Path
from typing import Any

import yaml

from clouddicted_keycloak_config_operator.constants import (
    API_GROUP,
    API_VERSION,
    KEYCLOAK_CLIENT_PLURAL,
    KEYCLOAK_CLIENT_SCOPE_PLURAL,
    KEYCLOAK_IDENTITY_PROVIDER_PLURAL,
    KEYCLOAK_PROTOCOL_MAPPER_PLURAL,
    KEYCLOAK_REALM_PLURAL,
    KEYCLOAK_ROLE_PLURAL,
    KEYCLOAK_TARGET_PLURAL,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = REPO_ROOT / "config"
INSTALL_DIR = CONFIG_DIR / "install"
OPERATOR_NAMESPACE = "keycloak-config-operator-system"
OPERATOR_NAME = "keycloak-config-operator"
OPERATOR_IMAGE = "ghcr.io/clouddicted/keycloak-config-operator:v0.3.0"
OPERATOR_ARGS = [
    "run",
    "-m",
    "clouddicted_keycloak_config_operator.main",
    "--all-namespaces",
]
CUSTOM_RESOURCES = {
    KEYCLOAK_TARGET_PLURAL,
    KEYCLOAK_REALM_PLURAL,
    KEYCLOAK_CLIENT_PLURAL,
    KEYCLOAK_IDENTITY_PROVIDER_PLURAL,
    KEYCLOAK_ROLE_PLURAL,
    KEYCLOAK_CLIENT_SCOPE_PLURAL,
    KEYCLOAK_PROTOCOL_MAPPER_PLURAL,
}


def test_install_kustomization_lists_expected_resources() -> None:
    kustomization = _load_one(INSTALL_DIR / "kustomization.yaml")

    assert kustomization == {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": [
            "../crd",
            "namespace.yaml",
            "service-account.yaml",
            "rbac.yaml",
            "deployment.yaml",
        ],
    }


def test_crd_and_sample_kustomizations_reference_existing_files() -> None:
    for path in (
        CONFIG_DIR / "crd" / "kustomization.yaml",
        CONFIG_DIR / "samples" / "kustomization.yaml",
    ):
        kustomization = _load_one(path)

        assert kustomization["kind"] == "Kustomization"
        assert kustomization["resources"]
        for resource in kustomization["resources"]:
            assert (path.parent / resource).exists()


def test_public_manifests_use_beta_api_version() -> None:
    assert API_VERSION == "v1beta1"
    old_api_version = "v1" + "alpha1"
    old_sample_prefix = "keycloak_v1" + "alpha1"

    checked_paths = [
        *CONFIG_DIR.rglob("*.yaml"),
        *(REPO_ROOT / "charts" / "keycloak-config-operator" / "crds").rglob("*.yaml"),
        *(REPO_ROOT / "tests" / "fixtures").rglob("*.yaml"),
        REPO_ROOT / "tests" / "integration" / "test_kind_fixtures.py",
    ]

    for path in checked_paths:
        text = path.read_text()
        assert old_api_version not in text
        assert old_sample_prefix not in text


def test_keycloak_client_crd_validates_common_user_mistakes() -> None:
    spec_schema = _crd_spec_schema(
        CONFIG_DIR / "crd" / "keycloak.clouddicted.com_keycloakclients.yaml"
    )
    spec_properties = spec_schema["properties"]

    assert spec_schema["x-kubernetes-validations"] == [
        {
            "rule": (
                "!has(self.serviceAccountsEnabled) || "
                "self.serviceAccountsEnabled == false || "
                "(has(self.clientType) && self.clientType == 'Confidential')"
            ),
            "message": (
                "serviceAccountsEnabled can be true only when clientType is Confidential."
            ),
        }
    ]
    for field_name in (
        "redirectUris",
        "webOrigins",
        "defaultClientScopes",
        "optionalClientScopes",
    ):
        assert spec_properties[field_name]["x-kubernetes-list-type"] == "set"


def test_crds_use_standard_status_condition_schema() -> None:
    condition_schemas = {
        path.name: _crd_condition_schema(path)
        for path in (CONFIG_DIR / "crd").glob("keycloak.clouddicted.com_*.yaml")
    }
    [expected_schema] = {yaml.dump(schema, sort_keys=True) for schema in condition_schemas.values()}

    for file_name, condition_schema in condition_schemas.items():
        assert yaml.dump(condition_schema, sort_keys=True) == expected_schema, file_name
        assert (
            condition_schema["description"]
            == "Current Kubernetes-style status conditions."
        )


def test_deployment_uses_kopf_module_entrypoint() -> None:
    deployment = _load_one(INSTALL_DIR / "deployment.yaml")
    pod_spec = deployment["spec"]["template"]["spec"]
    [container] = pod_spec["containers"]

    assert deployment["kind"] == "Deployment"
    assert deployment["metadata"]["namespace"] == OPERATOR_NAMESPACE
    assert pod_spec["serviceAccountName"] == OPERATOR_NAME
    assert pod_spec["securityContext"] == {
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert container["name"] == "manager"
    assert container["image"] == OPERATOR_IMAGE
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }
    assert container["command"] == ["kopf"]
    assert container["args"] == OPERATOR_ARGS


def test_dockerfile_defaults_to_all_namespaces_with_overridable_args() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text()

    assert "COPY pyproject.toml README.md LICENSE NOTICE ./" in dockerfile
    assert (
        'ENTRYPOINT ["kopf", "run", "-m", '
        '"clouddicted_keycloak_config_operator.main"]'
    ) in dockerfile
    assert 'CMD ["--all-namespaces"]' in dockerfile


def test_rbac_grants_current_operator_permissions_without_wildcards() -> None:
    rules = _cluster_role()["rules"]

    for rule in rules:
        assert "*" not in rule["apiGroups"]
        assert "*" not in rule["resources"]
        assert "*" not in rule["verbs"]

    secret_rule = _rule_for(rules, api_group="", resources={"secrets"})
    assert set(secret_rule["verbs"]) == {"get", "create", "patch"}

    event_rule = _rule_for(rules, api_group="", resources={"events"})
    assert set(event_rule["verbs"]) == {"create", "patch"}

    crd_rule = _rule_for(
        rules,
        api_group="apiextensions.k8s.io",
        resources={"customresourcedefinitions"},
    )
    assert set(crd_rule["verbs"]) == {"list", "watch"}

    resource_rule = _rule_for(rules, api_group=API_GROUP, resources=CUSTOM_RESOURCES)
    assert set(resource_rule["verbs"]) == {"get", "list", "watch", "patch", "update"}

    status_rule = _rule_for(
        rules,
        api_group=API_GROUP,
        resources={f"{resource}/status" for resource in CUSTOM_RESOURCES},
    )
    assert set(status_rule["verbs"]) == {"get", "patch", "update"}

    finalizer_rule = _rule_for(
        rules,
        api_group=API_GROUP,
        resources={f"{resource}/finalizers" for resource in CUSTOM_RESOURCES},
    )
    assert set(finalizer_rule["verbs"]) == {"patch", "update"}


def test_rbac_binds_service_account_in_operator_namespace() -> None:
    binding = _cluster_role_binding()

    assert binding["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "ClusterRole",
        "name": OPERATOR_NAME,
    }
    assert binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": OPERATOR_NAME,
            "namespace": OPERATOR_NAMESPACE,
        }
    ]


def _load_yaml_documents(path: Path) -> list[dict[str, Any]]:
    with path.open() as stream:
        return [document for document in yaml.safe_load_all(stream) if document is not None]


def _load_one(path: Path) -> dict[str, Any]:
    documents = _load_yaml_documents(path)
    assert len(documents) == 1
    return documents[0]


def _cluster_role() -> dict[str, Any]:
    return _document_by_kind(INSTALL_DIR / "rbac.yaml", "ClusterRole")


def _cluster_role_binding() -> dict[str, Any]:
    return _document_by_kind(INSTALL_DIR / "rbac.yaml", "ClusterRoleBinding")


def _document_by_kind(path: Path, kind: str) -> dict[str, Any]:
    for document in _load_yaml_documents(path):
        if document["kind"] == kind:
            return document

    raise AssertionError(f"{kind} was not found in {path}")


def _crd_spec_schema(path: Path) -> dict[str, Any]:
    crd = _load_one(path)
    version = crd["spec"]["versions"][0]
    return version["schema"]["openAPIV3Schema"]["properties"]["spec"]


def _crd_condition_schema(path: Path) -> dict[str, Any]:
    crd = _load_one(path)
    version = crd["spec"]["versions"][0]
    return version["schema"]["openAPIV3Schema"]["properties"]["status"]["properties"][
        "conditions"
    ]


def _rule_for(
    rules: list[dict[str, Any]],
    *,
    api_group: str,
    resources: set[str],
) -> dict[str, Any]:
    for rule in rules:
        if set(rule["apiGroups"]) == {api_group} and set(rule["resources"]) == resources:
            return rule

    raise AssertionError(f"missing rule for {api_group or 'core'} {sorted(resources)}")
