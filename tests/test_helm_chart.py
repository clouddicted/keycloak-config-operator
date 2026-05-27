import json
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CHART_DIR = REPO_ROOT / "charts" / "keycloak-config-operator"
CHART_CRD_DIR = CHART_DIR / "crds"
CONFIG_CRD_DIR = REPO_ROOT / "config" / "crd"
OPERATOR_IMAGE_REPOSITORY = "ghcr.io/clouddicted/keycloak-config-operator"


def test_helm_chart_metadata_matches_operator_release() -> None:
    chart = _load_one(CHART_DIR / "Chart.yaml")

    assert chart == {
        "apiVersion": "v2",
        "name": "keycloak-config-operator",
        "description": "Helm chart for the Clouddicted Keycloak Config Operator",
        "type": "application",
        "version": "0.3.0",
        "appVersion": "v0.3.0",
    }


def test_helm_values_default_to_operator_installation() -> None:
    values = _load_one(CHART_DIR / "values.yaml")

    assert values["replicaCount"] == 1
    assert values["image"] == {
        "repository": OPERATOR_IMAGE_REPOSITORY,
        "pullPolicy": "IfNotPresent",
        "tag": "",
    }
    assert values["serviceAccount"]["create"] is True
    assert values["serviceAccount"]["automount"] is True
    assert values["rbac"]["create"] is True
    assert values["watchNamespaces"] == []
    assert values["podSecurityContext"] == {
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert values["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }


def test_helm_values_schema_validates_watch_namespaces() -> None:
    schema = json.loads((CHART_DIR / "values.schema.json").read_text())
    watch_namespaces = schema["properties"]["watchNamespaces"]

    assert watch_namespaces["type"] == "array"
    assert watch_namespaces["default"] == []
    assert watch_namespaces["uniqueItems"] is True
    assert watch_namespaces["items"] == {"type": "string", "minLength": 1}


def test_helm_chart_packages_current_crds() -> None:
    config_crds = _crd_file_names(CONFIG_CRD_DIR)
    chart_crds = _crd_file_names(CHART_CRD_DIR)

    assert chart_crds == config_crds
    for file_name in config_crds:
        assert (CHART_CRD_DIR / file_name).read_text() == (
            CONFIG_CRD_DIR / file_name
        ).read_text()


def test_helm_templates_are_operator_scoped() -> None:
    template_paths = {
        path.relative_to(CHART_DIR).as_posix()
        for path in (CHART_DIR / "templates").rglob("*")
        if path.is_file()
    }

    assert template_paths == {
        "templates/NOTES.txt",
        "templates/_helpers.tpl",
        "templates/deployment.yaml",
        "templates/rbac.yaml",
        "templates/serviceaccount.yaml",
    }


def test_helm_deployment_template_runs_kopf_operator() -> None:
    deployment_template = (CHART_DIR / "templates" / "deployment.yaml").read_text()

    assert "image: \"{{ .Values.image.repository }}:" in deployment_template
    assert "- kopf" in deployment_template
    assert "- clouddicted_keycloak_config_operator.main" in deployment_template
    assert "- --all-namespaces" in deployment_template
    assert "range .Values.watchNamespaces" in deployment_template
    assert "- --namespace" in deployment_template
    assert "name: PYTHONUNBUFFERED" in deployment_template
    assert "containerPort" not in deployment_template
    assert "livenessProbe" not in deployment_template
    assert "readinessProbe" not in deployment_template


def test_helm_rbac_template_limits_selected_namespace_permissions() -> None:
    rbac_template = (CHART_DIR / "templates" / "rbac.yaml").read_text()

    assert "if not .Values.watchNamespaces" in rbac_template
    assert "range $namespace := .Values.watchNamespaces" in rbac_template
    assert "kind: ClusterRole" in rbac_template
    assert "customresourcedefinitions" in rbac_template
    assert "kind: Role" in rbac_template
    assert "kind: RoleBinding" in rbac_template


def _load_one(path: Path) -> dict[str, Any]:
    with path.open() as stream:
        document = yaml.safe_load(stream)

    assert isinstance(document, dict)
    return document


def _crd_file_names(path: Path) -> list[str]:
    return sorted(
        file_path.name
        for file_path in path.glob("*.yaml")
        if file_path.name != "kustomization.yaml"
    )
