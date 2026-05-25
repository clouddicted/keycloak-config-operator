import ast
import tomllib
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CRD_DIR = REPO_ROOT / "config" / "crd"
COMPATIBILITY_DOC = REPO_ROOT / "docs" / "compatibility.md"
CONFIGURATION_SUPPORT_DOC = REPO_ROOT / "docs" / "configuration-support.md"
README = REPO_ROOT / "README.md"
CONTRIBUTING = REPO_ROOT / "CONTRIBUTING.md"
SECURITY = REPO_ROOT / "SECURITY.md"
LICENSE = REPO_ROOT / "LICENSE"
NOTICE = REPO_ROOT / "NOTICE"
PYPROJECT = REPO_ROOT / "pyproject.toml"
KEYCLOAK_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "keycloak.yaml"
KIND_FIXTURES_MODULE = REPO_ROOT / "tests" / "integration" / "test_kind_fixtures.py"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def test_readme_links_compatibility_and_configuration_support_docs() -> None:
    readme = README.read_text()

    assert "[docs/compatibility.md](docs/compatibility.md)" in readme
    assert "[docs/configuration-support.md](docs/configuration-support.md)" in readme
    assert "[docs/api-reference.md](docs/api-reference.md)" in readme


def test_install_docs_reference_published_helm_chart() -> None:
    chart_ref = "oci://ghcr.io/clouddicted/charts/keycloak-config-operator"

    assert chart_ref in README.read_text()
    assert chart_ref in (REPO_ROOT / "docs" / "index.md").read_text()


def test_readme_shows_ci_and_version_badges() -> None:
    readme = README.read_text()

    assert (
        "[![CI](https://github.com/clouddicted/keycloak-config-operator/"
        "actions/workflows/ci.yml/badge.svg)]"
    ) in readme
    assert (
        "[![Version](https://img.shields.io/github/v/tag/"
        "clouddicted/keycloak-config-operator?sort=semver&label=version)]"
    ) in readme


def test_configuration_support_documents_every_crd_spec_field() -> None:
    text = CONFIGURATION_SUPPORT_DOC.read_text()

    for kind, field_names in _crd_spec_fields().items():
        assert kind in text
        for field_name in field_names:
            assert f"`spec.{field_name}`" in text, f"{kind} spec.{field_name} is undocumented"


def test_crd_spec_and_status_fields_have_descriptions() -> None:
    for path in CRD_DIR.glob("keycloak*.yaml"):
        crd = _load_one(path)
        version = crd["spec"]["versions"][0]
        schema = version["schema"]["openAPIV3Schema"]
        kind = crd["spec"]["names"]["kind"]

        for section in ("spec", "status"):
            section_schema = schema["properties"][section]
            missing = _missing_schema_descriptions(section_schema, section)

            assert not missing, f"{kind} has CRD fields without descriptions: {missing}"


def test_contributing_requires_support_docs_for_contract_changes() -> None:
    text = CONTRIBUTING.read_text()

    assert "`docs/configuration-support.md`" in text
    assert "`docs/compatibility.md`" in text


def test_security_policy_documents_reporting_and_supported_versions() -> None:
    text = SECURITY.read_text()

    assert "Do not open a public issue" in text
    assert "security/advisories/new" in text
    assert "`0.2.x`" in text
    assert "Kubernetes Secrets" in text
    assert "namespace watch scope" in text


def test_license_notice_and_package_metadata_are_aligned() -> None:
    readme = README.read_text()
    license_text = LICENSE.read_text()
    notice = NOTICE.read_text()
    pyproject = tomllib.loads(PYPROJECT.read_text())

    assert "Apache License" in license_text
    assert "Version 2.0" in license_text
    assert "Copyright 2026 Clouddicted" in license_text
    assert "Keycloak Config Operator" in notice
    assert "Copyright 2026 Clouddicted" in notice
    assert "[LICENSE](LICENSE)" in readme
    assert "[NOTICE](NOTICE)" in readme
    assert pyproject["project"]["license"] == {"file": "LICENSE"}
    assert (
        "License :: OSI Approved :: Apache Software License"
        in pyproject["project"]["classifiers"]
    )


def test_compatibility_doc_matches_ci_and_kind_fixture_versions() -> None:
    workflow = _load_one(CI_WORKFLOW)
    compatibility = COMPATIBILITY_DOC.read_text()
    fixture_images = [
        container["image"]
        for document in _load_yaml_documents(KEYCLOAK_FIXTURE)
        if document["kind"] == "Deployment"
        for container in document["spec"]["template"]["spec"]["containers"]
    ]

    default_version = workflow["env"]["KEYCLOAK_VERSION"]
    compatibility_version = workflow["env"]["KEYCLOAK_COMPATIBILITY_VERSION"]

    assert _module_constant(KIND_FIXTURES_MODULE, "DEFAULT_KEYCLOAK_VERSION") == default_version
    assert fixture_images == [f"quay.io/keycloak/keycloak:{default_version}"]
    assert f"`{default_version}`" in compatibility
    assert f"`{compatibility_version}`" in compatibility
    assert "KEYCLOAK_VERSION" in compatibility


def _crd_spec_fields() -> dict[str, set[str]]:
    fields_by_kind: dict[str, set[str]] = {}
    for path in CRD_DIR.glob("keycloak*.yaml"):
        crd = _load_one(path)
        version = crd["spec"]["versions"][0]
        spec_schema = version["schema"]["openAPIV3Schema"]["properties"]["spec"]
        fields_by_kind[crd["spec"]["names"]["kind"]] = set(spec_schema["properties"])

    return fields_by_kind


def _missing_schema_descriptions(schema: dict[str, Any], path: str) -> list[str]:
    missing: list[str] = []
    if not str(schema.get("description", "")).strip():
        missing.append(path)

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child_schema in properties.items():
            if isinstance(child_schema, dict):
                missing.extend(_missing_schema_descriptions(child_schema, f"{path}.{name}"))

    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        missing.extend(_missing_schema_descriptions(additional, f"{path}.*"))

    items = schema.get("items")
    if isinstance(items, dict):
        item_properties = items.get("properties")
        if isinstance(item_properties, dict):
            for name, child_schema in item_properties.items():
                if isinstance(child_schema, dict):
                    missing.extend(
                        _missing_schema_descriptions(child_schema, f"{path}[].{name}")
                    )

    return missing


def _load_one(path: Path) -> dict[str, Any]:
    documents = _load_yaml_documents(path)
    assert len(documents) == 1
    return documents[0]


def _load_yaml_documents(path: Path) -> list[dict[str, Any]]:
    with path.open() as stream:
        return [document for document in yaml.safe_load_all(stream) if document is not None]


def _module_constant(path: Path, name: str) -> str:
    module = ast.parse(path.read_text())
    for statement in module.body:
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == name
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            return statement.value.value

    raise AssertionError(f"{name} was not found in {path}")
