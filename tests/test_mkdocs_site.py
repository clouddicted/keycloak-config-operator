import tomllib
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CRD_DIR = REPO_ROOT / "config" / "crd"
API_REFERENCE = REPO_ROOT / "docs" / "api-reference.md"
MKDOCS_CONFIG = REPO_ROOT / "mkdocs.yml"
PYPROJECT = REPO_ROOT / "pyproject.toml"
GITIGNORE = REPO_ROOT / ".gitignore"


def test_mkdocs_configuration_uses_project_metadata() -> None:
    config = _load_mkdocs()

    assert config["site_name"] == "Keycloak Config Operator"
    assert config["site_url"] == "https://clouddicted.github.io/keycloak-config-operator/"
    assert config["repo_url"] == "https://github.com/clouddicted/keycloak-config-operator"
    assert config["theme"]["name"] == "material"
    assert config["strict"] is True
    assert config["extra"]["version"] == {"provider": "mike", "alias": True}


def test_mkdocs_nav_points_to_existing_docs() -> None:
    config = _load_mkdocs()
    nav_paths = _nav_paths(config["nav"])

    assert nav_paths == {
        "api-reference.md",
        "compatibility.md",
        "configuration-support.md",
        "getting-started.md",
        "index.md",
        "resources/index.md",
        "resources/keycloak-client-scope.md",
        "resources/keycloak-client.md",
        "resources/keycloak-identity-provider.md",
        "resources/keycloak-protocol-mapper.md",
        "resources/keycloak-realm.md",
        "resources/keycloak-role.md",
        "resources/keycloak-target.md",
        "usage.md",
    }
    for nav_path in nav_paths:
        assert (REPO_ROOT / "docs" / nav_path).exists()


def test_docs_extra_installs_mkdocs_material() -> None:
    pyproject = tomllib.loads(PYPROJECT.read_text())

    assert "mike>=2.2,<3" in pyproject["project"]["optional-dependencies"]["docs"]
    assert "mkdocs>=1.6,<2" in pyproject["project"]["optional-dependencies"]["docs"]
    assert (
        "mkdocs-crd-viewer>=0.2.1,<1"
        in pyproject["project"]["optional-dependencies"]["docs"]
    )
    assert (
        "mkdocs-material>=9.6,<10"
        in pyproject["project"]["optional-dependencies"]["docs"]
    )


def test_mkdocs_renders_crd_api_reference_with_crd_viewer() -> None:
    config = _load_mkdocs()
    plugins = config["plugins"]
    api_reference = API_REFERENCE.read_text()

    assert "crd-viewer" in plugins
    assert {"macros": {"modules": ["mkdocs_crd_viewer.macros"]}} in plugins
    for crd in sorted(CRD_DIR.glob("keycloak.clouddicted.com_*.yaml")):
        assert str(crd.relative_to(REPO_ROOT)) in api_reference


def test_site_build_output_is_ignored() -> None:
    assert "site/" in GITIGNORE.read_text().splitlines()


def _load_mkdocs() -> dict[str, Any]:
    with MKDOCS_CONFIG.open() as stream:
        config = yaml.safe_load(stream)

    assert isinstance(config, dict)
    return config


def _nav_paths(nav: list[Any]) -> set[str]:
    paths: set[str] = set()
    for item in nav:
        assert isinstance(item, dict)
        for value in item.values():
            if isinstance(value, str):
                paths.add(value)
            elif isinstance(value, list):
                paths.update(_nav_paths(value))

    return paths
