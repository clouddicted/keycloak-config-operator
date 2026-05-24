import tomllib
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
MKDOCS_CONFIG = REPO_ROOT / "mkdocs.yml"
PYPROJECT = REPO_ROOT / "pyproject.toml"
GITIGNORE = REPO_ROOT / ".gitignore"


def test_mkdocs_configuration_uses_project_metadata() -> None:
    config = _load_mkdocs()

    assert config["site_name"] == "Keycloak Config Operator"
    assert config["site_url"] == "https://clouddicted.github.io/keycloak-config-operator/"
    assert config["repo_url"] == "https://github.com/clouddicted/keycloak-config-operator"
    assert config["theme"]["name"] == "material"


def test_mkdocs_nav_points_to_existing_docs() -> None:
    config = _load_mkdocs()
    nav_paths = _nav_paths(config["nav"])

    assert nav_paths == {
        "index.md",
        "compatibility.md",
        "configuration-support.md",
    }
    for nav_path in nav_paths:
        assert (REPO_ROOT / "docs" / nav_path).exists()


def test_docs_extra_installs_mkdocs_material() -> None:
    pyproject = tomllib.loads(PYPROJECT.read_text())

    assert "mkdocs>=1.6,<2" in pyproject["project"]["optional-dependencies"]["docs"]
    assert (
        "mkdocs-material>=9.6,<10"
        in pyproject["project"]["optional-dependencies"]["docs"]
    )


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
