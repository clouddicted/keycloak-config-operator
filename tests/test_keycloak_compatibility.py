import json
from pathlib import Path

import pytest

from scripts.keycloak_compatibility import (
    CompatibilityVersions,
    StableVersion,
    build_pr_body,
    candidate_plan,
    load_versions,
    promote,
    render_documentation,
)


def test_stable_version_accepts_release_tags_and_orders_semantically() -> None:
    assert str(StableVersion.parse("v26.7.4")) == "26.7.4"
    assert StableVersion.parse("26.10.0") > StableVersion.parse("26.9.9")

    with pytest.raises(ValueError, match="invalid stable"):
        StableVersion.parse("26.8.0-rc1")


def test_candidate_plan_skips_a_version_already_in_the_rolling_pr() -> None:
    plan = candidate_plan(
        candidate="26.7.4",
        repository_versions=_versions(),
        rolling_default="26.7.4",
        releases=[],
        manual=False,
    )

    assert plan["shouldTest"] is False
    assert plan["testVersions"] == []
    assert plan["promotable"] is False


def test_candidate_plan_tests_new_patch_without_changing_previous_minor() -> None:
    versions = CompatibilityVersions(
        default=StableVersion.parse("26.7.3"),
        previous_minor=StableVersion.parse("26.6.2"),
    )

    plan = candidate_plan(
        candidate="26.7.4",
        repository_versions=versions,
        rolling_default=None,
        releases=[],
        manual=False,
    )

    assert plan == {
        "candidate": "26.7.4",
        "shouldTest": True,
        "testVersions": ["26.7.4"],
        "proposedPreviousMinor": "26.6.2",
        "promotable": True,
        "reason": "new stable release after 26.7.3",
    }


def test_candidate_plan_tests_latest_immediately_previous_minor() -> None:
    releases = [
        _release("26.8.0"),
        _release("26.7.4"),
        _release("26.7.3"),
        _release("26.6.2"),
        _release("26.7.5-rc1", prerelease=True),
    ]

    plan = candidate_plan(
        candidate="26.8.0",
        repository_versions=_versions(),
        rolling_default="26.7.3",
        releases=releases,
        manual=False,
    )

    assert plan["testVersions"] == ["26.8.0", "26.7.4"]
    assert plan["proposedPreviousMinor"] == "26.7.4"


def test_candidate_plan_preserves_rolling_previous_minor_for_superseding_patch() -> None:
    plan = candidate_plan(
        candidate="26.7.1",
        repository_versions=_versions(),
        rolling_default="26.7.0",
        rolling_previous_minor="26.6.4",
        releases=[],
        manual=False,
    )

    assert plan["testVersions"] == ["26.7.1"]
    assert plan["proposedPreviousMinor"] == "26.6.4"


def test_manual_plan_always_tests_only_requested_version() -> None:
    plan = candidate_plan(
        candidate="26.5.3",
        repository_versions=_versions(),
        rolling_default="26.7.4",
        releases=[],
        manual=True,
    )

    assert plan["shouldTest"] is True
    assert plan["testVersions"] == ["26.5.3"]
    assert plan["promotable"] is False


def test_render_and_promote_keep_versions_and_documentation_aligned(tmp_path: Path) -> None:
    versions_path = tmp_path / "versions.json"
    document_path = tmp_path / "compatibility.md"
    fixture_path = tmp_path / "keycloak.yaml"
    versions_path.write_text(
        json.dumps({"default": "26.6.2", "previousMinor": "26.5.3"}) + "\n"
    )
    document_path.write_text("# Compatibility\n\n## Tested Versions\n\nReleased rows.\n")
    fixture_path.write_text(
        "containers:\n  - name: keycloak\n"
        "    image: quay.io/keycloak/keycloak:26.6.2\n"
    )

    assert render_documentation(
        versions_path=versions_path,
        document_path=document_path,
        check=True,
    ) is False
    render_documentation(versions_path=versions_path, document_path=document_path)
    assert render_documentation(
        versions_path=versions_path,
        document_path=document_path,
        check=True,
    ) is True

    promote(
        candidate="26.7.4",
        previous_minor="26.6.2",
        versions_path=versions_path,
        document_path=document_path,
        fixture_path=fixture_path,
    )

    promoted = load_versions(versions_path)
    assert str(promoted.default) == "26.7.4"
    assert str(promoted.previous_minor) == "26.6.2"
    assert "| `develop` | `26.7.4` |" in document_path.read_text()
    assert "Released rows." in document_path.read_text()
    assert "quay.io/keycloak/keycloak:26.7.4" in fixture_path.read_text()


def test_pr_body_supersedes_the_previous_current_candidate() -> None:
    first = build_pr_body(
        candidate="26.7.3",
        previous_minor="26.6.2",
        repository_default="26.6.2",
        result="Passed, current candidate",
        evidence="[run 1](https://example.test/1)",
    )
    updated = build_pr_body(
        candidate="26.7.4",
        previous_minor="26.6.2",
        repository_default="26.6.2",
        result="Passed, current candidate",
        evidence="[run 2](https://example.test/2)",
        existing_body=first,
    )

    assert "| `26.7.3` | Passed, superseded |" in updated
    assert "| `26.7.4` | Passed, current candidate |" in updated
    assert "keycloak-compatibility-audit:" in updated


def _versions() -> CompatibilityVersions:
    return CompatibilityVersions(
        default=StableVersion.parse("26.6.2"),
        previous_minor=StableVersion.parse("26.5.3"),
    )


def _release(version: str, *, prerelease: bool = False) -> dict[str, object]:
    return {
        "tag_name": version,
        "draft": False,
        "prerelease": prerelease,
    }
