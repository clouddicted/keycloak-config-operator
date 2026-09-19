#!/usr/bin/env python3
"""Manage tested Keycloak versions and generated compatibility documentation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERSIONS_PATH = REPO_ROOT / "tests" / "kind" / "keycloak-versions.json"
DEFAULT_DOC_PATH = REPO_ROOT / "docs" / "compatibility.md"
DEFAULT_FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "keycloak.yaml"
GENERATED_START = "<!-- BEGIN GENERATED DEVELOPMENT COMPATIBILITY -->"
GENERATED_END = "<!-- END GENERATED DEVELOPMENT COMPATIBILITY -->"
AUDIT_DATA_PATTERN = re.compile(
    r"<!-- keycloak-compatibility-audit:(?P<data>\[.*?\]) -->",
    re.DOTALL,
)
VERSION_PATTERN = re.compile(
    r"^(?:v)?(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)$"
)


@dataclass(frozen=True, order=True)
class StableVersion:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: str) -> StableVersion:
        match = VERSION_PATTERN.fullmatch(value.strip())
        if match is None:
            raise ValueError(f"invalid stable Keycloak version: {value!r}")
        return cls(*(int(match.group(part)) for part in ("major", "minor", "patch")))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class CompatibilityVersions:
    default: StableVersion
    previous_minor: StableVersion


def load_versions(path: Path = DEFAULT_VERSIONS_PATH) -> CompatibilityVersions:
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("Keycloak versions file must contain a JSON object")

    default = StableVersion.parse(_required_string(raw, "default"))
    previous_minor = StableVersion.parse(_required_string(raw, "previousMinor"))
    if previous_minor >= default:
        raise ValueError("previousMinor must be older than default")
    if (previous_minor.major, previous_minor.minor) == (default.major, default.minor):
        raise ValueError("previousMinor must use an older major or minor line")
    return CompatibilityVersions(default=default, previous_minor=previous_minor)


def save_versions(versions: CompatibilityVersions, path: Path = DEFAULT_VERSIONS_PATH) -> None:
    payload = {
        "default": str(versions.default),
        "previousMinor": str(versions.previous_minor),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


def candidate_plan(
    *,
    candidate: str,
    repository_versions: CompatibilityVersions,
    rolling_default: str | None,
    releases: Sequence[dict[str, Any]],
    manual: bool,
    rolling_previous_minor: str | None = None,
) -> dict[str, Any]:
    parsed_candidate = StableVersion.parse(candidate)
    rolling = StableVersion.parse(rolling_default) if rolling_default else None
    rolling_previous = (
        StableVersion.parse(rolling_previous_minor) if rolling_previous_minor else None
    )
    if rolling_previous is not None and rolling is None:
        raise ValueError("rolling previous minor requires a rolling default")
    if rolling_previous is not None and (
        rolling_previous >= rolling
        or (rolling_previous.major, rolling_previous.minor)
        == (rolling.major, rolling.minor)
    ):
        raise ValueError("rolling previous minor must use an older release line")
    active_previous = (
        rolling_previous
        if rolling is not None
        and rolling >= repository_versions.default
        and rolling_previous is not None
        else repository_versions.previous_minor
    )
    baseline = max(
        version for version in (repository_versions.default, rolling) if version is not None
    )

    if manual:
        return {
            "candidate": str(parsed_candidate),
            "shouldTest": True,
            "testVersions": [str(parsed_candidate)],
            "proposedPreviousMinor": str(active_previous),
            "promotable": False,
            "reason": "manual exact-version test",
        }

    if parsed_candidate <= baseline:
        return {
            "candidate": str(parsed_candidate),
            "shouldTest": False,
            "testVersions": [],
            "proposedPreviousMinor": str(active_previous),
            "promotable": False,
            "reason": f"candidate is not newer than {baseline}",
        }

    test_versions = [parsed_candidate]
    proposed_previous = active_previous
    if (parsed_candidate.major, parsed_candidate.minor) > (baseline.major, baseline.minor):
        proposed_previous = _latest_previous_line(
            parsed_candidate,
            releases,
            fallback=baseline,
        )
        if proposed_previous not in test_versions:
            test_versions.append(proposed_previous)

    return {
        "candidate": str(parsed_candidate),
        "shouldTest": True,
        "testVersions": [str(version) for version in test_versions],
        "proposedPreviousMinor": str(proposed_previous),
        "promotable": True,
        "reason": f"new stable release after {baseline}",
    }


def render_development_compatibility(versions: CompatibilityVersions) -> str:
    return "\n".join(
        (
            GENERATED_START,
            "| Branch | Keycloak version | Status | Test scope | Notes |",
            "| --- | --- | --- | --- | --- |",
            (
                f"| `develop` | `{versions.default}` | Default tested | "
                "PR, branch, tag, manual, and latest-version kind e2e | "
                "Default version from `tests/kind/keycloak-versions.json`. |"
            ),
            (
                f"| `develop` | `{versions.previous_minor}` | Compatibility tested | "
                "Tag, manual, and new-minor latest-version kind e2e | "
                "Previous-minor smoke coverage. |"
            ),
            GENERATED_END,
        )
    )


def updated_documentation(text: str, versions: CompatibilityVersions) -> str:
    generated = render_development_compatibility(versions)
    if GENERATED_START in text or GENERATED_END in text:
        if text.count(GENERATED_START) != 1 or text.count(GENERATED_END) != 1:
            raise ValueError("compatibility document has invalid generated-section markers")
        start = text.index(GENERATED_START)
        end = text.index(GENERATED_END, start) + len(GENERATED_END)
        return text[:start] + generated + text[end:]

    heading = "## Tested Versions"
    if heading not in text:
        raise ValueError(f"compatibility document is missing {heading!r}")
    return text.replace(heading, f"## Development Compatibility\n\n{generated}\n\n{heading}", 1)


def render_documentation(
    *,
    versions_path: Path = DEFAULT_VERSIONS_PATH,
    document_path: Path = DEFAULT_DOC_PATH,
    check: bool = False,
) -> bool:
    versions = load_versions(versions_path)
    original = document_path.read_text()
    rendered = updated_documentation(original, versions)
    if check:
        return original == rendered
    document_path.write_text(rendered)
    return True


def promote(
    *,
    candidate: str,
    previous_minor: str,
    versions_path: Path = DEFAULT_VERSIONS_PATH,
    document_path: Path = DEFAULT_DOC_PATH,
    fixture_path: Path = DEFAULT_FIXTURE_PATH,
) -> CompatibilityVersions:
    current = load_versions(versions_path)
    promoted = CompatibilityVersions(
        default=StableVersion.parse(candidate),
        previous_minor=StableVersion.parse(previous_minor),
    )
    if promoted.default <= current.default:
        raise ValueError(
            f"promoted version {promoted.default} must be newer than {current.default}"
        )
    if promoted.previous_minor >= promoted.default:
        raise ValueError("previous minor must be older than the promoted default")
    if (promoted.previous_minor.major, promoted.previous_minor.minor) == (
        promoted.default.major,
        promoted.default.minor,
    ):
        raise ValueError("previous minor must use an older major or minor line")

    original_fixture = fixture_path.read_text()
    updated_fixture = _updated_fixture_image(original_fixture, fixture_path, promoted.default)
    save_versions(promoted, versions_path)
    render_documentation(versions_path=versions_path, document_path=document_path)
    fixture_path.write_text(updated_fixture)
    return promoted


def build_pr_body(
    *,
    candidate: str,
    previous_minor: str,
    repository_default: str,
    result: str,
    evidence: str,
    existing_body: str = "",
    observed_version: str | None = None,
) -> str:
    parsed_candidate = str(StableVersion.parse(candidate))
    parsed_observed = str(StableVersion.parse(observed_version or candidate))
    records = _audit_records(existing_body)
    if result == "Passed, current candidate":
        for record in records:
            if record.get("result") == "Passed, current candidate":
                record["result"] = "Passed, superseded"

    records = [record for record in records if record.get("version") != parsed_observed]
    records.append(
        {
            "version": parsed_observed,
            "result": result,
            "evidence": evidence,
        }
    )
    records.sort(key=lambda record: StableVersion.parse(str(record["version"])))

    rows = ["| Version | Result | Evidence |", "| --- | --- | --- |"]
    rows.extend(
        f"| `{record['version']}` | {record['result']} | {record['evidence']} |"
        for record in records
    )
    audit_json = json.dumps(records, separators=(",", ":"))
    return "\n".join(
        (
            f"Keycloak {parsed_candidate} passed the full kind e2e suite against `develop`.",
            "",
            "Proposed compatibility transition:",
            "",
            f"- Default tested version: `{repository_default}` → `{parsed_candidate}`",
            f"- Previous-minor version: `{previous_minor}`",
            "",
            "The result remains a compatibility candidate until this pull request is reviewed.",
            "",
            "### Compatibility audit",
            "",
            *rows,
            "",
            f"<!-- keycloak-compatibility-audit:{audit_json} -->",
            "",
            "Generated by the latest stable Keycloak compatibility workflow.",
        )
    )


def _latest_previous_line(
    candidate: StableVersion,
    releases: Sequence[dict[str, Any]],
    *,
    fallback: StableVersion,
) -> StableVersion:
    stable = _stable_release_versions(releases)
    if candidate.minor > 0:
        target_line = (candidate.major, candidate.minor - 1)
        matches = [version for version in stable if (version.major, version.minor) == target_line]
    else:
        older_major = [version for version in stable if version.major < candidate.major]
        if not older_major:
            matches = []
        else:
            previous_major = max(version.major for version in older_major)
            matches = [version for version in older_major if version.major == previous_major]

    if matches:
        return max(matches)
    if fallback < candidate:
        return fallback
    raise ValueError(f"no previous stable release line was found for {candidate}")


def _stable_release_versions(releases: Sequence[dict[str, Any]]) -> list[StableVersion]:
    versions: list[StableVersion] = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        tag_name = release.get("tag_name")
        if not isinstance(tag_name, str):
            continue
        try:
            versions.append(StableVersion.parse(tag_name))
        except ValueError:
            continue
    return versions


def _audit_records(body: str) -> list[dict[str, str]]:
    match = AUDIT_DATA_PATTERN.search(body)
    if match is None:
        return []
    raw = json.loads(match.group("data"))
    if not isinstance(raw, list):
        return []
    return [
        {
            "version": str(record["version"]),
            "result": str(record["result"]),
            "evidence": str(record["evidence"]),
        }
        for record in raw
        if isinstance(record, dict)
        and {"version", "result", "evidence"} <= record.keys()
    ]


def _required_string(raw: dict[str, Any], name: str) -> str:
    value = raw.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _updated_fixture_image(original: str, path: Path, version: StableVersion) -> str:
    updated, count = re.subn(
        r"(?m)^(\s*image:\s*quay\.io/keycloak/keycloak:)[^\s]+$",
        rf"\g<1>{version}",
        original,
    )
    if count != 1:
        raise ValueError(f"expected one Keycloak fixture image in {path}, found {count}")
    return updated


def _read_releases(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise ValueError("releases file must contain a JSON array")
    return [release for release in raw if isinstance(release, dict)]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--versions-file", type=Path, default=DEFAULT_VERSIONS_PATH)
    parser.add_argument("--document", type=Path, default=DEFAULT_DOC_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)

    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("field", choices=("default", "previousMinor"))

    subparsers.add_parser("github-output")

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("version")

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--candidate", required=True)
    plan_parser.add_argument("--rolling-default")
    plan_parser.add_argument("--rolling-previous-minor")
    plan_parser.add_argument("--releases-file", type=Path)
    plan_parser.add_argument("--manual", action="store_true")

    render_parser = subparsers.add_parser("render-docs")
    render_parser.add_argument("--check", action="store_true")

    promote_parser = subparsers.add_parser("promote")
    promote_parser.add_argument("--candidate", required=True)
    promote_parser.add_argument("--previous-minor", required=True)

    body_parser = subparsers.add_parser("pr-body")
    body_parser.add_argument("--candidate", required=True)
    body_parser.add_argument("--previous-minor", required=True)
    body_parser.add_argument("--repository-default", required=True)
    body_parser.add_argument("--result", default="Passed, current candidate")
    body_parser.add_argument("--evidence", required=True)
    body_parser.add_argument("--existing-body", type=Path)
    body_parser.add_argument("--observed-version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        versions = load_versions(args.versions_file)
        if args.command == "get":
            value = versions.default if args.field == "default" else versions.previous_minor
            print(value)
        elif args.command == "github-output":
            print(f"default={versions.default}")
            print(f"compatibility={json.dumps([str(versions.previous_minor)])}")
        elif args.command == "validate":
            print(StableVersion.parse(args.version))
        elif args.command == "plan":
            plan = candidate_plan(
                candidate=args.candidate,
                repository_versions=versions,
                rolling_default=args.rolling_default,
                releases=_read_releases(args.releases_file),
                manual=args.manual,
                rolling_previous_minor=args.rolling_previous_minor,
            )
            print(json.dumps(plan, indent=2))
        elif args.command == "render-docs":
            current = render_documentation(
                versions_path=args.versions_file,
                document_path=args.document,
                check=args.check,
            )
            if not current:
                print("compatibility documentation is out of date", file=sys.stderr)
                return 1
        elif args.command == "promote":
            promoted = promote(
                candidate=args.candidate,
                previous_minor=args.previous_minor,
                versions_path=args.versions_file,
                document_path=args.document,
            )
            print(
                json.dumps(
                    {
                        "default": str(promoted.default),
                        "previousMinor": str(promoted.previous_minor),
                    }
                )
            )
        elif args.command == "pr-body":
            existing = args.existing_body.read_text() if args.existing_body else ""
            print(
                build_pr_body(
                    candidate=args.candidate,
                    previous_minor=args.previous_minor,
                    repository_default=args.repository_default,
                    result=args.result,
                    evidence=args.evidence,
                    existing_body=existing,
                    observed_version=args.observed_version,
                )
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
