# Contributing

This project uses a small GitFlow-style process.

## Branches

- `develop` is the integration branch for normal work.
- `main` is the stable release branch.
- Use short-lived branches named `feature/<short-name>`, `hotfix/<short-name>`, or `chore/<short-name>`.
- Open pull requests into `develop` by default.
- Use `hotfix/*` for urgent production fixes. Merge the fix to `main`, tag it, then bring the same change back to `develop`.

## Commits

Keep commits small and focused. Prefer conventional commit-style subjects:

```text
feat(scope): add new behavior
fix(scope): correct broken behavior
test(scope): cover behavior
docs(scope): update documentation
ci(scope): update automation
chore(scope): maintain tooling
```

Install development and documentation dependencies, then run checks before opening
a pull request:

```bash
.venv/bin/python -m pip install -e ".[dev,docs]"
.venv/bin/ruff check .
.venv/bin/pytest
mkdocs build --strict
helm lint charts/keycloak-config-operator
helm template keycloak-config-operator charts/keycloak-config-operator --include-crds
```

Run kind e2e tests when changing reconciliation logic, CRDs, RBAC, install manifests,
Docker image behavior, or Helm chart installation:

```bash
.venv/bin/python tests/kind/e2e.py prepare
.venv/bin/python tests/kind/e2e.py test
.venv/bin/python tests/kind/e2e.py cleanup
```

When changing CRD fields or reconciliation behavior, update
`docs/configuration-support.md` in the same commit. When changing the tested
Keycloak version or release support policy, update `docs/compatibility.md`.

## Releases

Product iterations are Git tags created from `main`.

1. Merge `develop` to `main`.
2. Wait for the CI workflow on `main` to pass, including the `kind e2e tests` job.
3. Keep `pyproject.toml`, `charts/keycloak-config-operator/Chart.yaml`, and the operator image references aligned with the release version.
4. Create and push a semver tag from the green `main` commit:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The tag workflow repeats linting, unit tests, Helm checks, and the kind e2e suite
before publishing the container image, Helm chart, and GitHub release. Helm charts
are pushed to `oci://ghcr.io/clouddicted/charts`. Versioned documentation is
published to the `gh-pages` branch with `mike`: `develop` is available as the
development documentation, and each release tag is published as its own docs
version with the `latest` alias. Configure GitHub Pages to serve the `gh-pages`
branch from `/`.

If the tag workflow fails, fix the issue on a branch, merge through `develop` and
`main`, wait for `main` CI to pass again, then create a new tag.

After the first successful release, confirm the GitHub Container Registry packages
for the operator image and Helm chart are public.

Protect `develop` and `main` in GitHub so pull requests cannot merge until the CI
workflow passes. At minimum, require the `Python lint and tests`, `Helm lint and
package`, `Docs build`, `Container image build`, and `kind e2e tests` jobs.

## Local Files

Never commit `internal/` or `.codex`. Do not add them to `.gitignore`; keep them out of
commits by reviewing `git status` and staging only intended files.
