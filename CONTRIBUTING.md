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

Run checks before opening a pull request:

```bash
.venv/bin/ruff check .
.venv/bin/pytest
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

## Releases

Product iterations are Git tags created from `main`.

1. Merge `develop` to `main`.
2. Keep `pyproject.toml`, `charts/keycloak-config-operator/Chart.yaml`, and the operator image references aligned with the release version.
3. Create and push a semver tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The tag workflow runs linting, unit tests, Helm checks, the kind e2e suite, publishes
the operator image to GitHub Container Registry, packages the Helm chart, and attaches
the chart package to the GitHub Release.

## Local Files

Never commit `internal/` or `.codex`. Do not add them to `.gitignore`; keep them out of
commits by reviewing `git status` and staging only intended files.
