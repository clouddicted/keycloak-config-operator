"""Exercise Kopf's real change detection without a Kubernetes cluster."""

import asyncio
import copy
import logging
from collections.abc import Coroutine
from typing import Any

import kopf
import pytest
from kopf._cogs.structs import references
from kopf._core.actions import lifecycles
from kopf._core.engines import daemons, indexing
from kopf._core.reactor import inventory, processing

from clouddicted_keycloak_config_operator import main
from clouddicted_keycloak_config_operator.constants import API_GROUP, API_VERSION
from clouddicted_keycloak_config_operator.handlers import (
    dependencies,
    keycloak_identity_provider,
    keycloak_target,
)


def _settings() -> kopf.OperatorSettings:
    settings = kopf.OperatorSettings()
    main.configure(settings)
    return settings


def _memory() -> inventory.ResourceMemory:
    return inventory.ResourceMemory(daemons_memory=daemons.DaemonsMemory(idle_reset_time=0))


def _run(coroutine: Coroutine[Any, Any, Any]) -> None:
    async def bounded() -> None:
        await asyncio.wait_for(coroutine, timeout=5)

    asyncio.run(bounded())


def _handled_resource(settings: kopf.OperatorSettings) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "apiVersion": f"{API_GROUP}/{API_VERSION}",
        "kind": "KeycloakIdentityProvider",
        "metadata": {
            "name": "example",
            "namespace": "apps",
            "uid": "example-uid",
            "resourceVersion": "780",
        },
        "spec": {"alias": "example"},
    }
    body = kopf.Body(raw)
    patch = kopf.Patch()
    storage = settings.persistence.diffbase_storage
    storage.store(body=body, patch=patch, essence=storage.build(body=body))
    raw["metadata"].update(copy.deepcopy(patch["metadata"]))
    return raw


def _detect(
    settings: kopf.OperatorSettings,
    raw: dict[str, Any],
    source: dependencies.SourceResource,
    *,
    indexers: indexing.OperatorIndexers | None = None,
) -> Any:
    logger = logging.getLogger("test-dependency-runtime")
    return processing._detect_causes(
        indexers=indexers if indexers is not None else indexing.OperatorIndexers(),
        registry=kopf.get_default_registry(),
        settings=settings,
        resource=references.Resource(
            group=source.group, version=source.version, plural=source.plural,
        ),
        raw_event={"type": "MODIFIED", "object": raw},
        body=kopf.Body(raw),
        patch=kopf.Patch(),
        memory=_memory(),
        local_logger=logger,
        event_logger=logger,
    )


@pytest.mark.parametrize("source", dependencies.CUSTOM_RESOURCES, ids=lambda s: s.plural)
def test_dependency_annotation_selects_normal_reconciler(
    source: dependencies.SourceResource,
) -> None:
    settings = _settings()
    raw = _handled_resource(settings)
    raw["metadata"]["annotations"][dependencies.DEPENDENCY_TRIGGER_ANNOTATION] = (
        "core/secrets/apps/credentials@783"
    )

    cause = _detect(settings, raw, source).changing_cause

    assert cause.reason == "update"
    selected = kopf.get_default_registry()._changing.get_handlers(cause=cause)
    assert any(handler.id.startswith("reconcile_keycloak_") for handler in selected)


def test_dependency_update_runs_once_then_ignores_bookkeeping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    raw = _handled_resource(settings)
    raw["metadata"]["annotations"][dependencies.DEPENDENCY_TRIGGER_ANNOTATION] = (
        "core/secrets/apps/credentials@783"
    )
    source = dependencies.SourceResource(API_GROUP, API_VERSION, "keycloakidentityproviders")
    calls: list[Any] = []

    def reconcile(**kwargs: Any) -> None:
        calls.append(kwargs["spec"])

    monkeypatch.setattr(
        keycloak_identity_provider, "patch_keycloak_identity_provider_status", reconcile,
    )
    cause = _detect(settings, raw, source).changing_cause
    _run(processing.process_changing_cause(
        lifecycle=lifecycles.all_at_once,
        registry=kopf.get_default_registry(),
        settings=settings,
        memory=_memory(),
        cause=cause,
    ))

    assert calls == [raw["spec"]]
    raw["metadata"]["annotations"].update(cause.patch["metadata"]["annotations"])
    raw["metadata"]["resourceVersion"] = "785"
    raw["status"] = {"conditions": []}
    assert _detect(settings, raw, source).changing_cause.reason == "noop"


def test_secret_rotation_only_patches_dependents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    source = dependencies.SECRET_RESOURCE
    raw = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "credentials", "namespace": "apps", "resourceVersion": "783"},
        "data": {"clientSecret": "cm90YXRlZA=="},
    }
    registry = kopf.get_default_registry()
    indexers = indexing.OperatorIndexers()
    indexers.ensure(registry._indexing.get_all_handlers())
    indexers["keycloakidentityproviders_dependencies"].replace(
        ("apps", "example", "example-uid"),
        {("", "secrets", "apps", "credentials"): dependencies.DependentResource(
            namespace="apps", plural="keycloakidentityproviders", name="example",
        )},
    )
    patches: list[dict[str, Any]] = []

    class FakeApi:
        def patch_namespaced_custom_object(self, **kwargs: Any) -> None:
            patches.append(kwargs)

    monkeypatch.setattr(dependencies.kubernetes_client, "CustomObjectsApi", FakeApi)
    causes = _detect(settings, raw, source, indexers=indexers)
    _run(processing.process_watching_cause(
        lifecycle=lifecycles.all_at_once,
        registry=registry,
        settings=settings,
        cause=causes.watching_cause,
    ))

    assert len(patches) == 1
    assert patches[0]["body"]["metadata"]["annotations"] == {
        dependencies.DEPENDENCY_TRIGGER_ANNOTATION: "core/secrets/apps/credentials@783",
    }
    assert causes.watching_cause.patch == {}
    # Registering a changing handler causes Kopf to persist Secret data in a
    # last-handled annotation and creates extra resource versions/watch events.
    assert causes.changing_cause is None


def test_secret_trigger_propagates_through_target_to_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    raw = _handled_resource(settings)
    raw["metadata"]["annotations"][dependencies.DEPENDENCY_TRIGGER_ANNOTATION] = (
        "core/secrets/apps/credentials@783"
    )
    source = dependencies.SourceResource(API_GROUP, API_VERSION, "keycloaktargets")
    registry = kopf.get_default_registry()
    indexers = indexing.OperatorIndexers()
    indexers.ensure(registry._indexing.get_all_handlers())
    indexers["keycloakclients_dependencies"].replace(
        ("apps", "web", "web-uid"),
        {(API_GROUP, source.plural, "apps", "example"): dependencies.DependentResource(
            namespace="apps", plural="keycloakclients", name="web",
        )},
    )
    patches: list[dict[str, Any]] = []

    class FakeApi:
        def patch_namespaced_custom_object(self, **kwargs: Any) -> None:
            patches.append(kwargs)

    monkeypatch.setattr(dependencies.kubernetes_client, "CustomObjectsApi", FakeApi)
    monkeypatch.setattr(keycloak_target, "patch_keycloak_target_status", lambda **_: None)
    cause = _detect(settings, raw, source, indexers=indexers).changing_cause
    _run(processing.process_changing_cause(
        lifecycle=lifecycles.all_at_once, registry=registry,
        settings=settings, memory=_memory(), cause=cause,
    ))

    assert len(patches) == 1
    assert patches[0]["name"] == "web"
    assert patches[0]["body"]["metadata"]["annotations"] == {
        dependencies.DEPENDENCY_TRIGGER_ANNOTATION: f"{API_GROUP}/keycloaktargets/apps/example@780",
    }
