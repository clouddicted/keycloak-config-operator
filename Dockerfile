FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir .
RUN useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin keycloak-operator

USER 10001

ENTRYPOINT ["kopf", "run", "-m", "clouddicted_keycloak_config_operator.main", "--all-namespaces"]
