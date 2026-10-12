# syntax=docker/dockerfile:1
# Build:  docker buildx build --platform linux/amd64 -t ghcr.io/<owner>/cpr-jengasec-2026:v1 .

FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
RUN groupadd --system app && useradd --system --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /install /usr/local
WORKDIR /srv
COPY --chown=root:root alembic.ini ./
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root app ./app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    WEB_CONCURRENCY=2

USER app
EXPOSE 8080
CMD ["python", "-m", "app.run"]
