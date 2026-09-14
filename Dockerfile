# Eagle Eyes, as a container.
#
# Two stages so the image carries the application and its dependencies and not
# a compiler toolchain: a smaller image is a smaller thing to keep patched.

FROM python:3.12-slim AS build

WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1

# Dependencies first, so editing application code does not reinstall them.
COPY pyproject.toml README.md ./
COPY eagle_eyes/__init__.py eagle_eyes/
RUN pip install --prefix=/install ".[web,postgres]"


FROM python:3.12-slim

# Not root. The application never needs to write outside its data directory,
# and a container that runs as root turns any file-write bug into a
# root-owned file on a mounted volume.
RUN useradd --create-home --uid 10001 eagle

COPY --from=build /install /usr/local

WORKDIR /app
COPY --chown=eagle:eagle eagle_eyes/ ./eagle_eyes/
COPY --chown=eagle:eagle tools/ ./tools/
COPY --chown=eagle:eagle docs/ ./docs/
COPY --chown=eagle:eagle README.md pyproject.toml ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    EAGLE_EYES_IN_CONTAINER=1 \
    EAGLE_EYES_DATA_DIR=/data

# Created and owned here so it works with no volume attached. With one
# attached the platform mounts over it -- and runtime.ephemeral_storage_warning
# says loudly which of those is happening, because writing to the image layer
# works perfectly right up until the next deploy erases it.
RUN mkdir -p /data && chown eagle:eagle /data
VOLUME ["/data"]

USER eagle
EXPOSE 8000

# PORT is set by most platforms; 8000 when it is not. One worker on purpose:
# the SQLite path is single-writer, and the job queue is in-process, so a
# second worker would have its own queue and its own idea of what is running.
# Concurrency comes from threads within the worker, and from PostgreSQL when
# DATABASE_URL is set.
CMD ["sh", "-c", "exec uvicorn --factory eagle_eyes.web.app:create_app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --timeout-keep-alive 65"]
