# Eagle Eyes, as a container.
#
# Two stages so the image carries the application and its dependencies and not
# a compiler toolchain: a smaller image is a smaller thing to keep patched.

FROM python:3.12-slim AS build

WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1

# The whole package, then install. An earlier version copied only
# eagle_eyes/__init__.py here to keep the dependency layer cached across builds
# -- and pyproject declares packages = ["eagle_eyes", "eagle_eyes.web"], so
# setuptools went looking for a directory the stub did not include and failed
# with `package directory 'eagle_eyes/web' does not exist` before downloading
# anything. The cache only pays off on a builder that keeps layers between
# builds, which a fresh cloud builder does not, so it bought very little and
# cost a build.
COPY pyproject.toml README.md ./
COPY eagle_eyes/ ./eagle_eyes/
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

# The mount point, created and owned here so the app works with no volume at
# all. Attaching one is the platform's job, not this file's: Railway REJECTS a
# Dockerfile containing VOLUME outright ("docker VOLUME is not supported, use
# Railway Volumes") -- at validation, before a single layer runs, so no check
# that reads the built image would ever see it. There is nothing to declare
# here anyway; VOLUME states an intent, mkdir is what makes the path usable.
#
# With PostgreSQL attached no volume is needed at all, because DATABASE_URL
# sends everything there and the SQLite path is never touched.
# runtime.ephemeral_storage_warning() reports which of those actually happened,
# because writing to the image layer works perfectly right up until the next
# deploy erases it.
RUN mkdir -p /data && chown eagle:eagle /data

USER eagle
EXPOSE 8000

# PORT is set by most platforms; 8000 when it is not. One worker on purpose:
# the SQLite path is single-writer, and the job queue is in-process, so a
# second worker would have its own queue and its own idea of what is running.
# Concurrency comes from threads within the worker, and from PostgreSQL when
# DATABASE_URL is set.
CMD ["sh", "-c", "exec uvicorn --factory eagle_eyes.web.app:create_app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --timeout-keep-alive 65"]
