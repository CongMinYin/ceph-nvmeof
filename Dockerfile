# syntax = docker/dockerfile:1.4

ARG NVMEOF_SPDK_VERSION
ARG NVMEOF_TARGET  # either 'gateway' or 'cli'

#------------------------------------------------------------------------------
# Base image for NVMEOF_TARGET=cli (nvmeof-cli)
FROM registry.access.redhat.com/ubi9/ubi AS base-cli
ENTRYPOINT ["python3", "-m", "control.cli"]
CMD []

#------------------------------------------------------------------------------
# Base image for NVMEOF_TARGET=gateway (nvmeof-gateway)
FROM quay.io/ceph/spdk:${NVMEOF_SPDK_VERSION:-NULL} AS base-gateway
RUN \
    --mount=type=cache,target=/var/cache/dnf \
    --mount=type=cache,target=/var/lib/dnf \
    dnf install -y python3-rados
ENTRYPOINT ["python3", "-m", "control"]
CMD ["-c", "/src/ceph-nvmeof.conf"]

#------------------------------------------------------------------------------
# Intermediate layer for Python set-up
FROM base-$NVMEOF_TARGET AS python-intermediate

RUN \
    --mount=type=cache,target=/var/cache/dnf \
    --mount=type=cache,target=/var/lib/dnf \
    dnf update -y

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    PIP_NO_CACHE_DIR=off \
    PYTHON_MAJOR=3 \
    PYTHON_MINOR=9 \
    PDM_ONLY_BINARY=:all:

ARG APPDIR=/src

ARG NVMEOF_NAME \
    NVMEOF_SUMMARY \
    NVMEOF_DESCRIPTION \
    NVMEOF_URL \
    NVMEOF_VERSION \
    NVMEOF_MAINTAINER \
    NVMEOF_TAGS \
    NVMEOF_WANTS \
    NVMEOF_EXPOSE_SERVICES \
    BUILD_DATE \
    NVMEOF_GIT_REPO \
    NVMEOF_GIT_BRANCH \
    NVMEOF_GIT_COMMIT

# Generic labels
LABEL name="$NVMEOF_NAME" \
      version="$NVMEOF_VERSION" \
      summary="$NVMEOF_SUMMARY" \
      description="$NVMEOF_DESCRIPTION" \
      maintainer="$NVMEOF_MAINTAINER" \
      release="" \
      url="$NVMEOF_URL" \
      build-date="$BUILD_DATE" \
      vcs-ref="$NVMEOF_GIT_COMMIT"

# k8s-specific labels
LABEL io.k8s.display-name="$NVMEOF_SUMMARY" \
      io.k8s.description="$NVMEOF_DESCRIPTION"

# k8s-specific labels
LABEL io.openshift.tags="$NVMEOF_TAGS" \
      io.openshift.wants="$NVMEOF_WANTS" \
      io.openshift.expose-services="$NVMEOF_EXPOSE_SERVICES"

# Ceph-specific labels
LABEL io.ceph.component="$NVMEOF_NAME" \
      io.ceph.summary="$NVMEOF_SUMMARY" \
      io.ceph.description="$NVMEOF_DESCRIPTION" \
      io.ceph.url="$NVMEOF_URL" \
      io.ceph.version="$NVMEOF_VERSION" \
      io.ceph.maintainer="$NVMEOF_MAINTAINER" \
      io.ceph.git.repo="$NVMEOF_GIT_REPO" \
      io.ceph.git.branch="$NVMEOF_GIT_BRANCH" \
      io.ceph.git.commit="$NVMEOF_GIT_COMMIT"

ENV PYTHONPATH=$APPDIR/proto:$APPDIR/__pypackages__/$PYTHON_MAJOR.$PYTHON_MINOR/lib

WORKDIR $APPDIR

#------------------------------------------------------------------------------
FROM python-intermediate AS builder

ENV PDM_SYNC_FLAGS="-v --no-isolation --no-self --no-editable"

# https://pdm.fming.dev/latest/usage/advanced/#use-pdm-in-a-multi-stage-dockerfile
RUN \
    --mount=type=cache,target=/var/cache/dnf \
    --mount=type=cache,target=/var/lib/dnf \
    dnf install -y python3-pip
RUN \
    --mount=type=cache,target=/root/.cache/pip \
    pip install -U pip setuptools

RUN \
    --mount=type=cache,target=/root/.cache/pip \
    pip install pdm
COPY pyproject.toml pdm.lock pdm.toml ./
RUN \
    --mount=type=cache,target=/root/.cache/pdm \
    pdm sync $PDM_SYNC_FLAGS

COPY . .
RUN pdm run protoc

#------------------------------------------------------------------------------
FROM python-intermediate
COPY --from=builder $APPDIR .