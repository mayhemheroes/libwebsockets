# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org C/C++ base image
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer + cmake/ninja +
# libssl-dev + the identities + the build-contract ENV; this only adds the per-commit libwebsockets
# build.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t libwebsockets-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Declare it WITHOUT a default so an unset arg lets the base ENV flow through; --build-arg overrides.
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# libwebsockets builds with CMake/Ninja against OpenSSL. The base image already ships clang, cmake,
# ninja, gzip and libssl-dev, so no extra apt packages are needed. (Guarded install kept as a
# belt-and-braces in case a future base drops one of them.)
USER root
RUN if ! command -v cmake >/dev/null 2>&1 || ! command -v ninja >/dev/null 2>&1 \
       || [ ! -f /usr/include/openssl/ssl.h ]; then \
      [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true; \
      apt-get update && apt-get install -yq --no-install-recommends cmake ninja-build libssl-dev gzip \
      && rm -rf /var/lib/apt/lists/*; \
    fi
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history)
# is copied to /mayhem; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run libwebsockets' self-contained gunzip golden oracle at build time (a failing suite fails the
# image build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
