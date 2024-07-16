#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

######################################################################
# Node stage to deal with static asset construction
######################################################################
ARG PY_VER=3.10-slim-bookworm

# if BUILDPLATFORM is null, set it to 'amd64' (or leave as is otherwise).
ARG BUILDPLATFORM=${BUILDPLATFORM:-amd64}
FROM --platform=${BUILDPLATFORM} node:18-bullseye-slim AS superset-node

ARG NPM_BUILD_CMD="build"

# Somehow we need python3 + build-essential on this side of the house to install node-gyp
RUN apt-get update -qq \
    && apt-get install \
        -yqq --no-install-recommends \
        build-essential \
        python3 \
        make \
        gcc \
        g++

ENV BUILD_CMD=${NPM_BUILD_CMD} \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
# NPM ci first, as to NOT invalidate previous steps except for when package.json changes

RUN --mount=type=bind,target=/frontend-mem-nag.sh,src=./docker/frontend-mem-nag.sh \
    /frontend-mem-nag.sh

WORKDIR /app/superset-frontend
RUN --mount=type=bind,target=./package.json,src=./superset-frontend/package.json \
    --mount=type=bind,target=./package-lock.json,src=./superset-frontend/package-lock.json \
    npm ci

# Runs the webpack build process
COPY superset-frontend /app/superset-frontend
RUN npm run ${BUILD_CMD}

# This copies the .po files needed for translation
RUN mkdir -p /app/superset/translations
COPY superset/translations /app/superset/translations
# Compiles .json files from the .po files, then deletes the .po files
RUN npm run build-translation
RUN rm /app/superset/translations/*/LC_MESSAGES/*.po
RUN rm /app/superset/translations/messages.pot

######################################################################
# Final lean image...
######################################################################
FROM python:${PY_VER} AS lean

WORKDIR /app
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    SUPERSET_ENV=production \
    FLASK_APP="superset.app:create_app()" \
    PYTHONPATH="/app/pythonpath:/plaid:/etc/superset" \
    SUPERSET_HOME="/app/superset_home" \
    SUPERSET_PORT=8088

RUN mkdir -p ${PYTHONPATH} superset/static requirements superset-frontend apache_superset.egg-info requirements \
    && useradd --user-group -d ${SUPERSET_HOME} -m --no-log-init --shell /bin/bash superset \
    && apt-get update -qq && apt-get install -yqq --no-install-recommends \
        build-essential \
        curl \
        default-libmysqlclient-dev \
        git \
        libsasl2-dev \
        libsasl2-modules-gssapi-mit \
        libpq-dev \
        libecpg-dev \
        libldap2-dev \
        pkg-config \
        python3-dev \
    && touch superset/static/version_info.json \
    && chown -R superset:superset ./* \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=bind,target=./plaid/requirements.txt,src=./plaid/requirements.txt \
    pip install -r plaid/requirements.txt

COPY --chown=superset:superset pyproject.toml setup.py MANIFEST.in README.md ./
# setup.py uses the version information in package.json
COPY --chown=superset:superset superset-frontend/package.json superset-frontend/
COPY --chown=superset:superset requirements/base.txt requirements/
RUN --mount=type=cache,target=/root/.cache/pip \
    apt-get update -qq && apt-get install -yqq --no-install-recommends \
      build-essential \
    && pip install --upgrade setuptools pip \
    && pip install -r requirements/base.txt \
    && apt-get autoremove -yqq --purge build-essential \
    && rm -rf /var/lib/apt/lists/*

    # apt-get update -qq && apt-get install -yqq --no-install-recommends \
    #   build-essential \
    # && pip install -r requirements/development.txt \
    # && apt-get autoremove -yqq --purge build-essential \
    # && rm -rf /var/lib/apt/lists/*

USER superset
######################################################################
# CI image...
######################################################################
FROM lean AS ci

# COPY --chown=superset --chmod=755 ./docker/*.sh /app/docker/
COPY --chown=superset ./docker/*.sh /app/docker/
RUN chmod a+x /app/docker/*.sh

CMD ["/app/docker/docker-ci.sh"]
