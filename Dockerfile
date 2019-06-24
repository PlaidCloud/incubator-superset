FROM node:10-alpine AS build-client

COPY superset/assets /superset/assets

RUN cd /superset/assets/ \
 && npm ci \
 && npm run build

FROM python:3.6 AS build-distribution
RUN useradd --user-group --create-home --no-log-init --shell /bin/bash superset

# Configure environment
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update -y

# Install dependencies to fix `curl https support error` and `elaying package configuration warning`
RUN apt-get install -y apt-transport-https apt-utils

# Install superset dependencies
# https://superset.incubator.apache.org/installation.html#os-dependencies
RUN apt-get install -y build-essential libssl-dev \
    libffi-dev python3-dev libsasl2-dev libldap2-dev libxi-dev

# Install nodejs for custom build
# https://superset.incubator.apache.org/installation.html#making-your-own-build
# https://nodejs.org/en/download/package-manager/
RUN curl -sL https://deb.nodesource.com/setup_10.x | bash - \
    && apt-get install -y nodejs

WORKDIR /home/superset

COPY requirements.txt .
COPY requirements-dev.txt .

RUN pip install --upgrade setuptools pip \
    && pip install -r requirements.txt -r requirements-dev.txt \
    && rm -rf /root/.cache/pip

ENV PATH=/home/superset/superset/bin:$PATH \
    PYTHONPATH=/home/superset/superset/:$PYTHONPATH

COPY --chown=superset:superset setup.py setup.cfg README.md MANIFEST.in ./
COPY --chown=superset:superset superset superset
COPY --from=build-client --chown=superset:superset /superset/assets /home/superset/superset/assets/

USER superset
 
RUN cd /home/superset \
 && mkdir -p /home/superset/superset/static \
 && ln -s ../assets /home/superset/superset/static/assets \
 && python setup.py sdist

FROM python:3.6

# Configure environment
ENV GUNICORN_BIND=0.0.0.0:8088 \
GUNICORN_LIMIT_REQUEST_FIELD_SIZE=0 \
GUNICORN_LIMIT_REQUEST_LINE=0 \
GUNICORN_TIMEOUT=60 \
GUNICORN_WORKERS=2 \
LANG=C.UTF-8 \
LC_ALL=C.UTF-8 \
PYTHONPATH=/etc/superset:/home/superset:/plaidtools:$PYTHONPATH \
SUPERSET_REPO=apache/incubator-superset \
SUPERSET_HOME=/var/lib/superset
ENV GUNICORN_CMD_ARGS="--workers ${GUNICORN_WORKERS} --timeout ${GUNICORN_TIMEOUT} --bind ${GUNICORN_BIND} --limit-request-line ${GUNICORN_LIMIT_REQUEST_LINE} --limit-request-field_size ${GUNICORN_LIMIT_REQUEST_FIELD_SIZE}"

COPY requirements.txt .

# Create superset user & install dependencies
RUN useradd -U -m superset && \
mkdir /etc/superset && \
mkdir ${SUPERSET_HOME} && \
chown -R superset:superset /etc/superset && \
chown -R superset:superset ${SUPERSET_HOME} && \
apt-get update && \
apt-get install -y \
build-essential \
curl \
default-libmysqlclient-dev \
freetds-dev \
freetds-bin \
libffi-dev \
libldap2-dev \
libpq-dev \
libsasl2-dev \
libssl-dev && \
apt-get clean && \
rm -r /var/lib/apt/lists/* && \
pip install -r requirements.txt && \
pip install --no-cache-dir \
flask_oauthlib==0.9.5 \
flask-cors==3.0.3 \
flask-mail==0.9.1 \
flask-oauth==0.12 \
gevent==1.2.2 \
impyla==0.14.0 \
infi.clickhouse-orm==1.0.2 \
mysqlclient==1.3.7 \
psycopg2==2.6.1 \
pyathena==1.2.5 \
pyhive==0.5.1 \
pyldap==2.4.28 \
pymssql==2.1.3 \
redis==2.10.5 \
sqlalchemy-clickhouse==0.1.5.post0 \
sqlalchemy-redshift==0.7.1 \
Werkzeug==0.14.1 && \
rm requirements.txt

# Configure Filesystem
COPY --from=build-distribution /home/superset/dist/apache-superset-0.999.0.dev0.tar.gz /home/superset
WORKDIR /home/superset

# COPY superset_config.py /etc/superset/
COPY plaidtools /plaidtools/

RUN cd /plaidtools && python setup.py install
RUN pip install apache-superset-0.999.0.dev0.tar.gz


# Deploy application
EXPOSE 8088
HEALTHCHECK CMD ["curl", "-f", "http://localhost:8088/health"]
CMD ["gunicorn", "superset:app"]
USER superset