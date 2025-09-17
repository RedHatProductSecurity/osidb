FROM registry.access.redhat.com/ubi10:10.0

LABEL summary="OSIDB testrunner" \
      maintainer="Product Security DevOps <prodsec-dev@redhat.com>"

ARG PYPI_MIRROR="https://pypi.python.org/simple"
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_INDEX_URL=$PYPI_MIRROR \
    UV_DEFAULT_INDEX=$PYPI_MIRROR \
    UV_NO_CACHE=off \
    UV_NATIVE_TLS=true \
    UV_PROJECT_ENVIRONMENT="/opt/app-root/.venv" \
    REQUESTS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"

WORKDIR /opt/app-root/src/

# Download internal root CA cert and the IPA CA cert
ARG RH_CERT_URL=""
COPY ./scripts /opt/app-root/src/scripts
RUN ./scripts/install-certs.sh $RH_CERT_URL

# install dependencies and security updates
RUN dnf --nodocs --setopt install_weak_deps=false -y install \
        cargo \
        gcc \
        git \
        krb5-devel \
        krb5-workstation \
        libffi-devel \
        libpq-devel \
        make \
        openldap-devel \
        openssl-devel \
        python3.12-devel \
        python3.12-pip \
        python3.12-wheel \
        redhat-rpm-config \
        which \
    && dnf --nodocs --setopt install_weak_deps=false -y upgrade --security \
    && dnf clean all

# Before copying the entire source, copy just the dependency files
# This makes podman cache this (lengthy) step as long as the dependency files stays unchanged.
# Without this, any change in src/ would make uv sync
COPY ./pyproject.toml ./uv.lock /opt/app-root/src/

# Install uv
RUN pip3.12 install uv==0.8.3

# Sync development dependencies into a virtual environment 
RUN uv sync --frozen --only-dev && \
    rm -f /opt/app-root/src/pyproject.toml && \ 
    rm -f /opt/app-root/src/uv.lock

# Copy the project into the image
COPY . /opt/app-root/src

ENV VIRTUAL_ENV=$UV_PROJECT_ENVIRONMENT
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
