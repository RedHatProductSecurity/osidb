FROM registry.access.redhat.com/ubi9/ubi:9.6

LABEL summary="OSIDB" \
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

EXPOSE 8080

WORKDIR /opt/app-root/src/

# Download internal root CA cert and the IPA CA cert
ARG RH_CERT_URL=""
COPY ./scripts /opt/app-root/src/scripts
RUN ./scripts/install-certs.sh $RH_CERT_URL

# Download and install AWS RDS cert chain in order to connect to the DB via SSL
RUN curl "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem" \
    -o /etc/pki/ca-trust/source/anchors/aws-rds.pem && \
    update-ca-trust

# install dependencies and security updates
RUN dnf --nodocs --setopt install_weak_deps=false -y install \
        cargo \
        gcc \
        git \
        krb5-devel \
        krb5-workstation \
        libffi-devel \
        logrotate \
        make \
        openldap-devel \
        openssl-devel \
        postgresql-devel \
        procps-ng \
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
RUN pip3.12 install uv==0.9.7

# Sync project dependencies into a virtual environment 
RUN uv sync --frozen --no-dev && \
    rm -f /opt/app-root/src/pyproject.toml && \ 
    rm -f /opt/app-root/src/uv.lock

# Optional: GitLab HTTPS clone URL for the newtopia-cli monorepo; when set, install in-repo
# deptopia_client first, then newtopia_cli (PyPI has no deptopia_client).
# Optional: branch, tag, or commit for both installs (omit for the remote default branch).
ARG NEWCLI_REPO_URL=""
ARG NEWCLI_EXPERIMENTAL_BRANCH=""
RUN if [ -n "$NEWCLI_REPO_URL" ]; then \
        if [ -n "$NEWCLI_EXPERIMENTAL_BRANCH" ]; then \
            uv pip install --no-cache --python "$UV_PROJECT_ENVIRONMENT/bin/python" \
                "git+${NEWCLI_REPO_URL}@${NEWCLI_EXPERIMENTAL_BRANCH}#subdirectory=python/deptopia-client" && \
            uv pip install --no-cache --python "$UV_PROJECT_ENVIRONMENT/bin/python" \
                "git+${NEWCLI_REPO_URL}@${NEWCLI_EXPERIMENTAL_BRANCH}#egg=newtopia_cli&subdirectory=python/newtopia_cli"; \
        else \
            uv pip install --no-cache --python "$UV_PROJECT_ENVIRONMENT/bin/python" \
                "git+${NEWCLI_REPO_URL}#subdirectory=python/deptopia-client" && \
            uv pip install --no-cache --python "$UV_PROJECT_ENVIRONMENT/bin/python" \
                "git+${NEWCLI_REPO_URL}#egg=newtopia_cli&subdirectory=python/newtopia_cli"; \
        fi; \
    fi

# Copy the project into the image
COPY . /opt/app-root/src

ENV VIRTUAL_ENV=$UV_PROJECT_ENVIRONMENT
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root
