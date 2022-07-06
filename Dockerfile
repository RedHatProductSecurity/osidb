FROM registry.redhat.io/ubi8/ubi:8.6

LABEL summary="OSIDB" \
      maintainer="Product Security DevOps <prodsec-dev@redhat.com>"

ARG PYPI_MIRROR="https://pypi.python.org/simple"
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_INDEX_URL=$PYPI_MIRROR \
    REQUESTS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"

EXPOSE 8080

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
        make \
        openldap-devel \
        openssl-devel \
        postgresql-devel \
        procps-ng \
        python39-devel \
        python39-pip \
        python39-wheel \
        redhat-rpm-config \
        which \
    && dnf --nodocs --setopt install_weak_deps=false -y upgrade --security \
    && dnf clean all

# Before copying the entire source, copy just requirements.txt.
# This makes podman cache this (lengthy) step as long as requirements.txt stays unchanged.
# Without this, any change in src/ would make pip install run again.
COPY ./requirements.txt /opt/app-root/src/requirements.txt
RUN pip3 install -r /opt/app-root/src/requirements.txt && \
    rm -f /opt/app-root/src/requirements.txt
COPY . /opt/app-root/src

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root
