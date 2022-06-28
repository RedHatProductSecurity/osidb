FROM registry.redhat.io/ubi8/ubi:8.6

LABEL summary="OSIDB" \
      maintainer="Product Security DevOps <prodsec-dev@redhat.com>"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_INDEX_URL="https://repository.engineering.redhat.com/nexus/repository/pypi.org/simple/" \
    REQUESTS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"

EXPOSE 8080

WORKDIR /opt/app-root/src/

# Download internal root CA cert and the IPA CA cert
RUN curl https://password.corp.redhat.com/RH-IT-Root-CA.crt -o /etc/pki/ca-trust/source/anchors/RH-IT-Root-CA.crt && \
    mkdir /etc/ipa && \
    curl https://password.corp.redhat.com/ipa.crt -o /etc/ipa/ca.crt && \
    update-ca-trust

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

# copy krb client configuration
COPY etc/krb/krb5.conf /etc

# Before copying the entire source, copy just requirements.txt.
# This makes podman cache this (lengthy) step as long as requirements.txt stays unchanged.
# Without this, any change in src/ would make pip install run again.
COPY ./requirements.txt /opt/app-root/src/requirements.txt
RUN pip3 install -r /opt/app-root/src/requirements.txt && \
    rm -f /opt/app-root/src/requirements.txt
COPY . /opt/app-root/src

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root
