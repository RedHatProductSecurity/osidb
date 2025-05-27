FROM registry.redhat.io/ubi9/ubi:9.6

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
        python3-devel \
        python3-pip \
        python3-wheel \
        redhat-rpm-config \
        which \
    && dnf --nodocs --setopt install_weak_deps=false -y upgrade --security \
    && dnf clean all

# Before copying the entire source, copy just requirements.txt.
# This makes podman cache this (lengthy) step as long as requirements.txt stays unchanged.
# Without this, any change in src/ would make pip install run again.
COPY ./requirements.txt /opt/app-root/src/requirements.txt
RUN pip3 install --no-deps -r /opt/app-root/src/requirements.txt && \
    rm -f /opt/app-root/src/requirements.txt
COPY . /opt/app-root/src

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root
