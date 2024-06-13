#!/bin/bash

if [[ -z "${1}" ]]; then
    echo -e "\e[1;33mWARNING: RH_CERT_URL environment variable not set, internal RH resources won't be accessible\e[0m"
else
    curl "${1%/}/certs/2015-IT-Root-CA.pem" -o /etc/pki/ca-trust/source/anchors/RH-IT-Root-CA.crt
    curl "${1%/}/certs/2022-IT-Root-CA.pem" -o /etc/pki/ca-trust/source/anchors/2022-IT-Root-CA.pem
    mkdir /etc/ipa
    curl "${1%/}/chains/ipa-ca-chain-2015.crt" -o /etc/ipa/ipa.crt
    update-ca-trust
fi
