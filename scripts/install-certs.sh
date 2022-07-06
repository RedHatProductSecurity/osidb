#!/bin/bash

if [[ -z "${1}" ]]; then
    echo -e "\e[1;33mWARNING: RH_CERT_URL environment variable not set, internal RH resources won't be accessible\e[0m"
else
    curl "${1}RH-IT-Root-CA.crt" -o /etc/pki/ca-trust/source/anchors/RH-IT-Root-CA.crt
    mkdir /etc/ipa
    curl "${1}ipa.crt" -o /etc/ipa/ipa.crt
    update-ca-trust
fi
