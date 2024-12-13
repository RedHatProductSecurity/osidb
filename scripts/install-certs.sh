#!/bin/bash

if [[ -z "${1}" ]]; then
    echo -e "\e[1;33mWARNING: RH_CERT_URL environment variable not set, internal RH resources won't be accessible\e[0m"
else
    curl "${1%/}/certs/Current-IT-Root-CAs.pem" -o /etc/pki/ca-trust/source/anchors/RH-IT-Root-CAs.pem
    mkdir /etc/ipa
    curl "${1%/}/chains/ipa-ca-chain-2022.crt" -o /etc/ipa/ipa.crt
    curl "${1%/}/chains/rhcs-ca-chain-2022-self-signed.crt" -o /etc/ipa/rhcs.crt
    update-ca-trust
fi
