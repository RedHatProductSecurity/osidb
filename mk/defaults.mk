############################################################################
## Defaults
############################################################################
python3=`which python3`
tox=`which tox`
podman=`which podman`
oc=`which oc`
ap=`which ansible-playbook`
ocptoken=`oc whoami -t`
uv=`which uv`
openssl=`which openssl`
ds=`which detect-secrets`
pre-commit=`which pre-commit`

# Make sourcing work as expected. https://stackoverflow.com/a/43566158
SHELL := /bin/bash
