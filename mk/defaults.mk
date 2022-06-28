############################################################################
## Defaults
############################################################################
python3=`which python3`
tox=`which tox`
podman=`which podman`
podmancompose=`which podman-compose | head -n 1`
oc=`which oc`
ap=`which ansible-playbook`
ocptoken=`oc whoami -t`
pc=`which pip-compile`
ps=`which pip-sync`
openssl=`which openssl`
ds=`which detect-secrets`
pre-commit=`which pre-commit`

# Make sourcing work as expected. https://stackoverflow.com/a/43566158
SHELL := /bin/bash
