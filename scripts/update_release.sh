#!/usr/bin/env bash
# Update OSIDB version in all places
#

function check_and_set_version(){
    if [[ `grep -E $1=\"[0-9]*\.[0-9]*\.[0-9]*\" $2 | wc -l` != 1 ]] ; then
        echo "Didn't find 1 version in $2. Giving up."
        exit 1
    else
        echo "Replacing version in $2."
        sed -i 's/'$1'="[0-9]*\.[0-9]*\.[0-9]*"/'$1'="'$3'"/g' $2
    fi
}

if [[ $1 =~ [0-9]*\.[0-9]*\.[0-9]* ]]; then 
    echo "Replacing version in osidb/__init__.py"
    sed -i 's/__version__ = "[0-9]*\.[0-9]*\.[0-9]*"/__version__ = "'$1'"/g' osidb/__init__.py

    echo "Replacing version in config/settings.py"
    sed -i 's/"VERSION": "[0-9]*\.[0-9]*\.[0-9]*"/"VERSION": "'$1'"/g' config/settings.py

    echo "Replacing version in openapi.yml"
    make update-schema >/dev/null

    check_and_set_version 'osidb_source_ref' 'openshift/inventory/osidb' $1
else 
    echo "invalid version $1" 
    exit 1
fi

exit 0
