#!/usr/bin/env bash
# Update OSIDB version in all places
#

if [[ $1 =~ [0-9]*\.[0-9]*\.[0-9]* ]]; then 
    echo "Replacing version in osidb/__init__.py"
    sed -i 's/__version__ = "[0-9]*\.[0-9]*\.[0-9]*"/__version__ = "'$1'"/g' osidb/__init__.py

    echo "Replacing version in config/settings.py"
    sed -i 's/"VERSION": "[0-9]*\.[0-9]*\.[0-9]*"/"VERSION": "'$1'"/g' config/settings.py

    echo "Replacing version in pyproject.toml"
    sed -i 's/version = "[0-9]*\.[0-9]*\.[0-9]*"/version = "'$1'"/g' pyproject.toml

    echo "Replacing version in uv.lock"
    sed -i '/^name = "osidb"$/,/^$/ s/version = "[0-9]*\.[0-9]*\.[0-9]*"/version = "'$1'"/' uv.lock

    echo "Replacing version in openapi.yml"
    ./scripts/schema-check.sh

    echo "Updating the CHANGELOG.md to $1"
    sed -i 's/^## Unreleased.*/## Unreleased\n\n## ['"$1"'] - '$(date '+%Y-%m-%d')'/' docs/CHANGELOG.md
else 
    echo "invalid version $1" 
    exit 1
fi

exit 0
