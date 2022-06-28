#!/usr/bin/env bash
make check-venv-active
git diff --cached --name-only -z | xargs -0 detect-secrets-hook --baseline .secrets.baseline
