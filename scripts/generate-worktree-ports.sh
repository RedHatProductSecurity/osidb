#!/bin/bash
# Auto-generate unique ports for worktree based on directory name
IFS=$' \t\n'
set -euo pipefail

WORKTREE_NAME=$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | sed 's/^[^a-z0-9]*//' | sed 's/[^a-z0-9_-]/-/g')
[ -n "$WORKTREE_NAME" ] || WORKTREE_NAME="worktree-$(echo "$PWD" | cksum | cut -d' ' -f1)"

PORT_OFFSET=$(echo "$PWD" | cksum | cut -d' ' -f1)
[[ "$PORT_OFFSET" =~ ^[0-9]+$ ]] || { echo "ERROR: cksum produced non-numeric output: $PORT_OFFSET" >&2; exit 1; }
PORT_OFFSET=$(( (PORT_OFFSET % 999) + 1 ))

# Probe for port conflicts with other git worktrees; increment offset until clear
_has_port_conflict() {
    local offset="$1"
    local my_ports="$((8000 + offset)) $((5432 + offset)) $((6379 + offset)) $((5555 + offset)) $((1389 + offset)) $((1636 + offset)) $((9000 + offset))"
    local wt_path env_file line port p
    while IFS= read -r wt_path; do
        [ "$wt_path" = "$PWD" ] && continue
        env_file="${wt_path}/.env.worktree"
        [ -f "$env_file" ] || continue
        while IFS= read -r line; do
            case "$line" in
                OSIDB_PORT=*|POSTGRES_PORT=*|REDIS_PORT=*|FLOWER_PORT=*|LDAP_PORT=*|LDAPS_PORT=*|LOCUST_PORT=*)
                    port="${line#*=}"
                    for p in $my_ports; do [ "$p" = "$port" ] && return 0; done
                    ;;
            esac
        done < "$env_file"
    done < <(git worktree list --porcelain 2>/dev/null | sed -n 's/^worktree //p')
    return 1
}

if git rev-parse --git-dir >/dev/null 2>&1; then
    tries=0
    while _has_port_conflict "$PORT_OFFSET"; do
        PORT_OFFSET=$(( (PORT_OFFSET % 999) + 1 ))
        tries=$((tries + 1))
        [ "$tries" -lt 999 ] || { echo "ERROR: Cannot find a non-conflicting port allocation" >&2; exit 1; }
    done
fi

# Copy base .env to .env.worktree
cp .env .env.worktree

# Append worktree-specific overrides
cat >> .env.worktree <<EOF

# === Worktree-specific overrides below ===
# Auto-generated - DO NOT EDIT - regenerate with: make worktree-generate-env

# Worktree-specific project name
COMPOSE_PROJECT_NAME=${WORKTREE_NAME}

# Worktree-specific service ports (base + offset to avoid collisions)
OSIDB_PORT=$((8000 + PORT_OFFSET))
POSTGRES_PORT=$((5432 + PORT_OFFSET))
REDIS_PORT=$((6379 + PORT_OFFSET))
FLOWER_PORT=$((5555 + PORT_OFFSET))
LDAP_PORT=$((1389 + PORT_OFFSET))
LDAPS_PORT=$((1636 + PORT_OFFSET))
LOCUST_PORT=$((9000 + PORT_OFFSET))
EOF

echo "Generated .env.worktree for worktree: $WORKTREE_NAME"
echo "Ports: OSIDB=$((8000 + PORT_OFFSET)) POSTGRES=$((5432 + PORT_OFFSET)) REDIS=$((6379 + PORT_OFFSET)) FLOWER=$((5555 + PORT_OFFSET))"
