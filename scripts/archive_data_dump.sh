#!/bin/bash

BASE_DIR="osidb_data_backup_dump"
mkdir -p "$BASE_DIR"

LAST_NUM=$(ls -d ${BASE_DIR}/00* 2>/dev/null | sort -V | tail -n1 | grep -oE '[0-9]+$')
if [[ -z "$LAST_NUM" ]]; then
    NEXT_NUM=1
else
    NEXT_NUM=$((10#$LAST_NUM + 1))
fi

TARGET_DIR=$(printf "%s/%03d" "$BASE_DIR" "$NEXT_NUM")

mkdir -p "$TARGET_DIR"

mv osidb_data_backup_dump* "$TARGET_DIR" 2>/dev/null

echo "Moved files to $TARGET_DIR"
