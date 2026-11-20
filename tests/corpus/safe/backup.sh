#!/usr/bin/env bash
# expect-level: LOW
mkdir -p backup
tar -czf backup/workspace.tar.gz --exclude=./backup .
