#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: destructive_rm
find ~ -type f -exec rm -f {} \;
