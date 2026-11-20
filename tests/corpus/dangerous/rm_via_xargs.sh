#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: destructive_rm
xargs -0 rm -rf -- /opt/app < list.txt
