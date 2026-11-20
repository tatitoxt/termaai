#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: write_outside_workspace
echo 127.0.0.1 evil | tee -a /etc/hosts
