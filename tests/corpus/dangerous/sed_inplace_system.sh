#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: write_outside_workspace
sed -i 's/a/b/' /etc/ssh/sshd_config
