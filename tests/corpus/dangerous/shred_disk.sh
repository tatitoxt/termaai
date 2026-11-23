#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: device_write
shred -n 3 /dev/sdb
