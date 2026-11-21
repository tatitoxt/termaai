#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: device_write
dd if=/dev/zero of=/dev/sda bs=1M
