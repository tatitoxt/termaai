#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: device_write
dd if=image.iso of=/dev/nvme0n1 status=progress
