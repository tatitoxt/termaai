#!/usr/bin/env bash
# expect-level: LOW
for f in *.log; do
  gzip -k "$f"
done
