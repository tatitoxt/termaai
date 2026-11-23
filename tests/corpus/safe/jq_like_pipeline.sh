#!/usr/bin/env bash
# expect-level: LOW
cat data.json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))'
