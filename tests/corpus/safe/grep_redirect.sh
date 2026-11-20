#!/usr/bin/env bash
# expect-level: LOW
grep -rn TODO . > todo.txt 2>/dev/null || true
