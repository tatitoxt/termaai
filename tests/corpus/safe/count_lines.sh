#!/usr/bin/env bash
# expect-level: LOW
find . -type f -name '*.txt' -print0 | xargs -0 -r wc -l
