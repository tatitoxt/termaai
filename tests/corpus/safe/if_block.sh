#!/usr/bin/env bash
# expect-level: LOW
if [ -f notes.txt ]; then
  cat notes.txt
else
  echo missing
fi
