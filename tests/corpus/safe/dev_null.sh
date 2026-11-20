#!/usr/bin/env bash
# expect-level: LOW
ls missing 2>/dev/null >/dev/null || echo none
