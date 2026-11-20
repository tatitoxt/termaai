#!/usr/bin/env bash
# expect-level: LOW
sort data.txt | uniq -c | sort -rn | head -n 5
