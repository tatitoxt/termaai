#!/usr/bin/env bash
# expect-level: MEDIUM
# expect-rule: persistence
(crontab -l; echo '* * * * * ./x.sh') | crontab -
