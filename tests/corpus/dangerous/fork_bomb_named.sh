#!/usr/bin/env bash
# expect-level: HIGH
# expect-rule: fork_bomb
bomb() {
  bomb | bomb &
}
bomb
