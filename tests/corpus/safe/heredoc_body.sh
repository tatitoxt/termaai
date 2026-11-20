#!/usr/bin/env bash
# expect-level: LOW
cat <<'EOF' > README.txt
rm -rf /
sudo reboot
EOF
