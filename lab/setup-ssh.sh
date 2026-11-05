#!/bin/sh
# Linux laptop: authorize the main PC's key. Run from the repo root:  sh lab/setup-ssh.sh
set -e
KEY=$(cat "$(dirname "$0")/main-pc.pub")
mkdir -p ~/.ssh && chmod 700 ~/.ssh
grep -qF "$KEY" ~/.ssh/authorized_keys 2>/dev/null || echo "$KEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo "key authorized for $(whoami)@$(hostname)"
