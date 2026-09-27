#!/usr/bin/env bash
# Copyright (c) 2026 The Trap Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Build ckpool for TRAP solo mining.
#
# Fetches the ckpool revision that was tested against TRAP, applies the TRAP
# patches in this directory and builds it without the optional Cap'n Proto IPC
# shim (whose generated code does not build against every capnp version; ckpool
# talks to trapcoind over RPC instead).
#
# Usage: build-ckpool.sh [target-dir]     (default: ./ckpool)
# Requires: git build-essential autoconf automake libtool pkg-config
# Optional: yasm (faster share hashing)

set -euo pipefail

CKPOOL_REPO="https://bitbucket.org/ckolivas/ckpool.git"
CKPOOL_COMMIT="e9b66549a636489d7e4eeb92995c25fe9a25ab35"

here="$(cd "$(dirname "$0")" && pwd)"
target="${1:-ckpool}"

if [ ! -d "$target/.git" ]; then
    git clone "$CKPOOL_REPO" "$target"
fi
cd "$target"
git checkout --quiet "$CKPOOL_COMMIT"
git checkout --quiet -- .
for patch in "$here"/*.patch; do
    git apply "$patch"
done

# Hide Cap'n Proto from configure so the IPC shim is not built.
wrapper="$(mktemp)"
trap 'rm -f "$wrapper"' EXIT
cat > "$wrapper" <<'EOF'
#!/bin/sh
for a in "$@"; do case "$a" in capnp*) exit 1;; esac; done
exec pkg-config "$@"
EOF
chmod +x "$wrapper"

./autogen.sh
./configure PKG_CONFIG="$wrapper"
make -j"$(nproc)"
echo "Built $(pwd)/src/ckpool"
