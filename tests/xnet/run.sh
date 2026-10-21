#!/bin/sh
# Host unit test of the xnet extension's pure helpers (no proot, no device).
set -e
cd "$(dirname "$0")"
out="${TMPDIR:-/tmp}/test-xnet.$$"
cc -Wall -Wextra -DXNET_PURE_ONLY -o "$out" test-xnet.c
"$out"
rm -f "$out"
