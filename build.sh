#!/bin/bash
set -e

cd "$(dirname "$0")"

make -j$(nproc)

echo ""
echo "Run with: ./netman"
