#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CGO_ENABLED=0
go_command=${GO:-go}
mkdir -p dist
for os in linux windows darwin; do
  for arch in amd64 arm64; do
    name="dist/java4shell-${os}-${arch}"
    if [[ $os == windows ]]; then name+=.exe; fi
    GOOS=$os GOARCH=$arch "$go_command" build -trimpath -o "$name" .
    printf '%s\n' "$name"
  done
done
