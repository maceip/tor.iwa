#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOR_SRC="${TOR_SRC:-$(realpath "$SCRIPT_DIR/../Tor")}"
SOCKET_IWA="${SOCKET_IWA:-$(realpath "$SCRIPT_DIR/../socket-iwa")}"

if [ ! -f "$TOR_SRC/configure.ac" ]; then
  echo "ERROR: Tor source not found at $TOR_SRC"
  echo "Set TOR_SRC=/path/to/tor"
  exit 1
fi

if [ ! -f "$SOCKET_IWA/emscripten/src/lib/libdirectsockets.js" ]; then
  echo "ERROR: socket-iwa not found at $SOCKET_IWA"
  echo "Set SOCKET_IWA=/path/to/socket-iwa"
  exit 1
fi

echo "=== tor-iwa build ==="
echo "Tor source:   $TOR_SRC"
echo "socket-iwa:   $SOCKET_IWA"
echo "Build script: $SCRIPT_DIR"
echo ""

# Use a named volume to cache build artifacts between runs
docker volume create tor-iwa-build 2>/dev/null || true

docker run --rm \
  -v "$TOR_SRC:/tor-src:ro" \
  -v "$SOCKET_IWA:/socket-iwa:ro" \
  -v "$SCRIPT_DIR:/tor-iwa" \
  -v "$SCRIPT_DIR/deps:/deps:ro" \
  -v tor-iwa-build:/build \
  -w /tor-iwa \
  emscripten/emsdk:latest \
  bash /tor-iwa/docker_build.sh

echo ""
echo "=== Build complete ==="
ls -la "$SCRIPT_DIR/iwa/public/"
