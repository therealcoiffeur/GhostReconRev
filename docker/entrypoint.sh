#!/bin/sh
set -eu

mkdir -p /app/data /app/artifacts/collectors /app/artifacts/reports /app/tools/bin /tmp

exec "$@"
