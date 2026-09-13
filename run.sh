#!/bin/bash
# Build the project and start the local dashboard backend.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

./build.sh
echo ""
echo "ADTCN dashboard: http://localhost:8000"
echo "Press Ctrl-C to stop the backend."
cd backend-java
exec java -cp out adtcn.Main