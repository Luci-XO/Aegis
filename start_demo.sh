#!/usr/bin/env sh
# Start the Aegis dashboard on macOS/Linux and open it in the browser.
cd "$(dirname "$0")" || exit 1
if [ -x .venv/bin/python ]; then PY=.venv/bin/python; else PY=python3; fi
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "Aegis needs Python 3.10 or newer." >&2
  exit 1
fi
echo "Starting the Aegis dashboard at http://127.0.0.1:8000 (Ctrl+C to stop)"
exec "$PY" -m aegis.web --open "$@"
