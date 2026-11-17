#!/usr/bin/env bash
# Docker-only launcher. Nothing but Docker is required on the host.
#
#   ./run.sh                 # GUI + Explorer file picker / repository import
#   ./run.sh demo            # offline demo -> ./out/demo_report.{html,json}
#   ./run.sh start           # interactive CLI; /work inputs -> ./out reports
#   ./run.sh cli run ...     # any PatchTriage CLI command in Docker
#   ./run.sh --stop          # stop the GUI
#   PORT=9000 ./run.sh       # use a different GUI port
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8765}"
URL="http://localhost:${PORT}"

# docker compose (v2) or docker-compose (v1)?
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "ERROR: Docker Compose not found. Install Docker Desktop or the" >&2
  echo "       docker-compose-plugin, then re-run ./run.sh" >&2
  exit 1
fi

usage() {
  echo "Usage: ./run.sh [gui|demo|start|cli COMMAND...|--stop]"
  echo "  gui       Open the browser UI (default; file picker and repository URLs)"
  echo "  demo      Run the offline demo; reports are written under ./out"
  echo "  start     Run the guided CLI; repository files are mounted at /work"
  echo "  cli ...   Run an arbitrary patchtriage command inside Docker"
}

MODE="${1:-gui}"
case "${MODE}" in
  --help|-h)
    usage
    exit 0
    ;;
  --stop)
    "${DC[@]}" down
    echo "PatchTriage console stopped."
    exit 0
    ;;
  demo|start)
    if [[ "$#" -ne 1 ]]; then
      echo "ERROR: ./run.sh ${MODE} does not accept extra arguments." >&2
      usage >&2
      exit 2
    fi
    mkdir -p out
    echo "==> building the PatchTriage ${MODE} image..."
    "${DC[@]}" build "${MODE}"
    echo "==> running PatchTriage ${MODE} in Docker..."
    "${DC[@]}" run --rm "${MODE}"
    exit 0
    ;;
  cli)
    shift
    if [[ "$#" -eq 0 ]]; then
      echo "ERROR: ./run.sh cli needs a patchtriage command." >&2
      usage >&2
      exit 2
    fi
    mkdir -p out
    "${DC[@]}" build triage
    "${DC[@]}" run --rm triage "$@"
    exit 0
    ;;
  gui)
    if [[ "$#" -gt 1 ]]; then
      echo "ERROR: ./run.sh gui does not accept extra arguments." >&2
      usage >&2
      exit 2
    fi
    ;;
  *)
    echo "ERROR: unknown mode: ${MODE}" >&2
    usage >&2
    exit 2
    ;;
esac

echo "==> building and starting the PatchTriage console (Docker)..."
PATCHTRIAGE_PORT="${PORT}" "${DC[@]}" up -d --build gui

echo "==> waiting for the console to become ready..."
for i in $(seq 1 60); do
  if curl -fsS "${URL}/api/config" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done

if [[ "${ready:-}" != "1" ]]; then
  echo "The console did not become ready in time. Check logs with:" >&2
  echo "    ${DC[*]} logs gui" >&2
  exit 1
fi

echo
echo "  PatchTriage console is live:  ${URL}"
echo "  Stop it with:                 ./run.sh --stop"
echo

# Try to open a browser (ignored on headless servers).
if command -v xdg-open >/dev/null 2>&1; then xdg-open "${URL}" >/dev/null 2>&1 || true
elif command -v open   >/dev/null 2>&1; then open "${URL}"   >/dev/null 2>&1 || true
elif command -v powershell.exe >/dev/null 2>&1; then powershell.exe -NoProfile Start "${URL}" >/dev/null 2>&1 || true
else echo "Open ${URL} in your browser."; fi
