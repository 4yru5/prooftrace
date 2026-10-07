#!/usr/bin/env bash
# Run the ProofTrace investigation through Temporal end to end, locally.
#   - starts a Temporal dev server (Web UI on http://localhost:8233)
#   - starts the ProofTrace worker
#   - triggers the ProofTraceWorkflow on the seeded PR
# No cloud, no API key. Ctrl-C to stop; the server/worker are cleaned up.
set -euo pipefail
cd "$(dirname "$0")/.."

export PROOFTRACE_LLM="${PROOFTRACE_LLM:-auto}"
export PROOFTRACE_SANDBOX="${PROOFTRACE_SANDBOX:-auto}"

cleanup() { kill "${SERVER_PID:-}" "${WORKER_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT

echo "▶ starting Temporal dev server (Web UI: http://localhost:8233)…"
temporal server start-dev --log-level error >/tmp/prooftrace-temporal.log 2>&1 &
SERVER_PID=$!

# wait for the frontend to accept connections
for i in $(seq 1 30); do
  if temporal operator cluster health >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "▶ starting ProofTrace worker…"
uv run python -m prooftrace.worker >/tmp/prooftrace-worker.log 2>&1 &
WORKER_PID=$!
sleep 3

echo "▶ triggering ProofTraceWorkflow on the seeded PR…"
uv run python -m prooftrace.temporal_run

echo
echo "✓ workflow complete. Open the Temporal Web UI to see the history + retries:"
echo "    http://localhost:8233"
echo "  (press Ctrl-C to stop the server and worker)"
# keep the server up so the Web UI can be inspected / screen-captured
wait "$WORKER_PID"
