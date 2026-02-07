#!/usr/bin/env bash
set -euo pipefail

# Wait for CI checks to complete on the current branch's PR.
# Usage: wait-for-ci.sh [timeout_seconds] [poll_interval_seconds]
# Defaults: timeout=600 (10 min), poll=30s

TIMEOUT="${1:-600}"
POLL_INTERVAL="${2:-30}"
ELAPSED=0

PR_NUMBER=$(gh pr view --json number --jq '.number' 2>/dev/null)
if [ -z "$PR_NUMBER" ]; then
  echo "ERROR: No PR found for the current branch."
  exit 1
fi

echo "Waiting for CI on PR #${PR_NUMBER} (timeout: ${TIMEOUT}s)..."

while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
  STATUS=$(gh pr checks "$PR_NUMBER" --json state --jq '.[].state' 2>/dev/null || true)

  if [ -z "$STATUS" ]; then
    echo "No checks found yet, waiting..."
    sleep "$POLL_INTERVAL"
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
    continue
  fi

  # Check if any check failed
  if echo "$STATUS" | grep -qi "FAILURE\|ERROR\|CANCELLED"; then
    echo "CI FAILED on PR #${PR_NUMBER}."
    gh pr checks "$PR_NUMBER"
    exit 1
  fi

  # Check if all checks passed (no PENDING or IN_PROGRESS)
  if ! echo "$STATUS" | grep -qi "PENDING\|IN_PROGRESS\|QUEUED\|REQUESTED\|WAITING"; then
    echo "CI PASSED on PR #${PR_NUMBER}."
    exit 0
  fi

  echo "CI still running... (${ELAPSED}s elapsed)"
  sleep "$POLL_INTERVAL"
  ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

echo "TIMEOUT: CI did not complete within ${TIMEOUT}s."
exit 2
