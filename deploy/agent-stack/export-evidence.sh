#!/bin/sh
# Exports the agent evidence of the running isolation stack as the
# read-only auditor and verifies the bundle offline (ADR-005 §13).
#
# The checkpoint writer runs every few seconds in this stack. The newest
# records may not be under a checkpoint yet, which the verifier reports as
# a warning (exit 2): wait and try again. Any other failure is final.
set -eu

KEYS=/auditor/trusted-keys.json
WORK=$(mktemp -d)
attempt=0

while :; do
  attempt=$((attempt + 1))
  out="$WORK/bundle-$attempt"
  kept="$WORK/kept-$attempt.jsonl"

  # The checkpoint an operator would keep off-host, taken before the export.
  kavach-evidence checkpoints --latest > "$kept"
  if [ ! -s "$kept" ]; then
    if [ "$attempt" -ge 20 ]; then
      echo "FAIL: the running API wrote no checkpoint"
      exit 1
    fi
    echo "no checkpoint yet (attempt $attempt); waiting for the checkpoint writer"
    sleep 3
    continue
  fi

  kavach-evidence export --out "$out" --key-dir /auditor --key-id dev-export-1

  status=0
  kavach-evidence verify-bundle "$out" --keys "$KEYS" --dev \
    --expect-checkpoint "$kept" > "$WORK/report.txt" || status=$?
  cat "$WORK/report.txt"

  case "$status" in
    0) break ;;
    2)
      if [ "$attempt" -ge 20 ]; then
        echo "FAIL: the evidence is still not fully protected after $attempt attempts"
        exit 1
      fi
      echo "not fully protected yet (attempt $attempt); waiting for the checkpoint writer"
      sleep 3
      ;;
    *) echo "FAIL: the bundle does not verify"; exit 1 ;;
  esac
done

# The probe must have left records, and a real checkpoint must match.
grep -Eq '^  records: [1-9]' "$WORK/report.txt" || { echo "FAIL: no records were exported"; exit 1; }
grep -q '^  kept checkpoint: matches at record' "$WORK/report.txt" || {
  echo "FAIL: the chain was not compared with a kept checkpoint"; exit 1; }
grep -q '^  manifest: signed with dev-export-1' "$WORK/report.txt" || {
  echo "FAIL: the bundle is not signed with the export key"; exit 1; }

# A bundle changed after export must fail (here: one byte appended).
printf '\n' >> "$out/records.jsonl"
if kavach-evidence verify-bundle "$out" --keys "$KEYS" --dev --allow-warnings > /dev/null; then
  echo "FAIL: a changed bundle verified"
  exit 1
fi

echo "PASS evidence exported as kavach_auditor and verified offline (attempt $attempt)"
