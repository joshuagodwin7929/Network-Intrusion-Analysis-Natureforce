#!/usr/bin/env bash
# WARNING: this writes a real malware sample to disk (evidence/extracted/).
# Run it only inside an isolated VM. Never execute, open or double-click the result.
# Usage: ./scripts/extract_sample.sh --i-understand [path/to/pcap]
set -u
cd "$(dirname "$0")/.."
if [ "${1:-}" != "--i-understand" ]; then
  sed -n '2,5p' "$0"; exit 1
fi
P="${2:-pcaps/2026-10-01-traffic-analysis-exercise.pcap}"
OUT=evidence/extracted
mkdir -p "$OUT"
tshark -r "$P" -q --export-objects "http,$OUT" >/dev/null
f=$(find "$OUT" -iname '*runner_ilove*' | head -1)
[ -n "$f" ] || { echo "executable not found in HTTP objects" >&2; exit 1; }
[ "$f" = "$OUT/runner_ilove.exe" ] || mv "$f" "$OUT/runner_ilove.exe"
chmod -x "$OUT/runner_ilove.exe"
./scripts/verify_hashes.sh
