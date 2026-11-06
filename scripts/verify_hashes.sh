#!/usr/bin/env bash
# Check local files against evidence/hashes.sha256. Files that are not present are skipped.
set -u
cd "$(dirname "$0")/.."

echo "== SHA-256 =="
sha256sum -c --ignore-missing evidence/hashes.sha256

EXE="evidence/extracted/runner_ilove.exe"
if [ -f "$EXE" ]; then
  echo "== Executable checks =="
  size=$(stat -c %s "$EXE")
  echo "size: $size (expected 1646592)"
  echo "cb50fe432a302b85845bc7ea98742c11  $EXE" | md5sum -c -
  file "$EXE"
else
  echo "(extracted executable not present; skipping size, MD5 and type checks)"
fi
