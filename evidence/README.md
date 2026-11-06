# Evidence

| File | What it is | How I made it |
|---|---|---|
| `hashes.sha256` | SHA-256 of the pcap, the downloaded zip and the extracted executable | `sha256sum`; check it with `scripts/verify_hashes.sh` |
| `iocs.csv` | Indicators, defanged with `[.]` and `hxxp`. Refang with `sed 's/\[\.\]/./g; s/hxxp/http/'` | From the pcap and VirusTotal |
| `timeline.csv` | UTC timeline with frame numbers | From Wireshark and tshark |
| `stream-metrics.md` | Measured values for the three largest sessions | `tshark -z conv,tcp` and frame-length sums |

The screenshots are in [`../screenshots/`](../screenshots/). Each one is embedded in the report next to the finding it supports.

## Left out on purpose

- The pcap and its zip. They're large, and the exercise author distributes them.
- The extracted executable `runner_ilove.exe`, because it's malware. `.gitignore` blocks `pcaps/`, `evidence/extracted/` and common executable extensions.

## Sources and dates

I collected the VirusTotal results in late October 2026, and they change over time. The report says which values come from VirusTotal and which come from the capture.
