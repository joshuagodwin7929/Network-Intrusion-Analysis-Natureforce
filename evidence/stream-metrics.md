# Measured session values

These come from `tshark -z conv,tcp` and from summing frame lengths. `scripts/reproduce_metrics.sh` reproduces them. Start times are UTC, and the first packet is at 19:27:27.354882. Byte counts include Ethernet, IP and TCP headers.

| Stream | Endpoints | Start (UTC) | Duration | Server to victim | Victim to server | Packets |
|---|---|---|---|---|---|---|
| 127 | 10.10.1.128:63722 to 57.150.53[.]97:443 | 19:30:29.862 | 6.74 s | 8,535 frames, 11 MB | 4,344 frames, 270 kB | 12,879 |
| 128 | 10.10.1.128:63723 to 107.175.82[.]242:9000 | 19:30:36.732 | 2.14 s | 1,219 frames, 1,713 kB | 614 frames, 36 kB | 1,833 |
| 130 | 10.10.1.128:63725 to 195.63.128[.]106:443 | 19:30:44.329 | 2,233.64 s | 10,197 frames, 14 MB | 5,398 frames, 434 kB | 15,595 |

## Stream 130 in detail

| Measurement | Value |
|---|---|
| Server to victim bytes (exact) | 14,013,041 |
| Victim to server bytes (exact) | 434,262 |
| Share toward the victim | 97.0% (about 32 to 1) |
| TLS Client Hello in the stream | 0 |
| First payload bytes, frame 24969 | `749c90db ffffffff 24af9c9e 43000000` |
| Last packets | Frames 42489 and 42492 to 42495 (the frames between belong to other streams), all ACKs, last at 20:07:57.964747 |
| Domain check | 0 packets contain lapiscorbel, vdsina or rollup |

The screenshots behind these numbers are `screenshots/29-tshark-stream-metrics.png` and `screenshots/31-tshark-exact-bytes-and-holtandberyl.png`.
