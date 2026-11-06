# network-intrusion-analysis-natureforce

By OKUNNUWA JOSHUA GODWIN | [LinkedIn](https://www.linkedin.com/in/okunnuwa-joshua-godwin)

This is my write-up of the "Natureforce" traffic analysis exercise from Malware-Traffic-Analysis.net (2026-10-01). The exercise hands you two SOC alerts and one pcap. I used them to find the infected Windows host and its user, pull out the executable it downloaded, measure the session that came right after, check the indicators on VirusTotal, and wrote down what the capture shows and what it doesn't. I also drafted two detection rules from what I saw.

I did the whole thing in a Kali VM with Wireshark and tshark. If you only read one file, read the report: [`report/incident-report.md`](report/incident-report.md).

## What I found

| Question | Answer |
|---|---|
| Infected host IP | 10.10.1.128 |
| MAC address | 00:22:fb:ec:7e:e7 |
| Host name | DESKTOP-4VGYQX7 |
| User account | NATUREFORCE\bdiaz |
| Executable | `runner_ilove.exe`, 1,646,592 bytes |
| Executable SHA-256 | `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061` |

The story in three steps:

1. At 19:27:27 UTC the host joins the network and gets its address by DHCP. At 19:27:46 it asks for a Kerberos ticket for `NATUREFORCE\bdiaz`.
2. At 19:30:36 UTC it downloads a 64-bit Windows executable from 107.175.82[.]242 over plain HTTP on TCP 9000, using `curl`. 45 of 70 VirusTotal engines flag the file.
3. At 19:30:44 UTC, about 5.7 seconds after the download ends, it opens one TCP session to 195.63.128[.]106:443. The session carries about 14 MB, 97% of it coming toward the victim. It never does a TLS handshake, and it is still open 37 minutes later when the capture stops.

## The part that tripped me up

The alert names `195.64.128[.]106`, but that address is not in the capture anywhere. The address the victim actually talked to is `195.63.128[.]106`, one digit different. I filtered on the alert address first, got zero packets, and wondered if my filter was wrong. It wasn't. The empty result was the finding. Section 7 of the report covers it, and I did not assume the two addresses were the same thing.

## What I can't tell you

The capture doesn't show what the executable did on the host, and I can't read the contents of the long session. The report says so where it matters.

## What's in the repo

```
.
├── README.md                    this file
├── report/
│   └── incident-report.md       the full report with timeline, IOCs and screenshots
├── evidence/
│   ├── README.md                what each evidence file is and how I made it
│   ├── hashes.sha256            checksums for the pcap, the zip and the extracted file
│   ├── iocs.csv                 defanged indicators
│   ├── timeline.csv             timeline with frame numbers
│   └── stream-metrics.md        measured values for the three biggest sessions
├── screenshots/                 numbered Wireshark, terminal and VirusTotal captures
├── methodology/
│   ├── analysis-workflow.md     the investigation in the order I did it, including a mistake
│   ├── wireshark-filters.md     every display filter I used and why
│   └── lab-setup.md             Kali setup, including NetworkMiner under Mono
├── detections/
│   ├── README.md                test status and how to run the draft rules
│   ├── suricata/                draft Suricata rule and a generator for a synthetic test pcap
│   └── sigma/                   draft Sigma rule for proxy logs
├── scripts/
│   ├── verify_hashes.sh         check files against evidence/hashes.sha256
│   ├── reproduce_metrics.sh     regenerate every measured value with tshark
│   └── extract_sample.sh        export the executable (it's malware, read the warning first)
└── docs/
    └── lessons-learned.md
```

## Reproducing it

The pcap and the malware sample are not in this repo. To rebuild the analysis:

1. Download the Natureforce exercise (2026-10-01) from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/). The site's About page explains the zip password. For these files it was `infected_` followed by the date as `YYYYMMDD`.
2. Put the extracted pcap in `pcaps/`. Git ignores that folder.
3. Check the file: `./scripts/verify_hashes.sh`
4. Regenerate the numbers in the report: `./scripts/reproduce_metrics.sh`

Do this in an isolated VM and never run the extracted executable.

## Tools

Wireshark 4.6.6, tshark, capinfos, `sha256sum`, `md5sum`, `file`, and VirusTotal (searching by hash and IP only, nothing uploaded). I also installed NetworkMiner 3.2 in the lab ([`methodology/lab-setup.md`](methodology/lab-setup.md)), but every finding in the report comes from Wireshark and tshark.

## What this project covers

Reading DHCP, Kerberos, DNS, HTTP and TLS in Wireshark and tshark. Going from alert indicators to a victim host. Extracting a malware sample safely and checking it (size, MD5 against the server's ETag, file type, SHA-256). Measuring a long session instead of guessing about it. Enriching indicators while keeping the source and date, and noticing when two indicators conflict. Mapping to MITRE ATT&CK only where the capture supports it. Turning observed behaviour into detection rules.

## Credits

The exercise and its pcap are by Brad Duncan of [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/), used here for training. This repo holds only my own analysis, notes and screenshots. The detection rules are drafts and aren't ready for production.
