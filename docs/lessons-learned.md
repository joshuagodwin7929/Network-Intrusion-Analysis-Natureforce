# Lessons learned

## Technical

- Measure before you label. The first packets of the long session looked like data going out. The totals (14 MB in, 434 kB out) said the reverse. Reading a few rows gives you a hypothesis, and the conversation statistics are the test.
- An empty result can be the right result. A filter for the alert address returned nothing, and that was a real finding: the address in the alert wasn't the address in the capture.
- Copy, don't retype. Two addresses one digit apart are easy to mix up when you read them off a screen. Use Copy > Value from the packet details.
- One source is a lead and three is an answer. I got the host name from DHCP, LLMNR and Kerberos, and I checked the user name on every Kerberos packet.
- Check a file three ways before the hash goes anywhere: size against Content-Length, MD5 against the server's ETag, and type with `file`.
- Keep enrichment apart from evidence. VirusTotal labels disagreed (CapDoor, Zusy, AsyncRAT), so the report says the family isn't settled. The sandbox showed no network traffic for the executable, so the link to the long session rests on pcap timing alone.
- Say what you can't see. With no endpoint data and an unreadable stream, I don't know the session's purpose or what the executable did.

## Tooling

- NetworkMiner needed Mono and a launch workaround (see `methodology/lab-setup.md`). Wireshark and tshark were enough for every finding, and tshark makes the numbers reproducible through `scripts/reproduce_metrics.sh`.
- I ran `reproduce_metrics.sh` against the real pcap on Kali. The values I compared matched the report: the capture summary, DHCP, Kerberos, the executable request, stream 130, the SYN and DNS checks, and the holtandberyl redirects. Doing this showed me two small slips, a one-microsecond timestamp difference and a frame range, and I fixed both.
- Defanged indicators from alerts have to be refanged for filters and defanged again for reports.
- With `tshark -q -z`, the display filter has to go inside the `-z` argument (`-z io,phs,<filter>`). `-Y` is ignored for the statistics, and my first attempt silently gave me a table for the whole capture. The `Filter:` line at the top of the output shows whether the filter was applied.

## Still to do

- Compare my findings with the exercise author's published answers, and note what I missed or described differently. I'm doing this last on purpose.
