# Wireshark display filters I used

First set View > Time Display Format > UTC Date and Time of Day, so every time in the report is UTC.

| Question | Filter | What to look at |
|---|---|---|
| Who joined the network, and with what address? | `dhcp` | Frames 1 to 4. In the Offer and ACK: "Your (client) IP address" and "Client MAC address". In the Request: Option 50 and Option 12 |
| Which LAN host talks to the alert addresses? | `ip.addr == 107.175.82.242 \|\| ip.addr == 195.64.128.106` | The internal address in the Source or Destination columns |
| What exactly was requested from the first server? | `ip.addr == 107.175.82.242` | Frame 23091 (request) and 24916 (reassembled response) |
| What new connections did the victim start after the download? | `ip.src == 10.10.1.128 && tcp.flags.syn == 1 && tcp.flags.ack == 0 && frame.time_utc >= "2026-10-01 19:30:38"` | The destination address and port columns |
| What names did the victim look up? | `dns.flags.response == 0 && ip.src == 10.10.1.128` | Gaps in time and unusual names |
| Which user logged on? | `kerberos.CNameString && !(kerberos.CNameString contains "$")` | Add `CNameString` as a column. Names ending in `$` are computer accounts |
| Which computer account? | `kerberos.CNameString contains "$"` | `cname-string` in an AS-REQ |
| Everything in the long session | `tcp.stream eq 130` | Ctrl+End jumps to the last packet |
| Does the long session contain a TLS handshake? | `tcp.stream eq 130 && tls.handshake.type == 1` | Zero rows means no Client Hello was detected |
| Who is a TLS session talking to? | `tcp.stream eq 127 && tls.handshake.type == 1` | Add `tls.handshake.extensions_server_name` as a column |
| Google DNS session | `ip.addr == 8.8.4.4` | Client Hello with SNI `dns.google` (frame 24929) |
| Do known-related domains appear? | `frame contains "lapiscorbel" \|\| frame contains "vdsina" \|\| frame contains "rollup"` | Zero is a valid result |
| Any DNS answer for an address? | `dns.a == 195.63.128.106` | Zero means no plain DNS answer in the capture contained it. The address could still have come from an encrypted lookup (the host used dns.google) or been hard-coded. I got 0 |
| What did the victim connect to on the DC? | `ip.addr==10.10.1.128 && ip.addr==10.10.1.10 && tcp.flags.syn==1 && tcp.flags.ack==0` plus a `frame.time_utc` range | Destination ports: 389 LDAP, 88 Kerberos, 135 and a high port for RPC |
| Which DRSUAPI calls were made? | The same host filter plus `&& drsuapi` | Show `dcerpc.opnum`: 0 is bind, 12 is name lookup (DRSCrackNames), 1 is unbind, 3 would be replication (DRSGetNCChanges) |

## Other windows and menus

- Statistics > Conversations > TCP: untick "Limit to display filter" and tick "Absolute start time". Click the Bytes header to sort the largest sessions to the top.
- File > Export Objects > HTTP lists every HTTP object. The executable was packet 24916.
- Statistics > I/O Graphs with `tcp.stream eq 130` shows traffic over time for the long session.

## Notes

- `ip.addr == X` matches the address in either direction.
- Alert text is often defanged (`1.2.3[.]4`). Remove the brackets before you use an address in a filter, and copy the address from the packet details instead of retyping it.
- A filter that returns nothing is information, not an error. Check that the bar is green and that the status bar says "Displayed: 0".
- The Conversations dialog only counts what the current display filter shows when you open it. If every row shows 0 packets, clear the filter and reopen the dialog. This got me once.
- With `tshark -q -z`, put the filter inside the `-z` argument, for example `-z 'conv,tcp,ip.addr==10.10.1.10'`. A `-Y` filter is ignored for the statistics.
