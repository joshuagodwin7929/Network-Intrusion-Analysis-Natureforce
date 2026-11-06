# Analysis workflow

This is the investigation in the order I did it, with my reasoning at each step and one mistake I corrected along the way.

## 1. Record the evidence before touching it

I ran `capinfos` for the packet count, capture window and duration, and `sha256sum` on both the zip and the pcap. Those go at the top of the report so anyone can check they have the same file.

## 2. Find the victim with DHCP

Filter: `dhcp`

A client with no address sends a Discover from `0.0.0.0`. The server (10.10.1.10) answers with an Offer, the client sends a Request, and the server confirms with an ACK. All four packets share one transaction ID. The address being handed out isn't in the Source or Destination columns. It's in the DHCP fields "Your (client) IP address" (frames 2 and 4) and "Requested IP Address" (Option 50, frame 3). The same packets carry the client MAC address, and the Request carries the host name in Option 12.

That tells me who owns 10.10.1.128 and since when. It doesn't tell me the host is infected, so the next step ties it to the alerts.

## 3. Tie the host to the alerts

Filter: `ip.addr == 107.175.82.242 || ip.addr == 195.64.128.106`

The alert text is defanged (`107.175.82[.]242`), so I removed the brackets for Wireshark. One LAN host shows up, 10.10.1.128. The Info column shows a TCP handshake and then an HTTP GET for an executable. The Ethernet source of the first packet matches the MAC from DHCP, so the host that got the lease is the host that made the request.

## 4. Read the HTTP exchange, then extract the file

Frame 23091 is the request and frame 24916 is the end of the reassembled response. I wrote down the URI, Host, User-Agent, status, Content-Type, Content-Length, Server, ETag and Last-Modified.

I exported the file with File > Export Objects > HTTP and only touched it from a terminal:

```bash
ls -l runner_ilove.exe
sha256sum runner_ilove.exe
md5sum runner_ilove.exe
file runner_ilove.exe
```

Three checks agree. The size equals Content-Length, the MD5 equals the server's ETag, and `file` says it's a Windows PE. I then searched VirusTotal by the SHA-256 without uploading anything.

## 5. A correction: two addresses one digit apart

After the download I listed the victim's new outbound connections:

```
ip.src == 10.10.1.128 && tcp.flags.syn == 1 && tcp.flags.ack == 0 && frame.time_utc >= "2026-10-01 19:30:38"
```

A row at 19:30:44 looked like the second alert address, but a filter for `195.64.128.106` returned zero packets. My first thought was that the filter was broken. When I read the destination field of the packet itself, it said `195.63.128.106`, one digit off from the alert. The empty result had been right the whole time.

What I took from it: copy values out of Wireshark's fields instead of reading small digits off a screenshot, and treat a zero-packet result as a finding until something proves otherwise. The mismatch now has its own section in the report.

## 6. Measure the long session instead of assuming

Filtering on the address gave 15,595 packets, 36.7% of the whole capture. The first few packets of the session made it look like the victim was pushing data out, but the totals said the opposite, so I dropped that first impression. What I checked:

- `Statistics > Conversations > TCP` and `tshark -z conv,tcp` for packets, bytes and duration
- exact byte sums per direction using `frame.len`
- `tls.handshake.type == 1` inside the stream (none)
- the first payload bytes of the first data packet (not a TLS record)
- the last packet of the stream (an ACK, so the session was still open at the end)

## 7. Identify the other big sessions

Stream 127 (12 MB) turned out to be a Microsoft Azure blob host, going by its TLS server name, and VirusTotal confirmed the destination address as Microsoft's. I documented it as ordinary traffic that happened just before the download. I don't know why it happened then.

## 8. Account and host name

`kerberos.CNameString && !(kerberos.CNameString contains "$")` lists user principals, since computer accounts end in `$`. I added `CNameString` as a column and saw the same name on every row. I confirmed the host name in three places: DHCP Option 12, the Kerberos `addresses` field, and the LLMNR query.

## 9. Enrichment, kept apart from the capture

The VirusTotal results (hash, both IP addresses, the Microsoft address) sit in their own section of the report, marked as point-in-time. Where VirusTotal and the capture disagree or say nothing, the report says that. For example, the sandbox recorded no network traffic for the executable, and VirusTotal has no recorded link between the executable and the server.

## 10. Write only what the evidence supports

I mapped techniques to ATT&CK only where the capture shows them. The report lists open items instead of closing them with guesses.
