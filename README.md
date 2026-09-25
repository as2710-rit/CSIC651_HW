# pktsniffer

A simple tcpdump-style packet sniffer built on top of [Scapy](https://scapy.net/). It reads packets from a `.pcap` file, optionally filters them using a small expression language, and prints Ethernet, IP, and transport-layer (TCP/UDP/ICMP) header information as formatted tables.

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- [pandas](https://pandas.pydata.org/)

## Code documentation

The code documentation is provided in the `pktsniffer_html/pktsniffer.html`. Please open the html only through the folder
to avoid errors with the CSS/JS components of styling and sources. This documentation is generated through Sphinx.

## Installation

No compilation step is required — this is a pure Python script. Just install the two third-party dependencies:

```bash
pip install scapy pandas
```

(If you're on a system with both Python 2 and 3, or multiple environments, use `pip3` instead of `pip` to be safe, or install inside a virtual environment:)

```bash
python3 -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install scapy pandas
```

## Running the script

The script is run from the command line with `python3`:

```bash
python3 pktsniffer.py -r <pcap_file> [-c <count>] [-n <num_matches>] [filter expression]
```

### Arguments

| Flag | Required | Description |
|---|---|---|
| `-r`, `--pcap_file` | Yes | Path to the input `.pcap` file to read. |
| `-c`, `--count` | No | Only read the first N packets from the file. If omitted, all packets are read. |
| `-n`, `--num_matches` | No | Only *display* the first N packets that match the filter. Does not affect how many packets are read from the file (that's controlled by `-c`). |
| *(filter expression)* | No | An optional tcpdump-like filter (see below). If omitted, every packet read is shown. |

### Filter expression syntax

The filter expression is a sequence of one or more **primitives**, optionally combined with `and`, `or`, and negated with `not`. It's matched case-insensitively.

```
<primitive>      := ip | tcp | udp | icmp | arp
<primitive-arg>  := port <number> | net <addr>[/<prefixlen>] | host <addr>
<clause>         := [not] (<primitive> | <primitive-arg>)
<expression>     := <clause> [(and|or) <clause>]*
```

- If no connector is written between two clauses, `and` is assumed.
- `net <addr>` without a `/<prefixlen>` defaults to a `/24`.
- Flags of count and first n display should be written with a leading dash (`-c` and `--c` both work).
- Flags for other filters like `tcp`, `udp`, `ip`, `icmp`, `port` should be used without a leading dash.
- If nothing to display, returns empty lists.

## Examples

Read and display every packet in a capture:

```bash
python3 pktsniffer.py -r test_wifi.pcap
```

Read only the first 50 packets from the file:

```bash
python3 pktsniffer.py -r test_wifi.pcap -c 50
```

Show only packets on port 80 (HTTP):

```bash
python3 pktsniffer.py -r test_wifi.pcap port 80
```

Show only top n packets returned after a filter query:

```bash
python3 pktsniffer.py -r test_wifi.pcap -n 20 port 443 
```

Show only TCP packets destined for/from port 80:

```bash
python3 pktsniffer.py -r test_wifi.pcap tcp and port 80
```

Show all UDP or ICMP packets:

```bash
python3 pktsniffer.py -r test_wifi.pcap udp or icmp
```

Show packets to/from a subnet (defaults to /24 if no prefix is given):

```bash
python3 pktsniffer.py -r test_wifi.pcap net 192.168.1.0
```

Show packets to/from a specific host:

```bash
python3 pktsniffer.py -r test_wifi.pcap host 192.168.1.15
```

Show non-TCP traffic:

```bash
python3 pktsniffer.py -r test_wifi.pcap not tcp
```

Combine reading limits, filtering, and display limits — read only the first 500 packets from the file, filter for TCP traffic on port 80, but display only the first 5 matches:

```bash
python3 pktsniffer.py -r test_wifi.pcap -c 500 -n 5 tcp and port 80
```

## Output

For each run, the script prints:

1. **Read summary** — total packets read (and whether the file was read in full or truncated by `-c`).
2. **Filter summary** — the filter applied and how many packets matched (if a filter was given).
3. **Ethernet Header Information** — packet size, destination/source MAC address, and EtherType, one row per packet.
4. **IP Header Information** — version, header length, ToS, total length, identification, flags, fragment offset, TTL, protocol, checksum, and source/destination address, for IPv4, IPv6, and ARP packets.
5. **Encapsulated Packet Header Information (TCP/UDP/ICMP)** — protocol-specific fields such as ports, sequence/ack numbers, flags, window size, checksum, and (for ICMP) type/code.
