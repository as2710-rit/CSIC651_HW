"""A simple packet sniffer built on top of Scapy.

Reads packets from a pcap file, optionally filters them using a small
tcpdump-like expression language (port / ip / tcp / udp / icmp / arp /
net / host, combinable with 'and', 'or', and 'not'), and prints Ethernet,
IP, and transport-layer (TCP/UDP/ICMP/ICMPv6) header information as
pandas DataFrames.
"""
import argparse
import ipaddress

import pandas as pd
import scapy
from scapy.all import (
    ARP,
    ICMP,
    ICMPv6DestUnreach,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6PacketTooBig,
    ICMPv6TimeExceeded,
    IP,
    IPv6,
    PcapReader,
    TCP,
    UDP,
)

SUPPORTED_PRIMITIVES = {"ip", "tcp", "udp", "icmp", "arp"}
PRIMITIVES_WITH_ARG = {"port", "net", "host"}

# The specific ICMPv6 message types this script recognizes. Used so that
# the 'icmp' filter primitive matches ICMPv6 packets too, not just ICMP
# (v4) ones.
ICMPV6_MESSAGE_TYPES = (
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6ND_RS,
    ICMPv6ND_RA,
    ICMPv6DestUnreach,
    ICMPv6PacketTooBig,
    ICMPv6TimeExceeded,
)


def is_icmp(pkt):
    """Return True if `pkt` is an ICMP (v4) or a recognized ICMPv6 packet."""
    if ICMP in pkt:
        return True
    return any(cls in pkt for cls in ICMPV6_MESSAGE_TYPES)


def build_arg_parser():
    """Build and return the command-line argument parser."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-r", "--pcap_file", required=True,
        help="Input pcap file to read",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=None,
        help="Only read the first N packets",
    )
    parser.add_argument(
        "-n", "--num_matches", type=int, default=None,
        help="Only show the first N packets that match the filter "
             "(does not affect how many packets are read from the "
             "file - that is controlled by -c)",
    )
    # Everything after -r/-c/-n is treated as a tcpdump-style filter
    # expression, e.g.:
    #   pktsniffer -r file.pcap port 80
    #   pktsniffer -r file.pcap tcp and port 80
    #   pktsniffer -r file.pcap net 192.168.1.0
    #   pktsniffer -r file.pcap udp or icmp
    #   pktsniffer -r file.pcap -n 5 tcp and port 80
    # argparse.REMAINDER is used (instead of nargs='*') so that tokens
    # starting with a dash (e.g. "-host 192.168.1.0", as shown in some
    # examples) are still captured as part of the filter instead of
    # being rejected as unknown flags.
    parser.add_argument(
        "expression", nargs=argparse.REMAINDER,
        help="Optional tcpdump-like filter expression "
             "(port <n> | ip | tcp | udp | icmp | "
             "net <addr>[/<prefix>], combinable with 'and' / 'or' / "
             "'not')",
    )
    return parser


def read_packets(pcap_file, count=None):
    """Read up to `count` packets from `pcap_file` (all, if None)."""
    packets = []
    with PcapReader(pcap_file) as pcap_reader:
        for i, packet in enumerate(pcap_reader):
            if count is not None and i >= count:
                break
            packets.append(packet)
    return packets


# ---------------------------------------------------------------------------
# Filtering Arguments (-c or --c)
# ---------------------------------------------------------------------------
def normalize_tokens(raw_tokens):
    """Strip a leading '-' or '--' from filter arguments for c and n.
    c - read only the first N packets from the pcap file
    n - show only the first N packets that match the filter expression

    This allows both '-c' and '--c' style
    usage to be accepted.
    """
    normalized = []
    for tok in raw_tokens:
        stripped = tok.lstrip("-")
        keyword = stripped.lower()
        is_known_keyword = (
            keyword in SUPPORTED_PRIMITIVES
            or keyword in PRIMITIVES_WITH_ARG
            or keyword in ("and", "or", "not")
        )
        normalized.append(stripped if is_known_keyword else tok)
    return normalized


def parse_filter_tokens(tokens):
    """Parse a flat list of filter tokens into a list of clause dicts.

    Grammar supported (case-insensitive):

    .. code-block:: text

        <primitive>      := ip | tcp | udp | icmp | arp
        <primitive-arg>  := port <number> | net <addr>[/<prefixlen>] | host <addr>
        <clause>         := [not] (<primitive> | <primitive-arg>)
        <expression>     := <clause> [(and|or) <clause>]*

    Clauses are combined left-to-right using the connector that
    precedes them; if no connector is given between two clauses,
    'and' is assumed (this mirrors how most simple pcap-filter
    expressions are written).
    """
    clauses = []
    connector = None
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i].lower()

        if tok in ("and", "or"):
            connector = tok
            i += 1
            continue

        negate = False
        if tok == "not":
            negate = True
            i += 1
            if i >= n:
                raise ValueError(
                    "Filter expression ends with a dangling 'not'")
            tok = tokens[i].lower()

        if tok in SUPPORTED_PRIMITIVES:
            clauses.append({
                "connector": connector, "negate": negate,
                "type": tok, "value": None,
            })
            i += 1
        elif tok in PRIMITIVES_WITH_ARG:
            i += 1
            if i >= n:
                raise ValueError(f"Filter primitive '{tok}' requires a value")
            value = tokens[i]
            if tok == "port":
                try:
                    value = int(value)
                except ValueError:
                    raise ValueError(f"'port' expects a number, got '{value}'")
            clauses.append({
                "connector": connector, "negate": negate,
                "type": tok, "value": value,
            })
            i += 1
        else:
            raise ValueError(f"Unsupported filter token: '{tokens[i]}'")

        connector = None

    return clauses


def _get_ip_addrs(pkt):
    """Return (src, dst) IP-like addresses for IPv4, IPv6, or ARP packets."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    if ARP in pkt:
        return pkt[ARP].psrc, pkt[ARP].pdst
    return None, None


def match_net(pkt, net_str):
    """Return True if either endpoint of `pkt` falls within `net_str`."""
    if "/" not in net_str:
        # No prefix length given: default to a /24, a reasonable
        # assumption for typical IPv4 "net" filters used in this
        # assignment.
        net_str = net_str + "/24"
    try:
        network = ipaddress.ip_network(net_str, strict=False)
    except ValueError:
        return False

    src, dst = _get_ip_addrs(pkt)
    for addr in (src, dst):
        if addr is None:
            continue
        try:
            if ipaddress.ip_address(addr) in network:
                return True
        except ValueError:
            continue
    return False


def match_host(pkt, host_str):
    """Return True if `host_str` matches the source or destination of pkt."""
    src, dst = _get_ip_addrs(pkt)
    return host_str in (src, dst)


def match_port(pkt, port_num):
    """Return True if `port_num` matches the source or destination port."""
    if TCP in pkt:
        return pkt[TCP].sport == port_num or pkt[TCP].dport == port_num
    if UDP in pkt:
        return pkt[UDP].sport == port_num or pkt[UDP].dport == port_num
    return False


def eval_clause(pkt, clause):
    """Evaluate a single filter clause dict against a packet."""
    ctype = clause["type"]
    value = clause["value"]

    if ctype == "ip":
        result = IP in pkt
    elif ctype == "tcp":
        result = TCP in pkt
    elif ctype == "udp":
        result = UDP in pkt
    elif ctype == "icmp":
        result = is_icmp(pkt)
    elif ctype == "arp":
        result = ARP in pkt
    elif ctype == "port":
        result = match_port(pkt, value)
    elif ctype == "net":
        result = match_net(pkt, value)
    elif ctype == "host":
        result = match_host(pkt, value)
    else:
        result = False

    if clause["negate"]:
        result = not result
    return result


def matches_filter(pkt, clauses):
    """Return True if `pkt` satisfies the parsed filter `clauses`."""
    if not clauses:
        return True
    result = eval_clause(pkt, clauses[0])
    for clause in clauses[1:]:
        r = eval_clause(pkt, clause)
        if clause["connector"] == "or":
            result = result or r
        else:  # default connector is 'and'
            result = result and r
    return result


# ---------------------------------------------------------------------------
# Header extraction / reporting
# ---------------------------------------------------------------------------
def build_ethernet_dataframe(packets):
    """Build a DataFrame of Ethernet header fields for `packets`."""
    data = {
        "packet_size_bytes": [],
        "destination_mac_address": [],
        "source_mac_address": [],
        "ether_type": [],
    }
    for pkt in packets:
        has_ether = "Ether" in pkt
        data["packet_size_bytes"].append(len(pkt))
        data["destination_mac_address"].append(
            pkt["Ether"].dst if has_ether else None)
        data["source_mac_address"].append(
            pkt["Ether"].src if has_ether else None)
        data["ether_type"].append(
            scapy.layers.l2.ETHER_TYPES[pkt["Ether"].type]
            if has_ether else None)
    return pd.DataFrame(data)


def build_ip_dataframe(packets):
    """Build a DataFrame of IPv4 / IPv6 / ARP header fields for `packets`."""
    data = {
        "version": [], "header_length_bytes": [], "Type of Service": [],
        "total_length_bytes": [], "identification": [], "flags": [],
        "fragment_offset": [], "time_to_live": [], "protocol": [],
        "header_checksum": [], "source_ip_address": [],
        "destination_ip_address": [],
    }

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            data["version"].append(ip_layer.version)
            data["header_length_bytes"].append(ip_layer.ihl * 4)
            data["Type of Service"].append(ip_layer.tos)
            data["total_length_bytes"].append(ip_layer.len)
            data["identification"].append(ip_layer.id)
            data["flags"].append(ip_layer.flags)
            data["fragment_offset"].append(ip_layer.frag)
            data["time_to_live"].append(ip_layer.ttl)
            data["protocol"].append(
                IP(proto=ip_layer.proto).sprintf("%IP.proto%"))
            data["header_checksum"].append(ip_layer.chksum)
            data["source_ip_address"].append(ip_layer.src)
            data["destination_ip_address"].append(ip_layer.dst)
        elif IPv6 in pkt:
            ipv6_layer = pkt[IPv6]
            data["version"].append(ipv6_layer.version)
            # IPv6 header is always fixed at 40 bytes.
            data["header_length_bytes"].append(40)
            data["Type of Service"].append(ipv6_layer.tc)
            # Total length = payload + fixed header.
            data["total_length_bytes"].append(ipv6_layer.plen + 40)
            data["identification"].append(None)  # No such field in IPv6.
            data["flags"].append(None)  # No such field in IPv6.
            data["fragment_offset"].append(None)  # No such field in IPv6.
            data["time_to_live"].append(ipv6_layer.hlim)
            data["protocol"].append(
                IP(proto=ipv6_layer.nh).sprintf("%IP.proto%"))
            data["header_checksum"].append(None)  # No such field in IPv6.
            data["source_ip_address"].append(ipv6_layer.src)
            data["destination_ip_address"].append(ipv6_layer.dst)
        elif ARP in pkt:
            arp_layer = pkt[ARP]
            data["version"].append(None)  # ARP has no IP version.
            data["header_length_bytes"].append(None)  # No IP header.
            data["Type of Service"].append(None)
            data["total_length_bytes"].append(None)
            data["identification"].append(None)
            data["flags"].append(None)
            data["fragment_offset"].append(None)
            data["time_to_live"].append(None)
            data["protocol"].append("arp")
            data["header_checksum"].append(None)
            data["source_ip_address"].append(arp_layer.psrc)
            data["destination_ip_address"].append(arp_layer.pdst)

    ip_df = pd.DataFrame(data)
    int_columns = [
        "version", "header_length_bytes", "Type of Service",
        "total_length_bytes", "identification", "fragment_offset",
        "time_to_live", "header_checksum",
    ]
    for col in int_columns:
        ip_df[col] = ip_df[col].astype("Int64")
    return ip_df


def build_transport_dataframe(packets):
    """Build a DataFrame of TCP/UDP/ICMP/ICMPv6 header fields for packets."""
    data = {
        "protocol": [], "source_port": [], "destination_port": [],
        "sequence_number": [], "acknowledgment_number": [],
        "header_length_bytes": [], "flags": [], "window_size": [],
        "checksum": [], "urgent_pointer": [], "length_bytes": [],
        "icmp_type": [], "icmp_code": [],
    }

    for pkt in packets:
        if TCP in pkt:
            tcp_layer = pkt[TCP]
            data["protocol"].append("tcp")
            data["source_port"].append(tcp_layer.sport)
            data["destination_port"].append(tcp_layer.dport)
            data["sequence_number"].append(tcp_layer.seq)
            data["acknowledgment_number"].append(tcp_layer.ack)
            data["header_length_bytes"].append(
                tcp_layer.dataofs * 4 if tcp_layer.dataofs else None)
            data["flags"].append(str(tcp_layer.flags))
            data["window_size"].append(tcp_layer.window)
            data["checksum"].append(tcp_layer.chksum)
            data["urgent_pointer"].append(tcp_layer.urgptr)
            data["length_bytes"].append(None)
            data["icmp_type"].append(None)
            data["icmp_code"].append(None)
        elif UDP in pkt:
            udp_layer = pkt[UDP]
            data["protocol"].append("udp")
            data["source_port"].append(udp_layer.sport)
            data["destination_port"].append(udp_layer.dport)
            data["sequence_number"].append(None)
            data["acknowledgment_number"].append(None)
            # UDP header is always fixed at 8 bytes.
            data["header_length_bytes"].append(8)
            data["flags"].append(None)
            data["window_size"].append(None)
            data["checksum"].append(udp_layer.chksum)
            data["urgent_pointer"].append(None)
            data["length_bytes"].append(udp_layer.len)
            data["icmp_type"].append(None)
            data["icmp_code"].append(None)
        elif ICMP in pkt:
            icmp_layer = pkt[ICMP]
            data["protocol"].append("icmp")
            data["source_port"].append(None)
            data["destination_port"].append(None)
            data["sequence_number"].append(getattr(icmp_layer, "seq", None))
            data["acknowledgment_number"].append(None)
            data["header_length_bytes"].append(None)
            data["flags"].append(None)
            data["window_size"].append(None)
            data["checksum"].append(icmp_layer.chksum)
            data["urgent_pointer"].append(None)
            data["length_bytes"].append(None)
            data["icmp_type"].append(icmp_layer.type)
            data["icmp_code"].append(icmp_layer.code)
        elif ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
            icmp6_layer = (
                pkt[ICMPv6EchoRequest] if ICMPv6EchoRequest in pkt
                else pkt[ICMPv6EchoReply]
            )
            data["protocol"].append("icmpv6")
            data["source_port"].append(None)
            data["destination_port"].append(None)
            data["sequence_number"].append(getattr(icmp6_layer, "seq", None))
            data["acknowledgment_number"].append(None)
            data["header_length_bytes"].append(None)
            data["flags"].append(None)
            data["window_size"].append(None)
            data["checksum"].append(icmp6_layer.cksum)
            data["urgent_pointer"].append(None)
            data["length_bytes"].append(None)
            data["icmp_type"].append(icmp6_layer.type)
            data["icmp_code"].append(icmp6_layer.code)
        elif ICMPv6ND_NS in pkt or ICMPv6ND_NA in pkt:
            icmp6_layer = (
                pkt[ICMPv6ND_NS] if ICMPv6ND_NS in pkt else pkt[ICMPv6ND_NA]
            )
            data["protocol"].append("icmpv6")
            data["source_port"].append(None)
            data["destination_port"].append(None)
            data["sequence_number"].append(None)  # ND messages have no seq.
            data["acknowledgment_number"].append(None)
            data["header_length_bytes"].append(None)
            data["flags"].append(None)
            data["window_size"].append(None)
            data["checksum"].append(icmp6_layer.cksum)
            data["urgent_pointer"].append(None)
            data["length_bytes"].append(None)
            data["icmp_type"].append(icmp6_layer.type)
            data["icmp_code"].append(icmp6_layer.code)
        elif ICMPv6ND_RS in pkt or ICMPv6ND_RA in pkt:
            icmp6_layer = (
                pkt[ICMPv6ND_RS] if ICMPv6ND_RS in pkt else pkt[ICMPv6ND_RA]
            )
            data["protocol"].append("icmpv6")
            data["source_port"].append(None)
            data["destination_port"].append(None)
            data["sequence_number"].append(None)  # RS/RA have no seq.
            data["acknowledgment_number"].append(None)
            data["header_length_bytes"].append(None)
            data["flags"].append(None)
            data["window_size"].append(None)
            data["checksum"].append(icmp6_layer.cksum)
            data["urgent_pointer"].append(None)
            data["length_bytes"].append(None)
            data["icmp_type"].append(icmp6_layer.type)
            data["icmp_code"].append(icmp6_layer.code)
        elif (ICMPv6DestUnreach in pkt or ICMPv6PacketTooBig in pkt
              or ICMPv6TimeExceeded in pkt):
            if ICMPv6DestUnreach in pkt:
                icmp6_layer = pkt[ICMPv6DestUnreach]
            elif ICMPv6PacketTooBig in pkt:
                icmp6_layer = pkt[ICMPv6PacketTooBig]
            else:
                icmp6_layer = pkt[ICMPv6TimeExceeded]
            data["protocol"].append("icmpv6")
            data["source_port"].append(None)
            data["destination_port"].append(None)
            data["sequence_number"].append(None)  # Error msgs have no seq.
            data["acknowledgment_number"].append(None)
            data["header_length_bytes"].append(None)
            data["flags"].append(None)
            data["window_size"].append(None)
            data["checksum"].append(icmp6_layer.cksum)
            data["urgent_pointer"].append(None)
            data["length_bytes"].append(None)
            data["icmp_type"].append(icmp6_layer.type)
            data["icmp_code"].append(icmp6_layer.code)

    trans_df = pd.DataFrame(data)
    int_columns = [
        "source_port", "destination_port", "sequence_number",
        "acknowledgment_number", "header_length_bytes", "window_size",
        "checksum", "urgent_pointer", "length_bytes", "icmp_type",
        "icmp_code",
    ]
    for col in int_columns:
        trans_df[col] = trans_df[col].astype("Int64")
    return trans_df


def main():
    """Entry point: parse args, read, filter, and print packet headers."""
    args = build_arg_parser().parse_args()

    packets = read_packets(args.pcap_file, args.count)

    print("\n Total packets read:", len(packets))
    if args.count is not None:
        print("\n Only the first", args.count, "packets were read.")
    else:
        print("All packets were read from the pcap file.")

    filter_tokens = normalize_tokens(args.expression)
    try:
        filter_clauses = parse_filter_tokens(filter_tokens)
    except ValueError as exc:
        build_arg_parser().error(str(exc))
        return  # pragma: no cover - parser.error() exits the process.

    if filter_clauses:
        packets = [
            pkt for pkt in packets if matches_filter(pkt, filter_clauses)
        ]
        print("\n Filter applied:", " ".join(filter_tokens))
        print(" Packets matching filter:", len(packets))

    if args.num_matches is not None:
        total_matches = len(packets)
        packets = packets[:args.num_matches]
        if total_matches > len(packets):
            print(
                f" Showing only the first {args.num_matches} matching "
                f"packets (of {total_matches} total matches)."
            )

    print("\n Ethernet Header Information: \n")
    print(build_ethernet_dataframe(packets))

    print("\n IP Header Information: \n")
    print(build_ip_dataframe(packets))

    print("\n Encapsulated Packet Header Information "
          "(TCP / UDP / ICMP / ICMPv6): \n")
    with pd.option_context("display.max_columns", None, "display.width", None):
        print(build_transport_dataframe(packets))


if __name__ == "__main__":
    main()