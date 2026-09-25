from scapy.all import PcapReader, IP, TCP, UDP, ICMP
import scapy
import pandas as pd
import argparse
import ipaddress
from scapy.all import IP, IPv6, ARP


# pd.set_option('display.max_columns', None)
# pd.set_option('display.width', None)

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--pcap_file", required=True,
                     help="Input pcap file to read")
parser.add_argument("-c", "--count", type=int, default=None,
                     help="Only read the first N packets")
parser.add_argument("-n", "--num_matches", type=int, default=None,
                     help="Only show the first N packets that match the filter "
                          "(does not affect how many packets are read from the "
                          "file - that is controlled by -c)")
# Everything after -r/-c/-n is treated as a tcpdump-style filter expression, e.g.:
#   pktsniffer -r file.pcap port 80
#   pktsniffer -r file.pcap tcp and port 80
#   pktsniffer -r file.pcap net 192.168.1.0
#   pktsniffer -r file.pcap udp or icmp
#   pktsniffer -r file.pcap -n 5 tcp and port 80   (scans whole file, shows first 5 matches)
# argparse.REMAINDER is used (instead of nargs='*') so that tokens starting
# with a dash (e.g. "-net 192.168.1.0", as shown in some examples) are still
# captured as part of the filter instead of being rejected as unknown flags.
parser.add_argument("expression", nargs=argparse.REMAINDER,
                     help="Optional tcpdump-like filter expression "
                          "(port <n> | ip | tcp | udp | icmp | net <addr>[/<prefix>], "
                          "combinable with 'and' / 'or' / 'not')")
args = parser.parse_args()

packets = []
with PcapReader(args.pcap_file) as pcap_reader:
    for i, packet in enumerate(pcap_reader):
        if args.count is not None and i >= args.count:
            break
        packets.append(packet)

print("\n Total packets read:", len(packets))
if args.count is not None:
    print("\n Only the first", args.count, "packets were read.")
else:
    print("All packets were read from the pcap file.")


# ---------------------------------------------------------------------------
# Filtering (tcpdump-style: port / ip / tcp / udp / icmp / net)
# ---------------------------------------------------------------------------

SUPPORTED_PRIMITIVES = {"ip", "tcp", "udp", "icmp", "arp"}
PRIMITIVES_WITH_ARG = {"port", "net", "host"}


def normalize_tokens(raw_tokens):
    """Strip a leading '-' or '--' from filter keywords so that both
    'net 192.168.1.0' and '-net 192.168.1.0' style usage are accepted."""
    normalized = []
    for tok in raw_tokens:
        stripped = tok.lstrip("-")
        keyword = stripped.lower()
        if keyword in SUPPORTED_PRIMITIVES or keyword in PRIMITIVES_WITH_ARG or keyword in ("and", "or", "not"):
            normalized.append(stripped)
        else:
            normalized.append(tok)
    return normalized


def parse_filter_tokens(tokens):
    """Parse a flat list of filter tokens into a list of clause dicts.

    Grammar supported (case-insensitive):
        <primitive>        := ip | tcp | udp | icmp | arp
        <primitive-arg>     := port <number> | net <addr>[/<prefixlen>] | host <addr>
        <clause>            := [not] (<primitive> | <primitive-arg>)
        <expression>        := <clause> [(and|or) <clause>]*

    Clauses are combined left-to-right using the connector that precedes
    them; if no connector is given between two clauses, 'and' is assumed
    (this mirrors how most simple pcap-filter expressions are written).
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
                raise ValueError("Filter expression ends with a dangling 'not'")
            tok = tokens[i].lower()

        if tok in SUPPORTED_PRIMITIVES:
            clauses.append({"connector": connector, "negate": negate,
                             "type": tok, "value": None})
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
            clauses.append({"connector": connector, "negate": negate,
                             "type": tok, "value": value})
            i += 1
        else:
            raise ValueError(f"Unsupported filter token: '{tokens[i]}'")

        connector = None

    return clauses


def _get_ip_addrs(pkt):
    """Return (src, dst) IP-like addresses for IPv4, IPv6 or ARP packets."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    if ARP in pkt:
        return pkt[ARP].psrc, pkt[ARP].pdst
    return None, None


def match_net(pkt, net_str):
    if "/" not in net_str:
        # No prefix length given: default to a /24, a reasonable assumption
        # for typical IPv4 "net" filters used in this assignment.
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
    src, dst = _get_ip_addrs(pkt)
    return host_str in (src, dst)


def match_port(pkt, port_num):
    if TCP in pkt:
        return pkt[TCP].sport == port_num or pkt[TCP].dport == port_num
    if UDP in pkt:
        return pkt[UDP].sport == port_num or pkt[UDP].dport == port_num
    return False


def eval_clause(pkt, clause):
    ctype = clause["type"]
    value = clause["value"]

    if ctype == "ip":
        result = IP in pkt
    elif ctype == "tcp":
        result = TCP in pkt
    elif ctype == "udp":
        result = UDP in pkt
    elif ctype == "icmp":
        result = ICMP in pkt
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


filter_tokens = normalize_tokens(args.expression)
try:
    filter_clauses = parse_filter_tokens(filter_tokens)
except ValueError as exc:
    parser.error(str(exc))

if filter_clauses:
    packets = [pkt for pkt in packets if matches_filter(pkt, filter_clauses)]
    print("\n Filter applied:", " ".join(filter_tokens))
    print(" Packets matching filter:", len(packets))

if args.num_matches is not None:
    total_matches = len(packets)
    packets = packets[:args.num_matches]
    if total_matches > len(packets):
        print(f" Showing only the first {args.num_matches} matching packets "
              f"(of {total_matches} total matches).")


print("\n Ethernet Header Information: \n")
temp_dict = {"packet_size_bytes": [], "destination_mac_address": [], "source_mac_address": [], "ether_type": []}
for pkt in packets:
    packet_size = len(pkt)
    destination_mac_address = pkt["Ether"].dst if "Ether" in pkt else None
    source_mac_address = pkt["Ether"].src if "Ether" in pkt else None
    ether_type = scapy.layers.l2.ETHER_TYPES[pkt["Ether"].type] if "Ether" in pkt else None

    temp_dict["packet_size_bytes"].append(packet_size)
    temp_dict["destination_mac_address"].append(destination_mac_address)
    temp_dict["source_mac_address"].append(source_mac_address)
    temp_dict["ether_type"].append(ether_type)
print(pd.DataFrame(temp_dict))


# IP Header Information
print("\n IP Header Information: \n")
ip_temp_dict = {"version": [], "header_length_bytes": [], "Type of Service": [], "total_length_bytes": [], "identification": [], "flags": [], "fragment_offset": [], "time_to_live": [], "protocol": [], "header_checksum": [], "source_ip_address": [], "destination_ip_address": []}

for pkt in packets:
    if IP in pkt:
        ip_layer = pkt[IP]
        ip_temp_dict["version"].append(ip_layer.version)
        ip_temp_dict["header_length_bytes"].append(ip_layer.ihl * 4)
        ip_temp_dict["Type of Service"].append(ip_layer.tos)
        ip_temp_dict["total_length_bytes"].append(ip_layer.len)
        ip_temp_dict["identification"].append(ip_layer.id)
        ip_temp_dict["flags"].append(ip_layer.flags)
        ip_temp_dict["fragment_offset"].append(ip_layer.frag)
        ip_temp_dict["time_to_live"].append(ip_layer.ttl)
        ip_temp_dict["protocol"].append(IP(proto=ip_layer.proto).sprintf("%IP.proto%"))
        ip_temp_dict["header_checksum"].append(ip_layer.chksum)
        ip_temp_dict["source_ip_address"].append(ip_layer.src)
        ip_temp_dict["destination_ip_address"].append(ip_layer.dst)
    elif IPv6 in pkt:
        ipv6_layer = pkt[IPv6]
        ip_temp_dict["version"].append(ipv6_layer.version)
        ip_temp_dict["header_length_bytes"].append(40)  # IPv6 header is always fixed at 40 bytes
        ip_temp_dict["Type of Service"].append(ipv6_layer.tc)
        ip_temp_dict["total_length_bytes"].append(ipv6_layer.plen + 40)  # payload + fixed header
        ip_temp_dict["identification"].append(None)  # IPv6 does not have an identification field
        ip_temp_dict["flags"].append(None)  # IPv6 does not have flags
        ip_temp_dict["fragment_offset"].append(None)  # IPv6 does not have fragment offset
        ip_temp_dict["time_to_live"].append(ipv6_layer.hlim)
        ip_temp_dict["protocol"].append(IP(proto=ipv6_layer.nh).sprintf("%IP.proto%"))
        ip_temp_dict["header_checksum"].append(None)  # IPv6 does not have a header checksum
        ip_temp_dict["source_ip_address"].append(ipv6_layer.src)
        ip_temp_dict["destination_ip_address"].append(ipv6_layer.dst)
    elif ARP in pkt:
        arp_layer = pkt[ARP]
        ip_temp_dict["version"].append(None)              # ARP has no IP version
        ip_temp_dict["header_length_bytes"].append(None)  # ARP has no IP header
        ip_temp_dict["Type of Service"].append(None)
        ip_temp_dict["total_length_bytes"].append(None)
        ip_temp_dict["identification"].append(None)
        ip_temp_dict["flags"].append(None)
        ip_temp_dict["fragment_offset"].append(None)
        ip_temp_dict["time_to_live"].append(None)
        ip_temp_dict["protocol"].append("arp")
        ip_temp_dict["header_checksum"].append(None)
        ip_temp_dict["source_ip_address"].append(arp_layer.psrc)  # sender IP (from ARP payload)
        ip_temp_dict["destination_ip_address"].append(arp_layer.pdst)  # target IP (from ARP payload)

ip_df = pd.DataFrame(ip_temp_dict)

int_columns = ["version", "header_length_bytes", "Type of Service", "total_length_bytes",
               "identification", "fragment_offset", "time_to_live", "header_checksum"]

for col in int_columns:
    ip_df[col] = ip_df[col].astype("Int64")

print(ip_df)


# Encapsulated (TCP / UDP / ICMP) Header Information
print("\n Encapsulated Packet Header Information (TCP / UDP / ICMP): \n")
trans_temp_dict = {
    "protocol": [], "source_port": [], "destination_port": [],
    "sequence_number": [], "acknowledgment_number": [], "header_length_bytes": [],
    "flags": [], "window_size": [], "checksum": [], "urgent_pointer": [],
    "length_bytes": [], "icmp_type": [], "icmp_code": [],
}

for pkt in packets:
    if TCP in pkt:
        tcp_layer = pkt[TCP]
        trans_temp_dict["protocol"].append("tcp")
        trans_temp_dict["source_port"].append(tcp_layer.sport)
        trans_temp_dict["destination_port"].append(tcp_layer.dport)
        trans_temp_dict["sequence_number"].append(tcp_layer.seq)
        trans_temp_dict["acknowledgment_number"].append(tcp_layer.ack)
        trans_temp_dict["header_length_bytes"].append(tcp_layer.dataofs * 4 if tcp_layer.dataofs else None)
        trans_temp_dict["flags"].append(str(tcp_layer.flags))
        trans_temp_dict["window_size"].append(tcp_layer.window)
        trans_temp_dict["checksum"].append(tcp_layer.chksum)
        trans_temp_dict["urgent_pointer"].append(tcp_layer.urgptr)
        trans_temp_dict["length_bytes"].append(None)
        trans_temp_dict["icmp_type"].append(None)
        trans_temp_dict["icmp_code"].append(None)
    elif UDP in pkt:
        udp_layer = pkt[UDP]
        trans_temp_dict["protocol"].append("udp")
        trans_temp_dict["source_port"].append(udp_layer.sport)
        trans_temp_dict["destination_port"].append(udp_layer.dport)
        trans_temp_dict["sequence_number"].append(None)
        trans_temp_dict["acknowledgment_number"].append(None)
        trans_temp_dict["header_length_bytes"].append(8)  # UDP header is always fixed at 8 bytes
        trans_temp_dict["flags"].append(None)
        trans_temp_dict["window_size"].append(None)
        trans_temp_dict["checksum"].append(udp_layer.chksum)
        trans_temp_dict["urgent_pointer"].append(None)
        trans_temp_dict["length_bytes"].append(udp_layer.len)
        trans_temp_dict["icmp_type"].append(None)
        trans_temp_dict["icmp_code"].append(None)
    elif ICMP in pkt:
        icmp_layer = pkt[ICMP]
        trans_temp_dict["protocol"].append("icmp")
        trans_temp_dict["source_port"].append(None)
        trans_temp_dict["destination_port"].append(None)
        trans_temp_dict["sequence_number"].append(getattr(icmp_layer, "seq", None))
        trans_temp_dict["acknowledgment_number"].append(None)
        trans_temp_dict["header_length_bytes"].append(None)
        trans_temp_dict["flags"].append(None)
        trans_temp_dict["window_size"].append(None)
        trans_temp_dict["checksum"].append(icmp_layer.chksum)
        trans_temp_dict["urgent_pointer"].append(None)
        trans_temp_dict["length_bytes"].append(None)
        trans_temp_dict["icmp_type"].append(icmp_layer.type)
        trans_temp_dict["icmp_code"].append(icmp_layer.code)

trans_df = pd.DataFrame(trans_temp_dict)

trans_int_columns = ["source_port", "destination_port", "sequence_number",
                      "acknowledgment_number", "header_length_bytes", "window_size",
                      "checksum", "urgent_pointer", "length_bytes", "icmp_type", "icmp_code"]

for col in trans_int_columns:
    trans_df[col] = trans_df[col].astype("Int64")

with pd.option_context("display.max_columns", None, "display.width", None):
    print(trans_df)
