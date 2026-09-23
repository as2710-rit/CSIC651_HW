from scapy.all import PcapReader, IP, TCP, UDP
import scapy
import pandas as pd
import argparse
from scapy.all import IP, IPv6, ARP


# pd.set_option('display.max_columns', None)
# pd.set_option('display.width', None)

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--pcap_file", required=True,
                     help="Input pcap file to read")
parser.add_argument("-c", "--count", type=int, default=None,
                     help="Only read the first N packets")
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


