from scapy.all import PcapReader, IP, TCP, UDP
import scapy
import pandas as pd
import argparse

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

print("Total packets read:", len(packets))
if args.count is not None:
    print("Only the first", args.count, "packets were read.")
else:
    print("All packets were read from the pcap file.")
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