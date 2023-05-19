

import matplotlib.pyplot as plt
from scapy.all import *
from collections import Counter
from colorama import Fore, Style



# List of control PDUs
control_pdus = ["STP", "DTP", "CDP", "ARP", "ICMP", "DNS", "DHCP"]

# List to store the type of each PDU
pdu_types = []

# Capture 500 PDUs from the network
pkts = sniff(count=500)

# Classify each PDU as "control" or "data" based on its type
for pkt in pkts:
    if pkt.haslayer(Ether):
        if pkt.type == 0x0806:
            pdu_types.append("ARP")
        elif pkt.type == 0x0800:
            if pkt.haslayer(ICMP):
                pdu_types.append("ICMP")
            elif pkt.haslayer(IP):
                if pkt.haslayer(UDP):
                    if pkt.haslayer(DHCP):
                        pdu_types.append("DHCP")
                    elif pkt.haslayer(DNS):
                        pdu_types.append("DNS")
                    else:
                        pdu_types.append("data")
                else:
                    pdu_types.append("data")
            else:
                pdu_types.append("data")
        elif pkt.type == 0x8100:
            pdu_types.append("VLAN")
        else:
            pdu_types.append("data")
    elif pkt.haslayer(LLDP):
        pdu_types.append("LLDP")
    else:
        pdu_types.append("data")

# Count the number of data and control PDUs
pdu_type_counts = Counter(pdu_types)
num_data_pdus = pdu_type_counts["data"]
num_control_pdus = sum(pdu_type_counts[pdu] for pdu in control_pdus)

# Calculate the ratio of data PDUs over control PDUs
try:
    ratio = num_data_pdus / num_control_pdus
except ZeroDivisionError:
    ratio = 1

string = "Ratio of data PDUs over control PDUs:"
print(Fore.BLUE + string, ratio)
print(Style.RESET_ALL)

# Create a pie chart showing the ratio of data PDUs over control PDUs
labels = ["Data PDUs", "Control PDUs"]
sizes = [num_data_pdus, num_control_pdus]
colors = ["orange", "lightskyblue"]
explode = (0, 0.1)

plt.pie(sizes, explode=explode, labels=labels, colors=colors,
        autopct='%1.1f%%', shadow=True, startangle=90)

plt.axis('equal')
plt.title("Ratio of Data PDUs over Control PDUs")
plt.show()
