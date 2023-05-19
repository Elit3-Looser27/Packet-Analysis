from scapy.all import *
import time
import ipaddress
import socket
from prettytable import PrettyTable


def ethernet_packet(packet):
    # Check if the packet is a valid Ethernet packet
    if not packet.haslayer(Ether):
        print('Invalid Ethernet packet')
        return

    # Extract Ethernet header information
    eth_src = packet[Ether].src
    eth_dst = packet[Ether].dst
    eth_type = packet[Ether].type
    eth_size = len(packet)

    # Determine if packet is unicast, multicast, or broadcast
    if eth_dst == 'ff:ff:ff:ff:ff:ff':
        packet_type = 'Broadcast'
        local_address = get_if_addr(conf.iface)
        broadcast_address = '.'.join(local_address.split('.')[:3] + ['255'])
        network_id = '.'.join(local_address.split('.')[:3] + ['0'])
    elif (int(eth_dst.split(':')[0], 16) & 1) == 1:
        packet_type = 'Multicast'
        broadcast_address = eth_dst
        network_id = '.'.join(get_if_addr(conf.iface).split('.')[:3] + ['0'])
    else:
        packet_type = 'Unicast'
        broadcast_address = None
        network_id = '.'.join(get_if_addr(conf.iface).split('.')[:3] + ['0'])

    # Print packet information
    print(f'Ethernet Packet ({packet_type})')
    print(f'\tSource: {eth_src}')
    print(f'\tDestination: {eth_dst}')
    print(f'\tType: 0x{eth_type:04x}')
    print(f'\tSize: {eth_size} bytes')
    print(f'\tBroadcast Address: {broadcast_address}')
    print(f'\tNetwork ID: {network_id}\n')
    return [eth_src, eth_dst]

def ip_packet(packet):
    # Check if the packet is a valid IP packet
    if not packet.haslayer(IP):
        print('Invalid IP packet')
        return

    # Extract IP header information
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    ip_proto = packet[IP].proto
    ip_size = len(packet[IP])
    ip_ttl = packet[IP].ttl
    # Get IP address and mac address of your device
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    ip = IPAddr
    proc = subprocess.Popen('ipconfig', stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if ip.encode() in line:
            line = proc.stdout.readline()
            break
    mask = line.rstrip().split(b':')[+1].replace(b' ', b'').decode()
    # Calculating broadcast ip and network ID
    net = ipaddress.IPv4Network(ip_src + '/' + mask, False)
    network = ipaddress.IPv4Network(f'{ip_src}/{mask}', strict=False)

# Give the IP packet version IPV4 or IPV6
    def get_ip_packet_type(packet):
        if IP in packet:
            if packet[IP].version == 4:
                return "IPv4"
            elif packet[IP].version == 6:
                return "IPv6"
            return "Unknown"

    # Determines If the packet is unicast, multicast, or broadcast
    if ip_dst == '255.255.255.255':
        packet_type = 'Broadcast'
        broadcast_address = ip_dst
        network_id = '.'.join(get_if_addr(conf.iface).split('.')[:3] + ['0'])
    elif ip_dst.startswith('224.'):
        packet_type = 'Multicast'
        local_address = get_if_addr(conf.iface)
        broadcast_address = '.'.join(local_address.split('.')[:3] + ['255'])
        network_id = '.'.join(local_address.split('.')[:3] + ['0'])
    else:
        packet_type = 'Unicast'
        broadcast_address = None
        network_id = '.'.join(ip_dst.split('.')[:3] + ['0'])

    # Determine if source and destination IP addresses are public or private
    def is_private_ip(ip_addr):
        ip_octets = ip_addr.split('.')
        return (ip_octets[0] == '10') or \
               (ip_octets[0] == '172' and 16 <= int(ip_octets[1]) <= 31) or \
               (ip_octets[0] == '192' and ip_octets[1] == '168')

    src_ip_type = 'Private' if is_private_ip(ip_src) else 'Public'
    dst_ip_type = 'Private' if is_private_ip(ip_dst) else 'Public'

    # Print packet information
    print(f'\t IP Packet ({packet_type})')
    print(f'\t Source: {ip_src} ({src_ip_type})')
    print(f'\t Destination: {ip_dst} ({dst_ip_type})')
    print(f'\t Protocol: {ip_proto}')
    print(f'\t Size: {ip_size} bytes')
    print(f'\t TTL: {ip_ttl}')
    print(f'\t Broadcast Address: {broadcast_address}')
    print(f'\t Network ID: {network_id}\n')
    print(f'\t Your Device Name is: {hostname}')
    print(f'\t Your subnet mask is: {mask}')
    print(f'\t Your Device virtual box IP Address is: {IPAddr}')
    print(f'\t Broadcast IP: {net.broadcast_address}')
    print(f'\t Network ID: {network.network_address}')
    print(f'\t IP version: {get_ip_packet_type(packet)}')
    return [ip_src, ip_dst, get_ip_packet_type(packet)]
# Classifies ports
def classify_application(port):
    # Well-known ports
    if port == 20:
        return 'FTP Data'
    elif port == 21:
        return 'FTP Control'
    elif port == 22:
        return 'SSH'
    elif port == 23:
        return 'Telnet'
    elif port == 25:
        return 'SMTP'
    elif port == 53:
        return 'DNS'
    elif port == 80:
        return 'HTTP'
    elif port == 110:
        return 'POP3'
    elif port == 119:
        return 'NNTP'
    elif port == 123:
        return 'NTP'
    elif port == 143:
        return 'IMAP'
    elif port == 161:
        return 'SNMP'
    elif port == 179:
        return 'BGP'
    elif port == 443:
        return 'HTTPS'
    elif port == 465:
        return 'SMTPS'
    elif port == 514:
        return 'Syslog'
    elif port == 515:
        return 'LPD/LPR'
    elif port == 587:
        return 'SMTP (Submission)'
    elif port == 873:
        return 'rsync'
    elif port == 990:
        return 'FTPS'
    elif port == 993:
        return 'IMAPS'
    elif port == 995:
        return 'POP3S'
    elif port == 1080:
        return 'SOCKS Proxy'
    elif port == 1194:
        return 'OpenVPN'
    elif port == 1433:
        return 'Microsoft SQL Server'
    elif port == 1434:
        return 'Microsoft SQL Monitor'
    elif port == 1521:
        return 'Oracle SQL'
    elif port == 1701:
        return 'L2TP'
    elif port == 1723:
        return 'PPTP'
    elif port == 3306:
        return 'MySQL'
    elif port == 3389:
        return 'RDP'
    elif port == 5432:
        return 'PostgreSQL'
    elif port == 5900:
        return 'VNC'
    elif port == 5901:
        return 'VNC Alternate'
    elif port == 8080:
        return 'HTTP (Alternate)'
    # Unknown port
    else:
        return 'Unknown'


def transport_layer_packet(packet):
    # Check if the packet has a valid transport layer
    if not packet.haslayer(TCP) and not packet.haslayer(UDP):
        print('Invalid transport layer packet')
        return

    # Extract source and destination port numbers
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    else:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Classify ports as well-known, registered, or dynamic
    if src_port < 1024:
        src_port_type = 'Well-known'
    elif src_port < 49152:
        src_port_type = 'Registered'
    else:
        src_port_type = 'Dynamic'

    if dst_port < 1024:
        dst_port_type = 'Well-known'
    elif dst_port < 49152:
        dst_port_type = 'Registered'
    else:
        dst_port_type = 'Dynamic'

    # Attempt to identify the application type
    src_app = dst_app = 'N/A'
    try:
        src_app = socket.getservbyport(src_port)
    except OSError:
        pass

    try:
        dst_app = socket.getservbyport(dst_port)
    except OSError:
        pass

    # Print packet information
    print('\nTransport Layer Packet')
    print('----------------------')
    print(f'Source Port: {src_port} ({src_port_type})')
    print(f'Source Application: {src_app}')
    print(f'Destination Port: {dst_port} ({dst_port_type})')
    print(f'Destination Application: {dst_app}')
    return [src_port, dst_port, dst_app, src_app]

# Sniff the network for PDUs and analyze them
while True:
    print("Ethernet packets and analysis:\n")
    pkt = sniff(count=1) # Sniffs 1 time for each packet
    x = ethernet_packet(pkt[0]) # Prints the ethernet analysis
    print("----------------------------------------------------------")
    print("Waiting for 5 sec... to print IP analysis \n")
    time.sleep(5) # Delays for 5 seconds
    print("IP packets and analysis: \n")
    y = ip_packet(pkt[0]) # Prints the IP analysis
    print("----------------------------------------------------------")
    print("Waiting for 5 sec... to print Port analysis \n")
    time.sleep(5)
    z = transport_layer_packet(pkt[0]) # Prints Port classifications
    classify_application(pkt[0]) # Prints Application classification
    print("----------------------------------------------------------")
    print("Waiting for 5 sec... to print OSI Model \n")
    time.sleep(5)
    # OSI Model
    table = PrettyTable(['Layer', 'PDU', 'Address Type', 'Source', 'Destination', 'Protocols'])
    table.add_row(['Application', 'Data', 'Port Number', f'Source Port: {z[0]}', f'Destination port number: {z[1]}', f'Protocols: {z[3]} - {z[2]}'])
    table.add_row(['Transport', 'Segment', 'Port Number', f'Source Port: {z[0]}', f'Destination port number: {z[1]}', f'Protocols: {z[3]} - {z[2]}'])
    table.add_row(['Network', 'Packet', 'IP Address', f'Sender IP: {y[0]}', f'Receiver IP {y[1]}', f'IP-Version: {y[2]}'])
    table.add_row(['Data Link', 'Frame', 'MAC Address', f'Sender MAC: {x[0]}', f'Receiver MAC: {x[1]}', 'Protocols: Ethernet 2'])
    table.add_row(['Physical', 'Bit', 'N/A', 'N/A', 'N/A', 'N/A'])
    print(table)
    print("Waiting for 1 minute to get next packet info... \n")
    print('\n')
    time.sleep(60)

