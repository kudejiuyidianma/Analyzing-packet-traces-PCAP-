import dpkt
import socket

def to_hex(num):
    return '0x0' + hex(num)[2] if num <= 15 else hex(num)

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
for ts, packet in pcap:
    eth = dpkt.ethernet.Ethernet(packet)
    ip = eth.data
    tcp = ip.data

print(len(packet))
print()

