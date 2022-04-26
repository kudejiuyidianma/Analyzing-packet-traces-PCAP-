import socket
import sys
import dpkt

src = '130.245.145.12'
dst = '128.208.2.198'


class Packet:
    def __init__(self, timestamp, packet):
        self.timestamp = timestamp
        self.packet = packet

    def getPacketInfo(self):
        packet = self.packet

        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        tcp = ip.data

        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)

        src_port = tcp.sport
        dst_port = tcp.dport

        seqNumber = tcp.seq
        ackNumber = tcp.ack

        windowSize = tcp.win * 16384

        packet_info = {'src_port': src_port, 'dst_port': dst_port, 'seqNumber': seqNumber,
                       'ackNumber': ackNumber, 'windowSize': windowSize, 'src_ip': src_ip, 'dst_ip': dst_ip}
        return packet_info


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


def printPacket(packet):
    info = packet.getPacketInfo()
    print('Source Port: %-10d Destination Port: %-10d Sequence Number: %-20d Acknowledge Number: %-20d Window Size '
          '%-10d' % (info.get('src_port'), info.get('dst_port'), info.get('seqNumber'),
                     info.get('ackNumber'), info.get('windowSize')))


def findResponse(packet, seqNums):
    syn_info = packet.getPacketInfo()
    syn_dst_port = syn_info.get('dst_port')
    syn_src_port = syn_info.get('src_port')
    syn_ack_num = syn_info.get('ackNumber')
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        packet_j = Packet(ts, buf)
        packet_j_info = packet_j.getPacketInfo()
        packet_j_src_port = packet_j_info.get('src_port')
        packet_j_dst_port = packet_j_info.get('dst_port')
        packet_j_seq_num = packet_j_info.get('seqNumber')
        packet_j_ack_num = packet_j_info.get('ackNumber')
        if packet_j_src_port == syn_dst_port and packet_j_dst_port == syn_src_port and packet_j_seq_num == syn_ack_num:
            if packet_j_ack_num not in seqNums:
                return packet_j


def task_1():
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    initial_flow = []
    for ts, buf in pcap:
        packet_i = Packet(ts, buf)  # create a packet object for each transition
        packet_i_info = packet_i.getPacketInfo()
        packet_i_src_port = packet_i_info.get('src_port')
        packet_i_dst_port = packet_i_info.get('dst_port')
        packet_i_src_ip = packet_i_info.get('src_ip')
        # when find a new source port
        if packet_i_src_port not in initial_flow and packet_i_src_port != packet_i_dst_port and packet_i_src_ip != dst:
            initial_flow.append(packet_i_src_port)
        if packet_i_src_ip == dst:
            dst_port = packet_i_src_port
    f.close()
    print('There are', len(initial_flow), 'TCP initial flows initiated from the sender.')
    return initial_flow, dst_port


def task_2(initial_flow, dst_port_num):
    flow_index = 0
    for flow in initial_flow:
        flow_index += 1
        print('TCP flow', flow_index, ': ')
        print('%-6s%-20d%-10s%-10s' % ('Source Port: ', flow, 'Source IP address: ', src))
        print('%-6s%-20d%-10s%-10s' % ('Destination Port: ', dst_port_num, 'Destination IP address: ', dst))
        print()
        f = open('assignment2.pcap', 'rb')
        pcap = dpkt.pcap.Reader(f)
        trans_index = 0
        trans_array = []
        seqNumList = []
        # Find first two transitions in each flow.
        for ts, buf in pcap:
            packet_i = Packet(ts, buf)
            packet_i_info = packet_i.getPacketInfo()
            packet_i_src_port = packet_i_info.get('src_port')
            if packet_i_src_port == flow:
                trans_index += 1
                if trans_index <= 3:
                    continue
                # the 4th and 5th transaction from sender to receiver are we want
                elif trans_index == 5 or trans_index == 4:
                    trans_array.append(packet_i)
                    seqNumList.append(packet_i_info.get('seqNumber'))
                    ack_packet = findResponse(packet_i, seqNumList)
                    trans_array.append(ack_packet)
                else:
                    continue
        print('First Transaction:')
        printPacket(trans_array[0])
        printPacket(trans_array[1])
        print('Second Transaction: ')
        printPacket(trans_array[2])
        printPacket(trans_array[3])
        if flow_index != 3:
            print()
            print('--------------------------------------------------------------------------------------------------'
                  '---------------------------------------------------')
        print()
        f.close()


def throughput(flow_list):
    for flow in flow_list:
        total_bytes = 0
        ts_min = sys.maxsize
        ts_max = -sys.maxsize
        f = open('assignment2.pcap', 'rb')
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            packet = Packet(ts, buf)
            packet_info = packet.getPacketInfo()
            packet_src_port = packet_info.get('src_port')
            packet_dst_port = packet_info.get('dst_port')
            if packet_src_port == flow:
                total_bytes += len(buf)
                ts_min = min(ts, ts_min)
                ts_max = max(ts, ts_max)
        print('The sender throughput of flow', flow, 'is', '%d' % (total_bytes / (ts_max - ts_min)))
        f.close()


def congestion_window_size(flow_list):
    for flow in flow_list:
        step = 0
        cwnd = []
        send = 0
        index = 0
        f = open('assignment2.pcap', 'rb')
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            packet = Packet(ts, buf)
            packet_info = packet.getPacketInfo()
            packet_src_port = packet_info.get('src_port')
            packet_dst_port = packet_info.get('dst_port')
            if packet_src_port == flow or packet_dst_port == flow:
                step += 1
                if step < 5:
                    continue
                else:
                    if packet_src_port == flow:
                        send += 1
                    elif packet_dst_port == flow:
                        cwnd.append(send)
                        send -= 1
            else:
                continue
        print('The first 3 congestion window size of', flow, 'is ', cwnd[0:3])
        f.close()


def rto(flow):
    index = 0
    ts_start = 0
    ts_end = 0
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        packet_i = Packet(ts, buf)
        packet_i_info = packet_i.getPacketInfo()
        packet_i_src_port = packet_i_info.get('src_port')
        if packet_i_src_port == flow:
            if index == 0:
                ts_start = ts
                index += 1
            elif index == 1:
                ts_end = ts
                break
    f.close()
    return 2 * (ts_end - ts_start)


def check_timeout(flow, seq):
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    ts_min = sys.maxsize
    ts_max = -sys.maxsize
    for ts, buf in pcap:
        packet_i = Packet(ts, buf)
        packet_i_info = packet_i.getPacketInfo()
        packet_i_src_port = packet_i_info.get('src_port')
        packet_i_seq = packet_i_info.get('seqNumber')
        if packet_i_src_port == flow and packet_i_seq == seq:
            ts_min = min(ts_min, ts)
            ts_max = max(ts_max, ts)
    f.close()
    return ts_max - ts_min


def retransmission(flow_list):
    for flow in flow_list:
        index = 0
        seq_total = {}
        ack_total = {}
        f = open('assignment2.pcap', 'rb')
        pcap = dpkt.pcap.Reader(f)
        # count for each ack message and seq message number
        for ts, buf in pcap:
            # pass first three packet which set up the connection
            if index < 4:
                index += 1
                continue
            packet = Packet(ts, buf)
            packet_info = packet.getPacketInfo()
            packet_src_port = packet_info.get('src_port')
            packet_dst_port = packet_info.get('dst_port')
            packet_seq = packet_info.get('seqNumber')
            packet_ack = packet_info.get('ackNumber')
            if packet_src_port == flow:
                if packet_seq in seq_total:
                    seq_total[packet_seq] += 1
                    continue
                else:
                    seq_total[packet_seq] = 1
            elif packet_dst_port == flow:
                if packet_ack in ack_total:
                    ack_total[packet_ack] += 1
                else:
                    ack_total[packet_ack] = 1
        # the count of a seq_num > 1 means it is retransmission
        timeout = 0
        triple = 0
        other = 0
        for packet_seq in seq_total:
            if seq_total[packet_seq] > 1:
                if ack_total[packet_seq] > 2:
                    triple += 1
                else:
                    rto_flow = rto(flow)
                    interval = check_timeout(flow, packet_seq)
                    if interval > rto_flow:
                        timeout += 1
                    else:
                        other += 1
        print('The number of time a retransmission occurred due to timeout in', flow, 'is', timeout)
        print('The number of time a retransmission occurred due to triple duplicate ack in', flow, 'is', triple)
        print('The number of time a retransmission occurred due to other reason in', flow, 'is', other)
        print('--------------------------------------------------------------------------------------------'
              '-------------------------------------------')
        f.close()


if __name__ == '__main__':
    div = '=======================================================================================================' \
          '============================================='
    # The number of TCP flows initiated from the sender.
    initial_flows, dst_port = task_1()
    print(div)
    # source port, source IP address, destination port and destination IP address for each flow
    # first two transactions of each flow
    task_2(initial_flows, dst_port)
    print(div)
    # throughput
    throughput(initial_flows)
    print(div)
    congestion_window_size(initial_flows)
    print(div)
    retransmission(initial_flows)
