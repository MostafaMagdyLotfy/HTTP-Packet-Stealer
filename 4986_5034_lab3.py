import socket
import struct
import binascii

class IpPacket(object):


    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):


    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    return socket.inet_ntoa(raw_ip_addr)


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:

    ip_packet_payload_unpacked = struct.unpack("!HH8shh", ip_packet_payload[0:16])
    src_port=ip_packet_payload_unpacked[0]
    dst_port=ip_packet_payload_unpacked[1]
    data_offset=ip_packet_payload_unpacked[3] & 0xf000
    data_offset>>=12
    src_port = src_port
    dst_port = dst_port
    data_offset = data_offset
    data_start = data_offset*4
    data_end = len(ip_packet_payload)
    try:
        payload = ip_packet_payload[data_start:data_end].decode("utf-8")
        payload = ip_packet_payload[data_start:data_end]

    except:
        print("Received TCP packet is NOT in UTF-8 format")
        payload = None


    return TcpPacket(src_port, dst_port, data_offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:

    ip_packet_unpacked = struct.unpack("!b8sbh4s4s", ip_packet[0:20])
    ihl= ip_packet_unpacked[0] & 0x0f
    protocol=ip_packet_unpacked[2]
    source_address=ip_packet_unpacked[4]
    destination_address=ip_packet_unpacked[5]
    protocol = protocol
    ihl = ihl
    data_start = ihl*4
    data_end = len(ip_packet)
    payload = ip_packet[data_start:data_end]


    return IpPacket(protocol, ihl, parse_raw_ip_addr(source_address), parse_raw_ip_addr(destination_address), payload)


def main():
    packet_stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, 6)
    while True:
        packet, address = packet_stealer.recvfrom(4096)
        ip_packet = parse_network_layer_packet(packet)
        if (ip_packet.payload is not None) and (ip_packet.protocol == 6):
            tcp_packet = parse_application_layer_packet(ip_packet.payload)
            #Prints for checking the values
            print("\nIP_Protocol=" + str(ip_packet.protocol))
            print("IP_ihl=" + str(ip_packet.ihl))
            print("IP_Source_Address=" + str(ip_packet.source_address))
            print("IP_Destination_Address=" + str(ip_packet.destination_address))
            print("IP_Payload=" + str(binascii.hexlify(ip_packet.payload)))
            print("TCP_Source_Port=" + str(tcp_packet.src_port))
            print("TCP_Destination_Port=" + str(tcp_packet.dst_port))
            print("TCP_Data_Offset=" + str(tcp_packet.data_offset))
            print("TCP_Data=" + str(tcp_packet.payload))


if __name__ == "__main__":
    main()
