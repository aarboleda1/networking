import struct
import os
from collections import namedtuple
import argparse

"""A program to parse raw binary data. This exercise was a part
of Bradfield CS networking course, allowing me to parse and work
with headers for very important network protocols, Ethernet, IP, 
TCP, HTTP and binary data!

Example usage:
    python3 pcap.py -p net.cap -o my_image.jpg
"""

GlobalHeaderFormat = namedtuple(
    "GlobalHeaderFileFormat",
    [
        "magic_number",
        "major_version",
        "minor_version",
        "time_zone_offset", 
        "time_stamp_accuracy",
        "snapshot_length",
        "link_layer_header_type",
    ]
)
class GlobalHeader(GlobalHeaderFormat):
    """The pcap file global header
    https://www.tcpdump.org/manpages/pcap-savefile.5.txt
    """
    FORMAT = "IHHIIII"  
    LENGTH = 24  

    def __new__(cls, bytes):
        return super(GlobalHeader, cls).__new__(cls, *struct.unpack(cls.FORMAT, bytes))
    
    def verify(self):
        assert self.magic_number == 0xa1b2c3d4
        assert self.major_version == 2
        assert self.minor_version == 4 
        assert self.time_zone_offset == 0        
        assert self.time_stamp_accuracy == 0 # GMT (UTC)
        assert self.snapshot_length == 1514
        assert self.link_layer_header_type == 1 # LINKTYPE_ETHERNET
        print("Global Header Verified")

PacketHeaderFormat = namedtuple(
    "PacketHeaderFormat",
    [
        "timestamp_seconds",
        "timestamp_microseconds",
        "included_len",
        "original_len",
    ]
)
class PacketHeader(PacketHeaderFormat):
    FORMAT = "IIII"
    LENGTH = 16

    def __new__(cls, bytes):
        return super(PacketHeader, cls).__new__(cls, *struct.unpack(cls.FORMAT, bytes))
    
    def verify(self):
        assert self.included_len == self.original_len

EthernetHeaderFormat = namedtuple(
    "EthernetHeaderFormat",
    [
        "mac_dest", 
        "mac_source", 
        "ethertype", 
    ]
)
class EthernetHeader(EthernetHeaderFormat):
    """
    The Ethernet Frame Header 
    See https://en.wikipedia.org/wiki/Ethernet_frame for specification
    """    
    LENGTH = 14

    def __new__(cls, bytes):
        return super(EthernetHeader, cls).__new__(cls, 
            bytes[0:6],
            bytes[6:12],
            bytes[12:14]
        )

    def verify(self):
        # Verify ethertype for an IPv4 datagram
        assert self.ethertype == bytes.fromhex('0800')    

IPDatagramFormat = namedtuple(
    "IPDatagramFormat",
    [
        "version",
        "ihl",
        "dscp",
        "ecn",
        "total_len",
        "identification",
        "flags",
        "fragment_offset",
        "ttl",
        "protocol",
        "header_checksum",
        "source_ip_addr",
        "dest_ip_addr",
    ]
)
class IPDatagramHeader(IPDatagramFormat):
    """
    The header of an IPv4 datagram

    See https://en.wikipedia.org/wiki/IPv4#Packet_structure for specification
    """

    def __new__(cls, bytes):
        b1, b2, total_len, identification, b7_8, ttl, protocol, header_checksum = \
            struct.unpack('BBHHHBBH', bytes[:12]) 
        version = b1 >> 4
        ihl = cls.get_ihl(b1)
        dscp = b2 >> 2
        ecn = b2 & 3
        flags = b7_8 >> 13
        fragment_offset = b7_8 & 0x1fff
        source_ip = bytes[12:16]
        destination_ip = bytes[16:20]  
        return super(IPDatagramHeader, cls).__new__(
            cls,
            version,
            ihl,
            dscp,
            ecn,
            total_len,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_ip,
            destination_ip
        )

    def verify(self):
        assert self.version == 4
        assert self.ecn == 0
        assert self.protocol == 6  # indicates TCP
    
    def get_ihl(byte):
        return byte & 0x0f

TCPSegmentHeaderFormat = namedtuple(
    "TCPSegmentHeaderFormat",
    [
        "source_port", 
        "destination_port", 
        "seq_num", 
        "ack_num", 
        "data_offset",
        "reserved_bits",
        "flags",
        "window_size",
        "checksum",
        "urgent_pointer",
    ],
)
class TCPSegmentHeader(TCPSegmentHeaderFormat):
    """The TCP Segment Header
    
    See https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    """
    DEFAULT_LENGTH = 20
    def __new__(cls, bs):
        source_port, destination_port, seq_number, ack_number, b12_13, \
            window_size, checksum, urgent_pointer \
            = struct.unpack('!HHIIHHHH', bs[:20])
        data_offset = cls.get_data_offset(bs[:20])
        reserved_bits = (b12_13 >> 9) & 7
        # https://www.geeksforgeeks.org/tcp-flags/
        flags = {
            'NS': (b12_13 & (1 << 8)) > 0,
            'CWR': (b12_13 & (1 << 7)) > 0,
            'ECE': (b12_13 & (1 << 6)) > 0,
            'URG': (b12_13 & (1 << 5)) > 0,
            'ACK': (b12_13 & (1 << 4)) > 0,
            'PSH': (b12_13 & (1 << 3)) > 0,
            'RST': (b12_13 & (1 << 2)) > 0,
            'SYN': (b12_13 & (1 << 1)) > 0,
            'FIN': (b12_13 & (1 << 0)) > 0
        }
        return super().__new__(
            cls, source_port, destination_port, seq_number, ack_number,
            data_offset, reserved_bits, flags, window_size, checksum,
            urgent_pointer)
    
    def __str__(self):
        return 'TCP segment from port {} to {}'.format(
            self.source_port, self.destination_port)    

    @staticmethod
    def get_data_offset(bs):
        """
        Given the default header (without options) determine the data offset.

        This is in 32 bit words, so can be used to determine the true length
        of the header by multiplying by 4.
        """
        return bs[12] >> 4    
    
def run():
    parser = argparse.ArgumentParser(
            description="Parse the pcapture of a mystery image download")    
    parser.add_argument("-o", "--output",
                        help="The destination file to write to write to")
    parser.add_argument("-p","--path", help="path to pcap file to be parsed")
    args = parser.parse_args()
    requesting_host = (192, 168, 0, 101)  # we know this is us
    
    # Map sequence numbers to data in each segment
    seq_num_to_data = {}
    with open(args.path, 'rb') as f:
        global_header = GlobalHeader(f.read(GlobalHeader.LENGTH))
        global_header.verify()

        while True:
            bytes = f.read(PacketHeader.LENGTH)            

            if not bytes:
                break
            packet_header = PacketHeader(bytes)
            packet_header.verify()

            # Consume the ethernet header from the Global Packet header
            ethernet_frame = f.read(packet_header.included_len)
            eth_header = EthernetHeader(ethernet_frame[:EthernetHeader.LENGTH])
            eth_header.verify()
            
            ip_datagram = ethernet_frame[EthernetHeader.LENGTH:]

            """
            Parse the Internet Header Length, which is the lowest order 4 bits of 
            the first byte of the header. Extract this by performing a logical and 
            against the number 15 (byte & 0x0f). Multiply this by 4, to 
            determine the header length in bytes,
            """
            ip_header_length = 4 * (ip_datagram[0] & 0x0f)
            ip_header = IPDatagramHeader(ip_datagram[:ip_header_length])
            ip_header.verify()
            
            # the rest of the IP datagram is a TCP segment
            tcp_segment = ip_datagram[ip_header_length:]
            tcp_header_len = 4 * TCPSegmentHeader.get_data_offset(
                tcp_segment[:TCPSegmentHeader.DEFAULT_LENGTH]
            )
            tcp_header = TCPSegmentHeader(tcp_segment[:tcp_header_len])
            
            tcp_payload = tcp_segment[tcp_header_len:]

            # We want only the response segments
            if tuple(ip_header.dest_ip_addr) == requesting_host and not \
                    tcp_header.flags['SYN']:   
                seq_num_to_data[tcp_header.seq_num] = tcp_payload
        
        # Packets may come out of order
        http_message = b''.join(d for _, d in sorted(seq_num_to_data.items()))
        http_header, http_payload = http_message.split(b'\r\n\r\n', 1)
        if args.output:
            with open(args.output, 'wb') as output:
                output.write(http_payload)
            print(f"Success! Output written to {args.output}")

if __name__ == "__main__":
    run()