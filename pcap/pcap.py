import argparse
import os
import struct
import sys
from collections import namedtuple
from datetime import datetime


"""
Global File Header structure: https://wiki.wireshark.org/Development/LibpcapFileFormat
"""

GlobalHeaderStruct = namedtuple(
    "GLOBAL_HEADER_STRUCT",
    [
        "magic_number",
        "version_major",
        "version_minor",
        "thiszone",
        "sigfigs",
        "snaplen",
        "network",
    ],
)


class GlobalHeader(GlobalHeaderStruct):
    """The global file header of the entire pcap savefile

    https://www.tcpdump.org/manpages/pcap-savefile.5.txt
    """

    # https://docs.python.org/3/library/struct.html#format-characters
    FORMAT = "IHHIIII"
    LENGTH = 24

    def __new__(cls, bytes):
        return super(GlobalHeader, cls).__new__(cls, *struct.unpack(cls.FORMAT, bytes))

    def verify(self):
        assert self.magic_number == 0xA1B2C3D4
        assert self.version_major == 2
        assert self.version_minor == 4
        # assert self.thiszone == 0
        # assert self.snaplen == 0
        assert self.network == 1  # LINKTYPE_ETHERNET


PacketHeaderStruct = namedtuple(
    "PACKET_HEADER_STRUCT", ["ts_sec", "ts_usec", "captured_len", "total_len"]
)
# print(header)
# 2712847316 served in Little Endian!!1
#
# a - 11, b - 12, c = 13, d = 14
# d4 c3 b2 a1 02 00 04 00
#
class PacketHeader(PacketHeaderStruct):
    """The header of an individually captured libpcap header

    https://www.tcpdump.org/manpages/pcap-savefile.5.txt
    """

    # https://docs.python.org/3/library/struct.html#format-characters
    FORMAT = "IIII"
    LENGTH = 16

    def __new__(cls, bytes):
        return super(PacketHeader, cls).__new__(cls, *struct.unpack(cls.FORMAT, bytes))

    def __str__(self):
        return "pcap header len: {} captured at {}".format(
            self.incl_len, datetime.fromtimestamp(self.ts_sec + 1e-6 * self.ts_usec)
        )

    def verify(self):
        assert self.captured_len == self.total_len


EthHeaderStruct = namedtuple(
    "EthHeaderStruct", ["mac_dest_addr", "mac_source_addr", "ether_type"]
)


class EthernetHeader(EthHeaderStruct):
    """The Ethernet Header Frame
    https://en.wikipedia.org/wiki/Ethernet_frame

    MAC address: https://en.wikipedia.org/wiki/MAC_address
    """

    LENGTH = 14
    FORMAT = ""

    def __new__(cls, bytes):
        return super(EthernetHeader, cls).__new__(
            cls, bytes[0:6], bytes[6:12], bytes[12:14]
        )

    def __str__(self):
        def format_mac_addr(bytes):
            return struct.unpack(">HHH", bytes)

        return "Source mac addr: {} Dest mac addr: {}".format(
            format_mac_addr(self.mac_source_addr), format_mac_addr(self.mac_dest_addr)
        )

    def verify(self):
        # Verify for IPV4 datagram https://en.wikipedia.org/wiki/EtherType
        # https://www.google.com/search?q=2048+to+hex
        eth_type = struct.unpack(">H", self.ether_type)[0]
        assert eth_type == 2048


# https://tools.ietf.org/html/rfc791#section-3.1
IPHeaderStruct = namedtuple(
    "IPHeaderStruct",
    [
        "version",
        "IHL",
        "type_of_service",
        "total_len",
        "identification",
        "flags",
        "fragment_offset",
        "ttl",
        "protocol",
        "header_checksum",
        "source_addr",
        "dest_addr",
    ],
)


class IPHeader(IPHeaderStruct):
    """The IP Header
    """

    # https://docs.python.org/3/library/struct.html#format-characters
    FORMAT = "IIIIIIIIIIII"
    LENGTH = 32

    def __new__(cls, bytes):
        return super(IPHeader, cls).__new__(cls, *struct.unpack(cls.FORMAT, bytes))

    def __str__(self):
        print(self.total_len)

    @staticmethod
    def get_ihl(b):
        """
        Given the first byte of the header, Internet Header Length, which
        represents the number of 32 bit words in the header. 0x0f is the
        hexadecimal representation of a byte
        """
        return b & 0x0F


def main():
    # TODO Change to use args parse
    dir_name = os.path.dirname(os.path.abspath(__file__)) + "/net.cap"

    with open(dir_name, "rb") as f:
        global_header = GlobalHeader(f.read(GlobalHeader.LENGTH))
        global_header.verify()
        while True:
            bytes = f.read(PacketHeader.LENGTH)
            if not bytes:
                break
            header = PacketHeader(bytes)
            header.verify()
            etherenet_frame = f.read(header.captured_len)
            eth_header = EthernetHeader(etherenet_frame[: EthernetHeader.LENGTH])
            eth_header.verify()
            # the payload of the ethernet frame is an IP datagram
            # https://en.wikipedia.org/wiki/Ethernet_frame#structure
            ip_datagram = etherenet_frame[EthernetHeader.LENGTH :]

            # parse and verify the IP datagram header
            ip_header_length = 4 * IPHeader.get_ihl(ip_datagram[0])
            IPHip_datagram[:ip_header_length]


if __name__ == "__main__":
    main()
