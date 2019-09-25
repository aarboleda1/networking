import argparse
import os
import struct
from collections import namedtuple
from datetime import datetime


"""
Ethernet frames
IP datagrams
TCP segments

              pcap-savefile header file format
              +------------------------------+
              |        Magic number          |
              +--------------+---------------+
              from dataclasses import dataclass
              |Major version | Minor version |
              +--------------+---------------+
              |      Time zone offset        |
              +------------------------------+
              |     Time stamp accuracy      |
              +------------------------------+
              |       Snapshot length      ls
                |
              +------------------------------+
              |   Link-layer header type     |
              +------------------------------+

typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
"""

GlobalHeaderTuple = namedtuple(
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


class GlobalHeader(GlobalHeaderTuple):
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


PacketHeaderTuple = namedtuple(
    "PACKET_HEADER_STRUCT", ["ts_sec", "ts_usec", "captured_len", "total_len"]
)
# print(header)
# 2712847316 served in Little Endian!!1
#
# a - 11, b - 12, c = 13, d = 14
# d4 c3 b2 a1 02 00 04 00
#
class PacketHeader(PacketHeaderTuple):
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


EthHeaderTuple = namedtuple(
    "EthHeaderTuple", ["mac_dest_addr", "mac_source_addr", "ether_type"]
)


class EthernetHeader(EthHeaderTuple):
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

def main():
    # TODO Change to use args parse
    dir_name = os.path.dirname(os.path.abspath(__file__)) + "/net.cap"

    with open(dir_name, "rb") as f:
        global_header = GlobalHeader(f.read(GlobalHeader.LENGTH))
        global_header.verify()
        h_count = 0
        while True:
            bytes = f.read(PacketHeader.LENGTH)
            if not bytes:
                break
            header = PacketHeader(bytes)
            header.verify()
            eth_frame = f.read(header.captured_len)
            eth_header = EthernetHeader(eth_frame[: EthernetHeader.LENGTH])
            eth_header.verify()


if __name__ == "__main__":
    main()
