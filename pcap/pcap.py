import struct
import os
import argparse
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
        "network"
    ]
)

class GlobalHeader(GlobalHeaderTuple):
    """The global header of the entire pcap savefile

    https://www.tcpdump.org/manpages/pcap-savefile.5.txt
    """
    LENGTH = 24
    # https://docs.python.org/3/library/struct.html#format-characters
    FORMAT = "IHHIIII"
    # def __init__(self, bytes):
    def __new__(cls, bytes):
        return super(GlobalHeader, cls).__new__(
            cls, *struct.unpack(cls.FORMAT, bytes)
        )

PacketHeaderTuple = namedtuple(
    "PACKET_HEADER_STRUCT",
    [
        "ts_sec",
        "ts_usec",
        "incl_len",
        "orig_len"
    ]
)

class PacketHeader(PacketHeaderTuple):
    """The header of an individually captured libpcap header

    https://www.tcpdump.org/manpages/pcap-savefile.5.txt
    """
    # https://docs.python.org/3/library/struct.html#format-characters
    FORMAT = "IIII"
    LENGTH = 16

    def __new__(cls, bytes):
        return super(PacketHeader, cls).__new__(
            cls, *struct.unpack(cls.FORMAT, bytes)
        )

    def __str__(self):
        return "pcap header {} captured at {}".format(
            self.incl_len,
            datetime.fromtimestamp(self.ts_sec + 1e-6 * self.ts_usec)
        )

    def verify(self):
        assert self.incl_len == self.orig_len

def main():
    # TODO Change to use args parse
    dir_name = os.path.dirname(os.path.abspath(__file__)) + "/net.cap"

    with open(dir_name) as f:
        global_header = GlobalHeader(f.read(GlobalHeader.LENGTH))

        while True:
            bytes = f.read(PacketHeader.LENGTH)
            if not bytes:
                break
            header = PacketHeader(bytes)



if __name__ == "__main__":
    main()
