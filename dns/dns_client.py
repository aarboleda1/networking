import socket

def run(dest_name):
    clientsocket = socket.socket(
        family=socket.AF_INET, # for ipv4
        type=socket.SOCK_DGRAM # for UDP
    )
    clientsocket.bind(("", 0))
    clientsocket.sendto(dest_name)

    # Server
    # clientsocket.connect()
    # clientsocket.listen() # A willingness to accept incoming connnections
    # clientsocket.acccept() # accepts connections
    # Flags in Wireshark
    # RFC for DNS 1035
    # Section 4 is most helpful
    # Requests and responses have the same structure
    # 4.1.1
    # Defines a resource record - message compression. Label or offset

if __name__ == "__main__":
    run("www.google.com")


"""
HTTP3
Quick written by Google.com. TCP like protocol without the 3-way handshake

compression

"""
