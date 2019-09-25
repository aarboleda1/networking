import socket

s = socket.socket(
    family=socket.AF_INET, # for ipv4
    type=socket.SOCK_DGRAM # for UDP
)

# Define the port on which you want to connect
port = 1024

# connect to the server on local machine
serversocket = ("127.0.0.1", port)
s.connect(serversocket)
s.sendto("test msg", serversocket)
# close the connection
s.close()
