import socket


if __name__ == "__main__":
    # AF_INET refers to the address family ipv4.
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(("", 1024))
    serversocket.listen(5)

    while True:
        (clientsocket, address) = serversocket.accept()
        req = clientsocket.recv(4096)
        print(req)
        clientsocket.close()
