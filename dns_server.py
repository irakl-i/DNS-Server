from socket import *
import binascii


def listener(address):
    """Listens to the incoming connections. """

    listen_socket = socket(AF_INET, SOCK_DGRAM)
    listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_socket.bind(address)

    while True:
        client_data, client_address = listen_socket.recvfrom(512)
        for byte in bytearray(client_data):
            print(hex(byte))
        # print(bytearray(client_data))


if __name__ == '__main__':
    listener(('127.0.0.1', 53))
