from socket import *
import binascii
import io
import os
from easyzone import easyzone


def listener(address):
    """Listens to the incoming connections."""

    listen_socket = socket(AF_INET, SOCK_DGRAM)
    listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_socket.bind(address)

    while True:
        client_data, client_address = listen_socket.recvfrom(512)
        # listen_socket.sendto(get_response(
        #     bytearray(client_data)), client_address)


if __name__ == '__main__':
    if len(os.sys.argv) < 2:
        print("Exiting")
        os.sys.exit()

    for filename in os.listdir(os.sys.argv[1]):
        print(filename)

    zone = easyzone.zone_from_file('google.com', '/zones/google.com.conf')
    print(zone.root.records('NS').items)
    # listener(('127.0.0.1', 5353))
