from socket import *
from easyzone import easyzone
import binascii
import io
import os
import struct


def parse_header(dns_header):
    """Parses DNS header from binary data."""
    headers = struct.unpack('!6H', dns_header)
    print([hex(x) for x in headers])


def listener(address):
    """Listens to the incoming connections."""

    listen_socket = socket(AF_INET, SOCK_DGRAM)
    listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_socket.bind(address)

    while True:
        message, client_address = listen_socket.recvfrom(512)
        parse_header(message[:12])


if __name__ == '__main__':
    if len(os.sys.argv) < 2:
        print("Exiting")
        os.sys.exit()

    path = os.sys.argv[1]
    files = list()
    for filename in os.listdir(path):
        files.append(filename)

    print(files[0][:-5])

    for file in files:
        zone = easyzone.zone_from_file(
            file[:-5], '{}/{}'.format(path, file))
        print(zone.root.records('NS').items)

    listener(('127.0.0.1', 53))
