from socket import *
from easyzone import easyzone
import binascii
import io
import os
import struct

ID = 0
FLAGS = 1
QDCOUNT = 2
ANCOUNT = 3
NSCOUNT = 4
ARCOUNT = 5


def get_bit(byte, index):
    return (byte & 2 ** index) != 0


def parse_question(dns_question):
    """Parses DNS question from binary data."""


def parse_header(dns_header):
    """Parses DNS header from binary data."""
    headers = struct.unpack('!6H', dns_header)
    print([hex(x) for x in headers])

    recursion_desired = get_bit(headers[FLAGS], 8)
    questions = headers[QDCOUNT]
    print(recursion_desired, questions)


def listener(address):
    """Listens to the incoming connections."""

    listen_socket = socket(AF_INET, SOCK_DGRAM)
    listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_socket.bind(address)

    while True:
        message, client_address = listen_socket.recvfrom(512)
        parse_header(message[:12])
        parse_question(message[12:])


if __name__ == '__main__':
    if len(os.sys.argv) < 2:
        print("Exiting")
        os.sys.exit()

    path = os.sys.argv[1]
    files = list()
    for filename in os.listdir(path):
        files.append(filename)

    # print(files[0][:-5])

    for file in files:
        zone = easyzone.zone_from_file(
            file[:-5], '{}/{}'.format(path, file))
        # print(zone.root.records('NS').items)

    listener(('127.0.0.1', 53))
