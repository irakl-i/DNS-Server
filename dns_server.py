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

RECORDS = {1: 'A', 2: 'NS', 5: 'CNAME',
           6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA'}


def get_bit(byte, index):
    return (byte & 2 ** index) != 0


def parse_body(dns_body):
    """Parses DNS question from binary data."""
    length = struct.unpack('!B', dns_body[:1])[0]
    dns_body = dns_body[1:]

    domain = ""
    while True:
        part = struct.unpack('!{}c'.format(length), dns_body[:length])
        for ch in part:
            domain += ch.decode()
        dns_body = dns_body[length:]

        val = struct.unpack('!B', dns_body[:1])[0]
        if val == 0:
            break

        domain += '.'
        dns_body = dns_body[1:]
        length = val

    print(domain)
    record = struct.unpack('!H', dns_body[1:3])[0]
    print(RECORDS[record])


def parse_header(dns_header):
    """Parses DNS header from binary data."""
    headers = struct.unpack('!6H', dns_header)
    print([hex(x) for x in headers])

    recursion_desired = get_bit(headers[FLAGS], 8)
    questions = headers[QDCOUNT]
    # print(recursion_desired, questions)


def listener(address):
    """Listens to the incoming connections."""

    listen_socket = socket(AF_INET, SOCK_DGRAM)
    listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_socket.bind(address)

    while True:
        message, client_address = listen_socket.recvfrom(512)
        parse_header(message[:12])
        parse_body(message[12:])


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
