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

RECORDS = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA'
}

# Global variables
HEADERS = None
RECURSION_DESIRED = None
QUESTIONS = None


def get_bit(byte, index):
	return (byte & 2**index) != 0


def set_bit(byte, index):
	return byte | (2**index)


def clear_bit(byte, index):
	return byte & ~(2**index)


def generate_header():
	# Set correct values for flags
	flags = HEADERS[FLAGS]
	flags = set_bit(flags, 15)  # Set the query type to answer
	flags = set_bit(flags, 7)  # Set the recursion available to true
	flags = clear_bit(flags, 5)  # Clear the AD bit

	return struct.pack('!6H', HEADERS[ID], flags, 1, 1, 0, 0)


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

	global HEADERS
	global RECURSION_DESIRED
	global QUESTIONS

	HEADERS = struct.unpack('!6H', dns_header)
	RECURSION_DESIRED = get_bit(HEADERS[FLAGS], 8)
	QUESTIONS = HEADERS[QDCOUNT]


def listener(address):
	"""Listens to the incoming connections."""

	listen_socket = socket(AF_INET, SOCK_DGRAM)
	listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	listen_socket.bind(address)

	while True:
		message, client_address = listen_socket.recvfrom(512)
		parse_header(message[:12])
		parse_body(message[12:])
		listen_socket.sendto(generate_header(), client_address)


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
		zone = easyzone.zone_from_file(file[:-5], '{}/{}'.format(path, file))
		# print(zone.root.records('NS').items)

	listener(('127.0.0.1', 53))
