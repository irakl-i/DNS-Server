from socket import *
from easyzone import easyzone
import binascii
import io
import os
import struct
import ipaddress
from sys import getsizeof

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

def get_bit(byte, index):
	return (byte & 2**index) != 0


def set_bit(byte, index):
	return byte | (2**index)


def clear_bit(byte, index):
	return byte & ~(2**index)


def get_key(dictionary, search_value):
	for key, value in dictionary.items():
		if value == search_value:
			return key


def generate_header(questions):
	# Set correct values for flags
	flags = HEADERS[FLAGS]
	flags = set_bit(flags, 15)  		# Set the query type to answer
	flags = set_bit(flags, 7)  			# Set the recursion available to true
	flags = clear_bit(flags, 5)  		# Clear the AD bit

	return struct.pack('!6H', HEADERS[ID], flags, 1, questions, 0, 0)


def generate_body(requested_domain, requested_record, zone):
	compressed = int('c00c', 16) 					# Domain name location (c00c => starts from the 12th byte)
	record = get_key(RECORDS, requested_record)
	class_type = 1 									# Internet
	ttl = zone.names[requested_domain + '.'].ttl
	address = int(ipaddress.ip_address(zone.root.records(requested_record).items[0]))
	data_length = 4 								# TODO: Calculate correct values

	body = struct.pack('!HHHIHI', compressed, record, class_type, ttl, data_length, address)
	return body

def generate_query(requested_domain, requested_record, question_query):
	path = os.sys.argv[1]
	files = list()

	for filename in os.listdir(path):
		files.append(filename)

	zone = easyzone.zone_from_file(requested_domain, '{}/{}'.format(path, requested_domain + '.conf'))

	header = generate_header(len(zone.root.records(requested_record).items))
	body = question_query + generate_body(requested_domain, requested_record, zone)

	return header, body


def parse_body(dns_body):
	"""Parses DNS question from binary data."""

	length = struct.unpack('!B', dns_body[:1])[0]
	dns_body = dns_body[1:]

	requested_domain = ''
	query_length = 0
	while True:
		query_length += length + 1
		part = struct.unpack('!{}c'.format(length), dns_body[:length])
		for ch in part:
			requested_domain += ch.decode()
		dns_body = dns_body[length:]

		val = struct.unpack('!B', dns_body[:1])[0]
		if val == 0:
			query_length += 1
			break

		requested_domain += '.'
		dns_body = dns_body[1:]
		length = val

	record = struct.unpack('!H', dns_body[1:3])[0]
	requested_record = RECORDS[record]

	return requested_domain, requested_record, query_length + 4


def parse_header(dns_header):
	"""Parses DNS header from binary data."""

	global HEADERS
	global RECURSION_DESIRED

	HEADERS = struct.unpack('!6H', dns_header)
	RECURSION_DESIRED = get_bit(HEADERS[FLAGS], 8)


def listener(address):
	"""Listens to the incoming connections."""

	listen_socket = socket(AF_INET, SOCK_DGRAM)
	listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	listen_socket.bind(address)

	while True:
		message, client_address = listen_socket.recvfrom(512)

		parse_header(message[:12])
		requested_domain, requested_record, query_length = parse_body(message[12:])

		header, body = generate_query(requested_domain, requested_record, message[12:12 + query_length])
		listen_socket.sendto(header + body, client_address)


if __name__ == '__main__':
	if len(os.sys.argv) < 2:
		print("Exiting")
		os.sys.exit()

	listener(('127.0.0.1', 53))
