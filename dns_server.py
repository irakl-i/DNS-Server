from socket import *
import binascii
import dnslib
import io


def get_response(data):
    # packet = binascii.unhexlify(data)
    # print(dnslib.DNSRecord.parse(data))

    response = bytearray()
    response[:2] = data[:2]
    # print(response)

    return response


def listener(address):
    """Listens to the incoming connections."""

    listen_socket = socket(AF_INET, SOCK_DGRAM)
    listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_socket.bind(address)

    while True:
        client_data, client_address = listen_socket.recvfrom(512)
        listen_socket.sendto(get_response(
            bytearray(client_data)), client_address)


if __name__ == '__main__':
    with open("example.com.conf") as conf_file:
        z = dnslib.ZoneParser(conf_file.read())
        print(list(z.parse()))
    listener(('127.0.0.1', 53))
