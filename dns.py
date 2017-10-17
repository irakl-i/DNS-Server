from socket import *
import struct

serverPort = 53535
serversocket = socket(AF_INET, SOCK_DGRAM)
serversocket.bind(('', serverPort))

while 1:
    message, clientAddress = serversocket.recvfrom(512)
    dns_header = message[:12]
    h = struct.unpack('!6H',dns_header)
    print(type(h), h)
    tid, flags, t_question, t_ans, t_authrr, t_addrr = h

    p = struct.pack('!6H', tid, flags, t_question, t_ans, t_authrr, t_addrr)
    print(type(p))
