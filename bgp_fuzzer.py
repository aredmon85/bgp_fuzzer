import ipaddress
import socket
import struct
import time
PEER_IP = '10.130.0.222'
PORT = 179
BUFFER = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((PEER_IP,PORT))
ASN = 64701
VERSION = 4
HOLDTIME = 90
BGP_ID = 174260255
#Type (8b), Length (8b), AFI (16b), Reserved (8b), SAFI (8b)
CAPABILITY_IP4 = struct.pack('!BBHBB',1,4,1,0,1)
#Type (8b), Length (8b), AFI (16b), Reserved (8b), SAFI (8b)
CAPABILITY_FLOW_SPEC = struct.pack('!BBHBB',1,4,1,0,133)
#Type (8b), Length (8b)
CAPABILITY_RR = struct.pack('!BB',2,0)
#Type (8b), Length (8b), Restart Timers (16b)
CAPABILITY_GR = struct.pack('!BBH',64,2,33068)
#Type (8b), Length (8b), AS Number (32b)
CAPABILITY_4B_ASN = struct.pack('!BBI',65,4,ASN)
#Parameter Type (8b), Parameter Length (8b)
CAPABILITY_HDR = struct.pack('!BB',2,len(CAPABILITY_IP4) + len(CAPABILITY_FLOW_SPEC) + len(CAPABILITY_RR) + len(CAPABILITY_GR) + len(CAPABILITY_4B_ASN))
CAPABILITIES = CAPABILITY_HDR + CAPABILITY_IP4 + CAPABILITY_FLOW_SPEC + CAPABILITY_RR + CAPABILITY_GR + CAPABILITY_4B_ASN

OPEN_HDR = struct.pack('!BHHIB',VERSION,ASN,HOLDTIME,BGP_ID,len(CAPABILITIES)) + CAPABILITIES
OPEN_MESSAGE = b'\xff'*16 + struct.pack('!HB',len(OPEN_HDR) + 19,1) + OPEN_HDR
KEEPALIVE_MESSAGE = b'\xff'*16 + struct.pack('!HB',19,4)

s.send(OPEN_MESSAGE)
msg = s.recv(BUFFER)
s.send(KEEPALIVE_MESSAGE)
while True:
    time.sleep(10)
