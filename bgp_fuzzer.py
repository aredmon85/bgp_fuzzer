import ipaddress
import socket
import struct
import time
import argparse

parser = argparse.ArgumentParser(description='Run bgp_fuzzer.py')
parser.add_argument('--peer_ip',type=str)
parser.add_argument('--local_ip',type=str)
args = parser.parse_args()

if args.peer_ip and args.local_ip:
    if(ipaddress.IPv4Address(unicode(args.local_ip)) and ipaddress.IPv4Address(unicode(args.peer_ip))):
            
        PEER_IP = args.peer_ip
        PORT = 179
        BUFFER = 1024

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((PEER_IP,PORT))
        ASN = 64701
        VERSION = 4
        HOLDTIME = 9
        BGP_ID = int(ipaddress.IPv4Address(unicode(args.local_ip)))
        KEEPALIVE_INTERVAL = HOLDTIME / 3
        LOCAL_IP_ADDRESS = args.local_ip
        LOCAL_IP_INTEGER = int(ipaddress.IPv4Address(unicode(LOCAL_IP_ADDRESS)))
        PREFIX = int(ipaddress.IPv4Address(unicode('7.28.0.0')))
        #Marker - 16B, all bits set
        MARKER = struct.pack('!BBBBBBBBBBBBBBBB',255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255)
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

        #Open Message
        CAPABILITIES = CAPABILITY_HDR + CAPABILITY_IP4 + CAPABILITY_FLOW_SPEC + CAPABILITY_RR + CAPABILITY_GR + CAPABILITY_4B_ASN
        OPEN_HDR = struct.pack('!BHHIB',VERSION,ASN,HOLDTIME,BGP_ID,len(CAPABILITIES)) + CAPABILITIES
        OPEN_MESSAGE = MARKER + struct.pack('!HB',len(OPEN_HDR) + 19,1) + OPEN_HDR

        #Keepalive Message
        KEEPALIVE_MESSAGE = MARKER + struct.pack('!HB',19,4)

        #Establish session
        s.send(OPEN_MESSAGE)
        msg = s.recv(BUFFER)
        #s.send(KEEPALIVE_MESSAGE)

        #Update Message 

        #Flags (16b), Type (8b), Length (8b), Origin Code (8b)
        PATH_ATTRIBUTE_ORIGIN = struct.pack('!BBBB',64,1,1,0)

        #Segment Type (8b), Segment Length (8b), AS4 (32b) * number of AS's
        AS_PATH_SEGMENT = struct.pack('!BBIIIII',2,5,64706,64709,64704,64706,64701)

        #Flags (16b), Type (8b), Length (8b), Next Hop (32b)
        PATH_ATTRIBUTE_NEXT_HOP = struct.pack('!BBBI',64,3,4,LOCAL_IP_INTEGER)

        #Flags (16b), Type (8b), Length (8b)
        PATH_ATTRIBUTE_AS_PATH = struct.pack('!BBB',64,2,len(AS_PATH_SEGMENT))

        PATH_ATTRIBUTE = PATH_ATTRIBUTE_ORIGIN + PATH_ATTRIBUTE_AS_PATH + AS_PATH_SEGMENT + PATH_ATTRIBUTE_NEXT_HOP

        #Prefix length (8b), Prefix (32b)
        NETWORK_LAYER_REACHABILITY = struct.pack('!B',16)

        #BEWARE - Mask length determines the field length - FRUSTRATING - 1820 = 7.28.0.0
        NETWORK_LAYER_REACHABILITY += struct.pack('!H',1820)
        UPDATE = PATH_ATTRIBUTE + NETWORK_LAYER_REACHABILITY

        UPDATE_LEN = len(UPDATE) + len(MARKER) + 2 + 1 + 2 + 2 

        #Len (16b), Type (8b), Withdrawn Routes Length (16b), Total PA Length (16b)
        UPDATE_MESSAGE = MARKER + struct.pack('!HBHH',UPDATE_LEN,2,0,len(PATH_ATTRIBUTE)) + UPDATE
        UPDATE_IP4_EOR = MARKER + struct.pack('!HBHH',23,2,0,0)
        UPDATE_FLOW_SPEC_EOR = MARKER + struct.pack('!HBHHBBHHB',30,2,0,7,144,15,3,1,133)

        s.send(KEEPALIVE_MESSAGE + UPDATE_MESSAGE + UPDATE_IP4_EOR + UPDATE_FLOW_SPEC_EOR)

        keepalive_last_sent = time.time()
        update_last_sent = time.time()
        #s.send(KEEPALIVE_MESSAGE + UPDATE_IP4_EOR)
        long_active = True
        short_active = False
        while True:
            now = time.time()
            msg = s.recv(BUFFER)
            if now - keepalive_last_sent > 3:
                s.send(KEEPALIVE_MESSAGE)
                keepalive_last_sent = time.time()
            if now - update_last_sent > 2:
                if long_active == True:
                    PATH_ATTRIBUTE_ORIGIN = struct.pack('!BBBB',64,1,1,0)
                    AS_PATH_SEGMENT = struct.pack('!BBIIII',2,4,64706,64704,64706,64701)
                    PATH_ATTRIBUTE_NEXT_HOP = struct.pack('!BBBI',64,3,4,LOCAL_IP_INTEGER)
                    PATH_ATTRIBUTE_AS_PATH = struct.pack('!BBB',64,2,len(AS_PATH_SEGMENT))
                    PATH_ATTRIBUTE = PATH_ATTRIBUTE_ORIGIN + PATH_ATTRIBUTE_AS_PATH + AS_PATH_SEGMENT + PATH_ATTRIBUTE_NEXT_HOP
                    NETWORK_LAYER_REACHABILITY = struct.pack('!B',16)
                    NETWORK_LAYER_REACHABILITY += struct.pack('!H',1820)
                    UPDATE = PATH_ATTRIBUTE + NETWORK_LAYER_REACHABILITY
                    UPDATE_LEN = len(UPDATE) + len(MARKER) + 2 + 1 + 2 + 2
                    UPDATE_MESSAGE = MARKER + struct.pack('!HBHH',UPDATE_LEN,2,0,len(PATH_ATTRIBUTE)) + UPDATE
                    print("Sending shorter AS Path")
                    s.send(UPDATE_MESSAGE)
                    long_active = False
                    short_active = True
                    update_last_sent = time.time()
                    continue
                if short_active == True:
                    PATH_ATTRIBUTE_ORIGIN = struct.pack('!BBBB',64,1,1,0)
                    AS_PATH_SEGMENT = struct.pack('!BBIIIII',2,5,64706,64709,64704,64706,64701)
                    PATH_ATTRIBUTE_NEXT_HOP = struct.pack('!BBBI',64,3,4,LOCAL_IP_INTEGER)
                    PATH_ATTRIBUTE_AS_PATH = struct.pack('!BBB',64,2,len(AS_PATH_SEGMENT))
                    PATH_ATTRIBUTE = PATH_ATTRIBUTE_ORIGIN + PATH_ATTRIBUTE_AS_PATH + AS_PATH_SEGMENT + PATH_ATTRIBUTE_NEXT_HOP
                    NETWORK_LAYER_REACHABILITY = struct.pack('!B',16)
                    NETWORK_LAYER_REACHABILITY += struct.pack('!H',1820)
                    UPDATE = PATH_ATTRIBUTE + NETWORK_LAYER_REACHABILITY
                    UPDATE_LEN = len(UPDATE) + len(MARKER) + 2 + 1 + 2 + 2
                    UPDATE_MESSAGE = MARKER + struct.pack('!HBHH',UPDATE_LEN,2,0,len(PATH_ATTRIBUTE)) + UPDATE
                    print("Sending longer AS Path")
                    s.send(UPDATE_MESSAGE)
                    long_active = True
                    short_active = False
                    update_last_sent = time.time()
                    continue
else:
    print("Please provide --peer_ip and --local_ip")
