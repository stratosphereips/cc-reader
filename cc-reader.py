#!/usr/bin/env python
from scapy.all import *

with PcapReader('./2018-11-30-23-50-05-192.168.1.195.only-port-45.pcap') as pcap_reader:
    for pkt in pcap_reader:
        if pkt.haslayer(TCP):
            payload = pkt[TCP].payload.raw_packet_cache
            if payload:
                print('Packet received with len {}. From {} to {}'.format(len(payload), pkt[IP].src, pkt[IP].dst))
                # Not sure if there is some byte that we can use as 'type'.. trying with 0
                type = payload[0]
            if payload and len(payload) == 14:
                # String?
                print('\t{}'.format(hexdump(payload)))
            elif payload and len(payload) == 9:
                # String?
                print('\t{}'.format(hexdump(payload)))
            elif payload and len(payload) == 44:
                # String?
                print('\t{}'.format(hexdump(payload)))
            elif payload and len(payload) == 8:
                # String?
                print('\t{}'.format(hexdump(payload)))
            elif payload and len(payload) == 10:
                # String?
                print('\t{}'.format(hexdump(payload)))
            elif payload and len(payload) == 13:
                # String?
                print('\t{}'.format(hexdump(payload)))
            elif payload and len(payload) == 30:
                # String?
                print('\t{}'.format(hexdump(payload)))
            elif payload and payload != b'\x00\x00\x00\x00\x00\x00' and len(payload) > 6:
                # Convert the raw to hex
                hex_payload = payload.hex()
                #print('Hex payload: {}'.format(hex_payload))
                #print('Hexdump: {}'.format(hexdump(payload)))
                # Convert the hex to
                data = [hex_payload[i:i+2] for i in range(0, len(hex_payload), 2 )]
                first_data = '0x'
                second_data = '0x'
                for i in range(0,len(data)):
                    if i < 5:
                        # 5 Bytes, from  0 to 4
                        # Not sure. Ignore
                        pass
                    elif i == 5:
                        # 3 Bytes. From 5 to 8
                        # Not sure
                        first_data += data[i]
                        first_data += data[i + 1]
                        first_data += data[i + 2]
                        print('\tFirst unknown data: {}'.format(first_data))
                    elif i == 8:
                        # IP address. Use 4 bytes
                        # 4 Bytes. From 8 to 11
                        ip1 = str(int(data[i], 16))
                        ip2 = str(int(data[i + 1], 16))
                        ip3 = str(int(data[i + 2], 16))
                        ip4 = str(int(data[i + 3], 16))
                        ip = ip1 + '.' + ip2 + '.' + ip3 + '.' + ip4
                        print('\tIP Address: {}'.format(ip))
                    elif i == 12:
                        # 4 Bytes. From 12 to 15
                        second_data += data[i]
                        second_data += data[i + 1]
                        second_data += data[i + 2]
                        second_data += data[i + 3]
                        print('\tSecond unknown data: {}'.format(second_data))
                    elif i == 16:
                        # The port as ascii until the end
                        extra_data = data[i:]
                        port = ''
                        for edata in extra_data:
                            port += bytearray.fromhex(edata).decode()
                        print('\tPort: {}'.format(port))





