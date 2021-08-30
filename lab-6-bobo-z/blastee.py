#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

BLASTER_IP = '192.168.100.1'
BLASTER_MAC = '10:00:00:00:00:01'

BLASTEE_IP = '192.168.200.1'
BLASTEE_MAC = '20:00:00:00:00:01'

MIDDLEBOX_BLASTER_IP = '192.168.100.2'
MIDDLEBOX_BLASTER_MAC = '40:00:00:00:00:01'

MIDDLEBOX_BLASTEE_IP = '192.168.200.2'
MIDDLEBOX_BLASTEE_MAC = '40:00:00:00:00:02'


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = blasterIp
        self.num = int(num)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")

        eth = Ethernet()
        eth.src = BLASTEE_MAC
        eth.dst = MIDDLEBOX_BLASTEE_MAC

        ip = IPv4()
        ip.src = BLASTEE_IP
        ip.dst = BLASTER_IP
        ip.protocol = IPProtocol.UDP

        udp = UDP()
        udp.src = 1234
        udp.dst = 5678

        #debugger()
        rawdata = packet[RawPacketContents].data
        sequence_num = int.from_bytes(rawdata[0:4],'big')
        length = int.from_bytes(rawdata[4:6],'big')

        sequence_bytes = sequence_num.to_bytes(4,'big')
        payload = rawdata[6:].decode('utf-8','ignore')
        payload = payload + '0'*8
        payload_bytes = payload[:8].encode('utf-8','ignore')
        content = RawPacketContents(sequence_bytes+payload_bytes)
        ack = eth+ip+udp+content
        self.net.send_packet(fromIface, ack)

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
