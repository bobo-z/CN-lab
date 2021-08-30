#!/usr/bin/env python3

import time
from random import randint
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


class Packet_Window(object):
    def __init__(self, pkt, is_sent, is_ACKe, timestamp):
        self.pkt = pkt
        self.is_sent = True
        self.is_ACKd = False
        self.timestamp = time.time()

    def ACKd(self):
        self.is_ACKd = True


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp = blasteeIp
        self.num = int(num)
        self.length = int(length)
        self.senderWindow = int(senderWindow)
        self.timeout = float(timeout)/100
        self.recvTimeout = float(recvTimeout)/100

        self.lhs = 1
        self.rhs = 1
        self.start_time = None
        self.reTX_num = 0
        self.coarse_TOs_num = 0
        self.tx_size = 0
        self.good_tx_size = 0

        self.time_lhs_stuck = time.time()
        self.window = {}

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        bytes_data = packet[3].to_bytes()
        seq_num = int.from_bytes(bytes_data[0:4], 'big')
        self.window[seq_num].is_ACKd = True

        if seq_num == self.lhs:
            self.lhs += 1
            self.time_lhs_stuck = time.time()

        total_time = time.time()-self.start_time
        print('Total TX time (seconds):{}\n'.format(total_time))
        print('Number of reTx: {}\n'.format(self.reTX_num))
        print('Number of coarse TOs: {}\n'.format(self.coarse_TOs_num))
        print('Throughputs (Bps):{}\n'.format(self.tx_size / total_time))
        print('Goodput (Bps): {}\n'.format(self.good_tx_size / total_time))

    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        cur_time = time.time()

        if self.time_lhs_stuck + self.timeout > cur_time:
            self.coarse_TOs_num += 1
            self.time_lhs_stuck = cur_time

        i = self.lhs
        while i < self.rhs:
            if not self.window[i].is_ACKd:
                self.tx_size += len((self.window[i].pkt)[3].to_bytes())
                self.reTX_num += 1
                self.net.send_packet('blaster-eth0', self.window[i].pkt)
                self.window[i].timestamp = cur_time
            i += 1

        if self.lhs > self.num:
            self.shutdown()

        if self.rhs - self.lhs + 1 <= self.senderWindow and self.rhs <= self.num:

            # Creating the headers for the packet
            pkt = Ethernet() + IPv4() + UDP()
            pkt[1].protocol = IPProtocol.UDP

            # Do other things here and send packet
            pkt[0].src = BLASTER_MAC
            pkt[0].dst = MIDDLEBOX_BLASTER_MAC
            pkt[1].src = BLASTER_IP
            pkt[1].dst = BLASTEE_IP
            pkt[2].src = 1234
            pkt[2].dst = 5678

            seq_bytes = self.rhs.to_bytes(4,'big')
            payload = '0'*self.length
            payload_bytes = payload.encode('utf-8','ignore')
            length_bytes = len(payload_bytes).to_bytes(2,'big')
            content = RawPacketContents(seq_bytes+length_bytes+payload_bytes)

            pkt = pkt + content

            self.tx_size += len(content.to_bytes())
            self.good_tx_size += len(content.to_bytes())

            win_pkt = Packet_Window(pkt, True, False, time.time())

            self.window[self.rhs] = win_pkt
            self.rhs += 1

            if self.start_time is None:
                self.start_time = time.time()
            
            self.net.send_packet('blaster-eth0',pkt)



    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
