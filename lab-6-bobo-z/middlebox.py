#!/usr/bin/env python3

import time
import threading
from random import randint, uniform

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

BLASTER_MAC = '10:00:00:00:00:01'
BLASTEE_MAC = '20:00:00:00:00:01'


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)

    def drop(self):
        '''
        Should I drop the packets according to the dropRate?
        '''
        return uniform(0.0, 1.0) < self.dropRate

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if not self.drop():
                log_debug("Send to blastee")
                packet[Ethernet].src = self.net.interface_by_name(
                    'middlebox-eth1').ethaddr
                packet[Ethernet].dst = BLASTEE_MAC
                self.net.send_packet("middlebox-eth1", packet)
            else:
                log_debug("Drop the packet")
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            packet[Ethernet].src = self.net.interface_by_name(
                'middlebox-eth0').ethaddr
            packet[Ethernet].dst = BLASTER_MAC
            self.net.send_packet("middlebox-eth0", packet)
        else:
            log_debug("Oops :))")

    def start(self):
        '''A running daemon of the router.
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
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
