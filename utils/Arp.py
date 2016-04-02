#!/usr/bin/python3.4

__author__ = 'eshel'

import socket
import struct
import uuid
import codecs
import argparse


def get_local_mac_address():
    """

    :return:
    """
    int_mac_addr = uuid.getnode()
    bytes_mac_addr = struct.pack('>IH', int_mac_addr >> 8*2, int_mac_addr % 2**16)
    return bytes_mac_addr


class ArpPacket(object):
    """

    """
    ARP_ETHERNET_TYPE = b'\x08\x06'
    IP_ETHERNET_TYPE = b'\x08\x00'
    HARDWARE_TYPE = b'\x00\x01'
    HARDWARE_SIZE = b'\x06'
    PROTOCOL_SIZE = b'\x04'
    REQUEST_OPCODE = b'\x00\x01'

    def __init__(self, dst_ip, dst_mac=None, eth_dst_mac=None,
                 src_ip=None, src_mac=None, eth_src_mac=None, payload=None):
        """

        :param dst_ip:
        :param dst_mac:
        :param src_ip:
        :param src_mac:
        :param payload:
        :return:
        """
        self.dst_ip = dst_ip
        self.dst_mac = dst_mac or b'\x00' * 6
        self.eth_dst_mac = eth_dst_mac or b'\xff' * 6
        self.src_ip = src_ip or struct.pack('BBBB',
                                            *[int(x) for x in socket.gethostbyname(socket.gethostname()).split('.')])
        self.src_mac = src_mac or get_local_mac_address()
        self.eth_src_mac = eth_src_mac or get_local_mac_address()
        self.payload = payload or b''
        self.packet = self._construct_packet()

    def _construct_packet(self):
        """

        :return:
        """
        packet = b''
        packet += self.eth_dst_mac
        packet += self.eth_src_mac
        packet += ArpPacket.ARP_ETHERNET_TYPE
        packet += ArpPacket.HARDWARE_TYPE
        packet += ArpPacket.IP_ETHERNET_TYPE
        packet += ArpPacket.HARDWARE_SIZE
        packet += ArpPacket.PROTOCOL_SIZE
        packet += ArpPacket.REQUEST_OPCODE
        packet += self.src_mac
        packet += self.src_ip
        packet += self.dst_mac
        packet += struct.pack('BBBB', *[int(x) for x in self.dst_ip.split('.')])
        packet += self.payload
        return packet


def main():
    """

    :return:
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dst-ip', required=True)
    parser.add_argument('-i', '--interface', required=True)

    args = parser.parse_args()

    packet = ArpPacket(args.dst_ip)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((args.interface, 0))
    sock.send(packet.packet)


if __name__ == '__main__':
    main()
