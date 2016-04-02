#!/usr/bin/python3
import codecs
import socket
import struct
import uuid
import argparse
import re

BROADCAST_MAC = b'\xff' * 6

ARP_BROADCAST_MAC = b'\x00' * 6

__author__ = 'eshel'


MAC_RE = re.compile('([0-9a-fA-F]{2})[-:.]?([0-9a-fA-F]{2})[-:.]([0-9a-fA-F]{2})[-:.]?([0-9a-fA-F]{2})[-:.]([0-9a-fA-F]{2})[-:.]?([0-9a-fA-F]{2})')


def get_local_mac_address():
    """

    :return:
    """
    int_mac_addr = uuid.getnode()
    bytes_mac_addr = struct.pack('>IH', int_mac_addr >> 8*2, int_mac_addr % 2**16)
    return bytes_mac_addr


def ip_str_to_bytes(ip):
    """
    """

    return struct.pack('BBBB', *[int(x) for x in ip.split('.')])


def mac_str_to_bytes(mac):
    """
    """

    return struct.pack('BBBBBB', *[int(x, 16) for x in MAC_RE.findall(mac)[0]])


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
        :type dst_ip: str
        :param dst_mac:
        :type dst_mac: str
        :param src_ip:
        :type src_ip: str
        :param src_mac:
        :type src_mac: str
        :param payload:
        :type payload: bytes
        :return:
        """
        self.dst_ip = ip_str_to_bytes(dst_ip)
        self.dst_mac = mac_str_to_bytes(dst_mac) if dst_mac else ARP_BROADCAST_MAC
        self.eth_dst_mac = mac_str_to_bytes(eth_dst_mac) if eth_dst_mac else BROADCAST_MAC
        self.src_ip = ip_str_to_bytes(src_ip) if src_ip else struct.pack('BBBB',
                                               *[int(x) for x in socket.gethostbyname(socket.gethostname()).split('.')])
        self.src_mac = mac_str_to_bytes(src_mac) if src_mac else get_local_mac_address()
        self.eth_src_mac = mac_str_to_bytes(eth_src_mac) if eth_src_mac else get_local_mac_address()
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
        packet += self.dst_ip
        packet += self.payload
        return packet


def parse_args():
    """
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', required=True)
    parser.add_argument('-d', '--arp-dst-ip', required=True)
    parser.add_argument('-s', '--arp-src-ip')
    parser.add_argument('--arp-dst-mac')
    parser.add_argument('--arp-src-mac')
    parser.add_argument('--dst-mac')
    parser.add_argument('--src-mac')
    padding_group = parser.add_mutually_exclusive_group()
    padding_group.add_argument('-p', '--padding', type=lambda s: bytes(s, 'ASCII'))
    padding_group.add_argument('-P', '--hex-padding', type=lambda s: codecs.encode(s, 'hex'))

    args = parser.parse_args()

    return args


def main():
    """

    :return:
    """

    cmd_args = parse_args()

    interface = cmd_args.interface
    dst_ip = cmd_args.arp_dst_ip
    src_ip = cmd_args.arp_src_ip
    dst_mac = cmd_args.arp_dst_mac
    src_mac = cmd_args.arp_src_mac
    eth_dst_mac = cmd_args.dst_mac
    eth_src_mac = cmd_args.src_mac
    padding = cmd_args.padding or cmd_args.hex_padding

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((interface, 0))

    packet = ArpPacket(dst_ip, dst_mac, eth_dst_mac, src_ip, src_mac, eth_src_mac, padding)

    sock.send(packet.packet)


if __name__ == '__main__':
    main()
