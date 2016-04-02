import os
import random
import datetime
import struct

import math

ONE_MILION = 1000000

MAXIMUM_YEAR = 2016

MINIMUM_YEAR = 2015


def n_bytes_from_file(file, n):
    """
    """
    current_bytes = file.read(n)
    while True:
        yield current_bytes
        current_bytes = current_bytes[1:] + file.read(1)


def timestamp_from_eight_bytes(eight_bytes):
    """
    """
    try:
        assert len(eight_bytes) == 8
    except AssertionError:
        raise ValueError('argument eight_bytes expected len 8, got len %d' % len(eight_bytes))
    whole, fraction = struct.unpack('II', eight_bytes)
    assert fraction < ONE_MILION
    return whole + (fraction / ONE_MILION)


def sync_with_cap(cap_file, **hints):
    """
    """
    buffer = b''

    def is_datetime_plausible(dt):
        return MINIMUM_YEAR <= dt.year <= MAXIMUM_YEAR

    iterator = n_bytes_from_file(cap_file, 4)
    for pointer, bytes_string in enumerate(iterator):
        inferred_sniff_datetime = datetime.datetime.fromtimestamp(struct.unpack('<I', bytes_string)[0])
        if is_datetime_plausible(inferred_sniff_datetime):
            print(pointer)
            print(inferred_sniff_datetime)
            buffer += bytes_string  # save 'whole' part of the timestamp
            buffer += cap_file.read(4)  # now save 'fraction' part of the timestamp
            print(datetime.datetime.fromtimestamp(timestamp_from_eight_bytes(buffer)))
            supposed_four_bytes_packet_saved_length = cap_file.read(4)
            supposed_packet_saved_length = struct.unpack('<I', supposed_four_bytes_packet_saved_length)[0]
            print(supposed_packet_saved_length)
            supposed_four_bytes_packet_original_length = cap_file.read(4)
            supposed_packet_original_length = struct.unpack('<I', supposed_four_bytes_packet_original_length)[0]
            print(supposed_packet_original_length)
            supposed_raw_packet_data = cap_file.read(supposed_packet_saved_length)
            supposed_eight_bytes_next_packet_timestamp = cap_file.read(8)
            if is_datetime_plausible(datetime.datetime.fromtimestamp(
                    timestamp_from_eight_bytes(supposed_eight_bytes_next_packet_timestamp))):
                print(datetime.datetime.fromtimestamp(
                    timestamp_from_eight_bytes(supposed_eight_bytes_next_packet_timestamp)))
                return cap_file
            return

print(sync_with_cap(open('../data/test.cap', 'rb')))
