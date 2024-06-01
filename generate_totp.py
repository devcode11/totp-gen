#! /usr/bin/python3

import hashlib
import datetime
import base64
import hmac
import getpass
import sys

INTERVAL = 30
DIGITS = 6
DIGEST = hashlib.sha1

def current_timecode():
    current_time = datetime.datetime.now(datetime.timezone.utc)
    timecode = int(current_time.timestamp()) // INTERVAL
    return timecode

def get_hotp(secret, counter):
    secret_val = base64.b32decode(secret, casefold = True)
    secret_bytes = bytearray()
    while counter:
        secret_bytes.append(counter & 0xFF)
        counter >>= 8
    counter_bytes = bytes(bytearray(reversed(secret_bytes)).rjust(8, b'\0'))

    hash_bytes = bytearray(hmac.new(secret_val, counter_bytes, DIGEST).digest())

    offset = hash_bytes[-1] & 0xF

    result_code = (
        (hash_bytes[offset] & 0x7F) << 24 |
        (hash_bytes[offset + 1] & 0xFF) << 16 |
        (hash_bytes[offset + 2] & 0xFF) << 8 |
        (hash_bytes[offset + 3] & 0xFF)
    )

    str_code = str(100000000000 + (result_code % (10 ** DIGITS)))
    return str_code[-DIGITS:]


def get_totp(secret):
    return get_hotp(secret, current_timecode())


def read_secret():
    paswd = getpass.getpass()
    if len(paswd) == 0:
        raise ValueError('Secret is empty')
    return paswd


if __name__ == '__main__':
    try:
        print(get_totp(read_secret()))
    except Exception as e:
        print(e, file = sys.stderr)
