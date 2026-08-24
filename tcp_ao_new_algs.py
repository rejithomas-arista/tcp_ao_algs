#!/usr/bin/env python3
"""
TCP-AO New Algorithms: Implementation & Test Vector Generation

Implements draft-ietf-tcpm-tcp-ao-algs-06:
  - HMAC-SHA256-128 with HKDF-SHA256 KDF
  - KMAC256-128 with KMAC256-KDF (SP 800-56Cr2)

Validates against RFC 9235 known-good test vectors, then generates
64 new test vectors (32 provisional + 32 conformant).
"""

import hmac
import hashlib
import os
import struct
import json
import sys
import subprocess

from Crypto.Hash import CMAC, KMAC256
from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MASTER_KEY_80 = b"testvector"                          # RFC 9235, 80 bits
MASTER_KEY_256 = b"testvector-256-bit-key-tcp-ao!!!"   # 256 bits, conformant

CLIENT_IPV4 = bytes([10, 11, 12, 13])
SERVER_IPV4 = bytes([172, 27, 28, 29])
CLIENT_IPV6 = b'\xfd' + b'\x00' * 14 + b'\x01'
SERVER_IPV6 = b'\xfd' + b'\x00' * 14 + b'\x02'

CLIENT_KEYID = 0x3d   # 61
SERVER_KEYID = 0x54   # 84

SERVER_PORT = 179      # BGP

TCP_AO_KIND = 29
SNE = b'\x00\x00\x00\x00'

IPPROTO_TCP = 6

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str.replace(' ', '').replace('\n', ''))

def fmt_hex(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        lines.append(' '.join(f'{b:02x}' for b in chunk))
    return '\n'.join(lines)

def internet_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i+1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

# ---------------------------------------------------------------------------
# KDF Context (RFC 5925 §5.2)
# ---------------------------------------------------------------------------

def build_kdf_context(src_ip, dst_ip, src_port, dst_port, src_isn, dst_isn):
    return (src_ip + dst_ip +
            struct.pack('!HH', src_port, dst_port) +
            struct.pack('!II', src_isn, dst_isn))

# ---------------------------------------------------------------------------
# Pseudo-headers for MAC computation (RFC 5925 §5.1)
# ---------------------------------------------------------------------------

def ipv4_pseudo_header(src_ip, dst_ip, tcp_length):
    return src_ip + dst_ip + struct.pack('!BBH', 0, IPPROTO_TCP, tcp_length)

def ipv6_pseudo_header(src_ip, dst_ip, tcp_length):
    return src_ip + dst_ip + struct.pack('!I', tcp_length) + b'\x00\x00\x00' + bytes([IPPROTO_TCP])

# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

def parse_ipv4_packet(raw):
    ihl = (raw[0] & 0x0f) * 4
    total_len = struct.unpack('!H', raw[2:4])[0]
    src_ip = raw[12:16]
    dst_ip = raw[16:20]
    tcp_start = ihl
    tcp_data = raw[tcp_start:]
    return {
        'ip_version': 4,
        'ip_header': bytearray(raw[:ihl]),
        'ihl': ihl,
        'total_len': total_len,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'tcp_and_payload': bytearray(tcp_data),
    }

def parse_ipv6_packet(raw):
    payload_len = struct.unpack('!H', raw[4:6])[0]
    src_ip = raw[8:24]
    dst_ip = raw[24:40]
    tcp_start = 40
    tcp_data = raw[tcp_start:]
    return {
        'ip_version': 6,
        'ip_header': bytearray(raw[:40]),
        'payload_len': payload_len,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'tcp_and_payload': bytearray(tcp_data),
    }

def parse_tcp(tcp_bytes):
    src_port = struct.unpack('!H', tcp_bytes[0:2])[0]
    dst_port = struct.unpack('!H', tcp_bytes[2:4])[0]
    seq = struct.unpack('!I', tcp_bytes[4:8])[0]
    ack = struct.unpack('!I', tcp_bytes[8:12])[0]
    data_offset = (tcp_bytes[12] >> 4) * 4
    flags = struct.unpack('!H', tcp_bytes[12:14])[0] & 0x01ff
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': seq,
        'ack': ack,
        'data_offset': data_offset,
        'flags': flags,
        'header_bytes': bytearray(tcp_bytes[:data_offset]),
        'payload': bytearray(tcp_bytes[data_offset:]),
    }

def find_tcp_ao_option(tcp_header_bytes):
    """Find TCP-AO option in TCP header, return (offset, length)."""
    i = 20
    while i < len(tcp_header_bytes):
        kind = tcp_header_bytes[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(tcp_header_bytes):
            break
        opt_len = tcp_header_bytes[i + 1]
        if kind == TCP_AO_KIND:
            return i, opt_len
        i += opt_len
    return None, None

# ---------------------------------------------------------------------------
# MAC message construction (RFC 5925 §5.1)
# ---------------------------------------------------------------------------

def build_mac_message(ip_info, tcp_info, covers_options, mac_len):
    """Build the MAC input message per RFC 5925 §5.1.

    Args:
        ip_info: parsed IP info dict
        tcp_info: parsed TCP info dict
        covers_options: True = include all TCP options; False = omit non-AO options
        mac_len: length of the MAC field in bytes (12 for old, 16 for new)
    """
    tcp_header = bytearray(tcp_info['header_bytes'])
    tcp_len = len(tcp_info['header_bytes']) + len(tcp_info['payload'])

    # Build pseudo-header
    if ip_info['ip_version'] == 4:
        pseudo = ipv4_pseudo_header(ip_info['src_ip'], ip_info['dst_ip'], tcp_len)
    else:
        pseudo = ipv6_pseudo_header(ip_info['src_ip'], ip_info['dst_ip'], tcp_len)

    # Zero TCP checksum (bytes 16-17 of TCP header)
    tcp_header[16] = 0
    tcp_header[17] = 0

    # Find and zero TCP-AO MAC field
    ao_offset, ao_len = find_tcp_ao_option(tcp_header)
    if ao_offset is None:
        raise ValueError("TCP-AO option not found")

    mac_field_offset = ao_offset + 4  # skip Kind, Length, KeyID, RNextKeyID
    for j in range(mac_len):
        tcp_header[mac_field_offset + j] = 0

    if covers_options:
        tcp_for_mac = bytes(tcp_header)
    else:
        # Base TCP header (20 bytes) + TCP-AO option only
        base_header = bytes(tcp_header[:20])
        ao_option = bytes(tcp_header[ao_offset:ao_offset + ao_len])
        tcp_for_mac = base_header + ao_option

    return bytes(SNE) + bytes(pseudo) + tcp_for_mac + bytes(tcp_info['payload'])

# ---------------------------------------------------------------------------
# RFC 5926 KDFs (for baseline validation against RFC 9235)
# ---------------------------------------------------------------------------

def kdf_hmac_sha1(master_key, context, output_length_bits):
    """KDF using HMAC-SHA1 in counter mode (RFC 5926 §3.1.1)."""
    output_length_bytes = output_length_bits // 8
    prf_output_size = 20  # SHA-1 output = 160 bits
    iterations = (output_length_bytes + prf_output_size - 1) // prf_output_size
    result = b''
    label = b'TCP-AO'
    for i in range(1, iterations + 1):
        input_block = bytes([i]) + label + context + struct.pack('!H', output_length_bits)
        result += hmac.new(master_key, input_block, hashlib.sha1).digest()
    return result[:output_length_bytes]

def kdf_aes_128_cmac(master_key, context, output_length_bits):
    """KDF using AES-128-CMAC in counter mode (RFC 5926 §3.2)."""
    output_length_bytes = output_length_bits // 8
    prf_output_size = 16  # AES-CMAC output = 128 bits

    # Derive 128-bit key from variable-length master key (RFC 4615 §3)
    if len(master_key) == 16:
        derived_key = master_key
    else:
        c = CMAC.new(b'\x00' * 16, ciphermod=AES)
        c.update(master_key)
        derived_key = c.digest()

    iterations = (output_length_bytes + prf_output_size - 1) // prf_output_size
    result = b''
    label = b'TCP-AO'
    for i in range(1, iterations + 1):
        input_block = bytes([i]) + label + context + struct.pack('!H', output_length_bits)
        c = CMAC.new(derived_key, ciphermod=AES)
        c.update(input_block)
        result += c.digest()
    return result[:output_length_bytes]

# ---------------------------------------------------------------------------
# RFC 5926 MACs (for baseline validation against RFC 9235)
# ---------------------------------------------------------------------------

def mac_hmac_sha1_96(traffic_key, message):
    return hmac.new(traffic_key, message, hashlib.sha1).digest()[:12]

def mac_aes_128_cmac_96(traffic_key, message):
    c = CMAC.new(traffic_key, ciphermod=AES)
    c.update(message)
    return c.digest()[:12]

# ---------------------------------------------------------------------------
# New KDFs (draft-ietf-tcpm-tcp-ao-algs-06)
# ---------------------------------------------------------------------------

def kdf_hkdf_sha256(master_key, context):
    """HKDF-SHA256 KDF per draft §3.1.1 / RFC 5869."""
    salt = b'\x00' * 32
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    traffic_key = hmac.new(prk, context + b'\x01', hashlib.sha256).digest()
    return traffic_key

def kdf_kmac256(master_key, context):
    """KMAC256-KDF per draft §3.1.2 / SP 800-56Cr2 Option 3."""
    salt = b'\x00' * 132
    counter = b'\x00\x00\x00\x01'
    x = counter + master_key + context
    k = KMAC256.new(key=salt, data=x, mac_len=32, custom=b'KDF')
    return k.digest()

# ---------------------------------------------------------------------------
# New MACs (draft-ietf-tcpm-tcp-ao-algs-06)
# ---------------------------------------------------------------------------

def mac_hmac_sha256_128(traffic_key, message):
    """HMAC-SHA256 truncated to leftmost 128 bits."""
    return hmac.new(traffic_key, message, hashlib.sha256).digest()[:16]

def mac_kmac256_128(traffic_key, message):
    """KMAC256 with L=128 bits, S="" (empty customization)."""
    k = KMAC256.new(key=traffic_key, data=message, mac_len=16, custom=b'')
    return k.digest()

# ---------------------------------------------------------------------------
# RFC 9235 Test Vector Data
# ---------------------------------------------------------------------------

# Each scenario: (ip_version, algo_name, covers_options, packets)
# packets = [(client_isn, server_isn, client_port, packet_hex, expected_traffic_keys, expected_macs)]

RFC9235_VECTORS = {
    # Section 4.1: IPv4 HMAC-SHA-1-96, Covers Options
    'ipv4_sha1_covers': {
        'ip_version': 4,
        'kdf': kdf_hmac_sha1,
        'kdf_bits': 160,
        'mac_fn': mac_hmac_sha1_96,
        'mac_len': 12,
        'covers_options': True,
        'packets': [
            {
                'label': 'Send SYN',
                'client_isn': 0xfbfbab5a,
                'server_isn': 0x11c14261,
                'hex': '45 e0 00 4c dd 0f 40 00 ff 06 bf 6b 0a 0b 0c 0d'
                       'ac 1b 1c 1d e9 d7 00 b3 fb fb ab 5a 00 00 00 00'
                       'e0 02 ff ff ca c4 00 00 02 04 05 b4 01 03 03 08'
                       '04 02 08 0a 00 15 5a b7 00 00 00 00 1d 10 3d 54'
                       '2e e4 37 c6 f8 ed e6 d7 c4 d6 02 e7',
                'traffic_key': '6d 63 ef 1b 02 fe 15 09 d4 b1 40 27 07 fd 7b 04 16 ab b7 4f',
                'mac': '2e e4 37 c6 f8 ed e6 d7 c4 d6 02 e7',
                'key_type': 'send_syn',
            },
            {
                'label': 'Receive SYN-ACK',
                'client_isn': 0xfbfbab5a,
                'server_isn': 0x11c14261,
                'hex': '45 e0 00 4c 65 06 40 00 ff 06 37 75 ac 1b 1c 1d'
                       '0a 0b 0c 0d 00 b3 e9 d7 11 c1 42 61 fb fb ab 5b'
                       'e0 12 ff ff 37 76 00 00 02 04 05 b4 01 03 03 08'
                       '04 02 08 0a 84 a5 0b eb 00 15 5a b7 1d 10 54 3d'
                       'ee ab 0f e2 4c 30 10 81 51 16 b3 be',
                'traffic_key': 'd9 e2 17 e4 83 4a 80 ca 2f 3f d8 de 2e 41 b8 e6 79 7f ea 96',
                'mac': 'ee ab 0f e2 4c 30 10 81 51 16 b3 be',
                'key_type': 'recv_other',
            },
            {
                'label': 'Send Non-SYN',
                'client_isn': 0xfbfbab5a,
                'server_isn': 0x11c14261,
                'hex': '45 e0 00 87 36 a1 40 00 ff 06 65 9f 0a 0b 0c 0d'
                       'ac 1b 1c 1d e9 d7 00 b3 fb fb ab 5b 11 c1 42 62'
                       'c0 18 01 04 a1 62 00 00 01 01 08 0a 00 15 5a c1'
                       '84 a5 0b eb 1d 10 3d 54 70 64 cf 99 8c c6 c3 15'
                       'c2 c2 e2 bf ff ff ff ff ff ff ff ff ff ff ff ff'
                       'ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d'
                       '26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02'
                       '00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40'
                       '06 00 64 00 01 01 00',
                'traffic_key': 'd2 e5 9c 65 ff c7 b1 a3 93 47 65 64 63 b7 0e dc 24 a1 3d 71',
                'mac': '70 64 cf 99 8c c6 c3 15 c2 c2 e2 bf',
                'key_type': 'send_other',
            },
            {
                'label': 'Receive Non-SYN',
                'client_isn': 0xfbfbab5a,
                'server_isn': 0x11c14261,
                'hex': '45 e0 00 87 1f a9 40 00 ff 06 7c 97 ac 1b 1c 1d'
                       '0a 0b 0c 0d 00 b3 e9 d7 11 c1 42 62 fb fb ab 9e'
                       'c0 18 01 00 40 0c 00 00 01 01 08 0a 84 a5 0b f5'
                       '00 15 5a c1 1d 10 54 3d a6 3f 0e cb bb 2e 63 5c'
                       '95 4d ea c7 ff ff ff ff ff ff ff ff ff ff ff ff'
                       'ff ff ff ff 00 43 01 04 da c0 00 b4 ac 1b 1c 1d'
                       '26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02'
                       '00 02 02 42 00 02 06 41 04 00 00 da c0 02 08 40'
                       '06 00 64 00 01 01 00',
                'traffic_key': 'd9 e2 17 e4 83 4a 80 ca 2f 3f d8 de 2e 41 b8 e6 79 7f ea 96',
                'mac': 'a6 3f 0e cb bb 2e 63 5c 95 4d ea c7',
                'key_type': 'recv_other',
            },
        ],
    },
    # Section 4.2: IPv4 HMAC-SHA-1-96, Omits Options
    'ipv4_sha1_omits': {
        'ip_version': 4,
        'kdf': kdf_hmac_sha1,
        'kdf_bits': 160,
        'mac_fn': mac_hmac_sha1_96,
        'mac_len': 12,
        'covers_options': False,
        'packets': [
            {
                'label': 'Send SYN',
                'client_isn': 0xcb0efbee,
                'server_isn': 0xacd5b5e1,
                'hex': '45 e0 00 4c 53 99 40 00 ff 06 48 e2 0a 0b 0c 0d'
                       'ac 1b 1c 1d ff 12 00 b3 cb 0e fb ee 00 00 00 00'
                       'e0 02 ff ff 54 1f 00 00 02 04 05 b4 01 03 03 08'
                       '04 02 08 0a 00 02 4c ce 00 00 00 00 1d 10 3d 54'
                       '80 af 3c fe b8 53 68 93 7b 8f 9e c2',
                'traffic_key': '30 ea a1 56 0c f0 be 57 da b5 c0 45 22 9f b1 0a 42 3c d7 ea',
                'mac': '80 af 3c fe b8 53 68 93 7b 8f 9e c2',
                'key_type': 'send_syn',
            },
            {
                'label': 'Receive SYN-ACK',
                'client_isn': 0xcb0efbee,
                'server_isn': 0xacd5b5e1,
                'hex': '45 e0 00 4c 32 84 40 00 ff 06 69 f7 ac 1b 1c 1d'
                       '0a 0b 0c 0d 00 b3 ff 12 ac d5 b5 e1 cb 0e fb ef'
                       'e0 12 ff ff 38 8e 00 00 02 04 05 b4 01 03 03 08'
                       '04 02 08 0a 57 67 72 f3 00 02 4c ce 1d 10 54 3d'
                       '09 30 6f 9a ce a6 3a 8c 68 cb 9a 70',
                'traffic_key': 'b5 b2 89 6b b3 66 4e 81 76 b0 ed c6 e7 99 52 41 01 a8 30 7f',
                'mac': '09 30 6f 9a ce a6 3a 8c 68 cb 9a 70',
                'key_type': 'recv_other',
            },
            {
                'label': 'Send Non-SYN',
                'client_isn': 0xcb0efbee,
                'server_isn': 0xacd5b5e1,
                'hex': '45 e0 00 87 a8 f5 40 00 ff 06 f3 4a 0a 0b 0c 0d'
                       'ac 1b 1c 1d ff 12 00 b3 cb 0e fb ef ac d5 b5 e2'
                       'c0 18 01 04 6c 45 00 00 01 01 08 0a 00 02 4c ce'
                       '57 67 72 f3 1d 10 3d 54 71 06 08 cc 69 6c 03 a2'
                       '71 c9 3a a5 ff ff ff ff ff ff ff ff ff ff ff ff'
                       'ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d'
                       '26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02'
                       '00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40'
                       '06 00 64 00 01 01 00',
                'traffic_key': 'f3 db 17 93 d7 91 0e cd 80 6c 34 f1 55 ea 1f 00 34 59 53 e3',
                'mac': '71 06 08 cc 69 6c 03 a2 71 c9 3a a5',
                'key_type': 'send_other',
            },
            {
                'label': 'Receive Non-SYN',
                'client_isn': 0xcb0efbee,
                'server_isn': 0xacd5b5e1,
                'hex': '45 e0 00 87 54 37 40 00 ff 06 48 09 ac 1b 1c 1d'
                       '0a 0b 0c 0d 00 b3 ff 12 ac d5 b5 e2 cb 0e fc 32'
                       'c0 18 01 00 46 b6 00 00 01 01 08 0a 57 67 72 f3'
                       '00 02 4c ce 1d 10 54 3d 97 76 6e 48 ac 26 2d e9'
                       'ae 61 b4 f9 ff ff ff ff ff ff ff ff ff ff ff ff'
                       'ff ff ff ff 00 43 01 04 da c0 00 b4 ac 1b 1c 1d'
                       '26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02'
                       '00 02 02 42 00 02 06 41 04 00 00 da c0 02 08 40'
                       '06 00 64 00 01 01 00',
                'traffic_key': 'b5 b2 89 6b b3 66 4e 81 76 b0 ed c6 e7 99 52 41 01 a8 30 7f',
                'mac': '97 76 6e 48 ac 26 2d e9 ae 61 b4 f9',
                'key_type': 'recv_other',
            },
        ],
    },
    # Section 5.1: IPv4 AES-128-CMAC-96, Covers Options
    'ipv4_aes_covers': {
        'ip_version': 4,
        'kdf': kdf_aes_128_cmac,
        'kdf_bits': 128,
        'mac_fn': mac_aes_128_cmac_96,
        'mac_len': 12,
        'covers_options': True,
        'packets': [
            {
                'label': 'Send SYN',
                'client_isn': 0x787a1ddf,
                'server_isn': 0xfadd6de9,
                'hex': '45 e0 00 4c 7b 9f 40 00 ff 06 20 dc 0a 0b 0c 0d'
                       'ac 1b 1c 1d c4 fa 00 b3 78 7a 1d df 00 00 00 00'
                       'e0 02 ff ff 5a 0f 00 00 02 04 05 b4 01 03 03 08'
                       '04 02 08 0a 00 01 7e d0 00 00 00 00 1d 10 3d 54'
                       'e4 77 e9 9c 80 40 76 54 98 e5 50 91',
                'traffic_key': 'f5 b8 b3 d5 f3 4f db b6 eb 8d 4a b9 66 0e 60 e3',
                'mac': 'e4 77 e9 9c 80 40 76 54 98 e5 50 91',
                'key_type': 'send_syn',
            },
            {
                'label': 'Receive SYN-ACK',
                'client_isn': 0x787a1ddf,
                'server_isn': 0xfadd6de9,
                'hex': '45 e0 00 4c 4b ad 40 00 ff 06 50 ce ac 1b 1c 1d'
                       '0a 0b 0c 0d 00 b3 c4 fa fa dd 6d e9 78 7a 1d e0'
                       'e0 12 ff ff f3 f2 00 00 02 04 05 b4 01 03 03 08'
                       '04 02 08 0a 93 f4 e9 e8 00 01 7e d0 1d 10 54 3d'
                       'd6 ad a7 bc 4c dd 53 6d 17 69 db 5f',
                'traffic_key': '4b c7 57 1a 48 6f 32 64 bb d8 88 47 40 66 b4 b1',
                'mac': 'd6 ad a7 bc 4c dd 53 6d 17 69 db 5f',
                'key_type': 'recv_other',
            },
            {
                'label': 'Send Non-SYN',
                'client_isn': 0x787a1ddf,
                'server_isn': 0xfadd6de9,
                'hex': '45 e0 00 87 fb 4f 40 00 ff 06 a0 f0 0a 0b 0c 0d'
                       'ac 1b 1c 1d c4 fa 00 b3 78 7a 1d e0 fa dd 6d ea'
                       'c0 18 01 04 95 05 00 00 01 01 08 0a 00 01 7e d0'
                       '93 f4 e9 e8 1d 10 3d 54 77 41 27 42 fa 4d c4 33'
                       'ef f0 97 3e ff ff ff ff ff ff ff ff ff ff ff ff'
                       'ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d'
                       '26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02'
                       '00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40'
                       '06 00 64 00 01 01 00',
                'traffic_key': '8c 8a e0 e8 37 1e c5 cb b9 7e a7 9d 90 41 83 91',
                'mac': '77 41 27 42 fa 4d c4 33 ef f0 97 3e',
                'key_type': 'send_other',
            },
            {
                'label': 'Receive Non-SYN',
                'client_isn': 0x787a1ddf,
                'server_isn': 0xfadd6de9,
                'hex': '45 e0 00 87 b9 14 40 00 ff 06 e3 2b ac 1b 1c 1d'
                       '0a 0b 0c 0d 00 b3 c4 fa fa dd 6d ea 78 7a 1e 23'
                       'c0 18 01 00 e7 db 00 00 01 01 08 0a 93 f4 e9 e8'
                       '00 01 7e d0 1d 10 54 3d f6 d9 65 a7 83 82 a7 48'
                       '45 f7 2d ac ff ff ff ff ff ff ff ff ff ff ff ff'
                       'ff ff ff ff 00 43 01 04 da c0 00 b4 ac 1b 1c 1d'
                       '26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02'
                       '00 02 02 42 00 02 06 41 04 00 00 da c0 02 08 40'
                       '06 00 64 00 01 01 00',
                'traffic_key': '4b c7 57 1a 48 6f 32 64 bb d8 88 47 40 66 b4 b1',
                'mac': 'f6 d9 65 a7 83 82 a7 48 45 f7 2d ac',
                'key_type': 'recv_other',
            },
        ],
    },
    # Section 5.2: IPv4 AES-128-CMAC-96, Omits Options
    'ipv4_aes_omits': {
        'ip_version': 4,
        'kdf': kdf_aes_128_cmac,
        'kdf_bits': 128,
        'mac_fn': mac_aes_128_cmac_96,
        'mac_len': 12,
        'covers_options': False,
        'packets': [
            {
                'label': 'Send SYN',
                'client_isn': 0x389bed71,
                'server_isn': 0xd3844a6f,
                'hex': '45 e0 00 4c f2 2e 40 00 ff 06 aa 4c 0a 0b 0c 0d'
                       'ac 1b 1c 1d da 1c 00 b3 38 9b ed 71 00 00 00 00'
                       'e0 02 ff ff 70 bf 00 00 02 04 05 b4 01 03 03 08'
                       '04 02 08 0a 00 01 85 e1 00 00 00 00 1d 10 3d 54'
                       'c4 4e 60 cb 31 f7 c0 b1 de 3d 27 49',
                'traffic_key': '2c db ae 13 92 c4 94 49 fa 92 c4 50 97 35 d5 0e',
                'mac': 'c4 4e 60 cb 31 f7 c0 b1 de 3d 27 49',
                'key_type': 'send_syn',
            },
            {
                'label': 'Receive SYN-ACK',
                'client_isn': 0x389bed71,
                'server_isn': 0xd3844a6f,
                'hex': '45 e0 00 4c 6c c0 40 00 ff 06 2f bb ac 1b 1c 1d'
                       '0a 0b 0c 0d 00 b3 da 1c d3 84 4a 6f 38 9b ed 72'
                       'e0 12 ff ff e4 45 00 00 02 04 05 b4 01 03 03 08'
                       '04 02 08 0a ce 45 98 38 00 01 85 e1 1d 10 54 3d'
                       '3a 6a bb 20 7e 49 b1 be 71 36 db 90',
                'traffic_key': '3c e6 7a 55 18 69 50 6b 63 47 b6 33 c5 0a 62 4a',
                'mac': '3a 6a bb 20 7e 49 b1 be 71 36 db 90',
                'key_type': 'recv_other',
            },
            {
                'label': 'Send Non-SYN',
                'client_isn': 0x389bed71,
                'server_isn': 0xd3844a6f,
                'hex': '45 e0 00 87 ee 91 40 00 ff 06 ad ae 0a 0b 0c 0d'
                       'ac 1b 1c 1d da 1c 00 b3 38 9b ed 72 d3 84 4a 70'
                       'c0 18 01 04 88 51 00 00 01 01 08 0a 00 01 85 e1'
                       'ce 45 98 38 1d 10 3d 54 75 85 e9 e9 d5 c3 ec 85'
                       '7b 96 f8 37 ff ff ff ff ff ff ff ff ff ff ff ff'
                       'ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d'
                       '26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02'
                       '00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40'
                       '06 00 64 00 01 01 00',
                'traffic_key': '03 5b c4 00 a3 41 ff e5 95 f5 9f 58 00 50 06 ca',
                'mac': '75 85 e9 e9 d5 c3 ec 85 7b 96 f8 37',
                'key_type': 'send_other',
            },
            {
                'label': 'Receive Non-SYN',
                'client_isn': 0x389bed71,
                'server_isn': 0xd3844a6f,
                'hex': '45 e0 00 87 6a 21 40 00 ff 06 32 1f ac 1b 1c 1d'
                       '0a 0b 0c 0d 00 b3 da 1c d3 84 4a 70 38 9b ed 72'
                       'c0 18 01 00 04 49 00 00 01 01 08 0a ce 45 98 38'
                       '00 01 85 e1 1d 10 54 3d 5c 04 0f d9 23 33 04 76'
                       '5c 09 82 f4 ff ff ff ff ff ff ff ff ff ff ff ff'
                       'ff ff ff ff 00 43 01 04 da c0 00 b4 ac 1b 1c 1d'
                       '26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02'
                       '00 02 02 42 00 02 06 41 04 00 00 da c0 02 08 40'
                       '06 00 64 00 01 01 00',
                'traffic_key': '3c e6 7a 55 18 69 50 6b 63 47 b6 33 c5 0a 62 4a',
                'mac': '5c 04 0f d9 23 33 04 76 5c 09 82 f4',
                'key_type': 'recv_other',
            },
        ],
    },
    # Section 6.1: IPv6 HMAC-SHA-1-96, Covers Options
    'ipv6_sha1_covers': {
        'ip_version': 6,
        'kdf': kdf_hmac_sha1,
        'kdf_bits': 160,
        'mac_fn': mac_hmac_sha1_96,
        'mac_len': 12,
        'covers_options': True,
        'packets': [
            {
                'label': 'Send SYN',
                'client_isn': 0x176a833f,
                'server_isn': 0x3f51994b,
                'hex': '6e 08 91 dc 00 38 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 f7 e4 00 b3 17 6a 83 3f'
                       '00 00 00 00 e0 02 ff ff 47 21 00 00 02 04 05 a0'
                       '01 03 03 08 04 02 08 0a 00 41 d0 87 00 00 00 00'
                       '1d 10 3d 54 90 33 ec 3d 73 34 b6 4c 5e dd 03 9f',
                'traffic_key': '62 5e c0 9d 57 58 36 ed c9 b6 42 84 18 bb f0 69 89 a3 61 bb',
                'mac': '90 33 ec 3d 73 34 b6 4c 5e dd 03 9f',
                'key_type': 'send_syn',
            },
            {
                'label': 'Receive SYN-ACK',
                'client_isn': 0x176a833f,
                'server_isn': 0x3f51994b,
                'hex': '6e 01 00 9e 00 38 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 00 b3 f7 e4 3f 51 99 4b'
                       '17 6a 83 40 e0 12 ff ff bf ec 00 00 02 04 05 a0'
                       '01 03 03 08 04 02 08 0a bd 33 12 9b 00 41 d0 87'
                       '1d 10 54 3d f1 cb a3 46 c3 52 61 63 f7 1f 1f 55',
                'traffic_key': 'e4 a3 7a da 2a 0a fc a8 71 14 34 91 3f e1 38 c7 71 eb cb 4a',
                'mac': 'f1 cb a3 46 c3 52 61 63 f7 1f 1f 55',
                'key_type': 'recv_other',
            },
            {
                'label': 'Send Non-SYN',
                'client_isn': 0x176a833f,
                'server_isn': 0x3f51994b,
                'hex': '6e 08 91 dc 00 73 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 f7 e4 00 b3 17 6a 83 40'
                       '3f 51 99 4c c0 18 01 00 32 9c 00 00 01 01 08 0a'
                       '00 41 d0 91 bd 33 12 9b 1d 10 3d 54 bf 08 05 fe'
                       'b4 ac 7b 16 3d 6f cd f2 ff ff ff ff ff ff ff ff'
                       'ff ff ff ff ff ff ff ff 00 43 01 04 fd e8 00 b4'
                       '01 01 01 79 26 02 06 01 04 00 01 00 01 02 02 80'
                       '00 02 02 02 00 02 02 42 00 02 06 41 04 00 00 fd'
                       'e8 02 08 40 06 00 64 00 01 01 00',
                'traffic_key': '1e d8 29 75 f4 ea 44 4c 61 58 0c 5b d9 0d bd 61 bb c9 1b 7e',
                'mac': 'bf 08 05 fe b4 ac 7b 16 3d 6f cd f2',
                'key_type': 'send_other',
            },
            {
                'label': 'Receive Non-SYN',
                'client_isn': 0x176a833f,
                'server_isn': 0x3f51994b,
                'hex': '6e 01 00 9e 00 73 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 00 b3 f7 e4 3f 51 99 4c'
                       '17 6a 83 83 c0 18 01 00 ee 6e 00 00 01 01 08 0a'
                       'bd 33 12 a5 00 41 d0 91 1d 10 54 3d 6c 48 12 5c'
                       '11 33 5b ab 9a 07 a7 97 ff ff ff ff ff ff ff ff'
                       'ff ff ff ff ff ff ff ff 00 43 01 04 fd e8 00 b4'
                       '01 01 01 7a 26 02 06 01 04 00 01 00 01 02 02 80'
                       '00 02 02 02 00 02 02 42 00 02 06 41 04 00 00 fd'
                       'e8 02 08 40 06 00 64 00 01 01 00',
                'traffic_key': 'e4 a3 7a da 2a 0a fc a8 71 14 34 91 3f e1 38 c7 71 eb cb 4a',
                'mac': '6c 48 12 5c 11 33 5b ab 9a 07 a7 97',
                'key_type': 'recv_other',
            },
        ],
    },
    # Section 6.2: IPv6 HMAC-SHA-1-96, Omits Options
    'ipv6_sha1_omits': {
        'ip_version': 6,
        'kdf': kdf_hmac_sha1,
        'kdf_bits': 160,
        'mac_fn': mac_hmac_sha1_96,
        'mac_len': 12,
        'covers_options': False,
        'packets': [
            {
                'label': 'Send SYN',
                'client_isn': 0x020c1e69,
                'server_isn': 0xeba3734d,
                'hex': '6e 07 8f cd 00 38 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 c6 cd 00 b3 02 0c 1e 69'
                       '00 00 00 00 e0 02 ff ff a4 1a 00 00 02 04 05 a0'
                       '01 03 03 08 04 02 08 0a 00 9d b9 5b 00 00 00 00'
                       '1d 10 3d 54 88 56 98 b0 53 0e d4 d5 a1 5f 83 46',
                'traffic_key': '31 a3 fa f6 9e ff ae 52 93 1b 7f 84 54 67 31 5c 27 0a 4e dc',
                'mac': '88 56 98 b0 53 0e d4 d5 a1 5f 83 46',
                'key_type': 'send_syn',
            },
            {
                'label': 'Receive SYN-ACK',
                'client_isn': 0x020c1e69,
                'server_isn': 0xeba3734d,
                'hex': '6e 0a 7e 1f 00 38 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 00 b3 c6 cd eb a3 73 4d'
                       '02 0c 1e 6a e0 12 ff ff 77 4d 00 00 02 04 05 a0'
                       '01 03 03 08 04 02 08 0a 5e c9 9b 70 00 9d b9 5b'
                       '1d 10 54 3d 3c 54 6b ad 97 43 f1 2d f8 b8 01 0d',
                'traffic_key': '40 51 08 94 7f 99 65 75 e7 bd bc 26 d4 02 16 a2 c7 fa 91 bd',
                'mac': '3c 54 6b ad 97 43 f1 2d f8 b8 01 0d',
                'key_type': 'recv_other',
            },
            {
                'label': 'Send Non-SYN',
                'client_isn': 0x020c1e69,
                'server_isn': 0xeba3734d,
                'hex': '6e 07 8f cd 00 73 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 c6 cd 00 b3 02 0c 1e 6a'
                       'eb a3 73 4e c0 18 01 00 83 e6 00 00 01 01 08 0a'
                       '00 9d b9 65 5e c9 9b 70 1d 10 3d 54 48 bd 09 3b'
                       '19 24 e0 01 19 2f 5b f0 ff ff ff ff ff ff ff ff'
                       'ff ff ff ff ff ff ff ff 00 43 01 04 fd e8 00 b4'
                       '01 01 01 79 26 02 06 01 04 00 01 00 01 02 02 80'
                       '00 02 02 02 00 02 02 42 00 02 06 41 04 00 00 fd'
                       'e8 02 08 40 06 00 64 00 01 01 00',
                'traffic_key': 'b3 4e ed 6a 93 96 a6 69 f1 c4 f4 f5 76 18 f3 65 6f 52 c7 ab',
                'mac': '48 bd 09 3b 19 24 e0 01 19 2f 5b f0',
                'key_type': 'send_other',
            },
            {
                'label': 'Receive Non-SYN',
                'client_isn': 0x020c1e69,
                'server_isn': 0xeba3734d,
                'hex': '6e 0a 7e 1f 00 73 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 00 b3 c6 cd eb a3 73 4e'
                       '02 0c 1e ad c0 18 01 00 71 6a 00 00 01 01 08 0a'
                       '5e c9 9b 7a 00 9d b9 65 1d 10 54 3d 55 9a 81 94'
                       '45 b4 fd e9 8d 9e 13 17 ff ff ff ff ff ff ff ff'
                       'ff ff ff ff ff ff ff ff 00 43 01 04 fd e8 00 b4'
                       '01 01 01 7a 26 02 06 01 04 00 01 00 01 02 02 80'
                       '00 02 02 02 00 02 02 42 00 02 06 41 04 00 00 fd'
                       'e8 02 08 40 06 00 64 00 01 01 00',
                'traffic_key': '40 51 08 94 7f 99 65 75 e7 bd bc 26 d4 02 16 a2 c7 fa 91 bd',
                'mac': '55 9a 81 94 45 b4 fd e9 8d 9e 13 17',
                'key_type': 'recv_other',
            },
        ],
    },
    # Section 7.1: IPv6 AES-128-CMAC-96, Covers Options
    'ipv6_aes_covers': {
        'ip_version': 6,
        'kdf': kdf_aes_128_cmac,
        'kdf_bits': 128,
        'mac_fn': mac_aes_128_cmac_96,
        'mac_len': 12,
        'covers_options': True,
        'packets': [
            {
                'label': 'Send SYN',
                'client_isn': 0x193cccec,
                'server_isn': 0xa6744ecb,
                'hex': '6e 04 a7 06 00 38 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 f8 5a 00 b3 19 3c cc ec'
                       '00 00 00 00 e0 02 ff ff de 5d 00 00 02 04 05 a0'
                       '01 03 03 08 04 02 08 0a 13 e4 ab 99 00 00 00 00'
                       '1d 10 3d 54 59 b5 88 10 74 81 ac 6d c3 92 70 40',
                'traffic_key': 'fa 5a 21 08 88 2d 39 d0 c7 19 29 17 5a b1 b7 b8',
                'mac': '59 b5 88 10 74 81 ac 6d c3 92 70 40',
                'key_type': 'send_syn',
            },
            {
                'label': 'Receive SYN-ACK',
                'client_isn': 0x193cccec,
                'server_isn': 0xa6744ecb,
                'hex': '6e 06 15 20 00 38 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 00 b3 f8 5a a6 74 4e cb'
                       '19 3c cc ed e0 12 ff ff ea bb 00 00 02 04 05 a0'
                       '01 03 03 08 04 02 08 0a 71 da ab c8 13 e4 ab 99'
                       '1d 10 54 3d dc 28 43 a8 4e 78 a6 bc fd c5 ed 80',
                'traffic_key': 'cf 1b 1e 22 5e 06 a6 36 16 76 4a 06 7b 46 f4 b1',
                'mac': 'dc 28 43 a8 4e 78 a6 bc fd c5 ed 80',
                'key_type': 'recv_other',
            },
            {
                'label': 'Send Non-SYN',
                'client_isn': 0x193cccec,
                'server_isn': 0xa6744ecb,
                'hex': '6e 04 a7 06 00 73 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 f8 5a 00 b3 19 3c cc ed'
                       'a6 74 4e cc c0 18 01 00 32 80 00 00 01 01 08 0a'
                       '13 e4 ab a3 71 da ab c8 1d 10 3d 54 7b 6a 45 5c'
                       '0d 4f 5f 01 83 5b aa b3 ff ff ff ff ff ff ff ff'
                       'ff ff ff ff ff ff ff ff 00 43 01 04 fd e8 00 b4'
                       '01 01 01 79 26 02 06 01 04 00 01 00 01 02 02 80'
                       '00 02 02 02 00 02 02 42 00 02 06 41 04 00 00 fd'
                       'e8 02 08 40 06 00 64 00 01 01 00',
                'traffic_key': '61 74 c3 55 7a be d2 75 74 db a3 71 85 f0 03 00',
                'mac': '7b 6a 45 5c 0d 4f 5f 01 83 5b aa b3',
                'key_type': 'send_other',
            },
            {
                'label': 'Receive Non-SYN',
                'client_isn': 0x193cccec,
                'server_isn': 0xa6744ecb,
                'hex': '6e 06 15 20 00 73 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 00 b3 f8 5a a6 74 4e cc'
                       '19 3c cd 30 c0 18 01 00 52 f4 00 00 01 01 08 0a'
                       '71 da ab d3 13 e4 ab a3 1d 10 54 3d c1 06 9b 7d'
                       'fd 3d 69 3a 6d f3 f2 89 ff ff ff ff ff ff ff ff'
                       'ff ff ff ff ff ff ff ff 00 43 01 04 fd e8 00 b4'
                       '01 01 01 7a 26 02 06 01 04 00 01 00 01 02 02 80'
                       '00 02 02 02 00 02 02 42 00 02 06 41 04 00 00 fd'
                       'e8 02 08 40 06 00 64 00 01 01 00',
                'traffic_key': 'cf 1b 1e 22 5e 06 a6 36 16 76 4a 06 7b 46 f4 b1',
                'mac': 'c1 06 9b 7d fd 3d 69 3a 6d f3 f2 89',
                'key_type': 'recv_other',
            },
        ],
    },
    # Section 7.2: IPv6 AES-128-CMAC-96, Omits Options
    'ipv6_aes_omits': {
        'ip_version': 6,
        'kdf': kdf_aes_128_cmac,
        'kdf_bits': 128,
        'mac_fn': mac_aes_128_cmac_96,
        'mac_len': 12,
        'covers_options': False,
        'packets': [
            {
                'label': 'Send SYN',
                'client_isn': 0xb01da74a,
                'server_isn': 0xa6246145,
                'hex': '6e 09 3d 76 00 38 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 f2 88 00 b3 b0 1d a7 4a'
                       '00 00 00 00 e0 02 ff ff 75 ff 00 00 02 04 05 a0'
                       '01 03 03 08 04 02 08 0a 14 27 5b 3b 00 00 00 00'
                       '1d 10 3d 54 3d 45 b4 34 2d e8 bb 15 30 84 78 98',
                'traffic_key': 'a9 4f 51 12 63 e4 09 3d 35 dd 81 8c 13 bb bf 53',
                'mac': '3d 45 b4 34 2d e8 bb 15 30 84 78 98',
                'key_type': 'send_syn',
            },
            {
                'label': 'Receive SYN-ACK',
                'client_isn': 0xb01da74a,
                'server_isn': 0xa6246145,
                'hex': '6e 0c 60 0a 00 38 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 00 b3 f2 88 a6 24 61 45'
                       'b0 1d a7 4b e0 12 ff ff a7 0c 00 00 02 04 05 a0'
                       '01 03 03 08 04 02 08 0a 17 82 24 5b 14 27 5b 3b'
                       '1d 10 54 3d 1d 01 f6 c8 7c 6f 93 ac ff a9 d4 b5',
                'traffic_key': '92 de a5 bb c7 8b 1d 9f 5b 29 52 e9 cd 30 64 2a',
                'mac': '1d 01 f6 c8 7c 6f 93 ac ff a9 d4 b5',
                'key_type': 'recv_other',
            },
            {
                'label': 'Send Non-SYN',
                'client_isn': 0xb01da74a,
                'server_isn': 0xa6246145,
                'hex': '6e 09 3d 76 00 73 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 f2 88 00 b3 b0 1d a7 4b'
                       'a6 24 61 46 c0 18 01 00 c3 6d 00 00 01 01 08 0a'
                       '14 27 5b 4f 17 82 24 5b 1d 10 3d 54 29 0c f4 14'
                       'cc b4 7a 33 32 76 e7 f8 ff ff ff ff ff ff ff ff'
                       'ff ff ff ff ff ff ff ff 00 43 01 04 fd e8 00 b4'
                       '01 01 01 79 26 02 06 01 04 00 01 00 01 02 02 80'
                       '00 02 02 02 00 02 02 42 00 02 06 41 04 00 00 fd'
                       'e8 02 08 40 06 00 64 00 01 01 00',
                'traffic_key': '4f b2 08 6e 40 2c 67 90 79 ed 65 d4 bf 97 69 3d',
                'mac': '29 0c f4 14 cc b4 7a 33 32 76 e7 f8',
                'key_type': 'send_other',
            },
            {
                'label': 'Receive Non-SYN',
                'client_isn': 0xb01da74a,
                'server_isn': 0xa6246145,
                'hex': '6e 0c 60 0a 00 73 06 40 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 02 fd 00 00 00 00 00 00 00'
                       '00 00 00 00 00 00 00 01 00 b3 f2 88 a6 24 61 46'
                       'b0 1d a7 8e c0 18 01 00 34 51 00 00 01 01 08 0a'
                       '17 82 24 65 14 27 5b 4f 1d 10 54 3d 99 51 5f fc'
                       'd5 40 34 99 f6 19 fd 1b ff ff ff ff ff ff ff ff'
                       'ff ff ff ff ff ff ff ff 00 43 01 04 fd e8 00 b4'
                       '01 01 01 7a 26 02 06 01 04 00 01 00 01 02 02 80'
                       '00 02 02 02 00 02 02 42 00 02 06 41 04 00 00 fd'
                       'e8 02 08 40 06 00 64 00 01 01 00',
                'traffic_key': '92 de a5 bb c7 8b 1d 9f 5b 29 52 e9 cd 30 64 2a',
                'mac': '99 51 5f fc d5 40 34 99 f6 19 fd 1b',
                'key_type': 'recv_other',
            },
        ],
    },
}

# ---------------------------------------------------------------------------
# Traffic key derivation helper
# ---------------------------------------------------------------------------

def derive_traffic_key(kdf_fn, kdf_bits, master_key, ip_version,
                       client_port, client_isn, server_isn, key_type):
    """Derive a traffic key based on key_type and connection params."""
    if ip_version == 4:
        local_ip, remote_ip = CLIENT_IPV4, SERVER_IPV4
    else:
        local_ip, remote_ip = CLIENT_IPV6, SERVER_IPV6

    if key_type == 'send_syn':
        ctx = build_kdf_context(local_ip, remote_ip, client_port, SERVER_PORT,
                                client_isn, 0)
    elif key_type == 'recv_syn':
        ctx = build_kdf_context(remote_ip, local_ip, SERVER_PORT, client_port,
                                server_isn, 0)
    elif key_type == 'send_other':
        ctx = build_kdf_context(local_ip, remote_ip, client_port, SERVER_PORT,
                                client_isn, server_isn)
    elif key_type == 'recv_other':
        ctx = build_kdf_context(remote_ip, local_ip, SERVER_PORT, client_port,
                                server_isn, client_isn)
    else:
        raise ValueError(f"Unknown key_type: {key_type}")

    if kdf_fn in (kdf_hkdf_sha256, kdf_kmac256):
        return kdf_fn(master_key, ctx), ctx
    else:
        return kdf_fn(master_key, ctx, kdf_bits), ctx

# ---------------------------------------------------------------------------
# RFC 9235 Baseline Validation
# ---------------------------------------------------------------------------

def validate_rfc9235():
    """Validate all 32 RFC 9235 test vectors."""
    print("=" * 70)
    print("RFC 9235 Baseline Validation")
    print("=" * 70)

    total = 0
    passed = 0
    failed_details = []

    for scenario_name, scenario in RFC9235_VECTORS.items():
        ip_ver = scenario['ip_version']
        kdf_fn = scenario['kdf']
        kdf_bits = scenario['kdf_bits']
        mac_fn = scenario['mac_fn']
        mac_len = scenario['mac_len']
        covers = scenario['covers_options']

        for pkt_info in scenario['packets']:
            total += 1
            raw = hex_to_bytes(pkt_info['hex'])
            expected_tk = hex_to_bytes(pkt_info['traffic_key'])
            expected_mac = hex_to_bytes(pkt_info['mac'])

            # Parse packet
            if ip_ver == 4:
                ip_info = parse_ipv4_packet(raw)
            else:
                ip_info = parse_ipv6_packet(raw)
            tcp_info = parse_tcp(ip_info['tcp_and_payload'])

            # Derive client port from packet
            client_port = tcp_info['src_port'] if pkt_info['key_type'].startswith('send') else tcp_info['dst_port']

            # Derive traffic key
            tk, ctx = derive_traffic_key(kdf_fn, kdf_bits, MASTER_KEY_80, ip_ver,
                                         client_port,
                                         pkt_info['client_isn'],
                                         pkt_info['server_isn'],
                                         pkt_info['key_type'])

            # Build MAC message
            mac_msg = build_mac_message(ip_info, tcp_info, covers, mac_len)

            # Compute MAC
            computed_mac = mac_fn(tk, mac_msg)

            # Compare
            tk_ok = (tk == expected_tk)
            mac_ok = (computed_mac == expected_mac)
            status = "PASS" if (tk_ok and mac_ok) else "FAIL"

            label = f"  {scenario_name} / {pkt_info['label']}"
            if status == "PASS":
                passed += 1
                print(f"{label}: {status}")
            else:
                print(f"{label}: {status}")
                if not tk_ok:
                    print(f"    Traffic key expected: {expected_tk.hex()}")
                    print(f"    Traffic key got:      {tk.hex()}")
                if not mac_ok:
                    print(f"    MAC expected: {expected_mac.hex()}")
                    print(f"    MAC got:      {computed_mac.hex()}")
                failed_details.append((scenario_name, pkt_info['label'], tk_ok, mac_ok))

    print(f"\nResults: {passed}/{total} passed")
    if failed_details:
        print("FAILURES:")
        for name, label, tk_ok, mac_ok in failed_details:
            issues = []
            if not tk_ok:
                issues.append("traffic_key")
            if not mac_ok:
                issues.append("mac")
            print(f"  {name}/{label}: {', '.join(issues)} mismatch")
    return passed == total

# ---------------------------------------------------------------------------
# Packet mutation: 12-byte MAC → 16-byte MAC
# ---------------------------------------------------------------------------

def mutate_packet_for_128bit_mac(raw, ip_version):
    """Mutate an RFC 9235 packet: replace 16-byte TCP-AO option with 20-byte.

    Returns the mutated packet bytes (with MAC zeroed, checksum zeroed).
    """
    pkt = bytearray(raw)

    if ip_version == 4:
        ip_hdr_len = (pkt[0] & 0x0f) * 4
        tcp_start = ip_hdr_len
        # Increment IPv4 Total Length by 4
        total_len = struct.unpack('!H', pkt[2:4])[0] + 4
        struct.pack_into('!H', pkt, 2, total_len)
    else:
        tcp_start = 40
        # Increment IPv6 Payload Length by 4
        payload_len = struct.unpack('!H', pkt[4:6])[0] + 4
        struct.pack_into('!H', pkt, 4, payload_len)

    tcp = pkt[tcp_start:]
    data_offset = (tcp[12] >> 4)

    # Find TCP-AO option
    ao_off, ao_len = find_tcp_ao_option(tcp)
    if ao_off is None or ao_len != 16:
        raise ValueError(f"Expected 16-byte TCP-AO, got length={ao_len}")

    # Extract parts
    pre_ao = bytes(tcp[:ao_off])
    ao_header = bytes(tcp[ao_off:ao_off+4])  # Kind, Length, KeyID, RNextKeyID
    post_ao = bytes(tcp[ao_off+16:])  # everything after old 16-byte AO option

    # Build new TCP-AO option: 20 bytes (header + 16 zero bytes for MAC)
    new_ao = bytes([ao_header[0], 20, ao_header[2], ao_header[3]]) + b'\x00' * 16

    # Reassemble TCP
    new_tcp = bytearray(pre_ao + new_ao + post_ao)

    # Increment data offset by 1 word
    new_doff = data_offset + 1
    new_tcp[12] = (new_doff << 4) | (new_tcp[12] & 0x0f)

    # Zero TCP checksum
    new_tcp[16] = 0
    new_tcp[17] = 0

    # Reassemble full packet
    new_pkt = bytearray(pkt[:tcp_start]) + new_tcp

    # Recompute IPv4 header checksum
    if ip_version == 4:
        new_pkt[10] = 0
        new_pkt[11] = 0
        ip_chk = internet_checksum(bytes(new_pkt[:ip_hdr_len]))
        struct.pack_into('!H', new_pkt, 10, ip_chk)

    return bytes(new_pkt)


def compute_tcp_checksum(pkt_bytes, ip_version):
    """Compute TCP checksum for a full packet."""
    if ip_version == 4:
        ip_hdr_len = (pkt_bytes[0] & 0x0f) * 4
        src_ip = pkt_bytes[12:16]
        dst_ip = pkt_bytes[16:20]
        tcp_data = pkt_bytes[ip_hdr_len:]
        pseudo = ipv4_pseudo_header(src_ip, dst_ip, len(tcp_data))
    else:
        src_ip = pkt_bytes[8:24]
        dst_ip = pkt_bytes[24:40]
        tcp_data = pkt_bytes[40:]
        pseudo = ipv6_pseudo_header(src_ip, dst_ip, len(tcp_data))

    return internet_checksum(pseudo + tcp_data)


def finalize_packet(pkt_bytes, ip_version, mac_bytes):
    """Insert MAC and recompute TCP checksum."""
    pkt = bytearray(pkt_bytes)

    if ip_version == 4:
        tcp_start = (pkt[0] & 0x0f) * 4
    else:
        tcp_start = 40

    tcp = pkt[tcp_start:]
    ao_off, ao_len = find_tcp_ao_option(tcp)
    mac_field_off = tcp_start + ao_off + 4
    pkt[mac_field_off:mac_field_off+16] = mac_bytes

    # Zero checksum, recompute
    pkt[tcp_start+16] = 0
    pkt[tcp_start+17] = 0
    chk = compute_tcp_checksum(bytes(pkt), ip_version)
    struct.pack_into('!H', pkt, tcp_start+16, chk)

    return bytes(pkt)


# ---------------------------------------------------------------------------
# New algorithm test vector generation
# ---------------------------------------------------------------------------

# Map RFC 9235 scenarios to new algorithm scenarios
# Each RFC 9235 scenario shares ISNs with one HMAC-SHA256-128 and one KMAC256-128 scenario
SCENARIO_MAP = {
    'ipv4_sha1_covers':  ('ipv4', True),   # IPv4, covers options
    'ipv4_sha1_omits':   ('ipv4', False),   # IPv4, omits options
    'ipv4_aes_covers':   ('ipv4', True),
    'ipv4_aes_omits':    ('ipv4', False),
    'ipv6_sha1_covers':  ('ipv6', True),
    'ipv6_sha1_omits':   ('ipv6', False),
    'ipv6_aes_covers':   ('ipv6', True),
    'ipv6_aes_omits':    ('ipv6', False),
}

NEW_ALGORITHMS = [
    {
        'name': 'HMAC-SHA256-128',
        'kdf': kdf_hkdf_sha256,
        'mac_fn': mac_hmac_sha256_128,
        'mac_len': 16,
    },
    {
        'name': 'KMAC256-128',
        'kdf': kdf_kmac256,
        'mac_fn': mac_kmac256_128,
        'mac_len': 16,
    },
]

# RFC 9235 source scenarios: which scenario provides packets for which (ip, covers) combo
# SHA-1 scenarios share ISNs with HMAC-SHA256-128; AES scenarios share with KMAC256-128
SOURCE_PACKETS = {
    ('ipv4', True, 'HMAC-SHA256-128'):  'ipv4_sha1_covers',
    ('ipv4', False, 'HMAC-SHA256-128'): 'ipv4_sha1_omits',
    ('ipv4', True, 'KMAC256-128'):      'ipv4_aes_covers',
    ('ipv4', False, 'KMAC256-128'):     'ipv4_aes_omits',
    ('ipv6', True, 'HMAC-SHA256-128'):  'ipv6_sha1_covers',
    ('ipv6', False, 'HMAC-SHA256-128'): 'ipv6_sha1_omits',
    ('ipv6', True, 'KMAC256-128'):      'ipv6_aes_covers',
    ('ipv6', False, 'KMAC256-128'):     'ipv6_aes_omits',
}


def generate_new_vectors(master_key, master_key_label):
    """Generate 32 test vectors for one master key variant."""
    results = []
    ip_labels = {'ipv4': 4, 'ipv6': 6}

    for alg in NEW_ALGORITHMS:
        for ip_label in ('ipv4', 'ipv6'):
            ip_ver = ip_labels[ip_label]
            for covers in (True, False):
                src_key = (ip_label, covers, alg['name'])
                src_scenario_name = SOURCE_PACKETS[src_key]
                src_scenario = RFC9235_VECTORS[src_scenario_name]

                for pkt_info in src_scenario['packets']:
                    raw = hex_to_bytes(pkt_info['hex'])

                    # Mutate packet: 12B→16B MAC
                    mutated = mutate_packet_for_128bit_mac(raw, ip_ver)

                    # Parse mutated packet
                    if ip_ver == 4:
                        ip_info = parse_ipv4_packet(mutated)
                    else:
                        ip_info = parse_ipv6_packet(mutated)
                    tcp_info = parse_tcp(ip_info['tcp_and_payload'])

                    # Derive client port
                    key_type = pkt_info['key_type']
                    client_port = tcp_info['src_port'] if key_type.startswith('send') else tcp_info['dst_port']

                    # Derive traffic key with intermediates
                    tk, ctx = derive_traffic_key(
                        alg['kdf'], None, master_key, ip_ver,
                        client_port, pkt_info['client_isn'],
                        pkt_info['server_isn'], key_type)

                    # Compute KDF intermediates for JSON
                    kdf_intermediates = {}
                    if alg['name'] == 'HMAC-SHA256-128':
                        salt = b'\x00' * 32
                        prk = hmac.new(salt, master_key, hashlib.sha256).digest()
                        kdf_intermediates = {
                            'kdf_salt': salt.hex(),
                            'kdf_ikm': master_key.hex(),
                            'kdf_prk': prk.hex(),
                            'kdf_info': ctx.hex(),
                            'kdf_expand_input': (ctx + b'\x01').hex(),
                        }
                    else:
                        counter = b'\x00\x00\x00\x01'
                        kdf_input = counter + master_key + ctx
                        kdf_intermediates = {
                            'kdf_salt': (b'\x00' * 132).hex(),
                            'kdf_counter': counter.hex(),
                            'kdf_kmac_input': kdf_input.hex(),
                            'kdf_kmac_custom': '4b4446',
                        }

                    # Build MAC message
                    mac_msg = build_mac_message(ip_info, tcp_info, covers, alg['mac_len'])

                    # Annotate MAC message field boundaries
                    if ip_ver == 4:
                        pseudo_len = 12
                    else:
                        pseudo_len = 40
                    tcp_hdr_len = tcp_info['data_offset']
                    payload_len = len(tcp_info['payload'])
                    if covers:
                        tcp_in_mac = tcp_hdr_len
                    else:
                        ao_off_m, ao_len_m = find_tcp_ao_option(tcp_info['header_bytes'])
                        tcp_in_mac = 20 + ao_len_m
                    mac_field_boundaries = {
                        'sne': '0:4',
                        'pseudo_header': f'4:{4+pseudo_len}',
                        'tcp_header': f'{4+pseudo_len}:{4+pseudo_len+tcp_in_mac}',
                        'payload': f'{4+pseudo_len+tcp_in_mac}:{len(mac_msg)}',
                    }

                    # Compute MAC
                    mac_val = alg['mac_fn'](tk, mac_msg)

                    # Finalize packet
                    final_pkt = finalize_packet(mutated, ip_ver, mac_val)

                    # Section identifier matching draft appendix structure
                    alg_idx = '2' if alg['name'] == 'HMAC-SHA256-128' else '3'
                    if ip_ver == 6:
                        alg_idx = str(int(alg_idx) + 2)
                    cov_idx = '1' if covers else '2'
                    pkt_idx = str(src_scenario['packets'].index(pkt_info) + 1)
                    section = f"A.{alg_idx}.{cov_idx}.{pkt_idx}"

                    option_mode = 'covers' if covers else 'omits'
                    results.append({
                        'section': section,
                        'master_key_variant': master_key_label,
                        'master_key_hex': master_key.hex(),
                        'ip_version': ip_ver,
                        'algorithm': alg['name'],
                        'option_mode': option_mode,
                        'packet_type': pkt_info['label'],
                        'key_type': key_type,
                        'client_isn': f"0x{pkt_info['client_isn']:08x}",
                        'server_isn': f"0x{pkt_info['server_isn']:08x}",
                        'client_port': client_port,
                        'kdf_context': ctx.hex(),
                        'kdf_context_len': len(ctx),
                        **kdf_intermediates,
                        'traffic_key': tk.hex(),
                        'mac_message': mac_msg.hex(),
                        'mac_message_len': len(mac_msg),
                        'mac_field_boundaries': mac_field_boundaries,
                        'mac': mac_val.hex(),
                        'packet_hex': final_pkt.hex(),
                        'packet_len': len(final_pkt),
                    })

    return results


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_vectors(vectors):
    """Run all verification checks on generated vectors."""
    print("=" * 70)
    print("Verification")
    print("=" * 70)
    all_ok = True

    # 7.5 Directionality checks
    # Client Send_other key == Server Receive_other key (same context).
    # We compute both from the client perspective, so we independently derive
    # the server's Receive_other key and compare.
    print("\n--- Directionality Checks ---")
    dir_ok = True
    dir_checked = 0
    for v in vectors:
        if v['key_type'] != 'send_other':
            continue
        ip_ver = v['ip_version']
        mk = bytes.fromhex(v['master_key_hex'])
        alg_entry = [a for a in NEW_ALGORITHMS if a['name'] == v['algorithm']][0]
        client_isn = int(v['client_isn'], 16)
        server_isn = int(v['server_isn'], 16)

        # Client's send_other traffic key (already computed)
        client_send_tk = v['traffic_key']

        # Server's recv_other: from server perspective, remote=client, local=server
        # Context: src=client(remote), dst=server(local), src_ISN=client_ISN, dst_ISN=server_ISN
        if ip_ver == 4:
            server_recv_ctx = build_kdf_context(
                CLIENT_IPV4, SERVER_IPV4, v['client_port'], SERVER_PORT,
                client_isn, server_isn)
        else:
            server_recv_ctx = build_kdf_context(
                CLIENT_IPV6, SERVER_IPV6, v['client_port'], SERVER_PORT,
                client_isn, server_isn)
        server_recv_tk = alg_entry['kdf'](mk, server_recv_ctx).hex()

        if client_send_tk != server_recv_tk:
            print(f"  FAIL: Client Send_other != Server Recv_other for "
                  f"{v['algorithm']}/{v['option_mode']}/{v['master_key_variant']}")
            print(f"    Client send: {client_send_tk}")
            print(f"    Server recv: {server_recv_tk}")
            dir_ok = False
            all_ok = False
        dir_checked += 1

        # Also check reverse: server Send_other == client Recv_other
        # Find the matching recv_other vector
        for v2 in vectors:
            if (v2['key_type'] == 'recv_other' and
                v2['master_key_variant'] == v['master_key_variant'] and
                v2['ip_version'] == v['ip_version'] and
                v2['algorithm'] == v['algorithm'] and
                v2['option_mode'] == v['option_mode'] and
                v2['client_isn'] == v['client_isn'] and
                v2['packet_type'] == 'Receive Non-SYN'):
                client_recv_tk = v2['traffic_key']
                # Server's send_other: src=server(local), dst=client(remote)
                if ip_ver == 4:
                    server_send_ctx = build_kdf_context(
                        SERVER_IPV4, CLIENT_IPV4, SERVER_PORT, v['client_port'],
                        server_isn, client_isn)
                else:
                    server_send_ctx = build_kdf_context(
                        SERVER_IPV6, CLIENT_IPV6, SERVER_PORT, v['client_port'],
                        server_isn, client_isn)
                server_send_tk = alg_entry['kdf'](mk, server_send_ctx).hex()
                if client_recv_tk != server_send_tk:
                    print(f"  FAIL: Server Send_other != Client Recv_other for "
                          f"{v['algorithm']}/{v['option_mode']}/{v['master_key_variant']}")
                    dir_ok = False
                    all_ok = False
                dir_checked += 1
                break

    if dir_ok:
        print(f"  {dir_checked} directionality assertions passed")

    # 7.6 Final packet validation
    print("\n--- Packet Structural Validation ---")
    struct_ok = True
    for v in vectors:
        pkt = bytes.fromhex(v['packet_hex'])
        ip_ver = v['ip_version']

        if ip_ver == 4:
            ip_info = parse_ipv4_packet(pkt)
            # Check IPv4 Total Length
            actual_len = len(pkt)
            declared_len = struct.unpack('!H', pkt[2:4])[0]
            if actual_len != declared_len:
                print(f"  FAIL {v['algorithm']}/{v['option_mode']}/{v['packet_type']}: "
                      f"IPv4 Total Length {declared_len} != actual {actual_len}")
                struct_ok = False
                all_ok = False

            # Verify IPv4 header checksum
            ip_hdr_len = (pkt[0] & 0x0f) * 4
            hdr = bytearray(pkt[:ip_hdr_len])
            hdr[10] = 0
            hdr[11] = 0
            computed_chk = internet_checksum(bytes(hdr))
            actual_chk = struct.unpack('!H', pkt[10:12])[0]
            if computed_chk != actual_chk:
                print(f"  FAIL {v['algorithm']}/{v['option_mode']}/{v['packet_type']}: "
                      f"IPv4 checksum mismatch")
                struct_ok = False
                all_ok = False
        else:
            ip_info = parse_ipv6_packet(pkt)
            payload_len = struct.unpack('!H', pkt[4:6])[0]
            if payload_len != len(pkt) - 40:
                print(f"  FAIL {v['algorithm']}/{v['option_mode']}/{v['packet_type']}: "
                      f"IPv6 Payload Length mismatch")
                struct_ok = False
                all_ok = False

        # Parse TCP and check structure
        tcp_info = parse_tcp(ip_info['tcp_and_payload'])
        ao_off, ao_len = find_tcp_ao_option(tcp_info['header_bytes'])
        if ao_len != 20:
            print(f"  FAIL {v['algorithm']}/{v['option_mode']}/{v['packet_type']}: "
                  f"TCP-AO Length={ao_len}, expected 20")
            struct_ok = False
            all_ok = False

        # Check KeyID/RNextKeyID
        ao_keyid = tcp_info['header_bytes'][ao_off + 2]
        ao_rnext = tcp_info['header_bytes'][ao_off + 3]
        # Enforce directional KeyID/RNextKeyID pair:
        # Client-sent packets: KeyID=CLIENT_KEYID, RNextKeyID=SERVER_KEYID
        # Server-sent packets: KeyID=SERVER_KEYID, RNextKeyID=CLIENT_KEYID
        if v['key_type'].startswith('send'):
            expected_keyid, expected_rnext = CLIENT_KEYID, SERVER_KEYID
        else:
            expected_keyid, expected_rnext = SERVER_KEYID, CLIENT_KEYID
        if ao_keyid != expected_keyid:
            print(f"  FAIL {v['algorithm']}/{v['packet_type']}: "
                  f"KeyID=0x{ao_keyid:02x}, expected 0x{expected_keyid:02x}")
            struct_ok = False
            all_ok = False
        if ao_rnext != expected_rnext:
            print(f"  FAIL {v['algorithm']}/{v['packet_type']}: "
                  f"RNextKeyID=0x{ao_rnext:02x}, expected 0x{expected_rnext:02x}")
            struct_ok = False
            all_ok = False

        # Verify TCP checksum: zero the field, recompute, compare
        pkt_copy = bytearray(pkt)
        if ip_ver == 4:
            tcp_off = (pkt_copy[0] & 0x0f) * 4
        else:
            tcp_off = 40
        actual_tcp_chk = struct.unpack('!H', pkt_copy[tcp_off+16:tcp_off+18])[0]
        pkt_copy[tcp_off+16] = 0
        pkt_copy[tcp_off+17] = 0
        tcp_chk = compute_tcp_checksum(bytes(pkt_copy), ip_ver)
        if tcp_chk != actual_tcp_chk:
            print(f"  FAIL {v['algorithm']}/{v['option_mode']}/{v['packet_type']}: "
                  f"TCP checksum mismatch: computed=0x{tcp_chk:04x} actual=0x{actual_tcp_chk:04x}")
            struct_ok = False
            all_ok = False

        # 7.6.4 MAC round-trip: extract MAC from packet bytes (not JSON),
        # recompute from scratch, and compare
        if ip_ver == 4:
            ip_info2 = parse_ipv4_packet(pkt)
        else:
            ip_info2 = parse_ipv6_packet(pkt)
        tcp_info2 = parse_tcp(ip_info2['tcp_and_payload'])

        # Extract MAC directly from packet's TCP-AO option
        ao_off2, ao_len2 = find_tcp_ao_option(tcp_info2['header_bytes'])
        packet_mac = bytes(tcp_info2['header_bytes'][ao_off2+4:ao_off2+4+16])

        covers = (v['option_mode'] == 'covers')
        mac_msg2 = build_mac_message(ip_info2, tcp_info2, covers, 16)

        client_port2 = tcp_info2['src_port'] if v['key_type'].startswith('send') else tcp_info2['dst_port']
        alg_entry = [a for a in NEW_ALGORITHMS if a['name'] == v['algorithm']][0]
        mk = bytes.fromhex(v['master_key_hex'])
        tk2, _ = derive_traffic_key(alg_entry['kdf'], None, mk, ip_ver,
                                     client_port2,
                                     int(v['client_isn'], 16),
                                     int(v['server_isn'], 16),
                                     v['key_type'])
        mac2 = alg_entry['mac_fn'](tk2, mac_msg2)
        if mac2 != packet_mac:
            print(f"  FAIL {v['algorithm']}/{v['option_mode']}/{v['packet_type']}: "
                  f"MAC round-trip: recomputed={mac2.hex()} packet={packet_mac.hex()}")
            struct_ok = False
            all_ok = False

    if struct_ok:
        print("  All packets: structure, checksums, and MAC round-trip OK")

    # 7.7 Scapy cross-validation
    print("\n--- Scapy Cross-Validation ---")
    try:
        from scapy.all import IP as ScapyIP, IPv6 as ScapyIPv6, TCP as ScapyTCP
        scapy_ok = True
        for v in vectors:
            pkt_bytes = bytes.fromhex(v['packet_hex'])
            ip_ver = v['ip_version']
            if ip_ver == 4:
                sp = ScapyIP(pkt_bytes)
                saved_ip_chk = sp.chksum
                saved_tcp_chk = sp[ScapyTCP].chksum
                del sp.chksum
                del sp[ScapyTCP].chksum
                sp2 = ScapyIP(bytes(sp))
                if sp2.chksum != saved_ip_chk:
                    print(f"  FAIL: Scapy IPv4 checksum mismatch for {v['packet_type']}")
                    scapy_ok = False
                    all_ok = False
                if sp2[ScapyTCP].chksum != saved_tcp_chk:
                    print(f"  FAIL: Scapy TCP checksum mismatch for {v['packet_type']}")
                    scapy_ok = False
                    all_ok = False
            else:
                sp = ScapyIPv6(pkt_bytes)
                saved_tcp_chk = sp[ScapyTCP].chksum
                del sp[ScapyTCP].chksum
                sp2 = ScapyIPv6(bytes(sp))
                if sp2[ScapyTCP].chksum != saved_tcp_chk:
                    print(f"  FAIL: Scapy IPv6 TCP checksum mismatch for {v['packet_type']}")
                    scapy_ok = False
                    all_ok = False
        if scapy_ok:
            print("  All packets: Scapy checksum verification OK")
    except ImportError:
        print("  Scapy not available, skipping")

    # 7.8 Matrix enforcement
    print("\n--- Matrix Enforcement ---")
    expected_variants = {'testvector', 'testvector-256-bit'}
    expected_count = 2 * 2 * 2 * 4  # ip_versions * algorithms * option_modes * packet_types

    per_variant = {}
    for v in vectors:
        t = (v['ip_version'], v['algorithm'], v['option_mode'], v['packet_type'])
        per_variant.setdefault(v['master_key_variant'], set()).add(t)

    found_variants = set(per_variant.keys())
    if found_variants != expected_variants:
        missing = expected_variants - found_variants
        print(f"  FAIL: missing master-key variant(s): {missing}")
        all_ok = False
    for variant in sorted(expected_variants):
        tset = per_variant.get(variant, set())
        if len(tset) != expected_count:
            print(f"  FAIL: {variant} has {len(tset)} vectors, expected {expected_count}")
            all_ok = False
        else:
            print(f"  {variant}: {len(tset)} unique tuples OK")

    total_expected = len(expected_variants) * expected_count
    if len(vectors) != total_expected:
        print(f"  FAIL: total vectors {len(vectors)}, expected {total_expected}")
        all_ok = False
    else:
        print(f"  Total: {len(vectors)} vectors OK")

    return all_ok


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_rfc_format(vectors):
    """Print vectors in RFC appendix format."""
    print("\n" + "=" * 70)
    print("Generated Test Vectors (RFC Format)")
    print("=" * 70)

    current_section = None
    for v in vectors:
        section = f"IPv{v['ip_version']} {v['algorithm']} ({'Covers' if v['option_mode']=='covers' else 'Omits'} Options) [{v['master_key_variant']}]"
        if section != current_section:
            print(f"\n{'─' * 60}")
            print(f"  {section}")
            print(f"{'─' * 60}")
            current_section = section

        print(f"\n  {v['packet_type']}")
        print(f"    Client ISN = {v['client_isn']}")
        if v['packet_type'] in ('Receive SYN-ACK', 'Send Non-SYN', 'Receive Non-SYN'):
            print(f"    Server ISN = {v['server_isn']}")
        print(f"    KDF Context ({v['kdf_context_len']}B): {v['kdf_context']}")
        print(f"    Traffic Key: {' '.join(v['traffic_key'][i:i+2] for i in range(0, len(v['traffic_key']), 2))}")
        print(f"    MAC:         {' '.join(v['mac'][i:i+2] for i in range(0, len(v['mac']), 2))}")
        print(f"    Packet ({v['packet_len']}B):")
        pkt_bytes = bytes.fromhex(v['packet_hex'])
        for i in range(0, len(pkt_bytes), 16):
            chunk = pkt_bytes[i:i+16]
            print(f"      {' '.join(f'{b:02x}' for b in chunk)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print(f"Python {sys.version}")
    try:
        import Crypto
        print(f"pycryptodome {Crypto.__version__}")
    except Exception:
        pass
    try:
        import scapy
        print(f"scapy {scapy.__version__}")
    except Exception:
        pass
    result = subprocess.run(['openssl', 'version'], capture_output=True, text=True)
    print(result.stdout.strip())
    print()

    # Step 0: Algorithm-level known-answer tests
    print("=" * 70)
    print("Algorithm Known-Answer Tests")
    print("=" * 70)
    kat_ok = True

    # HKDF-SHA256: RFC 5869 Test Case 1
    _ikm = bytes.fromhex('0b' * 22)
    _salt = bytes.fromhex('000102030405060708090a0b0c')
    _info = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')
    _prk = hmac.new(_salt, _ikm, hashlib.sha256).digest()
    _t1 = hmac.new(_prk, _info + b'\x01', hashlib.sha256).digest()
    _t2 = hmac.new(_prk, _t1 + _info + b'\x02', hashlib.sha256).digest()
    _okm = (_t1 + _t2)[:42]
    _exp_prk = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'
    _exp_okm = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
    if _prk.hex() == _exp_prk and _okm.hex() == _exp_okm:
        print("  HKDF-SHA256 (RFC 5869 TC1): PASS")
    else:
        print("  HKDF-SHA256 (RFC 5869 TC1): FAIL")
        kat_ok = False

    # KMAC256: NIST Sample #4
    _kmac_key = bytes(range(0x40, 0x60))
    _kmac_data = bytes.fromhex('00010203')
    _kmac_exp = '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd'
    _kmac_out = KMAC256.new(key=_kmac_key, data=_kmac_data, mac_len=64,
                            custom=b'My Tagged Application').hexdigest()
    if _kmac_out == _kmac_exp:
        print("  KMAC256 (NIST Sample #4): PASS")
    else:
        print("  KMAC256 (NIST Sample #4): FAIL")
        kat_ok = False

    # KMAC256: NIST Sample #5 (long data, empty S)
    _kmac_data5 = bytes(range(0x00, 0xc8))
    _kmac_exp5 = '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69'
    _kmac_out5 = KMAC256.new(key=_kmac_key, data=_kmac_data5, mac_len=64,
                             custom=b'').hexdigest()
    if _kmac_out5 == _kmac_exp5:
        print("  KMAC256 (NIST Sample #5): PASS")
    else:
        print("  KMAC256 (NIST Sample #5): FAIL")
        kat_ok = False

    # KMAC256: NIST Sample #6 (long data, custom string)
    _kmac_exp6 = 'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965'
    _kmac_out6 = KMAC256.new(key=_kmac_key, data=_kmac_data5, mac_len=64,
                             custom=b'My Tagged Application').hexdigest()
    if _kmac_out6 == _kmac_exp6:
        print("  KMAC256 (NIST Sample #6): PASS")
    else:
        print("  KMAC256 (NIST Sample #6): FAIL")
        kat_ok = False

    # KMAC output-length dependence
    _m128 = KMAC256.new(key=_kmac_key, data=_kmac_data, mac_len=16,
                        custom=b'My Tagged Application').digest()
    _m256 = KMAC256.new(key=_kmac_key, data=_kmac_data, mac_len=32,
                        custom=b'My Tagged Application').digest()
    if _m128 != _m256[:16]:
        print("  KMAC L=128 != L=256[:16]: PASS (confirmed distinct)")
    else:
        print("  KMAC L=128 != L=256[:16]: FAIL (should be distinct!)")
        kat_ok = False

    # OpenSSL HKDF cross-check with a real TCP-AO context
    _ctx = build_kdf_context(CLIENT_IPV4, SERVER_IPV4, 0xe9d7, SERVER_PORT,
                             0xfbfbab5a, 0)
    _our_tk = kdf_hkdf_sha256(MASTER_KEY_80, _ctx)
    _ossl_cmd = (f'openssl kdf -keylen 32 -kdfopt digest:SHA256 '
                 f'-kdfopt mode:EXTRACT_AND_EXPAND '
                 f'-kdfopt hexkey:{MASTER_KEY_80.hex()} '
                 f'-kdfopt hexsalt:{"00"*32} '
                 f'-kdfopt hexinfo:{_ctx.hex()} HKDF')
    _ossl_r = subprocess.run(_ossl_cmd, shell=True, capture_output=True, text=True)
    _ossl_hex = _ossl_r.stdout.strip().replace(':', '').lower()
    if _ossl_hex == _our_tk.hex():
        print("  HKDF vs OpenSSL (TCP-AO context): PASS")
    else:
        print(f"  HKDF vs OpenSSL: FAIL (ours={_our_tk.hex()}, ossl={_ossl_hex})")
        kat_ok = False

    if not kat_ok:
        print("\nAlgorithm KATs FAILED.")
        sys.exit(1)
    print()

    # Step 1: RFC 9235 baseline
    ok = validate_rfc9235()
    if not ok:
        print("\nRFC 9235 baseline validation FAILED. Fix before proceeding.")
        sys.exit(1)
    print("\nRFC 9235 baseline validation PASSED.\n")

    # Step 3: Generate new vectors
    print("=" * 70)
    print("Generating New Test Vectors")
    print("=" * 70)

    vectors_provisional = generate_new_vectors(MASTER_KEY_80, 'testvector')
    print(f"  Generated {len(vectors_provisional)} provisional vectors (80-bit key)")

    vectors_conformant = generate_new_vectors(MASTER_KEY_256, 'testvector-256-bit')
    print(f"  Generated {len(vectors_conformant)} conformant vectors (256-bit key)")

    all_vectors = vectors_provisional + vectors_conformant

    # Verify
    ok = verify_vectors(all_vectors)

    # Print RFC format — conformant (256-bit) vectors only
    print_rfc_format(vectors_conformant)

    # Write JSON
    ossl_ver = subprocess.run(['openssl', 'version'], capture_output=True, text=True)
    output = {
        'generator': 'tcp_ao_new_algs.py',
        'draft': 'draft-ietf-tcpm-tcp-ao-algs-06',
        'python_version': sys.version.split()[0],
        'pycryptodome_version': Crypto.__version__,
        'scapy_version': scapy.__version__,
        'openssl_version': ossl_ver.stdout.strip(),
        'vectors': all_vectors,
    }
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tcp_ao_test_vectors.json')
    with open(json_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nJSON output: {json_path}")

    if not ok:
        print("\nVerification FAILED.")
        sys.exit(1)
    print(f"\nAll {len(all_vectors)} vectors generated and verified.")
