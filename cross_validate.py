#!/usr/bin/env python3
"""Cross-validate our TCP-AO implementation against cdleonard/tcp-authopt-test."""

import sys
sys.path.insert(0, '/garage/reji.thomas/tcp-authopt-test')
sys.path.insert(0, '/garage/reji.thomas/tcp_ao_algs')

from ipaddress import IPv4Address, IPv6Address
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6 as ScapyIPv6

from tcp_authopt_test.scapy_tcp_authopt import (
    build_context_from_packet,
    build_message_from_packet,
    get_alg,
)
from tcp_ao_new_algs import (
    RFC9235_VECTORS,
    MASTER_KEY_80,
    hex_to_bytes,
    parse_ipv4_packet,
    parse_ipv6_packet,
    parse_tcp,
    build_kdf_context,
    build_mac_message,
    derive_traffic_key,
    CLIENT_IPV4, SERVER_IPV4,
    CLIENT_IPV6, SERVER_IPV6,
    SERVER_PORT,
)

def cross_validate():
    print("=" * 70)
    print("Cross-Validation: our impl vs cdleonard/tcp-authopt-test")
    print("=" * 70)

    total = 0
    passed = 0
    failures = []

    for scenario_name, scenario in RFC9235_VECTORS.items():
        ip_ver = scenario['ip_version']
        kdf_fn = scenario['kdf']
        kdf_bits = scenario['kdf_bits']
        mac_fn = scenario['mac_fn']
        mac_len = scenario['mac_len']
        covers = scenario['covers_options']

        if kdf_bits == 160:
            ref_alg = get_alg("HMAC-SHA-1-96")
        else:
            ref_alg = get_alg("AES-128-CMAC-96")

        for pkt_info in scenario['packets']:
            total += 1
            raw = hex_to_bytes(pkt_info['hex'])

            # --- Reference implementation ---
            if ip_ver == 4:
                ref_pkt = IP(raw)
            else:
                ref_pkt = ScapyIPv6(raw)

            # Determine src_isn and dst_isn for reference impl
            # Reference uses packet-relative ISNs (src_isn = ISN of packet source)
            key_type = pkt_info['key_type']
            if key_type == 'send_syn':
                ref_src_isn = pkt_info['client_isn']
                ref_dst_isn = 0
            elif key_type == 'recv_other' and 'SYN-ACK' in pkt_info['label']:
                ref_src_isn = pkt_info['server_isn']
                ref_dst_isn = pkt_info['client_isn']
            elif key_type == 'send_other':
                ref_src_isn = pkt_info['client_isn']
                ref_dst_isn = pkt_info['server_isn']
            elif key_type == 'recv_other':
                ref_src_isn = pkt_info['server_isn']
                ref_dst_isn = pkt_info['client_isn']
            else:
                raise ValueError(f"Unexpected key_type: {key_type}")

            ref_ctx = build_context_from_packet(ref_pkt, ref_src_isn, ref_dst_isn)
            ref_tk = ref_alg.kdf(MASTER_KEY_80, ref_ctx)
            ref_msg = build_message_from_packet(ref_pkt, include_options=covers)
            ref_mac = ref_alg.mac(ref_tk, bytes(ref_msg))

            # --- Our implementation ---
            if ip_ver == 4:
                our_ip = parse_ipv4_packet(raw)
            else:
                our_ip = parse_ipv6_packet(raw)
            our_tcp = parse_tcp(our_ip['tcp_and_payload'])

            client_port = our_tcp['src_port'] if key_type.startswith('send') else our_tcp['dst_port']
            our_tk, our_ctx = derive_traffic_key(
                kdf_fn, kdf_bits, MASTER_KEY_80, ip_ver,
                client_port, pkt_info['client_isn'], pkt_info['server_isn'],
                key_type
            )
            our_msg = build_mac_message(our_ip, our_tcp, covers, mac_len)
            our_mac = mac_fn(our_tk, our_msg)

            # --- Compare ---
            ctx_ok = (bytes(ref_ctx) == bytes(our_ctx))
            tk_ok = (ref_tk == our_tk)
            msg_ok = (bytes(ref_msg) == bytes(our_msg))
            mac_ok = (ref_mac == our_mac)

            label = f"  {scenario_name} / {pkt_info['label']}"
            if ctx_ok and tk_ok and msg_ok and mac_ok:
                passed += 1
                print(f"{label}: MATCH")
            else:
                issues = []
                if not ctx_ok:
                    issues.append("context")
                    print(f"{label}: MISMATCH - context")
                    print(f"    ref: {bytes(ref_ctx).hex()}")
                    print(f"    our: {bytes(our_ctx).hex()}")
                if not tk_ok:
                    issues.append("traffic_key")
                    print(f"{label}: MISMATCH - traffic_key")
                    print(f"    ref: {ref_tk.hex()}")
                    print(f"    our: {our_tk.hex()}")
                if not msg_ok:
                    issues.append("mac_message")
                    print(f"{label}: MISMATCH - mac_message")
                    print(f"    ref len: {len(ref_msg)}")
                    print(f"    our len: {len(our_msg)}")
                    # Find first difference
                    for i in range(min(len(ref_msg), len(our_msg))):
                        if ref_msg[i] != our_msg[i]:
                            print(f"    first diff at byte {i}: ref=0x{ref_msg[i]:02x} our=0x{our_msg[i]:02x}")
                            break
                if not mac_ok:
                    issues.append("mac")
                    print(f"{label}: MISMATCH - mac")
                    print(f"    ref: {ref_mac.hex()}")
                    print(f"    our: {our_mac.hex()}")
                failures.append((scenario_name, pkt_info['label'], issues))

    print(f"\nResults: {passed}/{total} matched")
    if failures:
        print("MISMATCHES:")
        for name, label, issues in failures:
            print(f"  {name}/{label}: {', '.join(issues)}")
        return False
    return True


if __name__ == '__main__':
    ok = cross_validate()
    sys.exit(0 if ok else 1)
