# Validation Methodology

## 1. Primitive Verification

Each cryptographic primitive is validated against published test vectors before
use in TCP-AO computations.

| Primitive | Reference | Vectors |
|---|---|---|
| HKDF-SHA256 (Extract + Expand) | RFC 5869 Appendix A, Test Case 1 | PRK and OKM verified |
| KMAC256 | NIST CSRC KMAC test vectors, Samples #4, #5, #6 | Covers short/long data, empty/non-empty customization |
| KMAC output-length dependence | SP 800-185 | Asserts KMAC256(L=128) ≠ KMAC256(L=256)[:16] |
| HKDF-SHA256 cross-check | OpenSSL 3.2.2 `kdf` command | EXTRACT_AND_EXPAND with a real TCP-AO context |

## 2. Framework Validation (RFC 9235 Baseline)

All 32 test vectors from RFC 9235 are reproduced:
- 2 algorithms (HMAC-SHA-1-96, AES-128-CMAC-96) × 2 IP versions × 2 option modes × 4 packet types
- Traffic keys and MACs must match byte-for-byte
- Validates: KDF context construction (RFC 5925 §5.2), MAC message assembly (RFC 5925 §5.1),
  IPv4/IPv6 pseudo-header, TCP option handling (covers vs omits)

## 3. Independent Cross-Validation

All 32 RFC 9235 vectors are independently verified against
[cdleonard/tcp-authopt-test](https://github.com/cdleonard/tcp-authopt-test),
comparing four intermediate values per vector:
- KDF context bytes
- Traffic key
- MAC message bytes
- MAC output

## 4. Directionality Verification

For every `send_other` vector, the server's corresponding `recv_other` traffic key
is independently derived (constructing the context from the server's perspective)
and compared. The reverse is also checked: server `send_other` == client `recv_other`.

This confirms that source/destination fields are in correct packet order and that
the same key is produced at both endpoints.

## 5. Packet Structural Validation

Every generated packet is parsed back from hex and checked:

- **Lengths**: IPv4 Total Length / IPv6 Payload Length matches actual byte count
- **Data offset**: TCP data offset matches header + options length
- **TCP-AO option**: Kind=29, Length=20, correct directional KeyID/RNextKeyID pair
  (client-sent: KeyID=0x3d, RNextKeyID=0x54; server-sent: reversed)
- **Option boundaries**: no overlap, no padding errors
- **Payload**: exactly matches source packet (SYN/SYN-ACK have no payload;
  non-SYN packets carry a BGP OPEN message)

## 6. Checksum Verification

Two independent methods:

1. **Internal**: zero checksum field, recompute over pseudo-header + segment, compare
   (IPv4 header checksum and TCP checksum separately)
2. **Scapy**: delete checksum fields, re-serialize packet, verify Scapy recomputes
   identical values (tests both IPv4 and IPv6 paths independently)

## 7. MAC Round-Trip

For each finalized packet:
1. Extract the 16-byte MAC directly from the packet's TCP-AO option bytes
2. Zero the MAC and checksum fields
3. Reconstruct the MAC message from the packet
4. Re-derive the traffic key from connection parameters
5. Recompute the MAC
6. Assert recomputed MAC equals the MAC extracted from the packet

This catches any divergence between the generation path and the packet bytes.

## 8. Matrix Enforcement

Programmatic assertion that exactly 64 vectors exist:
- 2 master-key variants (`testvector`, `testvector-256-bit`) must both be present
- 32 unique parameter tuples per variant:
  2 IP versions × 2 algorithms × 2 option modes × 4 packet types
- No duplicates, no gaps

## 9. Environment

All results are reproducible with pinned versions emitted at the top of every run:
- Python 3.9.21
- pycryptodome 3.23.0
- scapy 2.7.0
- OpenSSL 3.2.2

Machine-readable output (`tcp_ao_test_vectors.json`) includes all intermediate
values (PRK, KDF inputs, MAC message bytes with field boundaries) for
cross-implementation debugging.
