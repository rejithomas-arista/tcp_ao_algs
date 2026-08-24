# TCP-AO New Algorithms: Test Vector Generator

Implementation and test vector generation for
[draft-ietf-tcpm-tcp-ao-algs-06](https://datatracker.ietf.org/doc/draft-ietf-tcpm-tcp-ao-algs/),
which adds two new MAC/KDF algorithm pairs to TCP Authentication Option
([RFC 5925](https://www.rfc-editor.org/rfc/rfc5925)):

| MAC Algorithm | KDF | Traffic Key | MAC Output |
|---|---|---|---|
| HMAC-SHA256-128 | HKDF-SHA256 (RFC 5869) | 256 bits | 128 bits |
| KMAC256-128 | KMAC256-KDF (SP 800-56Cr2) | 256 bits | 128 bits |

## What this produces

- **64 test vectors** (32 provisional with RFC 9235's 80-bit key + 32 conformant
  with a 256-bit key), covering IPv4/IPv6, covers/omits options, and all four
  packet types (SYN, SYN-ACK, non-SYN send, non-SYN recv)
- Complete packet hex dumps with corrected 20-byte TCP-AO options (128-bit MACs)
- Machine-readable JSON with all intermediate values (PRK, KDF inputs, MAC
  message bytes, field boundaries) for cross-implementation debugging

## Requirements

- Python 3.9+
- [pycryptodome](https://pypi.org/project/pycryptodome/) (for KMAC256 and AES-CMAC)
- [scapy](https://pypi.org/project/scapy/) (for independent checksum verification)
- OpenSSL 3.x CLI (for HKDF cross-check)

```
pip install pycryptodome scapy
```

## Quick start

```
git clone https://github.com/rejithomas-arista/tcp_ao_algs.git
cd tcp_ao_algs
python3 tcp_ao_new_algs.py
```

This runs the full pipeline:

1. Algorithm known-answer tests (RFC 5869, NIST KMAC samples, OpenSSL cross-check)
2. RFC 9235 baseline validation (32/32 vectors for HMAC-SHA-1-96 and AES-128-CMAC-96)
3. Test vector generation (64 vectors for the two new algorithms)
4. Verification (structural checks, checksums, Scapy cross-validation, MAC
   round-trip, directionality, matrix enforcement)
5. RFC-formatted output of the conformant (256-bit key) vectors
6. JSON output to `tcp_ao_test_vectors.json`

## Cross-validation against reference implementation

To cross-validate against
[cdleonard/tcp-authopt-test](https://github.com/cdleonard/tcp-authopt-test),
clone it as a sibling directory:

```
cd ..
git clone https://github.com/cdleonard/tcp-authopt-test.git
cd tcp_ao_algs
python3 cross_validate.py
```

Or pass the path explicitly:

```
python3 cross_validate.py /path/to/tcp-authopt-test
```

This compares KDF context bytes, traffic keys, MAC message bytes, and MAC
outputs for all 32 RFC 9235 test vectors between both implementations.

## Files

| File | Purpose |
|---|---|
| `tcp_ao_new_algs.py` | Implementation, generation, and verification |
| `cross_validate.py` | Cross-validation against cdleonard/tcp-authopt-test |
| `tcp_ao_new_algs_notes.md` | Assumptions and draft issues found |
| `validation_methodology.md` | Verification methodology (9 steps) |
| `tcp_ao_test_vectors.json` | Generated vectors with all intermediates |

## Draft issues documented

See [tcp_ao_new_algs_notes.md](tcp_ao_new_algs_notes.md) for issues found
during implementation, including:

- Appendix packets are structurally stale (12-byte MACs, wrong lengths/offsets)
- Master key length conflict (80-bit key vs 256-bit MUST)
- KMAC256-128 truncation wording (KMAC output length is not truncation)
- Incorrect SP 800-185 reference in the HKDF section
- Five-parameter KMAC expression needs explicit two-layer explanation
- KMAC256-128 MAC customization string unspecified (we assume S="")
