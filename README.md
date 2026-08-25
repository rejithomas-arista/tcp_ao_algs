# TCP-AO New Algorithms: Test Vector Generator

Implementation and test vector generation for
[draft-ietf-tcpm-tcp-ao-algs-07](https://datatracker.ietf.org/doc/draft-ietf-tcpm-tcp-ao-algs/),
which adds two new MAC/KDF algorithm pairs to TCP Authentication Option
([RFC 5925](https://www.rfc-editor.org/rfc/rfc5925)):

| MAC Algorithm | KDF | Traffic Key | MAC Output |
|---|---|---|---|
| HMAC-SHA256-128 | HKDF-SHA256 (RFC 5869) | 256 bits | 128 bits |
| KMAC256-128 | KMAC256-KDF (SP 800-56Cr2) | 256 bits | 128 bits |

## What this produces

- **32 test vectors** using the draft's 256-bit Master_Key, covering IPv4/IPv6,
  covers/omits options, and all four packet types (SYN, SYN-ACK, non-SYN send,
  non-SYN receive)
- Complete packet hex dumps with corrected 20-byte TCP-AO options (128-bit MACs)
- `tcp_ao_draft_vectors.json`, containing only the Traffic_Key, final packet,
  and MAC outputs needed for Appendix A
- `tcp_ao_test_vectors.json`, containing the same 32 vectors plus intermediate
  values for validation and cross-implementation debugging

## Master keys

Draft vector generation uses only the 32-byte Master_Key specified by revision
`-07`:

```
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

RFC 9235's 10-byte Master_Key, `"testvector"`, is used only to reproduce the
RFC 9235 baseline vectors. It is not used in either generated JSON file.

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
3. Test vector generation (32 vectors for the two new algorithms)
4. Verification (structural checks, checksums, Scapy cross-validation, MAC
   round-trip, directionality, matrix enforcement)
5. RFC-formatted output of the draft vectors
6. Draft output to `tcp_ao_draft_vectors.json` and detailed validation output to
   `tcp_ao_test_vectors.json`

## Cross-validation against reference implementation (RFC 9235)

The new algorithms reuse the same KDF context construction (RFC 5925 §5.2) and
MAC message assembly (RFC 5925 §5.1) as the existing algorithms. To verify this
shared framework is correct, `cross_validate.py` compares our implementation
against [cdleonard/tcp-authopt-test](https://github.com/cdleonard/tcp-authopt-test)
on all 32 RFC 9235 test vectors, checking KDF context bytes, traffic keys,
MAC message bytes, and MAC outputs.

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

## Files

| File | Purpose |
|---|---|
| `tcp_ao_new_algs.py` | Implementation, generation, and verification |
| `cross_validate.py` | Cross-validation against cdleonard/tcp-authopt-test |
| `tcp_ao_new_algs_notes.md` | Assumptions and draft issues found |
| `validation_methodology.md` | Verification methodology (9 steps) |
| `tcp_ao_draft_vectors.json` | Appendix outputs required by the draft |
| `tcp_ao_test_vectors.json` | Generated vectors with validation intermediates |

## Draft issues documented

See [tcp_ao_new_algs_notes.md](tcp_ao_new_algs_notes.md) for issues found
during implementation, including:

- Appendix packets are structurally stale (12-byte MACs, wrong lengths/offsets)
- KMAC256-128 truncation wording (KMAC output length is not truncation)
- Incorrect SP 800-185 reference in the HKDF section
- Five-parameter KMAC expression must be replaced with the standard
  four-parameter KMAC256 interface
- KMAC256-128 MAC customization string unspecified (we assume S="")
