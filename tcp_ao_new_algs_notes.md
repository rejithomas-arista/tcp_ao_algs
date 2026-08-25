# TCP-AO New Algorithms: Assumptions, Clarifications & Draft Issues

Reference: draft-ietf-tcpm-tcp-ao-algs-07

## 1. Assumptions Made During Implementation

### 1.1 KMAC256-128 MAC customization string (S="")

**Draft text**: Section 3.2.2 says "MAC_alg is KMAC256" but does not specify the
customization string S for the MAC operation (only the KDF specifies S="KDF").

**Assumption**: S="" (empty string), the SP 800-185 default when no customization
is desired.

### 1.2 KMAC256-KDF counter value

**Draft text**: References SP 800-56Cr2, which uses a 4-byte big-endian counter
starting at 0x00000001.

**Assumption**: Counter is 0x00000001 because the 256-bit output requires only one
KMAC256 invocation.

## 2. Draft Issues Found

### 2.1 CRITICAL: Appendix packets are structurally stale

Appendix A's packet dumps still encode TCP-AO Length `0x10` and a 12-byte MAC,
as used by RFC 9235. The algorithms defined by this draft produce 16-byte MACs.
Therefore, the complete packet dumps need to be regenerated with TCP-AO Length
`0x14` and the corresponding packet lengths, TCP data offsets, and checksums
updated. Replacing only the `TBD` Traffic_Key and MAC fields is insufficient
because the packet dumps themselves contain the old 12-byte MAC values.

### 2.2 Master key length conflict (nonconformant test vectors)

**Draft §3**: "Master_Key MUST be at least 256 bits in length."
**Appendix A**: "Input test vectors are as described in Section 3 of [RFC9235]."
**RFC 9235 §3.1.1**: Master_Key = "testvector" (10 bytes = 80 bits).

The 80-bit key is **nonconformant** with the draft's own normative requirement.

**Our approach**: Generate both:
- 32 provisional vectors using "testvector" (80-bit, for RFC 9235 continuity)
- 32 candidate conformant vectors using "testvector-256-bit-key-tcp-ao!!!" (32 bytes ASCII)

### 2.3 Scope truncation wording to HMAC-SHA256-128

Remove the generic statement that all MACs are truncated. In Section 3.2.1, state:

> The HMAC-SHA256 output is truncated to 128 bits. The first 128 bits are
> preserved and subsequent bits are discarded.

KMAC256-128 uses its specified 128-bit output length; no truncation statement is
needed.

### 2.4 Incorrect HKDF reference (SP 800-185)

Section 3.1.1 states that HKDF-SHA256 is described in SP 800-185, SP 800-56Cr2,
and RFC 5869. SP 800-185 does not define HKDF. Should we replace the sentence
with: “HKDF-SHA256 is specified in [RFC5869].”

### 2.5 Replace the five-parameter KMAC expression

There is no five-input KMAC256 operation. Replace Section 3.1.2 with:

```text
3.1.2.  KMAC256-KDF

   KMAC256-KDF uses the one-step key-derivation function specified in
   Section 4.1 of [DOI.10.6028_NIST.SP.800-56Cr2], with KMAC256 as the
   auxiliary function, as described by Option 3.

   The interface to KMAC256-KDF is:

   *  OKM = KMAC256(salt, counter || Z || FixedInfo,
                    H_outputBits, S)

   where:

   *  OKM is the Traffic_Key.

   *  salt is an all-zero byte string whose length equals 132 bytes.

   *  counter is the 32-bit integer 1, encoded in network byte order.

   *  Z is the Master_Key argument provided to the KDF interface.

   *  FixedInfo is the Context argument provided to the KDF interface.

   *  H_outputBits is equal to 256 bits.

   *  S is the byte string 01001011 || 01000100 || 01000110, which
      represents the sequence of characters "K", "D", and "F" in
      8-bit ASCII.

   Because the required output length is equal to H_outputBits, only
   one KMAC256 invocation is required.
```

## 3. Implementation Validation Summary

| Check | Result |
|---|---|
| RFC 9235 baseline (32 vectors, 2 algorithms × 2 IP × 2 modes × 4 pkts) | 32/32 PASS |
| Cross-validation vs cdleonard/tcp-authopt-test (context, TK, MAC msg, MAC) | 32/32 MATCH |
| HKDF-SHA256 vs RFC 5869 Test Case 1 | PASS |
| HKDF-SHA256 vs OpenSSL `kdf` command | PASS |
| KMAC256 vs NIST CSRC Samples #4, #5, #6 | PASS |
| KMAC output-length dependence (L=128 ≠ L=256[:16]) | Confirmed |
| Packet structure (IPv4/IPv6 lengths, data offset, AO Length=20) | All OK |
| IPv4 header checksums | All OK |
| TCP checksums (independent recomputation) | All OK |
| Scapy cross-validation (delete + re-serialize checksums) | All OK |
| MAC round-trip (parse final packet → recompute MAC → verify) | All OK |
| Matrix enforcement (32 per key variant, 64 total unique tuples) | OK |

## 4. Files

| File | Purpose |
|---|---|
| `tcp_ao_new_algs.py` | Implementation, generation, verification |
| `tcp_ao_new_algs_plan.md` | Detailed implementation plan |
| `tcp_ao_new_algs_notes.md` | This document |
| `tcp_ao_test_vectors.json` | Machine-readable output (64 vectors + intermediates) |
| `cross_validate.py` | Cross-validation against cdleonard/tcp-authopt-test |

## 5. Environment

- Python 3.9.21
- pycryptodome 3.23.0
- scapy 2.7.0
- OpenSSL 3.2.2
- Reference impl: cdleonard/tcp-authopt-test
