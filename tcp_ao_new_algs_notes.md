# TCP-AO New Algorithms: Assumptions, Clarifications & Draft Issues

Reference: draft-ietf-tcpm-tcp-ao-algs-06

## 1. Assumptions Made During Implementation

### 1.1 KMAC256-128 MAC customization string (S="")

**Draft text**: Section 3.2 says "MAC_alg is KMAC256" but does not specify the
customization string S for the MAC operation (only the KDF specifies S="KDF").

**Our assumption**: S="" (empty string), which is the SP 800-185 default when
no customization is desired.

**Rationale**: The draft specifies S explicitly for the KDF ("KDF", 0x4B 0x44 0x46)
but is silent on S for the MAC. If a non-empty S were intended, it would have been
stated, as it was for the KDF. An incorrect S produces entirely different output.

**Risk**: If another implementor assumes S="TCP-AO" or any other value, interop
will fail silently. The draft SHOULD state this explicitly.

**Status**: Open — needs WG clarification.

### 1.2 SYN-ACK uses "other" traffic keys, not "SYN" traffic keys

**Draft text**: The draft inherits RFC 5925 Section 5.2 for traffic key assignment.

**Our finding**: RFC 5925 defines "SYN segments" as "SYN set, ACK not set." SYN-ACK
(SYN=1, ACK=1) is NOT a SYN segment and uses Send_other/Receive_other traffic keys,
not Send_SYN/Receive_SYN. This is confirmed by RFC 9235 test vectors where the
SYN-ACK traffic key equals the Receive_other traffic key (both ISNs present in context).

**Verified against**: cdleonard/tcp-authopt-test reference implementation, which passes
both ISNs (src_isn=server_ISN, dst_isn=client_ISN) for SYN-ACK test cases.

### 1.3 KMAC256-KDF counter value

**Draft text**: References SP 800-56Cr2, which uses a 4-byte big-endian counter
starting at 0x00000001.

**Our assumption**: Counter is always 0x00000001 because 256 bits ≤ KMAC256's
maximum single-shot output, so only one iteration is needed.

**Implementation**: `KMAC256(key=0^132, data=0x00000001||Master_Key||Context, mac_len=32, custom="KDF")`

## 2. Draft Issues Found

### 2.1 CRITICAL: Appendix packets are structurally stale

All 32 appendix packet hex dumps are copied verbatim from RFC 9235 and still contain
12-byte MAC fields (96-bit). The new algorithms produce 16-byte MACs (128-bit),
requiring structural changes:

| Field | Current (wrong) | Correct |
|---|---|---|
| TCP-AO Length | `0x10` (16 bytes) | `0x14` (20 bytes) |
| SYN data offset | `0xe` (14 words) | `0xf` (15 words) |
| Non-SYN data offset | `0xc` (12 words) | `0xd` (13 words) |
| IPv4 Total Length | e.g., `0x004c` (76B) | +4 → `0x0050` (80B) |
| IPv6 Payload Length | e.g., `0x0038` (56B) | +4 → `0x003c` (60B) |
| IPv4 header checksum | old | must recompute |
| TCP checksum | old | must recompute |
| Embedded MAC bytes | 12B from RFC 9235 | 16B from new algorithms |

**The complete packet dumps must be replaced, not merely the TBD fields.**

Our implementation generates the corrected packets by mutating the RFC 9235 raw
bytes: replacing the 16-byte TCP-AO option with 20 bytes, adjusting lengths and
checksums, computing the new MAC, and recomputing the TCP checksum.

### 2.2 Master key length conflict (nonconformant test vectors)

**Draft §3**: "Master_Key MUST be at least 256 bits in length."
**Appendix A**: "Input test vectors are as described in Section 3 of [RFC9235]."
**RFC 9235 §3.1.1**: Master_Key = "testvector" (10 bytes = 80 bits).

The 80-bit key is **nonconformant** with the draft's own normative requirement.

**Our approach**: Generate both:
- 32 provisional vectors using "testvector" (80-bit, for RFC 9235 continuity)
- 32 candidate conformant vectors using "testvector-256-bit-key-tcp-ao!!!" (32 bytes ASCII)

### 2.3 KMAC256-128 truncation wording is misleading

**Draft §3.2**: "All MACs are truncated to 128 bits."

This is correct for HMAC-SHA256-128 (truncation = take leftmost 128 bits of a 256-bit
output) but **misleading for KMAC256-128**. KMAC incorporates the requested output
length L into its sponge padding:

```
KMAC256(..., L=128) ≠ KMAC256(..., L=256)[:16]
```

**Suggested replacement**:
> - HMAC-SHA256-128: Compute HMAC-SHA256 and take the leftmost 128 bits.
> - KMAC256-128: Request exactly 128 output bits from KMAC256 with an empty
>   customization string. Do not compute a longer output and truncate.

### 2.4 Incorrect HKDF reference (SP 800-185)

**Draft §3.1.1** cites SP 800-185 in the HKDF-SHA256 section. SP 800-185 defines
SHA-3-derived functions (cSHAKE, KMAC, TupleHash, ParallelHash) and has nothing to
do with HKDF. The reference should be RFC 5869 only.

### 2.5 Five-parameter KMAC expression needs explicit layering

**Draft §3.1.2** presents: `OKM = KMAC256(Z, salt, x, H_outputBits, S)`

There is no five-input KMAC operation. This is shorthand for two layers:

**Layer 1 — SP 800-56Cr2 one-step KDF**:
```
Z         = Master_Key
salt      = 132 zero bytes
FixedInfo = TCP-AO Context (RFC 5925 §5.2)
message   = 0x00000001 || Z || FixedInfo
```

**Layer 2 — Standard KMAC256 (4 parameters)**:
```
Traffic_Key = KMAC256(
    key           = salt (132 zero bytes),
    message       = 0x00000001 || Master_Key || Context,
    output_length = 256 bits,
    customization = "KDF"
)
```

Note: Master_Key appears in the KMAC *message*, not as the KMAC *key*. The all-zero
salt serves as the KMAC key. This follows SP 800-56Cr2 Option 3 exactly.

### 2.6 NIST KMAC test vector reference

**Draft §7** (Security Considerations/References): SP 800-185 §4 defines KMAC but
does not itself contain sample test vectors. The KMAC test vectors are published
separately on NIST CSRC (KMACtestvectors/). The draft should reference the correct
document for implementor validation.

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
