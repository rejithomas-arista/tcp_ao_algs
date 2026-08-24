# TCP-AO New Algorithms: Implementation & Test Vector Verification Plan

## 1. Background

**Draft**: [draft-ietf-tcpm-tcp-ao-algs-06](https://datatracker.ietf.org/doc/draft-ietf-tcpm-tcp-ao-algs/)

This draft extends TCP-AO (RFC 5925) with two new MAC/KDF algorithm pairs:

| MAC Algorithm | KDF | Traffic Key | MAC Output |
|---|---|---|---|
| HMAC-SHA256-128 | HKDF-SHA256 (RFC 5869) | 256 bits (32B) | 128 bits (16B) |
| KMAC256-128 | KMAC256-KDF (SP 800-56Cr2) | 256 bits (32B) | 128 bits (16B) |

The existing algorithms (RFC 5926) are HMAC-SHA-1-96 and AES-128-CMAC-96, both with 96-bit (12B) MACs.

The draft's appendix has 32 test scenarios but **all traffic keys and MAC values are "TBD"**. The packet hex dumps are placeholders copied from RFC 9235 (which used 12-byte MACs). Our job is to implement the algorithms and generate the correct test vectors.

## 2. What Changes vs. RFC 5926

### KDF Changes

RFC 5926 used a **counter-mode PRF** construction:
```
input = byte(i) || "TCP-AO" || Context || uint16(OutputLength_bits)
Traffic_Key = PRF(Master_Key, input)
```

The new draft replaces this entirely:

**HKDF-SHA256** (two-stage, per RFC 5869):
```
Extract:  PRK = HMAC-SHA256(key = 0x00 * 32, data = Master_Key)
Expand:   Traffic_Key = HMAC-SHA256(key = PRK, data = Context || 0x01)
```
- Context = RFC 5925 Section 5.2 format (IPs + ports + ISNs), used directly as `info`
- No "TCP-AO" label, no output-length encoding in info
- Single iteration (32B output = SHA-256 digest size, so one HKDF-Expand round suffices)

**KMAC256-KDF** (one-step KDF per SP 800-56Cr2, Option 3):
```
salt = 0x00 * 132  (default KMAC256 salt length)
X    = 0x00000001 || Master_Key || Context
S    = "KDF" (3 bytes: 0x4B 0x44 0x46)
Traffic_Key = KMAC256(key=salt, data=X, output_len=32, custom=S)
```
- Counter 0x00000001 is from SP 800-56Cr2 (always 1 since 256 bits fits in one KMAC output)
- The draft shows 5 parameters (Z, salt, x, H_outputBits, S) which is the SP 800-56Cr2
  one-step KDF interface — not raw KMAC256 which takes 4 (K, X, L, S). Our implementation
  maps: K=salt, X=counter||Z||x, L=H_outputBits, S=S.
> **Partially covered by reviewer comment** (Section 3.1.2): reviewer flagged the
> 5-vs-4 parameter mismatch but did not identify the SP 800-56Cr2 mapping as the cause.

### MAC Changes

**HMAC-SHA256-128**: `HMAC-SHA256(Traffic_Key, Message)` truncated to 16 bytes.

**KMAC256-128**: `KMAC256(key=Traffic_Key, data=Message, output_len=16, custom="")`.

### Packet Structure Changes

Because the MAC grows from 12B to 16B:
- TCP-AO option: 20 bytes (Kind=29, Length=20, KeyID, RNextKeyID, MAC×16) vs. old 16 bytes
- TCP data offset increases by 1 word (4 bytes)
- IPv4 Total Length increases by 4; IPv6 Payload Length increases by 4
- IPv4 header checksum changes (IPv6 has no header checksum); TCP checksum changes in both

## 3. Unchanged Elements

These are the same across old and new algorithms:

**KDF Context** (RFC 5925 §5.2):
```
IPv4: src_ip(4B) || dst_ip(4B) || src_port(2B) || dst_port(2B) || src_ISN(4B) || dst_ISN(4B) = 20 bytes
IPv6: src_ip(16B) || dst_ip(16B) || src_port(2B) || dst_port(2B) || src_ISN(4B) || dst_ISN(4B) = 44 bytes
```

**Traffic key directionality**:
| Key | Source | Destination | Dst ISN |
|-----|--------|-------------|---------|
| Send_SYN | local | remote | 0 |
| Recv_SYN | remote | local | 0 |
| Send_other | local | remote | remote ISN |
| Recv_other | remote | local | local ISN |

**MAC message** (RFC 5925 §5.1):
```
SNE(4B, zeros) || IP_pseudoheader || TCP_header(checksum+MAC zeroed) || TCP_payload
```

**"Covers options"**: All TCP options included in MAC, TCP-AO MAC field zeroed.
**"Omits options"**: Only base TCP header (20B) + TCP-AO option (MAC zeroed); all other options skipped.

**Connection parameters** (RFC 9235 §3):
| Parameter | Value |
|---|---|
| Master_Key | `"testvector"` (10 bytes ASCII, 80 bits) |
| Client KeyID | 61 (0x3d) |
| Server KeyID | 84 (0x54) |
| Client IPv4 | 10.11.12.13 |
| Server IPv4 | 172.27.28.29 |
| Client IPv6 | fd00::1 |
| Server IPv6 | fd00::2 |
| Server port | 179 (BGP) |
| SNE | 0 (initial connection) |

**Master Key length conflict** (see assumptions doc):
draft-06 §3 says Master_Key MUST be ≥256 bits, but Appendix A inherits RFC 9235's
80-bit `"testvector"` key. These are **nonconformant** with the draft's own normative
requirement. We generate vectors using `"testvector"` since the draft explicitly
references RFC 9235 §3, but mark them **PROVISIONAL** and flag this conflict for the
WG. Additionally generate a conformant set using the 256-bit key
`"testvector-256-bit-key-tcp-ao!!!"` (32 bytes ASCII, consistent with RFC 9235 style).
The WG must decide whether to:
  (a) exempt test vectors from the MUST, or
  (b) adopt the 256-bit key for the appendix.
> **Covered by reviewer comment** (Section A.1): reviewer independently flagged the
> same conflict and recommends defining a new master key.

## 4. Implementation Steps

### Step 1: Validate framework against RFC 9235

Implement RFC 5926's KDFs and MACs (HMAC-SHA-1-96, AES-128-CMAC-96) and verify against all 32 known-good test vectors from RFC 9235. This proves our KDF context construction, MAC message assembly, pseudo-header building, and TCP option handling are correct before we touch the new algorithms.

### Step 2: Implement HKDF-SHA256 KDF

Using Python stdlib (`hmac`, `hashlib`). Two HMAC-SHA256 calls — extract then expand.

### Step 3: Implement KMAC256-KDF

Using `pycryptodome` (`Crypto.Hash.KMAC256`). Single KMAC256 call with SP 800-56Cr2 input formatting.

### Step 4: Implement HMAC-SHA256-128 MAC

Stdlib `hmac` + `hashlib.sha256`, truncate `.digest()[:16]`.

**Important**: HMAC truncation is safe because HMAC output is independent of requested
length. This is NOT the case for KMAC — see Step 5.

### Step 5: Implement KMAC256-128 MAC

`Crypto.Hash.KMAC256` with `mac_len=16`, `custom=b""`.

**Critical**: Request exactly 128 bits from KMAC directly (`mac_len=16`). Do NOT compute
a 256-bit KMAC and truncate — KMAC incorporates the requested output length `L` into the
sponge padding, so `KMAC256(..., L=128) != KMAC256(..., L=256)[:16]`. They are
cryptographically different outputs.

> **Partially covered by reviewer comment** (Section 3.2): reviewer asked whether MAC
> truncation is left or right. Our point goes further — for KMAC256-128, truncation is
> the wrong mental model entirely; the output length must be requested directly. For
> HMAC-SHA256-128, truncation is left (MSB, per RFC 2104). The draft should clarify both.

### Step 6: Construct correct test packets

For each of the 8 test scenarios (ISN sets from RFC 9235), build packets with 20-byte
TCP-AO options by **mutating the RFC 9235 raw packet bytes** — do not reconstruct from
scratch. This preserves every original field (IPv4: ID, DSCP/ECN, flags, TTL; IPv6:
traffic class, flow label, hop limit; TCP: seq/ack, flags, window, urgent pointer;
all TCP options including ordering, timestamps, and padding).

Mutation steps:
1. Locate the 16-byte TCP-AO option in the raw packet
2. Replace it in-place with a 20-byte option (Kind=29, Length=20, same KeyID/RNextKeyID,
   16 zero bytes for MAC)
3. Increment TCP data offset by 1 word
4. IPv4: increment Total Length by 4, recompute header checksum
   IPv6: increment Payload Length by 4 (no header checksum)
5. Compute the MAC (with TCP checksum and MAC field zeroed)
6. Fill in the MAC field
7. Recompute TCP checksum
8. Output complete packet hex dump

### Step 7: Generate both 32-vector sets (64 total)

8 scenarios × 4 packet types each × 2 master key variants = **64 vectors total**:
- IPv4 × HMAC-SHA256-128 × {covers, omits} options
- IPv4 × KMAC256-128 × {covers, omits} options
- IPv6 × HMAC-SHA256-128 × {covers, omits} options
- IPv6 × KMAC256-128 × {covers, omits} options

Each combination is generated twice:
- 32 **provisional** vectors using `"testvector"` (80-bit, nonconformant with draft-06 §3)
- 32 **candidate conformant** vectors using `"testvector-256-bit-key-tcp-ao!!!"` (256-bit)

### Step 8: Create assumptions & clarifications document

Track ambiguities, design decisions, and open questions for the IETF WG.

## 5. Deliverables

| File | Purpose |
|---|---|
| `tcp_ao_new_algs.py` | Implementation + test vector generation |
| `tcp_ao_new_algs_notes.md` | Assumptions, clarifications, open questions |
| `tcp_ao_test_vectors.json` | Machine-readable output (all vectors + intermediates) |

## 6. Dependencies (pinned)

- Python 3.9.21
- OpenSSL 3.2.2 (cross-check)
- pycryptodome 3.23.0 (`Crypto.Hash.KMAC256`, `Crypto.Hash.CMAC`, `Crypto.Cipher.AES`)
- scapy 2.7.0 (independent packet validation)
- Python stdlib: `hmac`, `hashlib`, `struct`, `json`

Version info is emitted at the top of every run.

## 7. Verification Strategy

### 7.1 Algorithm-Level Known-Answer Tests (run before any TCP-AO work)

Verify each primitive against independently published test vectors:

| Primitive | Reference | Purpose |
|---|---|---|
| HKDF-SHA256 | RFC 5869 Appendix A (Test Case 1) | Validate our Extract/Expand code |
| KMAC256 | NIST CSRC KMAC test vectors (KMACtestvectors/) | Validate PyCryptodome API usage (custom string + output length). Note: SP 800-185 §4 defines KMAC but does not itself contain sample vectors; the test vectors are published separately on CSRC. |
| SP 800-56Cr2 construction | Standalone test: `KMAC256(key=0^132, data=0x00000001\|\|MK\|\|Ctx, mac_len=32, custom="KDF")` | Validate our one-step KDF input assembly |

### 7.2 Independent Cross-Checks

Do not validate vectors solely with the generator that created them:

- **HKDF/HMAC**: Cross-check traffic keys against OpenSSL CLI:
  ```
  openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt mode:EXTRACT_AND_EXPAND \
    -kdfopt hexkey:<hex> -kdfopt hexsalt:<hex> -kdfopt hexinfo:<hex> HKDF
  ```
- **KMAC256 primitive**: Cross-check against NIST CSRC KMAC test vectors to validate
  PyCryptodome's KMAC256 gives correct results for known inputs. This validates the
  primitive only — it does not independently verify the TCP-AO KMAC-KDF construction.
- **KMAC256-KDF construction**: Separately validate that our KDF input assembly
  (counter || Master_Key || Context) produces the correct byte string before passing
  it to KMAC256. Log and assert exact KDF input bytes for every vector.
- **Packets/checksums**: Parse every generated packet with Scapy and independently
  recompute IPv4 header checksum and TCP checksum; compare against our values

### 7.3 Intermediate Value Recording

For every vector, record and emit (in both human-readable and JSON):

1. **KDF Context bytes** — full hex dump with field annotations
2. **KDF input** — for HKDF: salt, IKM, PRK, info; for KMAC: salt, counter||MK||Context
3. **Traffic key** — 32-byte hex
4. **MAC message** — full hex dump of SNE || pseudo-header || TCP header || payload,
   with byte counts and field boundaries
5. **MAC output** — 16-byte hex

This makes any disagreement between implementations immediately diagnosable.

### 7.4 MAC Message Construction Verification

For both modes, assert exact byte content and lengths:

- **Covers options**: Verify all TCP options are present in MAC input, TCP-AO MAC field
  is zeroed (16 zero bytes), TCP checksum is zeroed. Assert total MAC input length.
- **Omits options**: Verify only base TCP header (20B) + TCP-AO option (20B, MAC zeroed)
  are present. All other options (MSS, timestamps, SACK, window scale) must be absent.
  Assert total MAC input length.
- **Data offset**: Explicitly verify the data-offset value in the TCP header used for
  MAC input matches the reconstructed packet.

### 7.5 Directionality Checks

For the same connection, assert these equalities:

- Client `Send_other_traffic_key` == Server `Receive_other_traffic_key`
  (same context bytes: client_ip, client_port, client_ISN as src; server as dst)
- Server `Send_other_traffic_key` == Client `Receive_other_traffic_key`
  (same context bytes: server_ip, server_port, server_ISN as src; client as dst)

Source/destination fields stay in packet order — no swapping at verification time.

### 7.6 Final Packet Validation (post-MAC-insertion)

After inserting the computed MAC into each packet:

1. **Parse back from hex** — extract all fields from the generated hex dump
2. **Structural checks**:
   - IPv4 Total Length / IPv6 Payload Length matches actual byte count
   - TCP data offset matches actual header + options length
   - TCP-AO option: Kind=29, Length=20, KeyID and RNextKeyID correct
   - Option boundaries are clean (no overlap, no padding errors)
   - Payload bytes exactly match the source packet (SYN/SYN-ACK have no payload;
     non-SYN packets carry a BGP OPEN message)
3. **Checksum verification**:
   - IPv4: recompute header checksum independently, compare
   - TCP: recompute checksum over pseudo-header + full segment, compare
4. **MAC round-trip**: Zero the MAC field in the parsed packet, reconstruct the MAC
   message, recompute the MAC, confirm it matches the embedded MAC

### 7.7 Scapy Cross-Validation

For each generated packet, parse with Scapy, then force checksum recomputation
(Scapy does NOT recompute checksums on parse — it preserves the wire values):

```python
from scapy.all import IP, IPv6, TCP, Raw

# --- IPv4 ---
pkt = IP(raw_bytes)
assert pkt[TCP].dataofs == expected_data_offset
saved_ip_chk = pkt[IP].chksum
saved_tcp_chk = pkt[TCP].chksum
del pkt[IP].chksum
del pkt[TCP].chksum
pkt_recomputed = IP(bytes(pkt))
assert pkt_recomputed[IP].chksum == saved_ip_chk
assert pkt_recomputed[TCP].chksum == saved_tcp_chk

# --- IPv6 ---
pkt6 = IPv6(raw_bytes)
assert pkt6[TCP].dataofs == expected_data_offset
saved_tcp_chk = pkt6[TCP].chksum
del pkt6[TCP].chksum
# IPv6 has no header checksum — only TCP
pkt6_recomputed = IPv6(bytes(pkt6))
assert pkt6_recomputed[TCP].chksum == saved_tcp_chk
```

### 7.8 Complete Matrix Enforcement

Programmatically assert 32 unique test outputs per master-key variant, 64 total:

```
2 IP versions × 2 algorithms × 2 option modes × 4 packet types = 32
```

Assert no duplicate parameter tuples `(master_key_variant, ip_version, algorithm,
option_mode, packet_type)` and no missing entries — 64 unique tuples total (32 per
master key variant). Note: traffic key values are NOT necessarily unique across the
matrix (e.g., Send_other from client == Receive_other from server by design).

### 7.9 Machine-Readable Output

Emit `tcp_ao_test_vectors.json` alongside RFC-formatted text:
```json
{
  "generator": "tcp_ao_new_algs.py",
  "python_version": "3.9.21",
  "pycryptodome_version": "3.23.0",
  "openssl_version": "3.2.2",
  "vectors": [
    {
      "section": "A.2.1.1",
      "ip_version": 4,
      "algorithm": "HMAC-SHA256-128",
      "option_mode": "covers",
      "packet_type": "Send_SYN",
      "client_isn": "0xfbfbab5a",
      "server_isn": "0x11c14261",
      "kdf_context": "0a0b0c0d...",
      "traffic_key": "...",
      "master_key_variant": "testvector",
      "master_key_hex": "74657374766563746f72",
      "mac_message_len": "<computed>",
      "mac": "...",
      "packet_hex": "45e0..."
    }
  ]
}
```

Alternatively, emit two separate files:
- `tcp_ao_test_vectors_provisional.json` (80-bit key)
- `tcp_ao_test_vectors_conformant.json` (256-bit key)

## 8. Draft Change Suggestions

Issues found during implementation planning that should be raised with the WG/authors.

### 8.1 Appendix packets are structurally stale

All appendix packet hex dumps still contain RFC 9235's 12-byte MAC format. They are
not usable as-is for 128-bit MAC algorithms. Specific byte-level errors:

| Field | Current (wrong) | Correct |
|---|---|---|
| TCP-AO option header | `1d 10` (Kind=29, Length=16) | `1d 14` (Kind=29, Length=20) |
| SYN data offset | `e` (14 words = 56 bytes) | `f` (15 words = 60 bytes) |
| Non-SYN data offset | `c` (12 words = 48 bytes) | `d` (13 words = 52 bytes) |
| IPv4 Total Length | old (e.g., `00 4c` = 76) | +4 (e.g., `00 50` = 80) |
| IPv6 Payload Length | old | +4 |
| IPv4 header checksum | old | must recompute |
| TCP checksum | old | must recompute |
| Embedded MAC bytes | RFC 9235's 12-byte MACs | 16-byte MACs from new algorithms |

**The complete packet dumps must be replaced, not merely the TBD traffic-key and MAC
fields.** Our implementation generates corrected packets.

### 8.2 KMAC256-128 truncation wording

Section 3.2 says "All MACs are truncated to 128 bits." This is correct for HMAC but
misleading for KMAC. KMAC incorporates the requested output length L into its sponge
padding, so `KMAC256(…, L=128)` and `KMAC256(…, L=256)[:16]` produce different outputs.

**Suggested replacement:**

> - HMAC-SHA256-128: Compute HMAC-SHA256 and take the leftmost 128 bits.
> - KMAC256-128: Request exactly 128 output bits from KMAC256 with an empty
>   customization string. Do not compute a longer output and truncate.

### 8.3 Incorrect HKDF reference

Section 3.1.1 cites SP 800-185 in the context of HKDF-SHA256. SP 800-185 defines
SHA-3-derived functions (cSHAKE, KMAC, TupleHash, ParallelHash) — it has nothing to
do with HKDF. The HKDF reference should be RFC 5869 only. Remove the SP 800-185
citation from the HKDF section.

### 8.4 KMAC256-KDF: five-parameter expression needs explicit layering

The draft presents the KDF as a five-parameter operation:

```
OKM = KMAC256(Z, salt, x, H_outputBits, S)
```

There is no five-input KMAC operation. This is shorthand for a two-layer construction
that should be explained explicitly:

**Layer 1 — SP 800-56Cr2 one-step KDF** receives:
```
Z         = Master_Key
salt      = 132 zero bytes
FixedInfo = TCP-AO Context (RFC 5925 §5.2)
```

It constructs the message:
```
message = 0x00000001 || Z || FixedInfo
```

The counter `00 00 00 01` is a 4-byte big-endian integer from SP 800-56Cr2 §4
(always 1, since 256 bits fits in a single KMAC256 output).

**Layer 2 — Raw KMAC256** (standard 4-parameter call per SP 800-185):
```
Traffic_Key = KMAC256(
    key             = salt           (132 zero bytes),
    message         = 0x00000001 || Master_Key || Context,
    output_length   = 256 bits,
    customization   = "KDF"          (0x4B 0x44 0x46)
)
```

Note: Master_Key appears in the KMAC *message*, not as the KMAC *key*. The all-zero
salt serves as the KMAC key. This follows SP 800-56Cr2 Option 3 exactly — the shared
secret Z is embedded in the input message, while salt parameterizes the extraction
function.

> **Partially covered by reviewer comment** (Section 3.1.2): reviewer flagged the
> 5-vs-4 parameter mismatch but did not identify the two-layer structure as the root
> cause or suggest the explicit layering explanation.
