# Acorn Squeeze - Squeezed Object Format (Technical Document)

**Program:** Acorn `squeeze`  
**Domain:** RISC OS / ARM executable image compression  
**Primary Source:** Kevin Bracey reverse-engineered description (2001): `https://www.chiark.greenend.org.uk/~theom/riscos/docs/SqueezedObjectFormat.txt`

---

## 1. Overview

Acorn's `squeeze` format is a word-oriented compression scheme designed for ARM binaries, especially AIF-style images. It combines:

- A compact dictionary for recurring 32-bit patterns
- A nibble-driven encoding for pairs of 32-bit words
- A top-down (high-address to low-address) in-place decompression strategy

The format is tuned for ARM code density, where instruction words and high 24-bit prefixes are often repeated.

---

## 2. File/Image Layout

The compressed image contains:

1. Encoded data stream
2. Compressed dictionary
3. A six-word table header
4. Decompression code

Conceptually:

```text
<-   encoded_size   -> <- tables_size ->
|-----encoded data-----|---dictionary----|-tbl-|--decomp code-|
<- ->
 bytestomove

<-                             decoded_size                              ->
|-------------------------------decoded data--------------------------------|
```

The `bytestomove` value indicates how much relocation/shuffling is needed before or during in-place expansion.

---

## 3. Header/Table Structure

The six-word table (all fields are 32-bit words) is described as:

```c
typedef struct {
    word decoded_size;
    word encoded_size;
    word tables_size;
    word nshorts;
    word nlongs;
    word bytestomove;
} comp_table;
```

Field meanings:

- `decoded_size`: total decompressed output size in bytes
- `encoded_size`: compressed payload size (encoded data portion)
- `tables_size`: size of compressed dictionary block
- `nshorts`: number of 32-bit dictionary entries ("short entries" in source text)
- `nlongs`: number of 24-bit-prefix dictionary entries ("long entries" in source text)
- `bytestomove`: number of bytes to move to avoid overwrite during in-place decode

Observed maxima from the source description:

- up to 1792 short entries
- up to 1792 long entries

---

## 4. Dictionary Model

Before data tokenization, input words are scanned for frequent patterns:

- **Short dictionary**: common full 32-bit words
- **Long dictionary**: common high 24 bits of words

The dictionary is itself compressed using delta-like encodings relative to the previous entry.

Total dictionary entries stored: `nshorts + nlongs`.

### 4.1 Dictionary Entry Coding

Dictionary stream byte forms:

- `00 WW XX YY` -> previous entry + `YYXXWW` (long)
- `00 WW XX YY ZZ` -> previous entry + `ZZYYXXWW` (short)
- `01` to `09` -> emit `n` consecutive entries from the last one
- `0A` to `5B` -> previous entry + `(n - 0A)`
- `5C` to `AD XX` -> previous entry + `((n - 5C) << 8) + XX`
- `AE` to `FF XX YY` -> previous entry + `((n - AE) << 16) + YYXX`

Notes:

- "previous entry" means dictionary values are reconstructed incrementally.
- The coding is monotonic/delta-friendly, matching sorted or clustered value distributions.

---

## 5. Encoded Data Model

Payload is encoded **two words at a time** and decoded from **top down**.

### 5.1 Pair Control Byte

Each pair begins with one control byte at the current highest encoded address:

- low nibble -> lower-address output word in the pair
- high nibble -> higher-address output word in the pair

Additional bytes are read (from decreasing addresses) as required by each nibble's form.

### 5.2 Word Forms by Nibble

For nibble `n`:

- `0` -> literal word `0x00000000`
- `1` + 4 bytes `WW XX YY ZZ` -> literal `WWXXYYZZ`
- `2` to `8` + 1 byte `ZZ` -> `short[((n - 2) << 8) + ZZ]`
- `9` to `F` + 2 bytes `YY ZZ` -> `(long[((n - 9) << 8) + ZZ] << 8) + YY`

Interpretation:

- `2..8` select one of seven 256-entry banks in the short dictionary (7 * 256 = 1792 max).
- `9..F` select one of seven 256-entry banks in the long dictionary (same capacity).
- Long-form reconstruction injects an 8-bit low byte (`YY`) beneath a 24-bit dictionary prefix.

### 5.3 Worked Example from Source

Encoded bytes:

```text
45 12 34 56 78 51
```

Represents:

- one literal word `0x12345678`
- one short-dictionary reference `short[0x345]`

---

## 6. Decompression Direction and In-Place Safety

A key property is **reverse traversal** (high memory to low memory):

- Decoder consumes encoded bytes from high addresses downward.
- Decoder writes output words in descending address order.
- This supports in-place expansion where source and destination regions overlap.

`bytestomove` in the table provides the relocation threshold/amount needed so compressed bytes are not overwritten before consumption.

---

## 7. Practical Characteristics

Why this works well for ARM-era binaries:

- ARM instructions are fixed-width 32-bit words, making word tokenization natural.
- Many instructions share high 24-bit patterns (opcode + register fields), fitting long dictionary mode.
- Frequent repeated literals and opcodes benefit from short dictionary mode.
- Zero words are cheap (`nibble=0`), helping with padding and sparse data.

The source notes that data is typically padded to an even number of words, often with zeros, before compression. For AIF usage this trailing padding is usually harmless.

---

## 8. Decoder-Oriented Pseudocode

```text
read comp_table
locate and decode dictionary into:
  short_dict[0 .. nshorts-1]
  long_dict[0 .. nlongs-1]   // 24-bit values

src = end_of_encoded_data
dst = end_of_output_buffer

while dst not before output_start:
  ctl = *src--
  nib_low  = ctl & 0x0F
  nib_high = ctl >> 4

  // lower-address word in pair
  w0 = decode_word(nib_low, src, short_dict, long_dict)
  // higher-address word in pair
  w1 = decode_word(nib_high, src, short_dict, long_dict)

  store w1 at dst; dst -= 4
  store w0 at dst; dst -= 4

function decode_word(n, src, short_dict, long_dict):
  if n == 0: return 0
  if n == 1:
    b0 = *src--; b1 = *src--; b2 = *src--; b3 = *src--
    return pack32(b0,b1,b2,b3)
  if 2 <= n <= 8:
    zz = *src--
    idx = ((n-2) << 8) + zz
    return short_dict[idx]
  // 9..15
  yy = *src--; zz = *src--
  idx = ((n-9) << 8) + zz
  return (long_dict[idx] << 8) | yy
```

Implementation details like exact byte-order handling depend on the runtime environment and loader conventions.

---

## 9. Constraints and Assumptions

- Input is effectively treated as a word stream.
- Encoded stream grammar assumes pairwise word processing.
- Maximum indexed dictionary space is 1792 per dictionary class.
- Decompressor is expected to run with memory layout compatible with reverse in-place expansion.
- Public documentation is reverse-engineered; edge cases may exist outside this summary.

---

## 10. Sources

1. Kevin Bracey, "Re: Acorn's squeeze", `comp.sys.acorn.programmer`, 13 Dec 2001 (reverse-engineered format description), mirrored at: `https://www.chiark.greenend.org.uk/~theom/riscos/docs/SqueezedObjectFormat.txt`.

2. Access context: this technical document is derived directly from the Bracey description above; no conflicting official Acorn PRM specification for this exact format is cited in the source text.

---

## 11. Historical Note

This format description originates from a reverse-engineering note by Kevin Bracey posted to `comp.sys.acorn.programmer` (Dec 2001), mirrored at chiark. It is widely cited for understanding Acorn `squeeze` behavior where official PRM coverage is limited.
