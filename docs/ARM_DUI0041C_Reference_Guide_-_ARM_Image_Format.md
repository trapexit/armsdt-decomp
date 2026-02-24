# ARM Image Format

From **ARM DUI0041C**


## Chapter 13: ARM Image Format

This chapter describes the ARM Image Format (AIF). It contains the
following sections:

- Overview of the ARM Image Format
- AIF variants
- The layout of AIF


## 13.1 Overview of the ARM Image Format

ARM Image Format (AIF) is a simple format for ARM executable images,
consisting of:

- a 128-byte header
- the image code
- the image initialized static data.

An AIF image is capable of self-relocation if it is created with the
appropriate linker options. The image can be loaded anywhere and it
will execute where it is loaded. After an AIF image has been
relocated, it can create its own zero-initialized area. Finally, the
image is entered at the unique entry point.


## 13.2 AIF Variants

There are three variants of AIF:


### Executable AIF

Executable AIF can be loaded at its load address and entered at the
same point (at the first word of the AIF header). It prepares itself
for execution by relocating itself if required and setting to zero its
own zero-initialized data.

The header is part of the image itself. Code in the header ensures
that the image is properly prepared for execution before being entered
at its entry address.

The fourth word of an executable AIF header is:

```
BL entrypoint
```

The most significant byte of this word (in the target byte order) is
`0xeb`.

The base address of an executable AIF image is the address at which
its header should be loaded. Its code starts at `base + 0x80`.


### Non-executable AIF

Non-executable AIF must be processed by an image loader that loads the
image at its load address and prepares it for execution as detailed in
the AIF header. The header is then discarded. The header is not part
of the image, it only describes the image.

The fourth word of a non-executable AIF image is the offset of its
entry point from its base address. The most significant nibble of this
word (in the target byte order) is `0x0`.

The base address of a non-executable AIF image is the address at which
its code should be loaded.


### Extended AIF

Extended AIF is a special type of non-executable AIF. It contains a
scatter-loaded image. It has an AIF header that points to a chain of
load region descriptors within the file. The image loader should place
each region at the location in memory specified by the load region
descriptor.


## 13.3 The Layout of AIF

This section describes the layout of AIF images.


### 13.3.1 AIF Image Layout

An AIF image has the following layout:

- Header
- Read-only area
- Read-write area
- Debugging data (optional)
- Self-relocation code (position-independent)
- Relocation list — a list of byte offsets from the beginning of the
  AIF header, of words to be relocated, followed by a word containing
  `-1`. The relocation of non-word values is not supported.

> **Note:** An AIF image is restartable if, and only if, the program
> it contains is restartable (an AIF image is not
> reentrant). Following self-relocation, the second word of the header
> must be reset to NOP. This causes no additional problems with the
> read-only nature of the code section.

On systems with memory protection, the self-relocation code must be
bracketed by system calls to change the access status of the read-only
section (first to writable, then back to read-only).


### 13.3.2 Debugging Data

After the execution of the self-relocation code, or if the image is
not self-relocating, the image has the following layout:

- Header
- Read-only area
- Read-write area
- Debugging data (optional)

AIF images support being debugged by an ARM debugger. Low-level and
source-level support are orthogonal. An AIF image can have both,
either, or neither kind of debugging support.

References from debugging tables to code and data are in the form of
relocatable addresses. After loading an image at its load address
these values are effectively absolute.

References between debugger table entries are in the form of offsets
from the beginning of the debugging data area. Following relocation of
a whole image, the debugging data area itself is position-independent
and may be copied or moved by the debugger.


### 13.3.3 AIF Header

The following table shows the layout of the AIF header.

> **Note:** In all cases, NOP is encoded as `MOV r0,r0`.

| Offset | Field | Description |
|--------|-------|-------------|
| `0x00` | NOP | — |
| `0x04` | `BL SelfRelocCode` | NOP if the image is not self-relocating. |
| `0x08` | `BL ZeroInit` | NOP if the image has none. |
| `0x0C` | `BL ImageEntryPoint` or `EntryPoint Offset` | BL to make the header addressable via r14 (the application will not return). Non-executable AIF uses an offset, not BL. BL is used to make the header addressable via r14 in a position-independent manner, and to ensure that the header will be position-independent. |
| `0x10` | Program Exit Instruction | Last attempt in case of return. Usually a SWI causing program termination. On systems that do not implement a SWI for this purpose, a branch-to-self is recommended. Applications are expected to exit directly and not to return to the AIF header. The ARM linker sets this field to `SWI 0x11` by default, but it may be set to any desired value by providing a template for the AIF header in an area called `AIF_HDR` in the first object file in the input list to `armlink`. |
| `0x14` | Image ReadOnly Size | Includes the size of the AIF header only if the AIF type is executable (i.e., if the header itself is part of the image). |
| `0x18` | Image ReadWrite Size | Exact size (a multiple of 4 bytes). |
| `0x1C` | Image Debug Size | Exact size (a multiple of 4 bytes). Includes high-level and low-level debug size. Bits 0–3 hold the type. Bits 4–31 hold the low level debug size. |
| `0x20` | Image Zero-Init Size | Exact size (a multiple of 4 bytes). |
| `0x24` | Image Debug Type | Valid values: **0** = No debugging data present; **1** = Low-level debugging data present; **2** = Source level debugging data present; **3** = 1 and 2 are present together. All other values are reserved. |
| `0x28` | Image Base | Address where the image (code) was linked. |
| `0x2C` | Work Space | Obsolete. |
| `0x30` | Address Mode (26/32 + 3 flag bytes) | 0, or contains in its least significant byte: **26** = image linked for 26-bit ARM mode (obsolete); **32** = image linked for 32-bit ARM mode. A value of 0 indicates an old-style 26-bit AIF header. If bit 8 is set, the image was linked with separate code and data bases; the word at `0x34` contains the data base address. |
| `0x34` | Data Base | Address where the image data was linked. |
| `0x38` | Two Reserved Words (initially 0) | In Extended AIF images, the word at `0x38` is non-zero. It contains the byte offset within the file of the header for the first non-root load region. See below for the region header format. |
| `0x40` | NOP | — |
| `0x44` | Zero-Init Code | 15 words. Header is 32 words long. |

**Extended AIF Region Header Format** (44 bytes):

| Word | Description |
|------|-------------|
| 0 | File offset of header of next region (0 if none) |
| 1 | Load address |
| 2 | Size in bytes (a multiple of 4) |
| 3–10 | Region name (32 chars, padded with zeros) |

The initializing data for the region follows the header.
