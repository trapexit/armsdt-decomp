# ARM Image Format

---

ARM Image Format (AIF) is a simple format for ARM executable images,
which consists of a 128 byte header followed by the image's code,
followed by the image's initialised static data.



# Properties of ARM image format

---

Two variants of AIF exist:

- *Executable AIF* (in which the header is part of the image
  itself) can be executed by entering the header at its first word. Code
  in the header ensures the image is properly prepared for execution
  before being entered at its entry address.

- *Non-executable AIF* (in which the header is not part
  of the image, but merely describes it) is intended to be loaded by a
  program which interprets the header, and prepares the following image
  for execution.

The two variants of AIF are distinguished as follows:

- The fourth word of an executable AIF header is BL *entrypoint*. The most significant byte of this word (in the target byte order) is 0xEB.

- The fourth word of a non-executable AIF image is the offset
   of its entry point from its base address. The most significant nibble
  of this word (in the target byte order) is 0x0.

The base address of an executable AIF image is the address at which its header should be loaded; its code starts at *base* + 0x80. The base address of a non-executable AIF image is the address at which its code should be loaded.

The remarks in the following subsection about executable AIF apply also
to non-executable AIF, except that loader code must interpret the AIF
header and perform any required uncompression, relocation, and creation
of zero-initialised data. Compression and relocation are, of course,
optional: AIF is often used to describe very simple absolute images.

## Executable AIF

It is assumed that on entry to a program in ARM Image Format (AIF), the
general registers contain nothing of value to the program (the program
is expected to communicate with its operating environment using SWI
instructions or by calling functions at known, fixed addresses).

A program image in ARM Image Format is loaded into memory at its load
address, and entered at its first word. The load address may be:

- an implicit property of the type of the file containing the image
  (as is usual with Unix executable file types, Acorn Absolute file types,
   etc.);

- read by the program loader from offset 0x28 in the file containing the AIF image;

- given by some other means, e.g. by instructing an operating
   system or debugger to load the image at a specified address in memory.

An AIF image may be compressed and can be self-decompressing (to support
 faster loading from slow peripherals, and better use of space in ROMs
and delivery media such as floppy discs). An AIF image is compressed by a
 separate utility which adds self-decompression code and data tables to
it.

If created with appropriate linker options, an AIF image may relocate
itself at load time. Two kinds of self-relocation are supported:

- relocate to load address (the image can be loaded anywhere and will execute where loaded);

- self-move up memory, leaving a fixed amount of workspace
  above, and relocate to this address (the image is loaded at a low
  address and will move to the highest address which leaves the required
  workspace free before executing there).

The second kind of self-relocation can only be used if the target system
 supports an operating system or monitor call which returns the address
of the top of available memory. The ARM linker provides a simple
mechanism for using a modified version of the self-move code illustrated
 in [Self-move and self-relocation code](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/1atsc.html#XREF20752), allowing AIF to be easily tailored to new environments. Using this facility is described in [Output format options](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/3augd.html#XREF17113).

AIF images support being debugged by the ARM Symbolic Debugger (armsd).
Low-level and source-level support are orthogonal, and both, either, or
neither kind of debugging support need be present in an AIF image.

Details of the format of the debugging tables are not available in this 3DO edition of this manual.

References from debugging tables to code and data are in the form of
relocatable addresses. After loading an image at its load address these
values are effectively absolute. References between debugger table
entries are in the form of offsets from the beginning of the debugging
data area. Thus, following relocation of a whole image, the debugging
data area itself is position independent and may be copied or moved by
the debugger.



# The layout of AIF

---

The layout of a compressed AIF image is as follows:

| Section              | Description                                  |
|----------------------|----------------------------------------------|
| Header               | Image header structure.                     |
| Compressed image     | The compressed program image.               |
| Decompression data   | Position-independent data used for decompression. |
| Decompression code   | Position-independent code used for decompression. |


The header is small, fixed in size, and described below. In a compressed AIF image, the header is *not* compressed.

An uncompressed image has the following layout:

| Section                | Description                                                      |
|------------------------|------------------------------------------------------------------|
| Header                 | Image header structure.                                          |
| Read-Only area         | Read-only code and constant data.                                |
| Read-Write area        | Writable initialized data.                                       |
| Debugging data         | Optional debugging information.                                  |
| Self-relocation code   | Position-independent code used to relocate the image at runtime. |
| Relocation list        | List of words to relocate, terminated by -1.                     |

Debugging data is absent unless the image has been linked using the
linker's -d option and, in the case of source-level debugging, unless
the components of the image have been compiled using the compiler's -g
option.

The relocation list is a list of byte offsets from the beginning of the
AIF header, of words to be relocated, followed by a word containing -1.
The relocation of non-word values is not supported.

After the execution of the self-relocation code - or if the image is not self-relocating - the image has the following layout:


| Section         | Description                                   |
|-----------------|-----------------------------------------------|
| Header          | Image header structure.                      |
| Read-Only area  | Read-only code and constant data.            |
| Read-Write area | Writable initialized data.                   |
| Debugging data  | Optional debugging information.              |


At this stage a debugger is expected to copy any debugging data to
somewhere safe, otherwise it will be overwritten by the zero-initialised
 data and/or the heap/stack data of the program. A debugger can seize
control at the appropriate moment by copying, then modifying, the third
word of the AIF header (see [AIF Header Layout](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/1atsb.html#XREF33429)).

## AIF Header Layout

| Offset (hex) | Field                                   | Description                                                                                                                  |
|--------------|------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| 0x00         | BL DecompressCode                        | NOP if the image is not compressed.                                                                                          |
| 0x04         | BL SelfRelocCode                         | NOP if the image is not self-relocating.                                                                                     |
| 0x08         | BL DBGInit/ZeroInit                      | NOP if the image has none.                                                                                                   |
| 0x0C         | BL ImageEntryPoint or EntryPoint offset  | BL to make the header addressable via r14, but the application shall not return. Non-executable AIF uses an offset, not BL.  |
| 0x10         | Program Exit Instr                       | Last resort in case of return.                                                                                               |
| 0x14         | Image ReadOnly size                      | Includes header size if executable AIF; excludes header size if non-executable AIF.                                          |
| 0x18         | Image ReadWrite size                     | Exact size — must be a multiple of 4 bytes.                                                                                  |
| 0x1C         | Image Debug size                         | Exact size — must be a multiple of 4 bytes.                                                                                  |
| 0x20         | Image Zero-init size                     | Exact size — must be a multiple of 4 bytes.                                                                                  |
| 0x24         | Image Debug type                         | 0, 1, 2, or 3 (see note below).                                                                                              |
| 0x28         | Image base                               | Address the image (code) was linked at.                                                                                      |
| 0x2C         | Work Space                               | Minimum workspace (in bytes) to be reserved by a self-moving relocatable image.                                              |
| 0x30         | Address mode: 26/32 + 3 flag bytes       | Least significant byte contains 26 or 32; bit 8 set when using a separate data base.                                         |
| 0x34         | Data base                                | Address the image data was linked at.                                                                                        |
| 0x38         | Two reserved words                       | Initially 0.                                                                                                                 |
| 0x40         | Debug Init Instr                         | NOP if unused.                                                                                                               |
| 0x44         | Zero-init code (14 words)                | Header is 32 words long.                                                                                                     |


### Notes

`NOP` is encoded as `MOV r0, r0`.

`BL` is used to make the header addressable via r14 in a
position-independent manner, and to ensure that the header will be
position-independent. Care is taken to ensure that the instruction
sequences which compute addresses from these r14 values work in both
26-bit and 32-bit ARM modes.

The *Program Exit Instruction* will usually be a SWI causing
 program termination. On systems which lack this, a branch-to-self is
recommended. Applications are expected to exit directly and *not*
to return to the AIF header, so this instruction should never be
executed. The ARM linker sets this field to SWI 0x11 by default, but it
may be set to any desired value by providing a template for the AIF
header in an area called AIF_HDR in the *first* object file in the input list to *armlink*.

The *Image ReadOnly Size* includes the size of the AIF header only if the AIF type is executable (that is, if the header itself is part of the image).

An AIF image is re-startable if, and only if, the program it contains is re-startable (n.b. an AIF image is *not* reentrant). If an AIF image is to be re-started then, following its
decompression, the first word of the header must be set to NOP.
Similarly, following self-relocation, the second word of the header must
 be reset to NOP. This causes no additional problems with the read-only
nature of the code segment: both decompression and relocation code must
write to it. On systems with memory protection, both the decompression
code and the self-relocation code must be bracketed by system calls to
change the access status of the read-only section (first to writable,
then back to read-only).

The *image debug type* has the following meaning:

| Value | Meaning                                        |
|-------|------------------------------------------------|
| 0     | No debugging data are present.                 |
| 1     | Low-level debugging data are present.          |
| 2     | Source-level (ASD) debugging data are present. |
| 3     | Both 1 and 2 are present together.             |


All other values of image debug type are reserved to ARM Ltd.

The *Debug Initialisation Instruction* (if used) is expected to be a
SWI instruction which alerts a resident debugger that a debuggable
image is commencing execution. Of course, there are other
possibilities within the AIF framework. The ARM cross-linker sets this
field to NOP by default, but it can be customised by providing your
own template for the AIF header in an area called AIF_HDR in the
*first* object file in the input list to *armlink*.

The *Address mode* word (at offset 0x30) is 0, or contains in its
least significant byte (using the byte order appropriate to the
target):

- the value 26, indicating the image was linked for a 26-bit ARM mode,
  and may not execute correctly in a 32-bit mode;

- the value 32, indicating the image was linked for a 32-bit ARM mode,
  and may not execute correctly in a 26-bit mode.

A value of 0 indicates an old-style 26-bit AIF header.

If the *Address mode* word has bit 8 set ((address_mode & 0x100) !=
0), then the image was linked with separate code and data bases
(usually the data is placed immediately after the code). In this case,
the word at offset 0x34 contains the base address of the image's data.



# Zero-initialisation code

---

The Zero-initialisation code is as follows:

```
ZeroInit
        NOP
```

or

```
        SUB     ip, lr, pc              ; base+12+[PSR] - (ZeroInit+12+[PSR])
                                        ; = base - ZeroInit

        ADD     ip, pc, ip              ; (base - ZeroInit) + (ZeroInit + 16)
                                        ; = base + 16

        LDMIB   ip, {r0, r1, r2, r4}    ; load various section sizes

        SUB     ip, ip, #16             ; ip = image base
        ADD     ip, ip, r0              ; + RO size
        ADD     ip, ip, r1              ; + RW size
                                        ; = base of zero-init area

        MOV     r0, #0
        MOV     r1, #0
        MOV     r2, #0
        MOV     r3, #0

        CMPS    r4, #0

00:     MOVLE   pc, lr                  ; nothing left to zero

        STMIA   ip!, {r0, r1, r2, r3}   ; zero 16 bytes per iteration
        SUBS    r4, r4, #16
        B       %B00
```


## Self-move and self-relocation code

This code is added to the end of an AIF image by the linker,
immediately before the list of relocations (which is terminated by
-1). Note that the code is entered via a BL from the second word of
the AIF header so, on entry, r14 -> AIFHeader + 8. In 26-bit ARM
modes, r14 also contains a copy of the PSR flags.

On entry, the relocation code calculates the address of the AIF header
(in a CPU-independent fashion) and decides whether the image needs to
be moved. If the image doesn't need to be moved, the code branches to
*R**elocateOnly*.

```
RelocCode:
        NOP                             ; required by ensure_byte_order() and used below

        SUB     ip, lr, pc              ; base+8+[PSR] - (RelocCode+12+[PSR])
                                        ; = base - 4 - RelocCode
        ADD     ip, pc, ip              ; base - 4 - RelocCode + RelocCode + 16 = base + 12
        SUB     ip, ip, #12             ; -> header address

        LDR     r0, RelocCode           ; load NOP instruction
        STR     r0, [ip, #4]            ; overwrite header, won't be called again on image re-entry

        LDR     r9, [ip, #&2C]          ; load min free space requirement
        CMPS    r9, #0                  ; 0 => no move, just relocate
        BEQ     RelocateOnly
```

If the image needs to be moved up memory, then the top of memory has to
be found. Here, a system service (SWI 0x10) is called to return the
address of the top of memory in r1. This is, of course, system specific
and should be replaced by whatever code sequence is appropriate to the
environment.

```
        LDR     r0, [ip, #&20]        ; image zero-init size
        ADD     r9, r9, r0            ; space to leave = min free + zero-init
        SWI     #&10                  ; return top of memory in r1
```

The following code calculates the length of the image inclusive of its
relocation data, and decides whether a move up store is possible.

```
        ADR     r2, End               ; r2 -> End of relocation list

01:     LDR     r0, [r2], #4          ; load relocation offset, increment r2
        CMNS    r0, #1                ; check for terminator (-1)?
        BNE     %B01                  ; not done, loop again

        SUB     r3, r1, r9            ; MemLimit - freeSpace
        SUBS    r0, r3, r2            ; compute amount to move by
        BLE     RelocateOnly          ; not enough space, jump to relocation routine

        BIC     r0, r0, #15           ; align down to multiple of 16 bytes
        ADD     r3, r2, r0            ; End + shift
        ADR     r8, %F02              ; set intermediate limit for copy-up
```

Finally, the image copies itself four words at a time, being careful
about the direction of copy, and jumping to the copied copy code as
soon as it has copied itself.

```
02:     LDMDB   r2!, {r4-r7}            ; load from source (decrement before)
        STMDB   r3!, {r4-r7}            ; store to destination (decrement before)
        CMPS    r2, r8                  ; have we finished this copy loop?
        BGT     %B02                     ; if not, continue loop
        ADD     r4, pc, r0
        MOV     pc, r4                  ; jump to copied copy code

03:     LDMDB   r2!, {r4-r7}            ; load from source
        STMDB   r3!, {r4-r7}            ; store to destination
        CMPS    r2, ip                  ; have we copied everything?
        BGT     %B03                     ; if not, continue loop
        ADD     ip, ip, r0              ; load address of code
        ADD     lr, lr, r0              ; relocate return address
```

Whether the image has moved itself or not, control eventually arrives
here, where the list of locations to be relocated is processed. Each
location is word sized and is relocated by the difference between the
address the image was loaded at (the address of the AIF header) and
the address the image was linked at (stored at offset 0x28 in the AIF
header).

```
RelocateOnly:
        LDR     r1, [ip, #&28]         ; header + 0x28 = code base set by Link
        SUBS    r1, ip, r1             ; compute relocation offset
        MOVEQ   pc, lr                 ; relocation offset = 0, nothing to do
        STR     ip, [ip, #&28]         ; store new image base = actual load address

        ADR     r2, End                ; start of relocation list

04:     LDR     r0, [r2], #4           ; load offset of word to relocate
        CMNS    r0, #1                 ; check for terminator (-1)?
        MOVEQ   pc, lr                 ; yes => return
        LDR     r3, [ip, r0]           ; load word to relocate
        ADD     r3, r3, r1             ; apply relocation
        STR     r3, [ip, r0]           ; store relocated word back
        B       %B04                    ; repeat for next entry

End:    ; List of offsets to relocate starts here, terminated by -1
```

You can customise the self-relocation and self-moving code generated
by *armlink* by providing your version of it in an area called
AIF_RELOC in the *first* object file in *armlink's* input list.
