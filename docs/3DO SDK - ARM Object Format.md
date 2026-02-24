# ARM Object Format

This document defines a file format called *ARM Object Format* or *AOF*, which is used by language processors for ARM-based systems.

The ARM linker accepts input files in this format and can generate 
output in the same format, as well as in a variety of image formats. The
 ARM linker is described in [The ARM Linker (armlink)](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/ARM.UG/cAUG.3.armlink.html#XREF21025) in the User Manual.

ARM Object Format directly supports the ARM Procedure Call standard (APCS), which is described in [ARM Procedure Call Standard](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/cATS.4.apcs.html#XREF28151) in this manual.



# About AOF

AOF is a simple object format, similar in complexity and expressive power to Unix's *a.out* format. As will be seen, it provides a generalised superset of a.out's 
descriptive facilities (though this was neither an original design goal 
nor an influence on the early development of AOF).

AOF was designed to be simple to generate and to process, rather than to be maximally expressive or maximally compact.

## Terminology

In the rest of this document, the term *object file* refers to a file in ARM Object Format, and the term *linker* refers to the ARM linker.

The terms *byte, half word, word*, and *string* are used to mean:

| Type      | Description                                                                                                                        |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| byte      | 8 bits; considered unsigned unless otherwise stated. Usually used to store flag bits or characters.                                |
| half word | 16 bits (2 bytes); usually considered unsigned.                                                                                    |
| word      | 32 bits (4 bytes); usually considered unsigned.                                                                                    |
| string    | A sequence of bytes terminated by a NUL (0x00) byte. The NUL byte is part of the string but is not counted in the string's length. |



## Byte sex or endian-ness

There are two sorts of AOF: *little-endian* and *big-endian*.

- In little-endian AOF, the least significant byte of a word or 
  half-word has the lowest address of any byte in the (half-)word. Used by
   DEC, Intel and Acorn, amongst others.

- In big-endian AOF, the most significant byte of a 
  (half-)word has the lowest address. Used by IBM, Motorola and Apple, 
  amongst others.

For data in a file, *address* means offset from the start of the file.

There is no guarantee that the endian-ness of an AOF file will be the 
same as the endian-ness of the system used to process it (the 
endian-ness of the file is always the same as the endian-ness of the 
target ARM system).

The two sorts of AOF cannot, be mixed (the target system cannot have 
mixed endian-ness: it must have one or the other). Thus the ARM linker 
will accept inputs of either sex and produce an output of the same sex, 
but will reject inputs of mixed endian-ness.

## Alignment

Strings and bytes may be aligned on any byte boundary.

AOF fields defined in this document make no use of half-words and align words on 4-byte boundaries.

Within the contents of an AOF file the alignment of words and half-words
 is defined by the use to which AOF is being put. For all current 
ARM-based systems, words are aligned on 4-byte boundaries and half-words
 on 2-byte boundaries.



# The overall structure of an AOF file

An AOF file contains a number of separate but related pieces of data. To
 simplify access to these data, and to give a degree of extensibility to
 tools which process AOF, the object file format is itself layered on 
another format called *Chunk File Format*, which provides a simple 
and efficient means of accessing and updating distinct chunks of data 
within a single file. The object file format defines five chunks:

- the AOF header
- the AOF areas
- the producer's identification
- the symbol table
- the string table

These are described in detail after the description of chunk file format.

## Chunk file format

A chunk is accessed via a header at the start of the file. The header 
contains the number, size, location and identity of each chunk in the 
file.

The size of the header may vary between different chunk files, but is 
fixed for each file. Not all entries in a header need be used, thus 
limited expansion of the number of chunks is permitted without a 
wholesale copy.

A chunk file can be copied without knowledge of the contents of its chunks.

The layout of a chunk file is as follows:

| Field           | Description                                                       |
| --------------- | ----------------------------------------------------------------- |
| ChunkfileId     | Fixed part of header; occupies 3 words and describes what follows |
| maxChunks       |                                                                   |
| numchunks       |                                                                   |
| entry_1         | Four words per entry                                              |
| entry_2         | Four words per entry                                              |
| ...             |                                                                   |
| entry_maxChunks |                                                                   |
| Chunk_1         | End of Header (3+4*maxChunks words)                               |
| ...             |                                                                   |
| chunk_numChunks | Start of Data Chunks                                              |

ChunkFileId-marks the file as a chunk file. Its value is 
0xC3CBC6C5. The endian-ness of the chunk file can be deduced from this 
value (if, when read as a word, it appears to be 0xC5C6CBC3 then each 
word value must be byte- reversed before use).

- maxChunks-defines the number of the entries in the header, fixed when the file is created.

- numChunks-defines how many chunks are currently used in the
   file, which can vary from 0 to maxChunks. numChunks is redundant in 
  that it can be found by scanning the entries.

Each entry in the chunk file header consists of four words in order:

| Field      | Description                                                                                                                                                                                                    |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| chunkId    | 8-byte field identifying what data the chunk contains; (note that this is an 8-byte field, not a 2-word field, so it has the same byte order independent of endian-ness)                                       |
| fileOffset | is a one word field defining the byte offset within the file of the start of the chunk. All chunks are word-aligned, so it must be divisible by four. A value of zero indicates that the chunk entry is unused |
| size       | is a one word field defining the exact byte size of the chunk's contents (which need not be a multiple of four)                                                                                                |

The chunkId field provides a conventional way of identifying what type 

For AOF files, the first part of each chunk's name is "OBJ_"; the second components are defined in the next section.



# ARM object format

Each piece of an object file is stored in a separate, identifiable, chunk. AOF defines five chunks as follows:

| Chunk          | Chunk Name |
| -------------- | ---------- |
| AOF Header     | OBJ_HEAD   |
| Areas          | OBJ_AREA   |
| Identification | OBJ_IDFN   |
| Symbol Table   | OBJ_SYMT   |
| String Table   | OBJ_STRT   |



Only the header and areas chunks must be present, but a typical object file contains all five of the above chunks.

Each name in an object file is encoded as an offset into the string table, stored in the OBJ_STRT chunk (see [The string table chunk (OBJ_STRT)](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/2atsf.html#XREF26065)). This allows the variable-length nature of names to be factored out from primary data formats.

A feature of ARM Object Format is that chunks may appear in any order in
 the file (indeed, the ARM C Compiler and the ARM Assembler produce 
their AOF chunks in different orders).

A language translator or other utility may add additional chunks to an 
object file, for example a language-specific symbol table or 
language-specific debugging data. Therefore it is conventional to allow 
space in the chunk header for additional chunks; space for eight chunks 
is conventional when the AOF file is produced by a language processor 
which generates all 5 chunks described here.

The AOF header chunk should not be confused with the chunk file's header.

## Format of the AOF header chunk

The AOF header consists of two parts, which appear contiguously in the 
header chunk. The first part is of fixed size and describes the contents
 and nature of the object file. The second part has a variable length 
(specified in the fixed part of the header), and consists of a sequence 
of area declarations describing the code and data areas within the 
OBJ_AREA chunk.

The AOF header chunk has the following format:

| Field             | Description                                         |
| ----------------- | --------------------------------------------------- |
| Object File Type  |                                                     |
| Version ID        |                                                     |
| Number of Areas   |                                                     |
| Number of Symbols |                                                     |
| Entry Area Index  |                                                     |
| Entry Offset      | 6 words in the fixed part                           |
| 1st Area Header   | 5 words per area header                             |
| 2nd Area Header   | 5 words per area header                             |
| ...               |                                                     |
| nth Area Header   | (6 + (5 * Number_of_Areas)) words in the AOF header |

An *Object File Type* of 0xC5E2D080 marks the file as being in 
relocatable object format (the usual output of compilers and assemblers 
and the usual input to the linker).

The endian-ness of the object code can be deduced from this value and 
shall be identical to the endian-ness of the containing chunk file.

The Version Id encodes the version of AOF to which the object file 
complies: version 1.50 is denoted by decimal 150; version 2.00 by 200; 
and this version by decimal 310 (0x136).

The code and data of an object file are encapsulated in a number of separate *areas* in the OBJ_AREA chunk, each with a name and some attributes (see 
below). Each area is described in the variable-length part of the AOF 
header which immediately follows the fixed part. Number of Areas gives 
the number of areas in the file and, equivalently, the number of area 
declarations which follow the fixed part of the AOF header.

If the object file contains a symbol table chunk (named OBJ_SYMT), then 
Number of Symbols records the number of symbols in the symbol table.

One of the areas in an object file may be designated as containing the 
start address of any program which is linked to include the file. If 
this is the case, the entry address is specified as an Entry Area Index,
 Entry Offset pair. Entry Area Index, in the range 1 to Number of Areas,
 gives the 1-origin index in the following array of area headers of the 
area containing the entry point. The entry address is defined to be the 
base address of this area plus Entry Offset.

A value of 0 for Entry Area Index signifies that no program entry address is defined by this AOF file.

## Format of area headers

The area headers follow the fixed part of the AOF header. Each area header has the following format:

| Area name              | (offset into string table) |
| ---------------------- | -------------------------- |
| Attributes + Alignment |                            |
| Area Size              |                            |
| Number of Relocations  |                            |
| Base Address or 0      | 5 words total              |

       

Each area within an object file must be given a name which is unique 
amongst all the areas in the file. Area Name gives the offset of that 
name in the string table (stored in the OBJ_STRT chunk - see [The string table chunk (OBJ_STRT)](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/2atsf.html#XREF26065)).

The *Area Size* field gives the size of the area in bytes, which 
must be a multiple of 4. Unless the Not Initialised bit (bit 4) is set 
in the area attributes (see [Attributes + Alignment](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/2atsc.html#XREF41510)),
 there must be this number of bytes for this area in the OBJ_AREA chunk.
 If the Not Initialised bit is set, then there shall be no initialising 
bytes for this area in the OBJ_AREA chunk.

The Number of Relocations word specifies the number of relocation 
directives which apply to this area, (equivalently: the number of 
relocation records following the area's contents in the OBJ_AREA chunk -
 see [Format of the areas chunk](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/2atsd.html#XREF30575)).

The Base Address field is unused unless the area has the absolute 
attribute (see below). In this case the field records the base address 
of the area. In general, giving an area a base address prior to linking,
 will cause problems for the linker and may prevent linking altogether, 
unless only a single object file is involved.

## Attributes + Alignment

Each area has a set of attributes encoded in the most-significant 24 bits of the *Attributes + Alignment* word. The least-significant 8 bits of this word encode the alignment of
 the start of the area as a power of 2 and shall have a value between 2 
and 32 (this value denotes that the area should start at an address 
divisible by 2 () *alignment*).

The linker orders areas in a generated image first by attributes, then 
by the (case-significant) lexicographic order of area names, then by 
position of the containing object module in the link list. The position 
in the link list of an object module loaded from a library is not 
predictable.

The precise significance to the linker of area attributes depends on the output being generated. For details see [The ARM Linker](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/arr3frst.html#XREF25184).

Bit 8-encodes the absolute attribute and denotes that the area must be 
placed at its Base Address. This bit is not usually set by language 
processors.

Bit 9*-*encodes the *code* attribute: if set the area contains code; otherwise it contains data.

Bits 10, 11-encode the common block definition and common block reference attributes, respectively.

Bit 10*-*specifies that the area is a common definition.

Bit 11- defines the area to be a reference to a common block, and
 precludes the area having initialising data (see Bit 12, below). In 
effect, bit 11 implies bit 12. If both bits 10 and 11 are set, bit 11 is ignored.

Common areas with the same name are overlaid on each other by the linker. The *Area Size* field of a common definition area defines the size of a common block. 
All other references to this common block must specify a size which is 
smaller or equal to the definition size. If, in a link step, there is 
more than one definition of an area with the common definition attribute
 (area of the given name with bit 10 set), then each of these areas must
 have exactly the same contents. If there is no definition of a common 
area, its size will be the size of the largest common reference to it.

Although common areas conventionally hold data, it is quite legal to use
 bit 10 in conjunction with bit 9 to define a common block containing 
code. This is most useful for defining a code area which must be 
generated in several compilation units but which should be included in 
the final image only once.

Bit 12-encodes the zero-initialised attribute, specifying that the area 
has no initialising data in this object file, and that the area contents
 are missing from the OBJ_AREA chunk. Typically, this attribute is given
 to large uninitialised data areas. When an uninitialised area is 
included in an image, the linker either includes a read-write area of 
binary zeroes of appropriate size, or maps a read-write area of 
appropriate size that will be zeroed at image start-up time. This 
attribute is incompatible with the read-only attribute (see Bit 13, 
below).

Whether or not a zero-initialised area is re-zeroed if the image is 
re-entered is a property of the relevant image format and/or the system 
on which it will be executed. The definition of AOF neither requires nor
 precludes re-zeroing.

A combination of bit 10 (common definition) and bit 12 (zero 
initialised) has exactly the same meaning as bit 11 (reference to 
common).

Bit 13 encodes the read only attribute and denotes that the area will 
not be modified following relocation by the linker. The linker groups 
read-only areas together so that they may be write protected at 
run-time, hardware permitting. Code areas and debugging tables should 
have this bit set. The setting of this bit is incompatible with the 
setting of bit 12.

Bit 14 encodes the position independent (PI) attribute, usually only of 
significance for code areas. Any reference to a memory address from a PI
 area must be in the form of a link-time-fixed offset from a base 
register (e.g. a PC-relative branch offset).

Bit 15 encodes the debugging table attribute and denotes that the area 
contains symbolic debugging tables. The linker groups these areas 
together so they can be accessed as a single continuous chunk at or 
before run-time (usually, a debugger will extract its debugging tables 
from the image file prior to starting the debugger).

Usually, debugging tables are read-only and, therefore, have bit 13 set also. In debugging table areas, bit 9 (the *code* attribute) is ignored.

Bits 16-19 encode additional attributes of code areas and shall be non-0 only if the area has the code attribute (bit 9 set).

Bit 16 encodes the 32-bit PC attribute, and denotes that code in 
this area complies with a 32-bit variant of the ARM Procedure Call 
Standard (APCS). For details, refer to [32-bit PC vs 26-bit PC](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/4atsb.html#XREF34877). Such code may be incompatible with code which complies with a 26-bit variant of the APCS.

Bit 17 encodes the reentrant attribute, and denotes that code in 
this area complies with a reentrant variant of the ARM Procedure Call 
Standard.

Bit 18, when set, denotes that code in this area uses the ARM's extended
 floating-point instruction set. Specifically, function entry and exit 
use the LFM and SFM floating-point save and restore instructions rather 
than multiple LDFEs and STFEs. Code with this attribute may not execute 
on older ARM-based systems.

Bit 19 encodes the No Software Stack Check attribute, denoting that code
 in this area complies with a variant of the ARM Procedure Call Standard without
 software stack-limit checking. Such code may be incompatible with code 
which complies with a limit-checked variant of the APCS.

Bits 20-27 encode additional attributes of data areas, and shall be non-0 only if the area does not have the code attribute (bit 9) unset.

Bit 20 encodes the based attribute, denoting that the area is 
addressed via link-time-fixed offsets from a base register (encoded in 
bits 24-27). Based areas have a special role in the construction of 
shared libraries and ROM-able code, and are treated specially by the 
linker.

Bit 21 encodes the Shared Library Stub Data attribute. In a link step 
involving layered shared libraries, there may be several copies of the 
stub data for any library not at the top level. In other respects, areas
 with this attribute are treated like data areas with the common 
definition (bit 10) attribute. Areas which also have the zero initialied
 attribute (bite 12) are treated much the same as areas with the common 
reference (bit 11) attribute.

This attribute is not usually set by language processors, but is set only by the linker (refer to [ARM shared library format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrj.html#XREF31382)).

Bits 22-23-reserved and shall be set to 0.

Bits 24-27*-*encode the base register used to address a *based* area. If the area does not have the *based* attribute then these bits shall be set to 0.

Bits 28-31*-*reserved and shall be set to 0.

## Area attributes ummary

| Bit   | Mask       | Attribute Description         | Notes           |
| ----- | ---------- | ----------------------------- | --------------- |
| 8     | 0x00000100 | Absolute attribute            |                 |
| 9     | 0x00000200 | Code attribute                |                 |
| 10    | 0x00000400 | Common block definition       |                 |
| 11    | 0x00000800 | Common block reference        |                 |
| 12    | 0x00001000 | Uninitialised (0-initialised) |                 |
| 13    | 0x00002000 | Read only                     |                 |
| 14    | 0x00004000 | Position independent          |                 |
| 15    | 0x00008000 | Debugging tables              |                 |
| 16    | 0x00010000 | Complies with the 32-bit APCS | Code areas only |
| 17    | 0x00020000 | Reentrant code                | Code areas only |
| 18    | 0x00040000 | Uses extended FP inst set     | Code areas only |
| 19    | 0x00080000 | No software stack checking    | Code areas only |
| 20    | 0x00100000 | Based area                    | Data areas only |
| 21    | 0x00200000 | Shared library stub data      | Data areas only |
| 24-27 | 0x0F000000 | Base register for based area  | Data areas only |
