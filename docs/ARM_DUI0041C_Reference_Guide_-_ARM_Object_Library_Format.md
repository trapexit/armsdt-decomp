# ARM Object Library Format

From **ARM DUI0041C**


## Chapter 14: ARM Object Library Format

This chapter describes the ARM Object Library Format (ALF). It
contains the following sections:

- Overview of ARM Object Library Format
- Endianness and alignment
- Library file format
- Time stamps
- Object code libraries


## 14.1 Overview of ARM Object Library Format

ARM Object Library Format (ALF) is used by the ARM linker and the ARM
object librarian.

A library file contains a number of separate but related pieces of
data. The library file format is layered on another format called
Chunk File Format, which provides a simple and efficient means of
accessing and updating distinct chunks of data within a single
file. Refer to the Chunk File Format section for a description.

The Library format defines four chunk classes: Directory, Time stamp,
Version, and Data. There may be many Data chunks in a library.

The Object Library Format defines two additional chunks: Symbol table
and Symbol table time stamp.


## 14.2 Endianness and Alignment

For data in a file, *address* means offset from the start of the file.

There is no guarantee that the endianness of an ALF file will be the
same as the endianness of the system used to process it (the
endianness of the file is always the same as the endianness of the
target ARM system).

The two sorts of ALF cannot meaningfully be mixed. The ARM linker
accepts inputs of either sex and produces an output of the same sex,
but rejects inputs of mixed endianness.


### 14.2.1 Alignment

Strings and bytes may be aligned on any byte boundary. ALF fields
defined in this document do not use halfwords, and align words on
4-byte boundaries.

Within the contents of an ALF file (within the data contained in
`OBJ_AREA` chunks), the alignment of words and halfwords is defined by
the use to which ALF is being put. For all current ARM-based systems,
alignment is strict.


## 14.3 Library File Format

For library files, the first part of each chunk name is `LIB_`. For
object libraries, the names of the additional two chunks begin with
`OFL_`.

Each piece of a library file is stored in a separate, identifiable
chunk.

| Chunk | Chunk Name |
|-------|-----------|
| Directory | `LIB_DIRY` |
| Time stamp | `LIB_TIME` |
| Version | `LIB_VRSN` |
| Data | `LIB_DATA` |
| Symbol table | `OFL_SYMT` (object code) |
| Time stamp | `OFL_TIME` (object code) |

There may be many `LIB_DATA` chunks in a library, one for each library
member. In all chunks, word values are stored with the same byte order
as the target system. Strings are stored in ascending address order,
which is independent of target byte order.


### 14.3.1 Earlier Versions of ARM Object Library Format

Notes for robustness with earlier, now obsolete, versions:

- Applications which create libraries or library members should ensure
  that the `LIB_DIRY` entries they create contain valid time stamps.
- Applications which read `LIB_DIRY` entries should not rely on any
  data beyond the end of the name string being present, unless the
  difference between the DataLength field and the name-string length
  allows for it.
- Applications which write `LIB_DIRY` or `OFL_SYMT` entries should
  ensure that padding is done with NULL (0) bytes. Applications that
  read these entries should make no assumptions about the values of
  padding bytes beyond the first, string-terminating NULL byte.


### 14.3.2 LIB_DIRY

The `LIB_DIRY` chunk contains a directory of the modules in the
library, each of which is stored in a `LIB_DATA` chunk. The directory
size is fixed when the library is created. The directory consists of a
sequence of variable length entries, each an integral number of words
long.

| Field | Description |
|-------|-------------|
| ChunkIndex | Zero-origin index within the chunk file header of the corresponding `LIB_DATA` chunk. Conventionally, the first three chunks of an OFL file are `LIB_DIRY`, `LIB_TIME` and `LIB_VRSN`, so ChunkIndex is at least 3. A ChunkIndex of 0 means the directory entry is unused. |
| EntryLength | Number of bytes in this `LIB_DIRY` entry, always a multiple of 4. |
| DataLength | Number of bytes used in the data section of this `LIB_DIRY` entry, also a multiple of 4. |
| Data | Contains (in order): a zero-terminated string (the name of the library member, using only ISO-8859 non-control characters); any other information relevant to the library module (often empty); a two-word, word-aligned time stamp. |


### 14.3.3 LIB_VRSN

The version chunk contains a single word whose value is 1.


### 14.3.4 LIB_DATA

A `LIB_DATA` chunk contains one of the library members indexed by the
`LIB_DIRY` chunk. The endianness or byte order of this data is, by
assumption, the same as the byte order of the containing library/chunk
file.

No other interpretation is placed on the contents of a member by the
library management tools. A member could itself be a file in chunk
file format or even another library.


## 14.4 Time Stamps

A library time stamp is a pair of words that encode:

- a six byte count of centiseconds since 00:00:00 1st January 1900
- a two byte count of microseconds since the last centisecond

**First (most significant) word:** Contains the most significant 4
bytes of the 6 byte centisecond count.

**Second (least significant) word:** Contains the least significant
two bytes of the six byte centisecond count in the most significant
half of the word and the two byte count of microseconds since the last
centisecond in the least significant half of the word. This is usually
0.

Time stamp words are stored in target system byte order. They must
have the same endianness as the containing chunk file.


### 14.4.1 LIB_TIME

The `LIB_TIME` chunk contains a two-word (eight-byte) time stamp
recording when the library was last modified.


## 14.5 Object Code Libraries

An object code library is a library file whose members are files in
ARM Object Format. An object code library contains two additional
chunks: an external symbol table chunk named `OFL_SYMT`, and a time
stamp chunk named `OFL_TIME`.


### 14.5.1 OFL_SYMT

The external symbol table contains an entry for each external symbol
defined by members of the library, together with the index of the
chunk containing the member defining that symbol.

The `OFL_SYMT` chunk has exactly the same format as the `LIB_DIRY`
chunk except that the Data section of each entry contains only a
string (the name of an external symbol) and between one and four bytes
of NULL padding:

| Field | Description |
|-------|-------------|
| ChunkIndex | — |
| EntryLength | Size of this `OFL_SYMT` chunk (an integral number of words). |
| DataLength | Size of the External Symbol Name and Padding (an integral number of words). |
| External Symbol Name | — |
| Padding | — |

`OFL_SYMT` entries do not contain time stamps.


### 14.5.2 OFL_TIME

The `OFL_TIME` chunk records when the `OFL_SYMT` chunk was last
modified and has the same format as the `LIB_TIME` chunk.
