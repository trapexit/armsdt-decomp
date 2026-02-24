# The ARM Linker

---

The ARM Linker combines the contents of one or more object files (the 
output of a compiler or assembler) with selected parts of one or more 
object libraries, to produce an executable program.

## About the ARM linker

---

The ARM linker, *armlink*, accepts as input:

- one or more separately compiled or assembled object files written in ARM Object Format (see [ARM object format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrf.html#XREF41738) for a synopsis, and [ARM Object Format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/ats2frst.html#XREF16187) for details);

- optionally, one or more object libraries in ARM Object Library Format (see [ARM Object Library Format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/ats3frst.html#XREF40359) for details).

The ARM linker performs the following functions:

- it resolves symbolic references between object files;

- it extracts from object libraries the object modules needed to satisfy otherwise unsatisfied symbolic references;

- it sorts object fragments (AOF areas) according to their 
  attributes and names , and consolidates similarly attributed and named 
  fragments into contiguous chunks;

- it relocates (possibly partially) relocatable values;

- it generates an output *image* possibly comprising several files (or a partially linked object file instead).

The ARM linker can produce output in any of the following formats:

- ARM Object Format, (see [ARM object format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrf.html#XREF41738) for a synopsis, and [ARM Object Format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/ats2frst.html#XREF16187) for details).

- Plain binary format, relocated to a fixed address, (see [Plain binary format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrg.html#XREF19244)).

- ARM Image Format, (see [ARM image format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrh.html#XREF13245), and also [ARM Image Format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/ats1frst.html#XREF23107) (Technical Specifications).

- Extended Intellec Hex Format, suitable for driving the Compass integrated circuit design tools, (see [Extended intellec hex Format (IHF)](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arri.html#XREF31708)).

- ARM Shared Library Format: a read-only position-independent reentrant sharable code segment (or *shared library*), written as a plain binary file, together with a *stub* containing read-write data, entry veneers, etc., written in ARM Object Format. See [ARM shared library format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrj.html#XREF31382) for details.

- ARM Overlay Format: a *root segment* written in ARM Image Format, together with a collection of *overlay segment**s*,
   each written as a plain binary file. A system of overlays may be static
   (each segment bound to a fixed address at link time), or dynamic (each 
  segment may be relocated when it is loaded).

For details of how to use the options available on the linker command line see [The ARM Linker (armlink)](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/aug3frst.html#XREF21025).



## Library module inclusion

---

An object file may contain references to external objects (functions and
 variables), which the linker will attempt to resolve by matching them 
to definitions found in other object files and libraries.

Usually, at least one library file is specified in the input list. A 
library is just a collection of AOF files stored in an ARM Object 
Library Format file. The important difference between object files and 
libraries is:

- each object file in the input list appears in the output 
  unconditionally, whether or not anything refers to it, (although unused 
  areas will be eliminated from outputs of type AIF);

- a module from a library is included in the output if, and 
  only if, some object file or some already-included library module makes a
   *non-weak* reference to it.

The linker processes its input list as follows:

- First, the object files are linked together, ignoring the 
  libraries. Usually there will be a resultant set of references to as yet
   undefined symbols. Some of these may be *weak*: references which are allowed to remain unsatisfied, and which do not cause a library member to be loaded.

- Then, in the order that they appear in the input file list, the libraries are processed as follows:

the library is searched for members containing symbol definitions which match currently unsatisfied, non-weak references;

- each such member is loaded, satisfying some unsatisfied references (including possibly *weak* ones), and maybe, creating new unsatisfied references (again, maybe including *weak* ones);

- the search is repeated until no further members are loaded.
  
  Each library is processed in turn, so a reference from a member of a 
  later library to a member of an earlier library cannot be satisfied. As a
   result, circular dependencies between libraries are forbidden.
  
  It is an error if any *non-weak* reference remains unsatisfied at 
  the end of a linking operation, other than one which generates 
  partially-linked, relocatable AOF.



## Area placement and sorting rules

---

Each object module in the input list, and each subsequently included library module contains at least one *area*.
 AOF areas are the fragments of code and data manipulated by the linker.
 In all output types except AOF, except where overridden by a -FIRST or 
-LAST option, the linker sorts the set of areas first by attribute, then
 by area name to achieve the following:

- The read-only parts of the image are collected into one contiguous 
  region which can be protected at run time on systems which have memory 
  management hardware. Page alignment between the read-only and read-write
   portions of the image can be forced using the area alignment attribute 
  of AOF areas, set using the ALIGN=*n* attribute of the ARM assembler AREA directive.

- Portions of the image associated with a particular language
   run-time system are collected together into a minimum number of 
  contiguous regions, (this applies particularly to code regions which may
   have associated exception handling mechanisms).

More precisely, the linker orders areas by attribute as follows:

```
read-only code
read-only based data
read-only data
read-write code
based data
other initialised data
zero-initialised (uninitialised) data
debugging tables
```

In some image types (AIF, for example), zero-initialised data is created
 at image initialisation time and does not appear in the image itself.

Debugging tables are included only if the linker's -Debug option is 
used. A debugger is expected to retrieve the debugging tables before the
 image is entered. The image is free to overwrite its debugging tables 
once it has started executing.

Areas unordered by attribute are ordered by AREA name. The comparison of
 names is lexicographical and case sensitive, using the ASCII collation 
sequence for characters.

Identically attributed and named areas are ordered according to their relative positions in the input list.

The -FIRST and -LAST options can be used to force particular areas to be
 placed first or last, regardless of their attributes, names or 
positions in the input list.

As a consequence of these rules, the positioning of identically 
attributed and named areas included from libraries is not predictable. 
However, if library L1 precedes library L2 in the input list, then all 
areas included from L1 will precede each area included from L2. If more 
precise positioning is required then modules can be extracted manually, 
and included explicitly in the input list.

Once areas have been ordered and the base address has been fixed, the 
linker may insert padding to force each area to start at an address 
which is a multiple of 2 ((area alignment)) (but most commonly, *area alignment* is 2, requiring only word alignment).



## Linker pre-defined symbols

---

There are several symbols which the Linker defines independently of any 
of its input files. The most important of these start with the string *Image$$*. These symbols, along with all other external names containing *$$*, are reserved by ARM.

The image-related symbols are:

| Symbol           | Description                                                                             |
| ---------------- | --------------------------------------------------------------------------------------- |
| Image$$RO$$Base  | The address of the start of the read-only area (usually this contains code).            |
| Image$$RO$$Limit | The address of the byte beyond the end of the read-only area.                           |
| Image$$RW$$Base  | The address of the start of the read/write area (usually this contains data).           |
| Image$$RW$$Limit | Address of the byte beyond the end of the read/write area.                              |
| Image$$ZI$$Base  | Address of the start of the 0-initialised area (zeroed at image load or start-up time). |
| Image$$ZI$$Limit | Address of the byte beyond the end of the zero-initialised area.                        |



The object/area-related symbols are the following:

| Symbol          | Description                                                                      |
| --------------- | -------------------------------------------------------------------------------- |
| areaname$$Base  | The address of the start of the consolidated area called areaname.               |
| areaname$$Limit | The address of the byte beyond the end of the consolidated area called areaname. |



Image$$RO$$Limit need not be the same as Image$$RW$$Base, although it 
often will be in simple cases of -AIF and -BIN output formats. 
Image$$RW$$Base is generally different from Image$$RO$$Limit if:

- the -DATA option is used to set the image's data base (Image$$RW$$Base);

- if either of the -SHL or -OVerlay options is used to create a shared library or overlaid image, respectively.

It is poor programming practise to rely on Image$$RO$$Limit being the same as Image$$RW$$Base.

Note that the read/write (data) area may contain code, as programs 
sometimes modify themselves (or better, generate code and execute it). 
Similarly, the read-only (code) area may contain read-only data, (for 
example string literals, floating-point constants, ANSI C const data).

These symbols can be imported and used as relocatable addresses by assembly language programs, or referred to as *extern* addresses from C (using the -fC compiler option which allows dollars in  identifiers). Image region bases and limits are often of use to programming language run-time systems.

Other image formats (for example shared library format) have linker-defined symbolic values associated with them. These are documented in the relevant sections in this chapter, and in a separate documents in the Technical Specifications.



## The handling of relocation directives

---

The linker implements the relocation directives defined by ARM Object 
Format. In this section you will read about their function, omitting 
the fine details given in [ARM Object Format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/ats2frst.html#XREF16187).

### The subject field

A relocation directive describes the relocation of a single *subject field*, the value of which may be:

- a byte;
- a half-word (2 bytes);
- a word (4 bytes);
- a value derived from a suitable sequence of instructions.

The relocation of a word value cannot overflow. In the other three 
cases, overflow is detected and faulted by the linker. The relocation of
 sequences of instructions is discussed later in this section.

### The relocation value

A relocation directive either refers to the value of a symbol, or to the
 base address of an AOF area in the same object file as the AOF area 
containing the directive. This value is called the *relocation value*, and the subject field is modified by it, as described in the following subsections.

### PC-relative relocation

A PC-relative relocation directive requests the following modification of the subject field:

```
subject-field = subject-field + relocation-value
                - base-of-area-containing (subject-field)
```

A special case of PC-relative relocation occurs when the relocation 
value is specified to be the base of the area containing the subject 
field. In this case, the relocation value is not added and:

```
subject-field = subject-field - base-of-area-containing 
    (subject-field)
```

which caters for a PC-relative branch to a fixed location, for example.

### Forcing use of an inter-link-unit entry point

A second special case of PC-relative relocation (specified by REL_B being set in the rel_flags field - see [ARM Object Format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/ats2frst.html#XREF16187) for details) applies when the relocation value is the value of a code symbol. It requests that the *inter*-link-unit value of the symbol be used, rather than the *intra*-link-unit
 value. Unless the symbol is marked with the SYM_LEAFAT attribute (by a 
compiler or via the assembler's EXPORT directive), the *inter*-link-unit value will be 4 bytes beyond the *intra*-link-unit value.

This directive allows the tail-call optimisation to be performed on 
reentrant code. For more information about tail call continuation see [Function entry-Introduction](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/4atsc.html#XREF29579).

### Additive relocation

A plain additive relocation directive requests that the subject field be modified as follows:

```
subject-field = subject-field + relocation-value
```

### Based area relocation

A based area relocation directive relocates a subject field by the 
offset of the relocation value within the consolidated area containing 
it:

```
subject-field = subject-field + relocation-value
            - base-of-area-group-containing (relocation-value)
```

For example, when compiling reentrant code, the C compiler places address constants in an *adcon* area called sb$$adcons based on register *sb*, and generates code to load them using *sb*-relative LDRs. At link time, separate adcon areas are merged, so *sb* no longer points where presumed at compile time (except for the first 
area in the consolidated group). The offset field of each LDR (other 
than those in the first area) must be modified by the offset of the base
 of the appropriate adcon area in the consolidated group:

```
LDR-offset = LDR-offset + base-of-my-sb$$adcons-area
                - sb$$adcons$$Base
```

### The relocation of instruction sequences

The linker recognises the following instruction sequences as defining a relocatable value:

- a B or BL;
- an LDR or STR;
- 1 to 3 ADD or SUB instructions, having a common destination 
  register and a common intermediate source register, and optionally 
  followed by an LDR or STR with that register as base.

For example, the following is a relocatable instruction sequence:

```
ADD    Rb, rx, #V1
ADD    Rb, Rb, #V2
LDR    ry, [Rb, #V3]
```

with value V = V1+V2+V3.

The length of sequence recognised may be further restricted to 1, 2 or 3
 instructions only by the relocation directive itself (see [Relocation directives](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/2atsd.html#XREF30764)).

After relocation, the new value of V is split between the instructions as follows:

- If the original offset in the LDR or STR can be preserved, it will 
  be preserved. This is possible if the difference between the new value 
  and the original LDR offset can be encoded in the available number of 
  ADD/SUB instructions. This preservation allows a sequence of ADDs and 
  SUBs to compute a common base address for several following LDRs or 
  STRs.

The remainder of the new value is split between the ADDs or SUBs as follows:

- If the new value is negative, it is negated, ADDs are changed to SUBs (or vice versa) and LDR/STR *up* is changed to LDR/STR *down* (or vice versa).

- Each ADD or SUB instruction, in turn, removes the most 
  significant part of the (now positive) new value, which can be 
  represented by an 8-bit constant, shifted left by an even number of bit 
  positions (i.e. which can be represented by an ARM data-processing 
  instruction's immediate value).

If there is no following LDR or STR, and the value remaining is non-zero, then the relocation has overflowed.

If there is a following LDR or STR, then any value remaining is assigned
 to it as an immediate offset. If this value is greater than 4095, then 
the relocation has overflowed.

In the relocation of a B or BL instruction, word offsets are converted 
to and from byte offsets. A B or BL is always relocated by itself, never
 in conjunction with any other instruction.



## ARM object format

---

An object file written in ARM Object Format (AOF) consists of any number of named, attributed *areas*. Attributes include: read-only; reentrant; code; data; position independent; etc. (for details see [Attributes + Alignment](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/2atsc.html#XREF41510) of the Technical Specifications). Typically, a compiled AOF file 
contains a read-only code area, and a read-write data area, (a 
0-initialised data area is also common, and reentrant code uses a 
separate based area for address constants).

Associated with each area is a (possibly empty) list of relocation 
directives which describe locations that the linker will have to update 
when:

- a non-zero base address is assigned to the area;
- a symbolic reference is resolved.

Each relocation directive may be given relative to the (not yet 
assigned) base address of an area in the same AOF file, or relative to a
 symbol in the symbol table. Each symbol may:

- have a definition within its containing object file which is local to the object file;

- have a definition within the object file which is visible globally (to all object files in the link step);

- be a reference to a symbol defined in some other object file.

When AOF is used as an output format, the linker does the following with its input object files:

- merges similarly named and attributed areas;

- performs PC-relative relocations between merged areas;

- re-writes symbol-relative relocation directives between 
  merged areas, as area-based relocation directives belonging to the 
  merged area;

- minimises the symbol table.

Unresolved references remain unresolved, and the output AOF file may be used as the input to a further link step.



## Plain binary format

---

An image in plain binary format is a sequence of bytes to be loaded into
 memory at a known address. How this address is communicated to the 
loader, and where to enter the loaded image, are not the business of the
 linker.

In order to produce a plain binary output there must be:

- no unresolved symbolic references between the input objects, (each reference must resolve directly or via an input library);

- an absolute base address (given by the -Base option to *armlink*);

- complete performance of all relocation directives.

Input areas having the read-only attribute are placed at the low-address
 end of the image; initialised writable areas follow; 0-initialised 
areas are consolidated at the end of the file where a block of zeroes of
 the appropriate size is written.



## ARM image format

---

At its simplest, a file in ARM Image Format (AIF) is a plain binary 
image preceded by a small (128 byte) header which describes what 
follows.

At its most sophisticated, AIF can be considered to be a collection of envelopes which enwrap a plain binary image, as follows:

- The outer wrapper allows the inner layers to be compressed using any
   compression algorithm to which you have access which supports efficient
   decompression at image load time, either by the loader or by the loaded
   image itself. In particular, AIF defines a simple structure for images 
  which decompress themselves, consisting of: AIF header; compressed 
  contents; decompression tables; decompression code.

- The next layer of wrapping deals with relocating the image 
  to its load address. Three options are supported: link-time relocation; 
  load-time relocation to whatever address the image has been loaded at; 
  load time relocation to a fixed offset from the top of memory. In 
  particular, an AIF image is capable of self-relocation or self-location 
  (to the high address end of memory), followed by self-relocation.

- Once an AIF image has been decompressed and relocated, it can create its own zero-initialised area.

- Finally, the enwrapped image is entered at the (unique) entry point found by the linker in the set of input object modules.

Two flavours of AIF are supported:

- Executable AIF, can be loaded at its load address and entered at the
   same point (at the first word of the AIF header). It prepares itself 
  for execution by relocating itself, zeroing its own 0-initialised data, 
  etc.

- Non-executable AIF must be processed by an image loader, 
  which loads the image at its load address and prepares it for execution 
  as detailed in the AIF header. The header is then discarded.

An executable AIF image is loaded at its load address (which may be 
arbitrary if the image is relocatable), and entered at the same address.
 Eventually, control passes to a branch to the image's entry point.

In order to produce an AIF output there must be:

- no unresolved symbolic references between the input objects, (each reference must resolve directly or via an input library);

- exactly one input object containing a program entry point 
  (or no input area containing an entry point, and the entry point given 
  using an -Entry option);

- either an absolute load address or the relocatable option given to the linker, (the self-location option is system-dependent).

The AIF header is specified fully in [The layout of AIF](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/1atsb.html#XREF12900).

The contents of some fields of the AIF header (such as the program exit 
instruction) can be customised by providing a template for the header in
 an area with the name AIF_HDR and a length of 128 bytes, in the *first* object module in the list of object modules given to *armlink*.

Similarly, the self-move and self-relocation code appended by the linker
 to a relocatable AIF image can customised by providing an area with the
 name AIF_RELOC, also in the *first* object module in the input list.



## Extended intellec hex Format (IHF)

---

This format is for small (< 64KB) images, such as those destined for 
ROM. IHF is essentially a plain binary format, encoded as 32-bit hex 
values and checksummed. All the restrictions of plain binary format 
apply to the generation of IHF.



## ARM shared library format

---

ARM Shared Library format directly supports:

- shared code in ROM;
- single-address-space, loadable, shared libraries.

Output in ARM Shared Library Format generates 2 files:

- a read-only, position-independent, reentrant shared library, written 
  as a plain binary file;

- a *stub* file containing read-write data, entry vectors, etc., 
  written in ARM Object Format, with which clients of the shared library 
  will subsequently be linked.

Optionally, a shared library can contain a read-only copy of its 
initialised static data which can be copied at run time to a 
zero-initialised place holder in the stub. Such data must be free of 
relocation directives.

The outputs are created from:

- a set of input object files, between/from which there must be no 
  unresolved symbolic references;

- a description of the shared library which includes the list of symbols 
  to be exported from the library to its clients and a description of the 
  data areas to be initialised at run time by copying from the shared 
  library image.

Code to be placed in a shared library must be compiled with the reentrant 
option, or if it is assembled, it must conform to the shared library 
addressing architecture described in [The shared 
library addressing architecture](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrj.html#XREF31509).

### Stub properties

The linker can generate a non-reentrant stub for use by non-reentrant 
client applications, or a reentrant stub which can be linked into another 
shared library or reentrant application.

The details of how a stub is initialised at load time or run time (so that 
a call to a stub entry point becomes a call to the corresponding library 
function) are system-specific. The linker provides a general mechanism for 
attaching code and data to both the library and the stub to support this. 
In particular:

- The linker appends a table of offsets of library entry points (the 
  Exported Function Table or EFT) to the library, followed by a parameter 
  block specified in the shared library description input to the linker.

- The linker writes the same parameter block to the stub, and 
  initialises the stub entry vector so that the first call through any 
  element of it is to the *dynamic linking code*. The dynamic linking 
  code can patch the stub entry vector given only a pointer to its shared 
  library's EFT. After dynamic linking, execution resumes by calling through 
  the stub vector entry which initially invoked the dynamic linking code. 
  The dynamic linking code will not be called again (for this shared 
  library).

- If the library contains a read-only copy of its initialised static 
  data, the linker writes the length and relocatable address of the place 
  holder immediately before the stub parameter block and writes the length 
  and offset of the initialising data immediately before the library 
  parameter block. For uniformity of dynamic linking, the length and 
  address or offset can be zero, denoting that neither initialising data nor 
  a stub place holder are present in this shared library (though they may be 
  present in other shared libraries handled by the same dynamic linker).

Provided the stub entry vector is writable, the only system-specific part 
of the matching of the stub to (a compatible version of) its library, is 
the location of the library itself. In general, this is expected to be a 
system service, though it would be equally possible to search a table at a 
fixed address, or simply search the whole of ROM for a named library (the 
linker provides support for prepending a name, the offset of the EFT, and 
anything else that can be assembled to a shared library).

Alternatively, in support of more protected systems, the patching code can 
simply be a call to a system service which locates the matching library 
and patches the entry vector.

The patching of shared library entry vectors by the loader at load time is 
not directly supported. However, it would be a relatively simple extension 
to AIF to support this. In general, it is considered more efficient to 
patch on demand in systems with multiple shared libraries.

The user-specified parameter block mechanism allows fine control over, and 
diagnosis of the compatibility of a stub with a version of its shared 
library. This supports a variety of approaches to *foreverness*, 
without mandating foreverness where it would be inappropriate. This issue 
is discussed in [Versions, compatibility and 
foreverness](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrj.html#XREF10379).

### The shared library addressing architecture

The central issue for shared objects is that of addressing their clients' 
static data.

On ARM processors, it is very difficult, and/or inefficient to avoid the 
use of address constants when addressing static data, particularly the 
static data of separately compiled or assembled objects; (an address 
constant is a pointer which has its value bound at link time-in effect, it 
is an execution-time constant).

Typically, in non-reentrant code, these address constants are embedded in 
each separately compiled or assembled code segment, and are, in turn, 
addressed relative to the program counter. In this organisation, all 
threadings of the code address the same, link-time bound static data.

In a reentrant object, these address constants (or adcons) are collected 
into a separate area (in AOF terminology called a *based* area) which 
is addressed via the *sb* register. When reentrant objects are linked 
together, the linker merges these adcon areas into a single, contiguous 
adcon vector, and relocates the references into the adcon vector 
appropriately (usually by adjusting the offset of an LDR ..., [sb, offset] 
instruction). The output of this process is termed a *link unit*.

In this organisation, it is possible for different threadings of the code 
to address different static data, and for the binding of the code to its 
data to be delayed until execution time, (an excellent idea if the code 
has to be committed to ROM, even if reentrancy is not required).

When control passes into a new link unit, a new value of sb has to be 
established; when control returns, the old value must be restored. A call 
between two separately linked program fragments is called an *inter link 
unit call*, or *inter-LU* call. The inter-LU calls are precisely 
the calls between a shared library's stub and the library's matching entry 
points.

Because an LDR instruction has a limited (4KB) offset, the linker packs 
adcons into the low-address part of the *based-sb* area. It is a 
current restriction that there can be no more than 1K adcons in a client 
application (but this number seems adequate to support quite large 
programs using several megabytes of sharable code).

The linker places the data for the inter-LU entry veneers immediately 
after the adcon vector (still in the based-sb area). If the stub is 
reentrant (to support linking into other shared libraries), then the 
inter-LU entry data consists of:

- the data part of the inter-LU veneer for each direct inter-LU call 
  (which is addressed sb-relative from the separate inter-LU code part);

- the entry veneer for each address-taken library function (i.e. for 
  each function that could be invoked via a function pointer).

If the stub is not reentrant, then the inter-LU entry data is an array of 
function variable veneers, one for each directly exported or address-taken 
function in the library.

A reentrant function called via a function pointer or from a non-reentrant 
caller, must have its sb value loaded pc-relative, as there is no sb value 
relative to which to load it. In turn, this forces the entry veneer to be 
part of the client's private data (or there could be no reentrancy).

### Including data areas in a shared library

Usually, a shared library only includes areas which have both the CODE and 
READONLY attributes.

When you ask for a read-only copy of a data area to be included in a 
shared library, the linker checks it is a simple, initialised data area. 
The following *cannot* be included in a shared library:

- zero-initialised data (these always remain in the stub);

- COMMON data;

- stub data from the stubs of other shared libraries with which this 
  library is being linked;

- inter-link-unit entry data and address constants.

When an area is found to be suitable for inclusion in a shared library, 
the following is done:

- A clone of the area is created with the name SHL$$data and the 
  attribute READONLY. It inherits its initialising data from the original 
  area but it inherits no symbol definitions.

- The original area is renamed $$0 and given the attribute 0INIT. It 
  inherits all of the symbols defined in the original area.

Area renaming is essential to ensure that multiple input areas will be 
sorted identically by the linker in both the stub and the sharable library 
and that both the placeholder and its initialising data will be sorted 
into contiguous chunks. This identicaly ordered contiguity - together with 
the absence of relocation directives - allows the placeholder to be 
initialised by directly copying its initialising image from the sharable 
library.

Names containing $$ are reserved to the implementors of the ARM software 
development tools, so these linker-invented area names cannot clash with 
any area name you choose yourself.

### Entry veneers

The inter-LU code for a direct, reentrant inter-LU call is:

```
FunctionName
ADD    ip, sb, #V1                                 ; calculate offset of veneer 
data 
                            ; from sb
ADD    ip, ip, #V2            
    LDMIA  ip, {ip, pc}                            ; load new-sb and pc 
values
```

This allows up to 32K entry veneers to be addressed, (V1 and V2 are 
jointly relocated by the linker and support a word offset in the range 
0-65K). The corresponding inter-LU data is:

```
    DCD    new-sb                                  ; sb value for called link 
unit
    DCD    entry-point                             ; address of the 
library entry point
```

Both of these values are created when the stub is patched, as introduced 
above and described in detail below.

The inter-LU code for an indirect or non-reentrant inter-LU call is:

```
FunctionName
    ADD    ip, pc, #0                              ; ip = pc+8
    LDMIA  ip, {ip, pc}                            ; load new-sb and pc 
values
    DCD    new-sb                                  ; sb value for called link 
unit
    DCD    entry-point                             ; address of the library 
entry point
```

Again, the data values are created when the stub is patched.

#### Entry veneer initial values

The linker initialises the data part of each entry veneer as follows:

- new-sb: the index of the entry point in the array of entry points 
  (note that the entries may not be of uniform length in the reentrant case);
- entry-point: the address of a 4-word code block, placed at the end of 
  the inter-LU data by the linker.

Overall, an adcon/inter-LU-data area for a link unit has the layout:

```
Base                                                ; sb points here
```

```
End
    STMFD  sp!, {r0-r6,r14}                          ; save work 
registers and lr
    LDR    r0, End-4                                 ; load address of End
    B      |__rt_dynlink|                            ; do the dynamic 
linking...
    DCD    Params - Base                             ; offset to 
sb-value
Params
```

Note the assumption that a stack has been created *before* any 
attempt is made to access the shared library. Note also that the word 
preceding *End* is initialised to the address of *End*.

#### Entry veneer patching

A simple version of the dynamic linking code, `__rt_dynlink`, 
referred to above, can be implemented as described in this section.

On entry to `__rt_dynlink`, a copy of the pointer is saved to 
the code/parameter block at the end of the inter-LU data area, and a bound 
is calculated on the stub size (the entries are in index order).

```
|__rt_dynlink|
    MOV    r6, r0
    LDR    r5, [r6, #-8]                         ; max-entry-index
    ADD    r5, r5, #1                            ; # max entries in stub
    MOV    r4, ip                                ; resume index
```

Then it is necessary to locate the matching library, which the following 
fragment does in a simple system-specific fashion. Note that in a library 
which contains no read-only static data image, r0+16 identifies the user 
parameter block (at the end of the inter-LU data area); if the library 
contains an initialising image for its static data then r0+24 identifies 
the user parameter block.

Here, the library location function is shown as a SWI which takes as its 
argument in r0 a pointer to the user paramter block and returnsthe address 
of the matching External Function Table in r0:

```
    ADD    r0, r6, #24                             ; stub parameter block 
address
    SWI    Get_EFT_Address                         ; are you there?
    BVS    Botched                                 ; system-dependent
```

R0 now points to the EFT, which begins with the number of entries in it. A 
simple sanity check is that if there are fewer entries in the library than 
in the stub, it has probably been patched incorrectly.

```
    LDR    ip, [r0]                           ; #entries in lib
    CMPS   ip, r5                             ; >= #max entries in stub?
    BLT    Botched                            ; no, botched it...
```

If the shared library contains data to be copied into the stub then check 
the length to copy:

```
    LDR    ip, [r6, #16]                          ; stub data length
    BIC    ip, ip, #3                             ; word aligned, I 
insist...
    ADD    r3, r6, #4
    LDR    r3, [r3, r5, LSL #2]                   ; library 
data length
    CMPS   r3, ip
    BNE    Botched                                ; library and stub 
lengths differ            
```

Checking the stub data length and library data length match is a naive, 
but low-cost, way to check the library and the stub are compatible. Now 
copy the static data from the library to the stub:

```
    LDR    r3, [r6, #20]                             ; stub data 
destination
    SUB    r2, r0, ip                                ; library data 
precedes the EFT
01  SUBS   ip, ip, #4                                ; word by word copy 
loop
    LDRGE  r1, [r2], #4
    STRGE  r1, [r3], #4
    BGE    %B01
```

Then initialise the entry vectors. First, the sb value is computed for the 
callee:

```
    LDR    ip, [r6, #12]                             ; length of 
inter-LU data area
    ADD    r3, r6, #24                               ; end of data area...
    SUB    r3, r3, ip                                ; start of data area 
= sb value
```

If there is no static data in the library then #24 above becomes #16.

Then the following loop works backwards through the EFT indices, and 
backwards through the inter-LU data area, picking out the indices of the 
EFT entries which need to be patched with an sb, entry-point pair. Ip 
still holds the index of the entry which caused arrival at this point, 
which is the index of the entry to be retried after patching the stub. The 
corresponding retry address is remembered in r14, which was saved by the 
code fragment at the end of the inter-LU data area before it branched to 
__rt_dynlink. A small complication is that the step back through a 
non-reentrant stub may be either 8 bytes or 16 bytes. However, there can 
be no confusion between an index (a small integer) and an ADD instruction, 
which has some top bits set.

```
    LDR    r2, [r6, #-8]!                            ; index of stub 
entry
00  SUB    ip, r5, #1                                ; index of the lib 
entry
    CMPS   ip, r2                                    ; is this lib entry in 
the stub?
    SUBGT  r5, r5, #1                                ; no, skip it
    BGT    %B00
    CMPS   r2, r4                                    ; found the retry index?
    MOVEQ  lr, r6                                    ; yes: remember retry 
address  
    LDR    ip, [r0, r5, lsl #2]          ;           ; entry 
point offset
    ADD    ip, ip, r0                                ; entry point address
    STMIA  r6, {r3, ip}                              ; save {sb, pc}
    LDR    r2, [r6, #-8]!                            ; load index and 
decrement r6...
    TST    r2, #&ff000000                            ; ... or if 
loaded an instr?
    LDRNE  r2, [r6, #-8]!                            ; ...load index 
and decrement r6
    SUBS   r5, r5, #1                                ; #EFT entries left...
    BGT    %B00
```

Finally, when the vector has been patched, the failed call can be 
retried:

```
    MOV    ip, lr                                    ; retry address
    LDMFD  sp!, {r0-r6, lr}                          ; restore saved 
regs
    LDMIA  ip, {ip, pc}                              ; and retry the call
```

### Versions, compatibility and foreverness

The mechanisms described so far are very general and, of themselves, give 
no guarantee that a stub and a library will be compatible, unless the stub 
and the library were the complementary components produced by a single 
link operation.

Often, in systems using shared libraries, stubs are bound into 
applications which must continue to run when a new release of the library 
is installed. This requirement is especially compelling when applications 
are constructed by third party vendors or end users.

The general requirements for compatibility are as follows:

- a library must be at least as new as the calling stub;

- libraries can only be extended, and then only by *disjoint* *extension* (adding new entries to a library, or by giving to 
  existing entries new interpretations to previously unused parameter value 
  combinations).

In general, the compatibility of a stub and a library can be reduced to 
the compatibility of their respective versions. The ARM shared library 
mechanism does not mandate how versions are described, but provides an 
open-ended parameter block mechanism which can be used to encode version 
information to suit the intended usage.

Because the addresses of library entry points are not bound into a stub 
until run-time, the only foreverness guarantees a library must give are:

- its entry points are in the same order in its EFT (this is a property 
  of the shared library description given to the linker, not of the 
  library's implementation);

- the behaviour of each exported function must be maintained compatibly 
  between releases (beware that it is genuinely difficult to prevent users 
  relying on unintended behaviour-the curse of bug compatibility).

Because a stub contains the indices of the entry points it needs, it is 
harmless to add new entry points to a library: the dynamic linking code 
simply ignores them. Of course, they must be added to the end of the list 
of exported functions if the first property, above, is to be maintained.

For libraries which export only code, and which make no use of static 
data, compatibility is straightforward to manage. Use of static data is 
more hazardous, and the direct export of it is positively lethal.

If a static data symbol is exported from a shared library, what is 
actually exported is a symbol in the library's stub. This symbol is bound 
when the stub is linked into an application and, from that instant 
onwards, cannot be unbound. Thus the direct export of a data symbol fixes 
the offset and length of the corresponding datum in the shared library's 
data area, forever (i.e. until the next incompatible release).

The linker does not fault the direct export of data symbols because the 
ARM shared library mechanism may not be being used to build a shared 
library, but is instead being used to structure applications for ROM. In 
this case a prohibition could be irksome. Those specifying or building 
genuine shared libraries need to be aware of this issue, and should 
generally not make use of directly exported data symbols. If data must be 
exported directly then:

- only export data which has very stable specifications (semantics, 
  size, alignment, etc.);

- place this data first in the library's data area, to allow all other 
  non-exported data to change size and shape in future releases (subject to 
  its total size remaining constant).

If a shared library makes any use of static data then it is prudent to 
include some unused space, so that non-exported data may change size and 
shape (within limits) in future releases without increasing the total size 
of the data area. Remember that if a *forever binary* guarantee is 
given, the size of the data area may never be increased.

In practice, it is rare for the direct export of static data to be 
genuinely necessary. Often a function can be written to take a pointer to 
its static data as an argument, or a function can be used to return the 
address of the relevant static data (thus delaying the binding of the 
offset and size of the datum until run-time, and avoiding the foreverness 
trap). It is only if references to a datum are frequent and ubiquitous 
that direct export is unavoidable. For example, a shared library 
implementation of an ANSI C library might export directly errno, stdin, 
stdout and stderr, (and even errno could be replaced by (*__errno()), with 
few implications).

### Describing a shared library to the linker

A shared library description consists of a sequence of lines. On all 
lines, leading white space (blank, tab, VT, CR) is ignored.

If the first significant character of a line is a semicolon (';') then the 
line is ignored. Lines beginning with ';' can be used to embed comments in 
a shared library description. A comment can also follow a \ which 
continues a parameter block description.

If the first significant character of a line is > then the line gives 
the name and parameter block for the library. Such lines can be continued 
over several contiguous physical lines by ending all but the last line 
with ''. For example:

```
> testlib        \        ; the name of the library image file
  "testlib"      \        ; the text name of the library -> parameter 
block
  101            \        ; the library version number
  0x80000001    
```

The first word following the > is the name of the file to hold the 
shared library binary image; the argument to the linker's -Output option 
is used to name the stub. Following tokens are parameter block entries, 
each of which is either a quoted string literal or a 32-bit integer. In 
the parameter block, each entry begins on a 4-byte boundary.

Within a quoted string literal, the characters '"' and '' must be preceded 
by '' (the same convention as in the C programming language). Characters 
of a string are packed into the parameter block in ascending address 
order, followed by a terminating NUL and NUL padding to the next 4-byte 
boundary.

An integer is written in any way acceptable to the ANSI C function 
strtoul() with a base of 0. That is, as an optional '-' followed by one 
of:

- a sequence of decimal digits, not beginning with 0;
- a 0 followed by a sequence of octal digits;
- 0x or 0X followed by a sequence of hexadecimal digits.

Values which overflow or are otherwise invalid are not diagnosed.

A line beginning with a '+' describes input data areas to be included, 
read-only, in the shared library and copied at run time to place holders 
inthe library's clients. The general format of such lines is a list of *object*(*area)* pairs instructing the linker to include area *area* from object *object*:

```
+ object ( area ) object ( area ) ...
```

If *object* is omitted then any object in the input list will match. 
For example:

```
 + (C$$data)
```

instructs the linker to include all areas called *C$$data*, whatever 
objects they are from.

If *area* is omitted too, then all sutitable input data areas will be 
included in the library. This is the most common usage. For example:

```
+ ()
```

Finally, a '+' on its own *excludes* all input data areas from the 
shared library but instructs the linker to write zero length and address 
or offset words immediately preceding the stub and library parameter 
blocks, for uniformity of dynamic linking.

All remaining non-comment lines are taken to be the names of library entry 
points which are to be exported, directly or via function pointers. Each 
such line has one of the following three forms:

```
entry-name
entry-name()
entry-name(object-name)
```

The first form names a directly exported global symbol: a direct entry 
point to the library, or the name of an exported datum (deprecated).

The second form names a global code symbol which is exported indirectly 
via a function pointer. Such a symbol may also be exported directly.

The third form names a non-exported function which, nonetheless, is 
exported from the library by being passed as a function argument, or by 
having its address taken by a function pointer. To clarify this, suppose 
the library contains:

```
void f1(...) {...}
void f2(...) {...}
static void f3(...) {...}                    /* from object module o3.o */
static void (*fp2)(...) = f2;
void (*pf3)(...) = f3;
```

...and that *f1* is to be exported directly. Then a suitable 
description is:

```
f1
f2()
f3(o3)
pf3                /* deprecated direct export of a datum */
```

Note that *f2* and *f3* have to be listed even though they are 
not directly exported, so that function variable veneers can be created 
for them.

*f3* must be qualified by its object module name, as there could be 
several non-exported functions with the same name (each in a differently 
named object module). Note that the *module* name, not the name of 
the file containing the object module, is used to qualify the function 
name.

If *f2* were to be exported directly then the following list of entry 
points would be appropriate:

```
f1
f2
f2()
f3(o3)
pf3
```

Unless all address-taken functions are included in the export list, the 
linker will complain and refuse to make a shared library.

### Linker pre-defined symbols

While a shared library is being constructed the linker defines several 
useful symbols:

| Symbol          | Definition                                                                                         |
| --------------- | -------------------------------------------------------------------------------------------------- |
| EFT$$Offset     | Offset of the External Function Table from the beginning of the shared library;                    |
| EFT$$Params     | Offset of the shared library's parameter block from its beginning;                                 |
| $$0$$Base       | The (relocatable) address of the zero-initialised place holder in the stub;                        |
| SHL$$data$$Base | Offset of the start of the read-only copy of the data from the beginning of the shared library;    |
| SHL$$data$$Size | Size of the shared library's data section, which is also the size of the place holder in the stub. |

EFT$$Offset and EFT$$Params are exported to the stub and may be referred 
to in following link steps; the others exist only while the shared library 
is being constructed.



## Overlays

---

The linker supports both static and dynamic overlays.

### Static overlays

In the static case, a simple 2-dimensional overlay scheme is supported. 
There is one root segment, and as many memory partitions as specified by
 the user (called, for example, 1_, 2_, etc.). Within each partition, 
some number of overlay segments (called, for example, 1_1, 1_2, ...) 
share the same area of memory. The user specifies the contents of each 
overlay segment and the linker calculates the size of each partition, 
allowing sufficient space for the largest segment in it. All addresses 
are calculated at link time so statically overlaid programs are not 
relocatable. A hypothetical example of the memory map for a statically 
overlaid program might be:

| 2_1     | 2_2 | 2_3 |      | high address |
| ------- | --- | --- | ---- | ------------ |
| 1_1     | 1_2 | 1_3 | 1_4  |              |
| segment |     |     | root | low address  |

Segments 1_1, 1_2, 1_3 and 1_4 share the same area of memory. Only one 
of these segments can be loaded at any given instant; the remainder must
 be on backing store.

Similarly, segments 2_1, 2_2 and 2_3 share the 2_ area of memory, but this is entirely separate from the 1_ partition.

It is a current restriction that an overlay segment name is of the form *partition_segment* and contains 10 or fewer characters. However, it is *not* required that *partition* and *segment* be numeric as shown here in the example: any alphanumeric characters are acceptable.

### Dynamic overlays

A dynamic or relocatable overlay scheme is obtained by specifying the -Relocatable command line option. In this case:

- the root segment is a (load-time) relocatable AIF image;
- each overlay segment is a plain binary image with relocation directives appended.

When using relocatable overlays, it is expected that:

- the overlay manager will allocate memory for a segment when it is first referenced;

- a segment will be unloaded, and the memory it occupies freed, by an explicit call to the overlay manager.

In this case, it suffices to give each overlay segment a simple name (no
 embedded underscore), and let the linker link each as if it were in its
 own partition (which is dynamically allocated by the overlay manager).

Nevertheless, if a 2-dimensional naming scheme is used, the linker will 
generate segment clash tables (see below), and segments can be unloaded 
implicitly by the overlay manager when a clashing segment is loaded. In 
effect, this supports the classification of dynamic overlay segments 
into disjoint sets of *not co-resident* objects.

A dynamic overlay segment (including a root segment) is followed by a 
sequence of relocation directives. The sequence is terminated by a word 
containing -1. Each directive is a 28-bit byte offset of a word or 
instruction to be relocated, together with a flag nibble in the most 
significant 4 bits of the word. Flag nibbles have the following 
meanings:

|     |                                                                                                                                                                                                                                                                                                                                  |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0   | relocate a word in the root segment by the difference between the address at which the root was loaded and the address at which it was linked;                                                                                                                                                                                   |
| 1   | relocate a word in an overlay segment by the address of the root;                                                                                                                                                                                                                                                                |
| 2   | relocate a word in an overlay segment by the address of the segment;                                                                                                                                                                                                                                                             |
| 3   | relocate a B or BL from an overlay segment to the root segment, by the difference (in words) between the segments address and the roots address;                                                                                                                                                                                 |
| 7   | relocate a B or BL from the root segment to an overlay segment, by the difference (in words) between the root's address and the segment's address, (such relocation directives always refer to a PCIT entry in an overlay segment, which is \|used to initialise a PCIT section in the root when the overlay segment is loaded). |



### Assignment of AREAs to overlay segments

The linker assigns AOF AREAs to overlay segments under user control (see
 below). Usually, a compiler produces one code AREA and one data AREA 
for each source file (called C$$code and C$$data when generated by the C
 compiler). The C compiler option -ZO allows each separate function to 
be compiled into a separate code AREA, allowing finer control of the 
assignment of functions to overlay segments, (but at the cost of 
slightly enlarged code and enlarged object files). The user controls the
 overlay structure by describing the assignment of certain AREAs to 
overlay segments. For each remaining AREA in the link list, the linker 
will act as follows:

- if all references to the AREA are from the same overlay segment, the AREA is included in that segment; otherwise,

- the AREA is included in the root segment.

This strategy can never make an overlaid program use more memory than if
 the linker put all remaining AREAs in the root, but it can sometimes 
make it smaller.

By default, only code AREAs are included in overlay segments. Data AREAs
 can be forcibly included, but it is the user's responsibility to ensure
 that doing so is meaningful and safe.

On disc, an overlaid program is organised as a directory containing a 
root image and a collection of overlay segments. The name of the 
directory is specified to the Linker as the argument to its -Output 
flag. The linker creates the following components within the application
 directory:

```
root
```

the root segment, which is an AIF image, and (for example):

```
1_1
1_2
...
2_1
...
```

overlay segments, which are plain binary image fragments.

### Describing an overlay structure to the linker

The overlay file, named as argument to the -OVerlay option, describes the required overlay structure. It is a sequence of *logical lines*:

- a '' immediately before the end of a physical line continues the logical line on the next physical line;

- any text from a ';' to end of the logical line inclusive is
   a comment (for documentation purposes) which is ignored by the linker.

Each logical line has the following structure:

```
segment-name                module-name                    [ "(" list-of-AREA-names ")" ]
                module-name                    ...
```

For example:

```
1_1    edit1 edit2 editdata(C$$code,C$$data) sort
```

*list-of-AREA-names* is a comma-separated list. If omitted, all AREAs with the CODE attribute are included.

*module-name* is either the name of an object file (with all 
leading pathname components and file name extensions removed), or the 
name of a library member (again, with all leading pathname components 
and file name extensions removed).

In the example above, sort would match the C library module of the same name.

Note that these rules require that, within a link list, modules have 
unique names. For example, it is not possible to overlay a program made 
up from *test/thing.o* and *thing.o* (two modules called *thing*). This is a restriction on overlaid programs only.

To help partition a program between overlay segments the linker can 
generate a list of inter-AREA references. This is requested by using the
 -Xref option. In general, if area A refers to area B, for example 
because *fx* in area A calls *fy* in area B, then A and B should not share the same area of memory. Otherwise, every time *fx* calls *fy*, or *fy* returns to *fx*, there will be an overlay segment swap.

The -MAP option requests the linker to print the base address and size 
of every AREA in the output program. Although not restricted to use with
 overlaid programs, -MAP is most useful with them, as it shows how AREAs
 might be packed more efficiently into overlay segments.



## The overlay manager

---

This section describes in detail how a static overlay manager operates. 
The details of a dynamic overlay manager are very similar. In both 
cases, details specific to the target system are omitted.

The job of the overlay manager is to load, swap, and unload, overlay 
segments. This is done by trapping inter-segment function calls.

References to data are resolved statically by the linker when each 
overlay segment is created. De-referencing a datum cannot cause an 
overlay segment to be loaded.

Every inter-segment procedure call is indirected through a table in the 
root segment that traps unloaded target overlay segments, (the procedure
 call indirection table, or PCIT). PCITs are created by the linker.

Each overlay segment contains the data required to initialise its 
section of the PCIT when it is loaded. This is simply a table of B *fn* instructions, one for each function exported by the overlay segment. As
 the linker knows the locations of each segment of the PCIT and of each 
function exported by each overlay segment, it can create these B *fn* instructions at link time.

(In a dynamic overlay scheme, all segments, including the root, are 
assumed to be linked at 0, and a type 7 relocation directive is 
generated to describe the relocation of each of the initializing branch 
instructions).

Initially, every sub-section of the procedure-call indirection table (PCIT) in the root segment is initialised with:

```
STR LR,    [PC, #-8]
```

(One for each procedure exported by the corresponding overlay segment).

A call to an entry in the root PCIT overwrites that entry, and every 
following entry, with the return address, until control falls off the 
end of that section of the PCIT into code which:

- finds which entry was called;

- loads the corresponding overlay segment (and executes its relocation directives, if it is relocatable);

- overwrites the PCIT subsection with the associated branch vector (from the just-loaded overlay segment);

- retries the call.

Future calls to this section of the PCIT will encounter instructions of the form B *fn*,
 adding only a few cycles to the procedure call overhead. This will 
persist until some function call, function return, or explicit call to 
the overlay manager causes this PCIT segment to be overwritten.

The load-segment code not only loads an overlay, but also re-initialises
 the PCIT sections corresponding to segments with which it cannot 
co-reside. It also installs handlers to catch returns to segments which 
have been unloaded.

### The structure of a PCIT section

The per-PCIT-section code and data structures are shown immediately 
below. These are created by the linker and used by the overlay manager. 
They are justified and explained in following subsections. The space 
cost of this code is (9 + #Clashes + #Entries) words per overlay 
segment. Most of the work is done in the function *load_seg_and_go* (which is shared between all PCIT sections), and in *load_segment* (which is the common tail for both *load_seg_and_go* and *load_seg_and_ret*). For an explanation of *load_seg_and_ret* see [Intercepting returns to overwritten segments](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrl.html#XREF14699).

```
        STR    LR, [PC, #-8]                                    ; guard word
EntryV  STR    LR, [PC, #-8]                                    ; > one entry for each
        ...                                    ; > procedure exported
        STR    LR, [PC, #-8]                                    ; > by this overlay segment
        BL     load_seg_and_go
PCITSection
Vecsize DCD    .-4-EntryV                                    ; size of entry vector
Base    DCD    ...                                    ; initialised by the linker
Limit   DCD    ...                                    ; initialised by the linker
Name    DCB    
```

```
Flags   DCB    0                                    ; ...and a flag byte
ClashSz DCD    PCITEnd-.-4                                    ; size of table following
Clashes DCD    ...                                    ; >table of pointers or offsets
  ...                                    ; >to segments which cannot
        DCD    ...                                    ; >co-reside with this one
PCITEnd
```

Pointers to clashing segments point to the appropriate PCIT*Section* labels (i.e. into the middle of PCIT sections).

(If the overlays are relocatable, then offsets between PCIT*Section* labels are used rather than addresses which would themselves require relocation).

We now define symbolic offsets from PCIT*Sections* for the data introduced here. These are used in the *load_seg_and_go* code described in the next subsection.

```
O_Vecsize   EQU Vecsize-PCITSection
O_Base      EQU Base-PCITSection
O_Limit     EQU Limit-PCITSection
O_Name      EQU Name-PCITSection
O_Flags     EQU Flags-PCITSection
O_ClashSz   EQU ClashSz-PCITSection
O_Clashes   EQU Clashes-PCITSection
```

### The load_seg_and_go code

The *load_seg_and_go* code contains a register save area which is shared with *load_seg_and_ret*. Both of these code fragments are veneers on *load_segment*.
 Both occur once in the overlay manager, not once per segment. Note that
 the register save area could be separated from the code and addressed 
via an address constant, as *ip* is available for use as a base 
register. For simplicity we ignore that here. Note also that 
load_segment and its veneers preserve *fp*, *sp*, and *sl*, which is vital.

```
    STRLR  STR LR, [PC, #-8]                                    ; a useful constant
    Rsave  %   10*4                                    ; for R0-R9
    LRSave %   4
    PCSave %   4
load_seg_and_go
    STR    R9, RSave+9*4                                    ; save a base register...
    ADR    R9, RSave
    STMIA  R9, {R0-R8}                                    ; ...and some working registers
    BIC    R8, LR, #&FC000003                                    ; clear out status bits 
                                    ; (26-bit mode)
    LDR    R0, R8, #-8]                                    ; saved R14 from EntryV...
    STR    R0, LRSave                                    ; ...save here ready for retry
    LDR    R0, STRLR                                    ; look for this...
    SUB    R1, R8, #8                                    ; ...starting at penultimate 
                                    ; overwrite
01  LDR    R2, [R1, #-4]!
    CMP    R2, R0                                    ; must stop on guard word...
    BNE    %B01
    ADD    R1, R1, #4                                    ; gone one too far...
    AND    R0, LR, #&FC000003                                    ; status bits at call 
                                    ; (26 bit mode)
    ORR    R1, R1, R0
    STR    R1, PCSave                                    ; where to resume at
    B      load_segment                                    ; ...and off to the common tail
```

On entry to load_segment, R9 points to a register save for 
{R0-R9,LR,PC}, and R8 identifies the segment to be loaded. FP, SP and SL
 are preserved at all times by the overlay segment manager. There is 
only one copy of *load_seg_and_go*, shared between all PCIT sections.

A similar section of code, called *load_seg_and_ret*, is invoked on return to an unloaded segment (see [Intercepting returns to overwritten segments](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrl.html#XREF14699)). This code is also a veneer on *load_segment* which shares RSave, LRSave and PCSave, and which branches to *load_segment* with R8 and R9 set up as described above.

Note that the code for STR LR, [PC, #-8] is 0xE50FE008. This address is 
unlikely to be in application code space, so overwriting indirection 
table entries with an application's return addresses is safe.

### The load_segment code

Load_segment must carry out the following:

- re-initialise the global PCIT sections for any overlay segment which
   'clashes' with this one, while checking the stack for return addresses 
  which are invalidated by so doing, and installing return handlers for 
  them;

- allocate memory for the about-to-be-loaded segment, (if the overlay scheme is dynamic) - this is system-specific;

- load the required overlay segment (system-specific);

- execute the loaded segment's relocation directives (if any);

- copy the overlay segment's PCIT into the global PCIT;

- restore the saved register state (with pc and lr suitably modified).

On entry to load_segment, R9 points to the register save area, and R8 to
 the PCIT section of the segment to load. First the code must 
re-initialise the PCIT section (if any) which clashes with this one:

```
load_segment
    ADD    R1, R8, #O_Clashes
    LDR    R0, [R8, #O_ClashSz]
01  SUBS   R0, R0, #4
    BLT    Done_Reinit                                    ; nothing left to do
    LDR    R7, [R1], #4                                    ; a clashing segment...
    ADD    R7, R7, R8                                    ; only if root is relocatable
    LDRB   R2, [R7, #O_Flags]
    CMPS   R2, #0                                    ; is it loaded?
    BEQ    %B01                                    ; no, so look again
    MOV    R0, #0
    STRB   R0, [R7, #O_Flags]                                    ; mark as unloaded
    LDR    R0, [R7, #O_Vecsize]
    SUB    R1, R7, #4                                    ; end of vector
    LDR    R2, STRLR                                    ; init value to store...
 02 STR    R2, [R1, #-4]!                    ;>
    SUBS   R0, R0, #4                                    ;> loop to initialise the 
                                    ; PCIT segment
    BGT    %B02                                    ;>
```

Next, the stack of call frames for return addresses invalidated by 
loading this segment is checked, and handlers are installed for each 
invalidated return. This is discussed in detail in the next subsection. 
Note that R8 identifies the segment being loaded, and R7 the segment 
being unloaded.

```
BL    check_for_invalidated_returns
```

Segment clashes have now been dealt with, as have the re-setting of the 
segment-loaded flags and the intercepting of invalidated returns. It's 
now time to load the required segment. This is system specific, so the 
details are omitted; (the name of the segment is at offset O_Name from 
R8).

On return, calculate and store the real base and limit of the loaded segment and mark it as loaded:

```
    BL     _host_load_segment                        ; return base address in R0

    LDR    r4, [r8, #PCITSect_Limit]
    LDR    r1, [r8, #PCITSect_Base]
    SUB    r1, r4, r1                        ; length
    STR    r0, [r8, #PCITSect_Base]                        ; real base
    ADD    r0, r0, r1                        ; real limit
    STR    r0, [r8, #PCITSect_Limit]
    MOV    r1, #1
    STRB   r1, [r8, #PCITSect_Flags]                        ; loaded = 1
```

The segment's entry vector is at the end of the segment; it must be 
copied to the PCIT section identified by R8, and zeroed in case it is in
 use as zero-initialised data:

```
    LDR    r1, [r8, #PCITSect_Vecsize]
    ADD    r0, r0, r1                        ; end of loaded segment...
    SUB    r3, r8, #8                        ; end of entry vector...
    MOV    r4, #0                        ; for data initialisation
01  LDR    r2, [r0, #-4]!                        ;> loop to copy
    STR    r4, [r0]                        ; (zero-init possible data
                        ;  section)
    STR    r2, [r3], #-4                        ;> the segment's PCIT
    SUBS   r1, r1, #4                        ;> section into the
    BGT    %B01                        ;> global PCIT...
```

Finally, continue execution:

```
    LDMIA  R9, {R0-R9, LR, PC}^
```

### Intercepting returns to overwritten segments

The overlay scheme as described so far is sufficient, provided no 
function call causes any overlay in the current call chain to be 
unloaded. As a specific example, consider a root segment and two 
procedures, A and B in overlays 1_1 and 1_2 respectively. Note that A 
and B may not be co-resident. Then any pattern of calls like:

```
((root calls A, A returns)* (root calls B, B returns)*)*
```

is unproblematic. However, A calls B is disastrous when B tries to 
return (as B will return to a random address within itself rather than 
to A).

To fix this deficiency, it is necessary to intercept (some) function 
returns. Trying to intercept all returns would be hopelessly expensive; 
at the point of call there are no working registers available, and there
 is nowhere to store a return address, (the stack cannot be used without
 potentially destroying the current function call's arguments).

The following observations hold the key to an efficient implementation:

- a return address can only be invalidated by loading a segment which displaces a currently loaded segment;

- at the point that a segment is loaded, the stack contains a
   complete record of return addresses which might be invalidated by the 
  load.

Before loading a segment, the procedure call back-trace (including the 
value stored in LRSave) must be checked for return addresses which fall 
in the segment about to be overwritten. Each such return address must be
 replaced by a pointer to a return handler which will load the segment 
before continuing the return.

Unfortunately, there is no simple way to avoid using a fixed pool of 
return handlers. The stack cannot be used (in a language-independent 
manner) because its layout is only partly defined in mid function call. A
 variant of the language-specific stack-extension code could be used, 
but it would complicate the implementation significantly, and make some 
aspects of the overlay mechanism language specific. Similarly, it would 
be unwise to make any assumptions about the availability or management 
of heap space.

Fortunately, using a fixed pool of handlers is not as bad as it first 
seems. A handler can only be needed if a call is made which overwrites 
the calling segment. If this is done strictly non-recursively (meaning 
that if any P in segment 1 calls some Q in segment 2, then no R in 
segment 2 may call any S in segment 1 until Q has returned), then the 
number of handlers required is bounded by the number of overlay 
segments. If recursive calls are made between overlay segments, then 
performance will be exceedingly poor unless a large amount of work is 
done by each call. It is hard to envisage an application which would 
require an unbounded depth of recursion, and would perform significant 
amounts of work at each level, (a recursively invokable CLI is such an 
example, but in this case it's hard to see why a moderate fixed limit on
 the depth of recursion would be unacceptable).

Note that only the most recent return should be allocated a return 
handler. For example, assume that there is a sequence of mutually 
recursive calls between segments A and B, followed by a call to C which 
unloads A. Then, only the latest return to A needs to be trapped, 
because as soon as A has been re-loaded the remainder of the 
mutually-recursive returns can unwind without being intercepted.

### Return handler code

A return handler must store the real return address, the identity of the
 segment to return to (e.g. the address of its PCIT section), and it 
must contain a call (indirectly) to the load_segment code. In addition, 
it is assumed that the handler pool is managed as a singly linked list. 
Then the handler code is:

```
        BL     load_seg_and_ret
RealLR  DCD    0                    ; space for the real return address
Segment DCD    0                    ; -> PCIT section of segment to load
Link    DCD    0                    ; -> next in stack order
```

RealLR, Segment and Link are set up by check_for_invalidated_returns.

### The load_seg_and_ret code

*HStack* and *HFree* are set up by overlay_mgr_init, and 
maintained by check_for_invalidated_returns. For simplicity, they are 
shown here as PC-relative-addressable variables. More properly, they are
 part of the data area shared with load_seg_and_go. As already noted, 
this data area can be addressed via an address constant, as *ip* is available as a base register.

```
HStack  DCD    0                ; top of stack of allocated handlers
HFree   DCD    0                ; head of free-list

load_seg_and_ret
    STR    R9, RSave+9*4                                ; save a base register...
    ADR    R9, RSave
    STMIA  R9, {R0-R8}                                ; ...and some working registers
    BIC    R8, LR, #&FC000003                                ; clear out status bits(26 bit mode
    LDMIA  R8, {R0, R1, R2}                                ; RealLR, Segment, Link
    STR    R0, LRSave
    STR    R0, PCSave
; Now unchain the handler and return it to the free pool
; (by hypothesis, HStack points to this handler...)
    STR    R2, HStack                                ; new top of handler stack
    LDR    R2, HFree
    STR    R2, [R8, #8]                                ; Link -> old HFree
    SUB    R2, R8, #4
    STR    R2, HFree                                ; new free list
    MOV    R8, R1                                ; segment to load
    B      load_segment
```

### The check_for_invalidated_returns Code

This code must check LRSave and the chain of call-frames for the first 
return address invalidated, by loading the segment identified by R8 into
 the slot identified by R7. R7-R9, FP, SP and SL must be preserved.

```
    ADR    R6, LRSav                                ; 1st location to check
    MOV    R0, FP                                ; temporary FP...
01  LDR    R1, [R6]                                ; the saved return address...
    BIC    R1, R1, #&FC000003                                ; ...with status bits masked off
    LDR    R2, [R7, #O_Base]
    CMPS   R1, R2                                ; see if >= base...
    BLT    %F02
    LDR    R2, [R7, #O_Limit]
    CMPS   R1, R2                                ; ...and < limit
    BLT    FoundClash
02  CMPS   R0, #0                                ; bottom of stack?
    MOVEQS PC, LR                                ; yes => return
    SUB    R6, R0, #4
    LDR    R0, [R0, #-12]                                ; previous FP
    B      %B01
```

Having found a segment containing a return address invalidated by this segment load, a handler is allocated for it:

```
FoundClash
    LDR    R0, HFree                                ; head of chain of free handlers
    CMPS   R0, #0
    BEQ    NoHandlersLeft
                                ; Transfer the next free handler to 
                                ; head of the handler stack.
    LDR    R1, [R0, #12]                                ; next free handler
    STR    R1, HFree
    LDR    R1, HStack                                ; the active handler stack
    STR    R1, [R0, #12]
    STR    R0, HStack                                ; now with the latest handler 
                                ; linked in Initialise the handler 
                                ; with a BL load_seg_and_ret, 

                                ; RealLR and Segment.
    ADR    R1, load_seg_and_ret
    SUB    R1, R1, R0                                ; byte offset for BL in handler
    SUB    R1, R1, #8                                ; correct for PC off by 8
    MOV    R1, R1, ASR #2                                ; word offset
    BIC    R1, #&FF000000
    ORR    R1, #&EB000000                                ; code for BL
    STR    R1, [R0]
    LDR    R1, [R6]
    STR    R6, [R0, #4]                                ; RealLR
    STR    R0, [R6]                                ; patch stack to return to handler
    STR    R7, [R0, #8]                                ; segment to re-load on return
    MOVS   PC, LR                                ; and return
NoHandlersLeft
    ...                                ; omitted for brevity
```

The initial creation of the handler pool is omitted for brevity.
