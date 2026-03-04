# ARM SDT File Formats Reference

## Executive Summary

This document provides comprehensive technical details about the file formats used by the ARM SDT (Software Development Toolkit) and Norcroft C compiler, including object formats, library formats, executable formats, and debug information formats.

## 1. AOF - ARM Object Format

### Overview

The ARM Object Format (AOF) is the standard relocatable object file format used by ARM SDT tools. It is produced by `armasm` (ARM Assembler) and `armcc` (ARM C Compiler) and serves as input to the ARM Linker (`armlink`).

### Historical Context

AOF is based on the multi-target, multi-language compiler suite from Codemist Ltd (Norcroft C compiler). It was designed to be:
- Architecture-independent at the format level
- Support multiple languages (C, C++, Assembly)
- Efficient for linking and relocation
- Extensible for debug information

### File Structure

An AOF file consists of:

1. **Header** - Format identification and file metadata
2. **Area Headers** - Descriptions of code/data areas
3. **Symbol Table** - Global and local symbols
4. **Relocation Directives** - Relocation information for linking
5. **Area Data** - Actual code and data content
6. **Debug Information** (optional) - ASD tables

### Header Format

```c
typedef struct {
    uint32_t magic;          // Magic number: 0x6E6F6D43 ('Cmon' in ASCII)
    uint32_t version;        // Format version (0x3130 for version 1.0)
    uint32_t num_areas;      // Number of areas in file
    uint32_t num_symbols;    // Number of symbol table entries
    uint32_t area_offset;    // Offset to area headers
    uint32_t symbol_offset;  // Offset to symbol table
    uint32_t string_offset;  // Offset to string table
    uint32_t debug_offset;   // Offset to debug info (0 if none)
} AOFHeader;
```

### Area Types

Areas in AOF files can be:

| Type | Description | Attributes |
|------|-------------|------------|
| **CODE** | Executable code | READONLY |
| **DATA** | Initialized data | READWRITE |
| **BSS** | Uninitialized data | NOINIT, READWRITE |
| **CONST** | Constant data | READONLY |
| **DEBUG** | Debug information | Various |

### Area Attributes

| Attribute | Meaning |
|-----------|---------|
| `READONLY` | Read-only at runtime |
| `READWRITE` | Read-write at runtime |
| `NOINIT` | No initialization (BSS) |
| `CODE` | Contains code |
| `DATA` | Contains data |
| `COMMON` | Common block (FORTRAN) |
| `ALIGN=<n>` | Alignment requirement (2^n) |
| `COMDEF` | Common definition |
| `BASED=<reg>` | Based addressing |

### Symbol Table

Symbols in AOF have the following structure:

```c
typedef struct {
    uint32_t name_offset;    // Offset into string table
    uint32_t flags;          // Symbol flags
    uint32_t area_index;     // Area index (0 = absolute)
    uint32_t value;          // Symbol value or offset
} AOFSymbol;
```

#### Symbol Types (from flags)

| Flag | Value | Description |
|------|-------|-------------|
| `SYMDEF` | 0x01 | Symbol is defined |
| `SYMGLOB` | 0x02 | Global symbol |
| `SYMWEAK` | 0x04 | Weak symbol |
| `SYMCODE` | 0x08 | Code symbol |
| `SYMDATA` | 0x10 | Data symbol |
| `SYMCOMM` | 0x20 | Common symbol |
| `SYMVERS` | 0x40 | Versioned symbol |

### Relocation Types

AOF supports multiple relocation types:

| Type | Description |
|------|-------------|
| `R_ARM_ABS32` | Absolute 32-bit |
| `R_ARM_ABS16` | Absolute 16-bit |
| `R_ARM_ABS8` | Absolute 8-bit |
| `R_ARM_PC24` | PC-relative 24-bit (branch) |
| `R_ARM_PC13` | PC-relative 13-bit (load/store) |
| `R_ARM_SBREL` | Static base relative |
| `R_ARM_GLOB` | Global symbol reference |

### Relocation Entry

```c
typedef struct {
    uint32_t offset;         // Offset within area
    uint32_t type;           // Relocation type
    uint32_t sym_index;      // Symbol table index |
    int32_t  addend;         // Addend for relocation
} AOFRelocation;
```

### Tools for AOF

- **decaof** - Decodes and displays AOF file contents
- **armlink** - Links AOF files into executables
- **armlib** - Manages AOF files in libraries

## 2. ALF - ARM Library Format

### Overview

The ARM Library Format (ALF) is used for static libraries, which are collections of AOF object files. ALF is the ARM equivalent of UNIX `.a` or Windows `.lib` files.

### File Structure

An ALF file contains:

1. **Magic Header** - Library signature
2. **Symbol Directory** - Sorted list of all symbols
3. **Object Directory** - List of AOF objects in library
4. **AOF Objects** - The actual object files
5. **String Table** - Symbol and file names

### Header Format

```c
typedef struct {
    char magic[8];           // "!<arch>\n" or ARM-specific
    uint32_t version;        // Library format version
    uint32_t num_objects;    // Number of AOF objects
    uint32_t num_symbols;    // Number of symbols in directory
    uint32_t obj_dir_offset; // Offset to object directory
    uint32_t sym_dir_offset; // Offset to symbol directory
    uint32_t data_offset;    // Offset to AOF data
} ALFHeader;
```

### Symbol Directory

The symbol directory provides fast lookup:

```c
typedef struct {
    uint32_t symbol_name;    // Offset to symbol name
    uint32_t object_index;   // Index of defining object
} ALFSymbolDirEntry;
```

Symbols are sorted alphabetically for binary search.

### Object Directory

```c
typedef struct {
    uint32_t name_offset;    // Object file name
    uint32_t offset;         // Offset in library file
    uint32_t size;           // Size of AOF object
    uint32_t timestamp;      // Modification time
} ALFObjectEntry;
```

### Library Operations

**Creating a library:**
```bash
armlib -c mylib.a file1.o file2.o file3.o
```

**Adding to library:**
```bash
armlib -a mylib.a newfile.o
```

**Extracting from library:**
```bash
armlib -x mylib.a            # Extract all
armlib -x mylib.a file1.o    # Extract specific
```

**Listing contents:**
```bash
armlib -t mylib.a            # List objects
armlib -s mylib.a            # Show symbol table
```

### Linker Behavior

When linking with ALF libraries:
- Only referenced objects are extracted
- Unreferenced objects don't increase executable size
- Symbol resolution follows link order
- Weak symbols can be overridden

## 3. AIF - ARM Image Format

### Overview

The ARM Image Format (AIF) is the executable format for ARM binaries, introduced by Acorn Computers for the Archimedes. It was the default output format from `armlink` prior to SDT 2.50.

### Header Structure (128 bytes)

```c
typedef struct {
    // Self-relocation information
    uint32_t branch;         // Branch to start or BL <decode>
    uint32_t zero1;          // Must be zero
    uint32_t selfreloc;      // Offset to self-reloc code or zero
    uint32_t zero2;          // Must be zero
    
    // Entry and exit
    uint32_t entry;          // Entry point offset
    uint32_t exitinst;       // Exit instruction (SWI or branch)
    
    // Image layout
    uint32_t image_size;     // Total image size
    uint32_t code_size;      // Code area size
    uint32_t data_size;      // Data area size
    uint32_t debug_size;     // Debug data size
    
    // Addressing
    uint32_t code_base;      // Base address for code
    uint32_t data_base;      // Base address for data
    
    // Debug information
    uint32_t debug_type;     // Type of debug info (0=none, 1=ASD)
    uint32_t debug_offset;   // Offset to debug data
    
    // Reserved
    uint32_t zero3;          // Must be zero
    uint32_t zero4;          // Must be zero
    
    // Extended AIF
    uint32_t mem_base;       // Memory base (extended)
    uint32_t mem_size;       // Memory size (extended)
    
    // StrongARM marker
    uint32_t arm_v;          // ARM architecture version
} AIFHeader;
```

### Debug Types

| Value | Type |
|-------|------|
| 0 | No debug information |
| 1 | ASD (ARM Symbolic Debugger) tables |
| 2 | Reserved |
| 3 | DWARF debug information |

### AIF Variants

#### Standard AIF
- Executable with fixed load address
- Requires relocation at load time
- Default for RISC OS

#### Relocatable AIF
- Generated with `-AIF -Relocatable`
- Contains self-relocation code
- Can be loaded at any address

#### Extended AIF
- Supports specific memory placement
- Includes memory requirements
- Used for complex embedded systems

#### Binary AIF
- Generated with `-AIF -BIN`
- Raw binary without header
- Used for ROM images

### Loading and Execution

1. **RISC OS Loader:**
   - Reads AIF header
   - Allocates required memory
   - Loads image at specified base
   - Performs relocations if needed
   - Jumps to entry point

2. **Self-Relocation:**
   - Code at `selfreloc` offset
   - Adjusts internal pointers
   - Runs before main code

3. **Entry Point:**
   - Specified by `entry` field
   - Typically start of code area
   - Can be different with scatter loading

## 4. ASD - ARM Symbolic Debug Tables

### Overview

ASD is ARM's proprietary debug information format used in SDT versions prior to 2.50. It was replaced by DWARF in SDT 2.50 and later.

### Structure

ASD information is organized in tables:

1. **Source File Table** - Source file names and paths
2. **Line Number Table** - Line number mappings
3. **Symbol Table** - Variable and function information
4. **Type Table** - Data type definitions
5. **Scope Table** - Block and function scopes

### ASD Header

```c
typedef struct {
    uint32_t magic;          // ASD magic number
    uint32_t version;        // ASD version
    uint32_t num_files;      // Number of source files
    uint32_t num_symbols;    // Number of symbols
    uint32_t num_types;      // Number of type definitions
    uint32_t file_offset;    // Offset to file table
    uint32_t line_offset;    // Offset to line table
    uint32_t sym_offset;     // Offset to symbol table
    uint32_t type_offset;    // Offset to type table
} ASDHeader;
```

### Line Number Mapping

Maps code addresses to source lines:

```c
typedef struct {
    uint32_t address;        // Code address
    uint32_t line;           // Source line number
    uint32_t file_index;     // Index into file table
} ASDLineEntry;
```

### Debug Symbol Types

| Type | Description |
|------|-------------|
| `SYMTYPE_AUTO` | Automatic (stack) variable |
| `SYMTYPE_STAT` | Static variable |
| `SYMTYPE_GLOB` | Global variable |
| `SYMTYPE_FUNC` | Function |
| `SYMTYPE_PARAM` | Function parameter |
| `SYMTYPE_TYPEDEF` | Type definition |
| `SYMTYPE_STRUCT` | Structure/union |
| `SYMTYPE_ENUM` | Enumeration |

### Using ASD Information

The `armsd` debugger uses ASD tables for:
- Source-level debugging
- Variable inspection
- Stack backtraces
- Breakpoint setting by line number

## 5. ELF - Executable and Linkable Format

### Overview

ELF became the default format in SDT 2.50, replacing AIF. It is the industry-standard format for executables and shared libraries.

### ELF Sections for ARM

| Section | Description |
|---------|-------------|
| `.text` | Code section |
| `.data` | Initialized data |
| `.bss` | Uninitialized data |
| `.rodata` | Read-only data |
| `.init` | Initialization code |
| `.fini` | Finalization code |
| `.ARM.attributes` | ARM-specific attributes |
| `.ARM.exidx` | Exception index table |
| `.ARM.extab` | Exception handling table |
| `.debug_*` | DWARF debug sections |

### ARM-Specific ELF Sections

```c
// ARM Attributes Section (.ARM.attributes)
typedef struct {
    uint32_t version;        // Format version
    uint32_t vendor_name;    // Vendor string offset
    uint32_t subsection_offset;
} ARMAttributesHeader;
```

### ELF Relocations for ARM

| Type | Description |
|------|-------------|
| `R_ARM_ABS32` | Absolute 32-bit |
| `R_ARM_PC24` | PC-relative 24-bit |
| `R_ARM_ABS12` | Absolute 12-bit (load/store) |
| `R_ARM_THM_ABS5` | Thumb absolute 5-bit |
| `R_ARM_THM_PC22` | Thumb PC-relative 22-bit |
| `R_ARM_GOT32` | GOT entry |
| `R_ARM_PLT32` | PLT entry |
| `R_ARM_CALL` | ARM call (BL) |
| `R_ARM_JUMP24` | ARM jump (B) |
| `R_ARM_THM_CALL` | Thumb call (BL/BLX) |
| `R_ARM_THM_JUMP24` | Thumb jump (B) |

## 6. DWARF Debug Format

### Overview

DWARF is the standardized debugging format used in SDT 2.50 and later. It is architecture-independent and supported by many tools.

### DWARF Sections

| Section | Description |
|---------|-------------|
| `.debug_info` | Main debug info (DIEs) |
| `.debug_abbrev` | Abbreviation tables |
| `.debug_line` | Line number information |
| `.debug_frame` | Call frame information |
| `.debug_str` | String table |
| `.debug_loc` | Location lists |
| `.debug_ranges` | Address ranges |
| `.debug_pubnames` | Public symbol lookup |
| `.debug_aranges` | Address lookup table |

### DWARF Information Entry (DIE)

```c
typedef struct {
    uint32_t abbrev_code;    // Abbreviation code
    // Attributes follow based on abbreviation
} DWARFDie;
```

### Common DIE Tags

| Tag | Description |
|-----|-------------|
| `DW_TAG_compile_unit` | Source file |
| `DW_TAG_subprogram` | Function |
| `DW_TAG_variable` | Variable |
| `DW_TAG_formal_parameter` | Function parameter |
| `DW_TAG_base_type` | Base data type |
| `DW_TAG_pointer_type` | Pointer type |
| `DW_TAG_structure_type` | Structure |
| `DW_TAG_union_type` | Union |
| `DW_TAG_enumeration_type` | Enumeration |
| `DW_TAG_typedef` | Type definition |

### Line Number Program

DWARF uses a bytecode program to encode line number mappings efficiently:

| Opcode | Description |
|--------|-------------|
| `DW_LNS_copy` | Append row to matrix |
| `DW_LNS_advance_pc` | Advance PC |
| `DW_LNS_advance_line` | Advance line number |
| `DW_LNS_set_file` | Set source file |
| `DW_LNS_set_column` | Set column number |
| `DW_LNE_end_sequence` | End of sequence |

## 7. File Format Conversion

### Using fromELF

The `fromELF` utility converts between formats:

**AOF to Binary:**
```bash
fromelf --bin input.o -o output.bin
```

**ELF to Intel Hex:**
```bash
fromelf --i32 input.elf -o output.hex
```

**ELF to Motorola Hex:**
```bash
fromelf --m32 input.elf -o output.hex
```

**ELF to Verilog Hex:**
```bash
fromelf --vhx input.elf -o output.vhx
```

**Extract symbols:**
```bash
fromelf --symbols input.elf
```

**Disassemble:**
```bash
fromelf --disassemble --interleave input.elf
```

## 8. Binary Analysis Techniques

### Identifying File Formats

| Magic Number | Format |
|--------------|--------|
| `0x7F 'E' 'L' 'F'` | ELF |
| `0x6E6F6D43` ('Cmon') | AOF |
| `!<arch>\n` | ALF (AR-style) |
| Various branch instructions | AIF |
| `0x41534400` ('ASD\0') | ASD debug |

### Tools for Analysis

**decaof - AOF Decoder:**
```bash
decaof -h file.o         # Show header
decaof -s file.o         # Show symbol table
decaof -r file.o         # Show relocations
decaof -a file.o         # Show all
```

**readelf - ELF Analysis:**
```bash
readelf -h file.elf      # ELF header
readelf -S file.elf      # Section headers
readelf -s file.elf      # Symbol table
readelf -r file.elf      # Relocations
```

**objdump - Disassembly:**
```bash
objdump -d file.o        # Disassemble
objdump -h file.o        # Section headers
objdump -t file.o        # Symbol table
```

### Reverse Engineering Workflow

1. **Identify Format:**
   ```bash
   file binary
   xxd binary | head
   ```

2. **Extract Information:**
   ```bash
   fromelf --info binary
   fromelf --symbols binary
   ```

3. **Disassemble:**
   ```bash
   fromelf --disassemble binary > disasm.txt
   ```

4. **Analyze Relocations:**
   ```bash
   readelf -r binary
   ```

5. **Extract Debug Info:**
   ```bash
   # For DWARF
   readelf --debug-dump=info binary
   
   # For ASD (requires specialized tools)
   ```

## References

- ARM DUI 0041C: ARM Software Development Toolkit Reference Guide
- ELF Specification: TIS Committee, Tool Interface Standard
- DWARF Specification: dwarfstd.org
- ARM ELF ABI: ARM Architecture Procedure Call Standard

## See Also

- `/docs/AOF_Specification.md` - Detailed AOF format
- `/docs/ALF_Specification.md` - Detailed ALF format  
- `/docs/AIF_Specification.md` - Detailed AIF format
- `/docs/ARM_DUI0041C_Reference_Guide_-_ARM_Object_Format.md` - ARM documentation
