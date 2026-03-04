# Reverse Engineering ARM SDT Binaries

## Executive Summary

This document provides comprehensive guidance on reverse engineering binaries produced by the ARM SDT (Software Development Toolkit) and Norcroft C compiler. Understanding the specific patterns, signatures, and formats used by these tools is essential for effective analysis of legacy ARM binaries.

## 1. Identifying Norcroft/ARM SDT Binaries

### Compiler Signatures

#### Code Generation Patterns

**Function Prologue (APCS with frame pointer):**
```asm
    STMFD   SP!, {R4-R11, LR}    ; Save preserved registers
    ADD     R11, SP, #offset     ; Set up frame pointer
    SUB     SP, SP, #locals      ; Allocate local variables
```

**Function Prologue (no frame pointer):**
```asm
    STMFD   SP!, {R4-R8, LR}     ; Save registers (variable set)
    SUB     SP, SP, #locals      ; Allocate stack space
```

**Function Epilogue (with frame pointer):**
```asm
    SUB     SP, R11, #offset     ; Restore stack pointer
    LDMFD   SP!, {R4-R11, PC}    ; Restore and return
```

**Function Epilogue (no frame pointer):**
```asm
    ADD     SP, SP, #locals      ; Deallocate locals
    LDMFD   SP!, {R4-R8, PC}     ; Restore and return
```

**Leaf Function (simple):**
```asm
    ; No stack manipulation
    ADD     R0, R0, R1           ; Computation
    MOV     PC, LR               ; Return
```

#### Norcroft-Specific Patterns

**Register Allocation by Graph Coloring:**
- Consistent register allocation within functions
- Minimized register spills
- Efficient use of callee-saved registers (R4-R11)

**Peephole Optimizations:**
- `MOV R0, R0` → (removed)
- `ADD R0, R0, #0` → (removed)
- `LDR R0, [SP], #0` → `LDR R0, [SP]`

**JOP Code Patterns:**
Look for:
- Basic block boundaries
- Consistent instruction scheduling
- Specific instruction selection patterns

### Runtime Library Signatures

Common Norcroft runtime functions have distinctive implementations:

**__rt_memcpy:**
```asm
    ; Norcroft memcpy often uses:
    LDRB    R3, [R1], #1
    STRB    R3, [R0], #1
    SUBS    R2, R2, #1
    BNE     __rt_memcpy
```

**__rt_memset:**
```asm
    ; Norcroft memset pattern:
    ADD     R3, R0, R2
memset_loop:
    CMP     R0, R3
    STRCCB  R1, [R0], #1
    BCC     memset_loop
```

**Division routines:**
```asm
    ; Software division (SDT soft-float)
    STMFD   SP!, {R4-R6, LR}
    ; ... division algorithm ...
    LDMFD   SP!, {R4-R6, PC}
```

### Binary Identification Checklist

**Indicators of Norcroft/ARM SDT:**

1. **AIF format executables** (pre-SDT 2.50)
2. **AOF object files** in libraries
3. **ASD debug tables** (pre-2.50)
4. **DWARF 2** with ARM extensions (SDT 2.50+)
5. **APCS compliance** in function signatures
6. **Specific register save patterns** in prologues
7. **ELF with .ARM.attributes** section (2.50+)

**Differentiating from GCC:**

| Feature | Norcroft | GCC |
|---------|----------|-----|
| Prologue | Consistent STMFD | Variable |
| Division | Library calls | Inline or libgcc |
| memcpy | Inline loops | May use library |
| Stack frames | Simpler | More complex |
| Debug info | ASD or DWARF | DWARF |

## 2. Disassembly Techniques

### Tool Selection

#### Capstone Framework

**Installation:**
```bash
pip install capstone
```

**Basic ARM Disassembly:**
```python
from capstone import *

CODE = b"\x00\x00\x00\xEA\x00\x00\x00\xEA"

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md.detail = True

for insn in md.disasm(CODE, 0x8000):
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
```

**Thumb Mode Disassembly:**
```python
from capstone import *

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
# ... same usage
```

**Features:**
- ARM, Thumb, ARM64 support
- Detailed instruction information
- Cross-platform bindings

#### Radare2

**Installation:**
```bash
git clone https://github.com/radareorg/radare2
cd radare2
./sys/install.sh
```

**Analyzing ARM Binary:**
```bash
# Open binary
r2 -a arm -b 32 binary.aif

# Analyze all
[0x00008000]> aaa

# List functions
[0x00008000]> afl

# Disassemble function
[0x00008000]> pdf @ sym.main

# Show strings
[0x00008000]> iz

# Show imports
[0x00008000]> ii

# Show cross-references
[0x00008000]> axg
```

**ARM-Specific Commands:**
```bash
# Set ARM mode
[0x00008000]> e asm.arch=arm
[0x00008000]> e asm.bits=32

# Set Thumb mode at address
[0x00008000]> s 0x8004
[0x00008004]> e asm.bits=16
[0x00008004]> pd 10

# Search for ARM patterns
[0x00008000]> /c stmfd
```

#### Ghidra

**ARM Analysis Setup:**
1. Import binary
2. Select language: `ARM:LE:32:v7` or `ARM:LE:32:v4t`
3. Analyze with default options
4. Look for:
   - APCS-style function prologues
   - Norcroft runtime functions
   - ASD debug symbols (if present)

**Creating Custom Signatures:**
```bash
# Use FLIRT tools
./sigmake -n"Norcroft_Runtime" patterns.pat norcroft.sig
# Add to Ghidra signatures
```

#### Binary Ninja

**ARM Analysis:**
1. Open binary
2. Select architecture: ARMv7 or ARMv4T
3. Enable linear sweep for better coverage
4. Use MLIL for high-level analysis

### Disassembly Strategies

#### Identifying Code Boundaries

**From AIF header:**
```python
# Parse AIF header
import struct

with open('binary.aif', 'rb') as f:
    header = f.read(128)
    
# Extract fields
branch, _, selfreloc, _, entry, exitinst = struct.unpack('<IIIIII', header[:24])
code_size, data_size = struct.unpack('<II', header[24:32])

code_start = 128  # After header
code_end = code_start + code_size
```

**Heuristic Approaches:**
1. Look for function prologue patterns: `STMFD SP!, {...}`
2. Find return sequences: `LDMFD SP!, {..., PC}`
3. Analyze branch targets from disassembly
4. Cross-reference with symbol tables

#### Mode Switching (ARM/Thumb)

**Detecting Interworking:**
```asm
; ARM to Thumb transition
    ADR     R0, thumb_func + 1    ; Set bit 0
    BX      R0                    ; Branch and exchange

; Thumb function
thumb_func:
    PUSH    {R4-R6, LR}
    ...
    POP     {R4-R6, PC}           ; Return (preserves mode)
```

**Analysis Technique:**
1. Track BX instructions
2. Check target address LSB (1 = Thumb, 0 = ARM)
3. Update disassembler mode accordingly
4. Look for BLX (ARMv5+) for mode switching calls

## 3. File Format Analysis

### AOF Object Files

**Using decaof:**
```bash
# Decode AOF file
decaof -a object.o

# Show header only
decaof -h object.o

# Show symbols
decaof -s object.o

# Show relocations
decaof -r object.o
```

**Manual Parsing:**
```python
import struct

def parse_aof(filename):
    with open(filename, 'rb') as f:
        # Read header
        magic = f.read(4)
        if magic != b'Cmon':
            raise ValueError("Not an AOF file")
        
        f.seek(0)
        header = struct.unpack('<IIIIIIII', f.read(32))
        version, num_areas, num_symbols = header[1], header[2], header[3]
        area_offset, symbol_offset = header[4], header[5]
        
        # Parse areas
        f.seek(area_offset)
        for i in range(num_areas):
            area_header = struct.unpack('<IIII', f.read(16))
            print(f"Area {i}: offset={area_header[0]}, size={area_header[1]}")
        
        # Parse symbols
        f.seek(symbol_offset)
        for i in range(num_symbols):
            sym = struct.unpack('<IIII', f.read(16))
            print(f"Symbol {i}: name_offset={sym[0]}, flags={sym[1]:08x}")

parse_aof("object.o")
```

### ALF Library Files

**Listing Library Contents:**
```bash
armlib -t library.a
armlib -s library.a
```

**Extracting Objects:**
```bash
# Extract all objects
armlib -x library.a

# Extract specific object
armlib -x library.a specific.o
```

### AIF Executables

**Header Analysis:**
```python
import struct

def parse_aif(filename):
    with open(filename, 'rb') as f:
        header = f.read(128)
    
    # Unpack fields
    fields = struct.unpack('<IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', header)
    
    aif = {
        'branch': fields[0],
        'selfreloc': fields[2],
        'entry': fields[4],
        'exitinst': fields[5],
        'image_size': fields[6],
        'code_size': fields[7],
        'data_size': fields[8],
        'debug_size': fields[9],
        'code_base': fields[10],
        'data_base': fields[11],
        'debug_type': fields[12],
        'debug_offset': fields[13],
        'mem_base': fields[16],
        'mem_size': fields[17]
    }
    
    return aif

aif = parse_aif("program.aif")
print(f"Entry: 0x{aif['entry']:08x}")
print(f"Code: 0x{aif['code_size']:08x} bytes")
print(f"Debug type: {aif['debug_type']}")
```

### ELF Files

**Using readelf:**
```bash
# Basic information
readelf -h binary.elf      # ELF header
readelf -S binary.elf      # Section headers
readelf -l binary.elf      # Program headers

# Symbols
readelf -s binary.elf      # Symbol table
readelf --dyn-syms binary.elf  # Dynamic symbols

# Relocations
readelf -r binary.elf      # Relocation entries

# Debug info
readelf --debug-dump=info binary.elf
readelf --debug-dump=line binary.elf
```

**ARM-Specific Analysis:**
```bash
# Show ARM attributes
readelf -A binary.elf

# Show unwind tables
readelf -u binary.elf
```

## 4. Debug Information Extraction

### ASD Tables (Pre-SDT 2.50)

ASD is ARM's proprietary debug format. Tools for extraction:

**Using armsd:**
```bash
# Load binary with ASD
armsd program.aif

# Set breakpoint by line
break file.c:42

# Show source
list main
```

**Manual Parsing:**
```python
# ASD format is proprietary
# Requires reverse engineering the format
# Key structures:
# - File table
# - Line number mappings
# - Symbol definitions
# - Type information
```

### DWARF (SDT 2.50+)

**Using dwarfdump:**
```bash
# Dump all DWARF info
dwarfdump binary.elf

# Specific sections
dwarfdump -i binary.elf    # .debug_info
dwarfdump -l binary.elf    # .debug_line
dwarfdump -p binary.elf    # .debug_pubnames
```

**Using pyelftools:**
```python
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarfinfo import DWARFInfo

with open('binary.elf', 'rb') as f:
    elffile = ELFFile(f)
    
    if elffile.has_dwarf_info():
        dwarf = elffile.get_dwarf_info()
        
        for CU in dwarf.iter_CUs():
            print(f"Compilation unit: {CU.cu_offset}")
            for DIE in CU.iter_DIEs():
                if DIE.tag == 'DW_TAG_subprogram':
                    name = DIE.attributes.get('DW_AT_name')
                    if name:
                        print(f"  Function: {name.value}")
```

## 5. Symbol Recovery Techniques

### Static Symbol Recovery

**From Symbol Tables:**
```bash
# AIF/ELF symbols
fromelf --symbols binary.elf

# Strip and recover
strip --strip-debug binary.elf
# Use strings and patterns
```

**String Analysis:**
```bash
# Extract strings
strings -n 8 binary.aif > strings.txt

# Find function names
strings binary.aif | grep -E '^[a-zA-Z_][a-zA-Z0-9_]*$'

# Find file paths
strings binary.aif | grep -E '\.(c|h|s|cpp)$'
```

**FLIRT Signature Matching:**
```bash
# Create signatures from known libraries
./flair/bin/linux/elf/pelf libacorn.a acorn.pat
./sigmake -n"Acorn_Lib" acorn.pat acorn.sig

# Apply in IDA Pro
# Load binary, apply signature
```

### Dynamic Symbol Recovery

**Using Qiling Framework:**
```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

def hook_mem_read(ql, access, addr, size, value):
    print(f"Read 0x{addr:x} = 0x{value:x}")

ql = Qiling(["binary.aif"], "/path/to/rootfs",
            arch="arm", endian="little", verbose=QL_VERBOSE.DEBUG)

ql.hook_mem_read(hook_mem_read)
ql.run()
```

**Function Identification:**
1. Trace execution to find function entry points
2. Analyze call graphs
3. Identify library calls
4. Map memory accesses to data structures

## 6. Decompilation Challenges

### ARM-Specific Challenges

**Multiple Return Values:**
```c
// C code
void get_coords(int *x, int *y);

// ARM assembly
    ; Returns in R0 and R1
    LDMIA   R0, {R0, R1}
    MOV     PC, LR
```

**Complex Calling Conventions:**
- Variations in APCS
- Stack passing for >4 arguments
- Double-precision floats in even-odd register pairs

**Position-Independent Code (PIC):**
```asm
; PC-relative addressing
    LDR     R0, [PC, #offset]    ; Read constant
    ADD     R0, PC, R0           ; Calculate address
```

**Mode Switching:**
- ARM/Thumb interworking
- State preservation across calls
- BLX instruction handling

### Decompiler Setup

#### Ghidra

1. Import binary with correct architecture
2. Run Auto Analyze
3. Manually identify functions if needed
4. Apply data types from headers
5. Review decompiled output

**Tips:**
- Look for Norcroft patterns
- Check APCS compliance
- Verify stack frame analysis

#### Reko

Open-source decompiler with ARM support:
```bash
# Install
pip install reko

# Decompile
reko-decompile binary.aif -a arm -o output.c
```

## 7. Practical Analysis Workflow

### Step-by-Step Analysis

1. **Initial Reconnaissance:**
   ```bash
   file binary.aif
   xxd binary.aif | head -20
   fromelf --info binary.aif
   ```

2. **Extract Information:**
   ```bash
   fromelf --symbols binary.aif
   strings binary.aif | head -100
   ```

3. **Disassemble:**
   ```bash
   fromelf --disassemble binary.aif > disasm.s
   # Or use r2: r2 -a arm -b 32 -c 'pd 1000 @ 0x8000' binary.aif
   ```

4. **Identify Functions:**
   - Search for prologues: `STMFD SP!,`
   - Find returns: `LDMFD SP!, {..., PC}`
   - Build call graph

5. **Extract Debug Info:**
   ```bash
   # If DWARF
   readelf --debug-dump=line binary.elf > lines.txt
   ```

6. **Analyze Data Structures:**
   - Look for constant data
   - Identify string tables
   - Map global variables

7. **Create IDB/Ghidra Project:**
   - Import with correct base address
   - Define functions
   - Add comments
   - Rename variables

### Common Patterns to Look For

**Main Function:**
```asm
main:
    STMFD   SP!, {R4-R11, LR}
    ; Initialize runtime
    BL      __rt_lib_init
    ; Call constructors
    BL      _main
    ; Exit
    BL      exit
```

**RISC OS SWI Calls:**
```asm
    SWI     0x20000 + number     ; X form (error return)
    ; or
    SWI     number               ; Standard form
```

**Division Routine Calls:**
```asm
    ; Software division (SDT)
    BL      __rt_udiv            ; Unsigned divide
    BL      __rt_sdiv            ; Signed divide
```

## Tools Summary

| Tool | Purpose | URL |
|------|---------|-----|
| Capstone | Disassembly | https://www.capstone-engine.org/ |
| Radare2 | RE Framework | https://radare.org/ |
| Ghidra | SRE Platform | https://ghidra-sre.org/ |
| Binary Ninja | RE Platform | https://binary.ninja/ |
| Unicorn | Emulation | https://www.unicorn-engine.org/ |
| Qiling | Binary Emulation | https://github.com/qilingframework/qiling |
| Reko | Decompiler | https://github.com/uxmal/reko |
| fromELF | ARM conversion | Included with SDT |

## References

- ARM DUI 0041C: ARM SDT Reference Guide
- ARM Architecture Reference Manual
- APCS Specification
- "ARM System Developer's Guide" (Sloss et al.)
- Reverse Engineering for Beginners (Dennis Yurichev)
