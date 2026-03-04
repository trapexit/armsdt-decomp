# ARM SDT Platform and Target Support

## Executive Summary

This document covers the platforms, architectures, and target systems supported by the ARM SDT (Software Development Toolkit). Understanding the target support is essential for reverse engineering as it determines code generation patterns, calling conventions, and binary format characteristics.

## 1. Target ARM Architectures

### ARM SDT 2.50 Supported Processors

#### Original Support (Pre-2.50)

| Processor | Architecture | Features | Typical Use |
|-----------|--------------|----------|-------------|
| **ARM6** | ARMv3 | 32-bit addressing, 4K cache | Early embedded |
| **ARM7** | ARMv3 | ARM6 successor | Embedded systems |
| **ARM7M** | ARMv3M | Fast multiplier | Digital signal processing |
| **ARM8** | ARMv4 | Enhanced DSP instructions | Multimedia |
| **ARM9** | ARMv4 | 5-stage pipeline | High-performance embedded |
| **StrongARM1** | ARMv4 | 233 MHz, low power | PDAs, mobile devices |

#### Added in SDT 2.50

| Processor | Architecture | Features | Notes |
|-----------|--------------|----------|-------|
| **ARM7T** | ARMv4T | Thumb instruction set | Code density |
| **ARM7TDMI** | ARMv4T | Thumb + Debug + Multiplier + ICE | Most popular |
| **ARM7TDI** | ARMv4T | Thumb + Debug + ICE | Debug support |
| **ARM7TM** | ARMv4T | Thumb + enhanced multiplier | DSP applications |
| **ARM7TDSP** | ARMv4T | Thumb + DSP extensions | Signal processing |
| **ARM9TDMI** | ARMv4T | 5-stage pipeline + Thumb | Higher performance |
| **ARM920T** | ARMv4T | MMU + cache controller | Complex embedded |
| **ARM940T** | ARMv4T | Memory protection unit | Real-time systems |
| **ARM710T** | ARMv4T | Thumb for ARM7 series | Upgrade path |
| **ARM740T** | ARMv4T | MPU version | Embedded control |
| **ARM7TDMI-S** | ARMv4T | Synthesizable version | ASIC designs |

### ARM Architecture Evolution

```
ARM2 (ARMv2) - 26-bit addressing
    ↓
ARM3 (ARMv2) - Added cache
    ↓
ARM6 (ARMv3) - 32-bit addressing
    ↓
ARM7 (ARMv3) - ARM6 improvements
    ↓
ARM7TDMI (ARMv4T) - Thumb mode added
    ↓
ARM9 (ARMv4/4T) - 5-stage pipeline
    ↓
StrongARM (ARMv4) - High performance
```

### Historical ARM Systems

| System | Processor | Year | OS |
|--------|-----------|------|-----|
| Acorn Archimedes A300 | ARM2 | 1987 | Arthur/RISC OS |
| Acorn Archimedes A400 | ARM3 | 1989 | RISC OS |
| Acorn Risc PC 600 | ARM610 | 1994 | RISC OS 3.5 |
| Acorn Risc PC 700 | ARM710 | 1995 | RISC OS 3.6 |
| Acorn StrongARM Risc PC | StrongARM | 1996 | RISC OS 3.7 |
| Acorn A7000 | ARM7500 | 1995 | RISC OS 3.6 |
| Apple Newton MessagePad | ARM710 | 1993 | NewtonOS |
| 3DO Interactive Multiplayer | ARM60 | 1993 | 3DO OS |
| Psion Series 5 | ARM710T | 1997 | EPOC |

## 2. ARM Procedure Call Standard (APCS)

### Overview

The ARM Procedure Call Standard defines how functions are called, including:
- Register usage conventions
- Stack management
- Parameter passing
- Return value handling

### APCS Variants

SDT 2.50 default: `-apcs 3/32/nofp/noswst/narrow/softfp`

#### APCS Qualifiers

| Qualifier | Description | Use Case |
|-----------|-------------|----------|
| `3/26bit` | 26-bit addressing | ARM2/ARM3 |
| `3/32bit` | 32-bit addressing | ARM6+ (default) |
| `fp` | Use frame pointer | Debugging |
| `nofp` | No frame pointer | Optimization |
| `swst` | Software stack checking | Safety |
| `noswst` | No stack checking | Performance (default) |
| `narrow` | Narrow APCS | Compatibility |
| `wide` | Wide APCS | Full support |
| `interwork` | ARM/Thumb interworking | Mixed code |
| `nointerwork` | No interworking | Pure ARM or Thumb |
| `softfp` | Software floating point | No FPU |
| `hardfp` | Hardware floating point | With FPU |

### APCS Register Usage

#### Core Registers

| Register | APCS Name | Purpose |
|----------|-----------|---------|
| R0 | a1 | Argument 1 / Return value |
| R1 | a2 | Argument 2 / Return value |
| R2 | a3 | Argument 3 |
| R3 | a4 | Argument 4 |
| R4 | v1 | Variable 1 (preserved) |
| R5 | v2 | Variable 2 (preserved) |
| R6 | v3 | Variable 3 (preserved) |
| R7 | v4 | Variable 4 (preserved) |
| R8 | v5 | Variable 5 (preserved) |
| R9 | sb/v6 | Static base / Variable 6 |
| R10 | sl/v7 | Stack limit / Variable 7 |
| R11 | fp | Frame pointer (optional) |
| R12 | ip | Intra-procedure call scratch |
| R13 | sp | Stack pointer |
| R14 | lr | Link register |
| R15 | pc | Program counter |

#### Stack Usage

```
High addresses
┌─────────────────┐
│  Stack limit    │ ← sl
├─────────────────┤
│   Arguments     │
│   > 4 words     │
├─────────────────┤
│  Return addr    │ ← lr (if not leaf)
├─────────────────┤
│  Preserved regs │ ← fp (if used)
├─────────────────┤
│  Local vars     │
├─────────────────┤
│  Temporaries    │
├─────────────────┤
│  Arguments      │ ← sp
│  for calls      │
└─────────────────┘
Low addresses
```

### Function Call Sequence

**Caller:**
1. Arguments 1-4 in R0-R3
2. Additional arguments on stack
3. `BL` instruction (sets LR)

**Callee (prologue):**
```asm
STMFD sp!, {r4-r11, lr}  ; Save preserved regs
SUB sp, sp, #local_size  ; Allocate locals
```

**Callee (epilogue):**
```asm
ADD sp, sp, #local_size  ; Deallocate locals
LDMFD sp!, {r4-r11, pc}  ; Restore and return
```

### 26-bit vs 32-bit Addressing

#### 26-bit Mode (ARM2/ARM3)
- PC stored in R15[25:0] (26 bits)
- Processor flags in R15[31:26] (6 bits)
- Maximum 64MB address space
- Return address in PC format

#### 32-bit Mode (ARM6+)
- Full 32-bit addressing
- Separate CPSR for flags
- 4GB address space
- Return address in LR (R14)

### Thumb Procedure Call Standard (TPCS)

For Thumb code, the TPCS defines:
- R0-R3 for arguments/return (same as APCS)
- R4-R7 preserved (callee-saved)
- R13 (sp), R14 (lr), R15 (pc)
- High registers (R8-R12) not used by default
- Smaller stack frame alignment

## 3. Floating Point Support

### FPA (Floating Point Accelerator)

The FPA was ARM's original floating-point coprocessor.

#### FPA Registers

| Register | Purpose |
|----------|---------|
| F0-F7 | Floating-point work registers |
| | Can hold single or double precision |

#### FPA Instructions

```asm
LDF F0, [R0]      ; Load float
ADF F0, F1, F2    ; Add float
MUF F0, F1, F2    ; Multiply float
SUF F0, F1, F2    ; Subtract float
DVF F0, F1, F2    ; Divide float
FIX R0, F0        ; Float to int
FLT F0, R0        ; Int to float
STF F0, [R0]      ; Store float
```

#### FPA System Registers

| Register | Purpose |
|----------|---------|
| FPSR | Floating-point status register |
| FPCR | Floating-point control register |

### Software Floating Point

When no FPU available, software emulation is used:

```c
// Compiler option: -fpu softfpa
// Runtime library functions:
// __adddf3, __addsf3 - Double/single add
// __muldf3, __mulsf3 - Multiply
// __divdf3, __divsf3 - Divide
// __extendsfdf2 - Single to double
// __truncdfsf2 - Double to single
```

### VFP (Vector Floating Point)

Introduced in later ARM architectures (not in SDT 2.50):
- 32 single-precision registers (S0-S31)
- 16 double-precision registers (D0-D15)
- SIMD capabilities
- Not widely used in SDT era

## 4. Memory Models

### Little-Endian (Default)

```
Address:  0x100  0x101  0x102  0x103
          ┌────┬────┬────┬────┐
Value:    │ 78 │ 56 │ 34 │ 12 │  (0x12345678)
          └────┴────┴────┴────┘
                  ↑
            Least significant byte at lowest address
```

### Big-Endian

```
Address:  0x100  0x101  0x102  0x103
          ┌────┬────┬────┬────┐
Value:    │ 12 │ 34 │ 56 │ 78 │  (0x12345678)
          └────┴────┴────┴────┘
                  ↑
            Most significant byte at lowest address
```

### Compiler Options

```bash
armcc --littleend    # Little-endian (default)
armcc --bigend       # Big-endian
```

### Bi-Endian Support

ARMv3+ processors support switchable endianness:
- Controlled by CP15 or memory-mapped registers
- Code and data can have different endianness
- Important for mixed-endian systems

## 5. Operating System Targets

### RISC OS

Primary target for Acorn development:
- Cooperative multitasking
- Module-based architecture
- SWI (Software Interrupt) interface
- Dynamic linking support

#### RISC OS Module Format

Modules are position-independent code:
```
Header:
  - Module flags
  - Name string
  - Help string
  - Entry points (init, final, service, commands)
  - Code and data
  - Relocation table
```

Compiler option: `-zM` (generate module)

### RISC iX

UNIX System V port for ARM:
- ELF binaries
- a.out format (early versions)
- Shared library support
- POSIX compliance

### Embedded/Bare Metal

Direct hardware programming:
- No operating system
- Custom startup code
- Linker scatter files for memory maps
- Direct hardware register access

#### Typical Embedded Layout

```
0x0000_0000  ─┬─  Flash/ROM (code)
              │   Reset vector at 0x0
              │
0x0800_0000  ─┤
              │
0x2000_0000  ─┼─  SRAM (data/stack)
              │   Initialized data
              │   BSS (zeroed)
              │   Heap
              │   Stack (grows down)
              │
0x4000_0000  ─┤
              │   Peripherals
              │   Memory-mapped I/O
```

## 6. ARM Instruction Sets

### ARM Mode (32-bit)

- Fixed 32-bit instructions
- 3-address format
- Conditional execution
- Barrel shifter
- Load/store architecture

Example:
```asm
    ADDNE R0, R1, R2, LSL #3   ; Add if not equal, with shift
    LDR R0, [R1, #4]!          ; Load with pre-index
    STMFD SP!, {R0-R3, LR}     ; Push multiple
```

### Thumb Mode (16-bit)

Added in ARM7TDMI:
- 16-bit instructions
- Reduced register access
- Limited immediate ranges
- Better code density (~30% smaller)

Example:
```asm
    ADDS R0, R1, #3            ; Add immediate
    LDR R0, [R1, #4]           ; Load
    PUSH {R0-R3, LR}           ; Push
```

### ARM/Thumb Interworking

Switching between modes:

```asm
; ARM code
    ADR R0, thumb_code + 1     ; Address with bit 0 set
    BX R0                      ; Branch and exchange to Thumb

; Thumb code
    BL arm_function            ; Call ARM function
    
; ARM function
    BX LR                      ; Return (mode preserved)
```

Compiler options:
```bash
armcc --arm          # ARM code (default)
armcc --thumb        # Thumb code
tcc                  # Thumb compiler
--apcs /interwork    # Enable interworking
```

## 7. Build Configuration Examples

### Standard ARM7TDMI

```bash
armcc -c --cpu ARM7TDMI -O2 -g --apcs /32bit/nofp/noswst/interwork
armasm --cpu ARM7TDMI -g
armlink --scatter scatter.scat --ro-base 0x8000
```

### RISC OS Module

```bash
armcc -c -zM --cpu ARM710 -O2 -zps1 -apcs 3/32/fp/narrow
armlink -o module -aof -bin
```

### Thumb-Only

```bash
tcc -c --cpu ARM7TDMI -O2 -g --apcs /interwork
armasm -16 --cpu ARM7TDMI
armlink --scatter scatter.scat
```

### Soft-Float

```bash
armcc -c --cpu ARM7TDMI --fpu softfpa -O2
```

## References

- ARM DUI 0041C: ARM Software Development Toolkit Reference Guide
- ARM DUI 0020: ARM Software Development Toolkit User Guide (SDT 2.11)
- ARM Architecture Reference Manual (ARM ARM)
- APCS Specification (ARM's Procedure Call Standard)
- RISC OS Programmer's Reference Manual
