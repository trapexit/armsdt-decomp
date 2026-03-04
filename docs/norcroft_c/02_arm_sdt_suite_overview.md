# ARM SDT (Software Development Toolkit) - Complete Tool Reference

## Executive Summary

The ARM Software Development Toolkit (SDT) was ARM Limited's official development toolchain from the mid-1990s through the late 1990s, replaced by ARM Developer Suite (ADS) in 2000. It was based on the Norcroft C compiler technology and provided a complete toolchain for ARM development.

## 1. SDT Version History

### Release Timeline

| Version | Date | Key Features |
|---------|------|--------------|
| SDT 2.10 | Jan 1997 | Major update from DUI 0020 |
| SDT 2.11 | June 1997 | Updated assembler, APCS 3/32/fp/swst |
| SDT 2.11a | 1997 | Bug fixes and improvements |
| **SDT 2.50** | **Nov 1998** | **Major release - ELF default, DWARF 2, merged assembler, instruction scheduling** |
| SDT 2.51 | 1998-1999 | Build 130 (version in repo) |

### SDT to ADS Transition

```
SDT 2.50 (1998)
    ↓
ADS 1.0.1 (2000) - CodeWarrior IDE, new debugger
    ↓
RVDS (RealView) - RealView tools integration
    ↓
ARM Compiler 5.x - Part of DS-5
    ↓
ARM Compiler 6.x - LLVM-based compiler
    ↓
ARM Development Studio - Current unified toolchain
    ↓
Keil MDK - Microcontroller-focused toolkit
```

**Key Changes in SDT 2.50 → ADS:**
- CodeWarrior IDE replaced APM
- New GUI debugger (AXD) replaced ADW
- Enhanced instruction set simulator
- Support for newer ARM cores (ARM9E, ARM10)

### Pricing (1999)

- ARM SDT 2.50: $4,500 USD
- ARM Evaluation Board (AEB-1): $150
- ARM Development Board (ARM7TDMI): $4,400

## 2. Complete Tool Suite

### Command-Line Development Tools

#### armcc - ARM C Compiler
- Compiles ANSI C to 32-bit ARM code
- Based on Norcroft C compiler technology
- Optimization levels: -O0, -O1, -O2
- APCS-compliant code generation

#### tcc - Thumb C Compiler
- Compiles ANSI C to 16-bit Thumb code
- Same command-line interface as armcc
- For code density optimization

#### armasm - ARM/Thumb Assembler
- Supports both ARM and Thumb assembly (merged in 2.50)
- Replaced separate armasm/tasm from earlier versions
- Directive support, pseudo-instructions
- APCS register pre-declarations

#### armlink - ARM Linker
- Combines object files and libraries into executables
- Default ELF format (AIF optional)
- Scatter-loading support
- Interworking veneer insertion
- Selective library inclusion

#### armsd - ARM Symbolic Debugger
- Command-line symbolic debugger
- Breakpoints, watchpoints, variable inspection
- Memory examination
- Source-level debugging

### Windows Development Tools

#### ADW - ARM Debugger for Windows
- GUI debugger environment
- Multi-ICE remote debugging support (added in 2.50)
- DWARF 1 and 2 support
- Memory, register, and variable windows

#### APM - ARM Project Manager
- GUI project management
- Tool configuration dialogs
- Build automation
- Integrated with ADW

### Utility Tools

#### fromELF - ARM Image Conversion Utility
- Converts ELF to AIF, binary, hex formats
- Binary extraction and conversion
- Verilog hex output
- Disassembly output

#### armprof - ARM Profiler
- Execution profiling
- Performance analysis
- Hotspot identification

#### armlib - ARM Librarian
- Creates and maintains ALF libraries
- Library manipulation (add, delete, extract)
- Symbol table management

#### decaof - ARM Object Format Decoder
- Decodes AOF files
- Displays object file contents
- Format verification

#### decaxf - ARM Executable Format Decoder
- Decodes AXF executables
- Displays executable structure

#### topcc - ANSI to PCC C Translator
- UNIX only
- Translates ANSI C to PCC-compatible C

### Supporting Software

#### ARMulator
- ARM core emulator
- Instruction-accurate emulation
- Software-based testing
- No hardware required

#### Angel
- ARM debug monitor
- Runs on target hardware
- Communications for debugging

### C++ Tools (Separate Purchase)

#### armcpp - ARM C++ Compiler
- C++ compilation to ARM code
- Based on CFront technology

#### tcpp - Thumb C++ Compiler
- C++ compilation to Thumb code

## 3. Supported Platforms

### Host Platforms (SDT 2.50)

**Windows:**
- Windows 95/98
- Windows NT 4.0

**UNIX:**
- Sun Solaris 2.5/2.6
- HP-UX 10

### Discontinued Platforms

- Windows NT 3.51
- SunOS 4.1.3
- HP-UX 9
- DEC Alpha NT

### Target Processors (SDT 2.50)

#### Original Support
- ARM6
- ARM7
- ARM7M
- ARM7T
- ARM7TM
- ARM7TDI
- ARM7TDMI
- ARM7TDSP
- ARM8
- ARM9
- ARM9TM
- StrongARM1

#### Added in 2.50
- ARM9TDMI
- ARM940T
- ARM920T
- ARM710T
- ARM740T
- ARM7TDMI-S
- ARM7TDI-S
- ARM7T-S

## 4. Key Technical Features

### File Formats

| Format | Description | Default In |
|--------|-------------|------------|
| **AOF** | ARM Object Format (relocatable objects) | SDT 2.11 |
| **ALF** | ARM Library Format (static libraries) | All versions |
| **AIF** | ARM Image Format (executables) | SDT 2.11 |
| **ELF** | Executable and Linkable Format | SDT 2.50 |
| **ASD** | ARM Symbolic Debug Tables | SDT 2.11 |
| **DWARF** | Standardized debugging format | SDT 2.50 |

### Procedure Call Standards

**APCS (ARM Procedure Call Standard):**
- APCS 3/32/nofp/noswst/narrow/softfp (default in 2.50)
- APCS variants for different configurations
- TPCS (Thumb Procedure Call Standard) for Thumb code

### Major Changes in SDT 2.50

1. **Default ELF format** (was AIF in earlier versions)
2. **Default DWARF 2 debugging** (was ASD)
3. **Merged assembler** (armasm supports both ARM and Thumb)
4. **Instruction scheduling** in compilers
5. **Multi-ICE support** in ADW
6. **fromELF tool** for image conversion
7. **New default processor**: ARM7TDMI (was ARM6)
8. **RDI 1.5** interface
9. **Removed features**: Demon debug monitor, shared library support, RDP protocol

## 5. Development Workflow

### Typical Build Process

```
Source Files (.c, .s)
    ↓
armcc/tcc (compile C)
armasm (assemble)
    ↓
Object Files (.o, AOF format)
    ↓
armlink (link)
    ↓
Executable (AIF or ELF)
    ↓
fromELF (optional conversion)
    ↓
Binary/Hex Output
```

### Library Management

```
Object Files (.o)
    ↓
armlib -c (create)
armlib -a (add)
armlib -r (replace)
    ↓
Library File (.a, ALF format)
    ↓
armlink (link with library)
```

## 6. Integration Features

### RDI (Remote Debug Interface)

- RDI 1.0 (SDT 2.11a)
- RDI 1.5 (SDT 2.50)
- Third-party DLL support
- Hardware debugger integration

### APM Project Management

- Visual project configuration
- Tool option dialogs
- Build automation
- Dependency tracking

### Scatter Loading

SDT 2.50 introduced scatter loading description files for complex memory layouts:
- Memory region definitions
- Section placement control
- Complex embedded system support

## 7. Documentation References

### Primary Documentation

- **ARM DUI 0041C**: ARM Software Development Toolkit Version 2.50 Reference Guide (Nov 1998)
- **ARM DUI 0040**: ARM Software Development Toolkit User Guide
- **ARM DUI 0100**: ARM Architectural Reference Manual
- **ARM DUI 0061**: ARM Target Development System User Guide

### File Format Specifications (in repo)

- AOF (ARM Object Format) - `/docs/AOF_Specification.md`
- ALF (ARM Library Format) - `/docs/ALF_Specification.md`
- AIF (ARM Image Format) - `/docs/AIF_Specification.md`

### Web Archives

- ARM Homepage (2000): https://web.archive.org/web/20000815073149/http://www.arm.com/
- ADS Product Page (2000): https://web.archive.org/web/20000816033036/http://www.arm.com/products/ADS/
- ADS Flyer: https://web.archive.org/web/20000816033036/http://www.arm.com/products/ADS/ADS.pdf
- ADS vs SDT Comparison: https://web.archive.org/web/20000816033036/http://www.arm.com/products/ADS/ADSchanges.pdf

### Current ARM Resources

- ARM Developer: https://developer.arm.com/
- Documentation Hub: https://developer.arm.com/documentation
- Keil (acquired by ARM): https://www.keil.com

## 8. Legacy and Historical Context

### Significance

The ARM SDT was the first comprehensive commercial toolchain for ARM development:
- Established ARM's software ecosystem
- Provided foundation for embedded ARM development
- Bridge between academic compiler technology (Norcroft) and commercial tools
- Standard toolchain for RISC OS development

### Transition to Modern Tools

Understanding SDT is important for:
- Legacy ARM binary reverse engineering
- RISC OS software preservation
- Historical ARM software analysis
- Migrating old projects to modern toolchains

## Summary for Reverse Engineers

The ARM SDT toolchain provides:

1. **Complete Toolchain**: Compiler, assembler, linker, debugger, profiler
2. **Multiple Output Formats**: AOF, ALF, AIF, ELF
3. **Rich Debug Information**: ASD and DWARF formats
4. **APCS Implementation**: Standard calling conventions
5. **Historical Significance**: Original ARM commercial toolchain
6. **RISC OS Integration**: Native RISC OS module generation

For reverse engineering projects, understanding SDT file formats, calling conventions, and code generation patterns is essential for analyzing binaries from the 1995-2000 era.
