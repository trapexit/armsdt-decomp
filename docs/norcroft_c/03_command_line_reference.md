# ARM SDT Command-Line Reference

## Executive Summary

This document provides comprehensive command-line documentation for all ARM SDT (Software Development Toolkit) tools, including compilers, assembler, linker, librarian, debugger, and utilities.

## 1. ARMCC - ARM C Compiler

### Basic Usage

```bash
armcc [options] source_files
```

### Compilation Control Options

| Option | Description |
|--------|-------------|
| `-c` | Compile only (no link) |
| `-o <file>` | Specify output file |
| `-S` | Generate assembly output only |
| `-E` | Preprocess only |
| `--asm` | Generate interleaved assembly listing |
| `-v` | Verbose output |
| `--brief_diagnostics` | Brief error messages |
| `--no_warnings` | Suppress warnings |

### Optimization Options

| Option | Description |
|--------|-------------|
| `-O0` | No optimization (best for debugging) |
| `-O1` | Basic optimizations |
| `-O2` | Full optimizations (default) |
| `-O3` | Aggressive optimizations |
| `-Os` | Optimize for size |
| `--inline` | Enable function inlining |
| `--no_inline` | Disable function inlining |
| `--autoinline` | Automatic inlining heuristics |
| `--multifile` | Enable cross-file optimization |
| `--no_multifile` | Disable cross-file optimization |

### Target Architecture Options

| Option | Description |
|--------|-------------|
| `--cpu=<name>` | Target specific CPU (e.g., ARM7TDMI) |
| `--fpu=<name>` | Specify FPU architecture (fpa, vfp, none) |
| `--arm` | Generate ARM code (default) |
| `--thumb` | Generate Thumb code |
| `--apcs=<qualifiers>` | APCS options (interworking, position independence) |
| `--bigend` | Big-endian mode |
| `--littleend` | Little-endian mode (default) |
| `-16` | 16-bit integer mode |
| `-32` | 32-bit integer mode (default) |

### Preprocessor Options

| Option | Description |
|--------|-------------|
| `-D<name>` | Define preprocessor macro |
| `-D<name>=<value>` | Define macro with value |
| `-U<name>` | Undefine preprocessor macro |
| `-I<dir>` | Add include directory |
| `-include <file>` | Include file at start |
| `-E` | Preprocess only |
| `-C` | Preserve comments in preprocessor output |
| `-M` | Generate dependency list |
| `-MM` | Generate dependency list (skip system headers) |

### Language Standard Options

| Option | Description |
|--------|-------------|
| `--c90` | C90 (ANSI C) standard |
| `--c99` | C99 standard |
| `--strict` | Strict standard compliance |
| `--gnu` | GNU extensions mode |

### Debug Options

| Option | Description |
|--------|-------------|
| `-g` | Generate debug information |
| `--debug` | Same as -g |
| `--no_debug` | No debug information |
| `-gt` | Debug tables only |
| `--dwarf2` | Generate DWARF 2 debug info |
| `--dwarf3` | Generate DWARF 3 debug info |

### Code Generation Options

| Option | Description |
|--------|-------------|
| `--signed_chars` | Default char is signed |
| `--unsigned_chars` | Default char is unsigned |
| `--enum_is_int` | Enums are always int size |
| `--strict_enums` | Strict enum checking |
| `--pointer_alignment=<n>` | Pointer alignment requirement |

### Warning Options

| Option | Description |
|--------|-------------|
| `-W` | Enable all warnings |
| `-Wall` | Enable most warnings |
| `-Werror` | Treat warnings as errors |
| `--warn_about_coding` | Coding standard warnings |
| `--no_warn` | Suppress all warnings |

### Output Format Options

| Option | Description |
|--------|-------------|
| `-elf` | Generate ELF format object |
| `-aof` | Generate AOF format object |
| `--list=<file>` | Generate listing file |
| `--depend=<file>` | Generate dependency file |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ARMCC5INC` | Path to compiler include files |
| `ARMCC5LIB` | Path to compiler libraries |
| `ARMROOT` | Root directory of ARM tools |
| `ARMLIB` | Library search path |

## 2. TCC - Thumb C Compiler

The Thumb C compiler (tcc) shares the same command-line options as armcc but generates 16-bit Thumb code by default.

### Thumb-Specific Options

| Option | Description |
|--------|-------------|
| `--thumb` | Generate Thumb code (default for tcc) |
| `--interwork` | Enable ARM/Thumb interworking |
| `--no_interwork` | Disable interworking |

## 3. ARMASM - ARM/Thumb Assembler

### Basic Usage

```bash
armasm [options] source_file
```

### Target Options

| Option | Description |
|--------|-------------|
| `--cpu=<name>` | Target processor (ARM7TDMI, etc.) |
| `--fpu=<name>` | FPU architecture |
| `-16` | Assemble as Thumb code |
| `-32` | Assemble as ARM code (default) |
| `--apcs=<qualifiers>` | APCS qualifiers |
| `--bigend` | Big-endian mode |
| `--littleend` | Little-endian mode |

### Output Options

| Option | Description |
|--------|-------------|
| `-o <file>` | Output object file |
| `--list=<file>` | Listing file |
| `--xref` | Cross-reference listing |
| `--md` | Generate make dependency file |
| `--depend=<file>` | Dependency output file |
| `--keep` | Keep local symbols in object |
| `--no_warn` | Suppress warnings |
| `-v` | Verbose output |

### Preprocessor Options

| Option | Description |
|--------|-------------|
| `--predefine="<directive>"` | Pre-execute assembler directive |
| `--via=<file>` | Read additional arguments from file |

### Debug Options

| Option | Description |
|--------|-------------|
| `-g` | Include debug information |
| `--debug` | Same as -g |
| `--no_debug` | No debug info |

### Assembler Directives

#### Section Definition

| Directive | Description |
|-----------|-------------|
| `AREA name [,attr]...` | Define code/data section |
| `AREA ||.text||, CODE, READONLY` | Example code section |
| `AREA ||.data||, DATA, READWRITE` | Example data section |

#### Entry and Export

| Directive | Description |
|-----------|-------------|
| `ENTRY` | Mark program entry point |
| `EXPORT <symbol>` | Make symbol visible externally |
| `EXPORT <symbol> [WEAK]` | Weak export |
| `GLOBAL <symbol>` | Same as EXPORT |
| `IMPORT <symbol>` | Import external symbol |
| `EXTERN <symbol>` | Same as IMPORT |

#### Data Definition

| Directive | Description |
|-----------|-------------|
| `DCD <expr> [, <expr>]...` | Define 32-bit constants |
| `DCDU <expr> [, <expr>]...` | Define 32-bit constants (unaligned) |
| `DCW <expr> [, <expr>]...` | Define 16-bit constants |
| `DCWU <expr> [, <expr>]...` | Define 16-bit constants (unaligned) |
| `DCB <expr> [, <expr>]...` | Define bytes |
| `DCDO <expr> [, <expr>]...` | Define 32-bit offsets |
| `SPACE <size>` | Reserve zeroed memory |
| `FILL <size> [, <value>]` | Reserve filled memory |
| `% <size>` | Same as SPACE |

#### Symbol Definition

| Directive | Description |
|-----------|-------------|
| `<symbol> EQU <value>` | Define constant |
| `<symbol> * <value>` | Same as EQU |
| `RN <n>` | Define register name |
| `RLIST <list>` | Define register list |

#### Alignment

| Directive | Description |
|-----------|-------------|
| `ALIGN [<expr>]` | Align to boundary (power of 2) |
| `ALIGN [<expr> [, <offset>]]` | With offset |

#### Procedure Definition

| Directive | Description |
|-----------|-------------|
| `<label> PROC [<type>]` | Function/procedure start |
| `ENDP` | Function/procedure end |
| `FUNCTION` | Same as PROC |
| `ENDFUNC` | Same as ENDP |

#### Macro Definition

| Directive | Description |
|-----------|-------------|
| `MACRO` | Macro definition start |
| `MEND` | Macro definition end |
| `MEXIT` | Exit macro early |

#### Conditional Assembly

| Directive | Description |
|-----------|-------------|
| `IF <logical_expr>` | Conditional assembly |
| `ELSE` | Else clause |
| `ENDIF` | End conditional |
| `WHILE <logical_expr>` | Loop construct |
| `WEND` | End while loop |

#### File Inclusion

| Directive | Description |
|-----------|-------------|
| `INCLUDE <filename>` | Include assembly file |
| `GET <filename>` | Same as INCLUDE |
| `INCBIN <filename>` | Include binary file |

#### Miscellaneous

| Directive | Description |
|-----------|-------------|
| `END` | End of assembly |
| `LTORG` | Literal pool directive |
| `ROUT [<name>]` | Set local label scope |
| `INFO <numeric_expr>, <string_expr>` | Diagnostic message |
| `ASSERT <logical_expr>` | Assertion |
| `OPT <n>` | Set listing options |
| `TTL <title>` | Set subtitle |
| `SUBT <subtitle>` | Set sub-subtitle |

## 4. ARMLINK - ARM Linker

### Basic Usage

```bash
armlink [options] object_files/libraries
```

### Output Control Options

| Option | Description |
|--------|-------------|
| `--output=<file>` | Output image file |
| `-o <file>` | Same as --output |
| `--elf` | Generate ELF format (default in 2.50) |
| `--aif` | Generate AIF format |
| `--bin` | Generate plain binary |
| `--info=<topic>` | Output information |
| `--map` | Generate memory map |
| `--symbols` | List all symbols |
| `--xref` | Generate cross-reference |
| `--callgraph` | Generate call graph |
| `--list=<file>` | Listing file |

### Memory Layout Options

| Option | Description |
|--------|-------------|
| `--ro-base=<addr>` | Read-only base address |
| `--rw-base=<addr>` | Read-write base address |
| `--zi-base=<addr>` | Zero-initialized base address |
| `--first=<section>` | Place section first |
| `--last=<section>` | Place section last |
| `--scatter=<file>` | Use scatter loading file |

### Entry Point Options

| Option | Description |
|--------|-------------|
| `--entry=<symbol>` | Set entry point |
| `--entry=<addr>` | Set entry point address |

### Library Options

| Option | Description |
|--------|-------------|
| `--libpath=<dir>` | Library search path |
| `-L<dir>` | Same as --libpath |
| `-l<lib>` | Link with library |
| `--scanlib` | Scan libraries for unresolved refs |
| `--noscanlib` | Don't scan default libraries |

### Section Control Options

| Option | Description |
|--------|-------------|
| `--remove` | Remove unused sections |
| `--noremove` | Keep all sections |
| `--verbose` | Verbose output |
| `--via=<file>` | Read options from file |

### Scatter Loading File Format

```
LOAD_ROM 0x0000 0x10000
{
    EXEC_ROM 0x0000 0x10000
    {
        * (+RO)
    }
    
    RAM 0x10000 0x10000
    {
        * (+RW, +ZI)
    }
}
```

#### Scatter File Syntax

```
<load_region> <base_addr> [<length>]
{
    <exec_region> <base_addr> [<length>]
    {
        <module> (<section_pattern>)
    }
}
```

#### Section Patterns

| Pattern | Description |
|---------|-------------|
| `+RO` | Read-only sections |
| `+RW` | Read-write sections |
| `+ZI` | Zero-initialized sections |
| `+ENTRY` | Section containing entry point |
| `*(section)` | All sections named 'section' |

## 5. ARMLIB - ARM Librarian

### Basic Usage

```bash
armlib [options] library [files...]
```

### Operation Modes

| Option | Description |
|--------|-------------|
| `-c` | Create new library |
| `--create` | Same as -c |
| `-a <files>` | Add files to library |
| `-d <files>` | Delete files from library |
| `-r <files>` | Replace files in library |
| `-x <files>` | Extract files from library |
| `-t` | List library contents |
| `-s` | Print library symbol table |

### Additional Options

| Option | Description |
|--------|-------------|
| `-v` | Verbose output |
| `--via=<file>` | Read options from file |
| `-c` (with -x) | Create directory when extracting |

### Library Management Examples

```bash
# Create new library
armlib -c mylib.a file1.o file2.o

# Add files to existing library
armlib -a mylib.a file3.o file4.o

# Extract all files
armlib -x mylib.a

# List contents
armlib -t mylib.a

# Show symbol table
armlib -s mylib.a
```

## 6. ARMSD - ARM Symbolic Debugger

### Basic Usage

```bash
armsd [options] [executable]
```

### Debugger Commands

#### Execution Control

| Command | Description |
|---------|-------------|
| `load <file>` | Load executable |
| `run` | Start execution |
| `run <args>` | Run with arguments |
| `stop` | Stop execution |
| `continue` | Continue execution |
| `step` | Single step (into) |
| `step <n>` | Step n instructions |
| `next` | Step over |
| `next <n>` | Step over n times |
| `go` | Same as continue |
| `quit` | Exit debugger |

#### Breakpoints and Watchpoints

| Command | Description |
|---------|-------------|
| `break <addr>` | Set breakpoint |
| `break <function>` | Break at function |
| `break <file>:<line>` | Break at line |
| `watch <addr>` | Set watchpoint |
| `watch <variable>` | Watch variable |
| `clear <n>` | Clear breakpoint n |
| `clear all` | Clear all breakpoints |
| `info breakpoints` | List breakpoints |
| `info watchpoints` | List watchpoints |

#### Data Inspection

| Command | Description |
|---------|-------------|
| `print <expr>` | Print expression |
| `p <expr>` | Same as print |
| `display <expr>` | Auto-display expression |
| `undisplay <n>` | Remove display |
| `x/<n><f><u> <addr>` | Examine memory |
| `registers` | Show registers |
| `reg <reg>` | Show specific register |

#### Memory Formats

| Format | Description |
|--------|-------------|
| `x` | Hexadecimal |
| `d` | Decimal |
| `u` | Unsigned decimal |
| `o` | Octal |
| `t` | Binary |
| `a` | Address |
| `c` | Character |
| `f` | Float |
| `s` | String |

#### Stack and Backtrace

| Command | Description |
|---------|-------------|
| `backtrace` | Show call stack |
| `bt` | Same as backtrace |
| `where` | Same as backtrace |
| `up` | Move up stack frame |
| `up <n>` | Move up n frames |
| `down` | Move down stack frame |
| `down <n>` | Move down n frames |
| `frame <n>` | Select frame n |

#### Source Navigation

| Command | Description |
|---------|-------------|
| `list` | Show source |
| `list <line>` | Show around line |
| `list <function>` | Show function |
| `disassemble <addr>` | Disassemble code |
| `search <pattern>` | Search source |

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--agent=<dll>` | Debug agent DLL |
| `--image=<file>` | Image to debug |
| `--script=<file>` | Execute script on startup |
| `--sym=<file>` | Additional symbol file |
| `--args <arguments>` | Pass arguments to program |

## 7. FROMELF - ARM Image Conversion Utility

### Basic Usage

```bash
fromelf [options] input_file [output_file]
```

### Output Format Options

| Option | Description |
|--------|-------------|
| `--bin` | Plain binary output |
| `--m32` | Motorola 32-bit Hex |
| `--i32` | Intel Hex-32 |
| `--vhx` | Byte-oriented Verilog Hex |
| `--elf` | ELF format (default) |
| `--aif` | AIF format |
| `--text` | Text information |
| `--output=<file>` | Output file |

### Information Options

| Option | Description |
|--------|-------------|
| `--info` | Image information |
| `--fieldoffsets` | Generate C header with structure offsets |
| `--symbols` | Symbol information |
| `--disassemble` | Disassemble code |
| `--dump` | Raw binary dump |
| `--text` | Text output of contents |

### Processing Options

| Option | Description |
|--------|-------------|
| `--nodebug` | Remove debug info |
| `--no_locals` | Remove local symbols |
| `--interleave` | Interleave source with disassembly |

## 8. Environment Variables Summary

### Global Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `ARMROOT` | All tools | Root directory of ARM installation |
| `ARMLIB` | armlink | Library search path |
| `ARMCONF` | All tools | Configuration file directory |

### Compiler-Specific

| Variable | Used By | Description |
|----------|---------|-------------|
| `ARMCC5INC` | armcc | Compiler include path |
| `ARMCC5LIB` | armcc | Compiler library path |
| `ARMCC5BIN` | armcc | Compiler binary path |

### Debugger-Specific

| Variable | Used By | Description |
|----------|---------|-------------|
| `ARMDLL` | armsd | Debug agent DLL path |
| `ARMDB` | armsd | Debugger configuration |

## 9. Build System Integration

### Makefile Example

```makefile
# ARM SDT Makefile Template

CC = armcc
AS = armasm
LD = armlink
AR = armlib

# Target CPU
CPU = ARM7TDMI

# Directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin

# Flags
CFLAGS = -c --cpu $(CPU) -O2 -g --apcs /interwork
ASFLAGS = --cpu $(CPU) -g
LDFLAGS = --scatter scatter.scat --map --symbols

# Source files
CSRCS = $(wildcard $(SRCDIR)/*.c)
ASRCS = $(wildcard $(SRCDIR)/*.s)

# Object files
COBJS = $(CSRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
AOBJS = $(ASRCS:$(SRCDIR)/%.s=$(OBJDIR)/%.o)
OBJS = $(COBJS) $(AOBJS)

# Target
TARGET = $(BINDIR)/project.elf

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BINDIR)
	$(LD) $(LDFLAGS) --output $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.s
	@mkdir -p $(OBJDIR)
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -rf $(OBJDIR) $(BINDIR)
```

### Via Files

For complex command lines, ARM SDT supports "via files":

**options.via:**
```
--cpu ARM7TDMI
-O2
-g
--apcs /interwork
-I../include
-DVERSION=2
```

**Usage:**
```bash
armcc --via=options.via -c main.c -o main.o
```

## 10. APCS Qualifiers

### APCS Options

| Qualifier | Description |
|-----------|-------------|
| `3/26bit` | 26-bit PC (ARM2/ARM3) |
| `3/32bit` | 32-bit PC (ARM6+) |
| `fp` | Use frame pointer |
| `nofp` | No frame pointer |
| `swst` | Software stack checking |
| `noswst` | No stack checking |
| `narrow` | Narrow APCS |
| `wide` | Wide APCS |
| `interwork` | ARM/Thumb interworking |
| `nointerwork` | No interworking |
| `softfp` | Software floating point |
| `hardfp` | Hardware floating point |

### Example Usage

```bash
armcc --apcs /32bit/nofp/noswst/interwork
armcc --apcs /26bit/fp/swst
```

## 11. Quick Reference Card

### Compile C to Object
```bash
armcc -c --cpu ARM7TDMI -O2 -g file.c -o file.o
```

### Assemble to Object
```bash
armasm --cpu ARM7TDMI -g file.s -o file.o
```

### Link Objects
```bash
armlink --ro-base 0x8000 --rw-base 0x10000 -o output.elf file1.o file2.o
```

### Create Library
```bash
armlib -c mylib.a file1.o file2.o
```

### Convert to Binary
```bash
fromelf --bin --output output.bin input.elf
```

### Debug Program
```bash
armsd --image=program.elf
```

## References

- ARM DUI 0040: ARM Software Development Toolkit User Guide
- ARM DUI 0041C: ARM Software Development Toolkit Reference Guide
- ARM DUI 0042: ARM Linker User Guide
- ARM DUI 0043: ARM Librarian User Guide
- ARM DUI 0044: fromelf User Guide
- ARM DUI 0045: ARM Debugger User Guide
