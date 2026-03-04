# Norcroft C Compiler - Comprehensive Technical Reference

## Executive Summary

Norcroft C is a historically significant C/C++ compiler suite originally developed by Codemist Limited in 1987. It became the foundation of ARM's official Software Development Toolkit (SDT) and was instrumental in the development of the RISC OS operating system and ARM ecosystem.

## 1. Origins and History

### Founding

**Codemist Limited** was founded in November 1987 by three academics:
- **Arthur Norman** (University of Cambridge)
- **Alan Mycroft** (University of Cambridge)
- **John Fitch** (University of Bath)

**Name Origin**: "Norcroft" is a portmanteau derived from the creators' surnames: **Nor**man + **Mycro**ft = Norcroft

### Development Timeline

| Year | Milestone |
|------|-----------|
| ~1985 | Initial compiler development work begins |
| 1987 | Codemist Limited formally established (November) |
| 1988 | Acornsoft ANSI C Release 1 for Archimedes |
| 1989 | Acorn ANSI C Release 3 - Major ANSI standard support |
| 1991 | Acorn Desktop C Release 4 - Includes Desktop Assembler |
| 1995 | Acorn C/C++ Release 5 - C++ support via CFront 3.0 |
| 1996 | Apple Newton C++ Toolbox version released |
| 2004+ | Castle Technology subscription updates |
| 2009+ | RISC OS Open (ROOL) assumes maintenance |
| 2016 | Codemist Limited dissolved (May) |
| 2020 | C18 (ISO9899:2018) standard support added |
| 2025 | DDE32b released (December) - Latest version |

### Academic Background

The compiler's development was grounded in academic computer science research. The founders brought expertise from Cambridge University Computing Labs, particularly in:
- Compiler optimization theory
- Register allocation algorithms
- Code generation techniques

## 2. Acorn Computers Collaboration

### Joint Development Model

The Acorn C/C++ compiler was developed as a collaboration between:
- **Codemist (Norcroft)**: Responsible for ANSI C standard compliance and portable optimizer
- **Acorn Computers Programming Languages Group (PLG)**: Responsible for RISC OS specifics and ARM-specific optimizations

### Quote from Ian Johnson (Acorn PLG)

> "The development of the compiler was a joint venture between Norcroft (at the time Arthur Norman and Alan Mycroft--two academics from Cambridge University Computing Labs) and the PLG at Acorn. Sources were regularly exchanged between both parties but, generally, Norcroft were responsible for adherence to the emerging ANSI standard, whilst Acorn concentrated on the RISC OS specifics of the C library and on common subexpression elimination, register allocation and peephole optimisation for the ARM."

### ARM Ltd. Transition

With the formation of ARM Ltd in 1990, compiler development moved to ARM Ltd, and Acorn began receiving source versions of the compiler for various ARM-based platforms.

## 3. Architecture Support

### Primary ARM Platforms

| Platform | Processor | Era |
|----------|-----------|-----|
| Acorn Archimedes | ARM2, ARM3 | 1987-1992 |
| Acorn Risc PC | ARM6/ARM7/StrongARM | 1994-2000 |
| Acorn A7000/A7000+ | ARM7500 | 1995-1997 |
| Apple Newton | ARM710 | 1996 |
| Embedded ARM systems | Various | 1990s-present |

### Other Norcroft Compiler Targets

The Norcroft compiler suite was highly portable and supported numerous architectures:

- INMOS Transputer (with Perihelion Software)
- Cambridge Consultants XAP processor
- AMD 29000
- DEC Alpha
- Intel Pentium (Linux)
- Intel i860
- MIPS
- Motorola 68K/88K
- National Semiconductor 320xx
- SPARC
- IBM 370
- Hitachi mainframe
- NEC 860

## 4. Technical Characteristics

### Intermediate Representation

The compiler uses **JOP-code** (Jump-Oriented Pseudo-code) as its intermediate representation:
- Similar structure to ARM instruction set
- Organized in "basic blocks" for optimization
- Machine-independent optimization performed on JOP-code
- ARM-specific peephole optimization in final code generation

### Optimization Features

| Optimization | Description |
|--------------|-------------|
| **Register Allocation** | Graph coloring algorithm - innovative for its time |
| **Global CSE** | Common Subexpression Elimination across basic blocks |
| **Instruction Scheduling** | Reorders instructions for pipeline efficiency |
| **Peephole Optimization** | ARM-specific code improvements |
| **Variable Lifetime Analysis** | Release 5+ - reduces code size up to 10% |
| **Function Inlining** | Automatic inlining of small library functions |

### Language Standards

| Standard | Support Level |
|----------|---------------|
| ANSI C (C89) | Strict implementation - primary focus |
| C99 | Extensions added by Castle Technology |
| C18 (ISO9899:2018) | Added October 2020 |
| C++ | Via AT&T CFront 3.0 translator (Release 5+) |

### Inline Assembly

The compiler supports inline assembly allowing C/assembly mixing, which was particularly important for RISC OS development where low-level hardware access was common.

## 5. ARM SDT Integration

### Role in ARM SDT

Norcroft C was the foundation of ARM's official Software Development Toolkit (SDT):

- **armcc**: The ARM C compiler based on Norcroft
- **tcc**: Thumb C compiler (16-bit code generation)
- ARM SDT 2.50 was the major release integrating Norcroft technology

### Code Generation Targets

- ARM A32 instruction set (32-bit)
- ARM T32 (Thumb) instruction set (16-bit)
- FPA (Floating Point Accelerator) instructions
- VFP (Vector Floating Point) instructions
- NEON (ARMv7+) support (later additions)

## 6. Comparison with GCC

From riscos.info comparison:

| Feature | Norcroft | GCC |
|---------|----------|-----|
| Compilation Speed | ~2x faster | Slower |
| Memory Usage | Lower (especially C++) | Higher |
| Warning Quality | Fewer but stronger (especially enums) | Many configurable |
| Module Generation | Yes (RISC OS modules) | No |
| Debug Info | Native DDT format | Various formats |
| C++ Support | Older (CFront-based) | More modern |
| C99 Support | Limited (later added) | Full C99 |
| GNU Extensions | No | Yes |
| Price | Commercial | Free |
| Code Speed | Similar (with optimization) | Similar |

**Performance**: Both compilers generate code running at similar speeds when GCC optimization is enabled.

**Unique Advantages of Norcroft**:
- Only compiler that can generate RISC OS modules
- Better integration with RISC OS debugging tools (DDT)
- Smaller memory footprint
- Faster compilation cycles

## 7. File Formats

### Generated Object Formats

- **AOF** (ARM Object Format) - Default object format
- **ELF** (Executable and Linkable Format) - Added in later versions
- **AIF** (ARM Image Format) - Executable output
- **ALF** (ARM Library Format) - Static libraries

### Debug Information

- **ASD** (ARM Symbolic Debug Tables) - Native format
- **DWARF** - Standardized format (later versions)

## 8. Reverse Engineering Significance

### Compiler Patterns

For reverse engineering ARM SDT binaries:

1. **JOP-code Characteristics**: Look for specific code generation patterns from the JOP intermediate representation
2. **Register Allocation**: Graph coloring produces distinctive register usage patterns
3. **Peephole Optimizations**: ARM-specific optimizations leave recognizable signatures
4. **APCS Compliance**: Generated code follows ARM Procedure Call Standard conventions

### Runtime Library Signatures

Norcroft C uses specific runtime libraries with distinctive signatures:
- Math library implementations
- String manipulation functions
- Memory allocation routines
- Exception handling (C++)

### Binary Identification

Indicators of Norcroft/ARM SDT compilation:
- Specific prologue/epilogue patterns
- APCS register usage (R0-R3 arguments, R0 return)
- Distinctive stack frame layouts
- Debug information format (ASD tables)

## 9. Documentation and References

### Primary Sources

1. **Wikipedia - Norcroft C compiler**  
   https://en.wikipedia.org/wiki/Norcroft_C_compiler

2. **Wikipedia - Acorn C/C++**  
   https://en.wikipedia.org/wiki/Acorn_C/C++

3. **RISC OS Open - Desktop Development Environment**  
   https://www.riscosopen.org/content/sales/dde

4. **Codemist Archives (Wayback Machine)**  
   https://web.archive.org/web/20120425081927/http://www.codemist.co.uk/ncc/index.html

5. **Interview with Ian Johnson (ACCU)**  
   https://web.archive.org/web/20060601035948/http://www.accu.informika.ru/acornsig/public/caugers/volume2/issue1/ianjohnson.html

6. **Norcroft vs GCC Comparison**  
   https://web.archive.org/web/20020404222725/http://www.riscos.info/compilers/compare.html

7. **Newton FAQ - Development Tools**  
   https://newtonfaq.com/newton-faq-development.html

### Technical Documentation

- "The internal structure of the Norcroft C compiler" (1986)
- "Implementation decisions for 'C' on non-standard architectures" (1992)
- "The Norcroft compiler suite; technical overview and details" (1993)

### ARM SDT Documentation

- ARM DUI 0041C: ARM Software Development Toolkit Version 2.50 Reference Guide
- ARM DUI 0040: ARM Software Development Toolkit User Guide
- ARM DUI 0047: C++ for the ARM Software Development Toolkit

### Academic Papers

Singer, Jeremy; Smith, Lee (2026). "The Norcroft Compiler at Arm". Lecture Notes in Computer Science. 15500: 3-13. DOI: 10.1007/978-3-032-08187-2_1

## 10. Legacy and Modern Status

### Current Maintenance

The Norcroft C compiler is now maintained by **RISC OS Open** as part of the Desktop Development Environment (DDE):
- Latest version: DDE32b (December 2025)
- Continues to be the primary tool for RISC OS development
- Supports modern ARM processors (ARMv7, ARMv8 AArch32)

### Historical Significance

- Used to build RISC OS operating system itself
- Foundation of ARM's commercial toolchain ecosystem
- Pioneered register allocation by graph coloring in commercial compilers
- Bridge between academic compiler research and commercial development

## Summary for Reverse Engineers

Understanding Norcroft C is essential for reverse engineering ARM SDT binaries from the 1987-2000 era because:

1. **Unique Code Generation**: JOP-code intermediate representation produces distinctive patterns
2. **Optimization Signatures**: Graph coloring register allocation and ARM-specific peepholes
3. **APCS Implementation**: Specific calling convention implementation details
4. **Runtime Libraries**: Distinctive library function implementations
5. **Debug Formats**: ASD tables provide rich symbol information
6. **File Formats**: AOF, ALF, AIF formats require specific parsers

The compiler represents a crucial piece of computing history as the original commercial C compiler for the ARM architecture, and understanding its internals is key to analyzing legacy ARM binaries.
