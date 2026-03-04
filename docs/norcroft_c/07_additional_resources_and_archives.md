# ARM SDT - Additional Resources and Archives

## Executive Summary

This document consolidates additional resources, archived documentation, and reference materials for Norcroft C and ARM SDT research.

## 1. Historical Documentation Archives

### ARM Official Documentation (DUI Series)

| Document ID | Title | Version | Date |
|-------------|-------|---------|------|
| DUI 0040 | ARM Software Development Toolkit User Guide | 2.50 | Nov 1998 |
| DUI 0041C | ARM Software Development Toolkit Reference Guide | 2.50 | Nov 1998 |
| DUI 0042 | ARM Linker User Guide | 2.50 | 1998 |
| DUI 0043 | ARM Librarian User Guide | 2.50 | 1998 |
| DUI 0044 | fromelf User Guide | 2.50 | 1998 |
| DUI 0045 | ARM Debugger User Guide | 2.50 | 1998 |
| DUI 0046 | ARMulator User Guide | 2.50 | 1998 |
| DUI 0047 | C++ for the ARM Software Development Toolkit | 2.50 | 1998 |
| DUI 0061 | ARM Target Development System User Guide | 2.50 | 1998 |
| DUI 0100 | ARM Architectural Reference Manual | Various | - |

### Archived Web Resources

**ARM Developer Website (2000 Archive):**
- URL: https://web.archive.org/web/20000815073149/http://www.arm.com/
- Contains product information and downloads

**ARM SDT Product Page (2000):**
- URL: https://web.archive.org/web/20000816033036/http://www.arm.com/DevSupp/ordering.html
- Pricing and ordering information

**ADS Product Page (2000):**
- URL: https://web.archive.org/web/20000816033036/http://www.arm.com/products/ADS/
- Information on SDT successor

**ADS Changes Document:**
- URL: https://web.archive.org/web/20000816033036/http://www.arm.com/products/ADS/ADSchanges.pdf
- Differences between SDT and ADS

### Cambridge University Archives

**ARM Tools Course Materials (1998):**
- URL: https://www.cl.cam.ac.uk/teaching/1998/CompDesn/fromlecturer/htmlman/
- HTML man pages for ARM tools
- Includes: armasm, armlink, armlib, etc.

## 2. RISC OS Development Resources

### Current Resources (RISC OS Open)

**Desktop Development Environment (DDE):**
- URL: https://www.riscosopen.org/content/sales/dde
- Modern version of Norcroft C
- Still maintained and sold

**Pricing:**
- Commercial: £150
- Personal/Educational: £50
- Includes: Compiler, assembler, linker, debugger

### Historical RISC OS Documentation

**RISC OS 3 Programmer's Reference Manuals:**
- Volumes 1-5 covering all aspects
- Still available from RISC OS dealers
- Essential for RISC OS reverse engineering

**Acorn C/C++ Release History:**

| Release | Year | Features |
|---------|------|----------|
| Release 1 | 1988 | Initial ANSI C |
| Release 2 | 1989 | Bug fixes |
| Release 3 | 1990 | Major improvements |
| Release 4 | 1991 | Desktop Assembler |
| Release 5 | 1995 | C++ support |
| Castle DDE | 2004+ | Subscription updates |
| ROOL DDE | 2009+ | Community maintenance |

### RISC OS Info Sites

**RISC OS Info:**
- URL: https://www.riscos.info/
- Wiki with compiler comparisons
- URL: https://web.archive.org/web/20020404222725/http://www.riscos.info/compilers/compare.html

**Iconbar:**
- URL: https://www.iconbar.com/
- RISC OS news and forums

**RISCOSitory:**
- URL: https://www.riscository.co.uk/
- Software repository

## 3. Acorn Computers History

### Historical Articles

**The Register - Acorn History:**
- Various articles on Acorn's rise and fall
- Search for "Acorn Computers" on theregister.com

**Drobe Launchpad Archive:**
- URL: https://www.drobe.co.uk/
- RISC OS news archive (2001-2009)

**Acorn User Magazine Archive:**
- Scanned issues available online
- Contains tutorials and reviews

### People and Interviews

**Ian Johnson Interview (ACCU):**
- URL: https://web.archive.org/web/20060601035948/http://www.accu.informika.ru/acornsig/public/caugers/volume2/issue1/ianjohnson.html
- Details on Acorn C/C++ development

**Arthur Norman (Codemist):**
- Professor at Cambridge
- Published papers on compiler construction
- Web: https://www.cam.ac.uk/

**Alan Mycroft:**
- Professor at Cambridge
- Worked on programming language theory
- Co-founded Codemist

### Apple Newton Connection

**Newton C++ Toolbox:**
- URL: https://newtonfaq.com/newton-faq-development.html
- Documentation on Newton development
- Norcroft C/C++ was used

**Newton Developer Resources:**
- UNNA Archive: http://www.unna.org/
- Newton development tools

## 4. File Format Specifications

### In-Repository Documentation

**AOF Specification:**
- File: `/docs/AOF_Specification.md`
- Detailed ARM Object Format
- Structure and field descriptions

**ALF Specification:**
- File: `/docs/ALF_Specification.md`
- ARM Library Format
- Organization and tools

**AIF Specification:**
- File: `/docs/AIF_Specification.md`
- ARM Image Format
- Executable structure

**3DO SDK Documentation:**
- ARM Image Format (3DO variant)
- ARM Object Format (3DO variant)
- ARM Object Library Format
- Procedure Call Standard
- The ARM Linker

### External Format References

**ELF Specification:**
- TIS Committee documents
- Available from various sources

**DWARF Standard:**
- URL: http://dwarfstd.org/
- DWARF 2, 3, 4, 5 specifications

**ARM ABI:**
- URL: https://github.com/ARM-software/abi-aa
- ARM Architecture ABI specifications

## 5. Academic Papers

### Compiler Technology

**Norcroft Compiler Academic Paper:**
- Singer, Jeremy; Smith, Lee (2026)
- "The Norcroft Compiler at Arm"
- Lecture Notes in Computer Science 15500: 3-13
- DOI: 10.1007/978-3-032-08187-2_1

**Register Allocation by Graph Coloring:**
- Chaitin, G.J. et al. (1981)
- "Register Allocation via Coloring"
- Computer Languages 6: 47-57
- Basis of Norcroft's allocator

### ARM Architecture

**Original ARM Papers:**
- Furber, S.B. and Wilson, A. (1984)
- "The ARM Architecture"
- Various ACM publications

## 6. Reverse Engineering Tools

### Disassemblers

**Capstone:**
- URL: https://www.capstone-engine.org/
- Multi-architecture disassembly framework
- Supports ARM, Thumb, ARM64
- Python, C, Rust bindings

**Radare2:**
- URL: https://radare.org/
- Complete reverse engineering framework
- ARM analysis plugins
- Command-line and GUI (Cutter)

**Ghidra:**
- URL: https://ghidra-sre.org/
- NSA's reverse engineering framework
- ARM decompiler
- Free and open source

**Binary Ninja:**
- URL: https://binary.ninja/
- Commercial RE platform
- Excellent ARM support
- MLIL for high-level analysis

### Emulators

**ARMulator:**
- Part of ARM SDT
- Instruction-accurate ARM emulation
- Included with SDT 2.50

**Unicorn Engine:**
- URL: https://www.unicorn-engine.org/
- CPU emulator framework
- ARM, Thumb, ARM64 support

**Qiling Framework:**
- URL: https://github.com/qilingframework/qiling
- Binary emulation with OS context
- ARM Linux, bare metal support

### Debuggers

**armsd:**
- Included with ARM SDT
- Command-line symbolic debugger
- Source-level debugging

**ADW (ARM Debugger for Windows):**
- GUI debugger in SDT
- Windows 95/98/NT support

## 7. Community Resources

### Forums and Discussion

**RISC OS Open Forum:**
- URL: https://www.riscosopen.org/forum/
- Active community discussion
- DDE/compiler questions

**Stardot:**
- URL: https://stardot.org.uk/
- Acorn/RISC OS community
- Retro computing focus

**Reddit:**
- r/ReverseEngineering
- r/arm
- r/retrobattlestations

### Archives and Collections

**The Acorn Preservation Team:**
- Software preservation efforts
- Documentation archives

**RISC OS Filebase:**
- URL: http://www.riscosfilebase.co.uk/
- Software archive

**RISC OS Software Library:**
- Various collections online
- Historical software

## 8. Related Toolchains

### GCC for ARM

**GNU ARM Tools:**
- Predecessor to modern arm-none-eabi-gcc
- Different code generation patterns
- Useful for comparison

**DevKitPro:**
- URL: https://devkitpro.org/
- Modern ARM toolchain
- Homebrew development

### Modern ARM Tools

**ARM Development Studio:**
- URL: https://developer.arm.com/tools-and-software/embedded/arm-development-studio
- Successor to SDT/ADS
- Commercial product

**Keil MDK:**
- URL: https://www.keil.com/
- Microcontroller development kit
- ARM-owned

**PlatformIO:**
- URL: https://platformio.org/
- Open source ecosystem
- ARM support via GCC/Clang

## 9. Books and Publications

### ARM Programming

**"ARM System Developer's Guide"**
- Sloss, Symes, and Wright
- Morgan Kaufmann, 2004
- ISBN: 1558608745
- Comprehensive ARM programming guide

**"The ARM Architecture Reference Manual"**
- ARM Limited
- Various editions
- Definitive ARM reference

### Compiler Construction

**"Compilers: Principles, Techniques, and Tools"**
- Aho, Sethi, Ullman (Dragon Book)
- Compiler theory and implementation

**"Modern Compiler Implementation in C"**
- Andrew W. Appel
- Practical compiler construction

### Reverse Engineering

**"Reverse Engineering for Beginners"**
- Dennis Yurichev
- Free online book
- ARM assembly coverage
- URL: https://beginners.re/

**"The IDA Pro Book"**
- Chris Eagle
- No Starch Press
- Practical RE techniques

## 10. Search Strategies

### Finding Historical Information

1. **Wayback Machine:**
   - Search for arm.com, acorn.co.uk
   - Look for documentation snapshots
   - Check specific dates (1997-2000)

2. **Google Scholar:**
   - Search for "Norcroft compiler"
   - Find academic papers
   - Citations and references

3. **GitHub:**
   - Search for ARM SDT references
   - File format implementations
   - Historical code

4. **Vintage Computing Forums:**
   - Stardot (Acorn focus)
   - Vintage Computer Federation
   - Retrocomputing Stack Exchange

5. **University Archives:**
   - Cambridge University
   - Bath University
   - Contact professors directly

### Key Search Terms

- "ARM SDT" "Software Development Toolkit"
- "Norcroft C" "Norcroft compiler"
- "Acorn C/C++"
- "Codemist"
- "Arthur Norman" "Alan Mycroft"
- "ARM Procedure Call Standard" "APCS"
- "AOF format" "ALF format" "AIF format"
- "RISC OS" "DDE" "Desktop Development Environment"

## References Summary

### Primary Documentation
- ARM DUI series (in repository)
- Codemist archives (Wayback Machine)
- Acorn/RISC OS manuals

### Online Resources
- ARM Developer (developer.arm.com)
- RISC OS Open (riscosopen.org)
- Cambridge ARM archives

### Communities
- Stardot forums
- RISC OS Open forums
- Reddit reverse engineering

### Tools
- Capstone, Radare2, Ghidra
- Unicorn, Qiling
- fromELF (ARM SDT)

---

*This document is a living resource. Add new findings and references as discovered.*
