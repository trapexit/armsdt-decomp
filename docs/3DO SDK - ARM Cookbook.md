# ARM Cookbook

---

This document covers a broad spectrum of topics; from introductory
illustrations through to complex examples. The material has not been
grouped or ordered by complexity, but by theme. Where possible, we
have given real recipes, supported by on-line code explained and
available for you to adapt to your particular needs.

To get the most out of the recipes, use this manual in conjunction
with the on-line examples, as well as the rest of the toolkit
documentation. The user is sometimes referred to other parts of the
documentation for more information.

It is also useful to have a copy of the ARM Datasheet for whatever
device is being used, as these manuals do not cover device specific
details.

# Audience

This manual is aimed at competent programmers who want to find out
rapidly how to exploit the ARM instruction set and make use of the ARM
Software Development Toolkit (the toolkit).

# How this document is organized

This document provides information about four main areas of interest:

- ARM Instruction Set and Processor Features, discusses features of
  the ARM instruction set.
- Exploring ARM Assembly Language, explores the ARM Assembly Language
  by providing several examples.
- Interfacing Assembly Language and C, provides examples and recipes
  for interfacing C and ARM Assembly Language.
- Programming in C, provides example of programming in C with the ARM
  Software Development Toolkit.

# Examples used in this document

The examples in this document are meant for illustration only. The
code for the examples is not included with the 3DO (tm) software.

# ARM Instruction Set and Processor Features

---

This document contains cookbook recipes that help you work better with
the ARM instruction set and processor. Click on one of the topics
below to select it.

- Overview of key features
- Making the most of conditional execution
- Using the Barrel Shifter
- Flexibility of load and store multiple
- Loading constants into registers

## Examples

The examples used in this document are meant to illustrate certain
points. Source code is not included on the 3DO CD-ROM.

# Exploring ARM Assembly Language

---

This document provides some recipes that help you understand how to
use ARM assembly language to best advantage.

Click on one of the topics below to select a recipe:

- Integer to string conversion
- Multiply by a constant
- Division by a constant
- Choosing a division implementation
- Digital signal processing on the ARM
- Using 16-bit data on the ARM
- ARM600
- Pseudo random number generation
- Loading a word from an unknown alignment
- Byte order reversal
- ARM assembly programming performance issues

# Interfacing Assembly Language and C

---

This document provides recipes for interfacing assembly language and
C. Click on one of the topics below to see the recipe:

- Register usage under the ARM procedure call standard
- Passing and returning structs
- In-Line SWIs

# Programming in C

---

The recipes in this chapter deal with programming in C. Click on one
of the topics below to see the recipe:

- A simple C program
- Writing efficient C for the ARM
- C Programming for deeply embedded applications
- ARM shared libraries

## Examples

The examples used in this document are meant to illustrate certain
points. Source code is not included on the 3DO CD-ROM.

# Overview of key features

---

The ARM instruction set has the following key features, some of which
are common to many other processors, and some of which are not:

- Load/Store architecture (only load and store instructions access
  memory).
- 32 bit instructions, 32/8 bit data words/bytes.
- 32 bit addresses (26 bit on earlier ARMs).
- 15 general purpose 32 bit registers, program counter and program
  status register - a subset of these are banked, to give rapid
  context switching for interrupt and supervisor modes. (See the
  appropriate ARM Data Sheet for details of particular processors).
- Flexible store multiple and load multiple instructions allow any set
  of registers from a single bank to be transferred to/from memory by
  a single instruction.
- There is no single instruction to move an immediate 32 bit value to
  a register (in general, a literal value has to be loaded from
  memory). However, a large set of common 32-bit values *can* be
  generated in a single instruction.
- All instructions are executed conditionally on the state of the
  current program status register. Only data processing operations
  with the S bit set change the state of the current program status
  register.
- The second argument to all data-processing and single data-transfer
  operations can be shifted in quite a general way before the
  operation is performed. This supports, but is not limited to, scaled
  addressing, multiplication by a small constant, and construction of
  constants, within a single instruction.
- Co-processor instructions support a general way to extend the ARM's
  architecture in a customer-specific manner.

In addition, the ARM processor has:

- Support for Big- or Little-Endian memory.
- A powerful barrel shifter to support ARM's within-instruction
  shifts.

The recipes in this chapter discuss some of these features in greater
detail.

# Making the most of conditional execution

---

## About this recipe

In this recipe you learn how conditional execution can eliminate
branch instructions, producing smaller and faster code. Euclid's
Greatest Common Divisor algorithm is used for illustrative
purposes. Specifically, you will learn how to use:

- conditional execution;
- the 'S' bit in ARM data processing instructions.

## The ARM's ALU status flags

The ARM's Program Status Register contains, among other flags, copies
of the ALU status flags:

| N | Negative result from ALU flag |
| --- | ----------------------------- |
| Z | Zero result from ALU flag |
| C | ALU operation Carried out |
| V | ALU operation oVerflowed |

## Execution conditions

Every ARM instruction has a 4 bit field which encodes the conditions
under which it will be executed. These conditions refer to the state
of the ALU N, Z, C and V flags as follows:

| EQ | Z set (equal) |
| ----- | ------------------------------------------------- |
| NE | Z clear (not equal) |
| CS/HS | C set (unsigned >=) |
| CC/LO | C clear (unsigned <) |
| MI | N set (negative) |
| PL | N clear (positive or zero) |
| VS | V set (overflow) |
| VC | V clear (no overflow) |
| HI | C set and Z clear (unsigned >) |
| LS | C clear and Z set (unsigned <=) |
| GE | N and V the same (signed >=) |
| LT | N and V differ (signed <) |
| GT | Z clear, N and V the same (signed >) |
| LE | Z set, N and V differ (signed <=) |
| AL | Always execute (the default if none is specified) |

## Setting the ALU flags in the PSR

Data processing instructions change the state of the ALU's N,Z,C and V
status outputs but these are latched in the PSR'S ALU flags only if a
special bit (the 'S' bit) is set in the instruction.

## Illustration

The following code fragment is extracted from **gcd.c**, which can be
found in the **examples** directory.

    while (a != b)
    { if (a > b) a -= b;
      else       b -= a;
    }

Without conditional execution this could be naively coded as:

    gcd CMP    a1, a2
        BEQ    end
        BLT    lessthan
        SUB    a1, a1, a2
        B      gcd
    lessthan
        SUB    a2, a2, a1
        B      gcd
    end 

Conditional execution and selective setting of the PSR'S ALU flags
allows it to be coded much more compactly as follows (this version can
be found in the **examples** directory as **gcd.s**).

    gcd CMP    a1, a2
        SUBGT  a1, a1, a2
        SUBLT  a2, a2, a1
        BNE    gcd

Two tricks are illustrated:

- The CMP instruction (implicitly) has the 'S' bit set, so the result
  of the comparison sets the PSR ALU status flags. However, the
  following two subtractions do not have the 'S' bit set, so they do
  not affect the PSR ALU status flags which remain in the state set by
  the earlier CMP instruction when the BNE instruction is
  executed. The test (a != b) has been combined with the branch back
  to the top of the loop, giving shorter code, and in many instances
  code which runs more quickly.
- The two subtractions are executed only if the condition specified is
  met, so two branches around these instructions can be avoided. In
  addition to the obvious benefit of smaller code, any pipeline refill
  caused by the branches will also have been avoided.

## Running the C example

You can run the C **gcd** routine shown above under **armsd**. To do
this first set your current directory to the **examples** directory.

Compile, link and run the C version of the **gcd** routine by using
the following commands:

    armcc -c gcd.c -li -apcs 3/32bit
    armcc -c gcdtest.c -li -apcs 3/32bit
    armlink -o gcdtest gcd.o gcdtest.o somewhere/armlib.321
    armsd -li gcdtest

where **somewhere** is the directory in which **armlib.32l** can be
found.

### Explanation

The two **armcc** commands compile the gcd function and the test
harness, creating relocatable object files **gcd.o** and
**gcdtest.o**. The -li flag tells **armcc** to compile for a
little-endian memory. The -apcs 3/32bit option tells **armcc** to use
a 32 bit version of the ARM Procedure Call Standard. You can omit
these options if your **armcc** has been configured for this default.

The **armlink** command links your relocatable objects with the ARM C
library to create a runnable program (here called **gcdtest**).

The **armsd** command invokes the debugger, with **gcdtest** as the
program to be run. Again -li specifies that little-endian memory is
required (as with **armasm** above).

## Running the assembler example

You can run the **gcd** routine shown above under **armsd**. To do
this first set your current directory to the **examples** directory.

You can assemble, link and run the assembler **gcd** routine by using
the following commands:

    armasm gcd.s -o gcd.o -li
    armcc -c gcdtest.c -li -3/32bit
    armlink -o gcdtest gcd.o gcdtest.o somewhere/armlib.32l
    armsd -li gcdtest

where **somewhere** is the directory in which **armlib.32l** can be
found.

### Explanation

The **armasm** command assembles the **gcd** function, creating the
relocatable object file **gcd.o**. The -li flag tells **armasm** to
assemble for a little-endian memory. The -apcs 3/32bit option tells
**armcc** to use a 32 bit version of the ARM Procedure Call
Standard. You can omit these options if your **armasm** has been
configured for this default.

The **armcc** command compiles the test harness. The -c flag tells
**armcc** not to link its output with the C library; the -li flag
tells **armcc** to compile for a little-endian memory (as with
**armasm**).

The **armlink** command links your relocatable objects with the ARM C
library to create a runnable program (here called **gcdtest**).

The **armsd** command invokes the debugger, with **gcdtest** as the
program to be run. Again -li specifies that little-endian memory is
required (as with **armasm** above).

## Related topics

- There are many examples of code which makes good use of the ARM's
  condition codes and 'S' bit in recipes in Exploring ARM Assembly
  Language.

# Using the Barrel Shifter

---

In this recipe you learn:

- how to index into an array efficiently in ARM assembler.
- how to use the barrel shifter in the main ARM instruction classes;

## Addressing an entry in a table of words

The following piece of code inefficiently calculates the address of an
entry in a table of words and then loads the desired word:

    ; R0 holds the entry number [0,1,2,...]
        LDR  R1, =StartOfTable
        MOV  R3, #4
        MLA  R1, R0, R3, R1
        LDR  R2, [R1]
        ...
    StartOfTable
        DCD table data

Loading the desired table entry is performed by first loading the
start address of the table, then moving the immediate constant "4"
into a register, using the multiply and add instruction to calculate
the address, and finally loading the entry. However, this operation
can be performed by the barrel shifter more efficiently as follows:

    ; R0 holds the entry number [0,1,2,...]
        LDR  R1, =StartOfTable
        LDR  R2, [R1, R0, LSL #2]
        ...
    StartOfTable
        DCD table data

In this code the barrel shifter shifts R0 left 2 bits (ie. multiplying
it by 4), this intermediate value is then used as the index for the
LDR instruction. Thus a single instruction is used to perform the
whole operation. Such significant savings can frequently be made by
making good use of the barrel shifter.

## The ARM's Barrel Shifter

The ARM core contains a Barrel shifter which takes a value to be
shifted or rotated, an amount to shift or rotate by and the type of
shift or rotate. This can be used by various classes of ARM
instructions to perform comparatively complex operations in a single
instruction. On ARMs up to and including the ARM6 family, instructions
take no longer to execute by making use of the barrel shifter, unless
the amount to be shifted is specified by a register, in which case the
instruction will take an extra cycle to complete.

The barrel shifter can perform the following types of operation:

| LSL | shift left by n bits; |
| --- | ----------------------------------------------------------------------------------------------------------------------------- |
| LSR | logical shift right by n bits; |
| ASR | arithmetic shift right by n bits (the bits fed into the top end of the operand are copies of the original top (or sign) bit); |
| ROR | rotate right by n bits; |
| RRX | rotate right extended by 1 bit.  This is a 33 bit rotate, where the 33rd bit is the PSR C flag.  |

The barrel shifter can be used in several of the ARM's instruction
classes. The options available in each case are described below.

## LDR/STR

The index can be a register shifted by any 5 bit constant. It may also
be an unshifted 12 bit constant, for example:

    STR  R7, [R0], #24                                 ;Post-indexed
    LDR  R2, [R0], R4, ASR #4                          ;Post-indexed
    STR  R3, [R0, R5, LSL #3]                          ;Pre-indexed
    LDR  R6, [R0, R1, ROR #6]!                         ;Pre-indexed + Writeback

### Explanation

In all of the above instructions R0 is the base register.

In the pre-indexed instructions the offset is calculated and added to
the base. This address is used for the transfer. If writeback is
selected, then the transfer address is written back into the base
register.

In the post-indexed instructions the offset is calculated and added to
the base after the transfer. The base register is always updated by
post-indexed instructions.

## Data processing operations

The last operand (the second for binary operations, and the first for
unary operations) may be:

- an 8 bit constant rotated right through an even number of
  positions. eg.
  
        ADD R0, R1, #&C5, 10
        MOV R5, #&FC000003

- Note that in the second example the assembler is left to work out
  how to split the constant &FC000003 into an 8 bit constant and an
  even shift (in this case "#&FC000003" could be replaced by "#&FF,
  6"). See Loading constants into registers for more information.

<!-- -->

- a register (optionally) shifted or rotated either by a 5-bit
  constant or by another register. eg.
  
        ADD R0, R1, R2
        SUB R0, R1, R2, LSR #10
        CMP R1, R2, R1, ROR R5    
        MVN R3, R2, RRX

## Program status register transfer instructions

For the precise format of these instructions see the appropriate
datasheet.

## Related topics

For more examples which make good use of the barrel shifter see many
of the recipes in Exploring ARM Assembly Language.

The following cover loading constants into registers, and explain how
*armasm* can help out the assembly language programmer:

- MOV / MVN;
- LDR Rd, =numeric constant.

# Flexibility of load and store multiple

---

## About this recipe

In this recipe you learn about:

- the benefits and capabilities of the load and store multiple
  instructions;
- types of stacks supported directly by load and store multiple.

## Multiple vs single transfers

The Load and Store Multiple instructions provide a way to efficiently
move the contents of several registers to and from memory. The
advantages of using a single load or store multiple instruction over a
series of load or store single instructions are:

- Smaller code size;
- On Von Neumann architectures such as all ARMs up to the ARM6 family,
  there is only a single instruction fetch overhead, rather than many
  instruction fetches.
- On Von Neumann architectures, only one register write back cycle is
  required for a load multiple, as opposed to one for every load
  single;
- On uncached ARM processors, the first word of data transfered by a
  load or store multiple will always be a non-sequential memory cycle,
  but all subsequent words transferred can be sequential (faster)
  memory cycles.

## The register list

The registers the load and store multiple instructions transfer are
encoded into the instruction by one bit for each of the registers R0
to R15. A set bit indicates the register will be transferred, and a
clear bit indicates that it will not be transferred. Thus it is
possible to transfer any subset of the registers in a single
instruction.

The way the subset of registers to be transferred is specified is
simply by listing those registers which are to be transferred in curly
brackets eg.

    {R1, R4-R6, R8, R10}

## Increment / Decrement, Before / After

The base address for the transfer can either be incremented or
decremented between register transfers, and this can happen either
before or after each register transfer. eg.

    STMIA R10, {R1, R3-R5, R8}

The suffix IA could also have been IB, DA or DB, where I indicates
increment, D decrement, A after and B before.

## Base register writeback

In the last instruction, although the address of the transfer was
changed after each transfer, the base register was not updated at any
point. Register writeback can be specified so that the base register
is updated. Clearly the base register will change by the same amount
whether "before" or "after" is selected. An example of a load multiple
using base writeback is:

    LDMDB R11!, {R9, R4-R7}

### Note

In all cases the lowest numbered register is transferred to or from
the lowest memory address, and the highest numbered register to or
from the highest address. \[The order in which the registers are
listed in the register list makes no difference. Also, the ARM always
performs sequential memory accesses in increasing memory address
order. Therefore 'decrementing' transfers actually perform a
subtraction first and then increment the transfer address register by
register\].

## Stack notation

Since the load and store multiple instructions have the facility to
update the base register (which for stack operations can be the stack
pointer), these instructions provide single instruction push and pop
operations for any number of registers. Load multiple being pop, and
store multiple being push.

There are several types of stack which the Load and Store Multiple
Instructions can be used with:

- Ascending or descending stacks. ie. the stack grows up memory or
  down memory. \[Sometimes a pair of stacks, one of which grows up
  memory and one of which grows downwards are used - thus choosing the
  direction is not always just a matter of taste\].
- Empty or Full stacks. The stack pointer can either point to the top
  item in the stack (a full stack), or the next free space on the
  stack (an empty stack).

As stated above, pop and push operations for these stacks can be
implemented directly by load and store multiple instructions. To make
it easier for the programmer special stack sufficies can be added to
the LDM and STM instructions (as an alternative to Increment /
Decrement and Before / After sufficies) as follows:

    STMFA R10!, {R0-R5}   ; Push R0-R5 onto a Full Ascending Stack
    LDMFA R10!, {R0-R5}   ; Pop  R0-R5 from a Full Ascending Stack
    
    STMFD R10!, {R0-R5}   ; Push R0-R5 onto a Full Descending Stack
    LDMFD R10!, {R0-R5}   ; Pop  R0-R5 from a Full Descending Stack
    
    STMEA R10!, {R0-R5}   ; Push R0-R5 onto an Empty Ascending Stack
    LDMEA R10!, {R0-R5}   ; Pop  R0-R5 from an Empty Ascending Stack
    
    STMED R10!, {R0-R5}   ; Push R0-R5 onto an Empty Descending Stack
    LDMED R10!, {R0-R5}   ; Pop  R0-R5 from an Empty Descending Stack

## Related topics

For more information on using stacks in assembly language see Stacks
in assembly language.

For further discussion of some of the benefits which can be gained by
using LDM and STM see Loop unrolling.

# Loading constants into registers

---

## About this recipe

This recipe explains and demonstrates:

- Why loading constants / addresses is an issue on the ARM;
- How to solve it using MOV / MVN;
- How to solve it using LDR Rd, =**expression**
- How to solve it using ADR and ADRL

## Why is loading constants an issue?

Since all ARM instructions are precisely 32 bits long, and ARM
instructions do not use the instruction stream as data, there is no
single instruction which will load any 32 bit immediate constant into
a register without performing a data load from memory.

However, there are ways to load many commonly used constants into a
register without resorting to a data load from memory. Of course, a
data load from memory allows any 32-bit value to be loaded into a
register, but the added expense of a data load can often be avoided.

The assembler provides several 'instruction extensions', and two
pseudo instructions to make the efficient loading of constants and
addresses non-painful.

## MOV / MVN

As described in the recipe Using the Barrel Shifter, the MOV and MVN
instructions allow many constants to be constructed. The constants
which these instructions can construct must be eight bit constants
rotated right through an even number of positions. By using MVN the
bitwise complement of such values can also be constructed.

Having to convert a constant into this form is an onerous task no-one
wants to do. Therefore **armasm** will do this automatically. Either
MOV or MVN may be used with a constant which can be constructed using
either of these instructions. **armasm** will choose the correct
instruction and construct the constant. If it is impossible to
construct the desired constant **armasm** will report this as an
error.

To illustrate this, look at the following MOV and MVN
instructions. The instruction listed in the comment is the ARM
instruction which is produced by **armasm**.

    MOV R0, #0                                 ; => MOV R0, #0
    MOV R1, #&FF000000                         ; => MOV R1, #&FF, 8 
    MOV R2, #&FFFFFFFF                         ; => MVN R2, #0
    MVN R0, #1                                 ; => MVN R0, #1
    MOV R1, #&FC000003                         ; => MOV R1, #&FF, 6
    MOV R2, #&03FFFFFC                         ; => MVN R2, #&FF, 6
    MOV R3, #&55555555                         ; Reports an error--cannot 
    be constructed

## Assembling the example

The above code is available in **loadcon1.s** in the **examples**
directory. To assemble it first set the current directory to
**examples** and then issue the command:

    armasm loadcon1.s -o loadcon1.o -li

To confirm that **armasm** produced the correct code, the code area
can be disassembled by looking at the output from:

    decaof -c loadcon1.o

### Explanation

The -li argument can be omitted if the tools have been configured
appropriately.

**decaof** is the ARM Object Format decoder. The -c option requests
that decaof dissassemble the code area.

## LDR Rd, =numeric constant

**armasm** provides a mechanism which unlike MOV and MVN can construct
any 32-bit numeric constant, but which may not result in a data
processing operation to do it. This is the "LDR Rd, =" mechanism.

If the numeric constant can be constructed by using either MOV or MVN,
then this will be the instruction used to load the constant. If this
cannot be done, however, **armasm** will produce an LDR instruction to
read the constant from a literal pool.

## Literal pools

A literal pool is a portion of memory set aside for constants. By
default a literal pool is placed right at the end of the
program. However, for large programs, this literal pool may not be
accessible throughout the program (due to the LDR offset being a 12
bit value), so further literal pools can be placed using the LTORG
directive.

When the "LDR, Rd, =" mechanism needs to access a literal in a literal
pool, **armasm** first checks previously encountered literal pools to
see if the desired constant is already available and addressable. If
it is then this literal is addressed, otherwise **armasm** will
attempt to place the literal in the next available literal pool. If
this literal pool is not addressable then an error will result, and an
additional LTORG should be placed close to (but after) the failed "LDR
Rd,=" instruction.

Although this may sound somewhat complicated, in practice, it is
simple to use. Consider the following example, which demonstrates how
literal pools and "LDR Rd,=" work. The instruction listed in the
comment is the ARM instruction which gets produced by **armasm**.

      AREA Example, CODE, REL
    
      LDR R0, =42                  ;=> MOV R0, #42
      LDR R1, =&55555555           ;=> LDR R1, [PC, #offset to Literal Pool 1]
      LDR R2, =&FFFFFFFF           ; => MVN R2, #0
    
      LTORG                        ; Literal Pool 1 contains literal &55555555
    
      LDR R3, =&55555555           ; => LDR R3, [PC, #offset to Literal Pool 1]
    ; LDR R4, =&66666666           ; If this is uncommented it fails, Literal
                                   ; Pool 2 is not accessible (out of reach)
    
    LargeTable2 % 4200
    
      END                          ; Literal Pool 2 is empty

## Assembling the example

The above code is available in **loadcon2.s** in the **examples**
directory. To assemble it first set the current directory to
**examples** and then issue the command:

    armasm loadcon2.s -o loadcon2.o -li

To confirm that **armasm** produced the correct code, the code area
can be disassembled by looking at the output from:

    decaof -c loadcon2.o

### Explanation

The -li argument can be omitted if the tools have been configured
appropriately.

**decaof** is the ARM Object Format decoder. The -c option requests
that decaof dissassemble the code area.

## LDR Rd, =PC relative expression

As well as numeric constants, the "LDR Rd, =" mechanism can cope with
PC relative expressions, such as labels.

Even if a PC relative ADD or SUB could be constructed, an LDR will be
generated to load the PC relative expression. Thus if a PC relative
ADD or SUB is desired then ADR should be used instead (see ADR and
ADRL). If no suitable literal is already available, then the literal
placed into the next literal pool will be the offset into the AREA,
and an AREA relative relocation directive will be added to ensure that
the constant is appropriate wherever the containing AREA gets located
by the linker. See [The handling of relocation
directives](../arrfldr/3arre.html#XREF31016) for more information
about relocation directives.

As an example consider the code below. The instruction listed in the
comment is the ARM instruction which gets produced by **armasm**.

      AREA Example, CODE, REL
    
    Start
      LDR R0, =StartLiteral                  ;=> LDR R0, PC, #offset to Litpool 1
      LDR R1, =DataArea + 12                 ; => LDR R1, [PC, #offset to Litpool 1
      LDR R2, =DataArea + 6000               ; => LDR R2, [PC, #offset to Litpool 1
    
      LTORG                                  ; Literal Pool 1 holds three literals
    
      LDR R3, =DataArea + 6000               ; => LDR R2, [PC, #offset to Litpool 1
                                             ; (sharing with previous literal)
    ; LDR R4, =DataArea + 6004               ; If uncommented will produce an error
                                             ; as Litpool 2 is out of range
    
    DataArea % 8000
    
      END                                    ; Literal Pool 2 is out of range of
                                             ; the LDR instructions above

## Assembling the example

The above code is available in **loadcon3.s** in the **examples**
directory. To assemble it first set the current directory to
**examples** and then issue the command:

    armasm loadcon3.s -o loadcon3.o -li

To confirm that **armasm** produced the correct code, the code area
can be disassembled by looking at the output from:

    decaof -c loadcon3.o

### Explanation

The -li argument can be omitted if the tools have been configured
appropriately.

**decaof** is the ARM Object Format decoder. The -c option requests
that decaof dissassemble the code area.

## ADR and ADRL

Sometimes it is important for efficiency purposes that loading an
address does not perform a memory access. The assembler provides two
pseudo instructions which make it easier to do this.

Whereas MOV and MVN only accept numeric constants, ADR and ADRL accept
numeric constants, PC relative expressions (labels within the same
area) and register relative expressions.

ADR will attempt to produce a single data processing instruction to
load an address into a register. This instruction will be one of MOV,
MVN, ADD or SUB, in the same way as the "LDR Rd, =" mechanism produces
instructions. If the desired address cannot be constructed in a single
instruction an error will be produced.

ADRL will attempt to produce either two data processing instructions
to load an address into a register. Even if it is possible to produce
a single data processing instruction to load the address into the
register then a second, redundant instruction will be produced (this
is a consequence of the strict two-pass nature of **armasm**) . In
cases where it is not possible to construct the address using two data
processing instructions ADRL will produce an error - the LDR, =
mechanism is probably the best option in this case.

As an example consider the code below. The instructions listed in the
comments are the ARM instruction which are produced by **armasm**.

      AREA Example, CODE, REL
    
    Start
      ADR  R0, &8000                      ; => MOV R0, #&8000
    ; ADR  R1, &8001                      ; This would fail as it cannot be
                                          ; constructed by a MOV or MVN
      ADR  R2, Start                      ; => SUB R2, PC, #offset to Start
      ADR  R3, DataArea                   ; => ADD R3, PC, #offset to DataArea
    ; ADR  R4, DataArea+4300              ; This would fail as the offset cannot
                                          ; be expressed by operand2 of an ADD
      ADRL R5, DataArea+4300              ; => ADD R5, PC, #offset1
                                          ;    ADD R5, R5, #offset2
      ADRL R6, &8001                      ; => MOV R6, #1
                                          ;    ADD R6, R6, #&8000
    ; ADRL R7, &55555555                  ; This would fail--the constant can't
                                          ; be constructed by 2 data processing
                                          ; instructions
    DataArea % 8000
    
      END

## Assembling the example

The above code is available in **loadcon4.s** in the **examples**
directory. To assemble it first set the current directory to
**examples** and then issue the command:

    armasm loadcon4.s -o loadcon4.o -li

To confirm that **armasm** produced the correct code, the code area
can be disassembled by looking at the output from:

    decaof -c loadcon4.o

### Explanation

The -li argument can be omitted if the tools have been configured
appropriately.

**decaof** is the ARM Object Format decoder. The -c option requests
that decaof dissassemble the code area.

## Related topics

For more information on the capabilities of the barrel shifter see
[Using the Barrel Shifter.

# Integer to string conversion

---

## About this recipe

This recipe shows you:

- how to convert an integer to a string in ARM assembly language;
- how to use a stack in an ARM assembly language program;
- how to write a recursive function in ARM assembly language.

This recipe refers to the program **utoa1.s** in the **examples**
directory. Its **dtoa** entry point converts a signed integer to a
string of decimal digits (possibly with a leading '-''); its **utoa**
entry point converts an unsigned integer to a string of decimal
digits.

## The algorithm

To convert a signed integer to a decimal string: generate a '-' and
negate the number if it is negative; then convert the remaining
unsigned value.

To convert a given unsigned integer to a decimal string, divide it by
10, yielding a quotient and a remainder. The remainder is in the range
0-9 and is used to create the last digit of the decimal
representation. If the quotient is non-zero it is dealt with in the
same way as the original number, creating the leading digits of the
decimal representation; otherwise the process has finished.

## The implementation

The implementation of **utoa** sketched below employs the register
naming and usage conventions of the **ARM Procedure Call Standard**:
a1-a4 are argument or scratch registers and a1 is the function result
register; v1-v5 are 'variable' registers (preserved across function
calls); sp is the stack pointer; at routine entry, lr holds the
subroutine call return address; and pc is the program counter.

    utoa
    STMFD  sp!, {v1, v2, lr}                ;function entry - save some v-registers
                                            ;and the return address.
      MOV    v1, a1                         ; preserve arguments over following
      MOV    v2, a2                         ; function calls
    
      MOV    a1, a2
      BL     udiv10                         ; a1 = a1 / 10
    
      SUB    v2, v2, a1, LSL #3             ; number - 8*quotient
      SUB    v2, v2, a1, LSL #1             ;  - 2*quotient = remainder
    
      CMP    a1, #0                         ; quotient non-zero?
      MOVNE  a2, a1                         ; quotient to a2...
      MOV    a1, v1                         ; buffer pointer unconditionally to a1
      BLNE   utoa                           ; conditional recursive call to utoa
    
      ADD    v2, v2, #'0'                   ; final digit
      STRB   v2, [a1], #1                   ; store digit at end of buffer
    
      LDMFD  sp!, {v1, v2, pc}              ; function exit - restore and return

### Explanation

On entry, a2 contains the unsigned integer to be converted and a1
addresses a buffer to hold the character representation of it.

On exit, a1 points immediately after the last digit written.

Both the buffer pointer and the original number have to be saved
across the call to **udiv10**. This could be done by saving the values
to memory. However, it turns out to be more efficient to use two
'variable' registers, v1 and v2 (which, in turn, have to be saved to
memory).

(An instructive exercise for the reader is to rework this example with
a1 and a2 saved to memory in the initial STMFD, rather than v1 and
v2).

Because utoa calls other functions (**udiv10** and **utoa**) it must
save its return link address passed in lr. The function therefore
begins by stacking v1, v2 and lr using STMFD sp!, {v1,v2,lr}.

In the next block of code, a1 and a2 are saved (across the call to
**udiv10**) in v1 and v2 respectively and the given number (a2) is
moved to the first argument register (a1) before calling **udiv10**
with a BL (Branch with Link) instruction.

On return from **udiv10**, 10 times the quotient is subtracted from
the original number (preserved in v2) by two SUB instructions. The
remainder (in v2) is ready to be converted to character form (by
adding ASCII '0') and to be stored into the output buffer.

But first, **utoa** has to be called to convert the quotient, unless
that is zero. The next four instructions do this, comparing the
quotient (in a1) with 0, moving the quotient to the second argument
register (a2) if not zero, moving the buffer pointer to the first
argument/result register (a1), and calling **utoa** if the quotient is
not zero.

Note that the buffer pointer is moved to a1 unconditionally: if
**utoa** is called recursively then a1 will be updated, but it will
still identify the next free buffer location; if **utoa** is not
called recursively, the next free buffer location is still needed in
a1 by the following code which plants the remainder digit and returns
the updated buffer location (via a1).

The remainder (in a2) is converted to character form by adding '0' and
is then stored in the location addressed by a1. A post-incrementing
STRB is used which stores the character and increments the buffer
pointer in a single instruction, leaving the result value in the
result register a1.

Finally, the function is exited by restoring the saved values of v1
and v2 from the stack, loading the stacked link address into pc and
popping the stack using a single multiple load instruction LDMFD sp!,
{v1,v2,pc}.

## Creating a runnable example

You can run the **utoa** routine described here under **armsd**. To do
this, you must assemble the example and the udiv10 function, compile a
simple test harness written in C, and link the resulting objects
together to create a runnable program.

Begin by setting your current directory to the **examples** directory
then use the following commands:

    armasm utoa1.s -o utoa1.o -li
    armasm udiv10.s -o udiv10.o -li 
    armcc -c utoatest.c -apcs 3/32bit
    armlink -o utoatest utoa1.o udiv10.o utoatest.o somewhere/armlib.321

where **somewhere** is the directory in which armlib.32l can be found.

### Explanation

The first two **armasm** commands assemble the **utoa** function and
the **udiv10** function, creating relocatable object files **utoa1.o**
and **udiv10.o**. The -li flag tells **armasm** to assemble for a
little-endian memory. You can omit this flag if your **armasm** has
been configured for this default.

The **armcc** command compiles the test harness. The -c flag tells
**armcc** not to link its output with the C library; the -li flag
tells **armcc** to compile for a little-endian memory (as with
**armasm**).

The **armlink** command links your three relocatable objects with the
ARM C library to create a runnable program (here called **utoatest**).

If you have installed your ARM development tools in a standard way
then you could use the following shorter command to do the compilation
and linking:

    armcc utoatest.c utoa1.o udiv10.o -apcs 3/32bit -li

## Running the example

You can run your example program under **armsd** using:

    armsd -li utoatest

Note that the -li and -apcs 3/32bit options can be omitted if the
tools have been configured appropriately.

## Stacks in assembly language

In this example, three words are pushed on to the stack on entry to
**utoa** and popped off again on exit. By convention, ARM software
uses r13, usually called sp, as a stack pointer pointing to the
last-used word of a downward growing stack (a so-called 'full,
descending' stack). However, this is only a convention and the ARM
instruction set supports equally all four stacking possibilities:
{full or empty} x {ascending or descending}.

The instruction used to push values on the stack was:

    STMFD  sp!, {v1, v2, lr}

The action of this instruction is as follows:

- subtract 4 \* number-of-registers from sp;
- store the registers named in {...} in ascending register number
  order to memory at \[sp\], \[sp,4\], \[sp,8\] ...

The matching pop instruction was:

    LDMFD  sp!, {v1, v2, pc}

Its action is:

- load the registers named in {...} in ascending register number order
  from memory at \[sp\], \[sp,4\], \[sp,8\] ...
- add 4 \* number-of-registers to sp.

### Discussion

Many, if not most, register-save requirements in simple assembly
language programs can be met using this approach to stacks.

A more complete treatment of run-time stacks requires a discussion of:

- stack-limit checking (and extension);
- local variables and stack frames.

In the **utoa** program, you must assume the stack is big enough to
deal with the maximum depth of recursion, as no one bothers to check
this. In practice, this assumption is OK. The biggest 32-bit unsigned
integer is about four billion, or ten decimal digits. This means that
at most 10 x 3 registers = 120 bytes have to be stacked. Because the
ARM Procedure Call Standard (APCS) guarantees that there are at least
256 bytes of stack available when a function is called and because we
can guess (or know) that **udiv10** uses no stack space, we can be
confident that **utoa** is quite safe if called by an APCS-conforming
caller such as a compiled-C test harness.

This discussion raises another delicacy. The stacking technique
illustrated here conforms to the ARM Procedure Call Standard only if
the function using it makes no function calls. **utoa** calls both
**udiv10** and itself; it really ought to establish a proper stack
frame (see [ARM Procedure Call
Standard](../atsfldr/ats4frst.html#XREF28151)). If you really want to
be safe and write functions that can 'plug and play together' you have
to follow the APCS exactly.

However, when writing a whole program in assembly language you often
know much more than when writing a program fragment for general,
robust service. This allows you to gently break the APCS in the
following way:

- Any chain of function/subroutine calls can be considered compatible
  with the APCS provided it uses less than 256 bytes of stack space.

So the **utoa** example is compatible with the APCS even though it
doesn't conform to the APCS.

Note however: if you call any function whose stack use is unknown (but
which is believed to be APCS conforming), you court disaster unless
you establish a proper APCS call frame and perform APCS stack limit
checking on function entry. Please refer to [ARM Procedure Call
Standard](../atsfldr/ats4frst.html#XREF28151) for further details.

## Related topics

For more information about stacks, and conforming to the ARM Procedure
Call Standard see:

- Flexibility of load and store multiple;
- Interfacing Assembly Language and C;
- Stack overflow checking.

# Multiply by a constant

---

## About this recipe

This recipe shows you how to construct a sequence of ARM instructions
to multiply by a constant.

For some applications multiply is used extensively, so it is important
to make the application run as fast as possible. For instance, most
DSP (Digital Signal Processing) applications perform a lot of
multiplication.

In many cases where a multiply is used, one of the values is a
constant (eg. weeks\*7). A naive programmer would assume that the only
way to calculate this would be to use the MUL instruction - but there
is an alternative...

This recipe demonstrates how to improve the speed of
multiply-by-constant by using a sequence of arithmetic instructions
instead of the general-purpose multiplier.

## Introduction

Throughout this recipe, registers are referred to using register names
(eg. Rd, Rm, Rs), but you should use only register names which have
been declared using the RN directive (eg. a1, r4 etc.) in assembler
source code. This recipe does not refer to any example programs; it
should be viewed as an explanation of the multiply-by-constant
technique.

MUL has the following syntax:

    MUL    Rd, Rm, Rs

The timing of this instruction depends on the value in Rs. The ARM6
datasheet specifies that for Rs between 2^(2m-3) and 2^(2m-1)-1
inclusive takes 1S + mI cycles. For more details on the multiplier,
see ARM6 multiplier performance issues. There is, of course, no
guarantee that MUL will not be implemented differently (possibly
faster) in the future...

When multiplying by a constant value, it is possible to replace the
general multiply with a fixed sequence of adds and subtracts which
have the same effect. For instance, multiply by 5 could be achieved
using a single instruction:

    ADD    Rd, Rm, Rm, LSL #2                 ; Rd = Rm + (Rm * 4) = Rm * 5

This ADD version is obviously better than the MUL version below:

        MOV    Rs, #5
        MUL    Rd, Rm, Rs

The 'cost' of the general multiply includes the instructions needed to
load the constant into a register (up to 4 may be needed, or an LDR
from a literal pool) as well as the multiply itself.

## The problem of finding the optimum sequence

The difficulty in using a sequence of arithmetic instructions is that
the constant must be decomposed into a set of operations which can be
done by one instruction each. Consider multiply by 105:

This could be achieved by decomposing thus:

        105 == 128 - 13
            == 128 - 16 + 3
            == 128 - 16 + 2 + 1
    
        ADD    Rd, Rm, Rm, LSL #1                        ; Rd = Rm*3
        SUB    Rd, Rd, Rm, LSL #4                        ; Rd = Rm*3 - Rm*16
        ADD    Rd, Rd, Rm, LSL #7                        ; Rd = Rm*3 - Rm*16 + Rm*128

Or, decomposing differently:

        105 == 15 * 7
            == (16 - 1) * (8 - 1)
    
        RSB    Rt, Rm, Rm, LSL #4                        ; Rt = Rm*15 (tmp reg)
        RSB    Rd, Rt, Rt, LSL #3                        ; Rd = Rt*7 = Rm*105

The second method is the optimal solution (fairly easy to find for
small values such as 105). However, the problem of finding the optimum
becomes much more difficult for larger constant values. A program can
be written to search exhaustively for the optimum, but it may take a
long time to execute. There are no known algorithms which solve this
problem quickly.

Temporary registers can be used to store intermediate results to help
achieve the shortest sequence. For a large constant, more than one
temporary may be needed, otherwise the sequence will be longer.

The C-compiler restricts the amount of searching it performs in order
to minimise the impact on compilation time. The current version of
armcc has a cut-off so that it uses a normal MUL if the number of
instructions used in the multiply-by-constant sequence exceeds some
number N. This is to avoid the sequence becoming too long.

## Experimenting with armcc assembly output

When writing a speed-critical ARM assembler program, it is a good idea
to code it in C first (to check the algorithm) before converting it to
hand tuned assembler. It is helpful to see the ARM code which the
compiler generates as a starting point for your work.

Invoking **armcc** with the -S flag will generate an assembly file
instead of an object file. For example, consider the following simple
C code:

    int mulby105( int num )
    {
        return num * 105;
    }

Compile this using:

    armcc -li -S mulby105.c

Now, examine the file **mulby105.s** which has been created:

    ; generated by Norcroft ARM C vsn 4.41 (Advanced RISC Machines)
        AREA |C$$code|, CODE, READONLY
    |x$codeseg|
    
        EXPORT  mulby105
    mulby105
        RSB    a1,a1,a1,LSL #4
        RSB    a1,a1,a1,LSL #3
        MOV    pc,lr
    
        AREA |C$$data|,DATA
    
    |x$dataseg|
    
        END

Notice that the compiler has found the short multiply-by-constant
sequence.

## Discussion of speed improvement

To evaluate the speed gains from using multiply-by-constant, consider
multiplying by 11585 (which is 8192\*sqr2) as an example:

A normal multiply consists of:

        MOV    Rs, #0x2D << 8                       ; load constant
        ORR    Rs, Rs, #0x41                        ; load constant, now Rs = 11585
        MUL    Rd, Rm, Rs                           ; do the multiply

The load-a-constant stage may take up to four 4 instructions (in this
case 2) or an LDR,= and the multiply takes 1 instruction fetch plus a
number of internal cycles to calculate the multiply (on ARM6 based
processors) .

The optimal multiply-by-constant sequence consists of:

        ADD    Rd, Rm, Rm, LSL #1                        ; Rd = Rm*3
        RSB    Rd, Rd, Rd, LSL #4                        ; Rd = Rd*15 = Rm*45
        ADD    Rd, Rm, Rd, LSL #8                        ; Rd = Rm + Rd*256 = Rm*11521
        ADD    Rd, Rd, Rm, LSL #6                        ; Rd = Rd + Rm*64 = Rm*11585

This is just 4 data processing instructions.

| Method | Cycles | |
| -------------------- | ----------------------------- | ------ |
| Normal multiply | 3 instructions + MUL internal | cycles |
| Multiply-by-constant | 4 instructions | |

Considering the ARM6 family, the 2-bit Booth's Multiplier used by MUL
takes a number of I-cycles depending on the value in Rs (in this case
m=8, as Rs lies between 8192 and 32767).

Hence multiply-by-constant looks to be the winner in this case.

An instruction fetch is an external memory S-cycle on the ARM60, or a
cache F-cycle (if there is a cache hit) on cached processors like the
ARM610.

With slow memory systems and non-cached processors, I-cycles can be
much faster than other cycles because they are internal to the ARM
core. This means that the general multiply can sometimes be the
fastest option (for large constants where an efficient solution cannot
be found)- it should also use less memory. If the load-a-constant
stage could be moved outside a loop, the balance would tip further in
favour of the general multiply as there is only the MUL to execute.

| Method | Cycles on ARM60 | Cycles on ARM610 |
| ----------------- | --------------- | ---------------- |
| Normal multiply | 3S + 8I | 11F |
| Multiply-by-const | 4S | 4F ant |

## Related topics

- Digital signal processing on the ARM;
- ARM6 multiplier performance issues;
- Multiplication - Returning a 64-bit result;
- ARM assembly programming performance issues.

# Division by a constant

---

## About this recipe

This recipe shows you:

- how to improve on the general divide code for the case when the
  divisor is a constant.
- the simple case for divide-by-2^n using the barrel shifter.
- how to use **divc.c** to generate ARM code for divide-by-constant.

## Introduction

The ARM instruction set was designed following a RISC philosophy. One
of the consequences of this is that the ARM core has no divide
instruction, so divides must be performed using a subroutine. This
means that divide can be quite slow, but this is not a major issue as
divide performance is rarely critical for applications.

It is possible to do better than the general divide in the special
case when the divisor is a constant. This recipe explains how the
divide-by-constant technique works, and how to generate ARM assembler
code for divide-by-constant.

## Special case for divide-by-2^n

In the special case when dividing by 2^n, a simple right shift is all
that is required (instead of a left shift which multiplies by a power
of 2).

There is a small caveat which concerns the handling of signed and
unsigned numbers. For signed numbers, an arithmetic right shift is
required as this performs sign extension (to handle negative numbers
correctly). In contrast, unsigned numbers require a 0-filled logical
shift right. Please refer to an ARM datasheet for more details of the
difference between arithmetic and logical shifts.

        MOV    a2, a1, lsr #5;            unsigned division by 32
        MOV    a2, a1, asr #10;           signed division by 1024

## Explanation of divide-by-constant ARM code

The divide-by-constant technique basically does a multiply in place of
the divide, but it is somewhat more complicated than
multiply-by-constant (see Multiply by a constant):

    x/y == x * (1/y)
               ^^^^^

consider the underlined portion as a 0.32 fixed-point number
(truncating any bits past the most significant 32). 0.32 means 0 bits
before the decimal point and 32 after it.

        == (x * (2^32/y)) / 2^32
                ^^^^^^^^

the underlined portion here is a 32.0 bit fixed-point number

        == (x * (2^32/y)) >> 32

This is effectively returning the top 32-bits of the 64-bit product of
x and (2^32/y).

If y is a constant, then (2^32/y) is obviously also a constant.

For certain y, the reciprocal (2^32/y) is a repeating pattern in
binary:

       2      10000000000000000000000000000000    #
       3      01010101010101010101010101010101    *
       4      01000000000000000000000000000000    #
       5      00110011001100110011001100110011    *
       6      00101010101010101010101010101010    *
       7      00100100100100100100100100100100    *
       8      00100000000000000000000000000000    #
       9      00011100011100011100011100011100    *
      10      00011001100110011001100110011001    *
      11      00010111010001011101000101110100
      12      00010101010101010101010101010101    *
      13      00010011101100010011101100010011
      14      00010010010010010010010010010010    *
      15      00010001000100010001000100010001    *
      16      00010000000000000000000000000000    #
      17      00001111000011110000111100001111    *
      18      00001110001110001110001110001110    *
      19      00001101011110010100001101011110
      20      00001100110011001100110011001100    *
      21      00001100001100001100001100001100    *
      22      00001011101000101110100010111010
      23      00001011001000010110010000101100
      24      00001010101010101010101010101010    *
      25      00001010001111010111000010100011

The lines marked with a '#' are the special cases 2^n, which have
already been dealt with. The lines marked with a '\*' have a simple
repeating pattern.

Note how regular the patterns are for y=2^n+2^m or y=2^n-2^m (for
n\>m)...

| n | m | (2^n+2^m) | n | m | (2^n-2^m) |
| --- | --- | --------- | --- | --- | --------- |
| 1 | 0 | 3 | 1 | 0 | 1 |
| 2 | 0 | 5 | 2 | 1 | 2 |
| 2 | 1 | 6 | 2 | 0 | 3 |
| 3 | 0 | 9 | 3 | 2 | 4 |
| 3 | 1 | 10 | 3 | 1 | 6 |
| 3 | 2 | 12 | 3 | 0 | 7 |
| 4 | 0 | 17 | 4 | 3 | 8 |
| 4 | 1 | 18 | 4 | 2 | 12 |
| 4 | 2 | 20 | 4 | 1 | 14 |
| 4 | 3 | 24 | 4 | 0 | 15 |
| 5 | 0 | 33 | 5 | 4 | 16 |
| 5 | 1 | 34 | 5 | 3 | 24 |
| 5 | 2 | 36 | 5 | 2 | 28 |
| 5 | 3 | 40 | 5 | 1 | 30 |
| 5 | 4 | 48 | 5 | 0 | 31 |

For the repeating patterns, it is a relatively easy matter to
calculate the product by using a multiply-by-constant method.

The result can be calculated in a small number of instructions by
taking advantage of the repetition in the pattern; this corresponds to
the optimal solution in the multiply-by-constant problem (see Multiply
by a constant).

The actual multiply is slightly unusual due to the need to return the
top 32-bits of the 64-bit result. It efficient to calculate just the
top 32-bits; this can be achieved by modifying the
multiply-by-constant sequence so that the input value is shifted right
rather than left.

Consider this fragment of the divide-by-ten code (x is the input
dividend as used in the above equations):

    SUB  a1,  x,  x, lsr #2 ;a1 = x*%0.11000000000000000000000000000000
    ADD  a1, a1, a1, lsr #4 ;a1 = x*%0.11001100000000000000000000000000
    ADD  a1, a1, a1, lsr #8 ;a1 = x*%0.11001100110011000000000000000000
    ADD  a1, a1, a1, lsr #16;a1 = x*%0.11001100110011001100110011001100
    MOV  a1, a1, lsr #3     ;a1 = x*%0.00011001100110011001100110011001

The SUB calculates (for example)

    a1 = x - x/4
       = x - x*%0.01
       = x*%0.11

Hence, just 5 instructions are needed to perform the multiply.

A small problem is caused by calculating just the top 32-bits, as this
ignores any carry from the low 32-bits of the 64-bit
product. Fortunately, this can be corrected. A correct divide would
round down, so the remainder can be calculated by:

    x - (x/10)*10 = 0..9

It takes just 2 ARM instructions to perform this multiply-by-10 and
subtract, by making good use of the ARM's barrel shifter. In the case
when (x/10) is too small by 1 (if carry has been lost), the remainder
will be in the range 10..19 in which case corrections must be
applied. This test would require a compare-with-10 instruction, but
this can be combined with other operations to save an instruction (see
below).

When a lost carry is detected, both the quotient and remainder must be
fixed up (1 instruction each).

This should explain the full divide-by-10 code:

    div10
    ; takes argument in a1
    ; returns quotient in a1, remainder in a2
    ; cycles could be saved if only divide or remainder is required
        SUB    a2, a1, #10                       ; keep (x-10) for later
        SUB    a1, a1, a1, lsr #2
        ADD    a1, a1, a1, lsr #4
        ADD    a1, a1, a1, lsr #8
        ADD    a1, a1, a1, lsr #16
        MOV    a1, a1, lsr #3
        ADD    a3, a1, a1, asl #2
        SUBS   a2, a2, a3, asl #1                ; calc (x-10) - (x/10)*10
        ADDPL  a1, a1, #1                        ; fix-up quotient
        ADDMI  a2, a2, #10                       ; fix-up remainder
        MOV    pc, lr

The optimisation which eliminates the compare-with-10 instruction is
to keep (x-10) for use in the subtraction to calculate the
remainder. This means that compare-with-0 is required instead, which
is easily achieved by adding an S (to set the flags) to the SUB
opcode. This also means that the subtraction has to be undone if no
rounding error occured (which is why the ADDMI instruction is used).

## How to generate divide-by-constant sequences

For suitable numbers , the details of the divide-by-constant technique
can be avoided completely by using the **divc** program. This is
supplied in ANSI C source form which is in the **examples**
directory. Naturally, it must be compiled it in order to use it; use
your host system's C compiler, or **armcc** in which case the
executable must be run using **armsd**.

The **divc** command-line help can be obtained by running **divc**
with no arguments:

    Usage: divc <n>
    Generates optimal ARM code for divide-by-constant
    where <n> is one of (2^n-2^m) or (2^n+2^m) eg. 10
    Advanced RISC Machines [01 Jul 92]

Type "`divc 10`" to generate the ARM assembler code for
divide-by-10. The output is suitable for immediate use as an
**armasm** source file.

The routine is called 'udiv10' for unsigned divide-by-10 (for
example). It takes the unsigned argument in a1, and returns the
quotient in a1 and the remainder in a2. It conforms fully to the APCS,
but the remainder may not be available when called from C.

The range of values covered by (2^n-2^m) and (2^n+2^m) contains some
useful numbers such as 7, 10, 24, 60.

## Related topics

- Multiply by a constant;
- C Programming for deeply embedded applications for information about
  the division routines to which **armcc** generates references;

# Choosing a division implementation

---

This recipe shows you:

- how to select a divide implementation for the C-library
- how to use the fast divide routines from the examples directory
- a comparison of the speeds of the divide routines.

The ARM instruction set does not have a divide instruction. In some
applications it is important that a general purpose divide executes as
quickly as possible. This recipe shows how to choose between different
divide implementations for the ARM.

## Divide implementations in the C-library

The C-library offers a choice between two divide variants. This choice
is basically a speed vs. space tradeoff; the options are: 'unrolled'
and 'small'.

In the C-library build directory (eg. directory *semi* for the
semi-hosted library), the file *options* is used to select variants of
the C-library.

The supplied file contains the following:

    memcpy = fast
    divide = unrolled
    stdfile_redirection = off
    fp_type = module
    stack = contiguous
    backtrace = off

The default divide implementation 'unrolled' is fast, but occupies a
total of 416 bytes (55 instructions for the signed version plus 49
instructions for the unsigned version). This is an appropriate default
for most toolkit users who are interested in obtaining maximum
performance.

Alternatively you can change this file to select 'small' divide which
is more compact at 136 bytes(20 instructions for signed plus 14
instructions for unsigned) but somewhat slower as there is
considerable looping overhead.

For a comparison of the speed difference between these two routines,
consult the following table (the speed of divide is data-dependent):

### Signed division example timings

Cycle times are F-cycles on a cached ARM6 series processor excluding
call & return

| Calc | unrolled | rolled cycles | cycles |
| ------------ | -------- | ------------- | ------ |
| 0/100 | 22 | 19 | |
| 9/7 | 22 | 19 | |
| 4096/2 | 70 | 136 | |
| 1000000/3 | 99 | 240 | |
| 1000000000/1 | 148 | 370 | |

If you have a specific requirement you can modify the supplied
routines to suit your application better. For instance, you could
write an unrolled-2-times version or you could combine the signed and
unsigned versions to save more space.

## Guaranteed-performance divide routines for real-time applications

The C-library also contains two fully unwound divide routines. These
have been carefully implemented for maximum speed. They are useful
when a guaranteed performance is required, eg. for real-time feedback
control routines or DSP. The long maximum division time of the
standard C-library functions may make them unsuitable for some
real-time applications.

The supplied routines implement signed division only; it would be
possible to modify them for unsigned division if required. The
routines are described by the standard header file "*stdlib.h*" which
contains the following declarations:

### ARM real-time divide functions for guaranteed performance

    typedef struct __sdiv32by16 { int quot, rem; } __sdiv32by16;
    /* used int so that values return in regs, although 16-bit */
    typedef struct __sdiv64by32 { int rem, quot; } __sdiv64by32;
    
    __value_in_regs extern __sdiv32by16 __rt_sdiv32by16(
        int /*numer*/,
        short int /*denom*/);
    /*
     * Signed div: (16-bit quot), (16-bit rem) = (32-bit) / (16-bit)
     */
    __value_in_regs extern __sdiv64by32 __rt_sdiv64by32(
        int /*numer_h*/, unsigned int /*numer_l*/,
        int /*denom*/);
    /*
     * Signed div: (32-bit quot), (32-bit rem) = (64-bit) / (32-bit)
     */

These routines both have guaranteed performance:

108 cycles for \_\_rt_sdiv64by32 (excluding call & return)

44 cycles for \_\_rt_sdiv32by16

Currently the C-compiler does not automatically use these routines, as
the default routines have early-termination which yields good
performance for small values.

In order to use these new divide routines, you should explicitly call
the relevant function. The \_\_rt_div64by32 function is complicated by
the fact that our C-compiler does not currently support 64-bit
integers, as you have to split a 64-bit value between two 32-bit
variables.

The following example program shows how to use these routines. This
program is available as *dspdiv.c* in the *examples* directory. Once
the program has been compiled and linked, type

    armsd dspdiv 1000 3            

to calculate 1000/3

### divdsp.c source code

    #include <stdlib.h>
    #include <stdio.h>
    
    int main(int argc, char *argv[])
    {
        if (argc != 3)
            puts("needs 2 numeric args");
        else
        {
            __sdiv32by16 result;
    
            result = __rt_sdiv32by16(atoi(argv[1]), atoi(argv[2]));
    
            printf("quotient %d\n", result.quot);
            printf("remainder %d\n", result.rem);
        }
        return 0;
    }

## Summary

The standard division routine used by the C-library can be selected by
using the options file in the C-library build area. If the supplied
variants are not suitable, you can write your own.

For real-time applications, the maximum division time must be as short
as possible to ensure that the calculation can complete in time. In
this case, the functions \_\_rt_sdiv64by32 and \_\_rt_sdiv32by16 are
useful.

## Related topics

- Division by a constant;
- C Programming for deeply embedded applications for information about
  the division routines to which *armcc* generates references;

# Digital signal processing on the ARM

---

## About this recipe

This recipe is designed to explain the issues when performing digital
signal processing (DSP) on the ARM.

DSP often needs to be performed in real-time, so it is important to
achieve the highest possible throughput. In such instances, careful
speed optimisation of ARM assembly code is often necessary to achieve
the performance required.

## Introduction

DSP is finding a growing number of applications as all kinds of
signals are now processed digitally eg. Compact Disc, telephone speech
compression (GSM, G.721 etc.), PhotoCD, JPEG, MPEG...

The ARM cannot match a dedicated DSP chip for raw performance, but not
all applications require ultra-high performance. The ARM processor can
also perform other tasks; DSP chips are severely limited in their
range of functions due to their specialised architecture.

### Features of most DSP chips

- single cycle multiply-accumulate
- no-overhead loops (dedicated loop counter register is decremented in
  parallel with executing body of loop)
- address generators (with circular buffer support, and bit-reversed
  addressing)
- Harvard architecture to funnel data into multiply-accumulate

There is just one main operation which DSP chips perform very fast:
the weighted sum. This is a scalar product where each element of one
array of data is multiplied by a corresponding element in another
array, and the total is accumulated.

In any book on digital signal processing, there are hundreds of
equations using sigma notation which denotes a weighted sum. This
single operation is required for the all the major DSP functions:
correlation, autocorrelation, FIR filters, IIR filters, convolution,
DCT etc.

### Features of the ARM which are advantageous for DSP

- barrel shifter in parallel with data processing instructions;
- MUL instruction;
- auto-update load/store instructions;
- auto-update load/store multiple (quick sequential addresses).

## Examples of some DSP code on the ARM

These examples demonstrate typical DSP code. The MLA accumulates the
products in a single 32-bit register, so care must be taken to ensure
that the value will not overflow. If 1024 products are to be
accumulated, the number of bits in the result should not exceed 22
otherwise the total may overflow.

### Naive version of weighted-sum ARM code:

This is the obvious version of the weighted-sum code which uses 2 load
instructions and a MLA.

        MOV    r10, #0                                 ; initialise total
    naive_sigma_loop
        LDR    r0, [r8], #4                            ; load data A & update pointer
        LDR    r1, [r9], #4                            ; load data B & update pointer
        MLA    r10, r0, r1, r10
        SUBS   r11, r11, #1                            ; decrement counter
        BNE    naive_sigma_loop

### Faster version of weighted-sum ARM code:

This shows how to unwind the loop 4 times (to lower the branch
overhead). Load-multiple (LDM) is used instead of a single register
load; this improves performance significantly. It is possible to use
more registers and unwind the loop more.

        MOV    r10, #0                         ; initialise total
    faster_sigma_loop
        LDMIA  r8!, {r0-r3}                    ; load 4 data A values & update pointer
        LDMIA  r9!, {r4-r7}                    ; load 4 data B values & update pointer
        MLA    r10, r0, r4, r10
        MLA    r10, r1, r5, r10
        MLA    r10, r2, r6, r10
        MLA    r10, r3, r7, r10
        SUBS   r11, r11, #1                    ; decrement counter
        BNE    faster_sigma_loop

### Cross-correlation:

This example performs cross-correlation; this particular code was
written for a telephone-quality speech compressor. It demonstrates
careful optimisation for this specific function; there are 10 MLA
instructions to every 1 LDM instruction. All the registers (apart from
r15) are used in order to reduce load operations.

Cross-correlation involves multiplying every element of one list with
the corresponding element in another list and accumulating the total
(a weighted sum). To calculate the cross-correlation function, the
offset is varied as in this example:

         i1   i2   i3   i4
          *    *    *    *                             = cross_corr_0
         j1   j2   j3   j4   j5   j6   j7   j8   j9
    
              i1   i2   i3   i4
               *    *    *    *                        = cross_corr_1
         j1   j2   j3   j4   j5   j6   j7   j8   j9
    
         and so on until:
                                  i1   i2   i3   i4
                                   *    *    *    *    = cross_corr_5
         j1   j2   j3   j4   j5   j6   j7   j8   j9

Notice that 'i' has 4 elements and 'j' has 9 elements, so the
cross_corr list has (9-4+1)=6 elements.

The routine given here is designed to process 4 elements from 'i' and
4 elements from 'j' per block. The block can be repeated to process
the entire 'i' list (which should be a multiple of 4). The 'i'-list
should be the smaller of the two, so that it is traversed
completely. This yields 5 totals which are cross-correlation
results. An outer loop can be used to update the start position in 'j'
in order to calculate the full cross-correlation function.

        LDMIA  r8!, {r0-r3}      ; initialise: load j1-j4              
    (1)
    
        LDMIA  r9!, {r4-r7}      ; repeating block start, load i1-i4   
    (2)
        MLA    r10, r0, r4, r10
        MLA    r10, r1, r5, r10
        MLA    r10, r2, r6, r10
        MLA    r10, r3, r7, r10
        MLA    r11, r1, r4, r11
        MLA    r11, r2, r5, r11
        MLA    r11, r3, r6, r11
        MLA    r12, r2, r4, r12
        MLA    r12, r3, r5, r12
        MLA    r13, r3, r4, r13
        LDMIA  r8!, {r0-r3}      ; load j5-j8                          
    (3)
        MLA    r14, r0, r4, r14
        MLA    r14, r1, r5, r14
        MLA    r14, r2, r6, r14
        MLA    r14, r3, r7, r14
        MLA    r13, r0, r5, r13
        MLA    r13, r1, r6, r13
        MLA    r13, r2, r7, r13
        MLA    r12, r0, r6, r12
        MLA    r12, r1, r7, r12
        MLA    r11, r0, r7, r11  ; repeating block end
    ; repeat block in order to traverse 'i'-list

The 22-instruction block calculates 5 cross-correlation sums (in
r10-r14), according to the following diagram:

```
     i1   i2   i3   i4                         |
      *    *    *    *                         |                        Total in r10
     j1   j2   j3   j4                         | j5   j6   j7   j8
                                               |
                                               |
          i1   i2   i3                         | i4
           *    *    *                         |  *                       Total in r11
     j1   j2   j3   j4                         | j5   j6   j7   j8
                                               |
                                               |
               i1   i2                         | i3   i4
                *    *                         |  *    *                Total in r12
     j1   j2   j3   j4                         | j5   j6   j7   j8
                                               |
                                               |
                    i1                         | i2   i3   i4
                     *                         |  *    *    *           Total in r13
     j1   j2   j3   j4                         | j5   j6   j7   j8
                                               |
                                               |
                                               | i1   i2   i3   i4
                                               |  *    *    *    *      Total in r14
     j1   j2   j3   j4                         | j5   j6   j7   j8|
                                               |
     First half of                             | Second half of
     repeating block                           | repeating block
```

The clever bit is reusing r0-r3 to hold the j5-j8 values which are
loaded in (3). By arranging the MLA instructions into 2 groups (left
and right of the dividing line), it is possible to use the j1-j4
values first, and then use j5-j8 second.

At the end of the block, r0-r3 (j5-j8) are used as j1-j4 for the next
block (because the pointers have moved on by 4).

This technique could also be applied to reduce the memory load traffic
of other DSP functions.

### Fixed-point arithmetic

Fixed-point arithmetic is an important part of DSP (for example,
weighting coefficients are often in the range -1..1). The MUL
instruction is an integer multiplier, so shifting will be necessary to
justify the result correctly. Fortunately, the ARM barrel shifter
makes this very easy.

When a single MUL is being used to multiply fixed-point numbers, it
may be necessary to right-shift the multiply operands so that the
result fits in 32-bits to avoid overflow.

As you would expect, add and subtract are unaffected if the operands
are fixed-point numbers, provided that both operands are the same
fixed-point format. Naturally, the barrel shifter can be applied to
the second operand (with no overhead) if it is necessary to align the
formats.

## ARM6 multiplier performance issues

The performance of the MUL instruction is important for many DSP
applications where multiply is used extensively (eg. digital filters,
correlation etc.)

This section explains how to predict the timing of a MUL instruction,
and suggests some ideas to improve the performance of speed-critical
programs. This section is specific to the 2-bit Booth's Multiplier in
the ARM6, ARM2 and ARM3.

### Explanation of Booth's multiplication

Consider the instruction:

        MUL   Rd, Rm, Rs
                      ^^

The speed of the multiply depends on the value in Rs. It is important
to place the smallest number in Rs so that the multiply takes the
least number of cycles. The rest of this section explains how the
value in Rs affects the time taken to perform the multiplication.

In the ARM6 core, the value in Rs is transferred to the Booth's
multiplier register during the first cycle of the
instruction. Thereafter, a number of internal I-cycles are required to
perform the multiplication.

The Booth's multiplier operates in the following way: a 32-bit
multiplier register is initialised with the second operand of the
multiplication. This register is extended at the low end with an extra
bit, which is initialised to zero. So, the register's contents after
initialisation are:

      M31 M30 M29 M28 ... M5 M4 M3 M2 M1 M0 0

On each iteration, the bottom 3 bits of this register are used to
generate a Booth digit, which controls what is done on the datapath
with the destination register and the first operand register. Then
this register is shifted right by 2 bits, losing the two bits at the
right hand end. The 2 leftmost bits are filled with zeros.

Early termination occurs if and when the entire multiplier register is
all zeros, with the process terminating after 16 iterations in any
case.

So, after the first iteration the multiplier register's contents are:

      0 0 M31 M30 ... M7 M6 M5 M4 M3 M2 M1

and the Booth digit which was used on the first iteration was based on
the three bits "`M1 M0 0`".

The second Booth digit will hence be "`M3 M2 M1`".

Each Booth digit takes an I-cycle to process, as the ARM datapath is
involved in accumulating the partial product. The total time for a MUL
is thus 1S + nI cycles where n depends on the value in Rs. From the
above explanation it can be shown that n has the following
relationship to the value in Rs:

Multiplication by 2^(2n-3) and 2^(2n-1)-1 inclusive takes 1S +
nI-cycles (n\>1). (Multiplication by 0 or 1 takes 1S + 1I-cycle).

(These speeds are taken straight from the ARM6 datasheet)

### Overflow issues

It is common to use the current multiply instruction in (for instance)
a 16bit x 16bit -\> 32bit mode to avoid overflow.

This situation can be generalised, as the number of result bits is
just the sum of the operand bits. Thus, the MUL can perform 16bit x
16bit -\> 32bit, 8bit x 24bit -\> 32bit etc. all without overflow. For
MLA, the total is accumulated (overflow of the total must be
avoided). Hence, MLA would be used as (for example) 12x12-\>24 leaving
8 bits to accumulate up to 256 values without the possibility of
overflow.

So, although the worst-case multiply is 1S + 16I-cycles, in practice
it is possible to arrange for a worst case which is at most 1S +
9I-cycles (by putting the operand with the least number of bits into
Rs, so that Rs \<= 16bits), but often considerably better.

### Negative operands

The multiplier yields correct results for negative operand values, so
the sign of the operands can be ignored. For positive values of Rs, a
16x16-\>32 MUL takes at most 1S + 9I-cycles (the average should be
better than this). But, the MUL \*always\* takes 1S + 16I-cycles if Rs
is negative. Early termination cannot take place because the top bit
of Rs is a 1, so the Booth's multiplier register never contains all 0s
(the maximum-of-16 limit is reached instead).

Obviously, you could guard the multiply instruction like this:

        CMP    Rs, #0
        RSBMI  Rs, Rs, #0
        MUL    Rd, Rm, Rs
        RSBMI  Rd, Rd, #

but this does not really improve things unless Rs is very small so
that the gain exceeds the (3-instruction) overhead. It is sometimes
possible to do away with the CMP by incorporating this into another
instruction (see below).

In the special case when squaring, the result does not need to be
negated after the multiplication as it will always be positive (thus
the second RSB instruction can be eliminated).

For example, consider this critical bit of code which uses MUL to
square signed 5-bit input values. This demonstrates the importance of
ensuring that Rs is positive, as the worst-case performance is
improved to just 1S + 3I-cycles for the MUL or MLA.

    AND    r1, r8, #31                        ; extract 5-bit field of interest
    AND    r2, r9, #31                        ; extract 5-bit field of interest
    SUBS   r1, r1, r2
    RSBMI  r1, r1, #0
    MUL    r0, r1, r1

As you can see, it has been arranged to only cost 1 S-cycle (for the
RSBMI instruction) to ensure the multiply is fast.

The issue of negating the value in Rs is more complicated if MLA is
used, as it is not possible to negate the product before the
accumulate. There are two possible solutions to this:

\(1\) Negate the total

    CMP    Rs, #0
    RSBMI  Rs, Rs, #0
    RSBMI  Ra, Ra, #0
    MLA    Ra, Rm, Rs, Ra
    RSBMI  Ra, Ra, #0

\(2\) Negate the other operand

    CMP    Rs, #0
    RSBMI  Rs, Rs, #0
    RSBMI  Rm, Rm, #0
    MLA    Ra, Rm, Rs, Ra

### Multiplication by constant

This technique replaces a MUL by a sequence of arithmetic instructions
which are equivalent to multiplying by a constant. The gains depend on
the value of the constant (smaller constants are generally
faster). For more details, please see Multiply by a constant.

## Related topics

- Multiply by a constant;
- Division by a constant;
- ARM assembly programming performance issues.

# Using 16-bit data on the ARM

---

## About this recipe

This recipe covers several different approaches to 16-bit data
manipulation:

- Converting the 16-bit data to 32-bit data, and from then on treating
  it as 32-bit data.
- Converting 16-bit data into 32-bit data when loading and storing,
  but using 32-bit data within ARM's registers.
- Load 16-bit data into the top 16-bits of ARM registers, and
  processing it as 16-bit data (ie. keeping the bottom 16-bits clear
  at all times).

Useful code fragments are given which can be used to help implement
these different approaches efficiently.

## Introduction

Since the ARM is a 32-bit processor, and does not have half-word load
and store instructions in its instruction set, at first glance the ARM
may look unsuitable for processing 16-bit data.

This recipe is intended to show that the ARM is quite capable of
handling 16-bit data efficiently, and in several different ways,
depending on the what is needed for a particular application.

## How "16-bit" is my data ?

Just because data is 16-bit in size does not mean that it cannot be
considered as 32-bit data by the ARM, and thus be manipulated using
the ARM instruction set in the normal way.

Clearly any unsigned 16-bit value can be held as a 32-bit value in
which the top 16 bits are all zero. Similarly any signed 16-bit value
can be held as a 32-bit value with the top 16 bits sign extended
(ie. copied from the top bit of the 16-bit value).

The main disadvantage of storing 16-bit data as 32-bit data in this
way for ARM based systems is that it takes up twice as much space in
memory or on disk. If the amount of memory taken up by the 16-bit data
is small, then simply treating it as 32-bit data is likely to be the
easiest and most efficient technique. ie. converting the data to
32-bit format and from then on treating it as 32-bit data.

When the space taken by 16-bit data in memory or on disk is not small,
an alternative method can be used: The 16-bit data is loaded and
converted to be 32-bit data for use within the ARM, and then when
processed, can either be output as 32-bit or 16-bit data. Useful code
fragments are given to perform the necessary conversions for this
approach in section Little endian loading recipes to section Big
endian storing recipes.

An issue which may arise when 16-bit data is converted to 32-bit data
for use in the ARM and then stored back out as 16-bit data is
detecting whether the data is still 16-bit data, ie. whether it has
'overflowed' into the top 16 bits of the ARM register. Code fragments
which detect this are given in the section Detecting overflow into the
top 16 bits.

Another approach which avoids having to use explicit code to check
whether results have overflowed into the top 16-bits is to keep 16-bit
data as 16-bit data all the time, by loading it into the top half of
ARM registers, and ensuring that the bottom 16 bits are
always 0. Useful code sequences, and the issues involved when taking
this approach are described in Using ARM registers as 16-bit
registers.

## Little endian loading recipes

Code fragments in this section which transfer a single 16-bit data
item transfer it to the least significant 16 bits of an ARM
register. The *byte offset* referred to is the byte offset within a
word at the load address. eg. the address 0x4321 has a byte offset of
1.

### One data item

The following code fragment loads a 16-bit value into a register,
whether the data is byte, half-word or word aligned in memory, by
using the ARM's load byte instruction.

This code is also optimal for the common case where the 16-bit data is
half word aligned, ie. at either byte offset 0 or 2 (but the same code
is required to deal with both cases). Optimisations can be made when
it is known that the data is at at byte offset 0, and also when it is
known to be at byte offset 2 (but not when it could be at either
offset).

        LDRB   R0, [R2, #0] ;             16-bit value is loaded from the
        LDRB   R1, [R2, #1] ;             address in R2, and put in R0
        ORR    R0, R0, R1, LSL #8;        R1 is required as a
    ;   MOV    R0, R0, LSL #16;           temporary register
    ;   MOV   R0, R0, ASR #16

The two MOV instructions are only required if the 16-bit value is
signed, and it may be possible to combine the second MOV with another
data processing operation by specifying the second argument as "R0,
ASR, \#16" rather than just R0.

### One data item

If the data is aligned on a half word boundary, but not a word
boundary, ie. the byte offset is 2, then the following code fragment
can be used (which is clearly much more efficient than the general
case given above):

    LDR    R0, [R2, #-2];             16-bit data is loaded from address in
    MOV    R0, R0, LSR #16;           R2 into R0 (R2 has byte offset 2)

The "LSR" should be replaced with "ASR" if the data is signed. Note
that as in the previous example it may be possible to combine the MOV
with another data processing operation.

### One data item

If the data is on a word boundary, then the following code fragment
will load a 16-bit value (again a significant improvement over the
general case):

    LDR    R0, [R2, #0];             16-bit value is loaded from the word
    MOV    R0, R0, LSL #16;          aligned address in R2 into R0.
    MOV    R0, R0, LSR #16

As before, "LSR" should be replaced with "ASR" if the data is
signed. Also, it may be possible to combine the second MOV with
another data processing operation.

This code can be further optimised if non-word-aligned word-loads are
permitted (ie. Alignment faults are not enabled). This makes use of
the way ARM rotates data into a register for non-word-aligned
word-loads, see the appropriate ARM Datasheet for more information:

    LDR    R0, [R2, #2] ;             16-bit value is loaded from the word
    MOV    R0, R0, LSR #16;           aligned address in R2 into R0.

### Two data items

Two 16-bit values stored in one word can be loaded more efficient;y
than two separate values. The following code loads two unsigned 16-bit
data items into two registers from a word aligned address:

    LDR    R0, [R2, #0];                 2 unsigned 16-bit values are loaded
    MOV    R1, R0, LSR #16 ;             from one word of memory [R2}. The
    BIC    R0, R0, R1, LSL #16;          1st is put in R0, 2nd in R1.

The version of this for signed data is:

    LDR    R0, [R2, #0]       ; 2 signed 16-bit values are loaded
    MOV    R1, R0, ASR #16    ; from one word of memory [R2].  The
    MOV    R0, R0, LSL #16    ; 1st is put in R0, 2nd in R1.
    MOV    R0, R0, ASR #16

The address in R2 should be word aligned (byte offset 0), in which
case these code fragments load the data item in bytes 0-1 into R0, and
the data item in bytes 2-3 into R1.

## Little endian storing recipes

The code fragment in this section which transfers a single 16-bit data
item transfers it from the least significant 16 bits of an ARM
register. The byte offset referred to is the byte offset from a word
address of the store address. eg. the address 0x4321 has a byte offset
of 1.

### One data item

The following code fragment saves a 16-bit value to memory, whatever
the alignment of the data address, by using the ARM's byte saving
instructions:

       STRB   R0, [R2, #0]       ; 16-bit value is stored to the address
       MOV    R0, R0, ROR #8     ; in R2.STRB   R0, [R2, #1]
    ;  MOV    R0, R0, ROR #24

The second MOV instruction is not needed if the data is no longer
needed after the data is stored.

Unlike load operations, knowing the alignment of the destination
address does not make optimisations possible.

### Two data items

Two unsigned 16-bit values in two registers can be packed into a
single word of memory very efficiently, as the following code fragment
demonstrates:

    ORR    R3, R0, R1, LSL #16      ;Two unsigned 16-bit values
    STR    R3, [R2, #0]             ;in R0 and R1 are packed into
                                    ;the word addressed by R2
                                    ;R3 is used as a temporary register

If the values in R0 and R1 are not needed after they are saved, then
R3 need not be used as a temporary register (one of R0 or R1 can be
used instead).

The version for signed data is:

        MOV    R3, R0, LSL #16       ; Two signed 16-bit values
        MOV    R3, R3, LSR #16       ; in R0 and R1 are packed into
        ORR    R3, R3, R1, LSL #16   ; the word addressed by R2
        STR    R3, [R2, #0]          ; R3 is a temporary register

Again, if the values in R0 and R1 are not needed after they are saved,
then R3 need not be used as a temporary register (R0 can be used
instead).

## Big endian loading recipes

Code fragments in this section which transfer a single 16-bit data
item transfer it to the least significant 16 bits of an ARM
register. The *byte offset* referred to is the byte offset within a
word at the load address. eg. the address 0x4321 has a byte offset of
1.

### One data item

The following code fragment loads a 16-bit value into a register,
whether the data is byte, half-word or word aligned in memory, by
using the ARM's load byte instruction.

This code is also optimal for the common case where the 16-bit data is
half word aligned, ie. at either byte offset 0 or 2 (but the same code
is required to deal with both cases). Optimisations can be made when
it is known that the data is at at byte offset 0, and also when it is
known to be at byte offset 2 (but not when it could be at either
offset).

        LDRB   R0, [R2, #0]         ; 16-bit value is loaded from the
        LDRB   R1, [R2, #1]         ; address in R2, and put in R0
        ORR    R0, R1, R0, LSL #8   ; R1 is a temporary register
    ;   MOV    R0, R0, LSL #16
    ;   MOV    R0, R0, ASR #16

The two MOV instructions are only required if the 16-bit value is
signed, and it may be possible to combine the second MOV with another
data processing operation by specifying the second argument as "R0,
ASR, \#16" rather than just R0.

### One data item

If the data is aligned on a word boundary, then the following code
fragment can be used (which is clearly much more efficient than the
general case given above):

        LDR    R0, [R2, #0]            ; 16-bit value is loaded from the word
        MOV    R0, R0, LSR #16         ; aligned address in R2 into R0.

The "LSR" should be replaced with "ASR" if the data is signed. Note
that as in the previous example it may be possible to combine the MOV
with another data processing operation.

### One data item

If the data is aligned on a half word boundary, but not a word
boundary, ie. the byte offset is 2, then the following code fragment
can be used (again a significant improvement over the general case):

        LDR    R0, [R2, #-2]          ; 16-bit value is loaded from the
        MOV    R0, R0, LSL #16        ; address in R2 into R0.  R2 is
        MOV    R0, R0, LSR #16        ; aligned to byte offset 2

As before, "LSR" should be replaced with "ASR" if the data is
signed. Also, it may be possible to combine the second MOV with
another data processing operation.

This code can be further optimised if non-word-aligned word-loads are
permitted (ie. Alignment faults are not enabled). This makes use of
the way ARM rotates data into a register for non-word-aligned
word-loads, see the appropriate ARM Datasheet for more information:

        LDR    R0, [R2, #0]            ; 16-bit value is loaded from the
        MOV    R0, R0, LSR #16         ; address in R2 into R0.  R2 is
                                       ; aligned to byte offset 2

### Two data items

Two 16-bit values stored in one word can be loaded more efficient;y
than two separate values. The following code loads two unsigned 16-bit
data items into two registers from a word aligned address:

        LDR    R0, [R2, #0]            ; 2 unsigned 16-bit values are
        MOV    R1, R0, LSR #16         ; loaded from one word of memory
        BIC    R0, R0, R1, LSL #16     ; 1st goes in R0, the 2nd in R1.

The version of this for signed data is:

        LDR    R0, [R2, #0]            ;2 signed 16-bit values are loaded 
        MOV    R1, R0, ASR #16         ;from one word of memory (address 
        MOV    R0, R0, LSL #16         ;in R2). The first is put in R0, and 
        MOV    R0, R0, ASR #16         ;the second into R1.

## Big endian storing recipes

The code fragment in this section which transfers a single 16-bit data
item transfers it from the least significant 16 bits of an ARM
register. The byte offset referred to is the byte offset from a word
address of the store address. eg. the address 0x4321 has a byte offset
of 1.

### One data item

The following code fragment saves a 16-bit value to memory, whatever
the alignment of the data address:

        STRB   R0, [R2, #1]           ; 16-bit value is stored to the
        MOV    R0, R0, ROR #8         ; address in R2.
        STRB   R0, [R2, #0]
    ;   MOV    R0, R0, ROR #24

The second MOV instruction is not needed if the data is no longer
needed after the data is stored.

Unlike load operations, knowing the alignment of the destination
address does not make optimisations possible.

### Two data items - byte offset 0

Two unsigned 16-bit values in two registers can be packed into a
single word of memory very efficiently, as the following code fragment
demonstrates:

        ORR    R3, R0, R1, LSL #16   ; Two unsigned 16-bit values in
        STR    R3, [R2, #0]          ; R0 and R1 are packed into the
                                     ; word addressed by R2
                                     ; R3 is a temporary register

If the values in R0 and R1 are not needed after they are saved, then
R3 need not be used as a temporary register (one of R0 or R1 can be
used instead).

The version for signed data is:

        MOV    R3, R0, LSL #16        ; Two signed 16-bit values in
        MOV    R3, R3, LSR #16        ; R0 and R1 are packed into the
        ORR    R3, R3, R1, LSL #16    ; word addressed by R2.  
        STR    R3, [R2, #0]           ; R3 is a temporary register

Again, if the values in R0 and R1 are not needed after they are saved,
then R3 need not be used as a temporary register (R0 can be used
instead).

## Detecting overflow into the top 16 bits

If 16-bit data is converted to 32-bit data for use in the ARM, it may
sometimes be necessary to check explicitly whether the result of a
calculation has 'overflowed' into the top 16 bits of an ARM
register. This is likely to be necessary because the ARM does not set
its processor status flags when this happens.

The following instruction sets the Z flag if the value in R0 is a
16-bit unsigned value. R1 is used as a temporary register.

        MOVS   R1, R0, LSR #16

The following instructions set the Z flag if the value in R0 is a
valid 16-bit signed value (ie. bit 15 is the same as the sign extended
bits). R1 is used as a temporary register.

        MOVS   R1, R0, ASR #15
        CMNNE  R1, R1, #1

## Using ARM registers as 16-bit registers

Instead of holding 16-bit data as 32-bit data within the ARM it can be
held as 16-bit data. This is done by positioning it in the top 16-bits
of the ARM registers as opposed to the bottom 16 bits as has been
described so far.

The advantages of this approach are:

- Some 16-bit data load instruction sequences are shorter. The loading
  and storing sequences shown above will have to be modified, and in
  some cases shorter instruction sequences will be possible. In
  particular, handling signed data will often be more efficient, as
  the top bit does not have to be copied into the top 16 bits of the
  register. Note that it is, however, necessary to ensure that the
  bottom 16 bits are all clear.
- The ARM processor status flags will be set if the 'S' bit of a data
  processing instruction is set and overflow or carry occurs out of
  the 16-bit value. Thus explicit 'overflow' checking instructions are
  not needed.
- Pairs of signed 16-bit integers can be saved more efficiently than
  in the the previous approach, since the sign extended bits do not
  have to be cleared out before the two values are combined.

The disadvantages of this approach are:

- Instructions such as add with carry cannot be used. eg. the
  instruction
  
                      ADC    R0, R0, #0

- to increment R0 if Carry is set should be replaced by
  
                      ADDCS R0, R0, #&10000

Having to use this form of instruction reduces the chance of being
able to combine several data processing operations into one by making
use of the barrel shifter.

- Before multiplying two 16-bit values in the top half of the
  registers, the values must be shifted into the bottom half of the
  register.
- Before combining a 16-bit value with a 32-bit value, the 16-bit
  value must be shifted into the bottom half of the register. Note,
  however, that this may cost nothing if the barrel shifter can be
  used in parallel.

The recipes given above for loading and storing 16-bit data into the
bottom half of ARM registers can be easily adapted to load the data
into the top half of the registers (and ensure the bottom half is all
zero), or save the data from the top half of the registers.

## Related topics

- Using the Barrel Shifter;

# ARM600 page table generation

---

## About this recipe

This recipe tells you how to use:

- **armasm** repetitive assembly;
- **armasm** conditional assembly;
- **armasm** macros;
- **armasm** and **armlink** to produce a plain binary output file
  (containing only the bytes you describe in your source program).

This recipe refers to the program pagetab.s in the **examples**
directory. Although pagetab.s generates ARM600 page tables, it is not
the format of the page tables which is being discussed in this recipe,
but how they are generated using **armasm**. To find out more about
ARM600 page tables please refer to the ARM600 datasheet.

## Repetitive assembly

The following code fragment is taken from *pagetab.s*:

               GBLA    counter
    counter    SETA 0
    
               WHILE   counter <= 3
               L1Entry SECTION, (counter:SHL:20), 0, U_BIT+C_BIT+B_BIT, 
    SVC_RW
    counter    SETA counter+1
               WEND

### Explanation

GBLA counter declares a global numeric variable called *counter* which
is initialized to zero using the SETA directive.

The WHILE ... WEND construct is then used to repeatedly assemble the
lines between WHILE and WEND.

In this example, the loop body is assembled for counter = 0, 1, 2 and
3, but because the looping condition is checked at the top of the
loop, it is possible for code between a WHILE and a WEND never to be
assembled. For example, if *counter* were initialized to 4, the body
of the WHILE ... WEND loop would not be assembled at all.

Each time around the loop the macro *L1Entry* is called (with 5
arguments), and then *counter* is incremented.

## Macro usage and conditional assembly

The following code fragment for L1Entry is also taken from
*pagetab.s*:

    MACRO
    L1Entry $type, $addr, $dom, $ucb, $acc
    IF ($type=SECTION)
        DCD ((($addr):AND:&FFF00000):OR:(($acc):SHL:10) \
            :OR:(($dom):SHL:5):OR:($ucb):OR:($type))
        MEXIT
    ENDIF
    IF ($type=PAGE)
        DCD ((($addr):AND:&FFFFFC00):OR:(($dom):SHL:5) \
            :OR:(($ucb):AND:U_BIT):OR:$type)
    ELSE
        DCD 0 ; Invalid Level 1 Page Table Entry
    ENDIF
    MEND

Note that a backslash breaks a logical line of assembly language
across two physical lines. However, there must be no character after
the backslash on the line.

### Explanation

The macro definition is enclosed between MACRO and MEND. The first
line of the definition gives the macro's name and lists its
parameters.

The body of the macro illustrates the use of IF ... ENDIF and IF
... ELSE ... ENDIF to assemble different code conditional on a value
known at assembly-time. In this example, the controlling expressions
of the IFs involve a macro parameter (\$type) which gets its value
when the macro is called.

This macro definition also shows how the MEXIT directive can be used
to exit from processing a macro before the MEND directive is
reached. You can think of MEXIT as being like a *return* statement in
a C function.

## Assembling the page tables in plain binary format

This section tells you how to create a file containing a plain binary
image of the page tables. In other words, a file containing just the
bytes you would need to load into memory *and nothing else* by way of
symbolic information, file content descriptors, load addresses, etc.

You create a plain binary image in two steps: first you create a
relocatable object file from your source file; then you use *armlink*
to make a plain binary version of the relocatable object.

### Method

Set your current directory to that containing the *pagetab.s* program
then assemble *pagetab.s* and link *pagetab.o* as follows:

    armasm pagetab.s -o pagetab.o -li
    armlink -bin -o pagetab pagetab.o

### Explanation

As in earlier examples, the -li option tells *armasm* to assemble code
for a little-endian memory. This need not be specified if the tools
have been *configured* for little-endian operation.

The -bin option tells *armlink* to make a plain binary output file
containing nothing but the bytes you described in your source program.

Because pagetab contains no position-dependent data, you do not need
to tell *armlink* where to base its output. If there had been
position-dependent data or code, you would have had to use the -base
*address* option to tell *armlink* where to base its output and, of
course, you would only be able to use the output at that memory
address.

## Related topics

- Loading constants into registers.

# Pseudo random number generation

---

## About this recipe

This recipe describes a 32-bit pseudo random number generator
implemented efficiently in ARM Assembly Language.

## The details

It is often necessary to generate pseudo random numbers, and the most
efficient algorithms are based on shift generators with exclusive-or
feedback (rather like a cyclic redundancy check
generator). Unfortunately the sequence of a 32-bit generator needs
more than one feedback tap to be maximal length (ie. 2^32-1 cycles
before repetition), so this example uses a 33 bit register with taps
at bits 33 and 20.

The basic algorithm is newbit:=bit33 EOR bit20, shift left the 33 bit
number and put in newbit at the bottom; this operation is performed
for all the newbits needed (ie. 32 bits). The entire operation can be
coded compactly by making maximal use of the ARM's barrel shifter:

    ; enter with seed in R0 (32 bits), R1 (1 bit in least significant bit)
    ; R2 is used as a temporary register.
    ; on exit the new seed is in R0 and R1 as before
    ; Note that a seed of 0 will always produce a new seed of 0.
    ; All other values produce a maximal length sequence.
    ;
        TST    R1, R1, LSR #1                       ; top bit into Carry
        MOVS   R2, R0, RRX                          ; 33 bit rotate right
        ADC    R1, R1, R1                           ; carry into lsb of R1
        EOR    R2, R2, R0, LSL #12                  ; (involved!)
        EOR    R0, R2, R2, LSR #20                  ; (similarly involved!)

## Using this example

This random number generation code is provided as *random.s* in the
*examples* directory. It is provided as ARM Assembly Language source
which can be assembled and then linked with C modules (see recipes in
Interfacing Assembly Language and C for more information).

The C test program *randtest.c* (also in the *examples* directory) can
be used to demonstrate this. First set the *examples* directory to be
your current directory, and execute the following commands to build an
executable suitable for *armsd*:

    armasm random.s -o random.o -li
    armcc -c randtest.c -li -apcs 3/32bit
    armlink randtest.o random.o -o randtest 

Where *somewhere* is the path to the *lib* directory of the ARM
Software Development Toolkit release.

Note that in both the above commands, and the *armsd* command below,
*-li* indicates that the target ARM is little endian, and *-apcs
3/32bit* specifies that the 32 bit variant of the ARM Procedure Call
Standard should be used. These options can be omitted if the tools
have already been configured appropriately.

*armsd* can be used to run this program as follows:

    > armsd -li randtest
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file randtest
    armsd: go
    randomnumber() returned 0b3a9965
    randomnumber() returned ac0b1672
    randomnumber() returned 6762ad4f
    randomnumber() returned 1965a731
    randomnumber() returned d6c1cef4
    randomnumber() returned f78fa802
    randomnumber() returned 8147fc15
    randomnumber() returned 3f62adfc
    randomnumber() returned b56e9da8
    randomnumber() returned b36dc5e2
    Program terminated normally at PC = 0x000082c8
          0x000082c8: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    >

## Related topics

Please refer to the index for other topics of interest.

# Loading a word from an unknown alignment

---

## About this recipe

In this recipe a code sequence which loads a word from memory at any
byte alignment is described. Although loading 32-bit data from non
word aligned addresses should be avoided whenever possible, it may
sometimes be necessary.

## The details

The ARM Load and Store (single and multiple) instructions are designed
to load word aligned data. Unless there is a very good reason it is
best to avoid having to load or store word-sized data to or from non
word aligned addresses, as neither the Load or Store instruction can
do this unaided.

To deal with misaligned word fetches two words must be read and the
required data extracted from these two words. The code below performs
this operation for a little endian ARM, making good use of the barrel
shifter in the process.

    ; enter with address in R0
    ; R2 and R3 are used as temporary registers
    ; the word is loaded into R1
    ;
    
    BIC    R2, R0, #3                         ; Get word aligned address
    LDMIA  R2, {R1, R3}                       ; Get 64 bits containing data
    AND    R2, R0, #3                         ; Get offset in bytes
    MOVS   R2, R2, LSL #3                     ; Get offset in bits
    MOVNE  R1, R1, LSR R2                     ; Extract data from bottom 32 bits
    RSBNE  R2, R2, #32                        ; Get 32 - offset in bits
    ORRNE  R1, R1, R3, LSL R2                 ; Extract data from top 32 bits
                                              ; and combine with the other data

This code can easily be modified for use on a big endian ARM - the LSR
R2 and LSL R2 just have to be swapped over.

For details of what the Load and Store instructions do if used with
non word aligned addresses refer to the appropriate datasheet. Note
that non word aligned word loads are also used in .

## Related topics

Using 16-bit data on the ARM

# Byte order reversal

---

## About this recipe

This recipe gives a compact ARM Instruction Sequence to perform byte
order reversal ie. reversing the endianess of a word.

## The details

Changing the endianess of a word can be a common operation in certain
applications. For example when communicating word sized data as a
stream of bytes to a receiver of the opposite endianess.

This operation can be performed efficiently on the ARM, using just
four instructions. The word to be reversed is held in a1 both on entry
and exit of this instruction sequence. ip is used as a temporary
register (For more information about these register names see
Interfacing Assembly Language and C):

        EOR    ip, a1, a1, ror #16
        BIC    ip, ip, #&ff0000
        MOV    a1, a1, ror #8
        EOR    a1, a1, ip, lsr #8

A demonstration program which should help explain how this works has
been provided in source form in the *examples* directory. To compile
this program and run it under *armsd* first set your current directory
to be *examples* and then use the following commands:

    >armcc bytedemo.c -o bytedemo -li -apcs 3/32bit
    >armsd -li bytedemo
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little endian.
    Object program file bytedemo
    armsd: go
        ... demonstration program executes ...

Note that this program uses ANSI control codes, so should work on most
terminal types under Unix and also on the PC.

# ARM assembly programming performance issues

---

## About this recipe

This recipe outlines many performance related issues which the ARM
Assembly Language Programmer should be aware of. Many of these issues
are dealt with more fully elsewhere in the Cookbook, but are mentioned
here for completeness. This recipe is also useful background for C
programmers using **armcc**, as some of these issues can also apply to
programming in C.

## Performance issues

Not all of the issues in this recipe apply to every ARM processor
based system. However, unless otherwise stated, all issues relate to
processors based on ARM6 and ARM7, with or without cache and/or write
buffer.

### LDM / STM

Use LDM and STM instead of a sequence of LDR or STR instructions
wherever possible. This provides several benefits:

- The code is smaller (and thus will cache better on an ARM processor
  with a cache);
- An instruction fetch cycle and a register copy back cycle is saved
  for each LDR or STR eliminated;
- On an uncached ARM processor (for LDM) or an unbuffered ARM
  processor (for STM), non-sequential memory cycles can be turned into
  faster memory sequential cycles.

For a more detailed discussion of LDM and STM see Flexibility of load
and store multiple.

### Conditional execution

In many situations, branches around short pieces of code can be
avoided by using conditionally executed instructions. This reduces the
size of code and may avoid a pipeline break.

For a more detailed explanation of the Conditional Execution of ARM
Instructions see Making the most of conditional execution.

### Using the Barrel Shifter

Combining shift operations with other operations can significantly
increase the code density (and thus performance) of much ARM code. An
explanation of how to use the ARM's barrel shifter is given in Using
the Barrel Shifter.

Many other recipes also demonstrate good use of the barrel shifter.

### Addressing modes

The ARM instruction set provides a useful selection of addressing
modes, which can often be used to improve the performance of
code. eg. using LDR or STR pre- or post-indexed with a non zero offset
increments the base register and performs the data transfer. For full
details of the addressing modes available refer to the appropriate ARM
datasheet.

### Multiplication

Be aware of the time taken by the ARM multiply and multiply accumulate
instructions. Making the best use of the multiplier is discussed in
ARM6 multiplier performance issues.

When multiplying by a constant value note that using the multiply
instruction is often not the optimal solution. The issues involved are
discussed in Multiply by a constant.

### Optimise register usage

Examine your code and see if registers can be reused for another value
during parts of a long calculation which uses many registers. Doing
this will reduce the amount of 'register spillage', ie. the number of
times a value has to be reloaded or an intermediate value saved and
then reloaded.

Notice that because data processing is cheap (much can be achieved in
a single instruction), keeping a calculated result in a register for
use some considerable time later may be less efficient than
recalculating it when it is next needed. This is because it may allow
the register so freed to be used for another purpose in the meantime,
thus reducing the amount of register spillage.

For example code which takes great care to optimise register usage see
some of the examples in Digital signal processing on the ARM.

### Loop unrolling

Loop unrolling involves using more than one copy of the inner loop of
an algorithm. The following benefits may be gained by loop unrolling:

- the branch back to the beginning of the loop is executed less
  frequently;
- it may be possible to combine some of one iteration with some of the
  next iteration, and thereby significantly reduce the cost of each
  iteration.
- A common case of this is combining LDR or STR instructions from two
  or more iterations into single LDM or STM instructions. This reduces
  code size, the number of instruction fetches, and in the case of
  LDM, the number of register writeback cycles.

As an example to illustrate the issues involved in loop unrolling, let
us consider calculating the following over an array: x\[i\] = y\[i\] -
y\[i+1\]. Below is a code fragment which performs this:

        LDR    R2, [R0]                                 ; Preload y[i]
    Loop
        LDR    R3, [R0, #4]!!                           ; Load y[i+1]
        SUB    R2, R2, R3                               ; x[i] = y[i] - y[i+1]
        STR    R2, [R1], #4                             ; Store x[i]
        MOV    R2, R3                                   ; y[i+1] is the next y[i]
        CMP    R0, R4                                   ; Finished ?
        BLT    Loop  

Let us consider the number of execution cycles this will take on an
ARM6 based processor. IF stands for Instruction Fetch, WB stands for
Register Write Back, R stands for Read, and W stands for Write.

The loop will execute in the following cycles: 6 IF, 1 R, 1 WB, 1 W,
and the branch costs an additional 2 IF cycles. Therefore the total
cycle count for processing a 100 element x\[\] array is:

    799 IF (198 caused by branching), 101 R, 101 WB, 100 W (1198 cycles)
    Code size: 7 instructions

Now consider the effects of unrolling this loop:

- Branch overhead cycles

- In the above example there are 198 IF's caused by
  branching. Unrolling the loop can clearly reduce this, and the table
  below shows how progressively unrolling the loop gives reducing
  returns for the increase in code size:

| Times | IF's caused by | IF saving Unrolled | Branching |
| ----- | -------------- | ------------------ | --------- |
| 2 | 98 | 100 | |
| 3 | 66 | 134 | |
| 4 | 48 | 150 | |
| 5 | 38 | 160 | |
| 10 | 18 | 180 | |
| 100 | 0 | 198 | |

Therefore if code size is an issue of any importance, unrolling any
more than around 3 times is unlikely to pay off with regard to branch
overhead elimination.

- Combining LDR's and STR's into LDM and STM
  
  The number of LDR's or STR's which can be combined into a single LDM
  or STM is restricted by the number of available registers. In this
  instance 10 registers is the most which are likely to be
  usable. This would result in unrolling the loop 10 times for the
  above example. Another case to consider is unrolling 3 times, as
  this seems to be a good compromise for branch overhead reduction.

<!-- -->

- Other optimisations
  
  Upon examining the unrolled code below, it can be seen that it is
  only necessary to execute the MOV once per loop, thus saving another
  2 IF cycles per loop for the 3 times unrolled code, and another 9 IF
  cycles per loop for the 10 times unrolled code.

Here is the code unrolled three times and then optimised as described
above:

        LDR     R2, [R0], #4                          ; Preload y[i]
    Loop
        LDMIA   R0!, {R3-R5}                          ; Load y[i+1] to y[i+3]
        SUB     R2, R2, R3                            ; x[i]   = y[i]   - y[i+1]
        SUB     R3, R3, R4                            ; x[i+1] = y[i+1] - y[i+2]
        SUB     R4, R4, R5                            ; x[i+2] = y[i+2] - y[i+3]
        STMIA   R1!, {R2-R4}                          ; Store x[i] to x[i+2]
        MOV     R2, R5                                ; y[i+3] is the next y[i]
        CMP     R0, R6                                ; Finished ?
        BLT     Loop

Analysing how this code executes for a y\[\] array of size 100, as
described above for the unrolled code produces the following results:

    339 IF (66 caused by branching), 101 R, 34 WB, 100 W (574 cycles)
    Code size: 9 instructions
    Saving over unrolled code: 460 IF, 67 WB

Here is the code unrolled ten times and then optimised in the same
way:

        LDR     R2, [R0], #4                               ; Preload y[i]
    Loop
        LDMIA   R0!, {R3-R12}                              ; Load y[i+1] to y[i+10]
        SUB     R2,  R2,  R3                               ; x[i]   = y[i]   - y[i+1]
        SUB     R3,  R3,  R4                               ; x[i+1] = y[i+1] - y[i+2]
        SUB     R4,  R4,  R5                               ; x[i+2] = y[i+2] - y[i+3]
        SUB     R5,  R5,  R6                               ; x[i+3] = y[i+3] - y[i+4]
        SUB     R6,  R6,  R7                               ; x[i+4] = y[i+4] - y[i+5]
        SUB     R7,  R7,  R8                               ; x[i+5] = y[i+5] - y[i+6]
        SUB     R8,  R8,  R9                               ; x[i+6] = y[i+6] - y[i+7]
        SUB     R9,  R9,  R10                              ; x[i+7] = y[i+7] - y[i+8]
        SUB     R10, R10, R11                              ; x[i+8] = y[i+8] - y[i+9]
        SUB     R11, R11, R12                              ; x[i+9] = y[i+9] - y[i+10]
        STMIA   R1!, {R2-R11}                              ; Store x[i] to x[i+9]
        MOV     R2,  R12                                   ; y[i+10] is the next y[i]
        CMP     R0,  R13                                   ; Finished ?
        BLT     Loop

Analysing how this code executes for a y\[\] array of size 100,
produces the following results:

    169 IF (18 caused by branching), 101 R, 10 WB, 100 W (380 cycles)
    Code size: 16 instructions
    Saving over unrolled code: 630 IF, 91 WB

Thus for this problem, unless the extra seven instructions make the
code too large unrolling ten times is likely to be the optimum
solution.

However, loop unrolling is not always a good idea, especially when the
optimisation between one iteration and the next is small. Consider the
following loop which copies an area of memory:

    Loop
        LDMIA  R0!,{R3-R14}
        STMIA  R1!,{R3-R14}
        CMP    R0, #LimitAddress
        BNE    Loop

This could be unrolled as follows:

    Loop
        LDMIA  R0!,{R3-R14}
        STMIA  R1!,{R3-R14}
        LDMIA  R0!,{R3-R14}
        STMIA  R1!,{R3-R14}
        LDMIA  R0!,{R3-R14}
        STMIA  R1!,{R3-R14}
        LDMIA  R0!,{R3-R14}
        STMIA  R1!,{R3-R14}
        CMP    R0, #LimitAddress
        BLT    Loop

In this code the CMP and BNE will be executed only a quarter as often,
but this will give only a small saving. However, other issues should
be taken into account:

- If in the above case the amount of data to be transferred was not a
  multiple of 48, then this amount of loop unrolling will copy too
  much data. This may be catastrophic, or may merely be inefficient.
- On a cached ARM processor, the larger the inner loop, the more
  likely it is that the loop will not stay entirely in the cache. In
  this case, it is not obvious at what point the performance gain due
  to unrolling is offset by the performance loss due to cache misses,
  or the disadvantage of larger code.
- On an ARM processor with a write buffer, the loop unrolling in the
  above example is unlikely to help. If the data being copied is not
  in the cache, then every LDMIA will be stalled while the write
  buffer empties. Thus the time the CMP and BNE take is irrelevent, as
  the processor will be stalled on the following LDMIA.

Loop unrolling can be a useful technique, but be warned that it
doesn't always gain anything, and in some situations can reduce
performance - detailed analysis is often necessary.

### Write buffer stalling

On ARM processors with a write buffer, performance can be maximised by
writing code which avoids stalling due to the write buffer. For a
write buffer with 2 tags and 8 words such as the ARM610, no three STR
or STM instructions should be close together (as the third will be
stalled until the first has finished). Similarly no two STR or STM
instructions which together store more than 8 words should be close
together, as the second will be stalled until there is space in the
write buffer.

Rearranging code so that the write buffer does not cause a stall in
this way is often hard, but is frequently worth the effort, and in any
case it is always wise to be aware of this performance factor.

### 16-bit data

If possible treat 16-bit data as 32-bit data. However, if this is not
possible, then be aware that it is possible to make use of the barrel
shifter and non word-aligned LDR's in order to make working with
16-bit data more efficient than might be initially imagined. See for a
full discussion of this topic.

### 8-bit data

When processing a sequence of byte sized objects (eg. strings), the
number of loads and stores can be reduced if the data is loaded a word
at a time and then processed a byte at a time by extracting the bytes
using the barrel shifter.

### The floating point emulator

If the software-only floating point emulator is being used then
floating point instructions should placed sequentially, as the
floating point emulator will detect that the next instruction is also
a floating point instruction, and will emulate it without leaving the
undefined instruction code.

Note that this advice is not applicable to systems which use the ARM
FPA co-processor.

### Make full use of cache lines

In order to help the cache on a cached ARM processor maintain a high
hit rate for data, place frequently accessed data values together so
that the are loaded into the same cache line, rather scattering them
around memory, as this will require more cache lines to be loaded, and
kept in the cache.

In a similar vein, commonly called subroutines (especially short ones)
will often run more quickly on a cached ARM processor if the entry
address is aligned so that it will be loaded into the first word of a
cache line. On the ARM610, for example this means quad-word
aligned. This ensures that all four words of the first line fetch will
be subsequently used by instruction fetches before another line fetch
is caused by an instruction fetch. This technique is most useful for
large programs which do not cache well, as the number of times the
code will have to feteched from memory is not likely to be significant
if the program does cache well.

### Minimise non-sequential cycles

This technique is only appropriate to un-cached ARM processors, and is
intended for memory systems in which non-sequential memory accesses
take longer than sequential memory accesses.

Consider such a system in which the length of memory bursts is B. That
is, if executing a long sequence of data operations, the memory
accesses which result are: one non-sequential memory cycle followed by
B-1 sequential memory cycles. eg. DRAM controlled by the ARM memory
manager MEMC1a.

This sequence of memory accesses will be broken up by several ARM
instruction types: Load or Store (single or multiple), Data Swap,
Branch instructions, SWI's and other instructions which modify the PC.

By placing these instructions carefully, so that they break up the
normal sequence of memory cycles only where a non-sequential cycle was
about to occur anyway, the number of sequential cycles which are
turned into longer non-sequential cycles can be minimised.

For a memory system in which has memory bursts of length B, the
optimal position for instructions which break up the memory cycle
sequence is 3 words before the next B-word boundary.

To help explain this consider a memory system with memory bursts of
length 4 (ie. quad word bursts), the optimal position for these
break-up instructions is 16-12=4 bytes from a quad-word offset. To
demonstrate this is the case imagine executing the following code in
this system:

    0x0000  Data Instr 1
    0x0004  STR
    0x0008  Data Instr 2
    0x000C  Data Instr 3
    0x0010  Data Instr 4

The memory cycles executing this code will produce are (taking into
account the ARM instruction pipeline):

    Instruction Fetch 0x0000 (Non Seq)
    Instruction Fetch 0x0004 (Seq)
    Instruction Fetch 0x0008 (Seq)      + Execute Data Instr 1
    Instruction Fetch 0x000C (Seq)      + Execute STR
    Data Write               (Non Seq)
    Instruction Fetch 0x0010 (Non Seq)  + Execute Data Instr 2
    Instruction Fetch 0x0014 (Seq)      + Execute Data Instr 3

The instruction fetch after the Data Write cycle had to be
non-sequential cycle, but since the instruction fetch was of a
quad-word aligned address it had to be non-sequential anyway. Hence
the STR is optimally positioned to avoid changing sequential
instruction fetches into non-sequential instruction fetches.

### Use an efficient algorithm

Despite all these techniques for optimising ARM Assembly Language, it
is important that care is taken to start off with an efficient
algorithm - all the optimisations in the world won't turn bubble sort
into an 'n log n' sorting algorithm!

## Related topics

Most of the recipes in this chapter are likely to have some
relevance. Specific references have been indicated above for
particular topics.

# Register usage under the ARM procedure call standard

---

## About this recipe

In this recipe you will learn about:

- the basic issues involved with interfacing ARM Assembly Language
  code to C programs;
- the basic concepts of the ARM Procedure Call Standard (or **APCS**),
  with more detail on register usage issues.

The supporting example illustrates:

- a simple function written in assembler which is linkable with C
  modules;
- some of the issues involved with the APCS.

## Introduction to the APCS

The ARM Procedure Call Standard is a set of rules which govern calls
between functions which are visible between separately compiled or
assembled code fragments.

The following are defined by the APCS:

- constraints on the use of registers;
- stack conventions;
- the format of a stack backtrace data structure;
- argument passing and result return;
- support for the ARM shared library mechanism.

Code which is produced by compilers is expected to adhere to the APCS
at all times. Such code is said to be **strictly conforming**.

Hand written code is expected to adhere to the APCS when making calls
to externally visible functions. Such code is said to be
**conforming**.

The ARM Procdeure Call Standard comprises a family of variants. The
following independent choices need to be made to fix the variant of
the APCS required:

- Is the Program Counter 32-bit or 26-bit?
- Is stack limit checking explicit or implicit? ie. is stack limit
  checking performed by code, or is it checked by memory management
  hardware?
- Should floating point values be passed in floating point registers?
- Is code reentrant or non-reentrant?

Code which conforms to one APCS variant conforms to none of the other
variants.

For the full specification of the APCS see [ARM Procedure Call
Standard](../atsfldr/ats4frst.html#XREF28151).

## Register names and usage under the APCS

The following table summarises the names and uses allocated to the ARM
and Floating Point registers under the APCS (note that not all ARM
systems support floating point):

| Name | Register | APCS Role | | |
| ----- | -------- | ---------------------------------- | --- | ----- |
| a1 | r0 | argument 1 / integer result | | |
| a2 | r1 | argument 2 | | |
| a3 | r2 | argument 3 | | |
| a4 | r3 | argument 4 | | |
| v1-v5 | r4-r8 | register variables | | |
| sb | r9 | static base | | |
| sl | r10 | stack limit / stack chunk handle | | |
| fp | r11 | frame pointer | | |
| ip | r12 | new-static base in inter-link-unit | | calls |
| sp | r13 | lower end of current stack frame | | |
| lr | r14 | link address | | |
| pc | r15 | program counter | | |
| f0 | f0 | FP argument 1 / FP result | | |
| f1 | f1 | FP argument 2 | | |
| f2 | f2 | FP argument 3 | | |
| f3 | f3 | FP argument 4 | | |
| f4-f7 | f4-f7 | FP register variables | | |

Simplistically:

| Register | Use | | | | | | | |
| -------------- | ----------------------------------------- | --------------------------------------- | -------------------------------------- | ---------------------------------------- | ------------------------------------ | --------------------------------------- | -------------------------------- | --------------------------------- |
| a1-a4, f0-f3 | Used to pass arguments to functions.  a1 | is also used to return integer results, | and f0 to return FP results.  These | registers can be corrupted by a called | function.  | | | |
| v1-v5, f4-f7 | Used as register variables.  They must | be preserved by called functions.  | | | | | | |
| sb,sl,fp,ip,sp | have a dedicated role in some APCS ,lr,pc | variants, some of the time.  ie. there | are times when some of these registers | can be used for other purposes even when | strictly conforming to the APCS.  In | some variants of the APCS sb and sl are | available as additional variable | registers v6 and v7 respectively. |

As stated previously, hand coded assembler routines need not **conform
strictly** to the APCS, but need only **conform**. This means that all
registers which do not need to be used in their APCS role by an
assembler routine (eg. fp) can be used as working registers as long as
their value on entry is restored before returning.

## 64 Bit integer addition

The purpose of this example is to examine coding a small function in
ARM Assembly Language, in a way which will enable it to be used from C
modules. First, however, the function is coded in C, and the
compiler's output examined.

Let us consider writing a 64 bit integer addition routine in C, where
the data structure used to store 64 bit integers is a two word
structure. The obvious way to code the addition of these double length
integers in assembler is to make use of the Carry flag from the low
word addition in the high word addition. However, there is no way to
specify this in C.

A possible way to code around this in C is as follows:

    void add_64(int64 *dest, int64 *src1, int64 *src2)
    { unsigned hibit1=src1->lo >> 31, hibit2=src2->lo >> 31, hibit3;
      dest->lo=src1->lo + src2->lo;
      hibit3=dest->lo >> 31;
      dest->hi=src1->hi + src2->hi +
               ((hibit1 & hibit2) || (hibit1!= hibit3));
      return;
    }

### Explanation

The highest bits of the low words in the two operands are calculated
(shifting them into bit 0, while clearing the rest of the
register). These are then used to determine the value of the carry bit
(in the same way as the ARM itself does).

### Examining the compiler's output

If the 64 bit integer addition routine is used a great deal, then a
poor implementation such as this is likely to be inadequate. To see
just how good or bad this implementation is let us look at the actual
code which the compiler produces.

Set the current directory to **examples**. The above code can be found
in **add64_1.c**, which we can compile to ARM Assembly Language source
as follows:

    armcc -li -apcs 3/32bit -S add64_1.c

The -S flag tells **armcc** to produce ARM Assembly Language source
(suitable for **armasm**) rather than producing object code. The -li
flag tells **armcc** to compile for a little-endian memory and the
-apcs option specifies that the 32 bit version of APCS 3 should be
used.

Looking at the output file, **add64_1.s**, we can see that this is
indeed an inefficient implementation.

### Modifying the compiler's output

Let us go back to the original intention of coding the 64 bit integer
addition using the ARM's Carry flag. Since use of the Carry flag
cannot be specified in C, we can get the compiler to produce almost
the right code, and then modify it by hand. Let us start with
(incorrect) code which does not perform the carry addition:

    void add_64(int64 *dest, int64 *src1, int64 *src2)
    { dest->lo=src1->lo + src2->lo;
      dest->hi=src1->hi + src2->hi;
      return;
    }

To compile this to give assembler suitable for use with **armasm**
first set the current directory to **examples**, and issue this
command (the options used are described above):

    armcc -li -apcs 3/32bit -S add64_2.c

This will produce the source in **add64_2.s**, which will include the
following code:

    add_64
        LDR    a4,[a2,#0]
        LDR    ip,[a3,#0]
        ADD    a4,a4,ip
        STR    a4,[a1,#0]
        LDR    a2,[a2,#4]
        LDR    a3,[a3,#4]
        ADD    a2,a2,a3
        STR    a2,[a1,#4]
        MOV    pc,lr

Looking at this carefully comparing it to the C source we can see that
the first ADD instruction produces the low order word, and the second
produces the high order word. All we need to do to get the carry from
the low to high word right is change the first ADD to ADDS (add and
set flags), and the second ADD to an ADC (add with carry). This
modified code is available in the **examples** directory as
**add64_3.s**.

### What effect did the APCS have on this example ?

Look at the above code again. The most obvious may in which the APCS
has affected the code produced is that the registers are all given
APCS style names, as introduced earlier in this recipe.

a1 clearly holds a pointer to the destination structure, a2 and a3
pointers to the operand structures. Both a4 and ip are used as
temporary registers, which are not preserved. The conditions under
which ip can be corrupted will be discussed later in this recipe.

This is a simple leaf function, which uses few temporary
registers. Therefore no registers are saved to the stack, and none
need to be restored on exit. Thus a simple "MOV pc,lr" can be used to
return.

If we had wished to return a result, perhaps the carry out from this
addition, then it would be loaded into a1 prior to exit. In this
example, this could be done by changing the second ADD to ADCS (add
with carry and set flags), and adding the following instructions to
load a1 with 1 or 0 depending on the carry out from the high order
addition.

        MOV    a1, #0
        ADC    a1, a1, #0

### Back to the first inefficient implementation

Although the first C implementation was inefficient, it shows us more
about the APCS than the more efficient hand modified version.

We have already seen a4 and ip being used as non-preserved temporary
registers. However, here v1 and lr are also used as temporary
registers. v1 is preserved by storing it (together with lr) on
entry. lr is corrupted, but a copy is saved, onto the stack, and is
reloaded into pc at the same time that v1 is restored.

Thus there is still only a single exit instruction, but now it is:

        LDMIA  sp!,{v1,pc}

## More detailed APCS register usage information

It was stated initially that sb,sl,fp,ip,sp and lr are dedicated
registers, but in the example we saw ip and lr being used as temporary
registers. Indeed, there are times when these registers are not used
for their APCS roles, and it is useful to know about these situations,
so that efficient (but safe) code can be written to make use of as
many of the registers as possible and thereby avoid doing unnecessary
register saving and restoring.

| Registe | Description r | | | | | | | | |
| ------- | ------------------------------------------------ | ----------------------------------------------- | ------------------------------------------------ | ------------------------------------------------ | --------------------------------------------- | ----------------------------------------------- | ---------------------------------------------- | ----------------------------------------------- | ------------------------------- |
| ip | This register is used only during function call. | It is conventionally used as a local code | generation temporary register.  At other times | it can be used as a corruptible temporary | register.  | | | | |
| lr | This register holds the address to which control | must return on function exit.  It can be (and | often is) used as a temporary register after | pushing its contents onto the stack.  This value | can then be reloaded straight into the PC.  | | | | |
| sp | This is the stack pointer, which is always valid | in strictly conforming code, but need only be | preserved in hand written code.  Note, however, | that if any use of the stack is to be made by | hand written code, sp must be available.  | | | | |
| sl | This is the stack limit register.  If stack | limit checking is explicit (ie. it is performed | by code when stack pushes occur, rather than by | memory management hardware causing a trap when | stack overflow occurs), then sl must be valid | whenever sp is valid.  If stack checking is | implicit sl is instead treated as v7, an | additional register variable (which must be | preserved by called functions). |
| fp | This is the frame pointer register.  It contains | either zero, or a pointer to the most recently | created stack backtrace data structure.  As with | the stack pointer, this must be preserved, but | in hand written code need not be available at | all instants.  It should, however, be valid | whenever any strictly conforming functions are | called.  | |
| sb | This is the static base register. If a the | variant of the APCS being used is reentrant, | then this register is used to access an array of | static data pointers to allow code to access | data reentrantly.  However, if the variant of | the APCS being used is not reentrant then sb is | instead available as an additional register | variable, v6 (which must be preserved by called | functions).  |

Thus sp,sl,fp and sb must all be preserved on function exit for APCS
**conforming** code.

## Related topics

- Passing and returning structs;
- In-Line SWIs.

# Passing and returning structs

---

## About this recipe

In this recipe you will learn about:

- the way structs are normally passed to and from functions;
- cases when this is automatically optimised;
- how to tell the compiler to return a struct value using several
  registers.

## The default way to pass and return a struct

Unless special conditions apply (detailed in following sections), C
structures are:

- passed in registers which if necessary overflow onto the stack;
- returned via a pointer to the memory location of the result.

For struct-valued functions a pointer to the location where the struct
result is to be placed is passed in a1, (the first argument
register). The first argument is then passed in a2, the second in a3
etc.

It is as if:

    struct s f(int x)

were compiled as:

    void f(struct s *result, int x)

As a demonstration of the default way in which structures are passed
and returned consider the following code:

    typedef struct two_ch_struct
    { char ch1;
      char ch2;
    } two_ch;
    
    two_ch max( two_ch a, two_ch b )
    { return (a.ch1>b.ch1) ? a : b;
    }

This code is available in the **examples** directory as
**two_ch.c**. It can be compiled to produce Assembly Language source
by using the following command:

    armcc -S two_ch.c -li -apcs 3/32bit

Where -li and -apcs 3/32bit can be omitted if **armcc** has been
configured appropriately already.

Here is the code which **armcc** produces:

    max
        MOV    ip,sp
        STMDB  sp!,{a1-a3,fp,ip,lr,pc}
        SUB    fp,ip,#4
        LDRB   a3,[fp,#-&14]
        LDRB   a2,[fp,#-&10]
        CMP    a3,a2
        SUBLE  a2,fp,#&10
        SUBGT  a2,fp,#&14
        LDR    a2,[a2,#0]
        STR    a2,[a1,#0]
        LDMDB  fp,{fp,sp,pc}

The STMDB instruction saves the arguments onto the stack, together
with the frame pointer, stack pointer, link register and current pc
value (this sequence of values is the stack backtrace data structure).

a2 and a3 are then used as temporary registers to hold the the
required part of the strucures passed, and a1 as a pointer to an area
in memory in which the resulting struct is placed - all as expected.

For a basic explanation of register naming and usage under the APCS,
see Register usage under the ARM procedure call standard. Detailed
information can be found in [C language calling
conventions](../atsfldr/4atsc.html#XREF36070).

## The optimisation of integer-like structures

The ARM Procedure Call Standard specifies different rules for
returning **integer-like** structs. An integer-like struct is one
which has the following properties:

- The size of the struct is no larger than one word;
- The byte offset of each addressable sub-field is 0 (bit-fields are
  not addressable).

Thus the following structs are integer-like:

    struct
    { unsigned a:8, b:8, c:8, d:8;
    }
    
    union polymorphic_ptr
    { struct A *a;
      struct B *b;
      int      *i;
    }

Whereas the structure used in the previous example is not
integer-like:

    struct { char ch1, ch2; }

Integer-like structs are returned by returning the struct's contents
in a1 rather than a pointer to the struct's contents. Thus a1 is not
needed to pass a pointer to a result struct in memory, and is instead
be used to pass the first argument.

For example, consider the following code:

    typedef struct half_words_struct
    { unsigned field1:16;
      unsigned field2:16;
    } half_words;
    
    half_words max( half_words a, half_words b )
    { half_words x;
      x= (a.field1>b.field1) ? a : b;
      return x;
    }

We would expect arguments a and b to be passed in registers a1 and a2,
and since half_word_struct is integer-like we expect the result
structure to be passed back directly in a1, (rather than a1 being used
to return a pointer to the result half_words_struct).

The above code is available in the **examples** directory as
**half_str.c**. It can be compiled to produce Assembly Language source
by using the following command:

    armcc -S half_str.c -li -apcs 3/32bit

Where -li and -apcs 3/32bit can be omitted if **armcc** has been
configured appropriately already.

Here is the code which **armcc** produces:

    max
        MOV    a3,a1,LSL #16
        MOV    a3,a3,LSR #16
        MOV    a4,a2,LSL #16
        MOV    a4,a4,LSR #16
        CMP    a3,a4
        MOVLE  a1,a2
        MOV    pc,lr

Clearly the contents of the **half_words** structure is returned
directly in a1 as expected.

## Returning non integer-like structs in registers

There are occasions when a function needs to return more than one
value. The normal way to achieve this is to define a structure which
holds all the values to be returned, and return this.

As we have seen, this will result in a pointer to the structure being
passed in a1, which will then be dereferenced to store the values
returned.

For some applications in which such a function is time critical, the
overhead involved in "wrapping" and then "unwrapping" this structure
can be significant. However, there is a way to tell the compiler that
a structure should be returned in the argument registers a1 -
a4. Clearly this is only useful for returning structures which are no
larger than 4 words.

The way to tell the compiler to return a structure in the argument
registers is to use the keyword "\_\_value_in_regs".

### Multiplication - Returning a 64-bit result

To illustrate how to use \_\_value_in_regs, let us consider writing a
function which multiplies two 32-bit integers together and returns the
64-bit result.

The way this function must work is to split the two 32-bit numbers (a,
b) into high and low 16-bit parts,(a_hi, a_lo, b_hi, b_lo). The four
multiplications a_lo \* b_lo, a_hi \* b_lo, a_lo \* b_hi, a_hi \* b_lo
must be performed, and the results added together, taking care to deal
with carry correctly.

Since the problem involves dealing with carry correctly, coding this
function in C will not produce optimal code (see 64 Bit integer
addition for more details). Therefore we will want to code the
function in ARM Assembly Language. The following code performs the
algorithm just described:

    ; On entry a1 and a2 contain the 32-bit integers to be multiplied (a, b)
    ; On exit a1 and a2 contain the result (a1 bits 0-31, a2 bits 32-63) mul64
    
        MOV    ip, a1, LSR #16                      ; ip = a_hi
        MOV    a4, a2, LSR #16                      ; a4 = b_hi
        BIC    a1, a1, ip, LSL #16                  ; a1 = a_lo
        BIC    a2, a2, a4, LSL #16                  ; a2 = b_lo
        MUL    a3, a1, a2                           ; a3 = a_lo * b_lo    (m_lo)
        MUL    a2, ip, a2                           ; a2 = a_hi * b_lo    (m_mid1)
        MUL    a1, a4, a1                           ; a1 = a_lo * b_hi    (m_mid2)
        MUL    a4, ip, a4                           ; a4 = a_hi * b_hi    (m_hi)
        ADDS   ip, a2, a1                           ; ip = m_mid1 + m_mid2 (m_mid)
        ADDCS  a4, a4, #&10000                      ; a4 = m_hi + carry       (m_hi')
        ADDS   a1, a3, ip, LSL #16                  ; a1 = m_lo + (m_mid<<16)
        ADC    a2, a4, ip, LSR #16                  ; a2 = m_hi' + (m_mid>>16) + carry
        MOV    pc, lr

Clearly this code is fine for use with Assembly language modules, but
in order to use it from C we need to be able tell the compiler that
this routine returns its 64-bit result in registers. This can be done
by making the following declarations in a header file:

    typedef struct int64_struct
    { unsigned int lo;
      unsigned int hi;
    } int64;
    
    __value_in_regs extern int64 mul64(unsigned a, unsigned b);

The Assembly Language code above, and the declarations above together
with a test program are all in the **examples** directory, as the
files: **mul64.s**, **mul64.h**, **int64.h** and **multest.c**. To
compile, assemble and link these to produce an executable image
suitable for **armsd** first set your current directory to
**examples**, and then execute the following commands:

    armasm mul64.s -o mul64.o -li
    armcc -c multest.c -li -apcs 3/32bit
    armlink mul64.o multest.o 

Where **somewhere** is the directory in which the semi-hosted C
libraries reside (eg. the **lib** directory of the ARM Software Tools
Release). Note also that **-li** and **-apcs 3/32bit** can be omitted
if **armcc** and **armasm** (and **armsd** below) have been configured
appropriately.

**multest** can then be run under **armsd** as follows:

    > armsd -li multest
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file multest
    armsd: go
    Enter two unsigned 32-bit numbers in hex eg.(100 FF43D)
    
    12345678 10000001
    Least significant word of result is 92345678
    Most  significant word of result is  1234567
    Program terminated normally at PC = 0x00008418
          0x00008418: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    >

To convince yourself that \_\_value_in_regs is being used try removing
it from **mul64.h**, recompile **multest.c**, relink **multest**, and
rerun **armsd**. This time the answers returned will be incorrect, as
the result is no longer expected to be returned in registers, but
instead in a block of memory (ie. the code now has a bug).

## Related topics

- ARM6 multiplier performance issues.

# In-Line SWIs

---

## About this recipe

This recipe shows how the ARM C Compiler can be used to generate
in-line SWIs directly from C.

## Introduction

The ARM instruction set provides the Software Interrupt (SWI)
instruction to call Operating System routines. It is useful to be able
to generate such operating system calls from C without having to call
hand crafted ARM Assembly Language to provide an interface between C
and the SWI.

The ARM C Compiler provides a mechanism which allows many SWIs to be
called efficiently from C. SWIs which conform to the following rules
can be compiled in-line, without additional calling overhead:

- The arguments to the SWI (if any) must be passed in r0-r3 only.
- The results returned from the SWI (if any) must be returned in r0-r3
  only.

The following sections demonstrate how to use the in-line SWI facility
of *armcc* for a variety of different SWIs which conform to these
rules. These SWIs are taken from the ARM Debug Monitor interface, .

In the examples below, the following options are used with *armcc*:

| Option | Use | |
| ------------- | ----------------------------------------- | ----------------- |
| -li | Specifies that the the target is a little | endian ARM.  |
| -apcs 3/32bit | Specifies that the 32 bit variant of APCS | 3 should be used. |

## Using a SWI which returns no result

For example: SWI_WriteC, which we want to be SWI number 0.

This SWI is intended to write a byte to the debugging channel. The
byte to be written is passed in r0.

The following C code, intended to write a Carriage Return / Line Feed
sequence to the debugging channel, can be found in the *examples*
directory as *newline.c*:

    void __swi(0) SWI_WriteC(int ch);
    
    void output_newline(void)
    { SWI_WriteC(13);
      SWI_WriteC(10);
    }

Look carefully at the declaration of SWI_WriteC. \_\_swi(0) is the way
in which the SWI_WriteC 'function' is declared to be in-line SWI
number 0.

This code can be compiled to produce ARM Assembly Language source
using:

    armcc -S -li -apcs 3/32bit newline.c -o newline.s

The code produced for the output_newline function is:

    output_newline
        MOV    a1,#&d
        SWI    &0
        MOV    a1,#&a
        SWI    &0
        MOV    pc,lr

## Using a SWI which returns one result

Consider SWI_ReadC, which we want to be SWI number 4.

This SWI is intended to read a byte from the debug channel, returning
it in r0.

The following C code, a naive read a line routine, can be found in the
*examples* directory as *readline.c*:

    char __swi(4) SWI_ReadC(void);
    
    void readline(char *buffer)
    {
        char ch;
        do {
            *buffer++=ch=SWI_ReadC();
      }     while (ch!=13);
        *buffer=0;
    }

Again, the way in which SWI_ReadC is declared should be noted: it is a
function which takes no arguments and returns a char, and is
implemented as in-line SWI number 4.

This code can be compiled to produce ARM Assembler source using:

    armcc -S -li -apcs 3/32bit readline.c -o readline.s

The code produced for the readline function is:

    readline
        STMDB  sp!,{lr}
        MOV    lr,a1
    |L000008.J4.readline|
        SWI    &4
        STRB   a1,[lr],#1
        CMP    a1,#&d
        BNE    |L000008.J4.readline|
        MOV    a1,#0
        STRB   a1,[lr,#0]
        LDMIA  sp!,{pc}

## Using a SWI which returns 2-4 results

If a SWI returns two, three or four results then its declaration must
specify that it is a struct-valued SWI, and the special keyword
\_\_value_in_regs must also be used. This is because a struct valued
function is usually treated much as if it were a void function with a
pointer to where to return the struct as the first argument. See
Passing and returning structs for more details.

As an example consider SWI_InstallHandler, which we want to be SWI
number 0x70.

On entry r0 contains the exception number, r1 contains the workspace
pointer, r2 contains the address of the handler.

On exit r0 is undefined, r2 contains the address of the previous
handler and r1 the previous handler's workspace pointer.

The following C code fragment demonstrates how this SWI could be
declared and used in C:

    typedef struct SWI_InstallHandler_struct
    { 
        unsigned exception;
        unsigned workspace;
        unsigned handler;
    }   SWI_InstallHandler_block;
    
    SWI_InstallHandler_block 
        __value_in_regs  
            __swi(0x70) SWI_InstallHandler
                                (unsigned r0, unsigned r1, unsigned r2);
    
    void InstallHandler(SWI_InstallHandler_block *regs_in,
                                SWI_InstallHandler_block *regs_out)
    { *regs_out=SWI_InstallHandler(regs_in->exception,
                                                regs_in->workspace,
                                                regs_in->handler);
    }

This code is provided in the *examples* directory as *installh.c*, and
can be compiled to produce ARM Assembler source using:

    armcc -S -li -apcs 3/32bit installh.c -o installh.s 

The code which *armcc* produces is:

    InstallHandler
        STMDB  sp!,{lr}
        MOV    lr,a2
        LDMIA  a1,{a1-a3}
        SWI    &70
        STMIA  lr,{a1-a3}
        LDMIA  sp!,{pc}

## The SWI number is not known until run time

If a SWI is to be called, but the number of the SWI is not known until
run time, then the mechanisms discussed above are not appropriate.

This situation might occur when there are a number of related
operations which can be performed on a object, and these various
operations are implemented by SWIs with different numbers.

There are several ways to deal with this, including:

- The SWI instruction can be constructed from the SWI Number, stored
  somewhere and then executed.
- A 'generic' SWI can be used which takes as an extra argument a code
  for the actual operation to be performed on its arguments. This
  'generic' SWI must then decode the operation and then perform it.

A mechanism has been added to *armcc* to support the second method
outlined here. The operation is specified by a value which is passed
in r12 (ip). The arguments to the 'generic' SWI are as usual passed in
registers r0-r3, and values may optionally be returned in r0-r3 using
the mechanisms described above. The operation number passed in r12 may
well be the number of the SWI to be called by the 'generic' SWI, but
it need not be.

Here is an C fragment which uses a 'generic', or 'indirect' SWI:

    unsigned __swi_indirect(0x80)
        SWI_ManipulateObject(unsigned operationNumber, unsigned object,
                                unsigned parameter);
    
    unsigned DoSelectedManipulation(unsigned object, 
                                unsigned parameter, unsigned operation)
                                   { return 
    SWI_ManipulateObject(operation, object, parameter);
    }

This code is provided in the *examples* directory as *swimanip.c*, and
can be compiled to produce ARM Assembler source using:

    armcc -S -li -apcs 3/32bit swimanip.c -o swimanip.s 

The code which *armcc* produces is:

    DoSelectedManipulation
        MOV    ip,a3
        SWI    &80
        MOV    pc,lr

## Related topics

- Register usage under the ARM procedure call standard
- Passing and returning structs;
- C Programming for deeply embedded applications for example programs
  which make use of in line swis.

# A simple C program

---

## About this recipe

This recipe gives you a simple exercise in using the ARM Software
Development Toolkit (the toolkit) to write a program in C. By
following it, you will learn how to:

- use the ARM C compiler **armcc** to create a runnable program;
- use the ARM source level debugger **armsd** to run your program on a
  (simulated) ARM system;
- use **armcc** to compile a C program to an object file;
- use the ARM linker **armlink** to create a runnable program from an
  object file and the ARM C library.

## Prerequisites

Before you can try this recipe, the toolkit must be properly installed
on your computer. Instructions for installation are given in the
installation notes distributed with every toolkit. If you experience
any difficulties, please refer to these notes.

## Making a simple runnable program

The "Hello World" program shown below, is included in the on-line
examples as file **hellow.c** in the directory **examples**:

    #include <stdio.h>
    
    int main( int argc, char **argv )
    { 
        printf("Hello World\n");
          return 0;
    }

If you set your working directory to be the **examples** directory you
can compile this program to runnable form in a single step using:

    armcc hellow.c -li -apcs 3/32bit

### Explanation

The argument -li says that the target is little endian and -apcs
3/32bit says that the 32 bit ARM procedure call standard should be
used. If the compiler has been **configured** to use these options by
default then these arguments need not be given. The executable program
is left in a file called **hellow**.

## Running the program

You can run the program (technically an AIF Image) using
**armsd**. You should follow the sample dialog below:

    host-prompt> armsd -li hellow
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file hellow
    armsd: go
    Hello world
    Program terminated normally at PC = 0x000082a0
          0x000082a0: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    host-prompt>

### Explanation

The -li argument to **armsd** tells it to emulate a little endian
arm. If armsd has been configured to be little endian by default then
-li can be omitted .

When armsd comes up with its "armsd:" prompt and waits for your
command, you should type "go**CR**". At the next prompt type
"quit**CR**" to exit **armsd**.

## Separate compiling

You can invoke the compiler and the linker separately. You can use:

    armcc -c hellow.c -li -apcs 3/32bit

to make an object file (in this example called **hellow.o**, by
default).

### Explanation

The -c flag tells the compiler to make an object file but not to link
it with the C library.

## Separate linking

When you have finished compiling, you can link your object file with
the C library to make a runnable program using:

    armlink -o hellow hellow.o somewhere/armlib.321

Where we have written **somewhere**, above, you must type the name of
the directory containing the ARM C libraries.

### Notes

You now have to be very explicit; you must specify:

- the name of the file which will contain the runnable program (here,
  **hellow**);
- the name of the object file (here, **hellow.o**);
- the location and name of the C library you wish to use.

In simple cases, **armcc** can reduce the need to be so explicit.

## Related topics

Please refer to the index to find topics of particular interest.

# Writing efficient C for the ARM

---

## About this recipe

The ARM C compiler can generate very good machine code for if you
present it with the right sort of input. From this note, you will
learn:

- what the C compiler compiles well and why;
- how to help the C compiler to generate excellent machine code.

Some of the rules of thumb presented are quite general; some are quite
specific to the ARM or the ARM C compiler. It should be quite clear
from context which rules are portable.

The first subsection below is concerned with how to design collections
of C functions to maximise low-level efficiency. The following
subsection is concerned with the efficiency of larger and more
complicated functions.

## Function design considerations

Unlike on many earlier CISC processor architectures, function call
overhead on the ARM is small and often in proportion to the work done
by the called function. Several feaures contribute to this:

- the minimal ARM call-return sequence is BL... MOV pc, lr, which is
  extremely economical;
- STM and LDM reduce the cost of entry to and exit from functions
  which must create a stack frame and/or save registers;
- the ARM Procedure Call Standard has been carefully designed to allow
  two very important types of function call to be optimised so that
  the entry and exit overheads are minimal.

Good general advice is to keep functions small, because function
calling overheads are low. In the remainder of this subsection you
will learn precisely when function call overhead is very low. In
following subsections you will learn how small functions help the ARM
C compiler; you will also learn how to assist the C compiler when
functions cannot be kept small.

### Leaf functions

In 'typical' programs, about half of all function calls made are to
leaf functions (a leaf function is one which makes no calls from
within its body).

Often, a leaf function is rather simple. On the ARM, if it is simple
enough to compile using just 5 registers (a1-a4 and ip), it will carry
no function entry or exit overhead. A surprising proportion of useful
leaf functions can be compiled within this constraint.

Once registers have to be saved, it is efficient to save them using
STM. In fact the more you can save at one go, the better. In a leaf
function, all and only the registers which need to be saved will be
saved by a single STMFD sp!,{regs,lr} on entry and a matching LDMFD
sp!,{regs,pc} on exit.

In general, the cost of pushing some registers on entry and popping
them on exit is very small compared to the cost of the useful work
done by a leaf function which is complicated enough to need more than
5 registers.

Overall, you should expect a leaf function to carry virtually no
function entry and exit overhead; and at worst, a small overhead, most
likely in proportion to the useful work done by it.

### Veneer functions (Simple fail continued functions)

Historically, abstraction veneers have been relatively expensive. The
kind of veneer function which merely changes the types of its
arguments, or which calls a low-level implementation with an extra
argument (say), has often cost much more in entry and exit overhead
than it was worth in useful work.

On the ARM, if a function ends with a call to another function, that
call can be converted to a **tail continuation**. In functions which
need to save no registers, the effect can be dramatic. Consider, for
example:

    extern void *__sys_alloc(unsigned type, unsigned n_words);
    #define  NOTGCable   0x80000000
    #define  NOTMovable  0x40000000
    
    void *malloc(unsigned n_bytes)
    {   
        return __sys_alloc(NOTGCable+NOTMovable, n_bytes/4);
    }

Here, **armcc** generates:

    malloc
        MOV     a2,a1,LSR #2
        MOV     a1,#&c0000000
        B       |__sys_alloc|

There is no function entry or exit overhead-just useful work massaging
arguments-and the function return has disappeared entirely - return is
direct from \_\_sys_alloc to malloc's caller. In this case, the basic
call-return cost for the function pair has been reduced from:

    BL + BL + MOV pc,lr + MOV pc,lr

to:

    BL + B  +             MOV pc,lr

a saving of 25%.

More complicated functions in which the only function calls are
immediately before a return, collapse equally well. An artificial
example is:

    extern int f1(int), int f2(int, int);
    
    int f(int a, int b)
    {   
        if (b == 0)
            return a;
        else if (b < 0)
            return f2(a, -b);
        else
            return f2(b, a);                              /* argument order 
    swapped */
    }

**armcc** generates the following, wonderfully efficient code:

    f    CMP     a2,#0
        MOVEQS  pc,lr
        RSBLT   a2,a2,#0
        BLT     f2
        MOV     a3,a1
        MOV     a1,a2
        MOV     a2,a3
        B       f2

### Fast paths and slow paths - A useful transformation

Inevitably, not all functions can be leaves or small abstraction
functions. And, inevitably, non-leaf functions must carry the cost of
establishing a call frame on entry and removing it on exit, perhaps
also the cost of saving and restoring some registers. How does this
hurt performance? Consider the following example:

    int f(Buffer *b)
    {    if (b->n > 0)
         {   /* The usual path through the function... */
             /*     95% of all calls.*/
             /* Simple calculation involving b->buf, b->n, etc.*/
             return ...;
         }
         /* Exceptional path through the function... */
         /*     5% of all calls.  */
         /* Complicated calculation involving calls
         /*     to other functions.*/
         return ...;
    }

In this case, the entry and register-save overhead caused by the
infrequent heavyweight path through the function applies to the much
more frequent lightweight path through it. To fix this, turn the
heavyweight path into a tail call. Yes, introducing another layer of
function call yields much more efficient code!

    int f2(Buffer *b)
    {     /* Exceptional path through the function... */
          /*     5% of all calls.  */
          /* Complicated calculation involving calls */
          /*     to other functions.*/
          return ...;
    }
    
    int f(Buffer *b)
    {    if (b->n > 0)
             {     /* The usual path through the function... */
                   /*     95% of all calls.*/
                   /* Simple calculation involving b->buf, b->n, etc.*/
                   return ...;]
            }
        return f2(b);
    }

If you are lucky, f() will now compile using only a1-a4 and ip and so
incur no entry overhead whatsoever. 95% of the time, the overhead on
the original f() will be reduced to zero.

This is quite a general source transformation technique and you should
look for opportunities to use it and analogous transformations. It
works for any processor to some extent; it works particulary well for
the ARM because of the careful optimisation of tail continuation in
lightweight functions.

Repeated application of this technique to the chain of six or so
functions called for every character processed by the preprocessing
phase of the ARM C compiler, improved the performance of the
preprocessor (running on the ARM) by about 30%.

### Function arguments and argument passing

The final aspect of function design which influences low-level
efficiency is argument passing.

Under the ARM Procedure Call Standard, up to four argument words can
be passed to a function in registers. Functions of up to four integral
(not floating point) arguments are particularly efficient and incur
very little overhead beyond that required to compute the argument
expressions themselves (there may be a little register juggling in the
called function, depending on its complexity).

If more arguments are needed, then the 5th, 6th, etc., words will be
passed on the stack. This incurs the cost of an STR in the calling
function and an LDR in the called function for each argument word
beyond four.

How can argument passing overhead be minimised?

- Try to ensure that small functions take four or fewer
  arguments. These will compile particualrly well.
- If a function needs many arguments, try to ensure that it does a
  significant amount of work on every call, so that the cost of
  passing arguments is amortised.
- Factor out read-mostly global control state and make this static. If
  it has to be passed as an argument (e.g. to support multiple
  clients) then wrap it up in a struct and pass a pointer to it. The
  characteristics of such control state are:

<!-- -->

- it's logically global to the compilation unit or program

- it's read-mostly, often read-only except in response to user input,
  and for almost all functions cannot be changed by them or any
  function called from them;

- references to it are ubiquitous, but in any function, references are
  relatively rare (frequent references should be replaced by
  references to a local, non-static copy).

- Don't confuse such control state with compuational arguments, the
  values of which differ on every call.

<!-- -->

- Collect related data into structs. Decide whether to pass pointers
  or struct values based on the use of each struct in the called
  function:

<!-- -->

- If few fields are read or written then passing a pointer is best.

- The cost of passing a struct via the stack is typically a share in
  an LDM-STM pair for each word of the struct. This can be better than
  passing a pointer if (i) on average, each field is used at least
  once and (ii) the register pressure in the function is high enough
  to force a pointer to be repeatedly re-loaded.

- As a rule of thumb, you can't lose much efficiency if you pass
  pointers to structs rather than struct values. To gain efficiency by
  passing struct values rather than pointers usually requires careful
  study of a function's machine code.

## Register allocation and how to help it

It is well known that register allocation is critical to the
efficiency of code compiled for RISC processors. It is particularly
critical for the ARM, which has only 16 registers rather than the
'traditional' 32.

The ARM C compiler has a highly efficient register allocator which
operates on complete functions and which tries to allocate the most
frequently used variables to registers (taking loop nesting into
account). It produces very good results unless the demand for
registers seriously outstrips supply. And it has one shortcoming,
namely that it allocates whole variables to registers, not separate
live ranges.

As code generation proceeds for a function, new variables are created
for expression temporaries. These are never reused in later
expressions and cannot be spilled to memory. Usually, this causes no
problems. However, a particularly pathological expression could, in
principle, occupy most of the allocatable registers, forcing almost
all program variables to be spilled to memory. Because the number of
registers required to evaluate an expression is a logarithmic function
of the number terms in it, it takes an expression of more than 32
terms to threaten the use of any variable register.

As a rule of thumb, avoid very large expressions (more than 30 terms).

The more serious problem is with long scope program variables. Our
allocator either allocates a variable to a chosen register everywhere
the variable is live, or it leaves the variable in memory. To help
visualise the problem - and to see how to help the allocator -
consider the following two program schemata:

    int f()                            int f()
    {   int i, j, ...;                 {   int j, ...;
                                         { int i;
        for (i = 0;  i < lim;  ++i)        for (i = 0;  i < lim;  ++i)
        {                                  {
            ...                               ...
        }                                  }
                                         }
                                         { int i;
        for (i = 0;  i < lim;  ++i)        for (i = 0;  i < lim;  ++i)
        {  /* register pressure in this    {
           loop forces 'i' to memory */
        }                                  }
                                         }
                                         { int i;
        for (i = 0;  i < lim;  ++i)        for (i = 0;  i < lim;  ++i)
        {                                  {
            ...                                ...
        }                                  }
                                         }
    }                                  }

In the left hand case, because the scope of 'i' is the whole function,
if 'i' cannot be allocated to a register everywhere then all three
loops will suffer their loop index being in memory. On the other hand,
in the right hand case there are three separate variables called 'i',
each of which will be allocated separately by the register allocator.

As a rule of thumb, keep variable declarations local, especially in
large functions. Use additional block structure as illustrated here
(right hand example), if necessary.

On the other hand, if this transformation is carried to excess, there
may be bad results. When a local variable is spilled to memory, there
is a stack adjustment on each entry to and exit from its containing
scope. The ARM C compiler does this to minimise the space used by
local variables. Suppose, for example, that in the right hand case
above, each block declared a 1KB buffer as well as 'i'. Then adjusting
the stack at every scope leads to stack usage of just over 1KB whereas
adjusting it only at function entry leads to usage of more than 3KB.

In principle, the compiler could be more intelligent about adjusting
the stack locally for large variables and only at function entry for
small variables. For the moment, the programmer must be aware of these
issues.

So, a modified rule of thumb is to cluster variable declarations into
reasonable sub-scopes within large functions and to avoid doing so
within the most deeply nested loops. This will most likely help the
allocator without introducing unwanted costs associated with local
stack adjustment.

## Static and extern variables - minimising access costs

A variable in a register costs nothing to access: it is just there,
waiting to be used. A local (auto) variable is addressed via the sp
register, which is always available for the purpose.

A static variable, on the other hand, can only be accessed after the
static base for the compilation unit has been loaded. So, the first
such use in a function always costs 2 LDRs or an LDR and an
STR. However, if there are many uses of static variables within a
function then there is a good chance that the static base will become
a global common subexpression (CSE) and that, overall, access to
static variables will be no more expensive than to auto variables on
the stack.

Extern variables are fundamentally more expensive: each has its own
base pointer. Thus each access to an extern is likely to cost 2 LDRs
or an LDR and an STR. It is much less likely that a pointer to an
extern will become a global CSE - and almost certain that there cannot
be several such CSEs - so if a function accesses lots of extern
variables, it is bound to incur significant access costs.

A further cost occurs when a function is called: the compiler has to
assume - in the absence of inter-procedural data flow analysis - that
**any** non- const static or extern variable **could** be
side-effected by the call. This severly limits the scope across which
the value of a static or extern variable can be held in a register.

Sometimes a programmer can do better than a compiler could do, even a
compiler that did interprocedural data flow analysis. An example in C
is given by the standard streams: stdin, stdout and stderr. These are
not pointers to const objects (the underlying FILE structs are
modified by I/O operations), nor are they necessarily const pointers
(they may be assignable in some implementations). Nonetheless, a
function can almost always safely slave a reference to a stream in a
local FILE \* variable.

It is a common programming paradigm to mimic the standard streams in
applications. Consider, for example, the shape of a typical non-leaf
printing function:

    extern FILE *out;                  extern FILE *out;
    /* the output stream */            /* the output stream */
    
    void print_it(Thing *t)            void print_it(Thing *t)
    {                                  {   FILE *f = out;
        fprintf(out, ...);                 fprintf(f, ...);
        print_1(t->first);                 print_1(t->first);
        fprintf(out, ...);                 fprintf(f, ...);
        print_2(t->second);                print_2(t->second);
        fprintf(out, ...);                 fprintf(f, ...);
        ...                                ...
    }                                  }

In the left hand case, out has be be re-computed or re-loaded after
each call to print\_... (and after each fprintf...). In the right hand
case, 'f' can be held in a register throughout the function (and
probably will be).

Uniform application of this transformation to the disassembly module
of the ARM C compiler saved more than 5% of its code space.

In general, it is difficult and potentially dangerous to assert that
no function you call (or any functions they in turn call) can affect
the value of any static or extern variables of which you currently
have local copies. However, the rewards can be considerable so it is
usually worthwhile to work out at the program design stage which
global variables are slavable locally and which are not. Trying to
retrofit this improvement to exisiting code is usually hazardous,
except in very simple cases like the above.

## The switch() statement

The switch() statement can be used to transfer control to one of
several destinations - conceptually an indexed transfer of control -
or to generate a value related to the controlling expression (in
effect computing an in-line function of the controlling expression).

In the first role, switch() is hard to improve upon: the ARM C
compiler does a good job of deciding when to compile jump tables and
when to compile trees of if-then-elses. It is rare for a programmer to
be able to improve upon this by writing if-then-else trees explicitly
in the source.

In the second role, however, use of switch() is often mistaken. You
can probably do better by being more aware of what is being computed
and how.

In the example below, which is abstracted from an early version of the
disassembly module of the ARM C Compiler, you will learn:

- the cost of implementing an in-line function using switch();
- how to implement the same function more economically.

The function below used for illustrative purposes maps a 4-bit field
of an ARM instruction to a 2-character condition code mnemonic. The
real case was more complicated, decoding two 4-bit fields to a 3-char
mnemonic, but for illustration the simple example serves just as
well. The real case was also embedded in a larger function, but this
is irrelevant to the discussion.

    char *cond_of_instr(unsigned instr)
    {   
        char *s;`
            switch (instr & 0xf0000000)
            {
    case 0x00000000:  s = "EQ";  break;
    case 0x10000000:  s = "NE";  break;
         ...          ...        ...
    case 0xF0000000:  s = "NV";  break;
            }
            return s;
    }

The compiler handles this code fragment well, generating 276 bytes of
code and string literals. But we could do better. If performance were
not critical (as it never is in disassembly) then we could look up the
code in a table of codes, in something like:

    char *cond_of_instr(unsigned instr)
    {
        static struct {char name[3];  unsigned code;}
            conds[] = {
                "EQ", 0x00000000,
                "NE", 0x10000000,
                 ....
                 "NV", 0xf0000000,
            };
        int j;
        for (j = 0;  j < sizeof(conds)/sizeof(conds[0]);  ++j)
            if ((instr & 0xf0000000) == conds[j].code)
                return conds[j].name;
        return "";
    
    }

This fragment compiles to 68 bytes of code and 128 bytes of table
data. Already this is a 30% improvement on the switch() case, but this
schema has other advantages: it copes well with a random code to
string mapping and if the mapping is not random admits further
optimisation. For example, if the code is stored in a byte (char)
instead of an unsigned and the comparison is with (instr \>\> 28)
rather than (instr & 0xF0000000) then only 60 bytes of code and 64
bytes of data are generated for a total of 124 bytes.

Another advantage we have heard of for table lookup is that is is
possible to share the same table between a disassembler and an
assembler - the assembler looks up the mnemonic to obtain the code
value, rather than the code value to obtain the mnemonic. Where
performance is not critical, the symmetric property of lookup tables
can sometimes be exploited to yield significant space savings.

Finally, by exploiting the denseness of the indexing and the
uniformity of the returned value it is possible to do better again,
both in size and performance, by direct indexing:

    char *cond_of_instr(unsigned instr)
    {
        return "\
    EQ\0\0NE\0\0CC\0\0CS\0\0MI\0\0PL\0\0VS\0\0VC\0\0\
    HI\0\0LS\0\0GE\0\0LT\0\0GT\0\0LE\0\0AL\0\0NV" + (instr >> 28)*4;
    }

This expression of the problem causes a miserly 16 bytes of code and
64 bytes of string literal to be generated and is probably close to
what an experienced assembly language programmer would naturally write
if asked to code this function. It is the solution finally adopted in
the ARM C compiler's disassembler module.

The uniform application of this transformation to the disassembler
module of the ARM C compiler saved between 5% and 10% of its code
space.

The moral of this tale is to think before using switch() to compute an
in-line function, especially if code size is an important
consideration. Switch() compiles to high performance code but often
table lookup will be smaller; where the function's domain is dense, or
piecewise dense, direct indexing into a table will often be both
faster and smaller.

## Related topics

- ARM assembly programming performance issues.
- Register usage under the ARM procedure call standard.
- Passing and returning structs.

# C Programming for deeply embedded applications

---

## About this recipe

In this recipe you will learn about the standalone runtime support
system for C programming in deeply embedded applications. In
particular you will discover:

- what **rtstand.s** supports;
- how to make use of it by looking at example programs;
- how to extend it by adding extra fuctionality from the C library;
- the size of the standalone run time library;

## Introduction

The semi hosted ANSI C library provides all the standard C library
facilities (and thus is quite large). This is acceptable when running
under emulation with plenty of memory available, or maybe even when
running on development hardware with access to a real debugging
channel and plenty of memory. However, in a deeply embedded
application many of the facilities of the C library may no longer be
relevent, eg. file access functions, time and date functions, and the
size of the semi hosted ANSI C library may be prohibitive if the
memory available is severely limited.

For deeply embedded applications a minimal C runtime system is needed
which takes up as little memory as possible, is easily portable to the
target hardware, and only supports those functions required for such
an application.

The ARM Software Development Toolkit comes with a minimal runtime
system in source form. The 'behind the scenes' jobs which it performs
are:

- setting up the initial stack and heap, and calling main;
- program termination - either automatic (returning from main() or
  forced - explicitly calling \_\_rt_exit);
- simple heap allocation (\_\_rt_alloc);
- stack limit checking;
- setjmp and longjmp support;
- divide and remainder functions (calls to which can be generated by
  **armcc**);
- high level error handler support (\_\_err_handler);
- optional floating point support, and a means to detect whether
  floating point support is available or not (\_\_rt_fpavailable);

The source code **rtstand.s** documents the options which you may want
to change for your target. These are not covered in this recipe. The
header file **rtstand.h** documents the functions which **rtstand.s**
provides to the C programmer.

Note that no support is provided for outputting data down the
debugging channel. This can be done, but is specific to the target
application. The example C programs described below use the ARM Debug
Monitor available under **armsd** to output messages using in-line
SWIs.

## Using the standalone runtime system

In this section the main features of the standalone runtime system are
demonstrated by example programs.

Before attempting any of the demonstrations below create a working
directory, and set this up as your current directory. Copy the
contents of the **clstand** directory into your working directory, and
also copy the files **fpe\*.o** from the **fpe340** directory of the
**cl** directory into your working directory. You are now ready to
experiment with the C standalone runtime system.

In the examples below, the following options are passed to **armcc**,
**armasm**, and in the first case **armsd**:

| Option | Description | | | |
| ------------- | -------------------------------------- | ------------------------------------- | -------------------------------- | ------------------------ |
| -li | Specifies that the the target is a | little endian ARM.  | | |
| -apcs 3/32bit | This specifies that the 32 bit variant | of APCS 3 should be used.  For armasm | this is used to set the built in | variable {CONFIG} to 32. |

These arguments can be changed if the target hardware differs from
this configuration. If the ARM Software Tools have been configured as
desired then these options may be omitted, as the tools will default
to the configuration time values.

These demonstrations are likely to be most useful if the sources
**rtstand.s**, **errtest.c** and **memtest.c** are studied in
conjunction with this recipe.

## A simple program

Let us compile the example program **errtest.c**, and assemble the
standalone runtime system. These can then be linked together to
provide an executable image, **errtest**:

    armcc -c errtest.c -li -apcs 3/32bit
    armasm rtstand.s -o rtstand.o -li -apcs 3/32bit
    armlink -o errtest errtest.o rtstand.o

We can then execute this image under the **armsd** as follows:

    > armsd -li errtest
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file errtest
    armsd: go
    (the floating point instruction-set is not available)
    Using integer arithmetic ...
    10000 / 0X0000000A = 0X000003E8
    10000 / 0X00000009 = 0X00000457
    10000 / 0X00000008 = 0X000004E2
    10000 / 0X00000007 = 0X00000594
    10000 / 0X00000006 = 0X00000682
    10000 / 0X00000005 = 0X000007D0
    10000 / 0X00000004 = 0X000009C4
    10000 / 0X00000003 = 0X00000D05
    10000 / 0X00000002 = 0X00001388
    10000 / 0X00000001 = 0X00002710
    Program terminated normally at PC = 0x00008550
          0x00008550: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    > 

The '\>' prompt is the Operating System prompt, and the 'armsd:'
prompt is output by **armsd** to indicate that user input is required.

Already several of the standalone runtime system's facilities have
been demonstrated:

- the C stack and heap have been set up;
- **main** has clearly been called;
- the fact that floating point support is not available has been
  detected;
- the integer division functions have been used by the compiler.
- program termination was successful.

## Error handling

The same program, **errtest**, can also be used to demonstrate error
handling, by recompiling **errtest.c** and predefining the
DIVIDE_ERROR macro:

    armcc -c errtest.c -li -apcs 3/32bit -DDIVIDE_ERROR
    armlink -o errtest errtest.o rtstand.o

Again, we can now execute this image under the **armsd** as follows:

    > armsd -li errtest
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file errtest
    armsd: go
    (the floating point instruction-set is not available)
    Using integer arithmetic ...
    10000 / 0X0000000A = 0X000003E8
    10000 / 0X00000009 = 0X00000457
    10000 / 0X00000008 = 0X000004E2
    10000 / 0X00000007 = 0X00000594
    10000 / 0X00000006 = 0X00000682
    10000 / 0X00000005 = 0X000007D0
    10000 / 0X00000004 = 0X000009C4
    10000 / 0X00000003 = 0X00000D05
    10000 / 0X00000002 = 0X00001388
    10000 / 0X00000001 = 0X00002710
    10000 / 0X00000000 = errhandler called: code = 0X00000001: divide by 0
    caller's pc = 0X00008304
    returning...
    
    run time error: divide by 0
    program terminated
    
    Program terminated normally at PC = 0x0000854c
          0x0000854c: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    > 

This time an integer division by zero has been detected by the
standalone runtime system, which called
**\_\_err_handler**. **\_\_err_hander** output the first set of error
messages in the above output. Control was then returned to the runtime
system which output the second set of error messages and terminated
execution.

## longjmp and setjmp

A further demonstration can be made using **errtest** by predefining
the macro LONGJMP to perform a **longjmp** out of **\_\_err_handler**
back into the user program, thus catching and dealing with the
error. First recompile and link **errtest**:

    armcc -c errtest.c -li -apcs 3/32bit -DDIVIDE_ERROR -DLONGJMP
    armlink -o errtest errtest.o rtstand.o

Then rerun **errtest** under **armsd**. We expect the integer divide
by zero to occur once again:

    > armsd -li errtest
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file errtest
    armsd: go
    (the floating point instruction-set is not available)
    Using integer arithmetic ...
    10000 / 0X0000000A = 0X000003E8
    10000 / 0X00000009 = 0X00000457
    10000 / 0X00000008 = 0X000004E2
    10000 / 0X00000007 = 0X00000594
    10000 / 0X00000006 = 0X00000682
    10000 / 0X00000005 = 0X000007D0
    10000 / 0X00000004 = 0X000009C4
    10000 / 0X00000003 = 0X00000D05
    10000 / 0X00000002 = 0X00001388
    10000 / 0X00000001 = 0X00002710
    10000 / 0X00000000 = errhandler called: code = 0X00000001: divide by 0
    caller's pc = 0X00008310
    returning...
    
    Returning from __err_handler() with errnum = 0X00000001
    
    Program terminated normally at PC = 0x00008558
          0x00008558: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    > 

The runtime system detected the integer divide by zero, and as before
\_\_err_handler was called, which produced the error
messages. However, this time \_\_err_handler used longjmp to return
control to the program, rather than the runtime system.

## Floating point support

Using **errtest** we can also demonstrate floating point support. You
should already have copied the appropriate floating point emulator
object code into your working directory. For the configuration used in
this example **fpe_32l.o** is the correct object file.

However, in addition to this it is also necessary to link with an fpe
**stub**, which we must compile from the source given (**fpestub.s**).

    armasm fpestub.s -o fpestub.o -li -apcs 3/32bit
    armlink -o errtest errtest.o rtstand.o fpestub.o fpe_32l.o -d

The resulting executable, **errtest**, can be run under **armsd** as
before:

    > armsd -li errtest
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file errtest
    armsd: go
    (the floating point instruction-set is available)
    Using Floating point, but casting to int ...
    10000 / 0X0000000A = 0X000003E8
    10000 / 0X00000009 = 0X00000457
    10000 / 0X00000008 = 0X000004E2
    10000 / 0X00000007 = 0X00000594
    10000 / 0X00000006 = 0X00000682
    10000 / 0X00000005 = 0X000007D0
    10000 / 0X00000004 = 0X000009C4
    10000 / 0X00000003 = 0X00000D05
    10000 / 0X00000002 = 0X00001388
    10000 / 0X00000001 = 0X00002710
    10000 / 0X00000000 = errhandler called: code = 0X80000202: Floating 
    Point
    Exception : Divide By Zero
    
    caller's pc = 0XE92DE000
    returning...
    
    Returning from __err_handler() with errnum = 0X80000202
    
    Program terminated normally at PC = 0x00008558 (__rt_exit + 0x10)
    +0010 0x00008558: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    > 

This time the floating point instruction set is found to be available,
and when a floating point division by zero is attempted,
**\_\_err_handler** is called with the details of the floating point
divide by zero exception.

Note that if you have compiled **errtest.c** other than as in longjmp
and setjmp, you will not see precisely this dialogue with **armsd**.

## Running out of heap

A second example program, **memtest.c** demonstrates how the
standalone runtime system copes with allocating stack space, and also
demonstrates the simple memory allocation function
**\_\_rt_alloc**. Let us first compile this program so that it should
repeatedly request more memory, until there is none left:

    armcc -li -apcs 3/32bit memtest.c -c
    armlink -o memtest memtest.o rtstand.o

This can be run under **armsd** in the usual way:

    > armsd -li memtest
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file memtest
    armsd: go
    kernel memory management test
    force stack to 4KB
    request 0 words of heap - allocate 256 words at 0X000085A0
    force stack to 8KB
    ..
    force stack to 60KB
    request 33211 words of heap - allocate 33211 words at 0X00049388
    force stack to 64KB
    request 49816 words of heap - allocate 5739 words at 0X00069A74
    memory exhausted, 105376 words of heap, 64KB of stack
    Program terminated normally at PC = 0x0000847c
          0x0000847c: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    > 

This demonstrates that allocating space on the stack is working
correctly, and also that the **\_\_rt_alloc** routine is working as
expected. The program terminated because in the end **\_\_rt_alloc**
could not allocate the requested amount of memory.

## Stack overflow checking

**memtest** can also be used to demonstrate stack overflow checking by
recompiling with the macro STACK_OVERFLOW defined. In this case the
amount of stack required is increased until there is not enough stack
available, and stack overflow detection causes the program to be
aborted.

To recompile and link **memtest.c** issue the following commands:

    armcc -li -apcs 3/32bit memtest.c -c -DSTACK_OVERFLOW
    armlink -o memtest memtest.o rtstand.o

Running this program under **armsd** produces the following output:

    > armsd -li memtest
    A.R.M. Source-level Debugger, version 4.10 (A.R.M.) [Aug 26 1992]
    ARMulator V1.20, 512 Kb RAM, MMU present, Demon 1.01, FPE, Little 
    endian.
    Object program file memtest
    armsd: go
    kernel memory management test
    force stack to 4KB
    ...
    force stack to 256KB
    request 1296 words of heap - allocate 1296 words at 0X0000AE20
    force stack to 512KB
    
    run time error: stack overflow
    program terminated
    
    Program terminated normally at PC = 0x0000847c
          0x0000847c: 0xef000011 .... : >  swi     0x11
    armsd: quit
    Quitting
    > 

Clearly stack overlfow checking did indeed catch the case where too
much stack was required, and caused the runtime system to terminate
the program after giving an appropriate diagnostic.

## Extending the standalone runtime system

For a many applications it may be desirable to have access to more of
the standard C library than just the minimal runtime system
provides. This section demonstrates how to take out a part of the
standard C library and plug it into the standalone runtime system.

The function which we will add to **rtstand** is **memmove**. Although
this is small, and easily extracted from the C library source, the
same methodology can be applied to larger sections of the C library,
eg. the dynamic memory allocation system (malloc, free, etc).

The source of the C library can be found in the **cl** directory. The
source for the **memmove** function is in **string.c**. The extracted
source for **memmove** has been put into **memmove.c**, and the
compile time option **\_copywords** has been removed. The function
declaration for **memmove** and a typedef for **size_t** (extracted
from **include/stddef.h**) have been put into **memmove.h**.

Our memmove module can be compiled as follows.

    armcc -c memmove.c -li -apcs 3/32bit

The output, **memmove.o** can be linkedwith the user's other object
modules together with rtstand.o in the normal way (see previous
examples in this section).

## The size of the standalone runtime library

**rtstand.s** has been separated into several code Areas. The
advantage of this is that **armlink** can detect if any Areas are
unreferenced, and then eliminate them from the output image.

The table below shows the typical size of the Areas in **rtstand.o**:

| Area | Size | Functions | (bytes) | |
| --------------------- | ---- | ------------------------- | ------- | ------------ |
| C$$data | 4 | | | |
| C$$code$$__main | 96 | __main, __rt_exit | | |
| C$$code$$__rt_fpavail | 8 | __rt_fpavailable able | | |
| C$$code$$__rt_trap | 128 | __rt_trap | | |
| C$$code$$__rt_alloc | 68 | __rt_alloc | | |
| C$$code$$__rt_stkovf | 76 | __rt_stkovf_split_* | | |
| C$$code$$__jmp | 100 | longjmp, setjmp | | |
| C$$code$$__divide | 256 | __rt_sdiv, __rt_udiv, | | __rt_udiv10, |
| All Areas | 736 | __rt_sdiv10, __rt_divtest | | |

If floating point support is definitely not required, then the
EnsureNoFPSupport variable can be set to {TRUE}, and some extra space
will be saved. After making any modifications to **rtstand.s**, the
size of the various areas can be found by using the command:

    decaof -b rtstand.o

From the above table it is clear that for many applications the
standalone runtime library will be roughly 0.5Kb.

## Related topics

- Register usage under the ARM procedure call standard;
- In-Line SWIs.

# ARM shared libraries

---

## About this recipe

In this recipe you will learn:

- what an ARM shared library is;
- how the shared library mechanism works;
- how to instruct the ARM linker to make a shared library;
- how to make a toy shared library from the string section of the ANSI
  C library.

## About ARM shared libraries

ARM **shared libraries** support the sharing of utility, service or
library functions between several concurrently executing **client**
applications in a single address space. Such shared code is
necessarily **reentrant**.

If a function is reentrant, each of its concurrently active clients
must have a separate copy of the data it manipulates for them. The
data cannot be associated with the code itself unless the data is
read-only. In the ARM shared library architecture, a dedicated
register (called **sb**) is used to address (indirectly) the static
data associated with a client.

An ARM shared library is read only, reentrant and usually position
independent. A shared library made exclusively from object code
compiled by the ARM C compiler will have all three of these
attributes. Library components implemented in ARM Assembly Language
need not be reentrant and position independent, but in practice, only
position independence is inessential.

A library with all three of these attributes in an ideal candidate for
packing into a system ROM.

Some shared library mechanisms associate a shared library's data with
the library itself and put only a place holder in the stub. At run
time, a copy of the library's initialised static data is copied into
the client's place holder by the dynamic linker or by library
initialisation code.

The ARM shared library mechanism supports these ways of working
provided the data is free of values which require link-time (or run
time) relocation. In other words, it can be supported provided the
input data areas are free of relocation directives.

## How ARM shared libraries work

### Stubs and proxy functions

When a client application is linked with a shared library, it is
linked not with the library itself but with a *stub object*
containing:

- an **entry vector**;
- a copy of the library's static data or a place holder for it.

Each member of the entry vector is a **proxy** for a function in the
matching shared library.

When a client **first** calls a **proxy** function, the call is
directed to a **dynamic linker**. This is a small function (typically
about 50-60 ARM instructions) which:

- locates the matching shared library;
- if required, copies an initial image of the library's static data
  from the library to the place holding area in the stub;
- patches the entry vector so each proxy function points at the
  corresponding library function;
- resumes the call.

Once an entry vector has been patched, all future proxy calls proceed
directly to the target library function with only minimal indirection
delay and no intervention by the dynamic linker.

Of course, making an **inter-link-unit** call like this **is** more
expensive than making a straightforward local procedure call, but not
a lot so. It is also the only supported way to call a function more
than 32MBytes away.

## Locating a library which matches the stub

Locating a matching shared library is specific to a target system and
you must provide code to do the location, but the remainder of the
dynamic linking process is generic to all target
systems. Consequently, in order to use ARM shared libraries, you have
to design and implement a library location mechanism and adapt the
dynamic linker to it. In practice, this is quite straightforward:

- the ARM Linker provides support for parameterising a location
  mechanism;
- a basic dynamic linker with neither location nor failure reporting
  mechanisms is a mere 42 ARM instructions.

Please refer to [ARM shared library
format](../arrfldr/3arrj.html#XREF31382) for a full explanation of
parameter blocks.

### How the dynamic linker works

The dynamic linker is entered via a proxy call with r0 pointing at the
dynamic linker's 16-byte entry stub. Following this stub code is a
copy of the parameter block for the shared library.

Stored in the parameter block is the identity of the library - perhaps
a 32-bit unique identifier or perhaps a string name. Either way, it
can be passed to the library location mechanism. You have to decide
how to identify your shared libraries and, hence, what to put in their
parameter blocks.

The library location function is required to return the address of the
start of the library's offset table.

A primitive location mechanism might be to search a ROM for a matching
string. This would identify the start of the parameter block of the
matching shared library. Immediately preceding it will be negative
offsets to library entry points and a non-negative count word
containing the number of entry points. By working backwards through
memory and counting, you can be sure you have found the entry vector
and can return the address of its count word to the dynamic linker.

More sophisticated location schemes are possible, for example:

- You might include in your library a header containing code to
  execute when the library is first loaded (into RAM) or initialised
  (in ROM) which registers the library's name with a library
  manager. Obviously, the library manager has to be locatable without
  using the library manager, so either it's address has to be known or
  its function has to be supported by an underlying system call.
- Acorn's RISC OS operating system supports a **module** mechanism
  which is sometimes used to implement shared libraries. A RISC OS
  module may, by declaring so in its module header, be called when
  software interrupts (SWIs) in a declared range occur. When such a
  module is loaded, it extends the range of SWIs interpreted by RISC
  OS. We can use this mechanism to locate a shared library by storing
  the identity of a library location SWI in the library's parameter
  block and by implementing this SWI in the library module's header.

## Instructing the linker to make a shared library

### Prerequisites

A shared library can be made from any number of object files,
including **reentrant stubs** of other shared libraries, but two
simple rules must be followed:

- each object file must conform to a reentrant version of the ARM
  Procedure Call Standard and each code area must have the REENTRANT
  attribute;
- there may be no unresolved references resulting from linking
  together the component objects.

An immediate consequence of the second rule is that it is impossible
to make two shared libraries which refer to one another: to make the
second library and its stub would require the stub of the first, but
to make the first and its stub would require the stub of the second.

The first rule is not 100% necessary and is difficult to enforce. The
ARM Linker warns you if it finds a non-reentrant code area in the list
of objects to be linked into a shared library but it will build the
library and its matching stub anyway. You have to decide whether the
warning is real, or merely a formality.

### Linker outputs

The ARM linker generates a shared library as two files:

- a plain binary file containing the read-only, reentrant, usually
  position independent, shared code;
- an AOF format **stub** file with which client applications can be
  linked.

The linker can also generate a reentrant stub suitable for inclusion
in another shared library.

The library image file contains, in order:

- read only code sections from your input objects;
- if so requested, a read only copy of the initialised static data
  from the input objects;
- a table of (negative) offsets from the end of the library to its
  entry points;
- if so requested, the size and offset of the static data image;
- a copy of the library's **parameter block**.

You request a copy of the initialised static data to be included in a
library when you describe to the linker how to make a shared
library. If you request this, the linker writes the length and offset
of the data image immediately after the entry vector. During linking,
**armlink** defines symbols SHL\$\$data\$\$Size and
SHL\$\$data\$\$Base to have these values; components of your library
may refer to these symbols. Instead of including the static data in
the stub **armlink** includes a zero initialised place holding area of
the same size. It also writes the length and (relocatable) address of
this place holding, zero initialised stub data area immediately after
the dynamic linker's entry veneer, giving the dynamic linker
sufficient information to initialise the place holder at run
time. During linking, the linker symbols SHL\$\$data\$\$Size and
\$\$0\$\$Base describe this length and relocatable address.

Obviously, any data included in your shared library must be free of
relocation directives. Please refer to [ARM shared library
format](../arrfldr/3arrj.html#XREF31382) for a full explanation of
what kind of data can be included in a shared library.

You specify a parameter block when you describe to the linker how to
make a shared library. You might, for example, include the name of the
library in its parameter block, to aid its location. An identical copy
of the parameter block is included in the library's entry vector in
the stub file.

### Describing a shared library to the linker

To describe a shared library to the linker you have to prepare a file
which describes:

- the name of the library;
- the library parameter block;
- what data areas to include;
- what entry points to export.

For precise details of how to do this, please refer to [ARM shared
library format](../arrfldr/3arrj.html#XREF31382). Below is an
intuitive example you can work with and adapt:

    ; First, give the name of the file to contain the library -
    ; strlib - and its parameter block - the single word 0x40000...
    > strlib \
      0x40000
    ; ...then include all suitable data areas...
    + ()
    ; ... finally export all the entry points...
    ; ... mostly omitted here for brevity of exposition.
    memcpy
    ...
    strtok

The name of this file is passed to **armlink** as the argument to the
-SHL command line option (please refer to the chapter [The ARM Linker
(armlink)](../augfldr/aug3frst.html#XREF21025) for further details).

## Making a toy string library

This section refers to the files collected in the **strlib**
subdirectory of the **examples** directory of the release.

The header files **config.h** and **interns.h** let you compile
cl/string.c locally. Little-endian code is assumed. If you want to
make a big-endian string library you should edit config.h. Similarly,
if you want to alter which functions are included or whether static
data is initialised by copying from the library, then you should edit
config.h. You do not need to edit interns.h. If you use config.h
unchanged you will build a little-endian library which includes a data
image and which exports all of its functions.

### Compiling the string library

To compile string.c, use the following command:

    armcc -li -apcs /reent -zps1 -c -I. ../../cl/string.c

The **-li** flag tells **armcc** to compile for a little-endian ARM.

The **-apcs /reent** flag tells **armcc** to compile reentrant code.

The **-zps1** flag turns off software stack limit checking and allows
the string library to be independent of all other objects and
libraries. With software stack limit checking turned on, the library
would depend on the stack limit checking functions which, in turn,
depend on other sections of the C run time library. While such
dependencies do not much obstruct the construction of full scale,
production quality shared libraries, they are major impediments to a
simple demonstration of the underlying mechanisms.

The **-I.** flag tells **armcc** to look for needed header files in
the current directory.

### Linking the string library

To make a shared library and matching stub from string.o, use the
following linker command:

    armlink -o strstub.o -shl strshl -s syms string.o

**strlib**'s stub will be put in **strstub.o** as directed by the -o
option.

The file **strshl** contains instructions for making a shared library
called **strlib**. A shortened version of it was shown in the earlier
section "Describing a shared library to the linker."

The option **-s syms** asks for a listing of symbol values in a file
called **syms**. You may later need to look up the value of
EFT\$\$Offset (it will be 0xA38 if you have changed nothing). As
supplied, the dynamic linker expects a library's extenal function
table (EFT) to be at the address 0x40000. So, unless you extend the
dynamic linker with a library location mechanism (please refer to the
discussion in the earlier section How the dynamic linker works), you
will have to load **strlib** at the address 0x40000-EFT\$\$Offset.

### Making the test program and dynamic linker

Now you should assemble the dynamic linker and compile the test code:

    armasm -li dynlink.s dynlink.o
    armcc -li -c strtest.c

You can extend the test code to probe lots of string functions, but
this is left as an exercise to help you understand what is going on.

To make the test program you must link together the test code, the
dynamic linker, the string library stub and the appropriate ARM C
library (so that references to library members other than the string
functions can be resolved):

armlink -d -o strtest strtest.o dynlink.o strstub.o
../../lib/armlib.32l

### Running the test program with the shared string library

Now you are ready to try everything under the control of command-line
armsd:

    A.R.M. Source-level Debugger version ...
    ARMulator V1.30, 4 Gb memory, MMU present, Demon 1.1,...
    Object program file strtest
    armsd: getfile strlib 0x40000-0xa38
    armsd: go
    
    strerror(42) returns unknown shared string-library error 0x0000002A
    
    Program terminated normally at PC = 0x00008354 (__rt_exit + 0x24)
    +0024 0x00008354: 0xef000011 .... :    swi      0x11
    armsd: q
    Quitting

Before starting **strtest** you must load the shared string library by
using:

    getfile strlib 0x40000-0xa38

**strlib** is the name of the file containing the library; 0x40000 is
the hard wired address at which the dynamic linker expects to find the
external function table; and 0xa38 is the value of EFT\$\$Offset, the
offset of the external function table from the start of the library.

When **strtest** runs, it calls **strerror(42)** which causes the
dynamic linker to be entered, the static data to be copied, the stub
vector to be patched and the call to be resumed. You can watch this is
more detail by setting a breakpoint on \_\_rt_dynlink and single
stepping.

## Suggested further exercises

### Library location mechanisms

Locating a library's EFT at 0x40000 is not very satisfactory, so an
obvious exercise is to extend the dynamic linker to locate a library
by looking for it. Try, for example, adding a header to the start of
the library which contains:

- offset to the next loaded library or 0
- the total length of the library
- the offset to the external function table
- the string name of the library

Hint: when you link this area with the other library contents you have
to ensure that it wil precede all other areas in the library. Please
refer to [Area placement and sorting
rules](../arrfldr/3arrc.html#XREF13307) for further details.

Your dynamic linker could now search a list of libraries loaded at
0x40000 onwards.

### Self-loading libraries

You could extend the header mechanism described in the previous
subsection so that a library could copy itself to the next free
location above 0x40000. This would allow libraries to be loaded at
0x8000 and 'executed' there. Of course, you would want your header to
begin with a branch to the code which will copy the library from
0x8000 to its destination above 0x40000.

### Multiple shared libraries

Once you have built location and loading mechanisms, you can build
more than one shared library. Try making one of your own and linking a
test program with the stubs of two or more libraries.

### Inter-library calls

Once you have multiple libraries working, you can try making one
library call functions in another (but remember that if library A
refers to library B then library B **may not** refer to library A). To
do this you will have to make a reentrant stub for the library you
wish to refer to and link this into the library making the reference.

## Related topics

- Register usage under the ARM procedure call standard
