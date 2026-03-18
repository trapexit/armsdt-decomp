# ARM Assembly Language

ARM Assembly Language is the language which *armasm*, the ARM
Assembler, parses and compiles to produce object code in ARM Object
Format. This chapter details ARM Assembly Language, but does not give
examples of its use. For such examples refer to the Cookbook.

## Overview

### General

Instruction mnemonics and register names may be written in upper or
lower case (but not mixed case). Directives must be written in upper
case.

### Input lines

The general form of assembler input lines is:

```text
{label} {instruction} {;comment}
```

A space or tab should separate the label, where one is used, and the
instruction. If no label is used, the line must begin with a space or
tab. Any combination of these three items will produce a valid line;
empty lines are also accepted by the assembler and can be used to
improve the clarity of source code.

Assembler source lines are allowed to be up to 255 characters long. To
make source files easier to read, a long line of source can be split
onto several lines by placing a backslash character, `', at the end of
a line. The backslash must not be followed by any other characters
(including spaces or tabs). The backslash + end of line sequence is
treated by *armasm* as white space. Note that the backslash + end of
line sequence should not be used within quoted strings.

### AREAs

AREAs are the independent, named, indivisible chunks of code and data
manipulated by the Linker. The Linker places each AREA in a program
image according to the AREA placement rules (ie. not necessarily
adjacent to the AREAs with which it was assembled or compiled).

Conventionally, an assembly, or the output of a compilation, consists
of two AREAs, one for the code (usually marked read-only), and one for
the data which may be written to. A reentrant object will generally
have a third AREA marked BASED sb (see below), which will contain
relocatable address constants. This allows the code area to be
read-only, position-independent and reentrant, making it easily
ROM-able.

In ARM assembly language, each AREA begins with an AREA directive. If
the AREA directive is missing the assembler will generate an AREA with
an unlikely name (|$$$$$$$|) and produce a diagnostic message to this
effect. This will limit the number of spurious errors caused by the
missing directive, but will not lead to a successful assembly.

The syntax of the AREA directive is:

```text
AREA name
```

You may choose any name for your AREAs, but certain choices are
conventional. For example, `|C$$code|` is used for code AREAs produced
by the C compiler, or for code AREAs otherwise associated with the C
library.

AREA Attributes are as follows:

| Attribute | Description |
| --- | --- |
| ABS | Absolute: rooted at a fixed address. |
| REL | Relocatable: may be relocated by the Linker (the default). |
| PIC | Position Independent Code: will execute where loaded without modification. |
| CODE | Contains machine instructions. |
| DATA | Contains data, not instructions. |
| READONLY | This area will not be written to. |
| COMDEF | Common area definition. |
| COMMON | Common area. |
| NOINIT | Data AREA initialised to zero: contains only space reservation directives, with no initialised values. |
| REENTRANT | The code AREA is reentrant. |
| BASED Rn | Static base data AREA containing tables of address constants locating static data items. Rn is a register, conventionally R9. Any label defined within this AREA becomes a register-relative expression which can be used with LDR and STR instructions. |
| ALIGN=expression | The ALIGN sub-directive forces the start of the area to be aligned on a power-of-two byte-address boundary. By default AREAs are aligned on a 4-byte word boundary, but the expression can have any value between 2 and 12 inclusive. |

### ORG and ABS

```text
ORG
```

The ORG (origin) directive is used to set the base address and the ABS
(absolute) attribute of the containing AREA, or of the following AREA
if there is no containing AREA. In some circumstances this will create
objects which cannot be linked. In general it only makes sense to use
ORG in programs consisting of one AREA, which need to map fixed
hardware addresses such as trap vector locations. Otherwise ORG should
be avoided.

### Symbols

Numbers, logical values, string values and addresses may be
represented by symbols. Symbols representing numbers or addresses,
logical values and strings are declared using the GBL and LCL
directives, and values are assigned immediately by SETA, SETL and SETS
directives respectively (see "Local and global variables - GBL, LCL
and SET"). Addresses are assigned by the Assembler as assembly
proceeds, some remaining in symbolic, relocatable form until link
time.

Symbols must start with a letter in either upper or lower case; the
assembler is case-sensitive and treats the two forms as
distinct. Numeric characters and the underscore character may be part
of the symbol name. All characters are significant.

Symbols should not use the same name as instruction mnemonics or
directives. While the assembler can distinguish between the uses of
the term through their relative positions in the input line, a
programmer may not always be able to do so.

Symbol length is limited by the 255 character line length limit.

If there is a need to use a wider range of characters in symbols, for
instance when working with other compilers, use enclosing bars to
delimit the symbol name; for example, `|C$$code|`. The bars are not
part of the symbol.

### Labels

Labels are a special form of symbol, distinguished by their position
at the start of lines. The address represented by a label is not
explicitly stated but is calculated during assembly.

### Local labels

The local label, a subclass of label, begins with a number in the
range 0-99. Local labels work in conjunction with the ROUT directive
and are most useful for solving the problem of macro-generated
labels. Unlike global labels, a local label may be defined many times;
the assembler uses the definition closest to the point of
reference. To begin a local label area use:

```text
{label}
```

The label area will start with the next line of source, and will end
with the next ROUT directive or the end of the program.

Local labels are defined as:

```text
number{routinename}
```

although *routinename* need not be used; if omitted, it is assumed to
match the label of the last ROUT directive. It is an error to give a
routine name when no label has been attached to the preceding ROUT
directive.

A reference to a local label has the following syntax:

```text
%{x}{y}n{routinename}
```

`%` introduces the reference and may be used anywhere where an ordinary
label reference is valid.

`x` tells the assembler where to search for the label; use *B* for
backward or *F* for forward. If no direction is specified the
assembler looks both forward and backward. However searches will never
go outside the local label area (i.e. beyond the nearest ROUT
directives).

`y` provides the following options: *A* to look at all macro levels,
*T* to look only at this macro level, or, if *y* is absent, to look at
all macro from the current level to the top level.

`n` is the number of the local label.

`routinename` is optional, but if present it will be checked against
the enclosing ROUT's label.

### Comments

The first semi-colon on a line marks the beginning of a comment,
except where the semi-colon appears inside a string constant. A
comment alone is a valid line. All comments are ignored by the
assembler.

### Constants

#### Numbers

Numeric constants are accepted in three forms: decimal (e.g. 123),
hexadecimal (e.g. &7B), and n_xxx, where n is a base between 2 and 9
and xxx is a number in that base.

#### Strings

Strings consist of opening and closing double quotes, enclosing
characters and spaces. If double quotes or dollar signs are used
within a string as literal text characters, they should be represented
by a pair of the appropriate character; e.g. $$ for $.

#### Boolean

The Boolean constants `true` and `false` should be written as `{TRUE}`
and `{FALSE}`.

### The END directive

Every assembly language source must end with:

```text
END
```

on a line by itself.

## The ARM instruction set

The ARM instruction set, describedin this section, may be subject to
processor-specific restrictions and changes. Particular combinations
of instructions must be avoided where noted, as unpredictable results
may otherwise occur. Refer to the appropriate ARM processor datasheet
for a precise definition of the instruction set, and also refer to
companion application notes for information on relevant restrictions
and changes.

The most significant variations are those between ARM processors with
26- and 32-bit program counters.

### Conditional execution and the `S` bit

All ARM instructions are conditional and are only executed if their
condition field matches the N, Z, C and V condition flags of the
program status register (PSR). For full details of the processor
status flags refer to the ARM Datasheet for the appropriate ARM
device. The default condition field setting is *execute* *always*;
other conditions are specified by appending a two-character condition
mnemonic to the instruction mnemonic. A conditionally executed
sequence of instructions will usually be shorter and sometimes even
faster than a branched-around sequence, because it will not cause
breaks in the CPU pipeline.

| Mnemonic | Condition | CPU condition flags |
| --- | --- | --- |
| EQ | EQual | Z set |
| NE | Not Equal | Z clear |
| CS | Carry Set/unsigned Higher or Same | C set |
| CC | Carry Clear/unsigned LOwer than | C clear |
| MI | Negative (MInus) | N set |
| PL | Positive (PLus) | N clear |
| VS | oVerflow Set | V set |
| VC | oVerflow Clear | V clear |
| HI | HIgher unsigned | C set and Z clear |
| LS | Lower or Same unsigned | C clear or Z set |
| GE | Greater than or Equal to | (N and V) set or (Nand V) clear |
| LT | Less Than | (N set and V clear) or (N clear and V set) |
| GT | Greater Than | ((N and V) set or clear) and Z clear |
| LE | Less Than or equal to | (N set and V clear) or (N clear and V set) or Z set |

HS (Higher or Same) and LO (LOwer than) are synonyms for CS and CC respectively.

Condition flags are set by executed ALU instructions which have the
`S` bit set, and by executed comparison instructions. The S bit is set
by appending `S` to the instruction mnemonic.

### Register Names and `.'

Fifteen registers (R0 to R14), the program counter (PC), and the
processor status register (PSR), are all directly accessible to the
programmer. Register R15 contains the PC, and in 26-bit address ARMs
it contains the PSR too. In 32-bit address ARMs the PSR is separate,
and is manipulated by separate instructions.

R14 is used as the subroutine link register, saving a copy of R15 when
a *Branch with Link* instruction is executed (see "Branch
instructions - B and BL"). R13 is conventionally used as a stack
pointer.

The non-user processor modes each have their own R13 and R14, and in
32-bit ARMs, PSR registers. FIQ mode additionally has its own
R8-R12. When a mode change occurs, because of interrupts, SWIs or
traps, R14 of the new mode is set to a copy of R15, and in 32-bit ARMs
the PSR of the new mode is copied from the PSR of the old mode. For
further details of banked registers and mode changes, consult the
appropriate ARM datasheet for the target processor.

Within an assembly language source, the current value of the program
counter (PC) can be referred to as `.`. Usually, `.` is 8 bytes ahead
of the instruction using it because of pipelining. For example:

```text
LDR R0,[.-8+offset]
```

loads a word at *offset* bytes from the current instruction. Please
refer to the appropriate ARM datasheet for precise details.

### Branch instructions

The syntax of these instructions is:

```text
B{L}{condition} expression
```

where the *expression* evaluates to the branch destination address. If
the address is within ± 32MB of the current program counter, it can be
expressed directly as an offset. On 32-bit address ARMs, branches of
more than 32MB have to be effected by loading the destination address
directly into the PC, or by adding a long offset to the PC using a
value loaded into a register. *Branch with Link* saves the PC into R14
of the current bank. To return, use:

```text
MOV    PC, R14
```

or

```text
LDMFD  SP!, {...,PC}
```

if the link register has been saved on a stack. Note that these
instructions will not restore the original PSR.

The assembler automatically compensates for the effects of pipelining
and prefetching when calculating offsets.

### Data processing instructions

The syntax of these instructions is:

```text
opcode{condition}{S} destination,operand2
```

The *destination* must be a register. *Operand2* may be any of:

- An 8-bit immediate constant, rotated right by a constant 0, 2,
  4...30 bits. Assembler syntax:

```text
#constant-expression{,constant-rotation}
```

- A register shifted left, shifted logically right, shifted
  arithmetically right, or rotated right by a constant 0...31
  bits. Assembler syntax:

```text
register {,shift #constant-expression}
```

- where shift is one of:

```text
LSL        Shift left
    LSR        Logical shift right
    ASR        Arithmetic shift right
    ROR        rotate right
```

- A register, shifted as above by the amount given in another
  register. Assembler syntax:

```text
register {,shift register}
```

- A register rotated 1 bit right through the carry flag, (a 1 bit
  rotate right of a 33-bit value, after which the most significant bit
  of the register is the old value of the carry flag). The assembler
  syntax in this case is:

```text
register, RRX
```

For simple constants (e.g. #&FC000003), the assembler will generate
the appropriate rotation for you.

### Data processing instructions

The syntax of this group of instructions is:

```text
opcode{condition}{S} destination,operand1,operand2
```

The *destination* and *operand1* must both be registers, and
*operand2* should be as described for the MOV and MVN instructions
(see [Data processing instructions - MOV and
MVN](#data-processing-instructions)).

With ADD and ADC a carry is generated by 32-bit overflows; for
subtractions it is generated if, and only if underflow did not occur.

With ADD, ADC, SUB, SBC, RSB and RSC the V flag is set if signed
overflow occurred, i.e. when the carry into bit 31 was not equal to
the carry out of that bit.

### Data processing instructions

The N and C flags may also be affected if a shift or rotation was
involved in the construction of *operand2*

The syntax of these instructions is:

```text
opcode{condition}{P} operand1,operand2
```

Each of these instructions preserves its operands and produces no
result other than updated PSR flags. *Operand1* must be a register,
and *operand2* must be as described for MOV and MVN (see [Data
processing instructions - MOV and
MVN](#data-processing-instructions)).

If *P* is not specified, the PSR condition flags are set to the ALU
condition flags after the operation (as described above), and the
instructions behave as conventional status-setting comparisons.

With 26-bit ARMs, use of *P* allows direct manipulation of the PSR, as
described below. *P* must not be used with 32-bit ARMs: instead use
MSR and MRS (see section [PSR transfer - MSR and MRS](#psr-transfer)).

In 26-bit user mode, `{`*opcode*`}P` moves the result of the operation
to the PSR, and sets the N, Z, C and V flags from the top four bits of
the result. In other 26-bit modes it sets the N, Z, C, V, I and F
flags from the top six bits, and the mode bits from the bottom two
bits of the result. A typical use of `{`*opcode*`}P` would be to
change modes.

### PSR transfer

The syntax of these instructions is:

```text
MSR
```

```text
MRS
```

These instructions are available on 32-bit ARMs only. R15 cannot be
used as the destination register. Please refer to your ARM datasheet
for precise details.

*psrl* can be one of CPSR, CPSR_all, CPSR_flg, CPSR_ctl, SPSR,
SPSR_all, SPSR_flg, or SPSR_ctl. (CPSR and CPSR_all are synonyms as
are SPSR and SPSR_all).

*psrs* can be one of SPSR, SPSR_all, CPSR or CPSR_all.

*Operand2* is as described in section ""Data processing instructions -
MOV and MVN".

In user mode the instructions behave as follows:

```text
MSR CPSR_all, op2                    ; CPSR{N,Z,C,V} <- op2
MSR CPSR_flg, op2                    ; CPSR{N,Z,C,V} <- op2
MSR CPSR_ctl, op2                    ; No effect
MRS Rd, CPSR                    ; Rd <- CPSR{N,Z,C,V,I,F,M[4:0]}
MSR SPSR, op2                    ; Not valid in user mode
MRS Rd, SPSR                    ; Not valid in user mode
```

In privileged modes the instructions behave as follows:

```text
MSR CPSR_all, op2                    ; CPSR{N,Z,C,V,I,F,M[4:0]} <- op2
MSR CPSR_flg, op2                    ; CPSR{N,Z,C,V} <- op2
MSR CPSR_ctl, op2                    ; CPSR{I,F,M[4.0]} <- op2
MRS Rd, CPSR                    ; Rd <- CPSR{N,Z,C,V,I,F,M[4:0]}
MSR SPSR_all, Rm                    ; SPSR_mode{N,Z,C,V,I,F,M[4:0]} <- op2
MSR SPSR_flg, Rm                    ; SPSR_mode{N,Z,C,V} <- op2
MSR SPSR_ctl, Rm                    ; SPSR_mode{I,F,M[4.0]} <- op2
MRS Rd, SPSR                    ; Rd <- SPSR_mode{N,Z,C,V,I,F,M[4:0]}
```

### Single data transfer

These instructions come in two forms called pre-indexed and post-indexed. The syntax of pre-indexed instructions is:

```text
opcode{condition}{B} register,[base{,index}]{!}
```

Post-indexed instructions take the form:

```text
opcode{condition}{B} register,[base]{,index}
```

*B* specifies a byte instead of a word transfer (i.e. 8 bits instead of 32). *Register* is the destination of the load or source of the store. *Base* must be a register; for pre-indexed addressing, *index* is added to it to yield the load or store address; with post-indexed addressing, *base* gives the address for the load or store, and *base*+*index* is the value written back to *base*. In the pre-indexed case *!* enables writeback of *base*+*index* to base.

Index may be one of the following:

```text
#{-}12-bit-constant-expression
{-}register {, shift #5-bit-constant-expression}
```

(*Shift* is explained in section [Data processing instructions - MOV and MVN](#data-processing-instructions). In this second form the value of *index* is the value in *register* shifted as specified.

LDR can also used to generate literal constants, program counter relative constant addresses and external addresses. The syntax is:

```text
LDR register,=expression
```

If expression is a numeric constant, then a MOV or MVN will be used rather than an LDR if the constant can be constructed by either of these instructions. Otherwise, the assembler will generate a program-relative LDR, and if the desired literal does nor already exist within the addressable range of this LDR, it will place the literal in the next literal pool, (see also LTORG [Organisational directives - END, ORG, LTORG and KEEP](#organisational-directives).

Additionally, LDR or STR can be used to transfer data to or from an address specified by a label (optionally with an offset) as follows:

```text
opcode{cond}{B} register,label-expression
```

When used in this form, *label expression* must either be addressable PC-relative from this instruction, or must be a register-relative label created using the `^' directive with a register operand, (see section [Describing the layout of store - ^ and #](#describing-the-layout-of-store)).

### Block data transfer

The syntax of these instructions is:

```text
opcode{condition}type base{!},register-list{^}
```

The opcode is combined with one of eight instruction types with the mnemonics DB, DA, IB, IA, FD, ED, FA, and EA; the meaning of FD, ED FA and EA varies according to whether a load or store is performed. In detail:

| Instruction | Meaning |
| --- | --- |
| STMDB | Decrement base Before the store |
| STMDA | Decrement base After the store |
| STMIB | Increment base Before the store |
| STMIA | Increment base After the store |
| LDMDB | Decrement base Before the load |
| LDMDA | Decrement base After the load |
| LDMIB | Increment base Before the load |
| LDMIA | Increment base After the load |
| STMFD | Push registers to a Full stack, Descending (STMDB) |
| STMED | Push registers to an Empty stack, Descending (STMDA) |
| STMFA | Push registers to a Full stack, Ascending (STMIB) |
| STMEA | Push registers to an Empty stack, Ascending (STMIA) |
| LDMFD | Pop registers from a Full stack, Descending (LDMIA) |
| LDMED | Pop registers from an Empty stack, Descending (LDMIB) |
| LDMFA | Pop registers from a Full stack, Ascending (LDMDA) |
| LDMEA | Pop registers from an Empty stack, Ascending (LDMDB) |

A full stack is one in which the stack pointer points to the last data item written to it, and an empty stack is one where the stack pointer points to the first free slot in it. A descending stack grows from high memory addresses to low, and an ascending stack vice versa.

*Base* contains the starting address for the transfer and can be any register except R15. If present *!* requests writeback of the updated base address to *base* after the instruction is executed.

*Register-list* is a comma-separated list of registers, or register ranges enclosed in {}. A register range is two register names joined by a hyphen, and represents the registers named and all those between them. The directive RLIST (see section [Miscellaneous directives - ALIGN, NOFP, RLIST and ENTRY](#miscellaneous-directives)) can also be used to create a list of registers to be used. In user mode ^ sets the S bit to load the PSR along with the PC; in privileged modes it forces transfer of the user mode registers.

### Multiplies

The syntax of these instructions is:

```text
MUL{condition}{S} destination,operand1,operand2
MLA{condition}{S} destination,operand1,operand2,operand3
```

The *destination* and all operands must be registers. MUL multiplies *operand1* by *operand2*, and places the result in the destination register. MLA multiplies *operand1* by *operand2*, adds *operand3* to the product and places the result in the destination register. Both instructions work with signed and unsigned integers. For details of how to make multiply instructions execute quickly, see the appropriate ARM datasheet, or the Cookbook.

Certain combinations of operands should be avoided and are warned against by the assembler. The destination register should not be the same as *operand1* as this will give a meaningless result. R15 should not be used as a destination register, nor as an operand. See the appropriate ARM datasheet for further details.

### Single data swap

SWP swaps a byte or word quantity between a register and memory, locking the memory bus in the process to preserve atomic operation (where supported by external hardware). The syntax is:

```text
SWP{condition}{B} destination,source,[base]
```

*Destination*, *source* and *base* must all be registers. *B* sets the width of the transfer to byte rather than word. The memory address is that in *base*; its contents are read, the source register is written to it, and the old memory contents are then stored in *destination*. The same register can serve as *source* and *destination*. R15 may not be used as the swap address, the *source* or the *destination*.

### Software interrupt/supervisor call

This instruction is used by programs to communicate with the host operating system. The syntax is:

```text
SWI constant-expression
```

The expression value is truncated to 24 bits (i.e. between &0 and &FFFFFF); it is ignored by the processor but is interpreted by operating system software.

### Pseudo-instructions

The Assembler supports several pseudo-instructions which are translated into the appropriate combination of ARM instructions at assembly time.

| Pseudo-instruction | Meaning |
| --- | --- |
| ADR | Assemble address to register |

Because the ARM has no `load effective address' instruction the assembler provides ADR, which will always assemble to produce ADD, SUB, MOV or MVN instructions to generate the address. The syntax is:

```text
ADR{condition}{L} register,expression
```

The *expression* can be register-relative, program-relative or numeric. ADR must assemble to one instruction, whereas ADRL allows a wider range of effective addresses to be assembled in two instructions..

| Pseudo-instruction | Meaning |
| --- | --- |
| NOP | No operation |

This generates the preferred *no-operation* code for a given ARM processor, which is often *MOV R0,R0*. NOP is really a directive and so cannot be used conditionally; not executing a *no-operation* is the same as executing it, so conditional execution is pointless.

## Generic coprocessor instructions

These are the generic coprocessor instructions implemented by all ARM processors with a coprocessor interface. Up to 16 coprocessors can be supported; all coprocessors have a number (CP#) in the range 0 to 15, and this must be specified in the instructions. Coprocessor 15 is used for cache, write-buffer and memory management control in several ARM processors, while coprocessors 1 and 2 are conventionally floating point units.

Coprocessors may have up to 16 directly addressable registers, C0-C15.

### Coprocessor data transfers

These instructions transfer data between a coprocessor and memory. The syntax is:

```text
op{condition}{L} CP#,Cd,[Rn {,#offset}]{!}
            [Rn],#offset
```

The memory address can be expressed in one of three ways, as shown above. In the first, pre-indexed form, an ARM register, *Rn*, holds the base address to which an offset can be added if necessary. Writeback of the effective address to *Rn* can be enabled using *!*. The offset must be divisible by 4, and within the range -1020 to 1020 bytes. With the second, post-indexed form, write-back of Rn+*offset* to Rn after the transfer, is automatic. Alternatively, a *program-or-register-relative-expression* can be used, in which case the assembler will generate a PC- or register-relative, pre-indexed address; if it is out of range an error will result.

*L* appended to the instruction specifies a long transfer; otherwise a short transfer takes place. The meaning of this is coprocessor-specific.

### Coprocessor data operations

This instruction is used for internal coprocessor operations. The syntax is:

```text
CDP{condition} CP#,CPOp,CRd,CRn,CRm{,CPOp2}
```

*CPOp* represents the coprocessor operation to be performed (four bits); details of such operations are coprocessor-specific and can be found in the appropriate datasheet. The operation is performed on *CRn* and *CRm* and the result written to *CRd*. The second, optional, *CPOp2* field allows further variations on the operation (three bits).

### Coprocessor register transfers

The syntax of these two instructions is:

```text
op{condition} CP#,CPOp,Rd,Cn,Cm{,CPOp2}
```

*CPOp* is a 3-bit constant which specifies which variant of the instruction to perform. The selected operation is performed using the coprocessor registers *Cn* and *Cm*, and the result transferred to the ARM register *Rd*. If R15 is specified as the destination, only bits 28-31 of the result are transferred and are used to set the N, Z, C and V flags in the PSR without affecting the program counter. *CPOp2*, where present, is a 3-bit constant which sets the ARM condition flags, supporting the further coprocessor-specific sub-operations.

MRC is often used to read a coprocessor's status register(s), while MCR is used to write its control register(s). MRC, with R15 as the destination, supports execution of ARM code conditional on the result of an earlier coprocessor operation, (e.g. floating point compare).

## Floating point instructions

The ARM assembler supports a comprehensive floating point instruction set. Whether implemented by hardware coprocessor or software emulation, floating point operations are performed to the IEEE 754 standard. There are eight floating point registers, numbered F0 to F7. Floating point operations, like integer operations, are performed between registers.

Precision must be specified for many floating point operations where shown as *prec* below. The options are *S* (Single), *D* (Double), *E* (Extended) and *P* (Packed BCD). The format in which extended precision numbers are stored varies between FP implementations, and cannot be relied upon. The rounding mode, shown below as *round*, defaults to `round to nearest', but can optionally be set in the appropriate instructions to: *P* (round to +infinity), *M* (round to -infinity) or *Z* (round to zero).

In all the following instruction patterns, *Rx* represents an ARM register, and *Fx* a floating point register.

### Floating point data transfer

The syntax of these instructions is:

```text
op{condition}prec Fd,[Rn]{,#offset}
            [Rn,#offset]{!}
```

The memory address can be expressed in one of three ways, as shown above. In the first, pre-indexed form, an ARM register *Rn* holds the base address, to which an offset can be added if necessary. Writeback of the effective address to *Rn* can be enabled using *!*. The offset must be divisible by 4, and within the range -1020 to 1020 bytes. With the second, post-indexed form, writeback of Rn+*offset* to Rn after the transfer, is automatic. Alternatively, a program- or register-relative expression can be used, in which case the assembler will generate a PC- or register-relative, pre-indexed address; if it is out of range an error will result.

### Floating point register transfer

The syntax of this instruction is:

```text
FLT{condition}prec{round} Fn,Rd
                          Fn,#built-in-fp-constant
```

where *Rd* is an ARM register and *built-in-fp-constant* is one of 0, 1, 2, 3, 4, 5, 10 or 0.5.

| Opcode | Meaning | Effect |
| --- | --- | --- |
| FIX | Floating point to Integer | Rd:=Fn |

The syntax of this instruction is:

```text
FIX{condition}{round} Rd,Fn
```

### Floating point register transfer

The following instructions transfer values between the FP coprocessor's status and control registers, and an ARM general purpose register.

| Opcode | Meaning | Effect |
| --- | --- | --- |
| WFS | Write Floating point Status | FPSR:=Rd |
| RFS | Read Floating point Status | Rd:=FPSR |
| WFC | Write Floating point Control | FPC:=Rd (privileged modes only) |
| RFC | Read Floating point Control | Rd:=FPC (privileged modes only) |

The syntax of the above four instructions is:

```text
opcode{condition} Rd
```

### Floating point multiple data transfer

(Note that these instructions are not supported by some older versions of the Floating Point Emulator.)

| Opcode | Meaning |
| --- | --- |
| LFM | Load Floating Multiple |
| SFM | Store Floating Multiple |

These instructions are used for block data transfers between the floating point registers and memory. Values are transferred in an internal 96-bit format, with no loss of precision and with no possibility of an IEEE exception occurring, (unlike STFE which may fault on loading a trapping NaN). There are two forms, depending on whether the instruction is being used for stacking operations or not. The first, non-stacking, form is:

```text
op{condition} Fd,count,[Rn]
                 [Rn,#offset]{!}
                [Rn],#offset
```

The first register to transfer is *Fd*, and the number of registers to transfer is *count*. Up to four registers can be transferred, always in ascending order. The count wraps round at F7, so if F6 is specified with four registers to transfer, F6, F7, F0 and F1 will be transferred in that order. With pre-indexed addressing the destination/source register can be specified with or without an *offset* expressed in bytes; writeback of the effective address to *Rn* can be specified with *!*. With post-indexed addressing (the third form above) writeback is automatically enabled. Note that R15 cannot be used with writeback, and that *offset* must be divisible by 4 and in the range -1020 to 1020, as for other coprocessor loads and stores.

The second form adds a two-letter stacking mnemonic (below *ss*) to the instruction and optional condition codes. The mnemonic, FD, denotes a full, descending stack (pre-decrement push, post-decrement pop), while EA denotes an empty, ascending stack (post-increment push, pre-decrement pop). The syntax is as follows:

```text
op{condition}ss Fd,count,[Rn]{!}
```

FD and EA define pre- and post-indexing, and the up/down bit by reference to the form of stack required. Unlike the integer block-data transfer operations, only FD and EA stacks are supported. *!*, if present, enables writeback of the updated base address to Rn; R15 cannot be the base register if writeback is enabled.

The possible combinations of mnemonics are listed below:

| Mnemonic | Meaning |
| --- | --- |
| LFMFD | Load floating multiple from a Full stack, Descending (Post-increment load) |
| LFMEA | Load floating multiple from an Empty stack, Ascending (Pre-decrement load) |
| SFMFD | Store floating multiple to a Full stack, Descending (Pre-decrement store) |
| SFMEA | Store floating multiple to an Empty stack, Ascending (Post-increment store) |

### Floating point comparisons

The syntax of these instructions is:

```text
opcode{condition}{E} Fn,Fm
```

CMF raises no exceptions and should be used to test for equality (Z clear/set) and unorderedness (V set/clear). To comply with IEEE 754, all other tests should use CMFE, which may raise an exception if either of the operands is not a number.

### Floating point binary operations

| Opcode | Meaning | Effect |
| --- | --- | --- |
| ADF | Add | Fd:=Fn+Fm |
| MUF | Multiply | Fd:=Fn*Fm |
| SUF | Subtract | Fd:=FnFm |
| RSF | Reverse Subtract | Fd:=FmFn |
| DVF | Divide | Fd:=Fn/Fm |
| RDF | Reverse Divide | Fd:=Fm/Fn |
| POW | Power | Fd:=Fn to the power of Fm |
| RPW | Reverse Power | Fd:=Fm to the power of Fn |
| RMF | Remainder | Fd:=remainder of Fn/Fm |
| FML | Fast Multiply | Fd:=Fn*Fm |
| FDV | Fast Divide | Fd:=Fn/Fm |
| FRD | Fast Reverse divide | Fd:=Fm/Fn |
| POL | Polar angle | Fd:=polar angle of Fn,Fm =ATN(Fm/Fn) whenever the quotient exists |

The syntax of these instructions is:

```text
binop{condition}prec{round} Fd,Fn,Fm
```

*Fm* can be either a floating point register, or one of the floating point constants #0, #1, #2, #3, #4, #5, #10 or #0.5. Fast operations produce results accurate to only single precision.

### Floating point unary operations

| Opcode | Meaning | Effect |
| --- | --- | --- |
| MVF | Move | Fd:=Fm |
| MNF | Move negated | Fd:=Fm |
| ABS | Absolute value | Fd:=ABS(Fm) |
| RND | Round to integral value | Fd:=integer value of Fm (using current rounding mode) |
| URD | Unnormalised Round: | Fd:= integer value of Fm, possibly in abnormal form |
| NRM | Normalise | Fd:= normalised form of Fm |
| SQT | Square root | Fd:=square root of Fm |
| LOG | Logarithm to base 10 | Fd:=log Fm |
| LGN | Logarithm to base e | Fd:=ln Fm |
| EXP | Exponent | Fd:=eFm |
| SIN | Sine | Fd:=sine of Fm |
| COS | Cosine | Fd:=cosine of Fm |
| TAN | Tangent | Fd:=tangent of Fm |
| ASN | Arc sine | Fd:=arc sine of Fm |
| ACS | Arc cosine | Fd:=arc cosine of Fm |
| ATN | Arc tangent | Fd:=arc tangent of Fm |

The syntax of these instructions is:

```text
unop{condition}prec{round} Fd,Fm
```

*Fm* can be either a floating point register or one of the floating point constants #0, #1, #2, #3, #4, #5, #10 or #0.5.

## Directives

### Storage reservation and initialisation

The syntax of the first three directives is:

```text
{label} directive expression-list
```

DCD can take program-relative and external expressions as well as numeric ones. In the case of DCB, the *expression-list* can include string expressions, the characters of which are loaded into consecutive bytes in store. Unlike C-strings, *armasm* strings do not contain an implicit trailing NUL, so a C-string has to be fabricated thus:

```text
C_string DCB "C_string",0
```

The syntax of *%* is:

```text
{label} % numeric-expression
```

This directive will initialise to zero the number of bytes specified by the *numeric* expression.

Note that an *external expression* consists of an external symbol followed optionally by a constant expression. The external symbol *must* come first.

### Floating point store initialisation

The syntax of these directives is:

```text
{label} directive fp-constant{,fp-constant}
```

Single precision numbers occupy one word, and double precision numbers occupy two; both should be word aligned. An *fp-constant* takes one of the following forms:

```text
{-}integer E{-}integer                            e.g. 1E3, -4E-9
{-}{integer}.integer{E{-}integer}                 e.g. 1.0, -.1, 3.1E6
```

*E* may also be written in lower case.

### Describing the layout of store

The syntax of these directives is:

```text
^ expression{,base-register}{label} # expression
```

The ^ directive sets the origin of a storage map at the address specified by the *expression*. A storage map location counter, @, is also set to the same address. The *expression* must be fully evaluable in the first pass of the assembly, but may be program-relative. If no ^ directive is used, the @ counter is set to zero. @ can be reset any number of times using ^ to allow many storage maps to be established.

Space within a storage map is described by the # directive. Every time # is used its *label* (if any) is given the value of the storage location counter @, and @ is then incremented by the number of bytes reserved.

In a ^ directive with a *base register*, the register becomes implicit in all symbols defined by # directives which follow, until cancelled by a subsequent ^ directive. These register-relative symbols can later be quoted in load and store instructions. For example:

```text
^ 0,r9
    # 4
Lab # 4
    LDR   r0,Lab
```

is equivalent to:

```text
LDR   r0,[r9,#4]
```

### Organisational directives

```text
END
```

The assembler stops processing a source file when it reaches the END directive. If assembly of the file was invoked by a GET directive, the assembler returns and continues after the GET directive (see section [Links to other source files - GET/INCLUDE](#links-to-other-source-files)). If END is reached in the top-level source file during the first pass without any errors, the second pass will begin. Failing to end a file with END is an error.

```text
ORG numeric-expression
```

A program's origin is determined by the ORG directive, which sets the initial value of the program location counter. Only one ORG is allowed in an assembly and no ARM instructions or store initialisation directives may precede it. If there is no ORG, the program is relocatable and the program counter is initialised to 0.

```text
LTORG
```

LTORG directs that the current literal pool be assembled immediately following it. A default LTORG is executed at every END directive which is not part of a nested assembly, but large programs may need several literal pools, each closer to where their literals are used to avoid violating LDR's 4KB offset limit.

```text
KEEP {symbol}
```

The assembler does not by default describe local (*non-exported*, see [Links to other object files - IMPORT and EXPORT](#links-to-other-object-files)) symbols in its output object file. However, they can be retained in the object file's symbol table by using the KEEP directive. If the directive is used alone all symbols are kept; if only a specific symbol needs to be kept it can be specified by name.

### Links to other object files

```text
IMPORT symbol{[FPREGARGS]}{,WEAK}
EXPORT symbol{[FPREGARGS,DATA,LEAF]}
```

IMPORT provides the assembler with a name (symbol) which is not defined in this assembly, but will be resolved at link time to a symbol defined in another, separate object file. The symbol is treated as a program address; if the WEAK attribute is given the Linker will not fault an unresolved reference to this symbol, but will zero the location referring to it. If [FPREGARGS] is present, the symbol defines a function which expects floating point arguments passed to it in floating point registers.

EXPORT declares a symbol for use at link time by other, separate object files. FPREGARGS signifies that the symbol defines a function which expects floating point arguments to be passed to it in floating point registers. DATA denotes that the symbol defines a code-segment datum rather than a function or a procedure entry point, and LEAF that it is a leaf function which calls no other functions.

### Links to other source files

```text
GET filename
INCLUDE filename
```

GET includes a file within the file being assembled. This file may in turn use GET directives to include further files. Once assembly of the included file is complete, assembly continues in the including file at the line following the GET directive. INCLUDE is a synonym for GET.

### Diagnostic generation

```text
ASSERT logical-expression
! arithmetic-expression, string-expression
```

ASSERT supports diagnostic generation. If the *logical expression* returns {FALSE}, a diagnostic is generated during the second pass of the assembly. ASSERT can be used both inside and outside macros.

! is related to ASSERT but is inspected on both passes of the assembly, providing a more flexible means for creating custom error messages. The arithmetic expression is evaluated; if it equals zero, no action is taken during pass one, but the string is printed as a warning during pass two; if the expression does not equal zero, the string is printed as a diagnostic and the assembly halts after pass one.

### Dynamic listing options - OPT

The OPT directive is used to set listing options from within the source code, providing that listing is turned on. The default setting is to produce a normal listing including the declaration of variables, macro expansions, call-conditioned directives and MEND directives, but without producing a pass one listing. These settings can be altered by adding the appropriate values from the list below, and using them with the OPT directive as follows:

| OPT n | Effect |
| --- | --- |
| 1 | Turns on normal listing. |
| 2 | Turns off normal listing. |
| 4 | Page throw: issues an immediate form feed and starts a new page. |
| 8 | Resets the line number counter to zero. |
| 16 | Turns on the listing of SET, GBL and LCL directives. |
| 32 | Turns off the listing of SET, GBL and LCL directives. |
| 64 | Turns on the listing of macro expansions. |
| 128 | Turns off the listing of macro expansions. |
| 256 | Turns on the listing of macro calls. |
| 512 | Turns off the listing of macro calls. |
| 1024 | Turns on the pass one listing. |
| 2048 | Turns off the pass one listing. |
| 4096 | Turns on the listing of conditional directives. |
| 8192 | Turns off the listing of conditional directives. |
| 16384 | Turns on the listing of MEND directives. |
| 32768 | Turns off the listing of MEND directives. |

### Titles - TTL and SUBT

Titles can be specified within the code using the TTL (title) and SUBT (subtitle) directives. Each is used on all pages until a new title or subtitle is called. If more than one appears on a page, only the latest will be used: the directives alone create blank lines at the top of the page. The syntax is:

```text
TTL title
SUBT subtitle
```

### Miscellaneous directives

```text
ALIGN {power-of-two{,offset-expression}}
```

After store-loading directives have been used, the program counter (PC) will not necessarily point to a word boundary. If an instruction mnemonic is then encountered, the assembler will insert up to three bytes of zeros to achieve alignment. However, an intervening label may not then address the following instruction. If this label is required, ALIGN should be used. On its own, ALIGN sets the instruction location to the next word boundary; the optional power-of-two parameter can be used to align with a coarser byte boundary, and the *offset expression* parameter to define a byte offset from that boundary.

```text
NOFP
```

In some circumstances there will be no support in either target hardware or software for floating point instructions. In these cases the NOFP directive can be used to ensure that no floating point instructions or directives are allowed in the code.

```text
RLIST
```

The syntax of this directive is:

```text
label RLIST list-of-registers
```

The RLIST (register list) directive can be used to give a name to a set of registers to be transferred by LDM or STM. *List-of-registers* is a list of register names or ranges enclosed in {} (see [Block data transfer - LDM and STM](#block-data-transfer)).

```text
ENTRY
```

The ENTRY directive declares its offset in its containing AREA to be the unique entry point to any program containing this AREA.

## Symbolic capabilities

### Setting constants

The EQU and * directives are used to give a symbolic name to a fixed or program-relative value. The syntax is:

```text
label EQU expression
label * expression
```

*RN* defines register names. Registers can only be referred to by name. The names R0-R15, r0-r15, PC, pc, LR and lr, are predefined.

*FN* defines the names of floating point registers. The names F0-F7 and f0-f7 are built in. The syntax is:

```text
label RN numeric-expression
label FN numeric-expression
```

*CP* gives a name to a coprocessor number, which must be within the range 0 to 15. The names p0-p15 are pre-defined.

*CN* names a coprocessor register number; c0-c15 are pre-defined. The syntax is:

```text
label CP numeric-expression
label CN numeric-expression
```

### Local and global variables

While most symbols have fixed values determined during assembly, variables have values which may change as assembly proceeds. The assembler supports both global and local variables. The scope of global variables extends across the entire source file while that of local variables is restricted to a particular instantiation of a macro (see [Macros](#macros)). Variables must be declared before use with one of these directives.

| Directive | Meaning |
| --- | --- |
| GBLA | Declares a global arithmetic variable. Values of arithmetic variables are 32-bit unsigned integers. |
| GBLL | Declares a global logical variable |
| GBLS | Declares a global string variable |
| LCLA | Declares and initialises a local arithmetic variable (initial state zero) |
| LCLL | Declares and initialises a local logical variable (initial state false) |
| LCLS | Declares and initialises a local string variable (initial state null string) |

The syntax of these directives is:

```text
directive variable-name
```

The value of a variable can be altered using the relevant one of the following three directives:

| Directive | Meaning |
| --- | --- |
| SETA | Sets the value of an arithmetic variable |
| SETL | Sets the value of a logical variable |
| SETS | Sets the value of a string variable |

The syntax of these directives is:

```text
variable-name directive expression
```

where *expression* evaluates to the value being assigned to the variable named.

### Variable substitution

Once a variable has been declared its name cannot be used for any other purpose, and any attempt to do so will result in an error. However, if the $ character is prefixed to the name, the variable's value will be substituted before the assembler checks the line's syntax. Logical and arithmetic variables are replaced by the result of performing a :STR: operation on them (see [Unary operators](#unary-operators)), string variables by their value.

### Built-in variables

There are seven built-in variables. They are:

| Variable | Meaning |
| --- | --- |
| {PC} or . | Current value of the program location counter. |
| {VAR} or @ | Current value of the storage-area location counter. |
| {TRUE} | Logical constant true. |
| {FALSE} | Logical constant false. |
| {OPT} | Value of the currently set listing option. The OPT directive can be used to save the current listing option, force a change in it or restore its original value. |
| {CONFIG} | Has the value 32 if the assembler is in 32-bit program counter mode, and the value 26 if it is in 26-bit mode. |
| {ENDIAN} | Has the value "big" if the assembler is in big-endian mode, and the value "little" if it is in little-endian mode. |

## Expressions and operators

Expressions are combinations of simple values, unary and binary operators, and brackets. There is a strict order of precedence in their evaluation: expressions in brackets are evaluated first, then operators are applied in precedence order. Adjacent unary operators evaluate from right to left; binary operators of equal precedence are evaluated from left to right.

The assembler includes an extensive set of operators for use in expressions, many of which resemble their counterparts in high-level languages.

### Unary operators

Unary operators have the highest precedence (bind most tightly) so are evaluated first. A unary operator precedes its operand, and adjacent operators are evaluated from right to left.

| Operator | Usage | Explanation |
| --- | --- | --- |
| ? | ?A | Number of bytes generated by line definie label A. |
| BASE | :BASE:A | If A is a PC-relative or register-relative expression then BASE returns the number of its register component and INDEX the offset from that base register. |
| INDEX | :INDEX:A | BASE and INDEX are most likely to be of use within macros. |
| LEN | :LEN:A | Length of string A |
| CHR | :CHR:A | ASCII string of A |
| STR | :STR:A | Hexadecimal string of ASTR returns an eight-digit hexadecimal string corresponding to a numeric expression, or the string T or F if used on a logical expression. |
| + | +A | Unary plus |
| - | -A | Unary negate + and - can act on numeric, program-relative and string expressions. |
| NOT | :NOT:A | Bitwise complement of A |
| LNOT | :LNOT:A | Logical complement of A |
| DEF | :DEF:A | {TRUE} if A is defined, otherwise {FALSE} |

### Binary operators

Binary operators are written between the pair of sub-expressions on which they operate. Operators of equal precedence are evaluated in left to right order. The binary operators are presented below in groups of equal precedence, in decreasing precedence order.

#### Multiplicative operators

These are the binary operators which bind most tightly and have the highest precedence:

| Operator | Usage | Explanation |
| --- | --- | --- |
| * | A*B | Multiply |
| / | A/B | Divide |
| MOD | A:MOD:B | A modulo B |

These operators act only on numeric expressions.

#### String manipulation operators

| Operator | Usage | Explanation |
| --- | --- | --- |
| LEFT | A:LEFT:B | The left-most B characters of A |
| RIGHT | A:RIGHT:B | The right-most B characters of A |
| CC | A:CC:B | B concatenated on to the end of A |

In the two slicing operators LEFT and RIGHT, *A* must be a string and *B* must be a numeric expression.

#### Shift operators

| Operator | Usage | Explanation |
| --- | --- | --- |
| ROL | A:ROL:B | Rotate A left B bits |
| ROR | A:ROR:B | Rotate A right B bits |
| SHL | A:SHL:B | Shift A left B bits |
| SHR | A:SHR:B | Shift A right B bits |

The shift operators act on numeric expressions, shifting or rotating the first operand by the amount specified by the second. Note that SHR is a logical shift and does not propagate the sign bit.

#### Addition and logical operators

| Operator | Usage | Explanation |
| --- | --- | --- |
| AND | A:AND:B | Bitwise AND of A and B |
| OR | A:OR:B | Bitwise OR of A and B |
| EOR | A:EOR:B | Bitwise Exclusive OR of A and B |
| + | A+B | Add A to B |
| - | A-B | Subtract B from A |

The bitwise operators act on numeric expressions. The operation is performed independently on each bit of the operands to produce the result.

#### Relational operators

| Operator | Usage | Explanation |
| --- | --- | --- |
| = | A=B | A equal to B |
| > | A>B | A greater than B |
| >= | A>=B | A greater than or equal to B |
| < | A<B | A less than B |
| <= | A<=B | A less than or equal to B |
| /= | A/=B | A not equal to B |
| <> | A<>B | A not equal to B |

The relational operators act upon two operands of the same type to produce a logical value. Allowable types of operand are numeric, program-relative, register-relative, and strings. Strings are sorted using ASCII ordering. String A will be less than string B if it is either a leading substring of string B, or if the left-most character of A in which the two strings differ is less than the corresponding character in string B. Note that arithmetic values are unsigned, so the value of 0>-1 is {FALSE}.

#### Boolean operators

These are the weakest binding operators with the lowest precedence.

| Operator | Usage | Explanation |
| --- | --- | --- |
| LAND | A:LAND:B | Logical AND of A and B |
| LOR | A:LOR:B | Logical OR of A and B |
| LEOR | A:LEOR:B | Logical Exclusive OR of A and B |

The Boolean operators perform the standard logical operations on their operands, which should evaluate to {TRUE} or {FALSE}.

## Conditional assembly

Sections of a source file may be assembled conditionally, only if certain conditions are true. The [ and ] (if and endif) directives are used to mark their start and finish; | provides an else construct. The syntax is:

```text
[ logical-expression
...code...
|
...code...
]
```

Note that [, | and ] may not be the first character of a line. If the logical-expression is true, the section will be assembled; if it is false, the second piece of code, the beginning of which is marked by | and the end of which is marked by ], will be assembled instead. Lines of code skipped during conditional assembly will not be listed unless the assembler is switched from its default TERSE mode by the -NOTERSE command-line switch.

The directives IF, ELSE and ENDIF may be used instead of [, | and ] respectively.

## Repetitive assembly

The conditional looping statement, useful for generating repetitive tables, is provided in the assembler by the WHILE...WEND directives. This produces an assembly-time loop, not a run-time loop. Because the test for the WHILE condition is made at the top of the loop, it is possible that no code will be generated during assembly; lines are listed as for conditional assembly. The syntax is:

```text
WHILE
```

```text
...code...
WEND
```

## Macros

### Usage

Macros are useful when a group of instructions and/or directives is frequently needed. *armasm* will replace the macro name with its definition. Macros may contain calls to other macros, nested up to 255 levels.

### Defining a macro

Two directives are used to define a macro. The syntax is:

```text
MACRO
{$label} macroname {$parameter1}{,$parameter2}{,$parameter3}..
    ...code...
    MEND
```

The directive MACRO must be followed by a macro prototype statement on the next line. This tells the assembler the name of the macro and its parameters. A label is optional, but useful if calls of the macro may be labelled. Any number of parameters can be used; each must begin with `$' to distinguish them from ordinary program symbols.

Within the macro body, *$label*, *$parameter*, etc., can be used in the same way as any other variables (see[Local and global variables - GBL, LCL and SET](#local-and-global-variables), and section [Variable substitution - $](#variable-substitution)). They will be given new values each time the macro is called.

Sometimes a macro parameter or label needs to be appended by a value. The appended value should be separated by a dot, which the assembler will ignore once it has used it to recognise the end of the parameter and label. For example:

```text
$label.$count
```

The end of the macro definition is signified by the MEND directive.There must be no un-closed WHILE/WEND loops or conditional assembly when the MEND directive is reached. Macro expansion terminates at MEND. However it can also be terminated with the MEXIT directive, which can be used in conjunction with WHILE/WEND or conditional assembly.

### Setting default parameter values

Default values can be set for parameters by following them with an equals sign and the default value. If the default has a leading or trailing space, the whole value should appear in quotes, as shown below:

```text
...{$parameter="default value"}
```

### Macro invocation

A macro defined with a pattern such as:

```text
$lab    xxxx $arg1,$arg2=5,$arg3
```

can be invoked as:

```text
Label    xxxx val1,val2,val3
```

An omitted actual argument is given a null (empty string) value. To force use of the default value, use `|' as the actual argument.
