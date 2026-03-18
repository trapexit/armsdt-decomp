# 3DO SDK - ARM Assembly Language

## ARM Assembly Language

ARM Assembly Language is the language which `armasm`, the ARM
Assembler, parses and compiles to produce object code in ARM Object
Format. Information on `armasm` command line options are detailed in
The ARM Assembler (`armasm`). This chapter details ARM Assembly
Language, but does not give examples of its use. For such examples
refer to the Cookbook.

Topics:
- Overview
- The ARM instruction set
- Generic coprocessor instructions
- Floating point instructions
- Directives
- Symbolic capabilities
- Expressions and operators
- Conditional assembly - `[`, `|` and `]`
- Repetitive assembly - `WHILE` and `WEND`
- Macros


## Overview

### General

Instruction mnemonics and register names may be written in upper or
lower case (but not mixed case). Directives must be written in upper
case.

### Input lines

General form:

```asm
{label} {instruction} {;comment}
```

- A space or tab should separate label and instruction.
- If no label is used, line must begin with space or tab.
- Any combination of label/instruction/comment is valid; empty lines are accepted.
- Source lines can be up to 255 chars.
- A long line can be split with a trailing backslash (`\`) at end of line.
- Do not use backslash-newline inside quoted strings.

### AREAs

AREAs are named indivisible chunks of code/data manipulated by the linker.

Typical output has:
- one code AREA (usually read-only)
- one writable data AREA
- for reentrant objects, often a third `BASED sb` AREA holding relocatable address constants.

Each AREA begins with:

```asm
AREA name
```

If missing, assembler generates `|$$$$$$$|` and reports a diagnostic.

AREA attributes:
- `ABS`: Absolute, fixed address
- `REL`: Relocatable (default)
- `PIC`: Position-independent code
- `CODE`: Contains instructions
- `DATA`: Contains non-instruction data
- `READONLY`: Area not written to
- `COMDEF`: Common area definition
- `COMMON`: Common area
- `NOINIT`: Zero-initialized data area with space reservation only
- `REENTRANT`: Reentrant code area
- `BASED Rn`: Static base data AREA containing tables of address
  constants locating static data items. Rn is a register,
  conventionally R9. Any label defined within this AREA becomes a
  register-relative expression which can be used with LDR and STR
  instructions.
- `ALIGN=expression`: The ALIGN sub-directive forces the start on of
  the area to be aligned on a power-of-two byte-address boundary. By
  default AREAs are aligned on a 4-byte word boundary, but the
  expression can have any value between 2 and 12 inclusive.

### ORG and ABS

```asm
ORG
```

`ORG` sets base address and `ABS` of containing AREA (or following AREA if none). Usually only sensible in single-AREA programs mapping fixed hardware addresses. Generally avoid otherwise.

### Symbols

- Numbers, booleans, strings, and addresses can be symbolic.
- Use `GBL`/`LCL` with `SETA`/`SETL`/`SETS` for number/logical/string symbols.
- Address values are assigned during assembly; some remain relocatable until link time.

Rules:
- Must start with letter.
- Case-sensitive.
- May contain digits and underscore.
- Avoid names colliding with mnemonics/directives.
- Limited by 255-char source line.
- To use wider character ranges, enclose with bars, e.g. `|C$$code|`.

### Labels

Labels are symbols at start of line; their address is determined during assembly.

### Local labels

- Local labels begin with a number `0..99`.
- Work with `ROUT` and can be defined multiple times.
- Assembler resolves nearest definition.

Definition:

```asm
number{routinename}
```

Reference form:

```asm
%{x}{y}n{routinename}
```

Where:
- `%` starts local-label reference
- `x`: `B` (backward) or `F` (forward), else both
- `y`: `A` all macro levels, `T` this macro level only, or default current->top
- `n`: local label number

Search does not cross local label area boundaries (`ROUT` to `ROUT`).

### Comments

First semicolon on a line starts a comment (unless in string constant). Comments are ignored.

### Constants

Numbers:
- Decimal: `123`
- Hex: `&7B`
- Base form: `n_xxx` where `n` is base `2..9`

Strings:
- Double-quoted.
- Escape literal `"` or `$` by doubling (`""`, `$$`).

Boolean:
- `{TRUE}` and `{FALSE}`.

### END directive

Every source must end with:

```asm
END
```

---

## The ARM instruction set

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7augb.html

Instruction availability/restrictions may vary by processor. Pay attention to 26-bit vs 32-bit PC differences.

### Conditional execution and the `S` bit

All ARM instructions are conditional, based on N/Z/C/V flags.

Condition mnemonics:
- `EQ`: Z set
- `NE`: Z clear
- `CS`/`HS`: C set
- `CC`/`LO`: C clear
- `MI`: N set
- `PL`: N clear
- `VS`: V set
- `VC`: V clear
- `HI`: C set and Z clear
- `LS`: C clear or Z set
- `GE`: N and V equal
- `LT`: N and V differ
- `GT`: Z clear and N/V equal
- `LE`: Z set or N/V differ

Flags are set by ALU instructions with `S` suffix and by compare instructions.

### Register names and `.`

- Accessible: `R0..R14`, `PC` (`R15`), `PSR`.
- `R14` is link register.
- `R13` is conventional stack pointer.
- Non-user modes have banked `R13`/`R14`; FIQ also banks `R8..R12`.
- `.` refers to current PC (usually current instruction address + 8 due to pipeline).

Example:

```asm
LDR R0,[.-8+offset]
```

### Branch instructions

```asm
B{L}{condition} expression
```

- `BL` stores return address in `R14`.
- Typical return:

```asm
MOV    PC, R14
```

or

```asm
LDMFD  SP!, {...,PC}
```

Assembler compensates for pipeline/prefetch in offset calculation.

### Data processing (`MOV`, `MVN` style)

```asm
opcode{condition}{S} destination,operand2
```

`operand2` forms:
- Immediate with rotate: `#const{,rotation}`
- Shifted register: `reg{,shift #const}`
- Register-shifted register: `reg{,shift reg}`
- RRX: `reg, RRX`

Shifts:
- `LSL`, `LSR`, `ASR`, `ROR`

### Data processing (`ADD`, `SUB`, etc.)

```asm
opcode{condition}{S} destination,operand1,operand2
```

`destination` and `operand1` must be registers; `operand2` as above.

### Compare/test group

```asm
opcode{condition}{P} operand1,operand2
```

- Updates flags, no normal destination result.
- `P` form is for 26-bit PSR manipulation and must not be used on 32-bit ARMs.
- On 32-bit ARMs use `MSR`/`MRS`.

### PSR transfer (`MSR`, `MRS`)

32-bit ARMs only.

- `psrl`: `CPSR`, `CPSR_all`, `CPSR_flg`, `CPSR_ctl`, `SPSR`, `SPSR_all`, `SPSR_flg`, `SPSR_ctl`
- `psrs`: `SPSR`, `SPSR_all`, `CPSR`, `CPSR_all`
- `R15` cannot be destination.

### Single data transfer (`LDR`, `STR`)

Pre-indexed:

```asm
opcode{condition}{B} register,[base{,index}]{!}
```

Post-indexed:

```asm
opcode{condition}{B} register,[base]{,index}
```

Index forms:
- `#{-}12-bit-constant-expression`
- `{-}register{, shift #5-bit-constant-expression}`

Literal/load pseudo form:

```asm
LDR register,=expression
```

Assembler may emit `MOV`/`MVN` for constructible constants, else PC-relative literal load and place value in literal pool (`LTORG`).

Label form:

```asm
opcode{cond}{B} register,label-expression
```

### Block data transfer (`LDM`, `STM`)

```asm
opcode{condition}type base{!},register-list{^}
```

Types include `DB`, `DA`, `IB`, `IA` and stack aliases:
- `STMFD` = `STMDB`
- `LDMFD` = `LDMIA`
- etc.

`register-list` uses `{}` and ranges, or `RLIST` directive.

### Multiply

```asm
MUL{condition}{S} destination,operand1,operand2
MLA{condition}{S} destination,operand1,operand2,operand3
```

- Avoid `destination == operand1`.
- Do not use `R15` as destination/operand.

### Single data swap (`SWP`)

```asm
SWP{condition}{B} destination,source,[base]
```

Byte/word swap with bus lock (if supported).

### Software interrupt

```asm
SWI constant-expression
```

Value truncated to 24 bits (`&0..&FFFFFF`).

### Pseudo-instructions

- `ADR{condition}{L} register,expression`
  - Emits `ADD`/`SUB`/`MOV`/`MVN` to synthesize address.
  - `ADRL` may use two instructions.
- `NOP`
  - Emits preferred no-op for target (often `MOV R0,R0`).

---

## Generic coprocessor instructions

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7augc.html

- Up to 16 coprocessors (`CP#` 0..15).
- `CP15` often system control; `CP1`/`CP2` often FP units.
- Coprocessor registers: `C0..C15`.

### Coprocessor data transfers

```asm
op{condition}{L} CP#,Cd,[Rn {,#offset}]{!}
                  [Rn],#offset
```

- Offset divisible by 4, range `-1020..1020`.
- `L` requests long transfer (coprocessor-specific meaning).
- Program/register-relative expressions may be used if in range.

### Coprocessor data operations

```asm
CDP{condition} CP#,CPOp,CRd,CRn,CRm{,CPOp2}
```

Internal coprocessor operation.

### Coprocessor register transfers

```asm
op{condition} CP#,CPOp,Rd,Cn,Cm{,CPOp2}
```

- `MRC` commonly reads status.
- `MCR` commonly writes control.
- If `Rd=R15`, bits 28..31 update N/Z/C/V flags only.

---

## Floating point instructions

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7augd.html

- IEEE 754 behavior (hardware coprocessor or emulation).
- FP regs: `F0..F7`.
- Precision specifier `prec`: `S`, `D`, `E`, `P`.
- Optional rounding mode `round`: default nearest, or `P`, `M`, `Z`.

### Floating point data transfer

```asm
op{condition}prec Fd,[Rn]{,#offset}
                  [Rn,#offset]{!}
```

- Offset divisible by 4, range `-1020..1020`.

### Floating point register transfer

```asm
FLT{condition}prec{round} Fn,Rd
FLT{condition}prec{round} Fn,#built-in-fp-constant
```

Built-in constants: `0, 1, 2, 3, 4, 5, 10, 0.5`.

`FIX`:

```asm
FIX{condition}{round} Rd,Fn
```

### FP status/control register transfer

- `WFS`: `FPSR := Rd`
- `RFS`: `Rd := FPSR`
- `WFC`: `FPC := Rd` (privileged)
- `RFC`: `Rd := FPC` (privileged)

Syntax:

```asm
opcode{condition} Rd
```

### Floating point multiple data transfer (`LFM`, `SFM`)

Non-stacking form:

```asm
op{condition} Fd,count,[Rn]
              [Rn,#offset]{!}
              [Rn],#offset
```

- Transfers up to 4 registers, wrapping after `F7`.

Stacking form (`FD` or `EA` only):

```asm
op{condition}ss Fd,count,[Rn]{!}
```

Mnemonics:
- `LFMFD`, `LFMEA`, `SFMFD`, `SFMEA`

### Floating point comparisons

```asm
opcode{condition}{E} Fn,Fm
```

- `CMF`: no exceptions; good for equality/unordered checks.
- `CMFE`: IEEE-compliant tests, may raise exception on NaN.

### Floating point binary operations

Examples: `ADF`, `MUF`, `SUF`, `RSF`, `DVF`, `RDF`, `POW`, `RPW`, `RMF`, `FML`, `FDV`, `FRD`, `POL`.

```asm
binop{condition}prec{round} Fd,Fn,Fm
```

`Fm` may be register or constant `#0,#1,#2,#3,#4,#5,#10,#0.5`.

### Floating point unary operations

Examples: `MVF`, `MNF`, `ABS`, `RND`, `URD`, `NRM`, `SQT`, `LOG`, `LGN`, `EXP`, `SIN`, `COS`, `TAN`, `ASN`, `ACS`, `ATN`.

```asm
unop{condition}prec{round} Fd,Fm
```

---

## Directives

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7auge.html

### Storage reservation and initialization

```asm
{label} directive expression-list
```

- `DCD` accepts program-relative/external expressions and numeric values.
- `DCB` list can include strings (stored bytewise).
- C-string example:

```asm
C_string DCB "C_string",0
```

`%` directive:

```asm
{label} % numeric-expression
```

Reserves that many bytes, initialized to zero.

### Floating point store initialization

```asm
{label} directive fp-constant{,fp-constant}
```

`fp-constant` forms include:
- `{-}integer E{-}integer` (e.g. `1E3`, `-4E-9`)
- `{-}{integer}.integer{E{-}integer}` (e.g. `1.0`, `-.1`, `3.1E6`)

### Layout of store (`^` and `#`)

```asm
^ expression{,base-register}
{label} # expression
```

- `^` sets storage map origin and `@` counter.
- `#` labels current `@`, then increments by byte count.
- With base register, following `#` labels become register-relative symbols.

### Organizational directives

- `END`: stop processing current source file.
- `ORG numeric-expression`: set initial program location counter.
- `LTORG`: emit current literal pool now.
- `KEEP {symbol}`: keep local symbols in object symbol table.

### Links to other object files

```asm
IMPORT symbol{[FPREGARGS]}{,WEAK}
EXPORT symbol{[FPREGARGS,DATA,LEAF]}
```

### Links to other source files

```asm
GET filename
INCLUDE filename
```

`INCLUDE` is a synonym for `GET`.

### Diagnostic generation

```asm
ASSERT logical-expression
! arithmetic-expression, string-expression
```

### Dynamic listing options (`OPT`)

`OPT n` where `n` is sum of flags controlling listing behavior, including normal listing, macro expansion/calls, pass one listing, conditional directives, and `MEND` listing.

### Titles (`TTL`, `SUBT`)

```asm
TTL title
SUBT subtitle
```

### Miscellaneous

- `ALIGN {power-of-two{,offset-expression}}`
- `NOFP`
- `RLIST`
  ```asm
  label RLIST list-of-registers
  ```
- `ENTRY`

---

## Symbolic capabilities

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7augf.html

### Setting constants

```asm
label EQU expression
label * expression
```

Register/coproc naming directives:

```asm
label RN numeric-expression
label FN numeric-expression
label CP numeric-expression
label CN numeric-expression
```

Predefined names:
- `R0..R15`, `PC`, `LR`
- `F0..F7`
- `p0..p15`
- `c0..c15`

### Local and global variables

Declarations:
- `GBLA`, `GBLL`, `GBLS`
- `LCLA`, `LCLL`, `LCLS`

Syntax:

```asm
directive variable-name
```

Assignments:
- `SETA`, `SETL`, `SETS`

```asm
variable-name directive expression
```

### Variable substitution

Prefix variable name with `$` to substitute value before syntax checking.

### Built-in variables

- `{PC}` or `.`: current program counter
- `{VAR}` or `@`: current storage-area location counter
- `{TRUE}`
- `{FALSE}`
- `{OPT}`: current listing option value
- `{CONFIG}`: `32` or `26` for assembler mode
- `{ENDIAN}`: `"big"` or `"little"`

---

## Expressions and operators

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7augg.html

Expressions combine values, operators, and parentheses with strict precedence.

### Unary operators

Examples:
- `?A`: bytes generated by line defining label `A`
- `:BASE:A`, `:INDEX:A`
- `:LEN:A`
- `:CHR:A`
- `:STR:A`
- `+A`, `-A`
- `:NOT:A`
- `:LNOT:A`
- `:DEF:A`

### Binary operators

Multiplicative:
- `A*B`, `A/B`, `A:MOD:B`

String:
- `A:LEFT:B`, `A:RIGHT:B`, `A:CC:B`

Shift:
- `A:ROL:B`, `A:ROR:B`, `A:SHL:B`, `A:SHR:B`

Addition/bitwise:
- `A:AND:B`, `A:OR:B`, `A:EOR:B`, `A+B`, `A-B`

Relational:
- `A=B`, `A>B`, `A>=B`, `A<B`, `A<=B`, `A/=B`, `A<>B`

Boolean (lowest precedence):
- `A:LAND:B`, `A:LOR:B`, `A:LEOR:B`

---

## Conditional assembly

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7augh.html

Use `[`, `|`, `]` (or `IF`, `ELSE`, `ENDIF`) to assemble conditionally:

```asm
[ logical-expression
...code...
|
...code...
]
```

- If expression true: first branch assembled.
- Else: second branch assembled.
- Skipped lines are not listed in TERSE mode.

---

## Repetitive assembly

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7augi.html

Assembly-time loop:

```asm
WHILE
...code...
WEND
```

Condition is tested at loop top, so loop body may produce no code.

---

## Macros

Source: https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/7augj.html

### Usage

Macros replace a macro name with its definition. Nesting up to 255 levels.

### Defining a macro

```asm
MACRO
{$label} macroname {$parameter1}{,$parameter2}{,$parameter3}..
    ...code...
    MEND
```

- `MACRO` followed by prototype line.
- Parameters begin with `$`.
- `$label`, `$parameter` etc. get values at each invocation.
- Use `.` as separator when appending text to params/labels:

```asm
$label.$count
```

- `MEND` ends definition.
- `MEXIT` can terminate macro expansion early.

### Default parameter values

```asm
...{$parameter="default value"}
```

### Macro invocation

Given:

```asm
$lab    xxxx $arg1,$arg2=5,$arg3
```

Invoke as:

```asm
Label    xxxx val1,val2,val3
```

- Omitted actual arg becomes null string.
- Use `|` as actual arg to force default value.
