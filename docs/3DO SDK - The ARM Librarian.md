# The ARM Librarian (armlib)

---

The ARM Librarian allows sets of related AOF files to be collected
together, and for these libraries to be maintained. Such a library can
then be passed to the linker instead of several AOF files.

However, linking with an object library file does not necessarily
produce the same results as linking with all the object files
collected into the object library file. This is due to the way
*armlink* processes its input files:

- each object file in the input list appears in the output
  unconditionally (although unused areas will be eliminated if the
  output is AIF or if the -NOUNUSEDareas option is specified);

- a module from a library file is only included in the output if an
   object file, or previously processed library file refers to it.

To see all [Command line
options](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/augfldr/4auga.html#XREF15633),
click on their highlighted name.

## For more information

For more information on how *armlink* processes its input files refer
to [Area placement and sorting
rules](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/arrfldr/3arrc.html#XREF13307).

The full specification of ARM Object Library Format can be found in
[ARM Object
Format](https://ext.3dodev.com/3DO/Portfolio_2.5/OnLineDoc/DevDocs/tktfldr/atsfldr/ats2frst.html#XREF16187).



# Command line options

---

The format of the armlib command is:

```
armlib <options> <library> [file-list | member-list]
```

The wildcards '*' and '?' may be used in *file-list* and *member-list*.

*options* can be any of the following`:`

```
--------------------------------------------------------
Option        |Description                              
--------------------------------------------------------
-h or -help   |give on-line details of the armlib       
              |command;                                 
--------------------------------------------------------
-c            |create a new library containing files in 
              |file-list;                               
--------------------------------------------------------
-i            |insert files in file-list into the       
              |library.  Existing members of the library
              |are replaced by mermbers of the same     
              |name;                                    
--------------------------------------------------------
-d            |delete members in member-list            
--------------------------------------------------------
-e            |extract members in member-list, placing  
              |them  in files of the same name;         
--------------------------------------------------------
-o            |add an external symbol table to an object
              |library;                                 
--------------------------------------------------------
-l            |list library.  This may be specified     
              |together with any other option;          
--------------------------------------------------------
-s            |list symbol table.  This may be specified
              |together with any other option;\         
--------------------------------------------------------
-v            |Additional arguments are read in from a  
<file>        |via file, in the same way as the armlink 
              |-via option.                             
--------------------------------------------------------

```



# Area placement and sorting rules

---

Each object module in the input list, and each subsequently included library module contains at least one *area*.
 AOF areas are the fragments of code and data manipulated by the linker.
 In all output types except AOF, except where overridden by a -FIRST or 
-LAST option, the linker sorts the set of areas first by attribute, then
 by area name to achieve the following:

- The read-only parts of the image are collected into one contiguous 
  region which can be protected at run time on systems which have memory 
  management hardware. Page alignment between the read-only and read-write
   portions of the image can be forced using the area alignment attribute 
  of AOF areas, set using the ALIGN=*n* attribute of the ARM assembler AREA directive.

- Portions of the image associated with a particular language
   run-time system are collected together into a minimum number of 
  contiguous regions, (this applies particularly to code regions which may
   have associated exception handling mechanisms).

More precisely, the linker orders areas by attribute as follows:

```
read-only code
read-only based data
read-only data
read-write code
based data
other initialised data
zero-initialised (uninitialised) data
debugging tables
```

In some image types (AIF, for example), zero-initialised data is
 created at image initialisation time and does not appear in the image
 itself.

Debugging tables are included only if the linker's -Debug option is
used. A debugger is expected to retrieve the debugging tables before
the image is entered. The image is free to overwrite its debugging
tables once it has started executing.

Areas unordered by attribute are ordered by AREA name. The comparison
 of names is lexicographical and case sensitive, using the ASCII
 collation sequence for characters.

Identically attributed and named areas are ordered according to their
relative positions in the input list.

The -FIRST and -LAST options can be used to force particular areas to
 be placed first or last, regardless of their attributes, names or
 positions in the input list.

As a consequence of these rules, the positioning of identically
attributed and named areas included from libraries is not predictable.
However, if library L1 precedes library L2 in the input list, then all
areas included from L1 will precede each area included from L2. If
more precise positioning is required then modules can be extracted
manually, and included explicitly in the input list.

Once areas have been ordered and the base address has been fixed, the
linker may insert padding to force each area to start at an address
which is a multiple of 2 ((area alignment)) (but most commonly, *area
alignment* is 2, requiring only word alignment).
