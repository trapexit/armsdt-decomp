typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned int    uint3;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef longlong __quad_t;

typedef __quad_t __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    void *__pad1;
    void *__pad2;
    void *__pad3;
    void *__pad4;
    size_t __pad5;
    int _mode;
    char _unused2[40];
};

struct _IO_marker {
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};

typedef struct _IO_FILE FILE;

typedef void (*__sighandler_t)(int);

typedef void *__gnuc_va_list;

typedef int (*__compar_fn_t)(void *, void *);

typedef struct Elf32_Dyn_x86 Elf32_Dyn_x86, *PElf32_Dyn_x86;

typedef enum Elf32_DynTag_x86 {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_XHASH=1879047924,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf32_DynTag_x86;

struct Elf32_Dyn_x86 {
    enum Elf32_DynTag_x86 d_tag;
    dword d_val;
};

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

typedef enum Elf_SectionHeaderType_x86 {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191
} Elf_SectionHeaderType_x86;

struct Elf32_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_x86 sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym {
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

typedef enum Elf_ProgramHeaderType_x86 {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482
} Elf_ProgramHeaderType_x86;

struct Elf32_Phdr {
    enum Elf_ProgramHeaderType_x86 p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef struct NoteAbiTag NoteAbiTag, *PNoteAbiTag;

struct NoteAbiTag {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    dword abiType; // 0 == Linux
    dword requiredKernelVersion[3]; // Major.minor.patch
};

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};



undefined _DT_INIT;
undefined _DT_FINI;
undefined FUN_0804c55c;
int DAT_0805ec28;
undefined *PTR_DAT_0805ec24;
dword DWORD_0805f038;
undefined DAT_0805f1a8;
int DAT_0805ec2c;
uint DAT_0805ec2c;
byte DAT_0805ec38;
undefined4 stdout;
int DAT_08060200;
int DAT_080601e4;
byte DAT_0805ec30;
undefined1 DAT_0805f1c0;
int DAT_080601fc;
int DAT_080601ec;
undefined *PTR_s_Byte_0805ec3c;
uint DAT_080601ec;
uint DAT_080601fc;
undefined FUN_080495e4;
uint *DAT_080601ec;
undefined4 *DAT_08060214;
uint *DAT_08060230;
int DAT_08060234;
int DAT_08060208;
undefined DAT_08060204;
int DAT_080601e8;
uint DAT_080601f8;
int DAT_08060214;
int DAT_0805ec34;
char *DAT_08060210;
undefined4 DAT_080589e4;
undefined4 DAT_08060218;
undefined FUN_08049c38;
uint *DAT_080601e4;
uint DAT_08060200;
uint DAT_080601f4;
int DAT_080601e0;
undefined4 stderr;
size_t DAT_080601f0;
uint *DAT_080601e0;
size_t DAT_080601f4;
uint *DAT_08060208;
int DAT_0806020c;
undefined FUN_0804c48c;
undefined DAT_0805ec30;
undefined4 DAT_080601e0;
undefined DAT_080601c0;
undefined4 DAT_080601f0;
void *DAT_08060210;
undefined4 DAT_0805ec4c;
int DAT_0805ec4c;
byte DAT_0805ec50;
int DAT_0805ec54;
undefined UNK_08059e60;
int DAT_08060238;
int DAT_0806023c;
undefined *DAT_08060240;
undefined4 DAT_08060244;
undefined DAT_08059f0d;
undefined UNK_08059f12;
undefined DAT_08059f40;
undefined DAT_08059f80;
undefined DAT_08059fc0;
undefined UNK_08059faf;
undefined DAT_08059fd7;
undefined4 DAT_08060238;
undefined4 DAT_0806023c;
pointer hexprefix;
undefined UNK_0805a12f;
undefined DAT_0805a148;
undefined UNK_0805a040;
undefined UNK_0805a044;
undefined DAT_0805a09f;
undefined DAT_0805a0c0;
undefined UNK_0805a115;
undefined DAT_0805a125;
undefined *PTR_DAT_0805ec64;
pointer PTR_DAT_0805ec64;
undefined DAT_0805a1ff;
undefined DAT_0805a202;
undefined DAT_0805a1d4;
undefined DAT_0805a260;
undefined DAT_0805a1e4;
undefined UNK_0805a2be;
undefined DAT_0805a1e9;
string s_utility_0805ec80;
undefined1 DAT_08060260;
undefined DAT_08060300;
char DAT_08060260;
pointer PTR_DAT_0805eca0;
undefined4 DAT_0805edf0;
undefined1 DAT_0805a36e;
undefined1 DAT_0805a371;
int DAT_0805edf0;
FILE *DAT_080603a0;
undefined DAT_080603a4;
int DAT_080603b8;
int DAT_080603b4;
undefined DAT_080603a5;
undefined4 DAT_080603a0;
uint *DAT_0805edf0;
undefined DAT_0805ab5d;
undefined4 DAT_080603b4;
undefined DAT_0805ab91;
undefined DAT_0805aaa6;
undefined DAT_0805abb5;
int DAT_08060618;
FILE *DAT_08060620;
int DAT_08060614;
int DAT_08060610;
int DAT_0805f030;
uint DAT_0805f034;
undefined *PTR_DAT_0805ee80;
undefined DAT_080603c0;
undefined DAT_080603c4;
undefined4 DAT_080603c8;
undefined *PTR_s_TAG_padding_0805edf4;
undefined *PTR_DAT_0805ef68;
undefined DAT_0805b7c8;
undefined *PTR_DAT_0805ef44;
undefined *PTR_DAT_0805ef9c;
byte DAT_0806060f;
undefined4 DAT_08060618;
undefined *PTR_DAT_0805ef88;
pointer PTR_s_ORD_row_major_0805effc;
undefined *PTR_DAT_0805f004;
undefined4 DAT_08060610;
undefined DAT_0806060c;
undefined4 DAT_08060614;
uint *DAT_0805f030;
undefined4 DAT_0806061c;
undefined4 *DAT_0806061c;
pointer PTR_s_DW_CFA_nop_0805c5e0;
undefined DAT_0805c5e4;
undefined DAT_0805c5e8;
undefined *PTR_DAT_0805d554;
undefined4 DAT_0805f03c;

void _DT_INIT(void)

{
  func_0x00000000();
  FUN_08048c10();
  FUN_08058530();
  return;
}



void FUN_0804890c(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int vsprintf(char *__s,char *__format,__gnuc_va_list __arg)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strchr(char *__s,int __c)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __register_frame_info(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int isprint(int param_1)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strcmp(char *__s1,char *__s2)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fprintf(FILE *__stream,char *__format,...)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

long ftell(FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int tolower(int __c)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memmove(void *__dest,void *__src,size_t __n)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __deregister_frame_info(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int vfprintf(FILE *__s,char *__format,__gnuc_va_list __arg)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fseek(FILE *__stream,long __off,int __whence)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputs(char *__s,FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strstr(char *__haystack,char *__needle)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __strtol_internal(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void qsort(void *__base,size_t __nmemb,size_t __size,__compar_fn_t __compar)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strncmp(char *__s1,char *__s2,size_t __n)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputc(int __c,FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __libc_start_main(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int islower(int param_1)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int toupper(int __c)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strcat(char *__dest,char *__src)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__sighandler_t __sysv_signal(int __sig,__sighandler_t __handler)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int isdigit(int param_1)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int isupper(int param_1)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void exit(int __status)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * calloc(size_t __nmemb,size_t __size)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int _IO_putc(int __c,_IO_FILE *__fp)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strncpy(char *__dest,char *__src,size_t __n)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sprintf(char *__s,char *__format,...)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strcpy(char *__dest,char *__src)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void processEntry entry(undefined4 param_1,undefined4 param_2)

{
  undefined1 auStack_4 [4];
  
  __libc_start_main(FUN_0804c55c,param_2,&stack0x00000004,_DT_INIT,_DT_FINI,param_1,auStack_4);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void FUN_08048bc0(void)

{
  code *pcVar1;
  
  if (DAT_0805ec28 == 0) {
    while (*(int *)PTR_DAT_0805ec24 != 0) {
      pcVar1 = *(code **)PTR_DAT_0805ec24;
      PTR_DAT_0805ec24 = PTR_DAT_0805ec24 + 4;
      (*pcVar1)();
    }
    __deregister_frame_info(&DWORD_0805f038);
    DAT_0805ec28 = 1;
  }
  return;
}



void FUN_08048c08(void)

{
  return;
}



void FUN_08048c10(void)

{
  __register_frame_info(&DWORD_0805f038,&DAT_0805f1a8);
  return;
}



void FUN_08048c30(void)

{
  return;
}



uint FUN_08048c40(uint3 *param_1)

{
  uint uVar1;
  uint uVar2;
  
  if (DAT_0805ec2c == 1) {
    uVar2 = (uint)(byte)*param_1 << 0x18 | (uint)*(byte *)((int)param_1 + 1) << 0x10 |
            (uint)*(byte *)((int)param_1 + 2) << 8;
    uVar1 = (uint)*(byte *)((int)param_1 + 3);
  }
  else {
    uVar2 = (uint)*param_1;
    uVar1 = (uint)*(byte *)((int)param_1 + 3) << 0x18;
  }
  return uVar2 | uVar1;
}



uint FUN_08048c94(byte *param_1)

{
  uint uVar1;
  uint uVar2;
  
  if (DAT_0805ec2c == 1) {
    uVar2 = (uint)*param_1 << 8;
    uVar1 = (uint)param_1[1];
  }
  else {
    uVar2 = (uint)*param_1;
    uVar1 = (uint)param_1[1] << 8;
  }
  return uVar2 | uVar1;
}



uint FUN_08048cc0(uint param_1,uint param_2,uint param_3)

{
  uint uVar1;
  int iVar2;
  
  DAT_0805ec2c = 0xffffffff;
  FUN_0804c990((uint)((param_1 & 0xff) == param_3 >> 0x18));
  uVar1 = FUN_0804c9cc(param_1);
  if (((param_2 & uVar1) == param_3) && (uVar1 = (uint)DAT_0805ec38, uVar1 == (uVar1 & 1))) {
    iVar2 = FUN_0804c9b0();
    DAT_0805ec2c = uVar1;
    if (iVar2 != 0) {
      uVar1 = 1 - uVar1;
      DAT_0805ec2c = uVar1;
    }
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



void FUN_08048d44(int param_1,int param_2)

{
  do {
    _IO_putc(0x20,stdout);
    param_1 = param_1 + 1;
  } while (param_1 < param_2);
  return;
}



int FUN_08048d6c(char param_1)

{
  char *pcVar1;
  
  pcVar1 = "\'\'\"\"??\\\\\aa\bb\ff\nn\rr\tt\vv<bad string index>";
  do {
    if (*pcVar1 == param_1) {
      return (int)pcVar1[1];
    }
    pcVar1 = pcVar1 + 2;
  } while (pcVar1 < "<bad string index>");
  return 0;
}



int FUN_08048d9c(int param_1)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  int local_408;
  byte local_404 [1024];
  
  local_408 = 0;
  if (((param_1 < 0) || (DAT_08060200 < param_1)) || (DAT_080601e4 == 0)) {
    printf("<bad string index>");
  }
  else {
    pbVar3 = (byte *)(param_1 + DAT_080601e4);
    if ((DAT_0805ec30 & 1) == 0) {
      pbVar3 = local_404;
      FUN_080515e0((byte *)(param_1 + DAT_080601e4),pbVar3,0x400);
    }
    while( true ) {
      bVar1 = *pbVar3;
      pbVar3 = pbVar3 + 1;
      if (bVar1 == 0) break;
      iVar2 = FUN_08048d6c(bVar1);
      if ((char)iVar2 == '\0') {
        iVar2 = isprint((uint)bVar1);
        if ((iVar2 == 0) || (0x7f < bVar1)) {
          printf("\\x%02x",(uint)bVar1);
          local_408 = local_408 + 4;
        }
        else {
          _IO_putc((int)(char)bVar1,stdout);
          local_408 = local_408 + 1;
        }
      }
      else {
        _IO_putc(0x5c,stdout);
        _IO_putc((int)(char)iVar2,stdout);
        local_408 = local_408 + 2;
      }
    }
  }
  return local_408;
}



undefined1 * FUN_08048eb8(int param_1)

{
  byte bVar1;
  char cVar2;
  byte bVar3;
  int iVar4;
  byte *pbVar5;
  byte *pbVar6;
  int iVar7;
  byte *local_408;
  byte local_404 [1024];
  
  if (((param_1 < 0) || (DAT_08060200 < param_1)) || (DAT_080601e4 == 0)) {
    memcpy(&DAT_0805f1c0,"<bad string index>",0x13);
    return &DAT_0805f1c0;
  }
  pbVar5 = &DAT_0805f1c0;
  iVar7 = 0xfff;
  local_408 = (byte *)(DAT_080601e4 + param_1);
  if ((DAT_0805ec30 & 1) == 0) {
    local_408 = local_404;
    FUN_080515e0((byte *)(DAT_080601e4 + param_1),local_408,0x400);
  }
  do {
    bVar1 = *local_408;
    local_408 = local_408 + 1;
    pbVar6 = pbVar5;
    if ((bVar1 == 0) || (iVar7 == 0)) goto LAB_08048ff6;
    iVar4 = FUN_08048d6c(bVar1);
    if ((byte)iVar4 == 0) {
      iVar4 = isprint((uint)bVar1);
      if ((iVar4 == 0) || (0x7f < bVar1)) {
        *pbVar5 = 0x5c;
        pbVar6 = pbVar5 + 1;
        if (iVar7 == 1) {
LAB_08048ff6:
          *pbVar6 = 0;
          return &DAT_0805f1c0;
        }
        *pbVar6 = 0x78;
        pbVar6 = pbVar5 + 2;
        if (iVar7 == 2) goto LAB_08048ff6;
        cVar2 = (char)((int)((int)(char)bVar1 & 0xf0U) >> 4);
        bVar3 = cVar2 + 0x30;
        if (0x39 < bVar3) {
          bVar3 = cVar2 + 0x57;
        }
        *pbVar6 = bVar3;
        pbVar6 = pbVar5 + 3;
        iVar7 = iVar7 + -3;
        if (iVar7 == 0) goto LAB_08048ff6;
        bVar3 = (bVar1 & 0xf) + 0x30;
        if (0x39 < bVar3) {
          bVar3 = (bVar1 & 0xf) + 0x57;
        }
        *pbVar6 = bVar3;
        pbVar5 = pbVar6;
      }
      else {
        *pbVar5 = bVar1;
      }
    }
    else {
      *pbVar5 = 0x5c;
      pbVar6 = pbVar5 + 1;
      iVar7 = iVar7 + -1;
      if (iVar7 == 0) goto LAB_08048ff6;
      *pbVar6 = (byte)iVar4;
      pbVar5 = pbVar6;
    }
    pbVar5 = pbVar5 + 1;
    iVar7 = iVar7 + -1;
  } while( true );
}



void FUN_0804900c(uint *param_1,undefined4 param_2,int param_3,int param_4,undefined4 param_5,
                 undefined4 param_6)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  bool bVar6;
  
  if ((param_3 != 0) && (0 < param_4)) {
    iVar5 = 0;
    bVar6 = false;
    if ((DAT_0805ec30 & 8) == 0) {
      pcVar2 = "\n** Identification (file %s)\n\n";
    }
    else {
      pcVar2 = "\n** Identification (file %s, offset 0x%x)\n\n";
    }
    printf(pcVar2,param_6,param_5);
    if (0 < param_4) {
      do {
        cVar1 = *(char *)(iVar5 + param_3);
        iVar5 = iVar5 + 1;
        if (cVar1 == '\0') break;
        bVar6 = cVar1 == '\n';
        _IO_putc((int)cVar1,stdout);
      } while (iVar5 < param_4);
    }
    if (!bVar6) {
      _IO_putc(10,stdout);
    }
  }
  if ((DAT_0805ec30 & 8) == 0) {
    pcVar2 = "\n** Header (file %s)\n\n";
  }
  else {
    pcVar2 = "\n** Header (file %s, offset 0x%x)\n\n";
  }
  printf(pcVar2,param_6,param_2);
  printf("AOF file type: ");
  if (DAT_0805ec2c == 1) {
    pcVar2 = "Big-endian, ";
  }
  else {
    pcVar2 = "Little-endian, ";
  }
  printf(pcVar2);
  uVar3 = FUN_0804c9cc(*param_1);
  if (uVar3 == 0xc5e2d081) {
    pcVar2 = "contiguous RO and RW areas";
  }
  else {
    if ((int)uVar3 < -0x3a1d2f7e) {
      if (uVar3 == 0xc5e2d080) {
        printf("Relocatable object code\n");
        goto LAB_08049168;
      }
LAB_08049150:
      uVar3 = FUN_0804c9cc(*param_1);
      printf("Unknown type %.8lx\n",uVar3);
      goto LAB_08049168;
    }
    if (uVar3 == 0xc5e2d082) {
      pcVar2 = "page-aligned RW area";
    }
    else {
      if (uVar3 != 0xc5e2d083) goto LAB_08049150;
      pcVar2 = "page-aligned RW area/block-aligned RO area";
    }
  }
  printf("Obsolete Image type (%s)\n",pcVar2);
LAB_08049168:
  uVar3 = FUN_0804c9cc(param_1[1]);
  printf("AOF Version:   %3ld\n",uVar3);
  uVar3 = FUN_0804c9cc(param_1[2]);
  printf("No of areas:   %3ld\n",uVar3);
  uVar3 = FUN_0804c9cc(param_1[3]);
  printf("No of symbols: %3ld\n\n",uVar3);
  uVar3 = FUN_0804c9cc(param_1[4]);
  if ((0 < (int)uVar3) && (uVar4 = FUN_0804c9cc(param_1[2]), (int)uVar3 <= (int)uVar4)) {
    if (DAT_080601e4 == 0) {
      uVar4 = FUN_0804c9cc(param_1[5]);
      printf("Entry point at offset 0x%.4lx in area %ld\n",uVar4,uVar3);
    }
    else {
      uVar3 = FUN_0804c9cc(param_1[uVar3 * 5 + 1]);
      pcVar2 = FUN_08048eb8(uVar3);
      uVar3 = FUN_0804c9cc(param_1[5]);
      printf("Entry point at offset 0x%.4lx in area \"%s\"\n",uVar3,pcVar2);
    }
  }
  _IO_putc(10,stdout);
  return;
}



int FUN_0804924c(int param_1)

{
  int iVar1;
  
  iVar1 = 1;
  while (0 < param_1) {
    iVar1 = iVar1 * 2;
    param_1 = param_1 + -1;
  }
  return iVar1;
}



void FUN_08049270(int param_1,uint *param_2,int param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  char *pcVar3;
  uint uVar4;
  uint uVar5;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  uVar1 = FUN_0804c9cc(*param_2);
  uVar2 = FUN_0804c9cc(param_2[1]);
  local_14 = 0;
  local_18 = 0;
  if ((int)uVar2 < 0) {
    local_8 = uVar2 & 0xffffff;
    uVar4 = (int)uVar2 >> 0x18 & 3;
    local_c = (int)uVar2 >> 0x1a & 1;
    uVar5 = (int)uVar2 >> 0x1b & 1;
    local_10 = (int)uVar2 >> 0x1c & 1;
    if (((local_10 != 0) && (uVar4 == 0)) && (((int)uVar2 >> 0x1d & 3U) == 3)) {
      local_18 = local_c ^ 1;
    }
    if (uVar4 == 3) {
      local_14 = uVar1 & 1;
      uVar1 = uVar1 & 0xfffffffe;
    }
  }
  else {
    local_8 = uVar2 & 0xffff;
    uVar4 = (int)uVar2 >> 0x10 & 3;
    local_c = (int)uVar2 >> 0x12 & 1;
    uVar5 = (int)uVar2 >> 0x13 & 1;
    if (local_c != 0) {
      uVar5 = 1;
    }
    if (uVar5 == 0) {
      local_8 = param_4;
    }
    local_10 = 0;
  }
  if (local_18 == 0) {
    printf("At %.6lx: %s",uVar1,(&PTR_s_Byte_0805ec3c)[uVar4]);
    if (uVar4 == 0) {
      printf("      [%.2x]",(int)*(char *)(uVar1 + param_3));
    }
    else {
      if (uVar4 == 1) {
        uVar1 = FUN_08048c94((byte *)(param_3 + uVar1));
        pcVar3 = "    [%.4lx]";
      }
      else {
        if (uVar4 < 2) goto LAB_080493dc;
        if ((local_14 == 0) || (uVar4 != 3)) {
          uVar1 = FUN_08048c40((uint3 *)(param_3 + uVar1));
          pcVar3 = " [%.8lx]";
        }
        else {
          uVar1 = FUN_08048c94((byte *)(param_3 + uVar1));
          pcVar3 = "     [%.4lx]";
        }
      }
      printf(pcVar3,uVar1);
    }
  }
  else {
    printf("Non-relocating reference to ");
  }
LAB_080493dc:
  if (uVar5 == 0) {
    uVar1 = FUN_0804c9cc(*(uint *)(param_1 + 8));
    if ((int)local_8 < (int)uVar1) {
      uVar1 = FUN_0804c9cc(*(uint *)(param_1 + 0x18 + local_8 * 0x14));
      pcVar3 = FUN_08048eb8(uVar1);
    }
    else {
      pcVar3 = "<bad AREA index>";
    }
    if (local_18 == 0) {
      if (local_c == 0) {
        if (local_10 == 0) {
          printf(" displaced by base of area %s (%d)\n",pcVar3,local_8);
        }
        else {
          printf(" base-relative to base of area %s\n",pcVar3);
        }
      }
      else if (local_10 == 0) {
        printf(" PC-relative to base of area %s\n",pcVar3);
      }
      else {
        printf(" tailcall to base of area %s\n",pcVar3);
      }
    }
    else {
      printf("area %s\n",pcVar3);
    }
  }
  else {
    if (((int)(local_8 * 0x10) < DAT_080601fc) && (DAT_080601e4 != 0)) {
      uVar1 = FUN_0804c9cc(*(uint *)(DAT_080601ec + local_8 * 0x10));
      pcVar3 = FUN_08048eb8(uVar1);
    }
    else {
      pcVar3 = "<bad symbol number>";
    }
    if (local_18 == 0) {
      if (local_c == 0) {
        if (local_10 == 0) {
          printf(" displaced by symbol %s\n",pcVar3);
        }
        else {
          printf(" base-relative to symbol %s\n",pcVar3);
        }
      }
      else if (local_10 == 0) {
        printf(" PC-relative to symbol %s\n",pcVar3);
      }
      else {
        printf(" tailcall to symbol %s\n",pcVar3);
      }
    }
    else {
      printf("symbol %s\n",pcVar3);
    }
  }
  return;
}



bool FUN_0804952c(uint param_1,char *param_2)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  
  bVar3 = false;
  if (DAT_080601e4 != 0) {
    uVar1 = FUN_0804c9cc(param_1);
    if ((-1 < (int)uVar1) && ((int)uVar1 < DAT_08060200)) {
      iVar2 = strcmp((char *)(uVar1 + DAT_080601e4),param_2);
      bVar3 = iVar2 == 0;
    }
  }
  return bVar3;
}



bool FUN_08049570(uint param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  bool bVar4;
  
  if (param_1 == param_2) {
    bVar4 = true;
  }
  else {
    bVar4 = false;
    if ((((DAT_080601e4 != 0) && (uVar1 = FUN_0804c9cc(param_1), -1 < (int)uVar1)) &&
        ((int)uVar1 < DAT_08060200)) &&
       ((uVar2 = FUN_0804c9cc(param_2), -1 < (int)uVar2 && ((int)uVar2 < DAT_08060200)))) {
      iVar3 = strcmp((char *)(DAT_080601e4 + uVar1),(char *)(uVar2 + DAT_080601e4));
      bVar4 = iVar3 == 0;
    }
  }
  return bVar4;
}



uint FUN_080495e4(int *param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = FUN_0804c9cc(*(uint *)(*param_1 + 8));
  uVar2 = FUN_0804c9cc(*(uint *)(*param_2 + 8));
  if (uVar1 < uVar2) {
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = (uint)(uVar1 != uVar2);
  }
  return uVar1;
}



uint * FUN_08049620(uint *param_1,undefined4 *param_2)

{
  bool bVar1;
  bool bVar2;
  uint uVar3;
  uint uVar4;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  uint uVar5;
  uint *puVar6;
  uint *puVar7;
  uint local_18;
  size_t local_14;
  uint *local_c;
  uint *local_8;
  
  local_8 = (uint *)0x0;
  local_c = (uint *)0x0;
  if ((DAT_080601ec != 0) && (DAT_080601e4 != 0)) {
    bVar1 = true;
    local_14 = 0;
    local_18 = 0;
    uVar3 = DAT_080601fc;
    if ((int)DAT_080601fc < 0) {
      uVar3 = DAT_080601fc + 0xf;
    }
    uVar3 = (uVar3 & 0xfffffff0) + DAT_080601ec;
    if (DAT_080601ec < uVar3) {
      puVar7 = (uint *)(DAT_080601ec + 8);
      puVar6 = (uint *)(DAT_080601ec + 0xc);
      uVar5 = DAT_080601ec;
      do {
        uVar4 = FUN_0804c9cc(puVar6[-2]);
        if (((uVar4 & 5) == 1) &&
           (bVar2 = FUN_08049570(*puVar6,*param_1), CONCAT31(extraout_var,bVar2) != 0)) {
          uVar4 = local_18;
          if ((bVar1) && (uVar4 = FUN_0804c9cc(*puVar7), (int)uVar4 < (int)local_18)) {
            bVar1 = false;
            uVar4 = local_18;
          }
          local_18 = uVar4;
          local_14 = local_14 + 1;
        }
        puVar6 = puVar6 + 4;
        puVar7 = puVar7 + 4;
        uVar5 = uVar5 + 0x10;
      } while (uVar5 < uVar3);
    }
    if ((local_14 != 0) && (local_8 = malloc(local_14 * 4), local_8 != (uint *)0x0)) {
      local_c = local_8;
      if (DAT_080601ec < uVar3) {
        puVar7 = (uint *)(DAT_080601ec + 0xc);
        uVar5 = DAT_080601ec;
        do {
          uVar4 = FUN_0804c9cc(puVar7[-2]);
          if (((uVar4 & 5) == 1) &&
             (bVar2 = FUN_08049570(*puVar7,*param_1), CONCAT31(extraout_var_00,bVar2) != 0)) {
            *local_c = uVar5;
            local_c = local_c + 1;
          }
          puVar7 = puVar7 + 4;
          uVar5 = uVar5 + 0x10;
        } while (uVar5 < uVar3);
      }
      if (!bVar1) {
        qsort(local_8,local_14,4,FUN_080495e4);
      }
    }
  }
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = local_c;
  }
  return local_8;
}



void FUN_08049780(char *param_1)

{
  printf("\n%-24s   code-size    literals   constdata   data-size  0init-size   debug-size\n",
         param_1);
  return;
}



void FUN_08049794(char *param_1,undefined4 *param_2)

{
  printf("%-24s%12lu%12lu%12lu%12lu%12lu%12lu\n",param_1,*param_2,param_2[1],param_2[2],param_2[3],
         param_2[4],param_2[5]);
  return;
}



void FUN_080497bc(undefined4 param_1,int *param_2,int *param_3)

{
  FUN_08049794(param_1,param_2);
  *param_3 = *param_3 + *param_2;
  param_3[1] = param_3[1] + param_2[1];
  param_3[2] = param_3[2] + param_2[2];
  param_3[3] = param_3[3] + param_2[3];
  param_3[4] = param_3[4] + param_2[4];
  param_3[5] = param_3[5] + param_2[5];
  return;
}



void FUN_080497fc(int *param_1)

{
  printf("%32s----------------------------%8s----------------------------\n","","");
  printf("%36s%12lu%24s%12lu\n","",param_1[1] + *param_1 + param_1[2],"",param_1[4] + param_1[3]);
  return;
}



void FUN_08049840(uint *param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_0804c9cc(param_1[1]);
  if ((uVar1 & 3) == 3) {
    printf("  EXPORT ");
    uVar1 = FUN_0804c9cc(*param_1);
    FUN_08048d9c(uVar1);
    _IO_putc(10,stdout);
  }
  uVar1 = FUN_0804c9cc(*param_1);
  FUN_08048d9c(uVar1);
  uVar1 = FUN_0804c9cc(param_1[2]);
  if (param_2 != uVar1) {
    uVar1 = FUN_0804c9cc(param_1[2]);
    printf("-0x%lx",uVar1 - param_2);
  }
  _IO_putc(10,stdout);
  return;
}



void FUN_080498d0(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  bool bVar2;
  uint uVar3;
  undefined3 extraout_var;
  uint *puVar4;
  undefined3 extraout_var_00;
  uint *puVar5;
  int iVar6;
  uint *puVar7;
  
  iVar6 = 0;
  for (puVar1 = param_2; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
    puVar1[2] = 0;
    iVar6 = iVar6 + 1;
  }
  if (((DAT_080601ec != (uint *)0x0) && (DAT_080601e4 != 0)) && (0 < iVar6)) {
    puVar4 = (uint *)(param_1 + 0x18);
    uVar3 = FUN_0804c9cc(*(uint *)(param_1 + 8));
    puVar5 = puVar4 + uVar3 * 5;
    for (; puVar4 < puVar5; puVar4 = puVar4 + 5) {
      puVar1 = param_2;
      if (iVar6 < 1) goto joined_r0x080499e6;
      for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
        bVar2 = FUN_0804952c(*puVar4,(char *)puVar1[1]);
        if (CONCAT31(extraout_var,bVar2) != 0) {
          puVar1[2] = 1;
          puVar1[3] = *puVar4;
          iVar6 = iVar6 + -1;
        }
      }
    }
    if (0 < iVar6) {
      uVar3 = DAT_080601fc;
      if ((int)DAT_080601fc < 0) {
        uVar3 = DAT_080601fc + 0xf;
      }
      puVar4 = (uint *)((uVar3 & 0xfffffff0) + (int)DAT_080601ec);
      if (DAT_080601ec < puVar4) {
        puVar5 = DAT_080601ec + 3;
        puVar1 = param_2;
        puVar7 = DAT_080601ec;
        do {
          for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
            uVar3 = FUN_0804c9cc(puVar5[-2]);
            if (((uVar3 & 5) == 1) &&
               (bVar2 = FUN_0804952c(*puVar7,(char *)puVar1[1]),
               CONCAT31(extraout_var_00,bVar2) != 0)) {
              puVar1[2] = 1;
              puVar1[3] = *puVar5;
            }
          }
          puVar5 = puVar5 + 4;
          puVar7 = puVar7 + 4;
          puVar1 = param_2;
        } while (puVar7 < puVar4);
      }
    }
  }
joined_r0x080499e6:
  for (; param_2 != (undefined4 *)0x0; param_2 = (undefined4 *)*param_2) {
    if (param_2[2] == 0) {
      FUN_0804fbe8("\'%s\' is neither an area name nor a symbol in an area");
    }
  }
  return;
}



undefined4 FUN_08049a0c(uint param_1)

{
  undefined4 *puVar1;
  bool bVar2;
  undefined3 extraout_var;
  
  puVar1 = DAT_08060214;
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      return 0;
    }
    bVar2 = FUN_08049570(param_1,puVar1[3]);
    if (CONCAT31(extraout_var,bVar2) != 0) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  return 1;
}



int FUN_08049a48(uint param_1,uint *param_2)

{
  uint *puVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int local_14;
  
  puVar1 = (uint *)((int)DAT_08060230 + DAT_08060234);
  iVar5 = 0;
  puVar2 = DAT_08060230;
  do {
    if (puVar1 <= puVar2) {
      return iVar5;
    }
    uVar3 = FUN_0804c9cc(*puVar2);
    if (uVar3 == param_1) {
      uVar3 = FUN_0804c9cc(puVar2[1]);
      if ((int)uVar3 < 0) {
        uVar6 = uVar3 & 0xffffff;
        uVar3 = (int)uVar3 >> 0x1b;
      }
      else {
        uVar6 = uVar3 & 0xffff;
        uVar3 = (int)uVar3 >> 0x13;
      }
      if ((uVar3 & 1) != 0) {
        if (((int)(uVar6 * 0x10) < DAT_080601fc) && (DAT_080601e4 != 0)) {
          *param_2 = 0xffffffff;
          uVar3 = FUN_0804c9cc(*(uint *)(DAT_080601ec + uVar6 * 0x10));
          return uVar3 + DAT_080601e4;
        }
        return 0;
      }
      uVar3 = FUN_0804c9cc(*(uint *)(DAT_08060208 + 8));
      if ((int)uVar3 <= (int)uVar6) {
        return 0;
      }
      *param_2 = 0xffffffff;
      uVar4 = 0;
      local_14 = DAT_08060208;
      if (0 < (int)uVar3) {
        iVar5 = 0;
        do {
          if ((uVar6 != uVar4) &&
             (*(int *)(uVar6 * 0x14 + DAT_08060208 + 0x18) == *(int *)(DAT_08060208 + 0x18 + iVar5))
             ) {
            *param_2 = uVar6;
            local_14 = DAT_08060208;
            break;
          }
          iVar5 = iVar5 + 0x14;
          uVar4 = uVar4 + 1;
        } while ((int)uVar4 < (int)uVar3);
      }
      DAT_08060208 = local_14;
      uVar3 = FUN_0804c9cc(*(uint *)(local_14 + 0x18 + uVar6 * 0x14));
      iVar5 = uVar3 + DAT_080601e4;
    }
    puVar2 = puVar2 + 2;
  } while( true );
}



undefined1 * FUN_08049bb0(undefined1 *param_1,undefined1 *param_2,byte *param_3,uint *param_4)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  if (param_1 < param_2 + -1) {
    iVar3 = (int)param_2 - (int)param_1;
    if ((DAT_0805ec30 & 1) == 0) {
      uVar2 = FUN_080516cc(param_3,param_1,iVar3,0);
    }
    else {
      uVar2 = 0;
    }
    if ((int)uVar2 < 1) {
      uVar2 = 0xffffffff;
      pbVar4 = param_3;
      do {
        if (uVar2 == 0) break;
        uVar2 = uVar2 - 1;
        bVar1 = *pbVar4;
        pbVar4 = pbVar4 + 1;
      } while (bVar1 != 0);
      if (iVar3 < (int)~uVar2) {
        *param_4 = ~uVar2;
      }
      param_1 = FUN_08051994(param_1,param_2,(char *)param_3);
    }
    else if (iVar3 < (int)uVar2) {
      param_1 = param_1 + iVar3 + -1;
      *param_4 = uVar2;
    }
    else {
      param_1 = param_1 + (uVar2 - 1);
    }
  }
  return param_1;
}



char * FUN_08049c38(int param_1,int param_2,uint param_3,undefined4 param_4,int *param_5,
                   char *param_6)

{
  int iVar1;
  int *piVar2;
  byte *pbVar3;
  char *pcVar4;
  uint uVar5;
  undefined1 *puVar6;
  int *piVar7;
  uint local_10;
  uint local_c;
  uint local_8;
  
  iVar1 = param_5[3];
  if (param_1 != 1) {
    if (param_1 != 0) {
      return param_6;
    }
    pbVar3 = (byte *)FUN_08049a48((param_3 - param_2) - *param_5,&local_8);
    if (pbVar3 != (byte *)0x0) {
      puVar6 = (undefined1 *)param_5[4];
      if (param_3 != 0) {
        puVar6 = puVar6 + -0xb;
      }
      local_c = 0;
      pcVar4 = FUN_08049bb0(param_6,puVar6,pbVar3,&local_c);
      if (0 < (int)local_c) {
        param_5[5] = (int)(param_6 + local_c + (0xb - iVar1));
      }
      if (param_3 == 0) {
        return pcVar4;
      }
      if ((int)param_3 < 0) {
        sprintf(pcVar4,"-0x%lx",-param_3);
        return pcVar4;
      }
      sprintf(pcVar4,"+0x%lx",param_3);
      return pcVar4;
    }
  }
  piVar7 = (int *)param_5[1];
  if (piVar7 != (int *)0x0) {
    piVar2 = (int *)param_5[2];
    for (; piVar7 < piVar2; piVar7 = piVar7 + 1) {
      uVar5 = FUN_0804c9cc(*(uint *)(*piVar7 + 8));
      if (uVar5 == param_3) {
        uVar5 = FUN_0804c9cc(*(uint *)*piVar7);
        local_10 = 0;
        pcVar4 = FUN_08049bb0(param_6,(undefined1 *)param_5[4],(byte *)(uVar5 + DAT_080601e4),
                              &local_10);
        if ((int)local_10 < 1) {
          return pcVar4;
        }
        param_5[5] = (int)(param_6 + local_10 + (0xb - iVar1));
        return pcVar4;
      }
    }
  }
  return param_6;
}



void FUN_08049d74(uint *param_1,int param_2,int *param_3)

{
  uint *puVar1;
  uint *__ptr;
  uint uVar2;
  int iVar3;
  char *__s1;
  char *pcVar4;
  char *pcVar5;
  bool bVar6;
  char *local_1c;
  uint local_18;
  uint *local_10;
  uint local_c;
  uint *local_8;
  
  local_c = 0xffffffff;
  __ptr = FUN_08049620(param_1,&local_8);
  if (__ptr != (uint *)0x0) {
    if (__ptr != local_8) {
      local_1c = "x$constdata";
      local_10 = __ptr;
      do {
        puVar1 = (uint *)*local_10;
        local_18 = FUN_0804c9cc(puVar1[2]);
        uVar2 = FUN_0804c9cc(*puVar1);
        __s1 = (char *)(uVar2 + DAT_080601e4);
        if (-1 < (int)local_c) {
          iVar3 = strncmp(__s1,"x$litpool_e$",0xc);
          if (iVar3 == 0) {
            if ((local_18 & 3) != 0) {
              local_18 = local_18 + 1;
            }
            param_3[1] = param_3[1] + (local_18 - local_c);
            local_c = 0xffffffff;
          }
        }
        iVar3 = 0xc;
        bVar6 = true;
        pcVar4 = __s1;
        pcVar5 = local_1c;
        do {
          if (iVar3 == 0) break;
          iVar3 = iVar3 + -1;
          bVar6 = *pcVar4 == *pcVar5;
          pcVar4 = pcVar4 + 1;
          pcVar5 = pcVar5 + 1;
        } while (bVar6);
        if (bVar6) {
          param_3[2] = param_2 - local_18;
        }
        else {
          iVar3 = strncmp(__s1,"x$litpool$",10);
          if (iVar3 == 0) {
            local_c = local_18;
          }
        }
        local_10 = local_10 + 1;
      } while (local_10 != local_8);
    }
    free(__ptr);
  }
  *param_3 = (param_2 - param_3[1]) - param_3[2];
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08049e80(int param_1,uint *param_2,int param_3)

{
  uchar param1;
  uint uVar1;
  uint param4;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;
  uint param3;
  uint uVar6;
  
  uVar1 = FUN_0804c9cc(param_2[1]);
  param4 = FUN_0804c9cc(param_2[2]);
  if ((DAT_0805ec30 & 8) == 0) {
    uVar2 = FUN_0804c9cc(param_2[3]);
    uVar6 = param4;
    uVar3 = FUN_0804924c(uVar1 & 0xff);
    uVar4 = FUN_0804c9cc(*param_2);
    pcVar5 = FUN_08048eb8(uVar4);
    printf("** Area %d %s, Alignment %u, Size %u (0x%.4x), %lu relocations\n",param_1,pcVar5,uVar3,
           param4,uVar6,uVar2);
  }
  else {
    uVar2 = FUN_0804c9cc(param_2[3]);
    uVar6 = param4;
    uVar3 = FUN_0804924c(uVar1 & 0xff);
    param3 = param_3 + _DAT_08060204;
    uVar4 = FUN_0804c9cc(*param_2);
    pcVar5 = FUN_08048eb8(uVar4);
    printf("** Area %d %s (offset 0x%x), Alignment %u, Size %u (0x%.4x), %lu relocations\n",param_1,
           pcVar5,param3,uVar3,param4,uVar6,uVar2);
  }
  printf("        Attributes");
  if ((uVar1 & 0x100) != 0) {
    printf(": Absolute");
  }
  if ((uVar1 & 0x200) == 0) {
    printf(": Data");
    if ((uVar1 & 0x200000) != 0) {
      printf(": Stub data");
    }
    if ((uVar1 & 0x100000) != 0) {
      printf(": Based r%lu",(int)uVar1 >> 0x18 & 0xf);
    }
  }
  else {
    printf(": Code");
    if ((uVar1 & 0x7f0000) != 0) {
      param1 = '{';
      if ((uVar1 & 0x10000) != 0) {
        printf("%c32bit",'{');
        param1 = ',';
      }
      if ((uVar1 & 0x20000) != 0) {
        printf("%creentrant",param1);
        param1 = ',';
      }
      if ((uVar1 & 0x40000) != 0) {
        printf("%cFPIS3",param1);
        param1 = ',';
      }
      if ((uVar1 & 0x80000) != 0) {
        printf("%cNoSWStackCheck",param1);
        param1 = ',';
      }
      if ((uVar1 & 0x100000) != 0) {
        printf("%cTHUMB",param1);
        param1 = ',';
      }
      if ((uVar1 & 0x200000) != 0) {
        printf("%cARM-Halfword",param1);
        param1 = ',';
      }
      if ((uVar1 & 0x400000) != 0) {
        printf("%cARM/THUMB-Interworking",param1);
      }
      fputc(0x7d,stdout);
    }
    if ((uVar1 & 0x4000) != 0) {
      printf(": Position-independent");
    }
  }
  if ((uVar1 & 0x400) != 0) {
    printf(": Common definition");
  }
  if ((uVar1 & 0x800) != 0) {
    printf(": Common");
  }
  if ((uVar1 & 0x1000) != 0) {
    printf(": Zero initialised");
  }
  if ((uVar1 & 0x2000) == 0) {
    pcVar5 = ": Read Write";
  }
  else {
    pcVar5 = ": Read only";
  }
  printf(pcVar5);
  if ((short)uVar1 < 0) {
    printf(": Debugging tables");
  }
  if ((uVar1 & 0x100) == 0) {
    param_2[4] = 0;
  }
  else {
    uVar1 = FUN_0804c9cc(param_2[4]);
    printf("        Base address 0x%.6lx\n",uVar1);
  }
  _IO_putc(10,stdout);
  return;
}



void FUN_0804a164(uint *param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  char *pcVar4;
  
  uVar1 = FUN_0804c9cc(param_1[1]);
  uVar2 = FUN_0804c9cc(*param_1);
  iVar3 = FUN_08048d9c(uVar2);
  if (((DAT_0805ec30 & 4) == 0) && (0x14 < iVar3)) {
    _IO_putc(10,stdout);
    iVar3 = 0;
  }
  while (iVar3 < 0x14) {
    _IO_putc(0x20,stdout);
    iVar3 = iVar3 + 1;
  }
  printf(" : ");
  if ((uVar1 & 3) == 2) {
    if ((uVar1 & 0x40) == 0) {
      pcVar4 = "External reference";
    }
    else {
      pcVar4 = "External common reference";
    }
    printf(pcVar4);
    if ((uVar1 & 0x1000) != 0) {
      printf(", 16-bit code");
    }
    if ((uVar1 & 0x200) != 0) {
      printf(", FPRegArgs");
    }
    if ((uVar1 & 8) != 0) {
      printf(", No-case");
    }
    if ((uVar1 & 0x10) != 0) {
      printf(", Weak");
    }
    if ((uVar1 & 0x40) == 0) goto LAB_0804a37e;
    uVar1 = FUN_0804c9cc(param_1[2]);
    pcVar4 = ", size = 0x%.4lx";
  }
  else {
    if ((uVar1 & 3) == 1) {
      pcVar4 = "Local,  ";
    }
    else {
      pcVar4 = "Global, ";
    }
    printf(pcVar4);
    if ((uVar1 & 0x100) == 0) {
      if ((uVar1 & 0x1000) != 0) {
        printf("16-bit code, ");
      }
      if ((uVar1 & 0x200) != 0) {
        printf("FPRegArgs, ");
      }
      if ((uVar1 & 0x400) != 0) {
        printf("Sb, ");
      }
      if ((uVar1 & 0x800) != 0) {
        pcVar4 = "Leaf, ";
        goto LAB_0804a2ec;
      }
    }
    else {
      pcVar4 = "Data, ";
LAB_0804a2ec:
      printf(pcVar4);
    }
    if ((uVar1 & 4) == 0) {
      pcVar4 = "Relative, ";
    }
    else {
      pcVar4 = "Absolute, ";
    }
    printf(pcVar4);
    if ((uVar1 & 0x20) != 0) {
      printf("Strong, ");
    }
    if ((uVar1 & 4) == 0) {
      if (param_2 != 0) {
        uVar1 = FUN_0804c9cc(param_1[3]);
        pcVar4 = FUN_08048eb8(uVar1);
        uVar1 = FUN_0804c9cc(param_1[2]);
        printf("offset 0x%.4lx in area \"%s\"",uVar1,pcVar4);
        goto LAB_0804a37e;
      }
      uVar1 = FUN_0804c9cc(param_1[2]);
      pcVar4 = "offset 0x%.4lx";
    }
    else {
      uVar1 = FUN_0804c9cc(param_1[2]);
      pcVar4 = "value 0x%.4lx";
    }
  }
  printf(pcVar4,uVar1);
LAB_0804a37e:
  _IO_putc(10,stdout);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804a394(int param_1,uint *param_2,uint param_3,int param_4,int param_5,int param_6)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined1 *puVar4;
  char *__format;
  
  iVar1 = param_6 + param_5;
  if (param_6 != 0) {
    iVar2 = param_5 + _DAT_08060204;
    uVar3 = FUN_0804c9cc(*param_2);
    puVar4 = FUN_08048eb8(uVar3);
    if ((DAT_0805ec30 & 8) == 0) {
      __format = "\n** Relocation table for area %d %s\n\n";
    }
    else {
      __format = "\n** Relocation table for area %d %s (offset 0x%x)\n\n";
    }
    printf(__format,param_3,puVar4,iVar2);
    for (; param_5 < iVar1; param_5 = param_5 + 8) {
      FUN_08049270(param_1,(uint *)(DAT_080601e8 + param_5),param_4 + DAT_080601e8,param_3);
    }
  }
  return;
}



void FUN_0804a420(int param_1,uint param_2,undefined4 param_3)

{
  uint uVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  uint uVar5;
  uint uVar6;
  undefined3 extraout_var;
  char *pcVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  byte bVar13;
  uint *puVar14;
  uint uVar15;
  uint *puVar16;
  int *piVar17;
  int *piVar18;
  uint *puVar19;
  uint **ppuVar20;
  uint *local_c4;
  uint *local_c0;
  uint *local_ac;
  uint local_a8;
  int local_a4;
  int local_a0;
  uint *local_9c;
  uint *local_98;
  uint local_90;
  short local_88;
  uint local_7c;
  uint local_78;
  uint local_74;
  uint *local_6c;
  uint *local_68;
  uint *local_64 [4];
  char *local_54;
  int local_50;
  uint *local_4c [4];
  char *local_3c;
  int local_38;
  int local_34 [6];
  int local_1c [4];
  int local_c;
  int local_8;
  
  uVar5 = FUN_0804c9cc(*(uint *)(param_1 + 8));
  local_74 = 0;
  uVar1 = param_2 & 0x200;
  if (uVar1 != 0) {
    piVar17 = &DAT_080589e4;
    piVar18 = local_1c;
    for (iVar12 = 6; iVar12 != 0; iVar12 = iVar12 + -1) {
      *piVar18 = *piVar17;
      piVar17 = piVar17 + 1;
      piVar18 = piVar18 + 1;
    }
  }
  local_7c = 0;
  uVar8 = param_2 & 0x10;
  local_6c = (uint *)(param_1 + 0x18);
  do {
    if ((int)uVar5 <= (int)local_7c) {
      if (uVar8 != 0) {
        local_74 = 0;
        local_7c = 0;
        if (0 < (int)uVar5) {
          local_c0 = (uint *)(param_1 + 0x24);
          local_c4 = (uint *)(param_1 + 0x20);
          local_6c = (uint *)(param_1 + 0x18);
          do {
            uVar8 = FUN_0804c9cc(local_c4[-1]);
            uVar9 = FUN_0804c9cc(*local_c4);
            if ((uVar8 & 0x1000) == 0) {
              local_78 = uVar9 + 3 + local_74 & 0xfffffffc;
            }
            else {
              local_78 = local_74;
            }
            if ((int)DAT_080601f8 < (int)local_78) {
              local_78 = DAT_080601f8;
            }
            uVar10 = FUN_0804c9cc(*local_c0);
            DAT_08060234 = uVar10 * 8;
            if ((int)DAT_080601f8 < (int)(DAT_08060234 + local_78)) {
              DAT_08060234 = DAT_080601f8 - local_78;
            }
            DAT_08060230 = (uint *)(local_74 + DAT_080601e8 + uVar9);
            if (((DAT_080601e8 != 0) && ((short)uVar8 < 0)) &&
               ((DAT_08060214 == 0 || (iVar12 = FUN_08049a0c(*local_6c), iVar12 != 0)))) {
              iVar12 = local_74 + DAT_080601e8;
              uVar8 = FUN_0804c9cc(*local_6c);
              if ((((-1 < (int)uVar8) && ((int)uVar8 <= DAT_08060200)) && (DAT_080601e4 != 0)) &&
                 ((*(char *)(uVar8 + DAT_080601e4) == '.' &&
                  (iVar11 = FUN_080559dc((char *)(uVar8 + DAT_080601e4)), iVar11 == 2)))) {
                FUN_08049e80(local_7c,local_6c,local_74);
                FUN_08055908(stdout,(char *)(uVar8 + DAT_080601e4),iVar12,0,uVar9,0x40000000,
                             (uint)(DAT_0805ec2c == 1));
                if ((param_2 & 0x20) != 0) {
                  FUN_0804a394(param_1,local_6c,local_7c,local_74,local_78,DAT_08060234);
                }
                printf("\n\n");
              }
            }
            local_7c = local_7c + 1;
            local_c4 = local_c4 + 5;
            local_c0 = local_c0 + 5;
            local_6c = local_6c + 5;
            local_74 = local_78 + DAT_08060234;
          } while ((int)local_7c < (int)uVar5);
        }
      }
      if (uVar1 != 0) {
        FUN_080497bc(param_3,local_1c,&DAT_08060218);
      }
      return;
    }
    bVar3 = false;
    uVar9 = FUN_0804c9cc(local_6c[1]);
    uVar10 = FUN_0804c9cc(local_6c[2]);
    uVar15 = uVar9 & 0x1000;
    if (uVar15 == 0) {
      local_78 = uVar10 + 3 + local_74;
    }
    else {
      local_78 = local_74 + 3;
    }
    local_78 = local_78 & 0xfffffffc;
    if ((int)DAT_080601f8 < (int)local_78) {
      local_78 = DAT_080601f8;
    }
    uVar6 = FUN_0804c9cc(local_6c[3]);
    DAT_08060234 = uVar6 * 8;
    if ((int)DAT_080601f8 < (int)(DAT_08060234 + local_78)) {
      DAT_08060234 = DAT_080601f8 - local_78;
    }
    if ((DAT_08060214 == 0) || (iVar12 = FUN_08049a0c(*local_6c), iVar12 != 0)) {
      if ((param_2 & 0x100) != 0) {
        uVar6 = FUN_0804c9cc(*local_6c);
        iVar12 = FUN_08048d9c(uVar6);
        FUN_08048d44(iVar12,0x18);
        printf("%8ld\n",uVar10);
      }
      if (uVar1 != 0) {
        if ((uVar9 & 0x200) == 0) {
          local_88 = (short)uVar9;
          if (local_88 < 0) {
            local_8 = local_8 + uVar10;
          }
          else if (uVar15 == 0) {
            if ((uVar9 & 0x800) == 0) {
              if ((uVar9 & 0x2000) == 0) {
                local_1c[3] = local_1c[3] + uVar10;
              }
              else {
                local_1c[2] = local_1c[2] + uVar10;
              }
            }
          }
          else {
            local_c = local_c + uVar10;
          }
        }
        else {
          piVar17 = &DAT_080589e4;
          piVar18 = local_34;
          for (iVar12 = 6; iVar12 != 0; iVar12 = iVar12 + -1) {
            *piVar18 = *piVar17;
            piVar17 = piVar17 + 1;
            piVar18 = piVar18 + 1;
          }
          FUN_08049d74(local_6c,uVar10,local_34);
          local_1c[0] = local_1c[0] + local_34[0];
          local_1c[1] = local_1c[1] + local_34[1];
          local_1c[2] = local_1c[2] + local_34[2];
        }
      }
      if ((((uVar9 & 0x8000) != 0) && (uVar8 != 0)) || ((param_2 & 1) != 0)) {
        if ((uVar15 == 0) && (uVar10 != 0)) {
          if (DAT_080601e8 != 0) {
            puVar14 = (uint *)(DAT_080601e8 + local_74);
            puVar19 = (uint *)((int)puVar14 + uVar10);
            DAT_08060230 = puVar19;
            if (((uVar9 & 0x8000) == 0) || (uVar8 == 0)) {
              local_98 = (uint *)0x0;
              FUN_08049e80(local_7c,local_6c,local_74);
              bVar3 = true;
              local_90 = FUN_0804c9cc(local_6c[4]);
              if ((((uVar9 & 0x200) != 0) && ((param_2 & 0x40) != 0)) || ((param_2 & 2) != 0)) {
                local_98 = FUN_08049620(local_6c,&local_68);
              }
              if (((uVar9 & 0x200) == 0) || ((param_2 & 0x40) == 0)) {
                if ((param_2 & 2) != 0) {
                  uVar9 = 0;
                  puVar14 = local_98;
                  for (uVar10 = local_74; (int)uVar10 < (int)local_78; uVar10 = uVar10 + 4) {
                    if ((uVar9 & 7) == 0) {
                      _IO_putc(10,stdout);
                      if ((local_98 != (uint *)0x0) && (puVar14 < local_68)) {
                        while (uVar9 = FUN_0804c9cc(*(uint *)(*puVar14 + 8)),
                              (int)uVar9 < (int)(local_90 + 0x20)) {
                          FUN_08049840((uint *)*puVar14,local_90);
                          puVar14 = puVar14 + 1;
                          if ((local_98 == (uint *)0x0) || (local_68 <= puVar14)) break;
                        }
                      }
                      printf("%.6lx:",local_90);
                      local_90 = local_90 + 0x20;
                      uVar9 = 0;
                    }
                    uVar15 = FUN_0804c9cc(*(uint *)(uVar10 + DAT_080601e8));
                    printf(" %.8lx",uVar15);
                    uVar9 = uVar9 + 1;
                  }
                  if (local_98 == (uint *)0x0) goto LAB_0804adae;
                  do {
                    if (local_68 <= puVar14) break;
                    FUN_08049840((uint *)*puVar14,local_90);
                    puVar14 = puVar14 + 1;
                  } while (local_98 != (uint *)0x0);
                }
LAB_0804ad96:
                if (local_98 != (uint *)0x0) {
                  free(local_98);
                }
              }
              else {
                local_9c = local_98;
                local_a0 = 4;
                local_a4 = local_74;
                if ((int)local_74 < (int)local_78) {
                  do {
                    uVar10 = 0;
                    local_a8 = 0xffffffff;
                    local_ac = (uint *)(local_a4 + DAT_080601e8);
                    if ((DAT_0805ec34 == 0) &&
                       (DAT_08060210 = malloc(0x150), DAT_08060210 != (char *)0x0)) {
                      DAT_0805ec34 = 0x100;
                    }
                    if (0 < DAT_0805ec34) {
                      if ((uVar9 & 0x100000) == 0) {
                        ppuVar20 = local_64;
                        for (iVar12 = 6; iVar12 != 0; iVar12 = iVar12 + -1) {
                          *ppuVar20 = (uint *)0x0;
                          ppuVar20 = ppuVar20 + 1;
                        }
                        local_64[0] = (uint *)0x8;
                        local_64[1] = local_98;
                        local_64[2] = local_68;
                        local_64[3] = (uint *)DAT_08060210;
                        local_54 = DAT_08060210 + DAT_0805ec34;
                        uVar10 = FUN_0804c9cc(*local_ac);
                        local_a0 = FUN_0804e950(uVar10,local_90,DAT_08060210,local_64,FUN_08049c38);
                        if ((0 < local_50) &&
                           (pcVar7 = malloc(local_50 + 0x51), pcVar7 != (char *)0x0)) {
                          free(DAT_08060210);
                          DAT_0805ec34 = local_50;
                          local_54 = pcVar7 + local_50;
                          DAT_08060210 = pcVar7;
                          local_64[3] = (uint *)pcVar7;
                          local_a0 = FUN_0804e950(uVar10,local_90,pcVar7,local_64,FUN_08049c38);
                        }
                      }
                      else {
                        ppuVar20 = local_4c;
                        for (iVar12 = 6; iVar12 != 0; iVar12 = iVar12 + -1) {
                          *ppuVar20 = (uint *)0x0;
                          ppuVar20 = ppuVar20 + 1;
                        }
                        local_4c[0] = (uint *)0x3;
                        local_4c[1] = local_98;
                        local_4c[2] = local_68;
                        local_4c[3] = (uint *)DAT_08060210;
                        local_3c = DAT_08060210 + DAT_0805ec34;
                        uVar10 = FUN_0804ca04((uint)(ushort)*local_ac);
                        local_a8 = FUN_0804ca04((uint)*(ushort *)((int)local_ac + 2));
                        local_a0 = FUN_0804dfec(uVar10,local_a8,local_90,DAT_08060210,local_4c,
                                                FUN_08049c38);
                        if ((0 < local_38) &&
                           (pcVar7 = malloc(local_38 + 0x50), pcVar7 != (char *)0x0)) {
                          free(DAT_08060210);
                          DAT_0805ec34 = local_38;
                          local_3c = pcVar7 + local_38;
                          DAT_08060210 = pcVar7;
                          local_4c[3] = (uint *)pcVar7;
                          local_a0 = FUN_0804dfec(uVar10,local_a8,local_90,pcVar7,local_4c,
                                                  FUN_08049c38);
                        }
                      }
                    }
                    if ((local_98 != (uint *)0x0) && (local_9c < local_68)) {
                      while (uVar15 = FUN_0804c9cc(*(uint *)(*local_9c + 8)),
                            (int)uVar15 < (int)(local_90 + local_a0)) {
                        FUN_08049840((uint *)*local_9c,local_90);
                        local_9c = local_9c + 1;
                        if ((local_98 == (uint *)0x0) || (local_68 <= local_9c)) break;
                      }
                    }
                    printf("  0x%.6lx:  ",local_90);
                    local_90 = local_90 + local_a0;
                    if ((uVar9 & 0x100000) == 0) {
                      pcVar7 = "%.8lx  ";
LAB_0804abc6:
                      printf(pcVar7,uVar10);
                    }
                    else {
                      printf("%.4lx ",uVar10);
                      if (2 < local_a0) {
                        pcVar7 = "%.4lx  ";
                        uVar10 = local_a8;
                        goto LAB_0804abc6;
                      }
                      printf("      ");
                    }
                    iVar12 = 0;
                    do {
                      if (iVar12 < local_a0) {
                        bVar13 = (byte)*local_ac;
                        local_ac = (uint *)((int)local_ac + 1);
                      }
                      else {
                        bVar13 = 0x20;
                      }
                      uVar10 = (uint)bVar13;
                      iVar11 = isprint(uVar10);
                      if (iVar11 == 0) {
                        uVar10 = 0x2e;
                      }
                      _IO_putc(uVar10,stdout);
                      iVar12 = iVar12 + 1;
                    } while (iVar12 < 4);
                    if (DAT_08060210 == (char *)0x0) {
                      printf("[no space for buffer]\n");
                    }
                    else {
                      printf(" : %s\n",DAT_08060210);
                    }
                    local_a4 = local_a4 + local_a0;
                  } while (local_a4 < (int)local_78);
                }
                while (local_98 != (uint *)0x0) {
                  if (local_68 <= local_9c) goto LAB_0804ad96;
                  FUN_08049840((uint *)*local_9c,local_90);
                  local_9c = local_9c + 1;
                }
              }
            }
            else {
              uVar9 = FUN_0804c9cc(*local_6c);
              if (((((int)uVar9 < 0) || (DAT_08060200 < (int)uVar9)) || (DAT_080601e4 == 0)) ||
                 (*(char *)(uVar9 + DAT_080601e4) != '.')) {
                FUN_08049e80(local_7c,local_6c,local_74);
                bVar3 = true;
                FUN_08051cc8(puVar14);
                do {
                  if (puVar19 <= puVar14) break;
                  puVar14 = FUN_08051cd8(stdout,puVar14,puVar19,1);
                } while (puVar14 != (uint *)0x0);
              }
              else {
                iVar12 = FUN_080559dc((char *)(uVar9 + DAT_080601e4));
                if (iVar12 == 0) {
                  FUN_08049e80(local_7c,local_6c,local_74);
                  bVar3 = true;
                  if ((param_2 & 0x400) == 0) {
                    uVar15 = 0x40000000;
                  }
                  else {
                    uVar15 = 0x50000000;
                  }
                  FUN_08055250(stdout,(char *)(uVar9 + DAT_080601e4),puVar14,uVar10,uVar15);
                }
                else {
                  if (iVar12 == 2) goto LAB_0804aea1;
                  FUN_08049e80(local_7c,local_6c,local_74);
                  bVar3 = true;
                  FUN_08055750(stdout,(char *)(uVar9 + DAT_080601e4),(int)puVar14,0,uVar10,
                               0x40000000,(uint)(DAT_0805ec2c == 1));
                }
              }
            }
          }
        }
        else {
          FUN_08049e80(local_7c,local_6c,local_74);
          bVar3 = true;
        }
LAB_0804adae:
        if ((((param_2 & 0x1000) != 0) && (DAT_080601ec != (uint *)0x0)) && (DAT_080601e4 != 0)) {
          bVar2 = false;
          uVar9 = DAT_080601fc;
          if ((int)DAT_080601fc < 0) {
            uVar9 = DAT_080601fc + 0xf;
          }
          puVar14 = (uint *)((uVar9 & 0xfffffff0) + (int)DAT_080601ec);
          if (DAT_080601ec < puVar14) {
            puVar19 = DAT_080601ec + 3;
            puVar16 = DAT_080601ec;
            do {
              uVar9 = FUN_0804c9cc(puVar19[-2]);
              if (((uVar9 & 5) == 1) &&
                 (bVar4 = FUN_08049570(*puVar19,*local_6c), CONCAT31(extraout_var,bVar4) != 0)) {
                if (!bVar2) {
                  uVar9 = FUN_0804c9cc(*local_6c);
                  pcVar7 = FUN_08048eb8(uVar9);
                  printf("\n** Symbols in area %d %s\n\n",local_7c,pcVar7);
                  bVar2 = true;
                }
                FUN_0804a164(puVar16,0);
              }
              puVar19 = puVar19 + 4;
              puVar16 = puVar16 + 4;
            } while (puVar16 < puVar14);
          }
        }
        if (bVar3) {
          if ((param_2 & 0x20) != 0) {
            FUN_0804a394(param_1,local_6c,local_7c,local_74,local_78,DAT_08060234);
          }
          printf("\n\n");
        }
      }
    }
LAB_0804aea1:
    local_7c = local_7c + 1;
    local_6c = local_6c + 5;
    local_74 = local_78 + DAT_08060234;
  } while( true );
}



void FUN_0804b0ec(int param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  char *pcVar4;
  
  puVar3 = DAT_080601ec;
  if (DAT_080601ec == (uint *)0x0) {
    pcVar4 = "** No symbol table **\n\n";
  }
  else {
    uVar1 = FUN_0804c9cc(*(uint *)(param_1 + 0xc));
    iVar2 = uVar1 * 0x10;
    if ((iVar2 != DAT_080601fc) &&
       (FUN_0804fbe8("anomaly: symbol table size %ld != OBJ_SYMT chunk size %ld"),
       DAT_080601fc < iVar2)) {
      iVar2 = DAT_080601fc;
    }
    if (iVar2 < 0) {
      iVar2 = iVar2 + 0xf;
    }
    if (iVar2 >> 4 < 1) {
      return;
    }
    if ((DAT_0805ec30 & 8) == 0) {
      pcVar4 = "** Symbol Table (file %s):-\n\n";
    }
    else {
      pcVar4 = "** Symbol Table (file %s, offset 0x%x):-\n\n";
    }
    printf(pcVar4,param_3,param_2);
    iVar2 = iVar2 >> 4;
    while (0 < iVar2) {
      FUN_0804a164(puVar3,1);
      puVar3 = puVar3 + 4;
      iVar2 = iVar2 + -1;
    }
    pcVar4 = "\n\n";
  }
  printf(pcVar4);
  return;
}



void FUN_0804b19c(int param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  char *__format;
  ulong param1;
  
  puVar2 = DAT_080601e4;
  if (DAT_080601e4 == (uint *)0x0) {
    printf("** No string table **\n\n");
  }
  else {
    param1 = 0;
    uVar3 = FUN_0804c9cc(*(uint *)(param_1 + 4));
    uVar4 = DAT_08060200;
    if (0x95 < (int)uVar3) {
      uVar4 = FUN_0804c9cc(*puVar2);
      if ((uVar4 == DAT_08060200) || ((uVar4 + 3 & 0xfffffffc) == DAT_08060200)) {
        param1 = 4;
      }
      else {
        FUN_0804fbe8("anomaly: string table size %lx != OBJ_STRT chunk size %lx\n");
        uVar4 = DAT_08060200;
      }
    }
    if ((DAT_0805ec30 & 8) == 0) {
      __format = "** String Table (file %s):-\n\n";
    }
    else {
      __format = "** String Table (file %s, offset 0x%x):-\n\n";
    }
    printf(__format,param_3,param_2);
    printf("Offset  String-name\n-------------------\n");
    while (uVar1 = param1, (int)param1 < (int)uVar4) {
      for (; ((int)uVar1 < (int)uVar4 && (*(char *)(uVar1 + (int)puVar2) != '\0'));
          uVar1 = uVar1 + 1) {
      }
      if (uVar1 == uVar4) {
        *(undefined1 *)((int)puVar2 + (uVar4 - 1)) = 0;
      }
      if (0 < (int)uVar1) {
        printf("%6lu: ",param1);
        FUN_08048d9c(param1);
        _IO_putc(10,stdout);
      }
      param1 = uVar1 + 1;
      if ((int)uVar3 < 0x96) {
        while( true ) {
          if ((int)uVar4 <= (int)param1) {
            return;
          }
          if ((param1 & 3) == 0) break;
          param1 = param1 + 1;
        }
      }
      else {
        for (; *(char *)(param1 + (int)puVar2) == '\0'; param1 = param1 + 1) {
        }
      }
    }
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0804b4e8)

undefined4 FUN_0804b2d8(char *param_1,uint *param_2,uint param_3)

{
  char cVar1;
  int **ppiVar2;
  int *__ptr;
  uint uVar3;
  uint uVar4;
  ulong param1;
  uint uVar5;
  uint uVar6;
  uint param4;
  int iVar7;
  int *piVar8;
  int iVar9;
  uint *puVar10;
  byte bVar11;
  char *pcVar12;
  char *pcVar13;
  ulong uVar14;
  uint *puVar15;
  uint *puVar16;
  undefined4 *puVar17;
  int iVar18;
  char *pcVar19;
  bool bVar20;
  bool bVar21;
  bool bVar22;
  int **local_168;
  uint *local_154;
  uint *local_14c;
  int local_148;
  undefined4 local_13c;
  uint local_138;
  int local_134;
  int *local_120;
  char local_11c [256];
  uint local_1c [4];
  uint local_c;
  uint local_8;
  
  uVar3 = FUN_0804c9cc(param_2[3]);
  bVar20 = (uVar3 & 0xff000000) != 0;
  uVar3 = FUN_0804c9cc(*param_2);
  bVar21 = uVar3 != 0xe1a00000;
  uVar3 = FUN_0804c9cc(param_2[1]);
  uVar4 = FUN_0804c9cc(param_2[0xc]);
  uVar14 = uVar4 & 0xff;
  local_134 = 0;
  local_138 = 0;
  local_13c = 0;
  if (uVar14 == 0) {
    uVar14 = 0x1a;
  }
  uVar4 = param_3 & 0x200;
  if (uVar4 == 0) {
    if ((param_3 & 0x100) == 0) {
      printf("%s: AIF image: ",param_1);
      if (bVar21) {
        printf("Compressed, ");
      }
      if (uVar3 != 0xe1a00000) {
        printf("Relocatable, ");
      }
      if (bVar20) {
        pcVar13 = "Executable, ";
      }
      else {
        pcVar13 = "Non-executable, ";
      }
      printf(pcVar13);
      if (DAT_0805ec2c == 1) {
        pcVar13 = "Big-endian, ";
      }
      else {
        pcVar13 = "Little-endian, ";
      }
      printf(pcVar13);
      printf("%lu-bit\n",uVar14);
      uVar14 = FUN_0804c9cc(param_2[5]);
      if (bVar20) {
        uVar14 = uVar14 - 0x80;
      }
      param1 = FUN_0804c9cc(param_2[10]);
      if (bVar20) {
        param1 = param1 + 0x80;
      }
      printf("    Read Only Section at:  0x%.8lx, size = %6lu (0x%.6lx)\n",param1,uVar14,uVar14);
      uVar5 = FUN_0804c9cc(param_2[6]);
      printf("    Read Write Section at: 0x%.8lx, size = %6lu (0x%.6lx)\n",param1 + uVar14,uVar5,
             uVar5);
      if (param_2[8] != 0) {
        uVar6 = FUN_0804c9cc(param_2[8]);
        printf("    Zero Init Section at:  0x%.8lx, size = %6lu (0x%.6lx)\n",param1 + uVar14 + uVar5
               ,uVar6,uVar6);
      }
      uVar5 = FUN_0804c9cc(param_2[9]);
      uVar6 = FUN_0804c9cc(param_2[7]);
      printf("    Debug size = 0x%.8lx",uVar6);
      if (uVar5 != 0) {
        local_138 = uVar5 >> 4;
        if ((uVar5 & 3) == 1) {
          pcVar13 = ": low-level debugging information";
        }
        else if ((uVar5 & 3) == 2) {
          pcVar13 = ": source-level debugging information";
        }
        else {
          pcVar13 = ": low-level and source-level debugging information";
        }
        printf(pcVar13);
        if (local_138 != 0) {
          printf(": ll info size 0x%lx",local_138);
        }
      }
      printf("\n");
    }
  }
  else {
    puVar15 = &DAT_080589e4;
    puVar16 = local_1c;
    for (iVar9 = 6; iVar9 != 0; iVar9 = iVar9 + -1) {
      *puVar16 = *puVar15;
      puVar15 = puVar15 + 1;
      puVar16 = puVar16 + 1;
    }
    local_1c[0] = FUN_0804c9cc(param_2[5]);
    local_1c[3] = FUN_0804c9cc(param_2[6]);
    local_c = FUN_0804c9cc(param_2[8]);
    local_8 = FUN_0804c9cc(param_2[7]);
  }
  if ((param_2[9] != 0) && (param_2[7] == 0)) {
    FUN_0804fbe8("%s: inconsistency: dbgtype != 0 but dbgsize == 0");
    local_13c = 1;
  }
  if (!bVar21) {
    uVar5 = FUN_0804c9cc(param_2[0xe]);
    if (uVar5 == 0) {
      uVar5 = FUN_0804c9cc(param_2[5]);
      uVar6 = FUN_0804c9cc(param_2[6]);
      local_134 = uVar6 + uVar5;
      if (!bVar20) {
        local_134 = local_134 + 0x80;
      }
    }
    else {
      do {
        if (DAT_080601f4 < uVar5 + 0x2c) {
          FUN_0804fbe8("%s: fragment header outside image file at %#lx");
          local_13c = 1;
          uVar5 = 0;
        }
        else {
          puVar15 = (uint *)(uVar5 + DAT_080601e0);
          uVar6 = FUN_0804c9cc(puVar15[2]);
          param4 = FUN_0804c9cc(puVar15[1]);
          printf("    Fragment %s: file offset %#lx, size %#lx: load address %#lx\n",
                 (char *)(puVar15 + 3),uVar5,uVar6,param4);
          if (DAT_080601f4 < uVar5 + uVar6) {
            FUN_0804fbe8("%s: fragment extends beyond image file (end %#lx, file size %#lx)");
            local_13c = 1;
          }
          else {
            local_134 = uVar5 + uVar6 + 0x2c;
          }
          if (uVar4 != 0) {
            local_1c[0] = local_1c[0] + uVar6;
          }
          uVar5 = FUN_0804c9cc(*puVar15);
        }
      } while (uVar5 != 0);
    }
  }
  uVar5 = FUN_0804c9cc(param_2[7]);
  if (DAT_080601f4 < uVar5 + local_134) {
    FUN_0804c9cc(param_2[7]);
    FUN_0804fbe8("%s: debug info extends beyond image file (end %#lx, file size %#lx)");
    local_13c = 1;
  }
  if (uVar4 != 0) {
    FUN_080497bc(param_1,(int *)local_1c,&DAT_08060218);
  }
  if (!bVar21) {
    if ((param_3 & 0x40) != 0) {
      local_14c = (uint *)(DAT_080601e0 + 0x80);
      uVar4 = FUN_0804c9cc(param_2[10]);
      if (bVar20) {
        uVar4 = uVar4 + 0x80;
      }
      uVar5 = FUN_0804c9cc(param_2[5]);
      local_148 = uVar5 + uVar4;
      if (bVar20) {
        local_148 = local_148 + -0x80;
      }
      if ((int)uVar4 < local_148) {
        do {
          uVar5 = FUN_0804c9cc(*local_14c);
          iVar9 = FUN_0804e950(uVar5,uVar4,local_11c,0,(undefined *)0x0);
          printf("  0x%.6lx:  ",uVar4);
          printf("%.8lx  ",uVar5);
          iVar18 = 0;
          do {
            if (iVar18 < iVar9) {
              bVar11 = (byte)*local_14c;
              local_14c = (uint *)((int)local_14c + 1);
            }
            else {
              bVar11 = 0x20;
            }
            uVar5 = (uint)bVar11;
            iVar7 = isprint(uVar5);
            if (iVar7 == 0) {
              uVar5 = 0x2e;
            }
            _IO_putc(uVar5,stdout);
            iVar18 = iVar18 + 1;
          } while (iVar18 < 4);
          printf(" : %s\n",local_11c);
          uVar4 = uVar4 + iVar9;
        } while ((int)uVar4 < local_148);
      }
    }
    if (!bVar21) {
      if (((param_3 & 0x10) != 0) && (uVar4 = FUN_0804c9cc(param_2[7]), 0 < (int)uVar4)) {
        uVar4 = FUN_0804c9cc(param_2[5]);
        uVar5 = FUN_0804c9cc(param_2[6]);
        local_154 = (uint *)(uVar4 + DAT_080601e0 + uVar5);
        if (!bVar20) {
          local_154 = local_154 + 0x20;
        }
        uVar4 = FUN_0804c9cc(param_2[7]);
        puVar15 = (uint *)((int)local_154 + uVar4);
        if (local_138 == 0) {
          printf("\nASD debug area:\n");
          FUN_08051cc8(local_154);
          do {
            if (puVar15 <= local_154) break;
            local_154 = FUN_08051cd8(stdout,local_154,puVar15,0);
          } while (local_154 != (uint *)0x0);
        }
        else {
          puVar15 = (uint *)((int)puVar15 - local_138);
          uVar4 = FUN_0804c9cc(*puVar15);
          if (((short)uVar4 == 1) && ((char)puVar15[1] == '\0')) {
            uVar5 = FUN_0804c9cc(puVar15[8]);
            puVar10 = puVar15 + 9;
            local_120 = (int *)0x0;
            puVar16 = puVar10;
            ppiVar2 = &local_120;
            uVar4 = uVar5;
            while (uVar4 = uVar4 - 1, -1 < (int)uVar4) {
              uVar6 = FUN_0804c9cc(*puVar16);
              pcVar12 = (char *)((int)puVar10 + (uVar6 & 0xffffff) + uVar5 * 8);
              uVar6 = 0xffffffff;
              pcVar13 = pcVar12;
              do {
                if (uVar6 == 0) break;
                uVar6 = uVar6 - 1;
                cVar1 = *pcVar13;
                pcVar13 = pcVar13 + 1;
              } while (cVar1 != '\0');
              uVar6 = ~uVar6;
              local_168 = ppiVar2;
              if (0xb < uVar6 - 1) {
                iVar9 = 0xc;
                bVar22 = true;
                pcVar13 = pcVar12 + (uVar6 - 0xc);
                pcVar19 = "$$DbgOffset";
                do {
                  if (iVar9 == 0) break;
                  iVar9 = iVar9 + -1;
                  bVar22 = *pcVar13 == *pcVar19;
                  pcVar13 = pcVar13 + 1;
                  pcVar19 = pcVar19 + 1;
                } while (bVar22);
                if (bVar22) {
                  local_168 = malloc(uVar6 + 0x14);
                  local_168[2] = (int *)(local_168 + 5);
                  piVar8 = (int *)FUN_0804c9cc(puVar16[1]);
                  local_168[3] = piVar8;
                  *local_168 = (int *)0x0;
                  local_168[1] = (int *)(uVar6 - 0xc);
                  local_168[4] = (int *)0xffffffff;
                  strncpy((char *)local_168[2],pcVar12,(size_t)(uVar6 - 0xc));
                  *(undefined1 *)((int)local_168[1] + (int)local_168[2]) = 0;
                  *ppiVar2 = (int *)local_168;
                }
              }
              puVar16 = puVar16 + 2;
              ppiVar2 = local_168;
            }
            uVar4 = FUN_0804c9cc(puVar15[8]);
            puVar15 = puVar10;
            while (uVar4 = uVar4 - 1, piVar8 = local_120, -1 < (int)uVar4) {
              uVar6 = FUN_0804c9cc(*puVar15);
              pcVar12 = (char *)((int)puVar10 + (uVar6 & 0xffffff) + uVar5 * 8);
              uVar6 = 0xffffffff;
              pcVar13 = pcVar12;
              do {
                if (uVar6 == 0) break;
                uVar6 = uVar6 - 1;
                cVar1 = *pcVar13;
                pcVar13 = pcVar13 + 1;
              } while (cVar1 != '\0');
              uVar6 = ~uVar6;
              if (7 < uVar6 - 1) {
                iVar9 = 8;
                bVar22 = true;
                pcVar13 = pcVar12 + (uVar6 - 8);
                pcVar19 = "$$Limit";
                do {
                  if (iVar9 == 0) break;
                  iVar9 = iVar9 + -1;
                  bVar22 = *pcVar13 == *pcVar19;
                  pcVar13 = pcVar13 + 1;
                  pcVar19 = pcVar19 + 1;
                } while (bVar22);
                if ((bVar22) && (local_120 != (int *)0x0)) {
                  piVar8 = local_120;
                  do {
                    if ((piVar8[1] == uVar6 - 8) &&
                       (iVar9 = strncmp((char *)piVar8[2],pcVar12,piVar8[1]), iVar9 == 0)) {
                      uVar6 = FUN_0804c9cc(puVar15[1]);
                      piVar8[4] = uVar6;
                      break;
                    }
                    piVar8 = (int *)*piVar8;
                  } while (piVar8 != (int *)0x0);
                }
              }
              puVar15 = puVar15 + 2;
            }
            for (; __ptr = local_120, piVar8 != (int *)0x0; piVar8 = (int *)*piVar8) {
              puVar15 = (uint *)((int)local_154 + piVar8[3]);
              pcVar13 = (char *)piVar8[2];
              if (*pcVar13 == '.') {
                iVar9 = FUN_0805555c(pcVar13);
                if (iVar9 == 0) {
                  FUN_08055750(stdout,(char *)piVar8[2],(int)local_154,piVar8[3],piVar8[4],
                               0x20000000,(uint)(DAT_0805ec2c == 1));
                }
                else {
                  if ((param_3 & 0x400) == 0) {
                    uVar4 = 0x20000000;
                  }
                  else {
                    uVar4 = 0x30000000;
                  }
                  FUN_08055250(stdout,(char *)piVar8[2],puVar15,piVar8[4],uVar4);
                }
              }
              else {
                puVar16 = (uint *)((int)puVar15 + piVar8[4]);
                printf("\n%s:\n",pcVar13);
                FUN_08051cc8(puVar15);
                do {
                  if (puVar16 <= puVar15) break;
                  puVar15 = FUN_08051cd8(stdout,puVar15,puVar16,0);
                } while (puVar15 != (uint *)0x0);
              }
            }
            while (local_120 = __ptr, __ptr != (int *)0x0) {
              if ((*(char *)__ptr[2] == '.') && (iVar9 = FUN_080559dc((char *)__ptr[2]), iVar9 != 0)
                 ) {
                FUN_08055908(stdout,(char *)__ptr[2],(int)local_154,__ptr[3],__ptr[4],0x20000000,
                             (uint)(DAT_0805ec2c == 1));
              }
              local_120 = (int *)*local_120;
              free(__ptr);
              __ptr = local_120;
            }
          }
          else {
            fprintf(stderr,"*** Format Error: Section expected at AREA offset %d\n",local_138);
          }
        }
      }
      if ((!bVar21) && (uVar3 != 0xe1a00000)) {
        if (bVar20) {
          FUN_0804fbe8("%s: sorry, don\'t know how to dump relocations from an execuatable image");
          local_13c = 1;
        }
        else {
          uVar4 = FUN_0804c9cc(param_2[7]);
          if (uVar3 == uVar4 + local_134) {
            if (DAT_080601f4 < uVar3 + 4) {
              puVar17 = (undefined4 *)&stack0xfffffe6c;
            }
            else {
              uVar4 = FUN_0804c9cc(*(uint *)(uVar3 + DAT_080601e0));
              if (uVar3 + 4 + uVar4 * 4 <= DAT_080601f4) {
                if (uVar4 == 1) {
                  pcVar13 = "    %ld relocation.\n";
                }
                else {
                  pcVar13 = "    %ld relocations.\n";
                }
                printf(pcVar13);
                if ((param_3 & 0x20) == 0) {
                  return local_13c;
                }
                if (uVar4 == 0) {
                  return local_13c;
                }
                puVar16 = (uint *)(uVar3 + DAT_080601e0 + 4);
                puVar15 = puVar16 + uVar4;
                iVar9 = 0;
                pcVar13 = "      ";
                while( true ) {
                  while( true ) {
                    printf(pcVar13);
                    if (puVar15 <= puVar16) {
                      return local_13c;
                    }
                    uVar3 = *puVar16;
                    puVar16 = puVar16 + 1;
                    uVar3 = FUN_0804c9cc(uVar3);
                    printf("0x%08lx",uVar3);
                    iVar9 = iVar9 + 1;
                    if ((iVar9 == 8) || (puVar15 <= puVar16)) break;
                    pcVar13 = ",";
                  }
                  iVar9 = 0;
                  _IO_putc(10,stdout);
                  if (puVar15 <= puVar16) break;
                  pcVar13 = "      ";
                }
                return local_13c;
              }
              puVar17 = (undefined4 *)&stack0xfffffe6c;
            }
          }
          else {
            FUN_0804c9cc(param_2[7]);
            puVar17 = (undefined4 *)&stack0xfffffe68;
          }
          puVar17[-1] = 0x804be3a;
          FUN_0804fbe8((char *)*puVar17);
          local_13c = 1;
        }
      }
    }
  }
  return local_13c;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0804bf04(char *param_1,uint param_2)

{
  uint *puVar1;
  FILE *__stream;
  size_t __n;
  size_t sVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  undefined1 *puVar8;
  uint *puVar9;
  int iVar10;
  char *pcVar11;
  uint *local_40;
  uint local_30;
  uint local_2c;
  uint local_28;
  uint local_24;
  
  local_2c = 0xffffffff;
  local_28 = 0xffffffff;
  local_30 = 0xffffffff;
  __stream = fopen(param_1,"r");
  if (__stream == (FILE *)0x0) {
    pcVar11 = "File %s doesn\'t exist?";
LAB_0804c248:
    FUN_0804fbe8(pcVar11);
  }
  else {
    if ((param_2 & 0x100) != 0) {
      printf("file %s\n",param_1);
    }
    fseek(__stream,0,2);
    __n = ftell(__stream);
    if ((int)DAT_080601f0 < (int)__n) goto LAB_0804bf90;
    if (DAT_080601e0 == (uint *)0x0) {
      for (; (int)DAT_080601f0 < (int)__n; DAT_080601f0 = DAT_080601f0 * 2) {
LAB_0804bf90:
      }
      if (DAT_080601e0 != (uint *)0x0) {
        free(DAT_080601e0);
      }
      DAT_080601e0 = malloc(DAT_080601f0);
      if (DAT_080601e0 != (uint *)0x0) goto LAB_0804bfe4;
      puVar8 = &stack0xffffffa8;
      FUN_0804fc0c("Not enough memory to process %s (need %lu bytes)");
    }
    else {
LAB_0804bfe4:
      fseek(__stream,0,0);
      sVar2 = fread(DAT_080601e0,1,__n,__stream);
      if (sVar2 == __n) {
        fclose(__stream);
        puVar1 = DAT_080601e0;
        DAT_080601f4 = __n;
        if (((int)__n < 4) ||
           (((uVar3 = FUN_08048cc0(*DAT_080601e0,0xffffffff,0xc3cbc6c5), (int)uVar3 < 0 &&
             (uVar3 = FUN_08048cc0(*puVar1,0xffffffff,0xe1a00000), (int)uVar3 < 0)) &&
            (uVar3 = FUN_08048cc0(*puVar1,0xff000000,0xeb000000), (int)uVar3 < 0)))) {
          pcVar11 = "%s is neither a chunk file nor an AIF file";
        }
        else {
          uVar3 = FUN_0804c9cc(*puVar1);
          puVar9 = DAT_080601e0;
          if (uVar3 == 0xc3cbc6c5) {
            uVar3 = FUN_0804c9cc(puVar1[1]);
            uVar4 = FUN_0804c9cc(puVar1[2]);
            if ((int)uVar3 < (int)uVar4) {
              FUN_0804fbe8("%s is corrupt: maxchunks(%d) < numchunks(%d)");
              return 1;
            }
            if ((int)__n <= (int)(uVar3 << 4 | 0xc)) {
              FUN_0804fbe8("%s is corrupt: header for maxchunks(%d) exceeds file size");
              return 1;
            }
            iVar7 = 0;
            if (0 < (int)uVar3) {
              local_40 = puVar1 + 5;
              puVar9 = puVar1 + 6;
              do {
                uVar4 = FUN_0804c9cc(*puVar9);
                uVar6 = FUN_0804c9cc(*local_40);
                if ((uVar6 != 0) &&
                   ((((int)uVar6 < 1 || ((int)uVar4 < 0)) || ((int)(__n - uVar4) < (int)uVar6)))) {
                  FUN_0804fbe8(
                              "%s is corrupt: chunk %d(%s) extends over end of file (%lx + %lx, %lx)"
                              );
                  return 1;
                }
                local_40 = local_40 + 4;
                puVar9 = puVar9 + 4;
                iVar7 = iVar7 + 1;
              } while (iVar7 < (int)uVar3);
            }
            iVar7 = FUN_0804ccc0((int)puVar1,"OBJ_HEAD");
            if (iVar7 != -1) {
              uVar3 = FUN_0804c9cc(puVar1[iVar7 * 4 + 5]);
              puVar9 = (uint *)(uVar3 + (int)DAT_080601e0);
              DAT_08060208 = puVar9;
              iVar7 = FUN_0804ccc0((int)puVar1,"OBJ_IDFN");
              if (iVar7 == -1) {
                iVar10 = 0;
                local_24 = 0;
              }
              else {
                local_28 = FUN_0804c9cc(puVar1[iVar7 * 4 + 5]);
                iVar10 = local_28 + (int)DAT_080601e0;
                local_24 = FUN_0804c9cc(puVar1[iVar7 * 4 + 6]);
              }
              iVar7 = FUN_0804ccc0((int)puVar1,"OBJ_SYMT");
              if (iVar7 == -1) {
                DAT_080601ec = 0;
                DAT_080601fc = 0;
              }
              else {
                local_2c = FUN_0804c9cc(puVar1[iVar7 * 4 + 5]);
                DAT_080601ec = local_2c + (int)DAT_080601e0;
                DAT_080601fc = FUN_0804c9cc(puVar1[iVar7 * 4 + 6]);
              }
              iVar7 = FUN_0804ccc0((int)puVar1,"OBJ_STRT");
              if (iVar7 == -1) {
                DAT_080601e4 = 0;
                DAT_08060200 = 0;
              }
              else {
                local_30 = FUN_0804c9cc(puVar1[iVar7 * 4 + 5]);
                DAT_080601e4 = local_30 + (int)DAT_080601e0;
                DAT_08060200 = FUN_0804c9cc(puVar1[iVar7 * 4 + 6]);
              }
              FUN_080498d0((int)puVar9,DAT_08060214);
              if ((param_2 & 0x300) == 0) {
                FUN_0804900c(puVar9,uVar3,iVar10,local_24,local_28,param_1);
              }
              DAT_080601e8 = 0;
              DAT_080601f8 = 0;
              iVar7 = FUN_0804ccc0((int)puVar1,"OBJ_AREA");
              if (iVar7 == -1) {
                printf("** No OBJ_AREA Chunk **\n\n");
              }
              else {
                _DAT_08060204 = FUN_0804c9cc(puVar1[iVar7 * 4 + 5]);
                DAT_080601e8 = _DAT_08060204 + (int)DAT_080601e0;
                DAT_080601f8 = FUN_0804c9cc(puVar1[iVar7 * 4 + 6]);
              }
              if ((param_2 & 0x351) != 0) {
                FUN_0804a420((int)puVar9,param_2,param_1);
              }
              if ((param_2 & 4) != 0) {
                FUN_0804b0ec((int)puVar9,local_2c,param_1);
              }
              if ((param_2 & 8) != 0) {
                FUN_0804b19c((int)puVar9,local_30,param_1);
              }
              DAT_0806020c = DAT_0806020c + 1;
              return 0;
            }
            pcVar11 = "%s isn\'t an AOF file";
          }
          else {
            uVar3 = FUN_0804c9cc(DAT_080601e0[2]);
            uVar4 = FUN_0804c9cc(puVar9[4]);
            if ((uVar4 == 0xef000011) &&
               ((((uVar3 & 0xff000000) == 0xeb000000 || (uVar3 == 0xe1a00000)) ||
                ((uVar3 & 0xff000000) == 0xfb000000)))) {
              uVar5 = FUN_0804b2d8(param_1,puVar9,param_2);
              return uVar5;
            }
            pcVar11 = "%s is neither a chunk file nor an AIF file";
          }
        }
        goto LAB_0804c248;
      }
      puVar8 = &stack0xffffffac;
      FUN_0804fbe8("Failed to load %s");
    }
    *(FILE **)(puVar8 + -4) = __stream;
    *(undefined4 *)(puVar8 + -8) = 0x804c01c;
    fclose(*(FILE **)(puVar8 + -4));
  }
  return 1;
}



void FUN_0804c48c(int param_1)

{
  __sysv_signal(param_1,FUN_0804c48c);
                    // WARNING: Subroutine does not return
  exit(1);
}



void FUN_0804c4a4(char *param_1)

{
  printf("\n%s Version %s [%s]\n       - %s\n\n%s [options] file [file...]\n","AOF Decoder",
         "4.20 (ARM Ltd SDT2.51)","Build number 130","decodes an ARM Object Format (AOF) file",
         param_1);
  printf(
        "\nOptions:-\n-b   (brief) print only the area declarations\n-a   print area contents in hex (=> -d)\n-d   print area declarations\n-r   print relocation directives (=> -d)\n-c   disassemble code areas (=> -d)\n-only xxx   process only area named or containing symbol xxx\n"
        );
  printf(
        "-g   print debug areas formatted readably\n-m   display mangled symbols\n-s   print symbol table\n-t   print string table\n-q   print area size summary\n-z   print code and data size summary\n"
        );
  printf("\nExamples:-\n     %s -agst myprog.o\n     %s -b test1.o test2.o test3.o\n",param_1,
         param_1);
  return;
}



int FUN_0804c4f4(char *param_1,char *param_2)

{
  int iVar1;
  int __c;
  int __c_00;
  
  while( true ) {
    __c = (int)*param_1;
    param_1 = param_1 + 1;
    __c_00 = (int)*param_2;
    param_2 = param_2 + 1;
    iVar1 = isupper(__c);
    if (iVar1 != 0) {
      __c = tolower(__c);
    }
    iVar1 = isupper(__c_00);
    if (iVar1 != 0) {
      __c_00 = tolower(__c_00);
    }
    if (__c != __c_00) break;
    if (__c == 0) {
      return 0;
    }
  }
  return __c - __c_00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0804c55c(int param_1,undefined4 *param_2)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  char *pcVar6;
  undefined4 *puVar7;
  undefined4 uVar8;
  uint local_14;
  int local_c;
  int local_8;
  
  __sysv_signal(2,FUN_0804c48c);
  FUN_0804fac8("AOF Decoder");
  FUN_0804fc30((char *)*param_2,&DAT_080601c0,0x20);
  if (param_1 < 2) {
    FUN_0804c4a4(&DAT_080601c0);
                    // WARNING: Subroutine does not return
    exit(1);
  }
  local_8 = 1;
  puVar3 = param_2;
  if (1 < param_1) {
    do {
      pcVar6 = (char *)puVar3[1];
      iVar2 = FUN_0804c4f4("-help",pcVar6);
      if ((iVar2 == 0) || (iVar2 = FUN_0804c4f4("-h",pcVar6), iVar2 == 0)) {
        FUN_0804c4a4(&DAT_080601c0);
                    // WARNING: Subroutine does not return
        exit(0);
      }
      local_8 = local_8 + 1;
      puVar3 = puVar3 + 1;
    } while (local_8 < param_1);
  }
  local_c = 0;
  local_14 = 0;
  _DAT_0805ec30 = 0;
  local_8 = 1;
  do {
    if (param_1 <= local_8) {
      if (local_14 == 0) {
        local_14 = 0xd;
      }
      if (local_14 == 0x1000) {
        local_14 = 0x1001;
      }
      if (((local_14 & 0x100) != 0) && ((local_14 & 0xfffffeff) != 0)) {
        FUN_0804fc0c("-q is not valid with any other options");
      }
      uVar5 = local_14 & 0x200;
      if ((uVar5 != 0) && ((local_14 & 0xfffffdff) != 0)) {
        FUN_0804fc0c("-z is not valid with any other options");
      }
      if (((char)local_14 < '\0') && ((local_14 & 0x7e) != 0)) {
        FUN_0804fbe8("-b overrides other options (which have been ignored)");
        local_14 = 1;
        uVar5 = 0;
      }
      if (local_c == 0) {
        FUN_0804fc0c("missing file argument(s)");
      }
      if (uVar5 != 0) {
        FUN_08049780("object file");
        puVar3 = &DAT_080589e4;
        puVar7 = &DAT_08060218;
        for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar7 = *puVar3;
          puVar3 = puVar3 + 1;
          puVar7 = puVar7 + 1;
        }
      }
      DAT_080601e0 = 0;
      DAT_080601f0 = 0xff78;
      uVar8 = 0;
      for (local_8 = 1; local_8 < param_1; local_8 = local_8 + 1) {
        pcVar6 = (char *)param_2[local_8];
        if (*pcVar6 == '-') {
          if ((pcVar6[1] == 'o') || (pcVar6[1] == 'O')) {
            uVar4 = (byte)pcVar6[2] - 0x6e;
            if ((uVar4 == 0) &&
               ((uVar4 = (byte)pcVar6[3] - 0x6c, uVar4 == 0 &&
                (uVar4 = (byte)pcVar6[4] - 0x79, uVar4 == 0)))) {
              uVar4 = (uint)(byte)pcVar6[5];
            }
            if (uVar4 == 0) {
              local_8 = local_8 + 1;
            }
          }
        }
        else {
          iVar2 = FUN_0804bf04(pcVar6,local_14);
          if (iVar2 != 0) {
            uVar8 = 1;
          }
          if (local_8 + 1 < param_1) {
            _IO_putc(10,stdout);
          }
        }
      }
      if (uVar5 != 0) {
        if (1 < DAT_0806020c) {
          _IO_putc(10,stdout);
          FUN_08049794("Total (of all files):",&DAT_08060218);
        }
        FUN_080497fc(&DAT_08060218);
      }
      if (DAT_08060210 != (void *)0x0) {
        free(DAT_08060210);
      }
      return uVar8;
    }
    if (*(char *)param_2[local_8] == '-') {
      pcVar6 = (char *)param_2[local_8] + 1;
      cVar1 = *pcVar6;
      while (cVar1 != '\0') {
        switch(cVar1) {
        case '1':
          _DAT_0805ec30 = _DAT_0805ec30 | 4;
          break;
        default:
          FUN_0804fbe8("unrecognised flag option %s (ignored)");
          break;
        case 'A':
        case 'a':
          local_14 = local_14 | 3;
          break;
        case 'B':
        case 'b':
          local_14 = 0x81;
          break;
        case 'C':
        case 'c':
          local_14 = local_14 | 0x41;
          break;
        case 'D':
        case 'd':
          local_14 = local_14 | 1;
          break;
        case 'F':
        case 'f':
          _DAT_0805ec30 = _DAT_0805ec30 | 8;
          break;
        case 'G':
        case 'g':
          local_14 = local_14 | 0x10;
          break;
        case 'M':
        case 'm':
          _DAT_0805ec30 = _DAT_0805ec30 | 1;
          break;
        case 'O':
        case 'o':
          uVar5 = (byte)pcVar6[1] - 0x6e;
          if (((uVar5 == 0) && (uVar5 = (byte)pcVar6[2] - 0x6c, uVar5 == 0)) &&
             (uVar5 = (byte)pcVar6[3] - 0x79, uVar5 == 0)) {
            uVar5 = (uint)(byte)pcVar6[4];
          }
          if (uVar5 == 0) {
            iVar2 = local_8 + 1;
            if (iVar2 < param_1) {
              puVar3 = malloc(0x10);
              *puVar3 = DAT_08060214;
              puVar3[1] = param_2[iVar2];
              puVar3[2] = 0;
              puVar3[3] = 0;
              DAT_08060214 = puVar3;
              local_8 = iVar2;
              goto LAB_0804c7cb;
            }
            pcVar6 = "the \'-%s\' option needs a parameter";
          }
          else {
            pcVar6 = "unrecognised flag option %s (ignored)";
          }
          FUN_0804fbe8(pcVar6);
          goto LAB_0804c7cb;
        case 'Q':
        case 'q':
          local_14 = local_14 | 0x100;
          break;
        case 'R':
        case 'r':
          local_14 = local_14 | 0x21;
          break;
        case 'S':
        case 's':
          local_14 = local_14 | 4;
          break;
        case 'T':
        case 't':
          local_14 = local_14 | 8;
          break;
        case 'V':
        case 'v':
          local_14 = local_14 | 0x400;
          break;
        case 'Y':
        case 'y':
          local_14 = local_14 | 0x1000;
          break;
        case 'Z':
        case 'z':
          local_14 = local_14 | 0x200;
        }
        pcVar6 = pcVar6 + 1;
        cVar1 = *pcVar6;
      }
    }
    else {
      local_c = local_c + 1;
    }
LAB_0804c7cb:
    local_8 = local_8 + 1;
  } while( true );
}



void FUN_0804c990(undefined4 param_1)

{
  DAT_0805ec4c = param_1;
  return;
}



undefined4 FUN_0804c9b0(void)

{
  return DAT_0805ec4c;
}



uint FUN_0804c9cc(uint param_1)

{
  if (DAT_0805ec4c != 0) {
    param_1 = (param_1 << 0x18 | param_1 >> 8) ^
              (((param_1 << 0x10 | param_1 >> 0x10) ^ param_1) & 0xff00ffff) >> 8;
  }
  return param_1;
}



uint FUN_0804ca04(uint param_1)

{
  if (DAT_0805ec4c != 0) {
    param_1 = (param_1 & 0xff) << 8 | (int)param_1 >> 8 & 0xffU;
  }
  return param_1;
}



void FUN_0804ca38(uint *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = param_3 >> 2;
  if (uVar2 != 0) {
    do {
      uVar1 = *param_2;
      param_2 = param_2 + 1;
      uVar1 = FUN_0804c9cc(uVar1);
      *param_1 = uVar1;
      param_1 = param_1 + 1;
      uVar2 = uVar2 - 1;
    } while (0 < (int)uVar2);
  }
  return;
}



uint FUN_0804ca80(int param_1)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_0805ec50;
  if (uVar1 == (uVar1 & 1)) {
    if (param_1 == DAT_0805ec54) {
      uVar1 = 1 - uVar1;
    }
    else if (param_1 != -0x3c34393b) {
      uVar1 = 0xffffffff;
    }
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



long * FUN_0804cad8(FILE *param_1,long *param_2)

{
  size_t sVar1;
  uint uVar2;
  long lVar3;
  int local_10;
  uint local_c;
  uint local_8;
  
  param_2[4] = 0;
  sVar1 = fread(&local_10,4,3,param_1);
  if ((sVar1 == 3) && (uVar2 = FUN_0804ca80(local_10), -1 < (int)uVar2)) {
    FUN_0804c990((uint)(local_10 != -0x3c34393b));
    uVar2 = FUN_0804c9cc(local_c);
    param_2[1] = uVar2;
    uVar2 = FUN_0804c9cc(local_8);
    param_2[2] = uVar2;
    param_2[4] = (long)param_1;
    param_2[3] = 0;
    lVar3 = ftell(param_1);
    *param_2 = lVar3;
    return param_2;
  }
  return (long *)0x0;
}



int FUN_0804cb6c(int param_1)

{
  int iVar1;
  
  if (*(int *)(param_1 + 0x10) == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 4) * 0x10 + 0xc;
  }
  return iVar1;
}



uint * FUN_0804cb8c(int *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  long lVar2;
  size_t sVar3;
  
  if (((param_1 != (int *)0x0) && (param_1[4] != 0)) && (param_1[1] * 0x10 + 0xcU <= param_3)) {
    uVar1 = FUN_0804c9cc(0xc3cbc6c5);
    *param_2 = uVar1;
    uVar1 = FUN_0804c9cc(param_1[1]);
    param_2[1] = uVar1;
    uVar1 = FUN_0804c9cc(param_1[2]);
    param_2[2] = uVar1;
    lVar2 = ftell((FILE *)param_1[4]);
    if (lVar2 != *param_1) {
      fseek((FILE *)param_1[4],*param_1,0);
    }
    sVar3 = fread(param_2 + 3,0x10,param_1[1],(FILE *)param_1[4]);
    if (sVar3 == param_1[1]) {
      param_1[3] = (int)param_2;
      return param_2;
    }
  }
  return (uint *)0x0;
}



undefined4 FUN_0804cc2c(int *param_1,void *param_2,uint param_3)

{
  int iVar1;
  long lVar2;
  size_t sVar3;
  
  if (((param_1 != (int *)0x0) && ((FILE *)param_1[4] != (FILE *)0x0)) &&
     (param_1[1] * 0x10 + 0xcU <= param_3)) {
    iVar1 = *param_1;
    lVar2 = ftell((FILE *)param_1[4]);
    if (lVar2 != iVar1 + -0xc) {
      fseek((FILE *)param_1[4],iVar1 + -0xc,0);
    }
    sVar3 = fwrite(param_2,0xc,1,(FILE *)param_1[4]);
    if ((sVar3 == 1) &&
       (sVar3 = fwrite((void *)((int)param_2 + 0xc),0x10,param_1[1],(FILE *)param_1[4]),
       sVar3 == param_1[1])) {
      return 0;
    }
  }
  return 0xffffffff;
}



int FUN_0804ccc0(int param_1,char *param_2)

{
  int iVar1;
  uint uVar2;
  char *__s1;
  int iVar3;
  
  iVar3 = 0;
  __s1 = (char *)(param_1 + 0xc);
  while( true ) {
    uVar2 = FUN_0804c9cc(*(uint *)(param_1 + 4));
    if ((int)uVar2 <= iVar3) {
      return -1;
    }
    uVar2 = FUN_0804c9cc(*(uint *)(__s1 + 8));
    if ((0 < (int)uVar2) && (iVar1 = strncmp(__s1,param_2,8), iVar1 == 0)) break;
    iVar3 = iVar3 + 1;
    __s1 = __s1 + 0x10;
  }
  return iVar3;
}



uint FUN_0804cd2c(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  
  if ((-1 < param_2) && (uVar2 = FUN_0804c9cc(*(uint *)(param_1 + 4)), param_2 < (int)uVar2)) {
    iVar1 = param_1 + 0xc + param_2 * 0x10;
    uVar2 = FUN_0804c9cc(*(uint *)(iVar1 + 8));
    if ((int)uVar2 < 1) {
      return 0;
    }
    uVar2 = FUN_0804c9cc(*(uint *)(iVar1 + 0xc));
    return uVar2;
  }
  return 0xffffffff;
}



void FUN_0804cd90(int param_1,int param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  
  if (-1 < param_2) {
    uVar2 = FUN_0804c9cc(*(uint *)(param_1 + 4));
    if (param_2 < (int)uVar2) {
      puVar1 = (undefined4 *)(param_1 + 0xc + param_2 * 0x10);
      *puVar1 = 0;
      puVar1[1] = 0;
      puVar1[2] = 0;
      puVar1[3] = 0;
    }
  }
  return;
}



int FUN_0804cde4(int *param_1,int param_2)

{
  uint uVar1;
  long lVar2;
  int iVar3;
  
  if ((((param_1[3] != 0) && (-1 < param_2)) &&
      (uVar1 = FUN_0804c9cc(*(uint *)(param_1[3] + 4)), param_2 < (int)uVar1)) &&
     (uVar1 = FUN_0804c9cc(*(uint *)(param_2 * 0x10 + param_1[3] + 0x14)), 0 < (int)uVar1)) {
    iVar3 = uVar1 + *param_1 + -0xc;
    lVar2 = ftell((FILE *)param_1[4]);
    if (lVar2 != iVar3) {
      iVar3 = fseek((FILE *)param_1[4],iVar3,0);
      return iVar3;
    }
    return 0;
  }
  return -1;
}



undefined4 FUN_0804ce60(int param_1,void *param_2,size_t param_3)

{
  size_t sVar1;
  
  if ((*(int *)(param_1 + 0xc) != 0) &&
     (sVar1 = fread(param_2,param_3,1,*(FILE **)(param_1 + 0x10)), sVar1 == 1)) {
    return 0;
  }
  return 0xffffffff;
}



undefined4 FUN_0804ce9c(int param_1,void *param_2,size_t param_3)

{
  size_t sVar1;
  
  if ((*(int *)(param_1 + 0xc) != 0) &&
     (sVar1 = fwrite(param_2,param_3,1,*(FILE **)(param_1 + 0x10)), sVar1 == 1)) {
    return 0;
  }
  return 0xffffffff;
}



void FUN_0804cee0(char *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  if (*param_1 != '\0') {
    uVar2 = 0xffffffff;
    pcVar3 = param_1;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    pcVar3 = param_1 + (~uVar2 - 1);
    pcVar3[0] = ',';
    pcVar3[1] = ' ';
    param_1 = pcVar3 + 2;
    pcVar3[2] = '\0';
  }
  vsprintf(param_1,param_2,&stack0x0000000c);
  return;
}



void FUN_0804d03c(int param_1,int param_2,undefined4 param_3,char *param_4)

{
  if (param_1 != param_2) {
    FUN_0804cee0(param_4,"%s = %s%lx");
  }
  return;
}



void FUN_0804d074(int param_1,undefined4 param_2,char *param_3)

{
  FUN_0804d03c(param_1,0,param_2,param_3);
  return;
}



char * FUN_0804d09c(char *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  vsprintf(param_1,param_2,&stack0x0000000c);
  uVar2 = 0xffffffff;
  pcVar3 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  return param_1 + (~uVar2 - 1);
}



void FUN_0804d0e0(char *param_1,char *param_2)

{
  char cVar1;
  
  while( true ) {
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    if (cVar1 == '\0') break;
    *param_2 = cVar1;
    param_2 = param_2 + 1;
  }
  return;
}



void FUN_0804d0fc(uint param_1,char *param_2)

{
  FUN_0804d0e0(&UNK_08059e60 + (param_1 >> 0x1c) * 4,param_2);
  return;
}



char * FUN_0804d128(int param_1,int param_2,char *param_3)

{
  char *pcVar1;
  
  if (DAT_08060238 == 0) {
    if (param_1 != 0xf) {
      pcVar1 = FUN_0804d09c(param_3,"r%ld");
      goto LAB_0804d179;
    }
    pcVar1 = "pc";
  }
  else {
    pcVar1 = *(char **)(DAT_08060238 + param_1 * 4);
  }
  pcVar1 = (char *)FUN_0804d0e0(pcVar1,param_3);
LAB_0804d179:
  if (param_2 != 0) {
    *pcVar1 = (char)param_2;
    pcVar1 = pcVar1 + 1;
  }
  return pcVar1;
}



char * FUN_0804d190(int param_1,int param_2,char *param_3)

{
  char *pcVar1;
  
  if (DAT_0806023c == 0) {
    pcVar1 = FUN_0804d09c(param_3,"f%ld");
  }
  else {
    pcVar1 = (char *)FUN_0804d0e0(*(char **)(DAT_0806023c + param_1 * 4),param_3);
  }
  if (param_2 != 0) {
    *pcVar1 = (char)param_2;
    pcVar1 = pcVar1 + 1;
  }
  return pcVar1;
}



char * FUN_0804d1e4(uint param_1,char *param_2)

{
  char *pcVar1;
  uint uVar2;
  
  pcVar1 = FUN_0804d128(param_1 & 0xf,0,param_2);
  if ((param_1 & 0x10) == 0) {
    uVar2 = (param_1 & 0xfe0) >> 5;
    if (uVar2 != 0) {
      if (uVar2 == 3) {
        pcVar1 = (char *)FUN_0804d0e0(",RRX",pcVar1);
      }
      else {
        pcVar1 = FUN_0804d09c(pcVar1,",%s ");
        pcVar1 = FUN_0804d09c(pcVar1,"#%ld");
      }
    }
  }
  else {
    pcVar1 = FUN_0804d09c(pcVar1,",%s ");
    pcVar1 = FUN_0804d128((param_1 & 0xf00) >> 8,0,pcVar1);
  }
  return pcVar1;
}



char * FUN_0804d2b8(uint param_1,int param_2,char *param_3)

{
  char *pcVar1;
  
  if (param_2 == 0) {
    *param_3 = '-';
    param_3 = param_3 + 1;
  }
  if (param_1 < 10) {
    pcVar1 = FUN_0804d09c(param_3,"%ld");
  }
  else {
    pcVar1 = FUN_0804d09c(param_3,"%s%lx");
  }
  return pcVar1;
}



void FUN_0804d310(uint param_1,int param_2,undefined1 *param_3)

{
  *param_3 = 0x23;
  FUN_0804d2b8(param_1,param_2,param_3 + 1);
  return;
}



void FUN_0804d338(int param_1,undefined1 *param_2)

{
  int iVar1;
  
  iVar1 = 9 - ((int)param_2 - param_1);
  do {
    *param_2 = 0x20;
    param_2 = param_2 + 1;
    iVar1 = iVar1 + -1;
  } while (0 < iVar1);
  return;
}



void FUN_0804d35c(char *param_1,char *param_2)

{
  undefined1 *puVar1;
  
  puVar1 = (undefined1 *)FUN_0804d0e0(param_1,param_2);
  FUN_0804d338((int)param_2,puVar1);
  return;
}



void FUN_0804d388(uint param_1,char *param_2,int param_3,char *param_4)

{
  char *pcVar1;
  undefined1 *puVar2;
  
  pcVar1 = (char *)FUN_0804d0e0(param_2,param_4);
  puVar2 = (undefined1 *)FUN_0804d0fc(param_1,pcVar1);
  if (param_3 != 0) {
    *puVar2 = (char)param_3;
    puVar2 = puVar2 + 1;
  }
  FUN_0804d338((int)param_4,puVar2);
  return;
}



void FUN_0804d3d0(char *param_1,uint param_2,char *param_3)

{
  char cVar1;
  char *pcVar2;
  char *__s;
  uint uVar3;
  
  pcVar2 = strchr(param_3,0x24);
  if (pcVar2 == (char *)0x0) {
    FUN_0804d388(param_2,param_3,0,param_1);
  }
  else {
    memcpy(param_1,param_3,(int)pcVar2 - (int)param_3);
    __s = (char *)FUN_0804d0fc(param_2,param_1 + ((int)pcVar2 - (int)param_3));
    vsprintf(__s,pcVar2 + 1,&stack0x00000010);
    uVar3 = 0xffffffff;
    pcVar2 = __s;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    FUN_0804d338((int)param_1,__s + (~uVar3 - 1));
  }
  return;
}



char * FUN_0804d480(uint param_1,int param_2,uint param_3,undefined4 param_4,char *param_5,
                   int param_6)

{
  uint uVar1;
  char *pcVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  char *pcVar6;
  uint local_c;
  
  uVar1 = param_1 & 0xf0000;
  pcVar2 = param_5;
  if (uVar1 == 0xf0000) {
    if ((param_1 & 0x1000000) == 0) goto LAB_0804d5b0;
    if ((param_1 & 0x2000000) == 0) {
      if ((param_1 & 0x800000) == 0) {
        param_3 = -param_3;
      }
      if (DAT_08060240 != (code *)0x0) {
        if ((param_1 & 0x100000) == 0) {
          uVar5 = 2;
        }
        else {
          uVar5 = 1;
        }
        pcVar2 = (char *)(*DAT_08060240)(uVar5,param_3,param_3 + 8 + param_2,param_4,DAT_08060244,
                                         param_5);
      }
      if (param_5 != pcVar2) {
        return pcVar2;
      }
      pcVar2 = FUN_0804d09c(pcVar2,"%s%lx");
      return pcVar2;
    }
  }
  if ((((param_1 & 0x1000000) != 0) && ((param_1 & 0x2000000) == 0)) &&
     (DAT_08060240 != (code *)0x0)) {
    uVar3 = param_3;
    if ((param_1 & 0x800000) == 0) {
      uVar3 = -param_3;
    }
    if ((param_1 & 0x100000) == 0) {
      uVar5 = 4;
    }
    else {
      uVar5 = 3;
    }
    pcVar2 = (char *)(*DAT_08060240)(uVar5,uVar3,uVar1 >> 0x10,param_4,DAT_08060244,param_5);
  }
LAB_0804d5b0:
  local_c = param_1 & 0x1000000;
  if (param_5 == pcVar2) {
    *pcVar2 = '[';
    uVar3 = param_1 & 0x800000;
    if (local_c == 0) {
      iVar4 = 0x5d;
    }
    else {
      iVar4 = 0;
    }
    pcVar2 = FUN_0804d128(uVar1 >> 0x10,iVar4,pcVar2 + 1);
    *pcVar2 = ',';
    pcVar6 = pcVar2 + 1;
    if ((param_1 & 0x2000000) == 0) {
      if (((param_6 == 0) || (local_c != 0)) ||
         (((param_1 & 0x200000) != 0 || (uVar3 >> 0x17 == 0)))) {
        pcVar6 = (char *)FUN_0804d310(param_3,uVar3 >> 0x17,pcVar6);
      }
      else {
        *pcVar6 = '{';
        if ((int)param_3 < 0) {
          param_3 = param_3 + 3;
        }
        pcVar6 = FUN_0804d2b8((int)param_3 >> 2,uVar3 >> 0x17,pcVar2 + 2);
        *pcVar6 = '}';
        pcVar6 = pcVar6 + 1;
      }
    }
    else {
      if (uVar3 == 0) {
        *pcVar6 = '-';
        pcVar6 = pcVar2 + 2;
      }
      pcVar6 = FUN_0804d1e4(param_1,pcVar6);
    }
    pcVar2 = pcVar6;
    if (local_c != 0) {
      *pcVar6 = ']';
      pcVar2 = pcVar6 + 1;
      if ((param_1 & 0x200000) != 0) {
        *pcVar2 = '!';
        pcVar2 = pcVar6 + 2;
      }
    }
  }
  return pcVar2;
}



void FUN_0804d688(uint param_1,int param_2,uint param_3,undefined4 param_4,char *param_5)

{
  FUN_0804d480(param_1,param_2,param_3,param_4,param_5,0);
  return;
}



char * FUN_0804d6b4(uint param_1,undefined1 *param_2)

{
  bool bVar1;
  bool bVar2;
  char *pcVar3;
  uint uVar4;
  uint uVar5;
  uint local_10;
  
  bVar1 = false;
  bVar2 = false;
  uVar5 = 0;
  local_10 = 0;
  *param_2 = 0x7b;
  pcVar3 = param_2 + 1;
  uVar4 = 0;
  do {
    if ((1 << ((byte)uVar4 & 0x1f) & param_1) >> ((byte)uVar4 & 0x1f) != 0) {
      if (bVar1) {
        if (uVar4 == local_10 + 1) {
          bVar2 = true;
          local_10 = uVar4;
        }
        else {
          if ((local_10 + 1 < uVar4) && (bVar2)) {
            if (uVar5 == local_10 - 1) {
              *pcVar3 = ',';
            }
            else {
              *pcVar3 = '-';
            }
            pcVar3 = FUN_0804d128(local_10,0,pcVar3 + 1);
            bVar2 = false;
          }
          *pcVar3 = ',';
          pcVar3 = FUN_0804d128(uVar4,0,pcVar3 + 1);
          uVar5 = uVar4;
          local_10 = uVar4;
        }
      }
      else {
        pcVar3 = FUN_0804d128(uVar4,0,pcVar3);
        bVar1 = true;
        uVar5 = uVar4;
        local_10 = uVar4;
      }
    }
    uVar4 = uVar4 + 1;
  } while (uVar4 < 0x10);
  if (bVar2) {
    if (uVar5 == local_10 - 1) {
      *pcVar3 = ',';
    }
    else {
      *pcVar3 = '-';
    }
    pcVar3 = FUN_0804d128(local_10,0,pcVar3 + 1);
  }
  *pcVar3 = '}';
  return pcVar3 + 1;
}



void FUN_0804d7c0(undefined4 param_1,uint param_2,char *param_3)

{
  char *pcVar1;
  
  pcVar1 = (char *)FUN_0804d388(param_2,"CDP",0,param_3);
  pcVar1 = FUN_0804d09c(pcVar1,"p%d,");
  pcVar1 = FUN_0804d09c(pcVar1,"%s%lx");
  *pcVar1 = ',';
  pcVar1 = FUN_0804d09c(pcVar1 + 1,"c%ld,");
  pcVar1 = FUN_0804d09c(pcVar1,"c%ld,");
  pcVar1 = FUN_0804d09c(pcVar1,"c%ld,");
  FUN_0804d09c(pcVar1,"%ld");
  return;
}



void FUN_0804d884(undefined4 param_1,uint param_2,char *param_3)

{
  char *pcVar1;
  
  if ((param_2 & 0x100000) == 0) {
    pcVar1 = "MCR";
  }
  else {
    pcVar1 = "MRC";
  }
  pcVar1 = (char *)FUN_0804d388(param_2,pcVar1,0,param_3);
  pcVar1 = FUN_0804d09c(pcVar1,"p%d,");
  pcVar1 = FUN_0804d09c(pcVar1,"%s%lx");
  *pcVar1 = ',';
  pcVar1 = FUN_0804d128((param_2 & 0xf000) >> 0xc,0x2c,pcVar1 + 1);
  pcVar1 = FUN_0804d09c(pcVar1,"c%ld,");
  pcVar1 = FUN_0804d09c(pcVar1,"c%ld,");
  FUN_0804d09c(pcVar1,"%ld");
  return;
}



void FUN_0804d95c(undefined4 param_1,uint param_2,int param_3,char *param_4,char *param_5)

{
  int iVar1;
  char *pcVar2;
  
  if ((param_2 & 0x400000) == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = 0x4c;
  }
  if ((param_2 & 0x100000) == 0) {
    pcVar2 = "STC";
  }
  else {
    pcVar2 = "LDC";
  }
  pcVar2 = (char *)FUN_0804d388(param_2,pcVar2,iVar1,param_4);
  pcVar2 = FUN_0804d09c(pcVar2,"p%d,");
  pcVar2 = FUN_0804d09c(pcVar2,"c%ld,");
  if ((((param_2 & 0x1000000) == 0) && ((param_2 & 0x200000) == 0)) && ((param_2 & 0x800000) == 0))
  {
    FUN_0804cee0(param_5,"Postindexed, Down, no WB");
  }
  FUN_0804d480(param_2,param_3,(param_2 & 0xff) << 2,0,pcVar2,1);
  return;
}



undefined4
FUN_0804da20(undefined4 param_1,int param_2,uint param_3,int param_4,char *param_5,char *param_6)

{
  undefined4 uVar1;
  
  if (param_2 == 1) {
    uVar1 = FUN_0804d884(param_1,param_3,param_5);
  }
  else if (param_2 == 0) {
    uVar1 = FUN_0804d7c0(param_1,param_3,param_5);
  }
  else if (param_2 == 2) {
    uVar1 = FUN_0804d95c(param_1,param_3,param_4,param_5,param_6);
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



int FUN_0804da8c(uint param_1)

{
  return (int)(char)(&DAT_08059f0d)[((param_1 & 0x8000) >> 0xf) + (param_1 >> 0x15 & 2)];
}



int FUN_0804dac0(uint param_1)

{
  return (int)(char)(&DAT_08059f0d)[((param_1 & 0x80) >> 7) + (param_1 >> 0x12 & 2)];
}



undefined * FUN_0804daf4(uint param_1)

{
  return &UNK_08059f12 + ((param_1 & 0x60) >> 4);
}



char * FUN_0804db1c(uint param_1,char *param_2)

{
  char *pcVar1;
  uint uVar2;
  
  uVar2 = param_1 & 7;
  if ((param_1 & 8) == 0) {
    pcVar1 = FUN_0804d190(uVar2,0,param_2);
  }
  else if (uVar2 < 6) {
    pcVar1 = FUN_0804d09c(param_2,"#%ld");
  }
  else {
    if (uVar2 == 6) {
      pcVar1 = "#0.5";
    }
    else {
      pcVar1 = "#10";
    }
    pcVar1 = (char *)FUN_0804d0e0(pcVar1,param_2);
  }
  return pcVar1;
}



void FUN_0804db84(uint param_1,char *param_2,char *param_3)

{
  char *pcVar1;
  undefined1 *puVar2;
  int iVar3;
  undefined *puVar4;
  uint uVar5;
  char *pcVar6;
  
  if ((param_1 & 0x8000) == 0) {
    puVar4 = &DAT_08059f80;
  }
  else {
    puVar4 = &DAT_08059f40;
  }
  pcVar1 = (char *)FUN_0804d0e0(puVar4 + ((param_1 & 0xf00000) >> 0x12),param_2);
  puVar2 = (undefined1 *)FUN_0804d0fc(param_1,pcVar1);
  iVar3 = FUN_0804dac0(param_1);
  *puVar2 = (char)iVar3;
  pcVar6 = puVar2 + 1;
  pcVar1 = FUN_0804daf4(param_1);
  puVar2 = (undefined1 *)FUN_0804d0e0(pcVar1,pcVar6);
  pcVar1 = (char *)FUN_0804d338((int)param_2,puVar2);
  pcVar1 = FUN_0804d190((param_1 & 0x7000) >> 0xc,0x2c,pcVar1);
  if ((param_1 & 0x8000) == 0) {
    pcVar1 = FUN_0804d190((param_1 & 0x70000) >> 0x10,0x2c,pcVar1);
  }
  else {
    uVar5 = (param_1 & 0x70000) >> 0x10;
    if (uVar5 != 0) {
      FUN_0804d074(uVar5,&DAT_08059fc0,param_3);
    }
  }
  FUN_0804db1c(param_1,pcVar1);
  return;
}



char * FUN_0804dc74(uint param_1,char *param_2)

{
  uint uVar1;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  uint uVar5;
  
  uVar5 = (param_1 & 0xf00000) >> 0x14;
  uVar1 = (param_1 & 0xf000) >> 0xc;
  if (uVar1 == 0xf) {
    if ((uVar5 & 9) == 9) {
      pcVar2 = (char *)FUN_0804d388(param_1,&UNK_08059faf + ((int)uVar5 >> 1) * 5,0,param_2);
      pcVar2 = FUN_0804d190((param_1 & 0x70000) >> 0x10,0x2c,pcVar2);
      pcVar2 = FUN_0804db1c(param_1,pcVar2);
      return pcVar2;
    }
  }
  else if (uVar5 < 6) {
    pcVar2 = (char *)FUN_0804d0e0(&DAT_08059fd7 + uVar5 * 4,param_2);
    pcVar2 = (char *)FUN_0804d0fc(param_1,pcVar2);
    if (uVar5 == 0) {
      iVar3 = FUN_0804dac0(param_1);
      *pcVar2 = (char)iVar3;
      pcVar2 = pcVar2 + 1;
    }
    if (uVar5 < 2) {
      pcVar4 = FUN_0804daf4(param_1);
      pcVar2 = (char *)FUN_0804d0e0(pcVar4,pcVar2);
    }
    pcVar2 = (char *)FUN_0804d338((int)param_2,pcVar2);
    if (uVar5 == 0) {
      pcVar2 = FUN_0804d190((param_1 & 0x70000) >> 0x10,0x2c,pcVar2);
    }
    pcVar2 = FUN_0804d128(uVar1,0,pcVar2);
    if (uVar5 != 1) {
      return pcVar2;
    }
    *pcVar2 = ',';
    pcVar2 = FUN_0804db1c(param_1,pcVar2 + 1);
    return pcVar2;
  }
  return (char *)0x0;
}



void FUN_0804ddc0(uint param_1,int param_2,char *param_3,char *param_4)

{
  int iVar1;
  char *pcVar2;
  
  if (((param_1 & 0x1000000) == 0) && ((param_1 & 0x200000) == 0)) {
    FUN_0804cee0(param_4,"Postindexed, no WB");
  }
  iVar1 = FUN_0804da8c(param_1);
  if ((param_1 & 0x100000) == 0) {
    pcVar2 = "STF";
  }
  else {
    pcVar2 = "LDF";
  }
  pcVar2 = (char *)FUN_0804d388(param_1,pcVar2,(int)(char)iVar1,param_3);
  pcVar2 = FUN_0804d190((param_1 & 0x7000) >> 0xc,0x2c,pcVar2);
  FUN_0804d688(param_1,param_2,(param_1 & 0xff) << 2,0,pcVar2);
  return;
}



void FUN_0804de5c(uint param_1,int param_2,char *param_3,char *param_4)

{
  char *pcVar1;
  
  if (((param_1 & 0x1000000) == 0) && ((param_1 & 0x200000) == 0)) {
    FUN_0804cee0(param_4,"Postindexed, no WB");
  }
  if ((param_1 & 0x100000) == 0) {
    pcVar1 = "SFM";
  }
  else {
    pcVar1 = "LFM";
  }
  pcVar1 = (char *)FUN_0804d388(param_1,pcVar1,0,param_3);
  pcVar1 = FUN_0804d190((param_1 & 0x7000) >> 0xc,0x2c,pcVar1);
  pcVar1 = FUN_0804d09c(pcVar1,"%d,");
  FUN_0804d688(param_1,param_2,(param_1 & 0xff) << 2,0,pcVar1);
  return;
}



char * FUN_0804df24(int param_1,int param_2,uint param_3,int param_4,char *param_5,char *param_6)

{
  char *pcVar1;
  
  if (param_2 == 1) {
    if (param_1 == 1) {
      pcVar1 = FUN_0804dc74(param_3,param_5);
      return pcVar1;
    }
  }
  else if (param_2 == 0) {
    if (param_1 == 1) {
      pcVar1 = (char *)FUN_0804db84(param_3,param_5,param_6);
      return pcVar1;
    }
  }
  else if (param_2 == 2) {
    if (param_1 == 1) {
      pcVar1 = (char *)FUN_0804ddc0(param_3,param_4,param_5,param_6);
      return pcVar1;
    }
    if (param_1 == 2) {
      pcVar1 = (char *)FUN_0804de5c(param_3,param_4,param_5,param_6);
      return pcVar1;
    }
  }
  return (char *)0x0;
}



void FUN_0804dfa4(undefined4 param_1,undefined4 param_2)

{
  DAT_08060238 = param_1;
  DAT_0806023c = param_2;
  return;
}



void FUN_0804dfcc(undefined *param_1)

{
  hexprefix = param_1;
  return;
}



undefined4
FUN_0804dfec(uint param_1,uint param_2,undefined4 param_3,char *param_4,undefined4 param_5,
            undefined *param_6)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined1 *puVar6;
  char *pcVar7;
  char *pcVar8;
  int *piVar9;
  uint uVar10;
  uint local_18;
  uint local_c;
  uint local_8;
  
  local_8 = param_1 & 7;
  local_c = (param_1 & 0x38) >> 3;
  uVar1 = (param_1 & 0x1c0) >> 6;
  uVar2 = (param_1 & 0x700) >> 8;
  uVar10 = param_1 & 0xff;
  local_18 = (param_1 & 0x7c0) >> 6;
  uVar3 = (param_1 & 0x800) >> 0xb;
  uVar4 = (param_1 & 0x400) >> 10;
  switch((param_1 & 0xf800) >> 0xb) {
  case 0:
  case 1:
  case 2:
    pcVar8 = (char *)FUN_0804d35c(&DAT_0805a09f + ((param_1 & 0x1800) >> 0xb) * 4,param_4);
    pcVar8 = FUN_0804d128(local_8,0x2c,pcVar8);
    if (local_8 != local_c) {
      pcVar8 = FUN_0804d128(local_c,0x2c,pcVar8);
    }
    pcVar8 = FUN_0804d09c(pcVar8,"#%ld");
    break;
  case 3:
    if ((((param_1 & 0x200) == 0) && (uVar4 != 0)) && (uVar1 == 0)) {
      pcVar8 = (char *)FUN_0804d35c("MOV",param_4);
      pcVar8 = FUN_0804d128(local_8,0x2c,pcVar8);
      pcVar8 = FUN_0804d128(local_c,0,pcVar8);
    }
    else {
      if ((param_1 & 0x200) == 0) {
        pcVar8 = "ADD";
      }
      else {
        pcVar8 = "SUB";
      }
      pcVar8 = (char *)FUN_0804d35c(pcVar8,param_4);
      pcVar8 = FUN_0804d128(local_8,0x2c,pcVar8);
      if (local_8 != local_c) {
        pcVar8 = FUN_0804d128(local_c,0x2c,pcVar8);
      }
      if (uVar4 == 0) {
        pcVar8 = FUN_0804d128(uVar1,0,pcVar8);
      }
      else {
        pcVar8 = (char *)FUN_0804d310(uVar1,1,pcVar8);
      }
    }
    break;
  case 4:
  case 5:
  case 6:
  case 7:
    pcVar8 = (char *)FUN_0804d35c(&UNK_0805a115 + ((param_1 & 0x1800) >> 9),param_4);
    pcVar8 = FUN_0804d128(uVar2,0x2c,pcVar8);
    pcVar8 = (char *)FUN_0804d310(uVar10,1,pcVar8);
    break;
  case 8:
    uVar10 = (param_1 & 0x7c0) >> 6;
    if (uVar10 < 0x10) {
      pcVar8 = &DAT_0805a0c0 + uVar10 * 4;
      goto LAB_0804e3b7;
    }
    if ((uVar10 & 2) != 0) {
      local_8 = local_8 + 8;
    }
    if ((uVar10 & 1) != 0) {
      local_c = local_c + 8;
    }
    switch(uVar10) {
    case 0x10:
    case 0x14:
    case 0x18:
      goto switchD_0804e0a1_default;
    case 0x11:
    case 0x12:
    case 0x13:
      pcVar8 = "ADD";
      break;
    case 0x15:
    case 0x16:
    case 0x17:
      pcVar8 = "CMP";
      break;
    case 0x19:
    case 0x1a:
    case 0x1b:
      pcVar8 = "MOV";
      break;
    case 0x1c:
    case 0x1d:
      pcVar8 = (char *)FUN_0804d35c("BX",param_4);
      pcVar8 = FUN_0804d128(local_c,0,pcVar8);
      goto LAB_0804e93f;
    case 0x1e:
    case 0x1f:
      pcVar8 = (char *)FUN_0804d35c("BLX",param_4);
      pcVar8 = FUN_0804d128(local_c,0,pcVar8);
      goto LAB_0804e93f;
    default:
      goto switchD_0804e33f_default;
    }
LAB_0804e3b7:
    param_4 = (char *)FUN_0804d35c(pcVar8,param_4);
switchD_0804e33f_default:
    pcVar8 = FUN_0804d128(local_8,0x2c,param_4);
    pcVar8 = FUN_0804d128(local_c,0,pcVar8);
    break;
  case 9:
    pcVar8 = (char *)FUN_0804d35c("LDR",param_4);
    pcVar7 = FUN_0804d128(uVar2,0x2c,pcVar8);
    pcVar8 = pcVar7;
    if (param_6 != (undefined *)0x0) {
      pcVar8 = (char *)(*(code *)param_6)(1);
    }
    if (pcVar8 == pcVar7) {
      pcVar8 = FUN_0804d09c(pcVar8,"%s%lx");
    }
    break;
  case 10:
  case 0xb:
    pcVar8 = (char *)FUN_0804d35c(&UNK_0805a040 + ((param_1 & 0xe00) >> 9) * 5,param_4);
    pcVar8 = FUN_0804d128(local_8,0x2c,pcVar8);
    *pcVar8 = '[';
    pcVar8 = FUN_0804d128(local_c,0x2c,pcVar8 + 1);
    pcVar8 = FUN_0804d128(uVar1,0x5d,pcVar8);
    break;
  case 0xc:
  case 0xd:
    local_18 = local_18 << 1;
  case 0x10:
  case 0x11:
    local_18 = local_18 << 1;
  case 0xe:
  case 0xf:
    goto switchD_0804e0a1_caseD_e;
  case 0x12:
  case 0x13:
    pcVar8 = (char *)FUN_0804d35c(&DAT_0805a125 + uVar3 * 4,param_4);
    pcVar7 = FUN_0804d128(uVar2,0x2c,pcVar8);
    local_18 = uVar10 << 2;
    pcVar8 = pcVar7;
    if (param_6 != (undefined *)0x0) {
      if (uVar3 == 0) {
        uVar5 = 4;
      }
      else {
        uVar5 = 3;
      }
      pcVar8 = (char *)(*(code *)param_6)(uVar5);
    }
    if (pcVar8 != pcVar7) break;
    *pcVar8 = '[';
    FUN_0804d128(0xd,0x2c,pcVar8 + 1);
    piVar9 = (int *)&stack0xffffffa8;
    goto LAB_0804e4de;
  case 0x14:
  case 0x15:
    pcVar8 = (char *)FUN_0804d35c(&DAT_0805a148 + uVar3 * 4,param_4);
    pcVar7 = FUN_0804d128(uVar2,0x2c,pcVar8);
    if (uVar3 == 0) {
      pcVar8 = pcVar7;
      if (param_6 != (undefined *)0x0) {
        pcVar8 = (char *)(*(code *)param_6)(5);
      }
      if (pcVar8 == pcVar7) {
        pcVar8 = FUN_0804d09c(pcVar8,"%s%lx");
      }
    }
    else {
      pcVar8 = FUN_0804d128(0xd,0x2c,pcVar7);
      pcVar8 = (char *)FUN_0804d310(uVar10 * 4,1,pcVar8);
    }
    break;
  case 0x16:
  case 0x17:
    if ((param_1 & 0x400) == 0) {
      if ((param_1 & 0xf00) == 0) {
        if ((param_1 & 0x80) == 0) {
          pcVar8 = "ADD";
        }
        else {
          pcVar8 = "SUB";
        }
        pcVar8 = (char *)FUN_0804d35c(pcVar8,param_4);
        pcVar8 = FUN_0804d128(0xd,0x2c,pcVar8);
        pcVar8 = (char *)FUN_0804d310((param_1 & 0x7f) << 2,1,pcVar8);
        break;
      }
    }
    else if ((param_1 & 0x200) == 0) {
      uVar10 = param_1 & 0x1ff;
      if ((param_1 & 0x100) != 0) {
        if (uVar3 == 0) {
          uVar10 = param_1 & 0xff | 0x4000;
        }
        else {
          uVar10 = param_1 & 0xff | 0x8000;
        }
      }
      puVar6 = (undefined1 *)FUN_0804d35c(&UNK_0805a12f + uVar3 * 5,param_4);
      pcVar8 = FUN_0804d6b4(uVar10,puVar6);
      break;
    }
  default:
switchD_0804e0a1_default:
    pcVar8 = "Undefined";
LAB_0804e937:
    pcVar8 = (char *)FUN_0804d35c(pcVar8,param_4);
    break;
  case 0x18:
  case 0x19:
    pcVar8 = (char *)FUN_0804d35c("STMIA" + uVar3 * 6,param_4);
    pcVar8 = FUN_0804d128(uVar2,0x21,pcVar8);
    *pcVar8 = ',';
    pcVar8 = FUN_0804d6b4(uVar10,pcVar8 + 1);
    break;
  case 0x1a:
  case 0x1b:
    uVar10 = (param_1 & 0xf00) >> 8;
    if (uVar10 == 0xf) {
      pcVar8 = (char *)FUN_0804d35c("SWI",param_4);
      if (param_6 != (undefined *)0x0) {
        (*(code *)param_6)(7);
      }
      pcVar8 = FUN_0804d09c(pcVar8,"%s%lx");
    }
    else {
      pcVar7 = (char *)FUN_0804d388(uVar10 << 0x1c,"B",0,param_4);
      pcVar8 = pcVar7;
      if (param_6 != (undefined *)0x0) {
        pcVar8 = (char *)(*(code *)param_6)(0);
      }
      if (pcVar8 == pcVar7) {
        pcVar8 = FUN_0804d09c(pcVar8,"%s%lx");
      }
    }
    break;
  case 0x1c:
    pcVar7 = (char *)FUN_0804d35c("B",param_4);
    pcVar8 = pcVar7;
    if (param_6 != (undefined *)0x0) {
      pcVar8 = (char *)(*(code *)param_6)(0);
    }
    if (pcVar8 == pcVar7) {
      pcVar8 = FUN_0804d09c(pcVar8,"%s%lx");
    }
    break;
  case 0x1d:
  case 0x1f:
    pcVar8 = "???";
    goto LAB_0804e937;
  case 0x1e:
    if ((param_2 & 0xe800) == 0xe800) {
      if ((param_2 & 0x1000) == 0) {
        pcVar8 = "BLX";
      }
      else {
        pcVar8 = "BL";
      }
      pcVar7 = (char *)FUN_0804d35c(pcVar8,param_4);
      pcVar8 = pcVar7;
      if (param_6 != (undefined *)0x0) {
        pcVar8 = (char *)(*(code *)param_6)(0);
      }
      if (pcVar8 == pcVar7) {
        pcVar8 = FUN_0804d09c(pcVar8,"%s%lx");
      }
      *pcVar8 = '\0';
      return 4;
    }
    pcVar8 = "???";
    goto LAB_0804e937;
  }
LAB_0804e93f:
  *pcVar8 = '\0';
  return 2;
switchD_0804e0a1_caseD_e:
  pcVar8 = (char *)FUN_0804d35c(&UNK_0805a044 + ((param_1 & 0xf800) >> 0xb) * 5,param_4);
  pcVar8 = FUN_0804d128(local_8,0x2c,pcVar8);
  *pcVar8 = '[';
  FUN_0804d128(local_c,0x2c,pcVar8 + 1);
  piVar9 = (int *)&stack0xffffffb4;
LAB_0804e4de:
  piVar9[-1] = local_18;
  piVar9[-2] = 0x804e4e4;
  puVar6 = (undefined1 *)FUN_0804d310(piVar9[-1],*piVar9,(undefined1 *)piVar9[1]);
  *puVar6 = 0x5d;
  pcVar8 = puVar6 + 1;
  goto LAB_0804e93f;
}



undefined4
FUN_0804e950(uint param_1,uint param_2,char *param_3,undefined4 param_4,undefined *param_5)

{
  FUN_0804eba4(param_1,param_2,param_3,param_4,param_5,0);
  return 4;
}



void FUN_0804e980(int param_1,uint param_2,int param_3,char *param_4,char *param_5)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = (param_2 & 0xf00) >> 8;
  puVar1 = (undefined4 *)PTR_DAT_0805ec64;
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      FUN_0804da20(uVar3,param_1,param_2,param_3,param_4,param_5);
      return;
    }
    iVar2 = (*(code *)puVar1[1])(uVar3,param_1,param_2,param_3,param_4,param_5);
    if (iVar2 != 0) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  return;
}



void FUN_0804e9f4(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)PTR_DAT_0805ec64;
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      puVar1 = malloc(8);
      *puVar1 = PTR_DAT_0805ec64;
      puVar1[1] = param_1;
      PTR_DAT_0805ec64 = (undefined *)puVar1;
      return;
    }
    if (puVar1[1] == param_1) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  return;
}



void FUN_0804ea40(undefined *param_1)

{
  undefined **ppuVar1;
  undefined **__ptr;
  
  ppuVar1 = &PTR_DAT_0805ec64;
  __ptr = (undefined **)PTR_DAT_0805ec64;
  while( true ) {
    if (__ptr == (undefined **)0x0) {
      return;
    }
    if (__ptr[1] == param_1) break;
    ppuVar1 = __ptr;
    __ptr = (undefined **)*__ptr;
  }
  *ppuVar1 = *__ptr;
  free(__ptr);
  return;
}



char * FUN_0804ea84(uint param_1,int param_2,char *param_3)

{
  uint uVar1;
  undefined4 uVar2;
  char *pcVar3;
  undefined1 *puVar4;
  sbyte sVar5;
  uint uVar6;
  
  if ((param_1 & 0x2000000) == 0) {
    pcVar3 = FUN_0804d1e4(param_1,param_3);
  }
  else {
    uVar6 = (param_1 & 0x1e00000) >> 0x15;
    sVar5 = (sbyte)((param_1 & 0xf00) >> 7);
    uVar1 = (param_1 & 0xff) >> sVar5 | (param_1 & 0xff) << 0x20 - sVar5;
    pcVar3 = param_3;
    if ((((uVar6 == 4) || (uVar6 == 2)) && ((param_1 & 0xf0000) == 0xf0000)) &&
       (DAT_08060240 != (code *)0x0)) {
      if (uVar6 == 4) {
        uVar2 = 5;
      }
      else {
        uVar2 = 6;
      }
      pcVar3 = (char *)(*DAT_08060240)(uVar2,uVar1,param_2 + 8,0,DAT_08060244,param_3);
    }
    if (((pcVar3 == param_3) &&
        ((pcVar3 = (char *)FUN_0804d310(uVar1,1,pcVar3), uVar6 == 4 || (uVar6 == 2)))) &&
       ((param_1 & 0xf0000) == 0xf0000)) {
      puVar4 = (undefined1 *)FUN_0804d0e0(" ; ",pcVar3);
      if (uVar6 != 4) {
        uVar1 = -uVar1;
      }
      pcVar3 = (char *)FUN_0804d310(param_2 + 8 + uVar1,1,puVar4);
    }
  }
  return pcVar3;
}



undefined4
FUN_0804eba4(uint param_1,uint param_2,char *param_3,undefined4 param_4,undefined *param_5,
            int param_6)

{
  bool bVar1;
  uint uVar2;
  undefined1 *puVar3;
  undefined4 uVar4;
  char *pcVar5;
  char *pcVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint local_ac;
  char *local_7c;
  int local_6c;
  char local_58 [8];
  char local_50 [12];
  char local_44 [64];
  
  local_44[0] = '\0';
  DAT_08060240 = (code *)param_5;
  DAT_08060244 = param_4;
  switch((param_1 & 0xf000000) >> 0x18) {
  case 0:
    goto switchD_0804ebf4_caseD_0;
  case 1:
  case 2:
  case 3:
    goto switchD_0804ebf4_caseD_1;
  case 4:
  case 5:
    break;
  case 6:
  case 7:
    if ((param_1 & 0x10) != 0) {
      pcVar6 = (char *)FUN_0804d0e0("Undefined Instruction",param_3);
      goto LAB_0804fa5a;
    }
    break;
  case 8:
  case 9:
    if ((param_1 & 0x100000) == 0) {
      pcVar6 = "STM";
    }
    else {
      pcVar6 = "LDM";
    }
    pcVar6 = (char *)FUN_0804d0e0(pcVar6,param_3);
    pcVar6 = (char *)FUN_0804d0fc(param_1,pcVar6);
    puVar3 = (undefined1 *)FUN_0804d0e0(&UNK_0805a2be + ((param_1 & 0x1800000) >> 0x15),pcVar6);
    pcVar6 = (char *)FUN_0804d338((int)param_3,puVar3);
    pcVar6 = FUN_0804d128((param_1 & 0xf0000) >> 0x10,0,pcVar6);
    if ((param_1 & 0x200000) != 0) {
      *pcVar6 = '!';
      pcVar6 = pcVar6 + 1;
    }
    *pcVar6 = ',';
    pcVar6 = FUN_0804d6b4(param_1,pcVar6 + 1);
    if ((param_1 & 0x400000) != 0) {
      *pcVar6 = '^';
      pcVar6 = pcVar6 + 1;
    }
    goto LAB_0804fa5a;
  case 10:
  case 0xb:
    if (param_1 >> 0x19 == 0x7d) {
      puVar3 = (undefined1 *)FUN_0804d0e0("BLX",param_3);
      pcVar5 = (char *)FUN_0804d338((int)param_3,puVar3);
    }
    else {
      if ((param_1 & 0x1000000) == 0) {
        pcVar6 = "B";
      }
      else {
        pcVar6 = "BL";
      }
      pcVar5 = (char *)FUN_0804d388(param_1,pcVar6,0,param_3);
    }
    iVar8 = (int)(param_1 << 8) >> 6;
    param_2 = iVar8 + 8 + param_2;
    if (param_6 == 0) {
      param_2 = param_2 & 0x3ffffff;
    }
    pcVar6 = pcVar5;
    if (DAT_08060240 != (code *)0x0) {
      pcVar6 = (char *)(*DAT_08060240)(0,iVar8,param_2,0,DAT_08060244,pcVar5);
    }
    if (pcVar6 != pcVar5) goto LAB_0804fa5a;
    goto LAB_0804f9e9;
  case 0xc:
  case 0xd:
    uVar9 = 2;
    goto LAB_0804fa24;
  case 0xe:
    uVar9 = param_1 >> 4 & 1;
LAB_0804fa24:
    pcVar6 = (char *)FUN_0804e980(uVar9,param_1,param_2,param_3,local_44);
    goto LAB_0804fa5a;
  case 0xf:
    pcVar5 = (char *)FUN_0804d388(param_1,"SWI",0,param_3);
    pcVar6 = pcVar5;
    if (DAT_08060240 != (code *)0x0) {
      pcVar6 = (char *)(*DAT_08060240)(7,param_1 & 0xffffff,0,0,DAT_08060244,pcVar5);
    }
    if (pcVar6 != pcVar5) goto LAB_0804fa5a;
LAB_0804f9e9:
    pcVar6 = FUN_0804d09c(pcVar6,"%s%lx");
    goto LAB_0804fa5a;
  default:
    pcVar6 = (char *)FUN_0804d0e0("EQUD    ",param_3);
    pcVar6 = FUN_0804d09c(pcVar6,"%s%lx");
    goto LAB_0804fa5a;
  }
  if ((param_1 & 0x100000) == 0) {
    pcVar6 = "STR";
  }
  else {
    pcVar6 = "LDR";
  }
  pcVar6 = (char *)FUN_0804d0e0(pcVar6,param_3);
  puVar3 = (undefined1 *)FUN_0804d0fc(param_1,pcVar6);
  if ((param_1 & 0x400000) != 0) {
    *puVar3 = 0x42;
    puVar3 = puVar3 + 1;
  }
  if (((param_1 & 0x1000000) == 0) && ((param_1 & 0x200000) != 0)) {
    *puVar3 = 0x54;
    puVar3 = puVar3 + 1;
  }
  pcVar6 = (char *)FUN_0804d338((int)param_3,puVar3);
  pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0x2c,pcVar6);
  if ((param_1 & 0x400000) == 0) {
    uVar4 = 4;
  }
  else {
    uVar4 = 1;
  }
  pcVar6 = (char *)FUN_0804d688(param_1,param_2,param_1 & 0xfff,uVar4,pcVar6);
  goto LAB_0804fa5a;
switchD_0804ebf4_caseD_0:
  if ((param_1 & 0xf0) == 0x90) {
    if ((param_1 & 0xc00000) == 0) {
      if ((param_1 & 0x100000) == 0) {
        iVar8 = 0;
      }
      else {
        iVar8 = 0x53;
      }
      if ((param_1 & 0x200000) == 0) {
        pcVar6 = "MUL";
      }
      else {
        pcVar6 = "MLA";
      }
      pcVar6 = (char *)FUN_0804d388(param_1,pcVar6,iVar8,param_3);
      pcVar6 = FUN_0804d128((param_1 & 0xf0000) >> 0x10,0x2c,pcVar6);
      pcVar6 = FUN_0804d128(param_1 & 0xf,0x2c,pcVar6);
      pcVar6 = FUN_0804d128((param_1 & 0xf00) >> 8,0,pcVar6);
      if ((param_1 & 0x200000) != 0) {
        *pcVar6 = ',';
        pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0,pcVar6 + 1);
      }
      goto LAB_0804fa5a;
    }
    if ((param_1 & 0x800000) != 0) {
      if ((param_1 & 0x100000) == 0) {
        iVar8 = 0;
      }
      else {
        iVar8 = 0x53;
      }
      if ((param_1 & 0x200000) == 0) {
        if ((param_1 & 0x400000) == 0) {
          pcVar6 = "UMULL";
        }
        else {
          pcVar6 = "SMULL";
        }
      }
      else if ((param_1 & 0x400000) == 0) {
        pcVar6 = "UMLAL";
      }
      else {
        pcVar6 = "SMLAL";
      }
      pcVar6 = (char *)FUN_0804d388(param_1,pcVar6,iVar8,param_3);
      pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0x2c,pcVar6);
      pcVar6 = FUN_0804d128((param_1 & 0xf0000) >> 0x10,0x2c,pcVar6);
      pcVar6 = FUN_0804d128(param_1 & 0xf,0x2c,pcVar6);
      pcVar6 = FUN_0804d128((param_1 & 0xf00) >> 8,0,pcVar6);
      goto LAB_0804fa5a;
    }
    FUN_0804cee0(local_44,"Bad arithmetic extension op = %ld");
  }
switchD_0804ebf4_caseD_1:
  if ((((param_1 & 0xc000000) != 0) || ((param_1 & 0x1800000) != 0x1000000)) ||
     ((param_1 & 0x100000) != 0)) {
LAB_0804f3b6:
    if ((((param_1 & 0xe000000) == 0) && ((param_1 & 0x80) != 0)) &&
       (((param_1 & 0x10) != 0 &&
        ((uVar9 = param_1 & 0x1000000, uVar9 != 0 || ((param_1 & 0x60) != 0)))))) {
      if (((param_1 & 0x1800000) == 0x1000000) &&
         (((param_1 & 0x300000) == 0 && ((param_1 & 0xff0) == 0x90)))) {
        if ((param_1 & 0x400000) == 0) {
          iVar8 = 0;
        }
        else {
          iVar8 = 0x42;
        }
        pcVar6 = (char *)FUN_0804d388(param_1,"SWP",iVar8,param_3);
        pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0x2c,pcVar6);
        pcVar6 = FUN_0804d128(param_1 & 0xf,0x2c,pcVar6);
        *pcVar6 = '[';
        pcVar6 = FUN_0804d128((param_1 & 0xf0000) >> 0x10,0x5d,pcVar6 + 1);
        goto LAB_0804fa5a;
      }
      if ((param_1 & 0x100000) == 0) {
        if ((param_1 & 0x60) == 0x20) goto LAB_0804f4a9;
      }
      else if ((param_1 & 0x60) != 0) {
LAB_0804f4a9:
        if ((param_1 & 0x100000) == 0) {
          pcVar6 = "STR";
        }
        else {
          pcVar6 = "LDR";
        }
        pcVar6 = (char *)FUN_0804d0e0(pcVar6,param_3);
        puVar3 = (undefined1 *)FUN_0804d0fc(param_1,pcVar6);
        if ((param_1 & 0x40) == 0) {
LAB_0804f513:
          *puVar3 = 0x48;
        }
        else {
          *puVar3 = 0x53;
          puVar3 = puVar3 + 1;
          if ((param_1 & 0x20) != 0) goto LAB_0804f513;
          *puVar3 = 0x42;
        }
        pcVar6 = (char *)FUN_0804d338((int)param_3,puVar3 + 1);
        pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0x2c,pcVar6);
        *pcVar6 = '[';
        pcVar6 = FUN_0804d128((param_1 & 0xf0000) >> 0x10,0,pcVar6 + 1);
        if (uVar9 == 0) {
          *pcVar6 = ']';
          pcVar6 = pcVar6 + 1;
        }
        *pcVar6 = ',';
        pcVar5 = pcVar6 + 1;
        if ((param_1 & 0x400000) == 0) {
          if ((param_1 & 0x800000) == 0) {
            *pcVar5 = '-';
            pcVar5 = pcVar6 + 2;
          }
          pcVar5 = FUN_0804d128(param_1 & 0xf,0,pcVar5);
        }
        else {
          pcVar5 = (char *)FUN_0804d310(((param_1 & 0xf00) >> 4) + (param_1 & 0xf),
                                        (param_1 & 0x800000) >> 0x17,pcVar5);
        }
        if (uVar9 == 0) {
          pcVar6 = pcVar5;
          if ((param_1 & 0x200000) != 0) {
            FUN_0804cee0(local_44,"Post-indexed, W=1");
          }
        }
        else {
          *pcVar5 = ']';
          pcVar6 = pcVar5 + 1;
          if ((param_1 & 0x200000) != 0) {
            pcVar5[1] = '!';
            pcVar6 = pcVar5 + 2;
          }
        }
        goto LAB_0804fa5a;
      }
      FUN_0804cee0(local_44,"Bad load/store extension op");
    }
    if (param_1 == 0xe1a00000) {
      pcVar6 = (char *)FUN_0804d388(0xe1a00000,"NOP",0,param_3);
      goto LAB_0804fa5a;
    }
    uVar9 = (param_1 & 0x1e00000) >> 0x15;
    uVar2 = (param_1 & 0xf000) >> 0xc;
    if ((param_1 & 0x100000) == 0) {
      iVar8 = 0;
    }
    else if (uVar9 - 8 < 4) {
      if (uVar2 == 0xf) {
        iVar8 = 0x50;
      }
      else {
        iVar8 = 0;
      }
    }
    else {
      iVar8 = 0x53;
    }
    local_ac = uVar9 - 8;
    pcVar6 = (char *)FUN_0804d388(param_1,&DAT_0805a260 + uVar9 * 4,iVar8,param_3);
    if (local_ac < 4) {
      if (uVar2 != 0xf) {
        FUN_0804d074(uVar2,&DAT_0805a1ff,local_44);
      }
    }
    else {
      pcVar6 = FUN_0804d128(uVar2,0x2c,pcVar6);
    }
    if ((uVar9 == 0xd) || (uVar9 == 0xf)) {
      FUN_0804d074((param_1 & 0xf0000) >> 0x10,&DAT_0805a1e9,local_44);
    }
    else {
      pcVar6 = FUN_0804d128((param_1 & 0xf0000) >> 0x10,0x2c,pcVar6);
    }
LAB_0804f74b:
    pcVar6 = FUN_0804ea84(param_1,param_2,pcVar6);
    goto LAB_0804fa5a;
  }
  uVar9 = param_1 & 0x2000000;
  if (uVar9 == 0) {
    if (((param_1 & 0x80) == 0) || ((param_1 & 0x10) == 0)) {
      if (((param_1 & 0xf0) == 0x10) &&
         (((param_1 & 0xfff00) == 0xfff00 && ((param_1 & 0x600000) == 0x200000)))) {
        pcVar6 = "BX";
      }
      else {
        if (((param_1 & 0xf0) != 0x30) ||
           (((param_1 & 0xfff00) != 0xfff00 || ((param_1 & 0x600000) != 0x200000))))
        goto LAB_0804eed0;
        pcVar6 = "BLX";
      }
      pcVar6 = (char *)FUN_0804d388(param_1,pcVar6,0,param_3);
      pcVar6 = FUN_0804d128(param_1 & 0xf,0,pcVar6);
      goto LAB_0804fa5a;
    }
    goto LAB_0804f3b6;
  }
LAB_0804eed0:
  if (((param_1 & 0xff00000) == 0x1600000) && ((param_1 & 0xf0) == 0x10)) {
    pcVar6 = (char *)FUN_0804d388(param_1,"CLZ",0,param_3);
    pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0x2c,pcVar6);
    pcVar6 = FUN_0804d128(param_1 & 0xf,0,pcVar6);
    goto LAB_0804fa5a;
  }
  if ((param_1 & 0xff0) != 0x50) {
    if ((((param_1 & 0xf800000) == 0x1000000) && ((param_1 & 0x10) == 0)) && ((param_1 & 0x80) != 0)
       ) {
      pcVar6 = (char *)0x0;
      local_6c = 0;
      bVar1 = true;
      switch((param_1 & 0x600000) >> 0x15) {
      case 0:
        pcVar6 = "SMLA";
        local_6c = 1;
        break;
      case 1:
        bVar1 = false;
        if ((param_1 & 0x20) == 0) {
          pcVar6 = "SMLAW";
          local_6c = 1;
        }
        else {
          pcVar6 = "SMULW";
        }
        break;
      case 2:
        pcVar6 = "SMLAL";
        local_6c = 2;
        break;
      case 3:
        pcVar6 = "SMUL";
      }
      strcpy(local_50,pcVar6);
      if (bVar1) {
        if ((param_1 & 0x20) == 0) {
          pcVar6 = "B";
        }
        else {
          pcVar6 = "T";
        }
        strcat(local_50,pcVar6);
      }
      if ((param_1 & 0x40) == 0) {
        pcVar6 = "B";
      }
      else {
        pcVar6 = "T";
      }
      strcat(local_50,pcVar6);
      pcVar6 = (char *)FUN_0804d388(param_1,local_50,0,param_3);
      if (local_6c == 2) {
        pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0x2c,pcVar6);
      }
      pcVar6 = FUN_0804d128((param_1 & 0xf0000) >> 0x10,0x2c,pcVar6);
      pcVar6 = FUN_0804d128(param_1 & 0xf,0x2c,pcVar6);
      pcVar6 = FUN_0804d128((param_1 & 0xf00) >> 8,(int)(char)(&DAT_0805a1d4)[local_6c != 1],pcVar6)
      ;
      if (local_6c == 1) {
        pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0,pcVar6);
      }
      goto LAB_0804fa5a;
    }
LAB_0804f1d7:
    if (uVar9 == 0) {
      if ((param_1 & 0x200000) == 0) {
        pcVar6 = (char *)FUN_0804d388(param_1,"MRS",0,param_3);
        pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0x2c,pcVar6);
        if ((param_1 & 0x400000) == 0) {
          pcVar5 = "CPSR";
        }
        else {
          pcVar5 = "SPSR";
        }
        pcVar6 = (char *)FUN_0804d0e0(pcVar5,pcVar6);
        FUN_0804d074(param_1 & 0xfff,&DAT_0805a1e4,local_44);
        FUN_0804d03c((param_1 & 0xf0000) >> 0x10,0xf,&DAT_0805a1e9,local_44);
        goto LAB_0804fa5a;
      }
    }
    else if ((param_1 & 0x200000) == 0) {
      FUN_0804cee0(local_44,"Bad control extension op");
      goto LAB_0804f3b6;
    }
    if ((param_1 & 0x400000) == 0) {
      pcVar6 = "CPSR";
    }
    else {
      pcVar6 = "SPSR";
    }
    uVar2 = (param_1 & 0xf0000) >> 0x10;
    local_58[0] = '_';
    local_7c = local_58 + 1;
    if ((uVar2 & 1) != 0) {
      local_58[1] = 99;
      local_7c = local_58 + 2;
    }
    if ((param_1 & 0x20000) != 0) {
      *local_7c = 'x';
      local_7c = local_7c + 1;
    }
    if ((uVar2 & 4) != 0) {
      *local_7c = 's';
      local_7c = local_7c + 1;
    }
    if ((param_1 & 0x80000) != 0) {
      *local_7c = 'f';
      local_7c = local_7c + 1;
    }
    if (uVar2 == 0) {
      FUN_0804cee0(local_44,"field-mask = 0");
    }
    *local_7c = ',';
    local_7c[1] = '\0';
    pcVar5 = (char *)FUN_0804d388(param_1,"MSR",0,param_3);
    pcVar6 = (char *)FUN_0804d0e0(pcVar6,pcVar5);
    pcVar6 = (char *)FUN_0804d0e0(local_58,pcVar6);
    FUN_0804d03c((param_1 & 0xf000) >> 0xc,0xf,&DAT_0805a1ff,local_44);
    if (uVar9 == 0) {
      FUN_0804d074((param_1 & 0xff0) >> 4,&DAT_0805a202,local_44);
    }
    goto LAB_0804f74b;
  }
  if ((param_1 & 0xf800000) != 0x1000000) goto LAB_0804f1d7;
  pcVar6 = (char *)0x0;
  bVar1 = false;
  switch((param_1 & 0x600000) >> 0x15) {
  case 0:
    pcVar6 = "QADD";
    break;
  case 1:
    pcVar6 = "QSUB";
    break;
  case 2:
    pcVar6 = "QDADD";
    goto LAB_0804efae;
  case 3:
    pcVar6 = "QDSUB";
LAB_0804efae:
    bVar1 = true;
  }
  pcVar6 = (char *)FUN_0804d388(param_1,pcVar6,0,param_3);
  pcVar6 = FUN_0804d128((param_1 & 0xf000) >> 0xc,0x2c,pcVar6);
  uVar7 = (param_1 & 0xf0000) >> 0x10;
  uVar9 = uVar7;
  uVar2 = param_1 & 0xf;
  if (bVar1) {
    uVar9 = param_1 & 0xf;
    uVar2 = uVar7;
  }
  pcVar6 = FUN_0804d128(uVar9,0x2c,pcVar6);
  pcVar6 = FUN_0804d128(uVar2,0,pcVar6);
LAB_0804fa5a:
  if (local_44[0] != '\0') {
    pcVar6 = FUN_0804d09c(pcVar6," ; ? %s");
  }
  *pcVar6 = '\0';
  return 4;
}



void FUN_0804fa90(char *param_1,char *param_2,int param_3)

{
  size_t __n;
  
  if (param_3 < 1) {
    __n = 0;
  }
  else {
    __n = param_3 - 1;
  }
  strncpy(param_1,param_2,__n);
  param_1[__n] = '\0';
  return;
}



void FUN_0804fac8(char *param_1)

{
  FUN_0804fa90(s_utility_0805ec80,param_1,0x20);
  return;
}



void FUN_0804faf0(char *param_1,char *param_2)

{
  FUN_0804fa90(&DAT_08060260,param_1,0xa0);
  FUN_0804fa90(&DAT_08060300,param_2,0xa0);
  return;
}



undefined1 * FUN_0804fb34(void)

{
  undefined1 *puVar1;
  
  puVar1 = &DAT_08060260;
  if (DAT_08060260 == '\0') {
    puVar1 = (undefined1 *)0x0;
  }
  return puVar1;
}



undefined * FUN_0804fb5c(void)

{
  undefined *puVar1;
  
  if (DAT_08060260 == '\0') {
    puVar1 = (undefined *)0x0;
  }
  else {
    puVar1 = &DAT_08060300;
  }
  return puVar1;
}



void FUN_0804fb88(char *param_1,__gnuc_va_list param_2)

{
  fprintf(stderr,"%s: ",s_utility_0805ec80);
  vfprintf(stderr,param_1,param_2);
  fprintf(stderr,"\n");
  return;
}



void FUN_0804fbe8(char *param_1)

{
  FUN_0804fb88(param_1,&stack0x00000008);
  return;
}



void FUN_0804fc0c(char *param_1)

{
  FUN_0804fb88(param_1,&stack0x00000008);
                    // WARNING: Subroutine does not return
  exit(1);
}



char * FUN_0804fc30(char *param_1,char *param_2,int param_3)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  size_t local_10;
  char *local_8;
  
  if (param_2 == (char *)0x0) {
    return param_1;
  }
  if (param_3 < 1) {
    return param_1;
  }
  uVar2 = 0xffffffff;
  pcVar5 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  local_10 = ~uVar2 - 1;
  local_8 = param_1 + local_10;
  if (4 < (int)local_10) {
    pcVar4 = local_8 + -4;
    iVar3 = 5;
    bVar7 = true;
    pcVar5 = pcVar4;
    pcVar6 = ".exe";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar7 = *pcVar5 == *pcVar6;
      pcVar5 = pcVar5 + 1;
      pcVar6 = pcVar6 + 1;
    } while (bVar7);
    if (!bVar7) {
      iVar3 = 5;
      bVar7 = true;
      pcVar5 = pcVar4;
      pcVar6 = ".EXE";
      do {
        if (iVar3 == 0) break;
        iVar3 = iVar3 + -1;
        bVar7 = *pcVar5 == *pcVar6;
        pcVar5 = pcVar5 + 1;
        pcVar6 = pcVar6 + 1;
      } while (bVar7);
      if (!bVar7) goto LAB_0804fcbe;
    }
    local_10 = ~uVar2 - 5;
    local_8 = pcVar4;
  }
LAB_0804fcbe:
  iVar3 = local_10 + -2;
  do {
    if (iVar3 < 0) {
LAB_0804fcf3:
      local_10 = (int)local_8 - (int)param_1;
      if ((int)(param_3 - 1U) < (int)local_8 - (int)param_1) {
        local_10 = param_3 - 1U;
      }
      if (0 < (int)local_10) {
        strncpy(param_2,param_1,local_10);
      }
      param_2[local_10] = '\0';
      return param_2;
    }
    cVar1 = param_1[iVar3];
    if ((((cVar1 == '\\') || (cVar1 == '/')) || (cVar1 == ':')) || (cVar1 == '.')) {
      param_1 = param_1 + iVar3 + 1;
      goto LAB_0804fcf3;
    }
    iVar3 = iVar3 + -1;
  } while( true );
}



void FUN_0804fd40(int *param_1,void *param_2,size_t param_3,void *param_4)

{
  void *pvVar1;
  size_t sVar2;
  size_t local_8;
  
  if (*param_1 == 0) {
    sVar2 = param_1[3] - (int)param_4;
    param_1[4] = param_1[4] + param_3;
    if (1 < (int)param_3) {
      *(undefined1 *)(param_1 + 5) = *(undefined1 *)((int)param_2 + (param_3 - 1));
    }
    if ((int)sVar2 < (int)param_3) {
      param_3 = sVar2;
    }
    local_8 = param_1[1] - (int)param_4;
    if ((int)(sVar2 - param_3) < param_1[1] - (int)param_4) {
      local_8 = sVar2 - param_3;
    }
    memmove((void *)((int)param_4 + param_3),param_4,local_8);
    memcpy(param_4,param_2,param_3);
    pvVar1 = (void *)param_1[2];
    if (param_4 <= pvVar1) {
      if ((int)param_3 < param_1[3] - (int)pvVar1) {
        param_1[2] = (int)pvVar1 + param_3;
      }
      else {
        param_1[2] = param_1[3];
      }
    }
    if ((int)(local_8 + param_3) < param_1[3] - (int)param_4) {
      param_1[1] = (int)((int)param_4 + param_3) + local_8;
    }
    else {
      param_1[1] = param_1[3];
    }
  }
  return;
}



void FUN_0804fe04(int *param_1,undefined1 *param_2,size_t param_3)

{
  undefined1 *puVar1;
  
  if (*param_1 == 0) {
    puVar1 = (undefined1 *)param_1[2];
    if (puVar1 == (undefined1 *)param_1[1]) {
      param_1[4] = param_1[4] + param_3;
      if (param_2 == (undefined1 *)0x0) {
        *(undefined1 *)(param_1 + 5) = 0x3f;
      }
      else if (0 < (int)param_3) {
        *(undefined1 *)(param_1 + 5) = param_2[param_3 - 1];
        if (puVar1 < (undefined1 *)param_1[3]) {
          do {
            if ((int)param_3 < 1) break;
            *puVar1 = *param_2;
            param_2 = param_2 + 1;
            param_1[2] = param_1[2] + 1;
            param_3 = param_3 - 1;
            puVar1 = (undefined1 *)param_1[2];
          } while (puVar1 < (undefined1 *)param_1[3]);
        }
        param_1[1] = (int)puVar1;
      }
    }
    else {
      FUN_0804fd40(param_1,param_2,param_3,puVar1);
    }
  }
  return;
}



void FUN_0804fe78(int *param_1,undefined1 param_2)

{
  undefined1 *puVar1;
  undefined1 local_5;
  
  local_5 = param_2;
  if (*param_1 == 0) {
    puVar1 = (undefined1 *)param_1[2];
    if (puVar1 == (undefined1 *)param_1[1]) {
      param_1[4] = param_1[4] + 1;
      if (puVar1 < (undefined1 *)param_1[3]) {
        *puVar1 = param_2;
        param_1[2] = param_1[2] + 1;
      }
      param_1[1] = param_1[2];
      *(undefined1 *)(param_1 + 5) = param_2;
    }
    else {
      FUN_0804fd40(param_1,&local_5,1,puVar1);
    }
  }
  return;
}



undefined4 FUN_0804fed4(int *param_1,char *param_2,uint param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined **ppuVar4;
  char *pcVar5;
  
  ppuVar4 = &PTR_DAT_0805eca0;
  do {
    iVar2 = strncmp(param_2,*ppuVar4,param_3);
    if (iVar2 == 0) {
      uVar3 = 0xffffffff;
      pcVar5 = *ppuVar4;
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar5 + 1;
      } while (cVar1 != '\0');
      if (~uVar3 - 1 <= param_3) {
        uVar3 = 0xffffffff;
        pcVar5 = "operator";
        break;
      }
    }
    ppuVar4 = ppuVar4 + 2;
    if (&DAT_0805edf0 <= ppuVar4) {
      return 0;
    }
  } while( true );
  while( true ) {
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
    if (cVar1 == '\0') break;
    if (uVar3 == 0) break;
  }
  FUN_0804fe04(param_1,"operator",~uVar3 - 1);
  uVar3 = 0xffffffff;
  pcVar5 = ppuVar4[1];
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  FUN_0804fe04(param_1,ppuVar4[1],~uVar3 - 1);
  return 1;
}



byte * FUN_0804ff84(int *param_1,byte *param_2,byte *param_3,int param_4)

{
  size_t sVar1;
  int iVar2;
  byte *pbVar3;
  
  sVar1 = __strtol_internal(param_2,0,10,0);
  if (0 < (int)sVar1) {
    while (iVar2 = isdigit((uint)*param_2), iVar2 != 0) {
      param_2 = param_2 + 1;
    }
    if (param_2 + sVar1 <= param_3) {
      if (param_4 == 0) {
        return param_2 + sVar1;
      }
      pbVar3 = FUN_08050fc0(param_1,param_2,sVar1);
      return pbVar3;
    }
  }
  return (byte *)0x0;
}



byte * FUN_0804ffe8(int *param_1,byte *param_2,byte *param_3,int param_4,int param_5)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  char *pcVar5;
  int local_8;
  
  if ((param_2 < param_3) && (iVar2 = isdigit((uint)*param_2), iVar2 != 0)) {
    local_8 = (char)*param_2 + -0x30;
    pbVar4 = param_2 + 1;
    if (1 < local_8) {
      while (pbVar4 = FUN_0804ff84(param_1,pbVar4,param_3,param_5), pbVar4 != (byte *)0x0) {
        if (param_5 != 0) {
          uVar3 = 0xffffffff;
          pcVar5 = "::";
          do {
            if (uVar3 == 0) break;
            uVar3 = uVar3 - 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          FUN_0804fe04(param_1,&DAT_0805a36e,~uVar3 - 1);
        }
        local_8 = local_8 + -1;
        if (local_8 < 2) {
          if (param_4 != 0) {
            return pbVar4;
          }
          pbVar4 = FUN_0804ff84(param_1,pbVar4,param_3,param_5);
          return pbVar4;
        }
      }
    }
  }
  return (byte *)0x0;
}



byte * FUN_0805009c(int *param_1,char *param_2,char *param_3,int param_4)

{
  byte *pbVar1;
  
  if (param_2 < param_3) {
    if (*param_2 == 'Q') {
      pbVar1 = FUN_0804ffe8(param_1,(byte *)(param_2 + 1),(byte *)param_3,0,param_4);
    }
    else {
      pbVar1 = FUN_0804ff84(param_1,(byte *)param_2,(byte *)param_3,param_4);
    }
  }
  else {
    pbVar1 = (byte *)0x0;
  }
  return pbVar1;
}



void FUN_080500e4(int *param_1,uint param_2,int param_3,int param_4)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  if ((param_3 != 0) && ((param_2 & 7) != 0)) {
    FUN_0804fe78(param_1,0x20);
  }
  if ((param_2 & 4) != 0) {
    uVar2 = 0xffffffff;
    pcVar3 = "__packed";
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    FUN_0804fe04(param_1,"__packed",~uVar2 - 1);
    if ((param_2 & 3) != 0) {
      FUN_0804fe78(param_1,0x20);
    }
  }
  if ((param_2 & 1) != 0) {
    uVar2 = 0xffffffff;
    pcVar3 = "const";
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    FUN_0804fe04(param_1,"const",~uVar2 - 1);
    if ((param_2 & 2) != 0) {
      FUN_0804fe78(param_1,0x20);
    }
  }
  if ((param_2 & 2) != 0) {
    uVar2 = 0xffffffff;
    pcVar3 = "volatile";
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    FUN_0804fe04(param_1,"volatile",~uVar2 - 1);
  }
  if ((param_4 != 0) && ((param_2 & 7) != 0)) {
    FUN_0804fe78(param_1,0x20);
  }
  return;
}



void FUN_080501e8(int *param_1,undefined4 *param_2,char *param_3,int param_4)

{
  uint uVar1;
  char *pcVar2;
  char cVar3;
  
  if (param_2 == (undefined4 *)0x0) {
    return;
  }
  pcVar2 = (char *)param_2[1];
  cVar3 = *pcVar2;
  if (cVar3 == 'P') {
    cVar3 = '*';
  }
  else {
    if (cVar3 < 'Q') {
      if (cVar3 == 'M') {
        if (param_4 != 0) {
          FUN_0804fe78(param_1,0x20);
          pcVar2 = (char *)param_2[1];
        }
        FUN_0805009c(param_1,pcVar2 + 1,param_3,1);
        uVar1 = 0xffffffff;
        pcVar2 = "::";
        do {
          if (uVar1 == 0) break;
          uVar1 = uVar1 - 1;
          cVar3 = *pcVar2;
          pcVar2 = pcVar2 + 1;
        } while (cVar3 != '\0');
        FUN_0804fe04(param_1,&DAT_0805a36e,~uVar1 - 1);
        FUN_0804fe78(param_1,0x2a);
        goto LAB_08050294;
      }
    }
    else if (cVar3 == 'R') {
      cVar3 = '&';
      goto LAB_0805028b;
    }
    cVar3 = *pcVar2;
  }
LAB_0805028b:
  FUN_0804fe78(param_1,cVar3);
LAB_08050294:
  FUN_080500e4(param_1,param_2[2],0,0);
  FUN_080501e8(param_1,(undefined4 *)*param_2,param_3,1);
  return;
}



byte * FUN_080502c0(int *param_1,byte *param_2,byte *param_3,uint param_4,undefined4 *param_5,
                   undefined4 *param_6,int *param_7)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  size_t sVar5;
  int *piVar6;
  byte *pbVar7;
  byte *pbVar8;
  uint uVar9;
  uint uVar10;
  char *pcVar11;
  byte bVar12;
  char *local_9c;
  int local_78;
  int *local_74;
  int local_70;
  int *local_6c;
  int local_68;
  int local_60;
  int local_5c;
  undefined4 *local_58;
  byte *local_54;
  uint local_50;
  int local_4c [18];
  
  bVar2 = false;
  local_68 = param_1[4];
  local_6c = param_7;
  local_70 = 0;
  if (param_7 == (int *)0x0) {
    local_74 = (int *)0x0;
  }
  else {
    local_74 = param_7 + 0x12;
  }
  local_78 = param_1[1];
  if (param_3 <= param_2) {
    return (byte *)0x0;
  }
  if (param_6 != (undefined4 *)0x0) {
    *param_6 = 0;
  }
  if (param_7 != (int *)0x0) {
    for (; local_6c < local_74; local_6c = local_6c + 2) {
      if (*local_6c == 0) {
        local_70 = (int)local_6c - (int)param_7 >> 3;
        break;
      }
    }
    if (local_6c == local_74) {
      local_70 = 9;
      local_6c = (int *)0x0;
    }
  }
LAB_08050df3:
  if (!bVar2) {
    uVar9 = (uint)*param_2;
    pbVar7 = param_2 + 1;
    iVar3 = islower(uVar9);
    if (((iVar3 != 0) || (iVar3 = isdigit(uVar9), iVar3 != 0)) || (uVar9 == 0x51)) {
      FUN_080500e4(param_1,param_4,0,1);
      switch(uVar9) {
      case 0x30:
      case 0x31:
      case 0x32:
      case 0x33:
      case 0x34:
      case 0x35:
      case 0x36:
      case 0x37:
      case 0x38:
      case 0x39:
        pbVar7 = FUN_0804ff84(param_1,param_2,param_3,1);
        goto LAB_080506d3;
      default:
        pbVar7 = (byte *)0x0;
        goto LAB_080506d3;
      case 0x51:
        pbVar7 = FUN_0804ffe8(param_1,pbVar7,param_3,0,1);
        goto LAB_080506d3;
      case 0x62:
        local_9c = "bool";
        goto LAB_08050676;
      case 99:
        local_9c = "char";
        uVar9 = 0xffffffff;
        pcVar11 = "char";
        do {
          if (uVar9 == 0) break;
          uVar9 = uVar9 - 1;
          cVar1 = *pcVar11;
          pcVar11 = pcVar11 + 1;
        } while (cVar1 != '\0');
        sVar5 = ~uVar9 - 1;
        break;
      case 100:
        local_9c = "double";
        goto LAB_08050676;
      case 0x65:
        local_9c = "...";
        goto LAB_08050676;
      case 0x66:
        local_9c = "float";
        uVar9 = 0xffffffff;
        pcVar11 = "float";
        do {
          if (uVar9 == 0) break;
          uVar9 = uVar9 - 1;
          cVar1 = *pcVar11;
          pcVar11 = pcVar11 + 1;
        } while (cVar1 != '\0');
        sVar5 = ~uVar9 - 1;
        break;
      case 0x69:
        local_9c = "int";
        goto LAB_08050676;
      case 0x6c:
        local_9c = "long";
        uVar9 = 0xffffffff;
        pcVar11 = "long";
        do {
          if (uVar9 == 0) break;
          uVar9 = uVar9 - 1;
          cVar1 = *pcVar11;
          pcVar11 = pcVar11 + 1;
        } while (cVar1 != '\0');
        sVar5 = ~uVar9 - 1;
        break;
      case 0x72:
        local_9c = "long double";
        uVar9 = 0xffffffff;
        pcVar11 = "long double";
        do {
          if (uVar9 == 0) break;
          uVar9 = uVar9 - 1;
          cVar1 = *pcVar11;
          pcVar11 = pcVar11 + 1;
        } while (cVar1 != '\0');
        sVar5 = ~uVar9 - 1;
        break;
      case 0x73:
        local_9c = "short";
        uVar9 = 0xffffffff;
        pcVar11 = "short";
        do {
          if (uVar9 == 0) break;
          uVar9 = uVar9 - 1;
          cVar1 = *pcVar11;
          pcVar11 = pcVar11 + 1;
        } while (cVar1 != '\0');
        sVar5 = ~uVar9 - 1;
        break;
      case 0x76:
        local_9c = "void";
        uVar9 = 0xffffffff;
        pcVar11 = "void";
        do {
          if (uVar9 == 0) break;
          uVar9 = uVar9 - 1;
          cVar1 = *pcVar11;
          pcVar11 = pcVar11 + 1;
        } while (cVar1 != '\0');
        sVar5 = ~uVar9 - 1;
        break;
      case 0x77:
        local_9c = "wchar_t";
        goto LAB_08050676;
      case 0x78:
        local_9c = "long long";
LAB_08050676:
        uVar9 = 0xffffffff;
        pcVar11 = local_9c;
        do {
          if (uVar9 == 0) break;
          uVar9 = uVar9 - 1;
          cVar1 = *pcVar11;
          pcVar11 = pcVar11 + 1;
        } while (cVar1 != '\0');
        sVar5 = ~uVar9 - 1;
      }
      FUN_0804fe04(param_1,local_9c,sVar5);
LAB_080506d3:
      FUN_080501e8(param_1,param_5,(char *)param_3,1);
LAB_08050a2f:
      bVar2 = true;
      param_2 = pbVar7;
      goto LAB_08050df3;
    }
    switch(uVar9) {
    case 0:
    case 0x5f:
      break;
    default:
      goto LAB_08050e32;
    case 0x41:
      uVar9 = param_1[2];
      if (param_5 != (undefined4 *)0x0) {
        FUN_0804fe78(param_1,0x28);
        FUN_080501e8(param_1,param_5,(char *)param_3,0);
        param_1[2] = param_1[1];
        if (param_6 != (undefined4 *)0x0) {
          *param_6 = 1;
        }
        FUN_0804fe78(param_1,0x29);
      }
      while( true ) {
        bVar12 = 0x5b;
        for (; FUN_0804fe78(param_1,bVar12), *pbVar7 != 0x5f; pbVar7 = pbVar7 + 1) {
          if (param_3 <= pbVar7) {
            return (byte *)0x0;
          }
          bVar12 = *pbVar7;
        }
        pbVar8 = pbVar7 + 1;
        if (param_3 <= pbVar8) {
          return (byte *)0x0;
        }
        FUN_0804fe78(param_1,0x5d);
        if (*pbVar8 != 0x41) break;
        pbVar7 = pbVar7 + 2;
      }
      uVar10 = param_1[2];
      if (uVar10 <= uVar9) {
        uVar10 = 0;
      }
      iVar3 = param_1[1];
      local_60 = 0;
      if (param_3 <= pbVar8) {
        return (byte *)0x0;
      }
      param_1[2] = uVar9;
      param_2 = FUN_080502c0(param_1,pbVar8,param_3,param_4,(undefined4 *)0x0,&local_60,param_7);
      if (local_60 == 0) {
        FUN_0804fe78(param_1,0x20);
      }
      if (uVar10 != 0) {
        param_1[2] = uVar10 + (param_1[1] - iVar3);
      }
      break;
    case 0x43:
      param_4 = param_4 | 1;
      param_2 = pbVar7;
      goto LAB_08050df3;
    case 0x46:
      uVar9 = param_1[2];
      if (param_3 <= pbVar7) {
        return (byte *)0x0;
      }
      piVar6 = local_4c;
      if (local_4c < &stack0xfffffffc) {
        do {
          *piVar6 = 0;
          piVar6[1] = 0;
          piVar6 = piVar6 + 2;
        } while (piVar6 < &stack0xfffffffc);
      }
      if (param_5 != (undefined4 *)0x0) {
        FUN_0804fe78(param_1,0x28);
        FUN_080501e8(param_1,param_5,(char *)param_3,0);
        param_1[2] = param_1[1];
        if (param_6 != (undefined4 *)0x0) {
          *param_6 = 1;
        }
        FUN_0804fe78(param_1,0x29);
      }
      FUN_0804fe78(param_1,0x28);
      if (*pbVar7 == 0x76) {
        pbVar7 = param_2 + 2;
      }
      else {
        while( true ) {
          pbVar7 = FUN_080502c0(param_1,pbVar7,param_3,0,(undefined4 *)0x0,(undefined4 *)0x0,
                                local_4c);
          if (pbVar7 == (byte *)0x0) {
            return (byte *)0x0;
          }
          if ((*pbVar7 == 0) || (*pbVar7 == 0x5f)) break;
          uVar10 = 0xffffffff;
          pcVar11 = ", ";
          do {
            if (uVar10 == 0) break;
            uVar10 = uVar10 - 1;
            cVar1 = *pcVar11;
            pcVar11 = pcVar11 + 1;
          } while (cVar1 != '\0');
          FUN_0804fe04(param_1,&DAT_0805a371,~uVar10 - 1);
        }
      }
      FUN_0804fe78(param_1,0x29);
      if (*pbVar7 == 0x5f) {
        uVar10 = param_1[2];
        if (uVar10 < uVar9) {
          uVar10 = 0;
        }
        iVar3 = param_1[1];
        local_5c = 0;
        param_1[2] = uVar9;
        pbVar7 = FUN_080502c0(param_1,pbVar7 + 1,param_3,0,(undefined4 *)0x0,&local_5c,local_4c);
        if (local_5c == 0) {
          FUN_0804fe78(param_1,0x20);
        }
        if (uVar10 != 0) {
          param_1[2] = uVar10 + (param_1[1] - iVar3);
        }
      }
      FUN_080500e4(param_1,param_4,1,0);
      goto LAB_08050a2f;
    case 0x4b:
      param_4 = param_4 | 4;
      param_2 = pbVar7;
      goto LAB_08050df3;
    case 0x4d:
    case 0x50:
    case 0x52:
      local_58 = param_5;
      local_50 = param_4;
      local_54 = param_2;
      if ((uVar9 == 0x4d) &&
         (pbVar7 = (byte *)FUN_0805009c(param_1,(char *)pbVar7,(char *)param_3,0),
         pbVar7 == (byte *)0x0)) {
        return (byte *)0x0;
      }
      if (param_3 <= pbVar7) {
        return (byte *)0x0;
      }
      param_2 = FUN_080502c0(param_1,pbVar7,param_3,0,&local_58,param_6,param_7);
      bVar2 = true;
      goto LAB_08050df3;
    case 0x4e:
      iVar3 = isdigit((uint)*pbVar7);
      if (iVar3 == 0) {
        return (byte *)0x0;
      }
      iVar3 = (char)*pbVar7 + -0x30;
      if (iVar3 < 2) {
        return (byte *)0x0;
      }
      iVar4 = isdigit((uint)param_2[2]);
      if (iVar4 == 0) {
        return (byte *)0x0;
      }
      iVar4 = (char)param_2[2] + -0x31;
      param_2 = param_2 + 3;
      if ((0 < iVar4) && (local_70 <= iVar4)) {
        return (byte *)0x0;
      }
      for (; 0 < iVar3; iVar3 = iVar3 + -1) {
        FUN_0804fe04(param_1,(undefined1 *)param_7[iVar4 * 2 + 1],param_7[iVar4 * 2]);
        if (1 < iVar3) {
          if (local_6c != (int *)0x0) {
            *local_6c = param_7[iVar4 * 2];
            local_6c[1] = local_78;
            if (param_1[1] != 0) {
              local_78 = param_1[1] + 1;
            }
            local_68 = param_1[4];
            local_6c = local_6c + 2;
            if (local_6c == local_74) {
              local_6c = (int *)0x0;
            }
          }
          uVar9 = 0xffffffff;
          pcVar11 = ", ";
          do {
            if (uVar9 == 0) break;
            uVar9 = uVar9 - 1;
            cVar1 = *pcVar11;
            pcVar11 = pcVar11 + 1;
          } while (cVar1 != '\0');
          FUN_0804fe04(param_1,&DAT_0805a371,~uVar9 - 1);
        }
      }
      break;
    case 0x53:
      FUN_080500e4(param_1,param_4,0,1);
      local_9c = "signed ";
      uVar9 = 0xffffffff;
      pcVar11 = "signed ";
      do {
        if (uVar9 == 0) break;
        uVar9 = uVar9 - 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar11 + 1;
      } while (cVar1 != '\0');
      goto LAB_08050ae9;
    case 0x54:
      iVar3 = isdigit((uint)*pbVar7);
      if (iVar3 == 0) {
        return (byte *)0x0;
      }
      iVar3 = (char)*pbVar7 + -0x31;
      if (iVar3 < 0) {
        return (byte *)0x0;
      }
      if (local_70 <= iVar3) {
        return (byte *)0x0;
      }
      FUN_0804fe04(param_1,(undefined1 *)param_7[iVar3 * 2 + 1],param_7[iVar3 * 2]);
      bVar2 = true;
      param_2 = param_2 + 2;
      goto LAB_08050df3;
    case 0x55:
      FUN_080500e4(param_1,param_4,0,1);
      local_9c = "unsigned ";
      uVar9 = 0xffffffff;
      pcVar11 = local_9c;
      do {
        if (uVar9 == 0) break;
        uVar9 = uVar9 - 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar11 + 1;
      } while (cVar1 != '\0');
LAB_08050ae9:
      param_4 = 0;
      FUN_0804fe04(param_1,local_9c,~uVar9 - 1);
      param_2 = pbVar7;
      goto LAB_08050df3;
    case 0x56:
      goto switchD_08050702_caseD_56;
    }
  }
  if (param_2 != (byte *)0x0) {
    if (local_6c != (int *)0x0) {
      if (*param_1 == 0) {
        local_68 = param_1[4] - local_68;
      }
      else {
        local_68 = 1;
      }
      *local_6c = local_68;
      local_6c[1] = local_78;
      return param_2;
    }
    return param_2;
  }
LAB_08050e32:
  return (byte *)0x0;
switchD_08050702_caseD_56:
  param_4 = param_4 | 2;
  param_2 = pbVar7;
  goto LAB_08050df3;
}



byte * FUN_08050e40(int *param_1,byte *param_2,byte *param_3)

{
  char cVar1;
  byte bVar2;
  byte *pbVar3;
  char *pcVar4;
  int *piVar5;
  uint uVar6;
  undefined1 uVar7;
  byte bVar8;
  int local_4c [18];
  
  piVar5 = local_4c;
  if (local_4c < &stack0xfffffffc) {
    do {
      *piVar5 = 0;
      piVar5[1] = 0;
      piVar5 = piVar5 + 2;
    } while (piVar5 < &stack0xfffffffc);
  }
  bVar2 = *param_2;
  if (bVar2 == 0x46) {
    uVar7 = 0x28;
  }
  else {
    if ((char)param_1[5] == '<') {
      FUN_0804fe78(param_1,0x20);
    }
    uVar7 = 0x3c;
  }
  FUN_0804fe78(param_1,uVar7);
  bVar8 = param_2[1];
  pbVar3 = param_2 + 1;
  if (bVar8 == 0x76) {
    param_2 = param_2 + 2;
  }
  else {
    while( true ) {
      param_2 = pbVar3;
      if (bVar8 == 0x58) {
        pcVar4 = strchr((char *)(param_2 + 1),0x59);
        if (pcVar4 == (char *)0x0) {
          return (byte *)0x0;
        }
        FUN_0804fe04(param_1,param_2 + 1,(size_t)(pcVar4 + (-1 - (int)param_2)));
        param_2 = param_2 + (int)(pcVar4 + (1 - (int)param_2));
      }
      else {
        param_2 = FUN_080502c0(param_1,param_2,param_3,0,(undefined4 *)0x0,(undefined4 *)0x0,
                               local_4c);
      }
      if (param_2 == (byte *)0x0) {
        return (byte *)0x0;
      }
      if (((param_3 <= param_2) || (*param_2 == 0x3e)) || (*param_2 == 0x5f)) break;
      uVar6 = 0xffffffff;
      pcVar4 = ", ";
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      FUN_0804fe04(param_1,&DAT_0805a371,~uVar6 - 1);
      bVar8 = *param_2;
      pbVar3 = param_2;
    }
  }
  if ((char)param_1[5] == '>') {
    FUN_0804fe78(param_1,0x20);
  }
  if (bVar2 == 0x46) {
    uVar7 = 0x29;
  }
  else {
    uVar7 = 0x3e;
  }
  FUN_0804fe78(param_1,uVar7);
  return param_2;
}



byte * FUN_08050fc0(int *param_1,byte *param_2,size_t param_3)

{
  bool bVar1;
  byte *pbVar2;
  char *pcVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  int local_1c [6];
  
  pbVar2 = param_2;
  bVar1 = false;
  pcVar3 = strstr((char *)param_2,"__t");
  if ((pcVar3 != (char *)0x0) && (3 < (int)(param_2 + param_3) - (int)pcVar3)) {
    piVar5 = param_1;
    piVar6 = local_1c;
    for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
      *piVar6 = *piVar5;
      piVar5 = piVar5 + 1;
      piVar6 = piVar6 + 1;
    }
    FUN_0804fe04(param_1,param_2,(int)pcVar3 - (int)param_2);
    param_2 = FUN_08050e40(param_1,param_2 + ((int)pcVar3 - (int)param_2) + 2,param_2 + param_3);
    if (param_2 == (byte *)0x0) {
      piVar5 = local_1c;
      piVar6 = param_1;
      for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
        *piVar6 = *piVar5;
        piVar5 = piVar5 + 1;
        piVar6 = piVar6 + 1;
      }
    }
    else {
      bVar1 = true;
    }
  }
  if (!bVar1) {
    FUN_0804fe04(param_1,pbVar2,param_3);
    param_2 = pbVar2 + param_3;
  }
  return param_2;
}



void FUN_08051094(int *param_1,byte *param_2,byte *param_3)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0xffffffff;
  pcVar3 = "operator";
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  FUN_0804fe04(param_1,"operator",~uVar2 - 1);
  FUN_0804fe78(param_1,0x20);
  FUN_080502c0(param_1,param_2,param_3,0,(undefined4 *)0x0,(undefined4 *)0x0,(int *)0x0);
  return;
}



int FUN_080510f4(byte *param_1,byte *param_2,size_t param_3,undefined1 *param_4,int param_5,
                uint param_6)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  byte *pbVar6;
  byte *pbVar7;
  uint uVar8;
  byte bVar9;
  byte *pbVar10;
  bool bVar11;
  char *local_3c;
  char *local_28;
  byte *local_24;
  byte *local_20;
  int local_1c;
  undefined1 *local_18;
  undefined1 *local_14;
  undefined1 *local_10;
  int local_c;
  undefined1 local_8;
  
  pbVar7 = param_1;
  local_20 = param_1;
  local_24 = (byte *)0x0;
  bVar2 = false;
  uVar8 = 0xffffffff;
  pbVar10 = param_1;
  do {
    if (uVar8 == 0) break;
    uVar8 = uVar8 - 1;
    bVar9 = *pbVar10;
    pbVar10 = pbVar10 + 1;
  } while (bVar9 != 0);
  pbVar10 = param_1 + (~uVar8 - 1);
  if (pbVar10 == param_1) {
    return 0;
  }
  local_1c = 0;
  local_14 = param_4;
  local_18 = param_4;
  if (param_5 < 1) {
    local_10 = param_4;
  }
  else {
    local_10 = param_4 + param_5 + -1;
  }
  local_c = 0;
  local_8 = 0;
  iVar3 = strncmp((char *)param_1,"__ct",4);
  iVar4 = strncmp((char *)param_1,"__dt",4);
  bVar11 = iVar4 == 0;
  local_28 = strstr((char *)(param_1 + 1),"__");
  if (local_28 == (char *)0x0) {
LAB_08051232:
    if ((param_2 == (byte *)0x0) && (local_24 == (byte *)0x0)) {
      if (*param_1 != 0x5f) {
        return 0;
      }
      if (param_1[1] != 0x5f) {
        return 0;
      }
      bVar2 = true;
    }
    uVar8 = 0xffffffff;
    pbVar6 = param_1;
    do {
      if (uVar8 == 0) break;
      uVar8 = uVar8 - 1;
      bVar9 = *pbVar6;
      pbVar6 = pbVar6 + 1;
    } while (bVar9 != 0);
    local_28 = (char *)(~uVar8 - 1);
    param_1 = param_1 + (int)local_28;
  }
  else {
    if ((local_28[2] == 't') && (local_28[3] == 'F')) {
      local_24 = (byte *)(local_28 + 4);
      pcVar5 = strstr((char *)local_24,"_<");
      if (pcVar5 == (char *)0x0) goto LAB_08051232;
      pcVar5 = strchr(pcVar5 + 2,0x3e);
      if (pcVar5 == (char *)0x0) {
        return 0;
      }
      local_28 = strstr(pcVar5 + 1,"__");
    }
    if (local_28 == (char *)0x0) goto LAB_08051232;
    local_28 = local_28 + -(int)param_1;
    param_1 = param_1 + (int)(local_28 + 2);
    if (*param_1 == 0x51) {
      if ((param_6 & 1) != 0) {
        local_1c = local_1c + 1;
      }
      param_1 = FUN_0804ffe8(&local_1c,param_1 + 1,pbVar10,1,1);
      if ((param_6 & 1) != 0) {
        local_1c = local_1c + -1;
      }
      if (param_1 == (byte *)0x0) {
        return 0;
      }
    }
    iVar4 = isdigit((uint)*param_1);
    if (iVar4 != 0) {
      param_3 = __strtol_internal(param_1,0,10,0);
      if ((int)param_3 < 1) {
        return 0;
      }
      while (iVar4 = isdigit((uint)*param_1), iVar4 != 0) {
        param_1 = param_1 + 1;
      }
      if (pbVar10 < param_1 + param_3) {
        return 0;
      }
      param_2 = param_1;
      param_1 = param_1 + param_3;
    }
  }
  if (param_2 == (byte *)0x0) {
    if (iVar3 == 0) {
      return 0;
    }
    if (bVar11) {
      return 0;
    }
LAB_080513f4:
    if (0 < (int)local_28) {
      if (local_24 == (byte *)0x0) {
        local_3c = local_28;
      }
      else {
        local_3c = (char *)(local_24 + (-4 - (int)local_20));
      }
      iVar3 = 0;
      if (((3 < (int)local_3c) && (*local_20 == 0x5f)) && (local_20[1] == 0x5f)) {
        iVar3 = FUN_0804fed4(&local_1c,(char *)(local_20 + 2),(uint)(local_3c + -2));
      }
      if (iVar3 == 0) {
        uVar8 = 0xffffffff;
        pcVar5 = "__op";
        do {
          if (uVar8 == 0) break;
          uVar8 = uVar8 - 1;
          cVar1 = *pcVar5;
          pcVar5 = pcVar5 + 1;
        } while (cVar1 != '\0');
        iVar3 = strncmp((char *)local_20,"__op",~uVar8 - 1);
        bVar11 = false;
        if (iVar3 == 0) {
          uVar8 = 0xffffffff;
          pcVar5 = "__op";
          do {
            if (uVar8 == 0) break;
            uVar8 = uVar8 - 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          pbVar7 = (byte *)FUN_08051094(&local_1c,local_20 + (~uVar8 - 1),local_20 + (int)local_3c);
          if (pbVar7 != local_20 + (int)local_3c) {
            return 0;
          }
          bVar11 = true;
        }
        if (!bVar11) {
          if (bVar2) {
            return 0;
          }
          FUN_0804fe04(&local_1c,local_20,(size_t)local_3c);
        }
      }
      if (local_24 != (byte *)0x0) {
        pcVar5 = strstr((char *)local_24,"_<");
        if (pcVar5 == (char *)0x0) {
          local_24 = local_24 + -1;
        }
        else {
          local_24 = (byte *)(pcVar5 + 1);
        }
        FUN_08050e40(&local_1c,local_24,local_20 + (int)local_28);
      }
    }
  }
  else {
    if ((param_6 & 1) == 0) {
      pbVar6 = FUN_08050fc0(&local_1c,param_2,param_3);
      if (pbVar6 == (byte *)0x0) {
        return 0;
      }
      uVar8 = 0xffffffff;
      pcVar5 = "::";
      do {
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar5 + 1;
      } while (cVar1 != '\0');
      FUN_0804fe04(&local_1c,&DAT_0805a36e,~uVar8 - 1);
    }
    if ((iVar3 != 0) && (!bVar11)) goto LAB_080513f4;
    if (bVar11) {
      FUN_0804fe78(&local_1c,0x7e);
    }
    pbVar6 = FUN_08050fc0(&local_1c,param_2,param_3);
    if (pbVar6 == (byte *)0x0) {
      return 0;
    }
    if (local_24 != (byte *)0x0) {
      local_28 = local_28 + -((int)local_24 - (int)(pbVar7 + 4));
      local_20 = local_24 + -4;
      goto LAB_080513f4;
    }
  }
  pbVar7 = param_1;
  if (*param_1 == 0x53) {
    if ((param_6 & 2) == 0) {
      uVar8 = 0xffffffff;
      pcVar5 = "static ";
      do {
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar5 + 1;
      } while (cVar1 != '\0');
      FUN_0804fd40(&local_1c,"static ",~uVar8 - 1,param_4);
    }
    param_1 = param_1 + 1;
  }
  else {
    if (*param_1 == 0x43) {
      pbVar7 = param_1 + 1;
    }
    bVar9 = *pbVar7;
    if (bVar9 != 0x56) goto LAB_08051576;
  }
  bVar9 = pbVar7[1];
LAB_08051576:
  if (bVar9 == 0x46) {
    if ((param_6 & 4) != 0) {
      local_1c = local_1c + 1;
    }
    param_1 = FUN_080502c0(&local_1c,param_1,pbVar10,0,(undefined4 *)0x0,(undefined4 *)0x0,
                           (int *)0x0);
    if (param_1 == (byte *)0x0) {
      return 0;
    }
  }
  if (param_1 != pbVar10) {
    return 0;
  }
  if (0 < param_5) {
    *local_18 = 0;
  }
  return local_c + 1;
}



void FUN_080515e0(byte *param_1,undefined1 *param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  uint __n;
  byte *pbVar4;
  
  iVar2 = FUN_080510f4(param_1,(byte *)0x0,0,param_2,param_3,0);
  if (iVar2 == 0) {
    uVar3 = 0xffffffff;
    pbVar4 = param_1;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      bVar1 = *pbVar4;
      pbVar4 = pbVar4 + 1;
    } while (bVar1 != 0);
    __n = ~uVar3 - 1;
    if (param_3 - 1U < ~uVar3 - 1) {
      __n = param_3 - 1U;
    }
    memcpy(param_2,param_1,__n);
    param_2[__n] = 0;
  }
  return;
}



byte * FUN_0805164c(byte *param_1,byte *param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_080510f4(param_1,(byte *)0x0,0,param_2,param_3,0);
  if ((0 < iVar1) && (iVar1 <= param_3)) {
    param_1 = param_2;
  }
  return param_1;
}



byte * FUN_0805168c(byte *param_1,byte *param_2,size_t param_3,byte *param_4,int param_5)

{
  int iVar1;
  
  iVar1 = FUN_080510f4(param_1,param_2,param_3,param_4,param_5,0);
  if ((0 < iVar1) && (iVar1 <= param_5)) {
    param_1 = param_4;
  }
  return param_1;
}



void FUN_080516cc(byte *param_1,undefined1 *param_2,int param_3,uint param_4)

{
  FUN_080510f4(param_1,(byte *)0x0,0,param_2,param_3,param_4);
  return;
}



void FUN_080516f8(byte *param_1,byte *param_2,size_t param_3,undefined1 *param_4,int param_5,
                 uint param_6)

{
  FUN_080510f4(param_1,param_2,param_3,param_4,param_5,param_6);
  return;
}



int FUN_08051724(byte *param_1,undefined1 *param_2,int param_3)

{
  byte bVar1;
  char *pcVar2;
  byte *pbVar3;
  uint uVar4;
  byte *pbVar5;
  int local_1c;
  undefined1 *local_18;
  undefined1 *local_14;
  undefined1 *local_10;
  int local_c;
  undefined1 local_8;
  
  uVar4 = 0xffffffff;
  pbVar5 = param_1;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    bVar1 = *pbVar5;
    pbVar5 = pbVar5 + 1;
  } while (bVar1 != 0);
  pbVar5 = param_1 + (~uVar4 - 1);
  if (((param_1 < pbVar5) && (pcVar2 = strstr((char *)param_1,"__t"), pcVar2 != (char *)0x0)) &&
     (3 < (int)pbVar5 - (int)pcVar2)) {
    local_1c = 0;
    local_14 = param_2;
    local_18 = param_2;
    if (0 < param_3) {
      param_2 = param_2 + param_3 + -1;
    }
    local_c = 0;
    local_8 = 0;
    local_10 = param_2;
    FUN_0804fe04(&local_1c,param_1,(int)pcVar2 - (int)param_1);
    pbVar3 = FUN_08050e40(&local_1c,param_1 + ((int)pcVar2 - (int)param_1) + 2,pbVar5);
    if (pbVar3 == pbVar5) {
      if (0 < param_3) {
        *local_18 = 0;
      }
      return local_c + 1;
    }
  }
  return 0;
}



byte * FUN_080517f0(byte *param_1,byte *param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_08051724(param_1,param_2,param_3);
  if ((0 < iVar1) && (iVar1 <= param_3)) {
    param_1 = param_2;
  }
  return param_1;
}



int FUN_08051830(char *param_1,char *param_2)

{
  int iVar1;
  int iVar2;
  
  while( true ) {
    iVar1 = toupper((int)*param_1);
    iVar2 = toupper((int)*param_2);
    iVar2 = (int)(char)iVar1 - (int)(char)iVar2;
    if (iVar2 != 0) {
      return iVar2;
    }
    if ((char)iVar1 == '\0') break;
    param_1 = param_1 + 1;
    param_2 = param_2 + 1;
  }
  return 0;
}



int FUN_08051890(char *param_1,char *param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  while( true ) {
    if (param_3 == 0) {
      return 0;
    }
    iVar1 = toupper((int)*param_1);
    iVar2 = toupper((int)*param_2);
    iVar2 = (int)(char)iVar1 - (int)(char)iVar2;
    if (iVar2 != 0) break;
    if ((char)iVar1 == '\0') {
      return 0;
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + 1;
    param_3 = param_3 + -1;
  }
  return iVar2;
}



bool FUN_080518fc(char *param_1,char *param_2)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  int iVar3;
  int iVar4;
  
  while( true ) {
    if (*param_1 == '*') {
      do {
        param_1 = param_1 + 1;
        cVar2 = *param_1;
      } while (cVar2 == '*');
      if (*param_2 == '\0') break;
      do {
        bVar1 = FUN_080518fc(param_1,param_2);
        if (CONCAT31(extraout_var,bVar1) != 0) {
          return true;
        }
        param_2 = param_2 + 1;
      } while (*param_2 != '\0');
    }
    cVar2 = *param_1;
    if (*param_2 == '\0') break;
    if (cVar2 != '?') {
      iVar3 = tolower((int)*param_1);
      iVar4 = tolower((int)*param_2);
      if (iVar3 != iVar4) {
        return false;
      }
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + 1;
  }
  return cVar2 == '\0';
}



undefined1 * FUN_08051994(undefined1 *param_1,undefined1 *param_2,char *param_3)

{
  char cVar1;
  uint uVar2;
  undefined1 *puVar3;
  undefined1 *__n;
  char *pcVar4;
  
  if (param_1 < param_2) {
    puVar3 = param_2 + (-1 - (int)param_1);
    if (puVar3 != (undefined1 *)0x0) {
      uVar2 = 0xffffffff;
      pcVar4 = param_3;
      do {
        if (uVar2 == 0) break;
        uVar2 = uVar2 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      __n = (undefined1 *)(~uVar2 - 1);
      if (puVar3 < (undefined1 *)(~uVar2 - 1)) {
        __n = puVar3;
      }
      memcpy(param_1,param_3,(size_t)__n);
      param_1 = param_1 + (int)__n;
    }
    *param_1 = 0;
  }
  return param_1;
}



void FUN_08051a00(int param_1)

{
  fprintf(DAT_080603a0,"%.6x%s ",param_1 - DAT_0805edf0,&DAT_080603a4);
  return;
}



void FUN_08051a28(ulong param_1,long param_2)

{
  char *__s;
  
  switch(param_2) {
  case 0:
    __s = "void";
    break;
  default:
    fprintf(DAT_080603a0,"*** ? type (%ld) at offset %#lx",param_2,param_1);
    return;
  case 10:
    __s = "signed char";
    break;
  case 0xb:
    __s = "signed short";
    break;
  case 0xc:
    __s = "signed int";
    break;
  case 0xd:
    __s = "signed long long";
    break;
  case 0x14:
    __s = "unsigned char";
    break;
  case 0x15:
    __s = "unsigned short";
    break;
  case 0x16:
    __s = "unsigned int";
    break;
  case 0x17:
    __s = "unsigned long long";
    break;
  case 0x1e:
    __s = "float";
    break;
  case 0x1f:
    __s = "double";
    break;
  case 0x20:
    __s = "long double";
    break;
  case 0x28:
    __s = "single complex";
    break;
  case 0x29:
    __s = "double complex";
    break;
  case 100:
    __s = "function";
  }
  fputs(__s,DAT_080603a0);
  return;
}



void FUN_08051af0(undefined4 param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_0804c9cc(param_2);
  iVar2 = (int)uVar1 >> 8;
  uVar1 = uVar1 & 0xff;
  while (uVar1 != 0) {
    fprintf(DAT_080603a0,"*");
    uVar1 = uVar1 - 1;
  }
  if (iVar2 < 0) {
    fprintf(DAT_080603a0,"type {%.6lx}",-iVar2);
  }
  else {
    FUN_08051a28(param_1,iVar2);
  }
  return;
}



void FUN_08051b54(char *param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_0804c9cc(param_2);
  if (uVar1 >> 0x16 == 0) {
    fprintf(DAT_080603a0,"%s at %ld",param_1,uVar1 & 0x3fffff);
  }
  else {
    fprintf(DAT_080603a0,"%s at %ld,%ld",param_1,uVar1 & 0x3fffff,uVar1 >> 0x16);
  }
  return;
}



void FUN_08051bac(char *param_1,uint *param_2,int param_3)

{
  uint param2;
  uint *puVar1;
  char *__format;
  uint local_8;
  
  param2 = FUN_0804c9cc(*param_2);
  fprintf(DAT_080603a0,"%s ",param_1);
  if (DAT_080603b8 == 0) {
    puVar1 = (uint *)0x0;
  }
  else {
    puVar1 = (uint *)FUN_08049a48((int)param_2 - DAT_0805edf0,&local_8);
  }
  if (puVar1 == (uint *)0x0) {
    fprintf(DAT_080603a0,"0x%lx",param2);
    if (param_3 != 0) {
      return;
    }
    if (DAT_080603b8 == 0) {
      return;
    }
    __format = "*** bad relocation at offset %#lx\n";
    puVar1 = param_2;
  }
  else {
    if (param2 != 0) {
      fprintf(DAT_080603a0,"0x%lx+",param2);
    }
    __format = "%s";
  }
  fprintf(DAT_080603a0,__format,puVar1);
  return;
}



void FUN_08051c64(void)

{
  int iVar1;
  
  (&DAT_080603a4)[DAT_080603b4] = 0x20;
  iVar1 = DAT_080603b4;
  DAT_080603b4 = DAT_080603b4 + 1;
  (&DAT_080603a5)[iVar1] = 0x20;
  iVar1 = DAT_080603b4;
  DAT_080603b4 = DAT_080603b4 + 1;
  (&DAT_080603a5)[iVar1] = 0;
  return;
}



void FUN_08051c98(void)

{
  int iVar1;
  
  iVar1 = DAT_080603b4 + 2;
  DAT_080603b4 = DAT_080603b4 + -2;
  *(undefined1 *)((int)&DAT_080603a0 + iVar1) = 0;
  return;
}



bool FUN_08051cb4(uint param_1)

{
  return (param_1 - 1 & param_1) != 0;
}



void FUN_08051cc8(undefined4 param_1)

{
  DAT_0805edf0 = param_1;
  return;
}



uint * FUN_08051cd8(FILE *param_1,uint *param_2,uint *param_3,int param_4)

{
  byte bVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  uint *puVar6;
  uint *puVar7;
  int iVar8;
  uint uVar9;
  char *pcVar10;
  uint *puVar11;
  bool bVar12;
  int param3;
  char *pcVar13;
  ushort *local_70;
  uint *local_6c;
  ulong local_60;
  uint local_5c;
  uint local_58;
  uint local_54;
  uint local_50;
  ulong local_4c;
  uint *local_44;
  int local_38;
  char *local_34;
  int local_18;
  uint local_14;
  uint *local_8;
  
  DAT_080603a0 = param_1;
  local_8 = param_2;
  local_18 = 0;
  if (DAT_0805edf0 == (uint *)0x0) {
    DAT_0805edf0 = param_2;
  }
  DAT_080603b4 = 0;
  DAT_080603a4 = 0;
  DAT_080603b8 = param_4;
  uVar3 = FUN_0804c9cc(*param_2);
  if ((short)uVar3 != 1) {
    fprintf(DAT_080603a0,"*** Format Error at %#lx: Section expected\n",(ulong)param_2);
    return param_3;
  }
  if ((char)param_2[1] != '\0') {
    FUN_08051a00((int)param_2);
    fprintf(DAT_080603a0,"Section: length %ld\n",uVar3 >> 0x10);
  }
  uVar4 = FUN_0804c9cc(param_2[7]);
  puVar6 = (uint *)(uVar4 + (int)param_2);
  if ((char)param_2[1] == '\0') {
    if (DAT_080603b8 == 0) {
      uVar3 = FUN_0804c9cc(param_2[8]);
      iVar8 = uVar3 * 8;
      puVar7 = param_2 + 9;
      while (uVar3 = uVar3 - 1, -1 < (int)uVar3) {
        uVar4 = FUN_0804c9cc(*puVar7);
        uVar9 = uVar4 & 0x6000000;
        uVar5 = FUN_0804c9cc(puVar7[1]);
        fprintf(DAT_080603a0,"%-24s 0x%.8lx : ",
                (char *)((int)(param_2 + 9) + (uVar4 & 0xffffff) + iVar8),uVar5);
        if (uVar9 == 0) {
          pcVar13 = "Absolute";
        }
        else {
          if ((uVar4 & 0x1000000) == 0) {
            pcVar13 = "Local,  ";
          }
          else {
            pcVar13 = "Global, ";
          }
          fprintf(DAT_080603a0,pcVar13);
          if ((uVar4 & 0x10000000) != 0) {
            fprintf(DAT_080603a0,"16-bit, ");
          }
          if (uVar9 == 0x2000000) {
            pcVar13 = "Code";
          }
          else if (uVar9 == 0x4000000) {
            pcVar13 = "Data";
          }
          else {
            pcVar13 = "Zero-Init";
          }
        }
        fprintf(DAT_080603a0,pcVar13);
        fprintf(DAT_080603a0,"\n");
        puVar7 = puVar7 + 2;
      }
      return puVar6;
    }
    pcVar13 = "*** Low level (linker generated) debugging tables in AOF file at offset %#lx\n";
    goto LAB_08053320;
  }
  FUN_08051a00((int)(param_2 + 1));
  bVar1 = (byte)param_2[1];
  if (bVar1 == 2) {
    pcVar13 = "    Language: Pascal\n";
LAB_08051f2c:
    fprintf(DAT_080603a0,pcVar13);
  }
  else {
    if (2 < bVar1) {
      if (bVar1 == 3) {
        pcVar13 = "    Language: Fortran\n";
      }
      else {
        if (bVar1 != 4) goto LAB_08051f40;
        pcVar13 = "    Language: Assembler\n";
      }
      goto LAB_08051f2c;
    }
    if (bVar1 == 1) {
      pcVar13 = "    Language: C\n";
      goto LAB_08051f2c;
    }
LAB_08051f40:
    fprintf(DAT_080603a0,"    Language: Unknown (%d)\n",(uint)(byte)param_2[1]);
  }
  FUN_08051a00((int)param_2 + 5);
  bVar1 = *(byte *)((int)param_2 + 5);
  fprintf(DAT_080603a0,"    Flags: ");
  if (bVar1 == 0) {
    pcVar13 = "none";
LAB_08051ff6:
    fprintf(DAT_080603a0,pcVar13);
  }
  else {
    bVar12 = (bVar1 & 1) != 0;
    if (bVar12) {
      fprintf(DAT_080603a0,"line number info");
    }
    if ((bVar1 & 2) != 0) {
      if (bVar12) {
        pcVar13 = ", variable info";
      }
      else {
        pcVar13 = "variable info";
      }
      fprintf(DAT_080603a0,pcVar13);
      bVar12 = true;
    }
    if ((*(byte *)((int)param_2 + 5) & 4) != 0) {
      if (bVar12) {
        pcVar13 = ", fp map";
      }
      else {
        pcVar13 = "fp map";
      }
      goto LAB_08051ff6;
    }
  }
  fprintf(DAT_080603a0,"\n");
  FUN_08051a00((int)param_2 + 7);
  fprintf(DAT_080603a0,"    Debugging table version: %d\n",(uint)*(byte *)((int)param_2 + 7));
  FUN_08051a00((int)(param_2 + 2));
  FUN_08051bac("    Code: address",param_2 + 2,1);
  uVar4 = FUN_0804c9cc(param_2[4]);
  fprintf(DAT_080603a0,", size = 0x%lx\n",uVar4);
  FUN_08051a00((int)(param_2 + 3));
  FUN_08051bac("    Data: address",param_2 + 3,1);
  uVar4 = FUN_0804c9cc(param_2[5]);
  fprintf(DAT_080603a0,", size = 0x%lx\n",uVar4);
  FUN_08051a00((int)(param_2 + 6));
  uVar4 = FUN_0804c9cc(param_2[6]);
  fprintf(DAT_080603a0,"    File info offset = 0x%.6lx\n",uVar4);
  FUN_08051a00((int)(param_2 + 7));
  uVar4 = FUN_0804c9cc(param_2[7]);
  fprintf(DAT_080603a0,"    Section size = %ld\n",uVar4);
  FUN_08051a00((int)(param_2 + 8));
  fprintf(DAT_080603a0,"    Section name: \"%.*s\"\n",(int)(char)param_2[8],
          (char *)((int)param_2 + 0x21));
  local_14 = uVar3 >> 0x10;
LAB_0805330d:
  if (local_14 != 0) {
    local_8 = (uint *)((int)local_8 + local_14);
    if (puVar6 <= local_8) {
      return puVar6;
    }
    uVar3 = FUN_0804c9cc(*local_8);
    local_14 = uVar3 >> 0x10;
    puVar7 = (uint *)(uVar3 & 0xffff);
    switch(puVar7) {
    case (uint *)0x1:
      FUN_08051a00((int)local_8);
      pcVar13 = "*** Misplaced section at offset %#lx\n";
      puVar7 = local_8;
      break;
    case (uint *)0x2:
      FUN_08051a00((int)local_8);
      FUN_08051b54(&DAT_0805aaa6,local_8[3]);
      fprintf(DAT_080603a0,": name %.*s:",(int)(char)local_8[8],(char *)((int)local_8 + 0x21));
      FUN_08051af0(local_8,local_8[1]);
      uVar3 = FUN_0804c9cc(local_8[2]);
      fprintf(DAT_080603a0,": %ld arguments\n",uVar3);
      FUN_08051a00((int)(local_8 + 4));
      FUN_08051bac("    Start address",local_8 + 4,0);
      FUN_08051bac(", body",local_8 + 5,0);
      fprintf(DAT_080603a0,"\n");
      FUN_08051a00((int)(local_8 + 6));
      if (local_8[6] == 0) {
        fprintf(DAT_080603a0,"    Endproc = 0 => Label\n");
      }
      else {
        uVar3 = FUN_0804c9cc(local_8[6]);
        fprintf(DAT_080603a0,"    Endproc 0x%.6lx\n",uVar3);
      }
      FUN_08051a00((int)(local_8 + 7));
      uVar3 = FUN_0804c9cc(local_8[7]);
      fprintf(DAT_080603a0,"    File 0x%.6lx\n",uVar3);
      local_18 = 0;
      FUN_08051c64();
      goto LAB_0805330d;
    case (uint *)0x3:
      FUN_08051c98();
      FUN_08051a00((int)local_8);
      FUN_08051b54("Endproc",local_8[1]);
      FUN_08051bac(": limit",local_8 + 2,0);
      fprintf(DAT_080603a0,"\n");
      FUN_08051a00((int)(local_8 + 3));
      uVar3 = FUN_0804c9cc(local_8[3]);
      fprintf(DAT_080603a0,"    File 0x%.6lx\n",uVar3);
      uVar3 = FUN_0804c9cc(local_8[4]);
      iVar8 = 0;
      if (0 < (int)uVar3) {
        puVar7 = local_8 + 5;
        do {
          FUN_08051a00((int)puVar7);
          if (iVar8 == 0) {
            pcVar13 = "    return point %ld";
          }
          else {
            pcVar13 = "                 %ld";
          }
          fprintf(DAT_080603a0,pcVar13,iVar8);
          FUN_08051bac(&DAT_0805ab5d,puVar7,0);
          fprintf(DAT_080603a0,"\n");
          puVar7 = puVar7 + 1;
          iVar8 = iVar8 + 1;
        } while (iVar8 < (int)uVar3);
      }
      if (local_18 != 0) {
        pcVar13 = "*** scopes still open at endproc at offset %#lx\n";
        puVar7 = local_8;
        goto LAB_080528d5;
      }
      goto LAB_0805330d;
    case (uint *)0x4:
      FUN_08051a00((int)local_8);
      FUN_08051b54(&DAT_0805ab91,local_8[2]);
      fprintf(DAT_080603a0,": name %.*s: ",(int)(char)local_8[5],(char *)((int)local_8 + 0x15));
      FUN_08051af0(local_8,local_8[1]);
      uVar3 = FUN_0804c9cc(local_8[3]);
      switch(uVar3) {
      case 1:
        fprintf(DAT_080603a0,": extern");
      case 2:
        if (uVar3 == 2) {
          fprintf(DAT_080603a0,": static");
        }
        FUN_08051bac(&DAT_0805abb5,local_8 + 4,0);
        fprintf(DAT_080603a0,"\n");
        goto LAB_0805330d;
      case 4:
        fprintf(DAT_080603a0,": register ");
        puVar7 = (uint *)FUN_0804c9cc(local_8[4]);
        if ((int)puVar7 < 0x18) {
          if ((int)puVar7 < 0x10) {
            pcVar13 = "R%ld\n";
          }
          else {
            puVar7 = puVar7 + -4;
            pcVar13 = "F%ld\n";
          }
          goto LAB_080528d5;
        }
        fprintf(DAT_080603a0,"*** ? register %ld at offset %#lx\n",(long)puVar7,(ulong)local_8);
        goto LAB_0805330d;
      case 5:
        fprintf(DAT_080603a0,": Argument by reference (Pascal VAR argument) ");
      case 3:
        if (uVar3 == 3) {
          fprintf(DAT_080603a0,": auto");
        }
        puVar7 = (uint *)FUN_0804c9cc(local_8[4]);
        pcVar13 = "FP offset %ld\n";
        break;
      case 7:
        fprintf(DAT_080603a0,": Fortran character argument");
      case 6:
        if (uVar3 == 6) {
          fprintf(DAT_080603a0,": Fortran argument");
        }
        puVar7 = (uint *)FUN_0804c9cc(local_8[4]);
        pcVar13 = " Argument list offset %ld\n";
        break;
      default:
        fprintf(DAT_080603a0,": *** ? storage class %ld at offset %#lx",uVar3,(ulong)local_8);
        uVar3 = FUN_0804c9cc(local_8[4]);
        fprintf(DAT_080603a0,"Offset / address = 0x%.6lx\n",uVar3);
        goto LAB_0805330d;
      }
      break;
    case (uint *)0x5:
      FUN_08051a00((int)local_8);
      fprintf(DAT_080603a0,"Type %.*s ",(int)(char)local_8[2],(char *)((int)local_8 + 9));
      FUN_08051af0(local_8,local_8[1]);
      fprintf(DAT_080603a0,"\n");
      goto LAB_0805330d;
    case (uint *)0x6:
    case (uint *)0x13:
    case (uint *)0x14:
      puVar11 = local_8 + 3;
      uVar3 = FUN_0804c9cc(local_8[1]);
      pcVar13 = "*** Unknown Type ***";
      FUN_08051a00((int)local_8);
      if (puVar7 == (uint *)0x13) {
        pcVar13 = "Class";
      }
      else if (puVar7 < (uint *)0x14) {
        if (puVar7 == (uint *)0x6) {
          pcVar13 = "Struct";
        }
      }
      else if (puVar7 == (uint *)0x14) {
        pcVar13 = "Union";
      }
      uVar4 = FUN_0804c9cc(local_8[2]);
      fprintf(DAT_080603a0,"%s: %ld fields, size 0x%lx\n",pcVar13,uVar3,uVar4);
      iVar8 = 0;
      if (0 < (int)uVar3) {
        do {
          uVar4 = puVar11[2];
          FUN_08051a00((int)puVar11);
          pcVar13 = (char *)((int)puVar11 + 9);
          uVar5 = (int)(char)uVar4;
          uVar9 = FUN_0804c9cc(*puVar11);
          fprintf(DAT_080603a0,"    field %ld offset 0x%lx: name %.*s: ",iVar8,uVar9,uVar5,pcVar13);
          FUN_08051af0(local_8,puVar11[1]);
          fprintf(DAT_080603a0,"\n");
          puVar11 = (uint *)((int)puVar11 + ((int)(char)uVar4 & 0xfffffffcU) + 0xc);
          iVar8 = iVar8 + 1;
        } while (iVar8 < (int)uVar3);
      }
      goto LAB_08052822;
    case (uint *)0x7:
      puVar7 = (uint *)FUN_0804c9cc(local_8[2]);
      FUN_08051a00((int)local_8);
      uVar3 = FUN_0804c9cc(local_8[1]);
      fprintf(DAT_080603a0,"Array: element size = %ld: ",uVar3);
      FUN_08051af0(local_8,local_8[3]);
      if (((((uint)puVar7 & 0xffffffc0) == 0) &&
          (bVar12 = FUN_08051cb4((uint)puVar7 & 0x13), CONCAT31(extraout_var,bVar12) == 0)) &&
         (bVar12 = FUN_08051cb4((uint)puVar7 & 0x2c), CONCAT31(extraout_var_00,bVar12) == 0)) {
        fprintf(DAT_080603a0," [");
        if (((uint)puVar7 & 2) == 0) {
          fprintf(DAT_080603a0,"?");
        }
        else {
          uVar3 = FUN_0804c9cc(local_8[4]);
          fprintf(DAT_080603a0,"%ld",uVar3);
        }
        if (((uint)puVar7 & 8) == 0) {
          fprintf(DAT_080603a0,"..?]\n");
        }
        else {
          uVar3 = FUN_0804c9cc(local_8[5]);
          fprintf(DAT_080603a0,"..%ld]\n",uVar3);
        }
        if (((uint)puVar7 & 3) == 0) {
          if (((uint)puVar7 & 0x10) == 0) {
            uVar3 = FUN_0804c9cc(local_8[4]);
            pcVar13 = "          %sVariable lower bound: FP offset %ld\n";
          }
          else {
            uVar3 = FUN_0804c9cc(local_8[4]);
            pcVar13 = "          %sVariable lower bound: var %ld\n";
          }
          fprintf(DAT_080603a0,pcVar13,&DAT_080603a4,uVar3);
        }
        if (((uint)puVar7 & 0xc) == 0) {
          if (((uint)puVar7 & 0x20) == 0) {
            uVar3 = FUN_0804c9cc(local_8[5]);
            pcVar13 = "          %sVariable upper bound: FP offset %ld\n";
          }
          else {
            uVar3 = FUN_0804c9cc(local_8[5]);
            pcVar13 = "          %sVariable upper bound: var %ld\n";
          }
          fprintf(DAT_080603a0,pcVar13,&DAT_080603a4,uVar3);
        }
      }
      else {
        pcVar13 = " *** ? flags 0x%lx\n";
LAB_080528d5:
        fprintf(DAT_080603a0,pcVar13,puVar7);
      }
      goto LAB_0805330d;
    case (uint *)0x8:
      uVar3 = FUN_0804c9cc(local_8[1]);
      uVar3 = uVar3 & 0xffff;
      FUN_08051a00((int)local_8);
      fprintf(DAT_080603a0,"Subrange\n");
      FUN_08051a00((int)(local_8 + 1));
      fprintf(DAT_080603a0,"Byte size = %ld",uVar3);
      if ((1 < uVar3 - 1) && (uVar3 != 4)) {
        fprintf(DAT_080603a0,"    *** Format error at offset %#lx: Illegal byte size\n",
                (ulong)local_8);
      }
      fprintf(DAT_080603a0,"    Type = ");
      uVar3 = FUN_0804c9cc(local_8[1]);
      FUN_08051a28(local_8,(int)uVar3 >> 0x10);
      fprintf(DAT_080603a0,"\n");
      FUN_08051a00((int)(local_8 + 2));
      uVar3 = FUN_0804c9cc(local_8[2]);
      fprintf(DAT_080603a0,"    Lowerbound = %ld\n",uVar3);
      FUN_08051a00((int)(local_8 + 3));
      uVar3 = FUN_0804c9cc(local_8[3]);
      fprintf(DAT_080603a0,"    Upperbound = %ld\n",uVar3);
      goto LAB_0805330d;
    case (uint *)0x9:
      FUN_08051a00((int)local_8);
      uVar3 = FUN_0804c9cc(local_8[1]);
      fprintf(DAT_080603a0,"Set: size %ld\n",uVar3);
      goto LAB_0805330d;
    case (uint *)0xa:
      FUN_08051a00((int)local_8);
      uVar3 = FUN_0804c9cc(*local_8);
      fprintf(DAT_080603a0,"File Info: length %ld\n",(int)uVar3 >> 0x10);
      local_8 = local_8 + 1;
      do {
        bVar1 = *(byte *)((int)param_2 + 7);
        FUN_08051a00((int)local_8);
        uVar3 = FUN_0804c9cc(*local_8);
        fprintf(DAT_080603a0,"Entry length = %ld",uVar3);
        if (*local_8 == 0) {
          fprintf(DAT_080603a0," => end of file info\n");
          return puVar6;
        }
        fprintf(DAT_080603a0,": \"%.*s\" ",(int)(char)local_8[2],(char *)((int)local_8 + 9));
        uVar3 = FUN_0804c9cc(local_8[1]);
        fprintf(DAT_080603a0,"date 0x%.8lx ",uVar3);
        iVar8 = (int)(char)((byte)local_8[2] & 0xfc);
        puVar7 = (uint *)((int)local_8 + iVar8 + 0x10);
        uVar3 = FUN_0804c9cc(*(uint *)((int)local_8 + iVar8 + 0xc));
        fprintf(DAT_080603a0,"%ld fragments\n",uVar3);
        FUN_08051c64();
        for (local_38 = 0; local_38 < (int)uVar3; local_38 = local_38 + 1) {
          local_44 = puVar7 + 5;
          uVar4 = FUN_0804c9cc(*puVar7);
          puVar11 = (uint *)(uVar4 + (int)puVar7);
          local_4c = FUN_0804c9cc(puVar7[3]);
          local_50 = FUN_0804c9cc(puVar7[1]);
          local_54 = 1;
          local_58 = 1;
          FUN_08051a00((int)puVar7);
          uVar4 = FUN_0804c9cc(puVar7[2]);
          uVar5 = FUN_0804c9cc(puVar7[1]);
          uVar9 = FUN_0804c9cc(*puVar7);
          fprintf(DAT_080603a0,"Fragment %ld (size %ld): lines %ld to %ld\n",local_38,uVar9,uVar5,
                  uVar4);
          FUN_08051a00((int)(puVar7 + 3));
          FUN_08051bac("Code address",puVar7 + 3,0);
          uVar4 = FUN_0804c9cc(puVar7[4]);
          fprintf(DAT_080603a0,", size 0x%lx\n",uVar4);
          FUN_08051c64();
          if (local_44 < puVar11) {
            local_70 = (ushort *)((int)puVar7 + 0x1a);
            puVar7 = puVar7 + 6;
            do {
              FUN_08051a00((int)local_44);
              if (local_54 == 1) {
                if (local_58 != 1) {
                  pcVar13 = "0x%.6lx line %ld  :%-2ld";
                  uVar4 = local_58;
                  goto LAB_08052fba;
                }
                fprintf(DAT_080603a0,"0x%.6lx line %ld     ",local_4c,local_50);
              }
              else if (local_58 == 1) {
                pcVar13 = "0x%.6lx line %ld/%1ld   ";
                uVar4 = local_54;
LAB_08052fba:
                fprintf(DAT_080603a0,pcVar13,local_4c,local_50,uVar4);
              }
              else {
                fprintf(DAT_080603a0,"0x%.6lx line %ld/%1ld:%-2ld",local_4c,local_50,local_54,
                        local_58);
              }
              uVar5 = (uint)(byte)*local_44;
              uVar4 = (uint)*(byte *)((int)puVar7 + -3);
              if ((uVar5 == 0) && (uVar4 == 0)) {
                uVar4 = FUN_0804ca04((uint)*(ushort *)((int)puVar7 + -2));
                uVar5 = FUN_0804ca04((uint)(ushort)*puVar7);
                local_58 = 1;
                fprintf(DAT_080603a0,"  (L 0x%lx %ld)\n",uVar5,uVar4);
                puVar7 = (uint *)((int)puVar7 + 6);
                local_70 = local_70 + 3;
                local_44 = (uint *)((int)local_44 + 6);
              }
              else {
                if (bVar1 < 3) {
LAB_080530c0:
                  local_58 = 1;
                  fprintf(DAT_080603a0,"  (S 0x%lx %ld)\n",uVar5,uVar4);
                }
                else {
                  if ((uVar5 == 0) && (uVar4 == 0x40)) {
                    uVar4 = FUN_0804ca04((uint)*(ushort *)((int)puVar7 + -2));
                    uVar5 = FUN_0804ca04((uint)(ushort)*puVar7);
                    local_58 = FUN_0804ca04((uint)*local_70);
                    fprintf(DAT_080603a0,"  (L2 0x%lx %ld %ld)\n",uVar5,uVar4,local_58);
                    puVar7 = puVar7 + 2;
                    local_70 = local_70 + 4;
                    local_44 = local_44 + 2;
                    goto LAB_080530e7;
                  }
                  if ((bVar1 < 3) || (uVar4 < 0x40)) goto LAB_080530c0;
                  local_58 = local_58 + (uVar4 - 0x40);
                  fprintf(DAT_080603a0,"  (S 0x%lx :%ld)\n",uVar5,uVar4 - 0x40);
                  uVar4 = 0;
                }
                puVar7 = (uint *)((int)puVar7 + 2);
                local_70 = local_70 + 1;
                local_44 = (uint *)((int)local_44 + 2);
              }
LAB_080530e7:
              if (uVar4 == 0) {
                local_54 = local_54 + 1;
              }
              else {
                local_54 = 1;
              }
              local_50 = local_50 + uVar4;
              local_4c = local_4c + uVar5;
            } while (local_44 < puVar11);
          }
          FUN_08051c98();
          puVar7 = (uint *)((uint)((int)puVar11 + 3) & 0xfffffffc);
        }
        FUN_08051c98();
        uVar3 = FUN_0804c9cc(*local_8);
        local_8 = (uint *)((int)local_8 + uVar3);
      } while( true );
    case (uint *)0xb:
      puVar11 = local_8 + 4;
      uVar3 = FUN_0804c9cc(local_8[2]);
      FUN_08051a00((int)local_8);
      fprintf(DAT_080603a0,"EnumC: ");
      FUN_08051af0(local_8,local_8[1]);
      fprintf(DAT_080603a0," %ld members\n",uVar3);
      if (0 < (int)uVar3) {
        iVar8 = 0;
        do {
          uVar4 = *puVar11;
          FUN_08051a00((int)puVar11);
          pcVar13 = (char *)((int)puVar11 + 1);
          param3 = (int)(char)uVar4;
          uVar5 = FUN_0804c9cc(local_8[3]);
          fprintf(DAT_080603a0,"    value 0x%lx: name %.*s\n",uVar5 + iVar8,param3,pcVar13);
          puVar11 = (uint *)((int)puVar11 + ((int)(char)uVar4 + 4U & 0xfffffffc));
          iVar8 = iVar8 + 1;
        } while (iVar8 < (int)uVar3);
      }
LAB_08052822:
      if ((uint *)((int)local_8 + local_14) < puVar11) {
LAB_08052836:
        fprintf(DAT_080603a0,
                "*** Format Error at offset %#lx: item longer than described by length field (%#lx vs %#lx)\n"
                ,(ulong)local_8,(int)puVar11 - (int)local_8,local_14);
        local_14 = (int)puVar11 - (int)local_8;
      }
      goto LAB_0805330d;
    case (uint *)0xc:
      puVar11 = local_8 + 3;
      uVar3 = FUN_0804c9cc(local_8[2]);
      FUN_08051a00((int)local_8);
      fprintf(DAT_080603a0,"EnumD: ");
      FUN_08051af0(local_8,local_8[1]);
      fprintf(DAT_080603a0," %ld members\n",uVar3);
      iVar8 = 0;
      if (0 < (int)uVar3) {
        do {
          uVar4 = puVar11[1];
          FUN_08051a00((int)puVar11);
          pcVar13 = (char *)((int)puVar11 + 5);
          uVar5 = (int)(char)uVar4;
          uVar9 = FUN_0804c9cc(*puVar11);
          fprintf(DAT_080603a0,"    value 0x%lx: name %.*s\n",uVar9,uVar5,pcVar13);
          puVar11 = (uint *)((int)puVar11 + ((int)(char)uVar4 & 0xfffffffcU) + 8);
          iVar8 = iVar8 + 1;
        } while (iVar8 < (int)uVar3);
      }
      if ((uint *)((int)local_8 + local_14) < puVar11) goto LAB_08052836;
      goto LAB_0805330d;
    default:
      FUN_08051a00((int)local_8);
      pcVar13 = "*** ? debugging item %ld\n";
      break;
    case (uint *)0xe:
      FUN_08051a00((int)local_8);
      FUN_08051bac("Begin scope at",local_8 + 1,0);
      fprintf(DAT_080603a0,"\n");
      local_18 = local_18 + 1;
      goto LAB_0805330d;
    case (uint *)0xf:
      FUN_08051a00((int)local_8);
      FUN_08051bac("End scope at",local_8 + 1,0);
      fprintf(DAT_080603a0,"\n");
      local_18 = local_18 + -1;
      goto LAB_0805330d;
    case (uint *)0x10:
      FUN_08051a00((int)local_8);
      fprintf(DAT_080603a0,"Bitfield: ");
      FUN_08051af0(local_8,local_8[1]);
      fprintf(DAT_080603a0," container: ");
      FUN_08051af0(local_8,local_8[2]);
      fprintf(DAT_080603a0," offset %ld size %ld\n",(uint)*(byte *)((int)local_8 + 0xd),
              (uint)(byte)local_8[3]);
      goto LAB_0805330d;
    case (uint *)0x11:
      FUN_08051a00((int)local_8);
      pcVar13 = (char *)((int)local_8 + 0x19);
      iVar8 = (int)(char)local_8[6];
      uVar3 = FUN_0804c9cc(local_8[2]);
      uVar4 = FUN_0804c9cc(local_8[1]);
      fprintf(DAT_080603a0,"File 0x%.6lx line %ld #define %.*s",uVar4,uVar3,iVar8,pcVar13);
      uVar3 = FUN_0804c9cc(local_8[4]);
      if (uVar3 != 0xffffffff) {
        local_34 = "";
        fprintf(DAT_080603a0,"(");
        uVar4 = FUN_0804c9cc(local_8[5]);
        pcVar13 = (char *)((int)param_2 + uVar4);
        while (uVar3 = uVar3 - 1, -1 < (int)uVar3) {
          cVar2 = *pcVar13;
          fprintf(DAT_080603a0,"%s%.*s",local_34,(int)cVar2,pcVar13 + 1);
          local_34 = ", ";
          pcVar13 = pcVar13 + ((int)cVar2 + 4U & 0xfffffffc);
        }
        fprintf(DAT_080603a0,")");
      }
      fprintf(DAT_080603a0,"\n");
      uVar3 = FUN_0804c9cc(local_8[3]);
      pcVar13 = (char *)((int)param_2 + uVar3);
      uVar3 = 0xffffffff;
      pcVar10 = pcVar13;
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar2 = *pcVar10;
        pcVar10 = pcVar10 + 1;
      } while (cVar2 != '\0');
      for (iVar8 = ~uVar3 - 1; 0 < iVar8; iVar8 = iVar8 + -0x46) {
        FUN_08051a00((int)pcVar13);
        if (iVar8 < 0x47) {
          fprintf(DAT_080603a0,"  %s\n",pcVar13);
        }
        else {
          fprintf(DAT_080603a0,"  %.70s\\\n",pcVar13);
          pcVar13 = pcVar13 + 0x46;
        }
      }
      goto LAB_0805330d;
    case (uint *)0x12:
      FUN_08051a00((int)local_8);
      pcVar13 = (char *)((int)local_8 + 0xd);
      iVar8 = (int)(char)local_8[3];
      uVar3 = FUN_0804c9cc(local_8[2]);
      uVar4 = FUN_0804c9cc(local_8[1]);
      fprintf(DAT_080603a0,"File 0x%.6lx line %ld #undef %.*s\n",uVar4,uVar3,iVar8,pcVar13);
      goto LAB_0805330d;
    case (uint *)0x20:
      goto switchD_0805217a_caseD_20;
    }
    fprintf(DAT_080603a0,pcVar13,puVar7);
    goto LAB_0805330d;
  }
  pcVar13 = "*** Item length = 0 at offset %#lx\n";
  param_2 = local_8;
LAB_08053320:
  fprintf(DAT_080603a0,pcVar13,param_2);
  return puVar6;
switchD_0805217a_caseD_20:
  uVar3 = FUN_0804c9cc(local_8[1]);
  local_5c = FUN_0804c9cc(local_8[5]);
  local_60 = FUN_0804c9cc(local_8[2]);
  FUN_08051a00((int)local_8);
  fprintf(DAT_080603a0,"fp map fragment: length %ld,",uVar3);
  FUN_08051bac(" base",local_8 + 2,0);
  uVar4 = FUN_0804c9cc(local_8[4]);
  fprintf(DAT_080603a0," size 0x%lx",uVar4);
  FUN_08051bac(" save",local_8 + 3,1);
  fprintf(DAT_080603a0,"\n");
  puVar11 = local_8 + 6;
  puVar7 = (uint *)(uVar3 + (int)puVar11);
  FUN_08051c64();
  if (puVar11 < puVar7) {
    local_6c = local_8 + 7;
    do {
      FUN_08051a00((int)puVar11);
      fprintf(DAT_080603a0,"0x%.6lx offset %ld",local_60,local_5c);
      uVar3 = (uint)(byte)*puVar11;
      uVar4 = (uint)*(char *)((int)local_6c + -3);
      if ((uVar3 == 0) && (uVar4 == 0)) {
        uVar3 = FUN_0804ca04((uint)*(ushort *)((int)local_6c + -2));
        uVar4 = FUN_0804ca04((int)(short)*local_6c);
        fprintf(DAT_080603a0,"  (L 0x%lx %ld)\n",uVar3,uVar4);
        local_6c = (uint *)((int)local_6c + 6);
        puVar11 = (uint *)((int)puVar11 + 6);
      }
      else {
        fprintf(DAT_080603a0,"  (S 0x%lx %ld)\n",uVar3,uVar4);
        local_6c = (uint *)((int)local_6c + 2);
        puVar11 = (uint *)((int)puVar11 + 2);
      }
      local_5c = local_5c + uVar4;
      local_60 = local_60 + uVar3;
    } while (puVar11 < puVar7);
  }
  FUN_08051c98();
  goto LAB_0805330d;
}



void FUN_08053340(uint *param_1)

{
  FUN_0804c9cc(*param_1);
  return;
}



uint FUN_08053370(short *param_1)

{
  uint uVar1;
  
  uVar1 = FUN_0804ca04((int)*param_1);
  return uVar1 & 0xffff;
}



void FUN_08053398(ulong param_1,int param_2)

{
  if (DAT_08060618 == 0) {
    if (DAT_08060614 == 0) {
      fprintf(DAT_08060620,"0x%08lx:%*s",param_1,param_2 * 2 + 2,"");
    }
    else {
      fprintf(DAT_08060620,"0x%08lx:%-2d%*s",param_1,DAT_08060610,param_2 * 2,"");
    }
  }
  else {
    fprintf(DAT_08060620,"%*s",param_2 * 2 + 0xd,"");
  }
  return;
}



int FUN_08053420(int param_1,int param_2,int param_3)

{
  byte param2;
  int iVar1;
  byte *pbVar2;
  int iVar3;
  int iVar4;
  int local_10;
  int local_c;
  byte local_5;
  
  local_c = 0;
  if (param_2 != 0) {
LAB_0805344a:
    do {
      FUN_08053398(param_3 + local_c,3);
      local_10 = 0;
      pbVar2 = (byte *)(param_1 + local_c);
      iVar3 = local_c;
      do {
        while( true ) {
          local_5 = *pbVar2;
          fprintf(DAT_08060620,"%.2x ",(uint)local_5);
          iVar3 = iVar3 + 1;
          pbVar2 = pbVar2 + 1;
          local_10 = local_10 + 1;
          if (0xb < local_10) goto LAB_080534ad;
          if (param_2 < 1) break;
          if (param_2 <= iVar3) goto LAB_080534ad;
        }
      } while (local_5 != 0);
LAB_080534ad:
      fprintf(DAT_08060620,"%*s   ",(0xc - local_10) * 3,"");
      iVar4 = 0;
      iVar3 = local_c + local_10;
      if (0 < local_10) {
        pbVar2 = (byte *)(param_1 + local_c);
        do {
          local_5 = *pbVar2;
          if ((0 < param_2) || (local_5 != 0)) {
            iVar1 = isprint((uint)local_5);
            param2 = local_5;
            if (iVar1 == 0) {
              param2 = 0x2e;
            }
            fprintf(DAT_08060620,"%c",param2);
          }
          pbVar2 = pbVar2 + 1;
          iVar4 = iVar4 + 1;
        } while (iVar4 < local_10);
      }
      fprintf(DAT_08060620,"\n");
      local_c = iVar3;
      if (0 < param_2) {
        if (param_2 <= iVar3) break;
        goto LAB_0805344a;
      }
    } while (local_5 != 0);
    if (param_2 < 0) {
      return iVar3;
    }
  }
  return param_2;
}



undefined * FUN_0805357c(uint param_1,int param_2)

{
  char cVar1;
  undefined *puVar2;
  uint *puVar3;
  int iVar4;
  undefined4 uVar5;
  uint *puVar6;
  uint uVar7;
  uint *puVar8;
  uint uVar9;
  uint *local_c;
  
  if (DAT_0805f030 == 0) {
    puVar2 = (undefined *)0x0;
  }
  else if (DAT_0805f034 < param_1) {
    FUN_08053398(param_1,param_2);
    fprintf(DAT_08060620,"*** Illegal offset into \'.debug\' section\n");
    puVar2 = (undefined *)0x0;
  }
  else {
    puVar3 = (uint *)(DAT_0805f030 + param_1);
    uVar7 = 0;
    iVar4 = 0;
    do {
      *(undefined4 *)((int)&DAT_080603c8 + iVar4) = 0;
      iVar4 = iVar4 + 0xc;
      uVar7 = uVar7 + 1;
    } while (uVar7 < 0x31);
    iVar4 = FUN_08053340(puVar3);
    FUN_08053370((short *)(puVar3 + 1));
    local_c = (uint *)(iVar4 + (int)puVar3);
    if ((uint *)(DAT_0805f034 + DAT_0805f030) < (uint *)(iVar4 + (int)puVar3)) {
      local_c = (uint *)(DAT_0805f034 + DAT_0805f030);
    }
    puVar8 = (uint *)((int)puVar3 + 6);
    while (puVar6 = puVar8, puVar6 < local_c) {
      uVar7 = FUN_08053370((short *)puVar6);
      uVar9 = (uVar7 & 0xffff) >> 4;
      puVar8 = (uint *)((int)puVar6 + 2);
      if ((uVar9 < 0x31) && (*(&PTR_DAT_0805ee80)[uVar9] != '\0')) {
        (&DAT_080603c8)[uVar9 * 3] = (int)puVar8 + (param_1 - (int)puVar3);
        *(uint *)(&DAT_080603c4 + uVar9 * 0xc) = uVar7 & 0xf;
        switch(uVar7 & 0xf) {
        case 1:
        case 2:
        case 6:
          *(undefined4 *)(&DAT_080603c0 + uVar9 * 0xc) = 4;
          break;
        case 3:
          uVar7 = FUN_08053370((short *)puVar8);
          *(uint *)(&DAT_080603c0 + uVar9 * 0xc) = uVar7 & 0xffff;
          (&DAT_080603c8)[uVar9 * 3] = (&DAT_080603c8)[uVar9 * 3] + 2;
          puVar8 = puVar6 + 1;
          break;
        case 4:
          uVar5 = FUN_08053340(puVar8);
          *(undefined4 *)(&DAT_080603c0 + uVar9 * 0xc) = uVar5;
          (&DAT_080603c8)[uVar9 * 3] = (&DAT_080603c8)[uVar9 * 3] + 4;
          puVar8 = (uint *)((int)puVar6 + 6);
          break;
        case 5:
          *(undefined4 *)(&DAT_080603c0 + uVar9 * 0xc) = 2;
          break;
        default:
          goto switchD_08053679_caseD_7;
        case 8:
          iVar4 = 0;
          cVar1 = *(char *)puVar8;
          puVar6 = puVar8;
          while ((cVar1 != '\0' && (puVar6 < local_c))) {
            puVar6 = (uint *)((int)puVar6 + 1);
            iVar4 = iVar4 + 1;
            cVar1 = *(char *)puVar6;
          }
          *(int *)(&DAT_080603c0 + uVar9 * 0xc) = iVar4 + 1;
        }
        puVar8 = (uint *)((int)puVar8 + *(int *)(&DAT_080603c0 + uVar9 * 0xc));
      }
    }
switchD_08053679_caseD_7:
    puVar2 = &DAT_080603c0;
  }
  return puVar2;
}



bool FUN_08053744(char *param_1,int param_2,int param_3,int param_4)

{
  uchar *puVar1;
  uchar param2;
  int iVar2;
  int iVar3;
  uchar *puVar4;
  int iVar5;
  bool bVar6;
  
  iVar5 = 0;
  if (DAT_0805f030 == 0) {
    bVar6 = false;
  }
  else {
    FUN_08053398(param_2,param_4);
    iVar2 = fprintf(DAT_08060620,param_1);
    fprintf(DAT_08060620,": ");
    puVar4 = (uchar *)(param_2 + DAT_0805f030);
    puVar1 = puVar4 + param_3 + -1;
    for (; puVar4 < puVar1; puVar4 = puVar4 + 1) {
      iVar5 = iVar5 + 1;
      if (iVar5 == 0x29) {
        fprintf(DAT_08060620,"\n");
        FUN_08053398((int)puVar4 - DAT_0805f030,iVar2 / 2 + 1 + param_4);
        iVar5 = 0;
      }
      iVar3 = isprint((int)(char)*puVar4);
      if (iVar3 == 0) {
        param2 = '.';
      }
      else {
        param2 = *puVar4;
      }
      fprintf(DAT_08060620,"%c",param2);
    }
    fprintf(DAT_08060620,"\n");
    bVar6 = puVar4 < puVar1;
  }
  return bVar6;
}



undefined * FUN_08053834(uint param_1,uint param_2,int param_3)

{
  undefined *puVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  char *__format;
  char *pcVar6;
  int local_c;
  
  puVar1 = FUN_0805357c(param_1,param_3);
  if (puVar1 == (undefined *)0x0) {
    puVar1 = (undefined *)0x0;
  }
  else {
    puVar5 = (uint *)(param_1 + DAT_0805f030);
    uVar2 = FUN_08053340(puVar5);
    uVar3 = FUN_08053370((short *)(puVar5 + 1));
    FUN_08053398(param_1,param_3);
    if (((ushort)uVar3 < 0x23) &&
       (pcVar6 = (&PTR_s_TAG_padding_0805edf4)[uVar3 & 0xffff], *pcVar6 != '\0')) {
      iVar4 = param_3 * -2 + 0x1a;
      __format = "%-*s (%ld bytes)\n";
    }
    else {
      pcVar6 = "";
      iVar4 = fprintf(DAT_08060620,"unknown tag (0x%x)",uVar3 & 0xffff);
      iVar4 = (0x1a - iVar4) + param_3 * -2;
      __format = "%*s (%ld bytes)\n";
    }
    fprintf(DAT_08060620,__format,iVar4,pcVar6,uVar2);
    if ((((param_2 & 1) != 0) && (*(int *)(puVar1 + 0x2c) != 0)) &&
       ((1 << ((byte)*(undefined4 *)(puVar1 + 0x28) & 0xf) & 0x100U) != 0)) {
      FUN_08053744("Name",*(int *)(puVar1 + 0x2c),*(int *)(puVar1 + 0x24),param_3 + 1);
    }
    if ((((param_2 & 2) != 0) && (*(int *)(puVar1 + 0x1c4) != 0)) &&
       ((1 << ((byte)*(undefined4 *)(puVar1 + 0x1c0) & 0xf) & 0x100U) != 0)) {
      FUN_08053744("Producer",*(int *)(puVar1 + 0x1c4),*(int *)(puVar1 + 0x1bc),param_3 + 1);
    }
    if (((param_2 & 4) != 0) &&
       ((((local_c = 5, *(int *)(puVar1 + 0x44) != 0 &&
          ((1 << ((byte)*(undefined4 *)(puVar1 + 0x40) & 0xf) & 0x20U) != 0)) ||
         (((local_c = 6, *(int *)(puVar1 + 0x50) != 0 &&
           ((1 << ((byte)*(undefined4 *)(puVar1 + 0x4c) & 0xf) & 8U) != 0)) ||
          ((local_c = 7, *(int *)(puVar1 + 0x5c) != 0 &&
           ((1 << ((byte)*(undefined4 *)(puVar1 + 0x58) & 0xf) & 4U) != 0)))))) ||
        ((local_c = 8, *(int *)(puVar1 + 0x68) != 0 &&
         ((1 << ((byte)*(undefined4 *)(puVar1 + 100) & 0xf) & 8U) != 0)))))) {
      iVar4 = local_c * 0xc;
      FUN_08053398(*(undefined4 *)(puVar1 + iVar4 + 8),param_3 + 1);
      fprintf(DAT_08060620,"Type: ");
      FUN_08054140((uint *)(*(int *)(puVar1 + iVar4 + 8) + DAT_0805f030),*(uint *)(puVar1 + iVar4),
                   *(undefined4 *)(puVar1 + iVar4 + 8),local_c,param_3);
    }
  }
  return puVar1;
}



undefined4 FUN_08053a74(uint *param_1,int param_2,uint param_3,int param_4)

{
  uint uVar1;
  uint uVar2;
  ulong param3;
  uint param2;
  undefined4 local_c;
  
  uVar1 = param_3 + param_2;
  local_c = 0;
  while (param_3 < uVar1) {
    uVar2 = *param_1;
    FUN_08053398(param_3,param_4);
    param2 = (uint)(byte)uVar2;
    if ((param2 < 5) && (param2 != 0)) {
      param3 = FUN_08053340((uint *)((int)param_1 + 1));
      fprintf(DAT_08060620,"%s(0x%lx)\n",(&PTR_DAT_0805ef68)[param2],param3);
      param_3 = param_3 + 5;
      param_1 = (uint *)((int)param_1 + 5);
    }
    else {
      if (((byte)uVar2 < 8) && (*(&PTR_DAT_0805ef68)[param2] != '\0')) {
        fprintf(DAT_08060620,"%s\n",(&PTR_DAT_0805ef68)[param2]);
      }
      else {
        fprintf(DAT_08060620,"unknown OP (%d)",param2);
        local_c = 1;
      }
      param_3 = param_3 + 1;
      param_1 = (uint *)((int)param_1 + 1);
    }
  }
  return local_c;
}



bool FUN_08053b3c(uint *param_1,int param_2,uint param_3,int param_4)

{
  uint uVar1;
  uchar param2;
  ulong param2_00;
  int iVar2;
  int iVar3;
  uint *local_c;
  
  uVar1 = param_3 + param_2;
  while (param_3 < uVar1) {
    param2_00 = FUN_08053340(param_1);
    iVar3 = 0;
    FUN_08053398(param_3,param_4);
    fprintf(DAT_08060620,"0x%.4lx: ",param2_00);
    param_3 = param_3 + 4;
    local_c = param_1 + 1;
    while( true ) {
      param2 = (uchar)*local_c;
      local_c = (uint *)((int)local_c + 1);
      param_3 = param_3 + 1;
      if (param2 == '\0') break;
      iVar3 = iVar3 + 1;
      if (iVar3 == 0x29) {
        fprintf(DAT_08060620,"\n");
        FUN_08053398(param_3,param_4 + 3);
        iVar3 = 0;
      }
      iVar2 = isprint((int)(char)param2);
      if (iVar2 == 0) {
        param2 = '.';
      }
      fprintf(DAT_08060620,"%c",param2);
    }
    fprintf(DAT_08060620,"\n");
    param_1 = local_c;
  }
  if (uVar1 < param_3) {
    FUN_08053398(param_3,param_4 + -1);
    fprintf(DAT_08060620,"*** Overruns\n");
  }
  return uVar1 < param_3;
}



bool FUN_08053c50(uint *param_1,int param_2,uint param_3,int param_4)

{
  uint uVar1;
  uint *puVar2;
  long lVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  ushort uVar7;
  uint uVar8;
  int iVar9;
  char *pcVar10;
  char *__format;
  int local_24;
  uint local_18;
  ushort local_14;
  byte local_d;
  uint *local_c;
  
  uVar1 = param_3 + param_2;
  local_c = param_1;
  local_d = 0;
switchD_08053c95_default:
  if (uVar1 <= param_3) {
LAB_080540e6:
    if (uVar1 < param_3) {
      FUN_08053398(param_3,param_4 + -1);
      fprintf(DAT_08060620,"*** Overruns\n");
    }
    if (local_d != 8) {
      FUN_08053398(param_3,param_4 + -1);
      fprintf(DAT_08060620,"*** Last subscript-data elememt not type-specifier\n");
    }
    return local_d != 8 || uVar1 < param_3;
  }
  FUN_08053398(param_3,param_4);
  local_d = (byte)*local_c;
  switch(local_d) {
  case 0:
  case 1:
  case 2:
  case 3:
    uVar4 = FUN_08053370((short *)((int)local_c + 1));
    fprintf(DAT_08060620,"Index: Fundamental type: ");
    if (((ushort)uVar4 < 0x18) && (pcVar10 = (&PTR_DAT_0805ef9c)[uVar4 & 0xffff], *pcVar10 != '\0'))
    {
      __format = "%s\n";
    }
    else {
      pcVar10 = (char *)(uVar4 & 0xffff);
      __format = "unknown FT (%d)\n";
    }
    fprintf(DAT_08060620,__format,pcVar10);
    iVar9 = param_3 + 3;
    local_c = (uint *)((int)local_c + 3);
    break;
  case 4:
  case 5:
  case 6:
  case 7:
    lVar3 = FUN_08053340((uint *)((int)local_c + 1));
    fprintf(DAT_08060620,"Index: User type ref: %ld\n",lVar3);
    iVar9 = param_3 + 5;
    local_c = (uint *)((int)local_c + 5);
    break;
  case 8:
    uVar4 = FUN_08053370((short *)((int)local_c + 1));
    local_18 = 0;
    uVar7 = (ushort)uVar4 >> 4;
    iVar9 = param_3 + 3;
    puVar2 = (uint *)((int)local_c + 3);
    if ((uVar7 < 0x31) && (*(&PTR_DAT_0805ee80)[uVar7] != '\0')) {
      fprintf(DAT_08060620,"%-20s",(&PTR_DAT_0805ee80)[uVar7]);
    }
    else {
      pcVar10 = "";
      iVar5 = fprintf(DAT_08060620,"unknown AT (0x%x)",(uint)uVar7);
      fprintf(DAT_08060620,"%*s",0x14 - iVar5,pcVar10);
    }
    uVar8 = (uint)uVar7;
    local_14 = (ushort)(uVar4 & 0xf);
    if (((uVar7 < 0x31) && (*(&PTR_DAT_0805ee80)[uVar8] != '\0')) &&
       ((8 < local_14 ||
        ((*(&PTR_DAT_0805ef44)[uVar4 & 0xf] == '\0' ||
         ((*(uint *)(&DAT_0805b7c8 + uVar8 * 4) & 1 << (sbyte)(uVar4 & 0xf)) == 0)))))) {
      FUN_08053398(param_3 + 1,param_4);
      pcVar10 = "*** Unexpected form for attribute\n";
LAB_08054093:
      fprintf(DAT_08060620,pcVar10);
      local_c = puVar2;
LAB_080540a1:
      FUN_08053398(iVar9,param_4);
      fprintf(DAT_08060620,"*** Dumping remaining data in this tag\n");
      local_18 = uVar1 - iVar9;
      FUN_08053420((int)local_c,local_18,param_4);
    }
    else {
      pcVar10 = "";
      uVar4 = uVar4 & 0xf;
      iVar5 = fprintf(DAT_08060620," (%s)",(&PTR_DAT_0805ef44)[uVar4]);
      fprintf(DAT_08060620,"%*s",0x13 - iVar5,pcVar10);
      if (uVar8 == 6) {
LAB_08053fd6:
        uVar6 = FUN_08053370((short *)puVar2);
        fprintf(DAT_08060620,"(%ld bytes)",uVar6 & 0xffff);
        iVar9 = param_3 + 5;
        puVar2 = (uint *)((int)local_c + 5);
      }
      else if (uVar8 < 7) {
        if (uVar8 != 5) {
LAB_08054081:
          FUN_08053398(param_3 + 1,param_4);
          pcVar10 = "*** Bad type attribute\n";
          goto LAB_08054093;
        }
      }
      else if (uVar8 != 7) {
        if (uVar8 != 8) goto LAB_08054081;
        goto LAB_08053fd6;
      }
      local_c = puVar2;
      fprintf(DAT_08060620,"\n");
      FUN_08053398(iVar9,param_4 + 1U);
      if (uVar4 == 3) {
        local_18 = FUN_08053370((short *)((int)local_c + -2));
        local_18 = local_18 & 0xffff;
      }
      else if (uVar4 < 4) {
        if (uVar4 == 2) {
          local_18 = 4;
        }
      }
      else if (uVar4 == 5) {
        local_18 = 2;
      }
      iVar5 = FUN_08054140(local_c,local_18,iVar9,uVar8,param_4 + 1U);
      if (iVar5 != 0) goto LAB_080540a1;
    }
    param_3 = iVar9 + local_18;
    local_c = (uint *)((int)local_c + local_18);
  default:
    goto switchD_08053c95_default;
  }
  local_24 = param_4 + 1;
  FUN_08053398(iVar9,local_24);
  if (local_d < 2) {
    lVar3 = FUN_08053340(local_c);
    fprintf(DAT_08060620,"Lower bound:  %ld\n",lVar3);
    param_3 = iVar9 + 4;
    local_c = local_c + 1;
  }
  else {
    uVar4 = FUN_08053370((short *)local_c);
    if ((short)uVar4 == 0) {
      fprintf(DAT_08060620,"Lower bound: <unspecified>\n");
      uVar4 = 0;
    }
    else {
      uVar4 = uVar4 & 0xffff;
      fprintf(DAT_08060620,"Lower bound (loc): (%d bytes)\n",uVar4);
      FUN_08053420((int)local_c + 2,uVar4,iVar9 + 2);
    }
    param_3 = uVar4 + iVar9 + 2;
    local_c = (uint *)((int)local_c + uVar4 + 2);
  }
  if (uVar1 <= param_3) goto LAB_080540e6;
  FUN_08053398(param_3,local_24);
  if ((local_d == 0) || (local_d == 2)) {
    lVar3 = FUN_08053340(local_c);
    fprintf(DAT_08060620,"Higher bound: %ld\n",lVar3);
    param_3 = param_3 + 4;
    local_c = local_c + 1;
  }
  else {
    uVar4 = FUN_08053370((short *)local_c);
    if ((short)uVar4 == 0) {
      fprintf(DAT_08060620,"Higher bound: <unspecified>\n");
      uVar4 = 0;
    }
    else {
      uVar4 = uVar4 & 0xffff;
      fprintf(DAT_08060620,"Higher bound (loc): (%d bytes)\n",uVar4);
      FUN_08053420((int)local_c + 2,uVar4,param_3 + 2);
    }
    param_3 = uVar4 + param_3 + 2;
    local_c = (uint *)((int)local_c + uVar4 + 2);
  }
  goto switchD_08053c95_default;
}



undefined4 FUN_08054140(uint *param_1,uint param_2,undefined4 param_3,int param_4,uint param_5)

{
  uint uVar1;
  char *pcVar2;
  undefined4 uVar3;
  uint uVar4;
  char *pcVar5;
  
  if (param_4 - 5U < 2) {
    uVar4 = 2;
  }
  else {
    uVar4 = 4;
  }
  if ((param_4 == 6) || (param_4 == 8)) {
    for (; uVar4 < param_2; uVar4 = uVar4 + 1) {
      pcVar2 = (char *)(int)(char)*param_1;
      param_1 = (uint *)((int)param_1 + 1);
      if ((pcVar2 < (char *)0x5) && (*(&PTR_DAT_0805ef88)[(int)pcVar2] != '\0')) {
        pcVar5 = "%-s ";
        pcVar2 = (&PTR_DAT_0805ef88)[(int)pcVar2];
      }
      else {
        pcVar5 = "unknown MOD (%d) ";
      }
      fprintf(DAT_08060620,pcVar5,pcVar2);
    }
  }
  if (param_4 - 5U < 2) {
    uVar1 = FUN_08053370((short *)param_1);
    if (((ushort)uVar1 < 0x18) && (pcVar2 = (&PTR_DAT_0805ef9c)[uVar1 & 0xffff], *pcVar2 != '\0')) {
      pcVar5 = "%s\n";
    }
    else {
      pcVar2 = (char *)(uVar1 & 0xffff);
      pcVar5 = "unknown FT (%d)\n";
    }
    fprintf(DAT_08060620,pcVar5,pcVar2);
  }
  else {
    uVar1 = FUN_08053340(param_1);
    fprintf(DAT_08060620,"reference to offset 0x%06lx\n",uVar1);
    uVar3 = DAT_08060618;
    if (param_5 < 5) {
      DAT_08060618 = uVar3;
      if ((DAT_0806060f & 0x10) != 0) {
        DAT_08060618 = 1;
        FUN_08053834(uVar1,5,param_5);
        DAT_08060618 = uVar3;
      }
    }
    else {
      FUN_08053398(param_5,uVar1);
      fprintf(DAT_08060620,"...\n");
    }
  }
  if ((uVar4 == param_2) || (param_2 == 0)) {
    uVar3 = 0;
  }
  else {
    FUN_08053398(param_3,param_5 - 1);
    fprintf(DAT_08060620,"*** Block length differs from expected length\n");
    uVar3 = 1;
  }
  return uVar3;
}



bool FUN_0805429c(uint *param_1,uint param_2,int param_3,int param_4)

{
  ulong param2;
  uint uVar1;
  
  uVar1 = 0;
  if (param_2 != 0) {
    do {
      FUN_08053398(param_3,param_4);
      param2 = FUN_08053340(param_1);
      fprintf(DAT_08060620,"reference to offset 0x%06lx\n",param2);
      uVar1 = uVar1 + 4;
      param_3 = param_3 + 4;
      param_1 = param_1 + 1;
    } while (uVar1 < param_2);
  }
  if (uVar1 != param_2) {
    FUN_08053398(param_3,param_4 + -1);
    fprintf(DAT_08060620,"*** Overruns\n");
  }
  return uVar1 != param_2;
}



uint FUN_08054318(uint *param_1,int param_2)

{
  bool bVar1;
  int param3;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  uint uVar6;
  short *psVar7;
  uint *puVar8;
  char *pcVar9;
  uint local_c;
  uint local_8;
  
  local_8 = 0;
  local_c = 0;
  param3 = FUN_08053340(param_1);
  uVar2 = FUN_08053370((short *)(param_1 + 1));
  FUN_08053398(param_2,1);
  if (((ushort)uVar2 < 0x23) && (*(&PTR_s_TAG_padding_0805edf4)[uVar2 & 0xffff] != '\0')) {
    fprintf(DAT_08060620,"%-24s (%ld bytes)\n",(&PTR_s_TAG_padding_0805edf4)[uVar2 & 0xffff],param3)
    ;
  }
  else {
    pcVar9 = "";
    iVar5 = param3;
    iVar3 = fprintf(DAT_08060620,"unknown tag (0x%x)",uVar2 & 0xffff);
    fprintf(DAT_08060620,"%*s (%ld bytes)\n",0x18 - iVar3,pcVar9,iVar5);
  }
  psVar7 = (short *)((int)param_1 + 6);
  do {
    if ((short *)((int)param_1 + param3) <= psVar7) {
      return local_8;
    }
    uVar4 = FUN_08053370(psVar7);
    uVar2 = uVar4 & 0xf;
    uVar4 = (uVar4 & 0xffff) >> 4;
    FUN_08053398((int)psVar7 + (param_2 - (int)param_1),2);
    if ((uVar4 < 0x31) && (*(&PTR_DAT_0805ee80)[uVar4] != '\0')) {
      fprintf(DAT_08060620,"%-22s",(&PTR_DAT_0805ee80)[uVar4]);
    }
    else {
      pcVar9 = "";
      iVar5 = fprintf(DAT_08060620,"unknown AT (0x%x)",uVar4);
      fprintf(DAT_08060620,"%*s",0x16 - iVar5,pcVar9);
    }
    puVar8 = (uint *)(psVar7 + 1);
    if ((8 < uVar2) || (*(&PTR_DAT_0805ef44)[uVar2] == '\0')) {
      fprintf(DAT_08060620," (unknown FORM) (0x%x)\n",uVar2);
      iVar5 = param_2 + ((int)puVar8 - (int)param_1);
      FUN_08053398(iVar5,3);
      fprintf(DAT_08060620,"*** Dumping remaining data in this tag\n");
      FUN_08053420((int)(psVar7 + 2),(param3 - ((int)puVar8 - (int)param_1)) + -2,iVar5);
      return local_8;
    }
    uVar6 = 0;
    pcVar9 = "";
    iVar5 = fprintf(DAT_08060620," (%s)",(&PTR_DAT_0805ef44)[uVar2]);
    fprintf(DAT_08060620,"%*s",0x12 - iVar5,pcVar9);
    switch(uVar2) {
    case 1:
    case 2:
    case 6:
      local_c = FUN_08053340(puVar8);
      fprintf(DAT_08060620," 0x%08lx\n",local_c);
      uVar6 = 4;
      break;
    case 3:
    case 4:
      if (uVar2 == 3) {
        uVar6 = FUN_08053370((short *)puVar8);
        uVar6 = uVar6 & 0xffff;
        puVar8 = (uint *)(psVar7 + 2);
      }
      else {
        uVar6 = FUN_08053340(puVar8);
        puVar8 = (uint *)(psVar7 + 3);
      }
      fprintf(DAT_08060620," ");
      fprintf(DAT_08060620,"(%ld bytes)",uVar6);
      fprintf(DAT_08060620,"\n");
      break;
    case 5:
      local_c = FUN_08053370((short *)puVar8);
      local_c = local_c & 0xffff;
      fprintf(DAT_08060620," 0x%04x\n",local_c);
      uVar6 = 2;
      break;
    case 8:
      fprintf(DAT_08060620,"\n");
      uVar6 = FUN_08053420((int)puVar8,-1,(int)puVar8 + (param_2 - (int)param_1));
    }
    if (((uVar4 < 0x31) && (*(&PTR_DAT_0805ee80)[uVar4] != '\0')) &&
       ((*(uint *)(&DAT_0805b7c8 + uVar4 * 4) & 1 << (sbyte)uVar2) == 0)) {
      FUN_08053398((int)puVar8 + (param_2 - (int)param_1),2);
      fprintf(DAT_08060620,"*** Unexpected form for attribute\n");
      goto switchD_0805462d_caseD_3;
    }
    switch(uVar4) {
    case 1:
      local_8 = local_c;
      break;
    case 2:
      iVar5 = FUN_08053a74(puVar8,uVar6,(int)puVar8 + (param_2 - (int)param_1),3);
      goto LAB_080546a5;
    default:
      goto switchD_0805462d_caseD_3;
    case 5:
    case 6:
    case 7:
    case 8:
      iVar5 = (int)puVar8 + (param_2 - (int)param_1);
      FUN_08053398(iVar5,3);
      iVar5 = FUN_08054140(puVar8,uVar6,iVar5,uVar4,3);
      goto LAB_080546a5;
    case 9:
      FUN_08053398((int)puVar8 + (param_2 - (int)param_1),3);
      if ((local_c < 2) && (*(&PTR_s_ORD_row_major_0805effc)[local_c] != '\0')) {
        fprintf(DAT_08060620,"%s\n",(&PTR_s_ORD_row_major_0805effc)[local_c]);
      }
      else {
        fprintf(DAT_08060620,"unknown ORD (%ld)\n",local_c);
      }
      break;
    case 10:
      bVar1 = FUN_08053c50(puVar8,uVar6,(int)puVar8 + (param_2 - (int)param_1),3);
      iVar5 = CONCAT31(extraout_var,bVar1);
      goto LAB_080546a5;
    case 0xf:
      bVar1 = FUN_08053b3c(puVar8,uVar6,(int)puVar8 + (param_2 - (int)param_1),3);
      iVar5 = CONCAT31(extraout_var_00,bVar1);
LAB_080546a5:
      if (iVar5 != 0) {
switchD_0805462d_caseD_3:
        if (uVar2 - 3 < 2) {
          FUN_08053420((int)puVar8,uVar6,(int)puVar8 + (param_2 - (int)param_1));
        }
      }
      break;
    case 0x13:
      FUN_08053398((int)puVar8 + (param_2 - (int)param_1),3);
      if ((local_c < 0xb) && (*(&PTR_DAT_0805f004)[local_c] != '\0')) {
        fprintf(DAT_08060620,"%s\n",(&PTR_DAT_0805f004)[local_c]);
      }
      else {
        fprintf(DAT_08060620,"unknown LANG (%ld)\n",local_c);
      }
      break;
    case 0x1f:
      FUN_0805429c(puVar8,uVar6,(int)puVar8 + (param_2 - (int)param_1),3);
    }
    psVar7 = (short *)((int)puVar8 + uVar6);
  } while( true );
}



undefined4 FUN_08054804(int param_1,uint param_2,uint param_3)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  
  DAT_08060610 = DAT_08060610 + 1;
  do {
    while( true ) {
      while( true ) {
        if (param_3 - param_2 < 4) {
          DAT_08060610 = DAT_08060610 + -1;
          if (DAT_08060610 != 0) {
            FUN_08053398(param_2,1);
            fprintf(DAT_08060620,"*** Reached sibling of parent (missing null entry)\n");
          }
          return 0;
        }
        puVar3 = (uint *)(param_1 + param_2);
        uVar1 = FUN_08053340(puVar3);
        uVar4 = 0;
        if (uVar1 < 5) {
          if (uVar1 != 0) {
            FUN_08053398(param_2,1);
            fprintf(DAT_08060620,"null entry (%ld bytes)",uVar1);
            if (uVar1 < 5) {
              fprintf(DAT_08060620,"\n");
            }
            else {
              FUN_08053420((int)(puVar3 + 1),uVar1 - 4,param_2 + 4);
            }
            uVar4 = uVar1 + param_2;
            if (uVar4 < param_3) {
              FUN_08053398(uVar4,1);
              fprintf(DAT_08060620,"\n");
              FUN_08053398(uVar4,1);
              iVar2 = (param_3 - param_2) - uVar1;
              fprintf(DAT_08060620,"%ld bytes of padding data\n",iVar2);
              FUN_08053420((int)puVar3 + uVar1,iVar2,uVar4);
            }
            else if (param_3 < uVar4) {
              FUN_08053398(uVar4,1);
              fprintf(DAT_08060620,"\n");
              FUN_08053398(uVar4,1);
              fprintf(DAT_08060620,"*** Overruns\n");
            }
            FUN_08053398(param_3,1);
            fprintf(DAT_08060620,"\n");
            DAT_08060610 = DAT_08060610 + -1;
            return 0;
          }
          FUN_08053398(param_2,1);
          fprintf(DAT_08060620,"*** TAG has length 0 (assuming 4)\n");
          uVar1 = 4;
        }
        else {
          uVar4 = FUN_08054318(puVar3,param_2);
        }
        uVar1 = param_2 + uVar1;
        FUN_08053398(uVar1,1);
        fprintf(DAT_08060620,"\n");
        param_2 = uVar1;
        if (uVar4 != 0) break;
        FUN_08053398(uVar1,1);
        fprintf(DAT_08060620,"*** No sibling found (assuming this+length)\n");
      }
      if (uVar1 <= uVar4) break;
      FUN_08053398(uVar1,1);
      fprintf(DAT_08060620,"*** Sibling (0x%lx) points before this element (assuming this+length)\n"
              ,uVar4);
    }
    param_2 = uVar4;
  } while ((uVar4 <= uVar1) || (iVar2 = FUN_08054804(param_1,uVar1,uVar4), iVar2 == 0));
  DAT_08060610 = DAT_08060610 + -1;
  return 1;
}



uint FUN_08054a4c(uint *param_1,uint param_2,int param_3)

{
  bool bVar1;
  ulong param2;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  uint local_14;
  uint local_c;
  int local_8;
  
  local_8 = 0;
  local_c = 0;
  bVar1 = true;
  local_14 = FUN_08053340(param_1);
  param2 = FUN_08053340(param_1 + 1);
  FUN_08053398(param_3,0);
  fprintf(DAT_08060620,"Compilation unit at address %08lx (%ld bytes)\n",param2,local_14);
  if (param_2 < local_14) {
    FUN_08053398(param_3,0);
    fprintf(DAT_08060620,"*** Truncating to %ld bytes\n",param_2);
    local_14 = param_2;
  }
  uVar5 = 8;
  if (7 < local_14 - 10) {
    do {
      puVar4 = (uint *)((int)param_1 + uVar5);
      uVar2 = FUN_08053370((short *)(puVar4 + 1));
      uVar3 = FUN_08053340((uint *)((int)puVar4 + 6));
      local_8 = FUN_08053340(puVar4);
      if (local_8 == 0) {
        FUN_08053398(param_3 + uVar5,1);
        fprintf(DAT_08060620,"0x%08lx",param2 + uVar3);
        if (uVar3 < local_c) {
          fprintf(DAT_08060620,"  (PC offset not greater than previous entry)");
          bVar1 = false;
        }
        fprintf(DAT_08060620,"\n");
        uVar5 = uVar5 + 10;
      }
      else {
        FUN_08053398(param_3 + uVar5,1);
        fprintf(DAT_08060620,"0x%08lx at line %ld",param2 + uVar3,local_8);
        if ((short)uVar2 != -1) {
          fprintf(DAT_08060620,":%d",uVar2 & 0xffff);
        }
        if (uVar3 < local_c) {
          fprintf(DAT_08060620,"  (PC offset not greater than previous entry)");
          bVar1 = false;
        }
        fprintf(DAT_08060620,"\n");
      }
      uVar5 = uVar5 + 10;
      local_c = uVar3;
    } while (uVar5 <= local_14 - 10);
  }
  if (uVar5 < local_14) {
    FUN_08053398(param_3 + uVar5,1);
    fprintf(DAT_08060620,"%ld bytes of padding data\n",local_14 - uVar5);
    FUN_08053420((int)param_1 + uVar5,local_14 - uVar5,param_3 + uVar5);
  }
  else if (local_8 != 0) {
    FUN_08053398(param_3 + local_14,1);
    fprintf(DAT_08060620,"*** List doesn\'t end with line 0\n");
  }
  if (!bVar1) {
    FUN_08053398(param_3 + local_14,1);
    fprintf(DAT_08060620,"*** PC deltas do not increase monotonically\n");
  }
  FUN_08053398(param_3 + local_14,0);
  fprintf(DAT_08060620,"\n");
  return local_14;
}



uint FUN_08054cb4(uint *param_1,uint param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  ulong param2;
  long param2_00;
  ulong param2_01;
  uint uVar3;
  int *piVar4;
  char *__format;
  uint local_8;
  
  iVar2 = FUN_08053340(param_1);
  local_8 = iVar2 + 4;
  uVar3 = param_1[1];
  FUN_08053398(param_3,0);
  fprintf(DAT_08060620,"Compilation unit (%ld bytes) vsn %d:\n",local_8,(uint)(byte)uVar3);
  if (param_2 < local_8) {
    FUN_08053398(param_3,0);
    fprintf(DAT_08060620,"*** Truncating to %ld bytes\n",param_2);
    local_8 = param_2;
  }
  if ((byte)uVar3 == 1) {
    param2 = FUN_08053340((uint *)((int)param_1 + 5));
    param2_00 = FUN_08053340((uint *)((int)param_1 + 9));
    uVar1 = local_8 + param_3;
    FUN_08053398(param_3 + 6,1);
    fprintf(DAT_08060620,"reference to offset 0x%06lx\n",param2);
    FUN_08053398(param_3 + 9,1);
    fprintf(DAT_08060620,"%ld bytes generated for unit\n",param2_00);
    uVar3 = param_3 + 0xd;
    param_1 = (uint *)((int)param_1 + 0xd);
    while (uVar3 < uVar1) {
      param2_01 = FUN_08053340(param_1);
      if (param2_01 == 0) {
        FUN_08053398(uVar3,1);
        fprintf(DAT_08060620,"End of list for compilation unit (zero offset)\n");
        if (uVar3 == uVar1 - 4) {
          return local_8;
        }
        FUN_08053398(uVar3 + 4,1);
        fprintf(DAT_08060620,"%ld bytes of padding data\n",(uVar1 - uVar3) + -4);
        piVar4 = (int *)&stack0xffffffc8;
        goto LAB_08054e2e;
      }
      FUN_08053398(uVar3,2);
      fprintf(DAT_08060620,"Offset 0x%lx (0x%lx)\n",param2_01,param2 + param2_01);
      iVar2 = FUN_08053420((int)(param_1 + 1),-1,uVar3 + 4);
      uVar3 = uVar3 + iVar2 + 4;
      if (uVar1 < uVar3) {
        FUN_08053398(uVar3,1);
        __format = "*** Overruns\n";
LAB_08054ea1:
        fprintf(DAT_08060620,__format);
      }
      else if (uVar3 == uVar1) {
        FUN_08053398(uVar1,1);
        __format = "*** End of list for compilation unit (should be a zero offset)\n";
        goto LAB_08054ea1;
      }
      param_1 = (uint *)((int)param_1 + iVar2 + 4);
    }
  }
  else {
    FUN_08053398(param_3 + 4,1);
    fprintf(DAT_08060620,"*** Unknown version number - skipping\n");
    piVar4 = (int *)&stack0xffffffcc;
LAB_08054e2e:
    piVar4[-1] = (int)(param_1 + 1);
    piVar4[-2] = 0x8054e37;
    FUN_08053420(piVar4[-1],*piVar4,piVar4[1]);
  }
  return local_8;
}



uint FUN_08054ec8(uint *param_1,uint param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  long param2;
  ulong param2_00;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  uint local_8;
  
  iVar1 = FUN_08053340(param_1);
  local_8 = iVar1 + 4;
  uVar2 = param_1[1];
  FUN_08053398(param_3,0);
  fprintf(DAT_08060620,"Compilation unit (%ld bytes) vsn %d:\n",local_8,(uint)(byte)uVar2);
  if (param_2 < local_8) {
    FUN_08053398(param_3,0);
    fprintf(DAT_08060620,"*** Truncating to %ld bytes\n",param_2);
    local_8 = param_2;
  }
  if ((byte)uVar2 == 1) {
    uVar2 = FUN_08053340((uint *)((int)param_1 + 5));
    param2 = FUN_08053340((uint *)((int)param_1 + 9));
    uVar3 = local_8 + param_3;
    FUN_08053398(param_3 + 6,1);
    fprintf(DAT_08060620,"reference to offset 0x%06lx\n",uVar2);
    if ((DAT_0806060f & 0x10) != 0) {
      DAT_08060618 = 1;
      FUN_08053834(uVar2,0xffffffff,2);
      DAT_08060618 = 0;
    }
    FUN_08053398(param_3 + 9,1);
    fprintf(DAT_08060620,"%ld bytes generated for unit\n",param2);
    puVar4 = (uint *)((int)param_1 + 0xd);
    for (uVar2 = param_3 + 0xd; uVar5 = uVar2, uVar2 < uVar3; uVar2 = uVar2 + 8) {
      param2_00 = FUN_08053340(puVar4);
      iVar1 = FUN_08053340(puVar4 + 1);
      if ((param2_00 == 0) || (iVar1 == 0)) {
        FUN_08053398(uVar2,1);
        fprintf(DAT_08060620,"End of list for compilation unit (zero offset)\n");
        uVar5 = uVar3;
        if (uVar2 != uVar3 - 8) {
          FUN_08053398(uVar2 + 8,1);
          iVar1 = (uVar3 - uVar2) + -8;
          fprintf(DAT_08060620,"%ld bytes of padding data\n",iVar1);
          FUN_08053420((int)(puVar4 + 2),iVar1,uVar2 + 8);
        }
        break;
      }
      FUN_08053398(uVar2,2);
      fprintf(DAT_08060620,"0x%.8lx: %ld bytes\n",param2_00,iVar1);
      puVar4 = puVar4 + 2;
    }
    if (uVar3 < uVar5) {
      fprintf(DAT_08060620,"*** Overruns\n");
    }
  }
  else {
    FUN_08053398(param_3 + 4,1);
    fprintf(DAT_08060620,"*** Unknown version number - skipping\n");
    FUN_08053420((int)param_1 + 5,local_8 - 6,param_3);
  }
  return local_8;
}



int FUN_080550e4(uint *param_1,undefined4 param_2,int param_3)

{
  ulong param2;
  ulong param2_00;
  ulong uVar1;
  ulong param3;
  int iVar2;
  
  FUN_08053398(param_3,1);
  param2 = FUN_08053340(param_1);
  fprintf(DAT_08060620,"Line info  0x%.6lx\n",param2);
  FUN_08053398(param_3 + 4,1);
  param2_00 = FUN_08053340(param_1 + 1);
  fprintf(DAT_08060620,"Sf names   0x%.6lx\n",param2_00);
  FUN_08053398(param_3 + 8,1);
  uVar1 = FUN_08053340(param_1 + 2);
  fprintf(DAT_08060620,"code start 0x%.6lx\n",uVar1);
  FUN_08053398(param_3 + 0xc,1);
  uVar1 = FUN_08053340(param_1 + 3);
  fprintf(DAT_08060620,"code end   0x%.6lx\n",uVar1);
  iVar2 = 0x14;
  while( true ) {
    uVar1 = FUN_08053340((uint *)((int)param_1 + iVar2));
    if (uVar1 == 0xffffffff) break;
    param3 = FUN_08053340((uint *)((int)param_1 + iVar2 + 4));
    iVar2 = iVar2 + 8;
    FUN_08053398(param_3 + iVar2,2);
    fprintf(DAT_08060620,"L %lx F %lx (0x%.6lx, 0x%.6lx)\n",uVar1,param3,param2 + uVar1,
            param2_00 + param3);
  }
  return iVar2 + 4;
}



bool FUN_08055210(char *param_1,size_t param_2,char *param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  bool bVar5;
  
  uVar3 = 0xffffffff;
  pcVar4 = param_3;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  if (param_2 == ~uVar3 - 1) {
    iVar2 = strncmp(param_1,param_3,param_2);
    bVar5 = iVar2 == 0;
  }
  else {
    bVar5 = false;
  }
  return bVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_08055250(FILE *param_1,char *param_2,uint *param_3,uint param_4,uint param_5)

{
  char cVar1;
  bool bVar2;
  char *pcVar3;
  undefined3 extraout_var;
  int iVar4;
  undefined3 extraout_var_00;
  uint uVar5;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  uint uVar6;
  size_t sVar7;
  uint *puVar8;
  
  pcVar3 = strstr(param_2,"$$$");
  if (pcVar3 == (char *)0x0) {
    uVar6 = 0xffffffff;
    pcVar3 = param_2;
    do {
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    sVar7 = ~uVar6 - 1;
  }
  else {
    sVar7 = (int)pcVar3 - (int)param_2;
  }
  DAT_08060620 = param_1;
  DAT_08060610 = 0;
  _DAT_0806060c = param_5;
  if ((param_5 & 0x20000000) != 0) {
    fprintf(param_1,"\n%s:\n",param_2);
  }
  bVar2 = FUN_08055210(param_2,sVar7,".debug");
  if (CONCAT31(extraout_var,bVar2) == 0) {
    bVar2 = FUN_08055210(param_2,sVar7,".line");
    if (CONCAT31(extraout_var_00,bVar2) == 0) {
      bVar2 = FUN_08055210(param_2,sVar7,".debug_pubnames");
      if (CONCAT31(extraout_var_01,bVar2) == 0) {
        bVar2 = FUN_08055210(param_2,sVar7,".debug_aranges");
        if (CONCAT31(extraout_var_02,bVar2) == 0) {
          bVar2 = FUN_08055210(param_2,sVar7,".debug_sfnames");
          if (CONCAT31(extraout_var_03,bVar2) == 0) {
            bVar2 = FUN_08055210(param_2,sVar7,".debug_srcinfo");
            if (CONCAT31(extraout_var_04,bVar2) == 0) {
              bVar2 = FUN_08055210(param_2,sVar7,".asd");
              if (((CONCAT31(extraout_var_05,bVar2) == 0) &&
                  (bVar2 = FUN_08055210(param_2,sVar7,"C$$debug"),
                  CONCAT31(extraout_var_06,bVar2) == 0)) &&
                 (bVar2 = FUN_08055210(param_2,sVar7,"C$$fpmap"),
                 CONCAT31(extraout_var_07,bVar2) == 0)) {
                DAT_08060614 = 0;
                fprintf(DAT_08060620,"*** Unrecognised DWARF debugging area \"%s\"\n",param_2);
                return false;
              }
              puVar8 = (uint *)((int)param_3 + param_4);
              FUN_08051cc8(param_3);
              if (param_3 != (uint *)0x0) {
                do {
                  if (puVar8 <= param_3) break;
                  param_3 = FUN_08051cd8(DAT_08060620,param_3,puVar8,param_5 >> 0x1e & 1);
                } while (param_3 != (uint *)0x0);
              }
            }
            else {
              DAT_08060614 = 0;
              if (param_4 != 0) {
                uVar6 = 0;
                do {
                  iVar4 = FUN_080550e4((uint *)((int)param_3 + uVar6),param_4 - uVar6,uVar6);
                  uVar6 = uVar6 + iVar4;
                } while (uVar6 < param_4);
              }
            }
          }
          else {
            DAT_08060614 = 0;
            if (param_4 != 0) {
              uVar6 = 0;
              do {
                uVar5 = 0xffffffff;
                pcVar3 = (char *)((int)param_3 + uVar6);
                do {
                  if (uVar5 == 0) break;
                  uVar5 = uVar5 - 1;
                  cVar1 = *pcVar3;
                  pcVar3 = pcVar3 + 1;
                } while (cVar1 != '\0');
                FUN_08053398(uVar6,1);
                fprintf(DAT_08060620,"\"%s\"\n",(char *)((int)param_3 + uVar6));
                uVar6 = ~uVar5 + uVar6;
              } while (uVar6 < param_4);
            }
          }
        }
        else {
          DAT_08060614 = 0;
          if (param_4 != 0) {
            uVar6 = 0;
            do {
              uVar5 = FUN_08054ec8((uint *)((int)param_3 + uVar6),param_4 - uVar6,uVar6);
              uVar6 = uVar6 + uVar5;
            } while (uVar6 < param_4);
          }
        }
      }
      else {
        DAT_08060614 = 0;
        if (param_4 != 0) {
          uVar6 = 0;
          do {
            uVar5 = FUN_08054cb4((uint *)((int)param_3 + uVar6),param_4 - uVar6,uVar6);
            uVar6 = uVar6 + uVar5;
          } while (uVar6 < param_4);
        }
      }
    }
    else {
      DAT_08060614 = 0;
      uVar6 = 0;
      if (param_4 != 2) {
        do {
          uVar5 = FUN_08054a4c((uint *)((int)param_3 + uVar6),param_4 - uVar6,uVar6);
          uVar6 = uVar6 + uVar5;
        } while (uVar6 < param_4 - 2);
      }
    }
    bVar2 = true;
  }
  else {
    DAT_08060614 = 1;
    DAT_0805f030 = param_3;
    DAT_0805f034 = param_4;
    iVar4 = FUN_08054804((int)param_3,0,param_4);
    bVar2 = iVar4 == 0;
  }
  return bVar2;
}



undefined4 FUN_0805555c(char *param_1)

{
  char cVar1;
  bool bVar2;
  char *pcVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  uint uVar4;
  size_t sVar5;
  
  pcVar3 = strstr(param_1,"$$$");
  if (pcVar3 == (char *)0x0) {
    uVar4 = 0xffffffff;
    pcVar3 = param_1;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    sVar5 = ~uVar4 - 1;
  }
  else {
    sVar5 = (int)pcVar3 - (int)param_1;
  }
  bVar2 = FUN_08055210(param_1,sVar5,".debug");
  if ((((((CONCAT31(extraout_var,bVar2) == 0) &&
         (bVar2 = FUN_08055210(param_1,sVar5,".line"), CONCAT31(extraout_var_00,bVar2) == 0)) &&
        (bVar2 = FUN_08055210(param_1,sVar5,".debug_pubnames"), CONCAT31(extraout_var_01,bVar2) == 0
        )) && ((bVar2 = FUN_08055210(param_1,sVar5,".debug_aranges"),
               CONCAT31(extraout_var_02,bVar2) == 0 &&
               (bVar2 = FUN_08055210(param_1,sVar5,".debug_sfnames"),
               CONCAT31(extraout_var_03,bVar2) == 0)))) &&
      ((bVar2 = FUN_08055210(param_1,sVar5,".debug_srcinfo"), CONCAT31(extraout_var_04,bVar2) == 0
       && ((bVar2 = FUN_08055210(param_1,sVar5,".asd"), CONCAT31(extraout_var_05,bVar2) == 0 &&
           (bVar2 = FUN_08055210(param_1,sVar5,"C$$debug"), CONCAT31(extraout_var_06,bVar2) == 0))))
      )) && (bVar2 = FUN_08055210(param_1,sVar5,"C$$fpmap"), CONCAT31(extraout_var_07,bVar2) == 0))
  {
    return 0;
  }
  return 1;
}



char * FUN_08055660(char *param_1,uint param_2,uint param_3,int param_4)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  char *pcVar4;
  uint local_8;
  
  pcVar4 = (char *)0x0;
  if (param_4 != 0) {
    pcVar4 = (char *)FUN_08049a48(param_2,&local_8);
  }
  if (pcVar4 == (char *)0x0) {
    pcVar4 = "0x%lx";
    pcVar3 = param_1;
  }
  else {
    pcVar3 = param_1;
    if (param_3 != 0) {
      sprintf(param_1,"0x%lx+",param_3);
      uVar2 = 0xffffffff;
      do {
        if (uVar2 == 0) break;
        uVar2 = uVar2 - 1;
        cVar1 = *pcVar3;
        pcVar3 = pcVar3 + 1;
      } while (cVar1 != '\0');
      pcVar3 = param_1 + (~uVar2 - 1);
    }
    sprintf(pcVar3,"%s",pcVar4);
    uVar2 = 0xffffffff;
    pcVar4 = pcVar3;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    pcVar3 = pcVar3 + (~uVar2 - 1);
    if (local_8 == 0xffffffff) {
      return param_1;
    }
    pcVar4 = " (%d)";
    param_3 = local_8;
  }
  sprintf(pcVar3,pcVar4,param_3);
  return param_1;
}



bool FUN_08055710(char *param_1,size_t param_2,char *param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  bool bVar5;
  
  uVar3 = 0xffffffff;
  pcVar4 = param_3;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  if (param_2 == ~uVar3 - 1) {
    iVar2 = strncmp(param_1,param_3,param_2);
    bVar5 = iVar2 == 0;
  }
  else {
    bVar5 = false;
  }
  return bVar5;
}



void FUN_08055750(FILE *param_1,char *param_2,int param_3,int param_4,undefined4 param_5,
                 uint param_6,undefined4 param_7)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  char *pcVar4;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  uint uVar5;
  size_t sVar6;
  int local_224;
  int local_220;
  int local_21c;
  uint local_c;
  undefined4 local_8;
  
  pcVar4 = strstr(param_2,"$$$");
  if (pcVar4 == (char *)0x0) {
    uVar5 = 0xffffffff;
    pcVar4 = param_2;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    sVar6 = ~uVar5 - 1;
  }
  else {
    sVar6 = (int)pcVar4 - (int)param_2;
  }
  bVar2 = false;
  local_c = param_6;
  local_8 = param_7;
  DAT_08060620 = param_1;
  FUN_080578cc(&local_224,param_4 + param_3,param_5);
  bVar3 = FUN_08055710(param_2,sVar6,".debug_line");
  if (CONCAT31(extraout_var,bVar3) == 0) {
    bVar3 = FUN_08055710(param_2,sVar6,".debug_macinfo");
    if (CONCAT31(extraout_var_00,bVar3) == 0) {
      bVar3 = FUN_08055710(param_2,sVar6,".debug_abbrev");
      if (CONCAT31(extraout_var_01,bVar3) == 0) {
        bVar3 = FUN_08055710(param_2,sVar6,".debug_frame");
        if (CONCAT31(extraout_var_02,bVar3) == 0) goto LAB_080558d2;
        if ((param_6 & 0x20000000) != 0) {
          fprintf(param_1,"\n%s:\n",param_2);
        }
        FUN_08055d1c(&local_224);
      }
      else {
        if ((param_6 & 0x20000000) != 0) {
          fprintf(param_1,"\n%s:\n",param_2);
        }
        DAT_0806061c = FUN_08055e80(&local_224);
      }
    }
    else {
      if ((param_6 & 0x20000000) != 0) {
        fprintf(param_1,"\n%s:\n",param_2);
      }
      FUN_080576a8(&local_224);
    }
  }
  else {
    if ((param_6 & 0x20000000) != 0) {
      fprintf(param_1,"\n%s:\n",param_2);
    }
    FUN_080575d8(&local_224);
  }
  bVar2 = true;
LAB_080558d2:
  if (bVar2) {
    if (local_220 != local_21c) {
      fprintf(param_1," *** %ld extra bytes in area %s\n",local_21c - local_220,param_2);
    }
  }
  return;
}



void FUN_08055908(FILE *param_1,char *param_2,int param_3,int param_4,undefined4 param_5,
                 uint param_6,undefined4 param_7)

{
  char cVar1;
  bool bVar2;
  char *pcVar3;
  undefined3 extraout_var;
  uint uVar4;
  size_t sVar5;
  int local_224;
  int local_220;
  int local_21c;
  uint local_c;
  undefined4 local_8;
  
  pcVar3 = strstr(param_2,"$$$");
  if (pcVar3 == (char *)0x0) {
    uVar4 = 0xffffffff;
    pcVar3 = param_2;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    sVar5 = ~uVar4 - 1;
  }
  else {
    sVar5 = (int)pcVar3 - (int)param_2;
  }
  local_c = param_6;
  local_8 = param_7;
  DAT_08060620 = param_1;
  FUN_080578cc(&local_224,param_4 + param_3,param_5);
  bVar2 = FUN_08055710(param_2,sVar5,".debug_info");
  if (CONCAT31(extraout_var,bVar2) != 0) {
    if ((param_6 & 0x20000000) != 0) {
      fprintf(param_1,"\n%s:\n",param_2);
    }
    FUN_08056228(&local_224,DAT_0806061c);
    if (local_220 != local_21c) {
      fprintf(param_1," *** %ld extra bytes in area %s\n",local_21c - local_220,param_2);
    }
  }
  return;
}



undefined4 FUN_080559dc(char *param_1)

{
  char cVar1;
  bool bVar2;
  char *pcVar3;
  undefined3 extraout_var;
  undefined4 uVar4;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  uint uVar5;
  size_t sVar6;
  
  pcVar3 = strstr(param_1,"$$$");
  if (pcVar3 == (char *)0x0) {
    uVar5 = 0xffffffff;
    pcVar3 = param_1;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    sVar6 = ~uVar5 - 1;
  }
  else {
    sVar6 = (int)pcVar3 - (int)param_1;
  }
  bVar2 = FUN_08055710(param_1,sVar6,".debug_info");
  if (CONCAT31(extraout_var,bVar2) == 0) {
    bVar2 = FUN_08055710(param_1,sVar6,".debug_macinfo");
    if ((((CONCAT31(extraout_var_00,bVar2) == 0) &&
         (bVar2 = FUN_08055710(param_1,sVar6,".debug_abbrev"), CONCAT31(extraout_var_01,bVar2) == 0)
         ) && (bVar2 = FUN_08055710(param_1,sVar6,".debug_line"),
              CONCAT31(extraout_var_02,bVar2) == 0)) &&
       (bVar2 = FUN_08055710(param_1,sVar6,".debug_frame"), CONCAT31(extraout_var_03,bVar2) == 0)) {
      return 0;
    }
    uVar4 = 1;
  }
  else {
    uVar4 = 2;
  }
  return uVar4;
}



void FUN_08055a90(int *param_1)

{
  uint uVar1;
  char local_204 [512];
  
  do {
    uVar1 = FUN_08057878(param_1,local_204,0x200);
    fprintf(DAT_08060620,"%s",local_204);
  } while (uVar1 == 1);
  return;
}



void FUN_08055ad8(int param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = param_2[1];
  while (iVar1 != param_1) {
    param_2 = (int *)*param_2;
    iVar1 = param_2[1];
  }
  return;
}



int FUN_08055af0(int param_1,int *param_2,undefined4 param_3,int param_4)

{
  uint uVar1;
  ulong uVar2;
  char *__format;
  
  switch(param_3) {
  default:
    goto switchD_08055b0b_caseD_0;
  case 1:
    uVar1 = FUN_080578f4(param_2);
    uVar2 = uVar1 * *(int *)(param_1 + 0x10);
    fprintf(DAT_08060620," %#.6lx",uVar2);
    return uVar2;
  case 2:
    uVar1 = FUN_08057840(param_2);
    break;
  case 3:
    uVar1 = FUN_080579d4(param_2);
    uVar1 = uVar1 & 0xffff;
    break;
  case 4:
    uVar1 = FUN_080578f4(param_2);
    break;
  case 5:
    uVar1 = FUN_08057a60(param_2);
    __format = "r%lu";
    goto LAB_08055b90;
  case 6:
    uVar1 = FUN_08057a60(param_2);
    uVar1 = uVar1 * *(int *)(param_1 + 0x14);
    __format = "=%#lx";
LAB_08055b90:
    fprintf(DAT_08060620,__format,uVar1);
    goto switchD_08055b0b_caseD_0;
  }
  uVar2 = uVar1 * *(int *)(param_1 + 0x10);
  param_4 = param_4 + uVar2;
  fprintf(DAT_08060620,"+%#lx =%#.6lx",uVar2,param_4);
switchD_08055b0b_caseD_0:
  return param_4;
}



void FUN_08055ba8(int param_1,int *param_2,uint param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  char *__format;
  
LAB_08055d07:
  while( true ) {
    do {
      while( true ) {
        while( true ) {
          if (param_3 <= (uint)param_2[1]) {
            return;
          }
          param_2[0x84] = 0;
          uVar2 = FUN_08057840(param_2);
          uVar3 = uVar2 & 0xc0;
          if (uVar3 != 0x40) break;
          uVar2 = (uVar2 & 0x3f) * *(int *)(param_1 + 0x10);
          param_4 = param_4 + uVar2;
          fprintf(DAT_08060620,"    DW_CFA_advance_loc +%#x = %#.6lx\n",uVar2,param_4);
        }
        if (uVar3 < 0x41) break;
        if (uVar3 != 0x80) goto code_r0x08055bfb;
        uVar3 = FUN_08057a60(param_2);
        fprintf(DAT_08060620,"    DW_CFA_offset r%d=%#lx\n",uVar2 & 0x3f,
                uVar3 * *(int *)(param_1 + 0x14));
      }
    } while (uVar3 != 0);
    if (0xe < (int)uVar2) break;
    iVar1 = uVar2 * 0xc;
    fprintf(DAT_08060620,"    %s ",(&PTR_s_DW_CFA_nop_0805c5e0)[uVar2 * 3]);
    iVar4 = FUN_08055af0(param_1,param_2,*(undefined4 *)(&DAT_0805c5e4 + iVar1),param_4);
    iVar5 = *(int *)(&DAT_0805c5e8 + iVar1);
    if (iVar5 == 5) {
      fprintf(DAT_08060620,", ");
      iVar5 = *(int *)(&DAT_0805c5e8 + iVar1);
    }
    param_4 = FUN_08055af0(param_1,param_2,iVar5,iVar4);
    fprintf(DAT_08060620,"\n");
  }
  __format = "    unknown (%d)\n";
  goto LAB_08055cf9;
code_r0x08055bfb:
  if (uVar3 == 0xc0) {
    uVar2 = uVar2 & 0x3f;
    __format = "    DW_CFA_restore r%d\n";
LAB_08055cf9:
    fprintf(DAT_08060620,__format,uVar2);
  }
  goto LAB_08055d07;
}



void FUN_08055d1c(int *param_1)

{
  ulong param2;
  uint uVar1;
  int *piVar2;
  int iVar3;
  uint param4;
  uint param5;
  char *__format;
  uint uVar4;
  int *local_8;
  
  local_8 = (int *)0x0;
  while( true ) {
    param2 = param_1[1];
    if (param2 == param_1[2]) {
      return;
    }
    if (param_1[2] - param2 < 4) break;
    uVar4 = FUN_080578f4(param_1);
    if ((uint)(param_1[2] - param_1[1]) < uVar4) {
      __format = "*** Dw_Df_DecodeFrame -- not enough data to read %lu bytes for frame data\n";
      goto LAB_08055d62;
    }
    uVar4 = param_1[1] + uVar4;
    uVar1 = FUN_080578f4(param_1);
    if (uVar1 == 0xffffffff) {
      piVar2 = malloc(0x1c);
      piVar2[1] = param2;
      uVar1 = FUN_08057840(param_1);
      *(char *)(piVar2 + 2) = (char)uVar1;
      fprintf(DAT_08060620,"  CIE %.6lx: version %d, \"",param2,(uint)*(byte *)(piVar2 + 2));
      FUN_08055a90(param_1);
      uVar1 = FUN_08057a60(param_1);
      piVar2[4] = uVar1;
      uVar1 = FUN_08057aa0(param_1);
      piVar2[5] = uVar1;
      uVar1 = FUN_08057840(param_1);
      *(char *)(piVar2 + 6) = (char)uVar1;
      fprintf(DAT_08060620,"\", code align %.6lx, data align %.6lx, return reg r%d\n",piVar2[4],
              piVar2[5],(uint)*(byte *)(piVar2 + 6));
      *piVar2 = (int)local_8;
      FUN_08055ba8((int)piVar2,param_1,uVar4,0);
      local_8 = piVar2;
    }
    else {
      iVar3 = FUN_08055ad8(uVar1,local_8);
      param4 = FUN_080578f4(param_1);
      param5 = FUN_080578f4(param_1);
      fprintf(DAT_08060620,"  FDE %.6lx: CIE %.6lx, init loc %.6lx, range %.6lx\n",param2,uVar1,
              param4,param5);
      FUN_08055ba8(iVar3,param_1,uVar4,uVar1);
    }
  }
  uVar4 = 4;
  __format = "*** Dw_Df_DecodeFrame -- not enough data to read %u bytes for length\n";
LAB_08055d62:
  fprintf(DAT_08060620,__format,uVar4);
  return;
}



undefined4 FUN_08055e80(int *param_1)

{
  size_t __size;
  char cVar1;
  bool bVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  char *pcVar6;
  uint uVar7;
  void *pvVar8;
  char *param4;
  uint *local_278;
  int local_260;
  uint local_254;
  undefined4 *local_24c;
  undefined4 local_248;
  uint local_244 [128];
  char local_44 [64];
  
  local_248 = 0;
  local_24c = &local_248;
  bVar2 = false;
  if ((uint)param_1[1] < (uint)param_1[2]) {
    do {
      puVar3 = malloc(0x14);
      puVar3[1] = param_1[1];
      puVar3[3] = 0;
      local_254 = 0;
      while( true ) {
        param_1[0x84] = 0;
        param_1[0x85] = param_1[1];
        uVar7 = FUN_08057a60(param_1);
        if (uVar7 == 0) break;
        if (bVar2) {
          fprintf(DAT_08060620,"\n");
          bVar2 = false;
        }
        puVar4 = malloc(0x14);
        *puVar4 = puVar3[3];
        puVar3[3] = puVar4;
        puVar4[1] = uVar7;
        uVar5 = FUN_08057a60(param_1);
        puVar4[2] = uVar5;
        uVar5 = FUN_08057840(param_1);
        puVar4[3] = uVar5;
        if (local_254 < uVar7) {
          local_254 = uVar7;
        }
        pcVar6 = FUN_08057aec(puVar4[2],local_44);
        if (puVar4[3] == 0) {
          param4 = "no";
        }
        else {
          param4 = "  ";
        }
        fprintf(DAT_08060620,"  %.8lx %2ld: %s children: %s\n",param_1[0x85],puVar4[1],param4,pcVar6
               );
        local_260 = 0;
        local_278 = local_244;
        while( true ) {
          param_1[0x84] = 0;
          param_1[0x85] = param_1[1];
          uVar7 = FUN_08057a60(param_1);
          *local_278 = uVar7;
          uVar7 = FUN_08057a60(param_1);
          local_244[local_260 * 2 + 1] = uVar7;
          if ((*local_278 == 0) && (uVar7 == 0)) break;
          pcVar6 = FUN_08057de4(local_244[local_260 * 2],local_44,(undefined4 *)0x0);
          fprintf(DAT_08060620,"    %.6lx %s",param_1[0x85],pcVar6);
          uVar7 = 0xffffffff;
          do {
            if (uVar7 == 0) break;
            uVar7 = uVar7 - 1;
            cVar1 = *pcVar6;
            pcVar6 = pcVar6 + 1;
          } while (cVar1 != '\0');
          if (~uVar7 - 1 < 0x1a) {
            fprintf(DAT_08060620,"%*s",0x1a - (~uVar7 - 1),"");
          }
          pcVar6 = FUN_08058408(local_244[local_260 * 2 + 1],local_44);
          fprintf(DAT_08060620," %s\n",pcVar6);
          local_278 = local_278 + 2;
          local_260 = local_260 + 1;
        }
        __size = local_260 * 8 + 8;
        pvVar8 = malloc(__size);
        puVar4[4] = pvVar8;
        memcpy(pvVar8,local_244,__size);
      }
      pvVar8 = calloc(4,local_254 + 1);
      for (puVar4 = (undefined4 *)puVar3[3]; puVar4 != (undefined4 *)0x0;
          puVar4 = (undefined4 *)*puVar4) {
        *(undefined4 **)((int)pvVar8 + puVar4[1] * 4) = puVar4;
      }
      puVar3[2] = local_254;
      puVar3[4] = pvVar8;
      *puVar3 = 0;
      *local_24c = puVar3;
      bVar2 = true;
      local_24c = puVar3;
    } while ((uint)param_1[1] < (uint)param_1[2]);
  }
  return local_248;
}



undefined4 FUN_080561f0(FILE *param_1,undefined4 *param_2,int param_3)

{
  int iVar1;
  
  iVar1 = 0;
  while( true ) {
    if ((char *)*param_2 == (char *)0x0) {
      return 0;
    }
    if (iVar1 == param_3) break;
    iVar1 = iVar1 + 1;
    param_2 = param_2 + 1;
  }
  fputs((char *)*param_2,param_1);
  return 1;
}



void FUN_08056228(int *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  ulong uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint param2;
  uint param5;
  char *pcVar7;
  uint uVar8;
  int iVar9;
  ulong unaff_ESI;
  uint unaff_EDI;
  uint local_148;
  uint local_13c;
  uint *local_138;
  int local_118;
  int local_114;
  undefined4 *local_108;
  char local_104 [256];
  
  local_114 = 0;
  uVar5 = param_1[2];
  uVar4 = param_1[1];
joined_r0x08056258:
  if (uVar4 < uVar5) {
    uVar8 = uVar5 - uVar4;
    local_118 = 0;
    if (10 < uVar8) {
      param_1[2] = uVar5;
      fprintf(DAT_08060620,"  Header\n");
      uVar8 = FUN_080578f4(param_1);
      uVar6 = FUN_080579d4(param_1);
      param2 = FUN_080578f4(param_1);
      param5 = FUN_08057840(param_1);
      pcVar7 = FUN_08055660(local_104,param_1[1] - 5,param2,(uint)param_1[0x86] >> 0x1e & 1);
      fprintf(DAT_08060620,"    size 0x%lx bytes, dwarf version %d, abbrevp %s, address size %d\n",
              uVar8,uVar6 & 0xffff,pcVar7,param5);
      for (puVar1 = param_2; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
        if (puVar1[1] == param2) {
          local_118 = puVar1[4];
          break;
        }
      }
      uVar8 = uVar4 + uVar8 + 4;
      param_1[2] = uVar8;
      if (local_118 == 0) {
        fprintf(DAT_08060620,"Can\'t find .debug_abbrev section 0x%lx\n",param2);
        param_1[1] = param_1[2];
        uVar4 = param_1[2];
      }
      else {
        local_148 = param_1[1];
        if (local_148 < uVar8) {
          do {
            param_1[0x85] = local_148;
            param_1[0x84] = 0;
            uVar8 = FUN_08057a60(param_1);
            if (local_114 < 10) {
              fprintf(DAT_08060620,"  %.6lx:%*s %ld  ",param_1[0x85],local_114 * 2,"",uVar8);
            }
            if (uVar8 == 0) {
              if (local_114 < 1) {
                if ((uint)(param_1[2] - param_1[1]) < 4) {
                  pcVar7 = "padding\n";
                }
                else {
                  pcVar7 = "*** unexpected padding ***\n";
                }
                fprintf(DAT_08060620,pcVar7);
              }
              else {
                if (local_114 < 10) {
                  fprintf(DAT_08060620,"null\n");
                }
                local_114 = local_114 + -1;
              }
            }
            else if (((uint)puVar1[2] < uVar8) ||
                    (iVar2 = *(int *)(local_118 + uVar8 * 4), iVar2 == 0)) {
              fprintf(DAT_08060620,"***Unknown abbreviation code %#lx\n",uVar8);
            }
            else {
              local_138 = *(uint **)(iVar2 + 0x10);
              if (local_114 < 10) {
                pcVar7 = FUN_08057aec(*(int *)(iVar2 + 8),local_104);
                fprintf(DAT_08060620,"= 0x%lx (%s)\n",*(ulong *)(iVar2 + 8),pcVar7);
              }
              local_13c = local_138[1];
              if (local_13c != 0) {
LAB_080565a7:
                iVar9 = 0;
                param_1[0x85] = param_1[1];
                param_1[0x84] = 0;
                if (local_114 < 10) {
                  pcVar7 = FUN_08057de4(*local_138,local_104,&local_108);
                  fprintf(DAT_08060620,"  %.6lx:%*s %s ",param_1[0x85],local_114 * 2 + 2,"",pcVar7);
                }
LAB_0805661e:
                switch(local_13c) {
                case 1:
                case 0x10:
                  iVar9 = 4;
                  goto switchD_0805662e_caseD_6;
                default:
                  goto switchD_0805662e_caseD_2;
                case 3:
                  iVar9 = 3;
                  break;
                case 4:
                  iVar9 = 3;
                  goto LAB_08056749;
                case 5:
                  break;
                case 6:
                  goto switchD_0805662e_caseD_6;
                case 7:
                  iVar9 = 1;
                  unaff_ESI = FUN_080578f4(param_1);
                  unaff_EDI = FUN_080578f4(param_1);
                  goto switchD_0805662e_caseD_2;
                case 8:
                  do {
                    uVar8 = FUN_08057878(param_1,local_104,0x100);
                    if (local_114 < 10) {
                      fprintf(DAT_08060620,"%s",local_104);
                    }
                  } while (uVar8 == 1);
                  if (local_114 < 10) {
                    pcVar7 = "\n";
                    goto LAB_08056950;
                  }
                  goto LAB_0805695e;
                case 9:
                  iVar9 = 3;
                  unaff_ESI = FUN_08057a60(param_1);
                  goto switchD_0805662e_caseD_2;
                case 10:
                  iVar9 = 3;
                  unaff_ESI = FUN_08057840(param_1);
                  goto switchD_0805662e_caseD_2;
                case 0xb:
                case 0xc:
                  unaff_ESI = FUN_08057840(param_1);
                  goto switchD_0805662e_caseD_2;
                case 0xf:
                  goto switchD_0805662e_caseD_f;
                case 0x15:
                  iVar9 = 5;
                  goto switchD_0805662e_caseD_f;
                case 0x16:
                  goto switchD_0805662e_caseD_16;
                }
                uVar8 = FUN_080579d4(param_1);
                unaff_ESI = uVar8 & 0xffff;
                goto switchD_0805662e_caseD_2;
              }
LAB_08056976:
              if (*(int *)(iVar2 + 0xc) != 0) {
                local_114 = local_114 + 1;
              }
            }
            local_148 = param_1[1];
          } while (local_148 < (uint)param_1[2]);
        }
        if (local_114 != 0) {
          fprintf(DAT_08060620,"***Nesting = %d at end of section\n",local_114);
          local_148 = param_1[1];
        }
        uVar8 = local_148 + 3 & 0xfffffffc;
        uVar4 = local_148;
        if (uVar8 <= (uint)param_1[2]) {
          param_1[1] = uVar8;
          uVar4 = uVar8;
        }
      }
      goto joined_r0x08056258;
    }
    fprintf(DAT_08060620,"*** %lu junk bytes at end of section\n",uVar8);
    fprintf(DAT_08060620,"  %.6lx:  ",param_1[1]);
    for (; uVar8 != 0; uVar8 = uVar8 - 1) {
      uVar5 = FUN_08057840(param_1);
      fprintf(DAT_08060620," %.2x",uVar5 & 0xff);
    }
  }
  return;
switchD_0805662e_caseD_16:
  local_13c = FUN_08057a60(param_1);
  if (local_114 < 10) {
    pcVar7 = FUN_08058408(local_13c,local_104);
    fprintf(DAT_08060620,"indirect %s ",pcVar7);
  }
  goto LAB_0805661e;
switchD_0805662e_caseD_f:
  unaff_ESI = FUN_08057a60(param_1);
  goto switchD_0805662e_caseD_2;
switchD_0805662e_caseD_6:
LAB_08056749:
  unaff_ESI = FUN_080578f4(param_1);
switchD_0805662e_caseD_2:
  if (iVar9 == 0) {
    if (local_114 < 10) {
      if ((local_108 == (undefined4 *)0x0) ||
         (iVar9 = FUN_080561f0(DAT_08060620,local_108,unaff_ESI), iVar9 == 0)) {
        fprintf(DAT_08060620,"0x%lx",unaff_ESI);
      }
      fputc(10,DAT_08060620);
    }
    goto LAB_0805695e;
  }
  if (iVar9 == 5) {
    if (9 < local_114) goto LAB_0805695e;
    if (uVar4 == 0) {
      fprintf(DAT_08060620,"0x%lx\n",unaff_ESI);
      goto LAB_0805695e;
    }
    pcVar7 = "0x%lx (0x%lx)\n";
    uVar8 = uVar4 + unaff_ESI;
  }
  else {
    if (iVar9 == 4) {
      if (local_114 < 10) {
        pcVar7 = FUN_08055660(local_104,param_1[1] - 4,unaff_ESI,(uint)param_1[0x86] >> 0x1e & 1);
        fprintf(DAT_08060620,"%s\n",pcVar7);
      }
      goto LAB_0805695e;
    }
    if (iVar9 != 1) {
      if (iVar9 == 3) {
        uVar3 = unaff_ESI;
        if (local_114 < 10) {
          fprintf(DAT_08060620," block size 0x%lx = {",unaff_ESI);
        }
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          uVar8 = FUN_08057840(param_1);
          if (local_114 < 10) {
            fprintf(DAT_08060620," %.2x",uVar8 & 0xff);
          }
        }
        if (local_114 < 10) {
          pcVar7 = "}\n";
LAB_08056950:
          fprintf(DAT_08060620,pcVar7);
        }
      }
      goto LAB_0805695e;
    }
    if (9 < local_114) goto LAB_0805695e;
    pcVar7 = "0x%lx 0x%lx\n";
    uVar8 = unaff_EDI;
  }
  fprintf(DAT_08060620,pcVar7,unaff_ESI,uVar8);
LAB_0805695e:
  local_13c = local_138[3];
  local_138 = local_138 + 2;
  if (local_13c == 0) goto LAB_08056976;
  goto LAB_080565a7;
}



void FUN_08056a00(int param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  undefined4 local_508;
  char local_504 [1280];
  
  sprintf(local_504,"  %.6lx:  ",*(ulong *)(param_1 + 0x214));
  uVar2 = 0xffffffff;
  pcVar3 = local_504;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  vsprintf(local_504 + (~uVar2 - 1),param_2,&stack0x0000000c);
  uVar2 = 0xffffffff;
  pcVar3 = local_504;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  for (uVar2 = ~uVar2 - 1; uVar2 < 0x28; uVar2 = uVar2 + 1) {
    local_504[uVar2] = ' ';
  }
  local_504[uVar2] = ':';
  pcVar3 = local_504 + uVar2 + 1;
  uVar2 = 0;
  if (*(int *)(param_1 + 0x210) != 0) {
    local_508 = param_1 + 0x10;
    do {
      sprintf(pcVar3," %.2x",(uint)*(byte *)(uVar2 + local_508));
      uVar2 = uVar2 + 1;
      pcVar3 = pcVar3 + 3;
    } while (uVar2 < *(uint *)(param_1 + 0x210));
  }
  if (*(int *)(param_1 + 0x220) != 0) {
    fprintf(DAT_08060620,"\n");
  }
  fprintf(DAT_08060620,"%s",local_504);
  *(int *)(param_1 + 0x220) = (int)pcVar3 - (int)local_504;
  *(undefined4 *)(param_1 + 0x214) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(param_1 + 0x210) = 0;
  return;
}



undefined4 * FUN_08056b14(undefined4 *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  puVar1 = malloc(0x3b8);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar3 = puVar1 + 0xa3;
    puVar4 = puVar1 + 0x91;
    do {
      *puVar3 = 0;
      *puVar4 = 0;
      puVar3 = puVar3 + 1;
      puVar4 = puVar4 + 4;
    } while ((int)puVar3 <= (int)(puVar1 + 0xa6));
    puVar1[0xa2] = 0;
    puVar1[0xa8] = 0;
    puVar1[0xa7] = 0;
    puVar1[0xa1] = 0;
    puVar3 = puVar1;
    for (iVar2 = 0x88; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = *param_1;
      param_1 = param_1 + 1;
      puVar3 = puVar3 + 1;
    }
    puVar1[0x85] = 0;
    puVar1[0x84] = 0;
    puVar1[0x88] = 0;
  }
  return puVar1;
}



void FUN_08056bb0(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  void *pvVar2;
  void *pvVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  
  uVar1 = param_1[2];
  if (param_2[0x88] != 0) {
    fputc(10,DAT_08060620);
  }
  pvVar3 = (void *)param_2[0xa2];
  while (pvVar3 != (void *)0x0) {
    pvVar2 = *(void **)((int)pvVar3 + 0x44);
    free(pvVar3);
    pvVar3 = pvVar2;
  }
  pvVar3 = (void *)param_2[0xa8];
  while (pvVar3 != (void *)0x0) {
    pvVar2 = *(void **)((int)pvVar3 + 0x14);
    free(pvVar3);
    pvVar3 = pvVar2;
  }
  puVar5 = param_2;
  puVar6 = param_1;
  for (iVar4 = 0x88; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  param_1[2] = uVar1;
  free(param_2);
  return;
}



int FUN_08056c4c(int param_1,char *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)

{
  char cVar1;
  void *pvVar2;
  uint uVar3;
  void *pvVar4;
  void *pvVar5;
  int iVar6;
  char *pcVar7;
  int iVar8;
  int local_8;
  
  pvVar5 = (void *)0x0;
  local_8 = 0;
  uVar3 = 0xffffffff;
  pcVar7 = param_2;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar7 + 1;
  } while (cVar1 != '\0');
  if ((void *)(param_1 + 0x244) != (void *)0x0) {
    pvVar2 = (void *)(param_1 + 0x244);
    pvVar5 = (void *)0x0;
    do {
      pvVar4 = pvVar2;
      pvVar2 = pvVar4;
      if (*(int *)((int)pvVar4 + 0x40) != 4) break;
      local_8 = local_8 + 4;
      pvVar2 = *(void **)((int)pvVar4 + 0x44);
      pvVar5 = pvVar4;
    } while (pvVar2 != (void *)0x0);
    if (pvVar2 != (void *)0x0) {
      iVar6 = *(int *)((int)pvVar2 + 0x40);
      goto LAB_08056cc3;
    }
  }
  if (pvVar5 == (void *)0x0) {
    return 0;
  }
  pvVar2 = malloc(0x48);
  *(void **)((int)pvVar5 + 0x44) = pvVar2;
  if (pvVar2 == (void *)0x0) {
    return 0;
  }
  *(undefined4 *)((int)pvVar2 + 0x44) = 0;
  iVar6 = 0;
LAB_08056cc3:
  pvVar5 = malloc(~uVar3);
  iVar8 = iVar6 * 0x10;
  *(void **)(iVar8 + (int)pvVar2) = pvVar5;
  if (pvVar5 == (void *)0x0) {
    return 0;
  }
  memcpy(pvVar5,param_2,~uVar3);
  *(undefined4 *)(iVar8 + 4 + (int)pvVar2) = param_4;
  *(undefined4 *)(iVar8 + 8 + (int)pvVar2) = param_5;
  *(undefined4 *)(iVar8 + 0xc + (int)pvVar2) = param_3;
  *(int *)((int)pvVar2 + 0x40) = iVar6 + 1;
  return iVar6 + 1 + local_8;
}



int FUN_08056d20(int param_1,char *param_2)

{
  char cVar1;
  void *pvVar2;
  void *pvVar3;
  uint uVar4;
  int iVar5;
  char *pcVar6;
  int iVar7;
  void *local_8;
  
  local_8 = (void *)0x0;
  iVar5 = 0;
  uVar4 = 0xffffffff;
  pcVar6 = param_2;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar6;
    pcVar6 = pcVar6 + 1;
  } while (cVar1 != '\0');
  pvVar2 = (void *)(param_1 + 0x28c);
  if ((void *)(param_1 + 0x28c) != (void *)0x0) {
    do {
      pvVar3 = pvVar2;
      pvVar2 = pvVar3;
      if (*(int *)((int)pvVar3 + 0x10) != 4) break;
      iVar5 = iVar5 + 4;
      pvVar2 = *(void **)((int)pvVar3 + 0x14);
      local_8 = pvVar3;
    } while (pvVar2 != (void *)0x0);
    if (pvVar2 != (void *)0x0) {
      iVar7 = *(int *)((int)pvVar2 + 0x10);
      goto LAB_08056d94;
    }
  }
  if (local_8 == (void *)0x0) {
    return 0;
  }
  pvVar2 = malloc(0x18);
  *(void **)((int)local_8 + 0x14) = pvVar2;
  if (pvVar2 == (void *)0x0) {
    return 0;
  }
  *(undefined4 *)((int)pvVar2 + 0x14) = 0;
  iVar7 = 0;
LAB_08056d94:
  pvVar3 = malloc(~uVar4);
  *(void **)((int)pvVar2 + iVar7 * 4) = pvVar3;
  if (pvVar3 == (void *)0x0) {
    return 0;
  }
  memcpy(pvVar3,param_2,~uVar4);
  *(int *)((int)pvVar2 + 0x10) = iVar7 + 1;
  return iVar7 + 1 + iVar5;
}



int FUN_08056dd0(int param_1,uint param_2)

{
  int iVar1;
  
  iVar1 = param_1 + 0x244;
  if (param_2 != 0) {
    for (; 4 < param_2; param_2 = param_2 - 4) {
      if (iVar1 == 0) {
        return 0;
      }
      iVar1 = *(int *)(iVar1 + 0x44);
    }
    if ((iVar1 != 0) && (param_2 <= *(uint *)(iVar1 + 0x40))) {
      return iVar1 + -0x10 + param_2 * 0x10;
    }
  }
  return 0;
}



undefined4 FUN_08056e0c(int param_1,uint param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = param_1 + 0x28c;
  for (; 4 < param_2; param_2 = param_2 - 4) {
    if (iVar2 == 0) goto LAB_08056e40;
    iVar2 = *(int *)(iVar2 + 0x14);
  }
  if (iVar2 == 0) {
LAB_08056e40:
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(iVar2 + -4 + param_2 * 4);
  }
  return uVar1;
}



void FUN_08056e44(int param_1)

{
  *(undefined4 *)(param_1 + 0x228) = 0;
  *(undefined4 *)(param_1 + 0x22c) = 1;
  *(undefined4 *)(param_1 + 0x230) = 1;
  *(undefined4 *)(param_1 + 0x234) = 0;
  *(uint *)(param_1 + 0x238) = (uint)*(byte *)(param_1 + 0x2b1);
  *(undefined4 *)(param_1 + 0x23c) = 0;
  return;
}



int * FUN_08056e8c(int *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  char local_104 [256];
  
  iVar4 = param_1[1];
  uVar1 = FUN_080578f4(param_1);
  param_1[0xa9] = uVar1;
  param_1[2] = uVar1 + 4 + iVar4;
  uVar1 = FUN_080579d4(param_1);
  *(short *)(param_1 + 0xaa) = (short)uVar1;
  uVar1 = FUN_080578f4(param_1);
  param_1[0xab] = uVar1;
  uVar1 = FUN_08057840(param_1);
  *(char *)(param_1 + 0xac) = (char)uVar1;
  uVar1 = FUN_08057840(param_1);
  *(char *)((int)param_1 + 0x2b1) = (char)uVar1;
  uVar1 = FUN_08057840(param_1);
  *(char *)((int)param_1 + 0x2b2) = (char)uVar1;
  uVar1 = FUN_08057840(param_1);
  *(char *)((int)param_1 + 0x2b3) = (char)uVar1;
  uVar1 = FUN_08057840(param_1);
  *(char *)(param_1 + 0xad) = (char)uVar1;
  fprintf(DAT_08060620,
          "  Header:\n    total length %ld\n    version %d\n    prologue length %ld\n    minimum instruction length %d\n    default is_stmt %d\n    line base %d\n    line range %d\n    opcode base %d\n"
          ,param_1[0xa9],(uint)*(ushort *)(param_1 + 0xaa),param_1[0xab],
          (uint)*(byte *)(param_1 + 0xac),(uint)*(byte *)((int)param_1 + 0x2b1),
          (int)*(char *)((int)param_1 + 0x2b2),(uint)*(byte *)((int)param_1 + 0x2b3),uVar1 & 0xff);
  fprintf(DAT_08060620,"    opcode args  ");
  iVar4 = 1;
  while (iVar4 < (int)(uVar1 & 0xff)) {
    uVar2 = FUN_08057840(param_1);
    *(char *)(iVar4 + 0x2b5 + (int)param_1) = (char)uVar2;
    fprintf(DAT_08060620,"%d",uVar2);
    iVar4 = iVar4 + 1;
    if (iVar4 < (int)(uVar1 & 0xff)) {
      fprintf(DAT_08060620,", ");
    }
  }
  fprintf(DAT_08060620,"\n");
  param_1[0x85] = param_1[1];
  param_1[0x84] = 0;
  while( true ) {
    uVar1 = FUN_08057878(param_1,local_104,0x100);
    if (uVar1 == 0xffffffff) {
      return (int *)0x0;
    }
    FUN_08056a00((int)param_1,"directory \"%s\"");
    if (local_104[0] == '\0') break;
    iVar4 = FUN_08056d20((int)param_1,local_104);
    if (iVar4 == 0) {
      return (int *)0x0;
    }
  }
  while( true ) {
    uVar1 = FUN_08057878(param_1,local_104,0x100);
    if (uVar1 == 0xffffffff) {
      return (int *)0x0;
    }
    if (local_104[0] == '\0') break;
    uVar1 = FUN_08057a60(param_1);
    uVar2 = FUN_08057a60(param_1);
    uVar3 = FUN_08057a60(param_1);
    FUN_08056a00((int)param_1,"file \"%s\": dir %d time 0x%lx length %ld");
    iVar4 = FUN_08056c4c((int)param_1,local_104,uVar1,uVar2,uVar3);
    if (iVar4 == 0) {
      return (int *)0x0;
    }
  }
  FUN_08056a00((int)param_1,"file \"%s\"");
  FUN_08056e44((int)param_1);
  param_1[0x90] = 0;
  return param_1;
}



void FUN_080570d0(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  char *__format;
  
  puVar1 = (undefined4 *)FUN_08056dd0(param_1,*(uint *)(param_1 + 0x22c));
  uVar3 = *(uint *)(param_1 + 0x220);
  if (0x3c < uVar3) {
    fputc(10,DAT_08060620);
    uVar3 = 0;
  }
  fprintf(DAT_08060620,"%*s%.8lx: ",0x3c - uVar3,"",*(ulong *)(param_1 + 0x228));
  if (puVar1 == (undefined4 *)0x0) {
    fputc(0x3f,DAT_08060620);
  }
  else {
    if (puVar1[3] != 0) {
      iVar2 = FUN_08056e0c(param_1,puVar1[3]);
      if (iVar2 == 0) {
        iVar2 = puVar1[3];
        __format = "?dir %d?";
      }
      else {
        __format = "%s";
      }
      fprintf(DAT_08060620,__format,iVar2);
    }
    fprintf(DAT_08060620,"%s",(char *)*puVar1);
  }
  fprintf(DAT_08060620,":%ld.%ld",*(long *)(param_1 + 0x230),*(long *)(param_1 + 0x234));
  if (((*(int *)(param_1 + 0x238) != 0) || (*(int *)(param_1 + 0x23c) != 0)) ||
     (iVar2 = 0, *(int *)(param_1 + 0x240) != 0)) {
    fputc(0x20,DAT_08060620);
    iVar2 = *(int *)(param_1 + 0x238);
  }
  if (iVar2 != 0) {
    fputc(0x5b,DAT_08060620);
  }
  if (*(int *)(param_1 + 0x23c) != 0) {
    fputc(0x7b,DAT_08060620);
  }
  if (*(int *)(param_1 + 0x240) != 0) {
    fputc(0x5d,DAT_08060620);
  }
  fputc(10,DAT_08060620);
  *(undefined4 *)(param_1 + 0x220) = 0;
  return;
}



int * FUN_08057240(int *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  char **ppcVar5;
  undefined1 *puVar6;
  char *pcStack_240;
  char *pcStack_23c;
  char *pcVar7;
  char local_204 [256];
  char local_104 [256];
  
  uVar1 = FUN_08057840(param_1);
  switch(uVar1) {
  case 0:
    uVar1 = FUN_08057a60(param_1);
    uVar2 = FUN_08057840(param_1);
    if (uVar2 == 1) {
      FUN_08056a00((int)param_1,"DW_LNE_end sequence");
      FUN_080570d0((int)param_1);
      FUN_08056e44((int)param_1);
      param_1[0x90] = 1;
      return param_1;
    }
    if ((int)uVar2 < 2) {
      if (uVar2 == 0xffffffff) {
        return (int *)0x0;
      }
    }
    else {
      if (uVar2 == 2) {
        uVar1 = FUN_080578f4(param_1);
        param_1[0x8a] = uVar1;
        pcStack_23c = (char *)0x80572ff;
        pcStack_23c = FUN_08055660(local_104,param_1[1] - 4,uVar1,(uint)param_1[0x86] >> 0x1e & 1);
        ppcVar5 = &pcStack_240;
        pcStack_240 = "DW_LNE_set_address %s";
        break;
      }
      if (uVar2 == 3) {
        uVar1 = FUN_08057878(param_1,local_204,0x100);
        if (uVar1 == 0xffffffff) {
          return (int *)0x0;
        }
        if (local_204[0] != '\0') {
          uVar1 = FUN_08057a60(param_1);
          uVar2 = FUN_08057a60(param_1);
          uVar3 = FUN_08057a60(param_1);
          pcStack_240 = local_204;
          pcStack_23c = (char *)uVar1;
          FUN_08056a00((int)param_1,"DW_LNE_define_file %s dir %d time 0x%lx length %d");
          pcStack_23c = (char *)0x805738b;
          iVar4 = FUN_08056c4c((int)param_1,local_204,uVar1,uVar2,uVar3);
          if (iVar4 == 0) {
            return (int *)0x0;
          }
          return param_1;
        }
        return param_1;
      }
    }
    while (uVar1 = uVar1 - 1, uVar1 != 0) {
      FUN_08057840(param_1);
    }
    return param_1;
  case 1:
    puVar6 = &stack0xfffffdd4;
    FUN_08056a00((int)param_1,"DW_LNS_copy");
    goto LAB_080575b8;
  case 2:
    uVar1 = FUN_08057a60(param_1);
    param_1[0x8a] = param_1[0x8a] + *(byte *)(param_1 + 0xac) * uVar1;
    ppcVar5 = (char **)&stack0xfffffdd0;
    break;
  case 3:
    uVar1 = FUN_08057aa0(param_1);
    param_1[0x8c] = param_1[0x8c] + uVar1;
    ppcVar5 = (char **)&stack0xfffffdd0;
    break;
  case 4:
    uVar1 = FUN_08057a60(param_1);
    param_1[0x8b] = uVar1;
    ppcVar5 = (char **)&stack0xfffffdd0;
    break;
  case 5:
    uVar1 = FUN_08057a60(param_1);
    param_1[0x8d] = uVar1;
    ppcVar5 = (char **)&stack0xfffffdd0;
    break;
  case 6:
    param_1[0x8e] = (uint)(param_1[0x8e] == 0);
    pcVar7 = "DW_LNS_negate_stmt";
    goto LAB_08057513;
  case 7:
    param_1[0x8f] = 1;
    pcVar7 = "DW_LNS_set_basic_block";
    goto LAB_08057513;
  case 8:
    param_1[0x8a] =
         param_1[0x8a] +
         (int)((ulonglong)(byte)~*(byte *)(param_1 + 0xad) /
              (ulonglong)(longlong)(int)(uint)*(byte *)((int)param_1 + 0x2b3)) *
         (uint)*(byte *)(param_1 + 0xac);
    pcVar7 = "DW_LNS_const_add_pc";
LAB_08057513:
    FUN_08056a00((int)param_1,pcVar7);
    return param_1;
  case 9:
    uVar1 = FUN_080579d4(param_1);
    param_1[0x8a] = param_1[0x8a] + (uVar1 & 0xffff);
    ppcVar5 = (char **)&stack0xfffffdd0;
    break;
  case 0xffffffff:
    return (int *)0x0;
  default:
    if ((int)uVar1 < (int)(uint)*(byte *)(param_1 + 0xad)) {
      for (uVar1 = (uint)*(byte *)(uVar1 + 0x2b5 + (int)param_1); uVar1 != 0; uVar1 = uVar1 - 1) {
        FUN_08057a60(param_1);
      }
      pcVar7 = "Unknown standard opcode";
      goto LAB_08057513;
    }
    iVar4 = uVar1 - *(byte *)(param_1 + 0xad);
    puVar6 = &stack0xfffffdcc;
    FUN_08056a00((int)param_1,"SPECIAL(%d, %d)");
    param_1[0x8c] =
         param_1[0x8c] +
         iVar4 % (int)(uint)*(byte *)((int)param_1 + 0x2b3) + (int)*(char *)((int)param_1 + 0x2b2);
    param_1[0x8a] =
         param_1[0x8a] +
         (iVar4 / (int)(uint)*(byte *)((int)param_1 + 0x2b3)) * (uint)*(byte *)(param_1 + 0xac);
LAB_080575b8:
    *(int **)(puVar6 + -4) = param_1;
    *(undefined4 *)(puVar6 + -8) = 0x80575be;
    FUN_080570d0(*(int *)(puVar6 + -4));
    param_1[0x8f] = 0;
    return param_1;
  }
  ppcVar5[-1] = (char *)param_1;
  ppcVar5[-2] = (char *)0x80574df;
  FUN_08056a00((int)ppcVar5[-1],*ppcVar5);
  return param_1;
}



void FUN_080575d8(undefined4 *param_1)

{
  int *piVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  
  if ((uint)param_1[1] < (uint)param_1[2]) {
    do {
      piVar1 = FUN_08056b14(param_1);
      piVar2 = FUN_08056e8c(piVar1);
      if (piVar2 == (int *)0x0) {
        fputs("*** Error reading lineinfo header\n",DAT_08060620);
        return;
      }
      do {
        piVar2 = FUN_08057240(piVar1);
      } while (piVar2 != (int *)0x0);
      FUN_08056bb0(param_1,piVar1);
      uVar3 = param_1[1] + 3 & 0xfffffffc;
      uVar4 = param_1[1];
      if (uVar3 <= (uint)param_1[2]) {
        param_1[1] = uVar3;
        uVar4 = uVar3;
      }
    } while (uVar4 < (uint)param_1[2]);
  }
  return;
}



void FUN_08057650(int *param_1)

{
  uint uVar1;
  char local_204 [512];
  
  do {
    uVar1 = FUN_08057878(param_1,local_204,0x200);
    fprintf(DAT_08060620,"%s",local_204);
  } while (uVar1 == 1);
  fprintf(DAT_08060620,"\n");
  return;
}



void FUN_080576a8(int *param_1)

{
  uint uVar1;
  uint uVar2;
  char *__format;
  int iVar3;
  
  uVar1 = param_1[1];
  if (uVar1 < (uint)param_1[2]) {
LAB_080576c0:
    do {
      while( true ) {
        param_1[0x85] = uVar1;
        param_1[0x84] = 0;
        uVar1 = FUN_08057840(param_1);
        if (uVar1 != 2) break;
        uVar1 = FUN_08057a60(param_1);
        iVar3 = param_1[0x85];
        __format = "  %.6lx: line %ld undef ";
LAB_080577cc:
        fprintf(DAT_08060620,__format,iVar3,uVar1);
        FUN_08057650(param_1);
        uVar1 = param_1[1];
      }
      if (2 < (int)uVar1) {
        if (uVar1 == 4) {
          fprintf(DAT_08060620,"  %.6lx: end include\n",param_1[0x85]);
          uVar1 = param_1[1];
        }
        else if ((int)uVar1 < 4) {
          uVar1 = FUN_08057a60(param_1);
          uVar2 = FUN_08057a60(param_1);
          fprintf(DAT_08060620,"  %.6lx: include at line %ld - file %ld\n",param_1[0x85],uVar1,uVar2
                 );
          uVar1 = param_1[1];
        }
        else {
          if (uVar1 == 0xff) {
            uVar1 = FUN_08057a60(param_1);
            iVar3 = param_1[0x85];
            __format = "  %.6lx: vendor ext 0x%lx ";
            goto LAB_080577cc;
          }
LAB_080577e8:
          fprintf(DAT_08060620,"  %.6lx: unknown op %.2x\n",param_1[0x85],uVar1);
          uVar1 = param_1[1];
        }
        goto LAB_080576c0;
      }
      if (uVar1 != 0) {
        if (0 < (int)uVar1) {
          uVar1 = FUN_08057a60(param_1);
          iVar3 = param_1[0x85];
          __format = "  %.6lx: line %ld define ";
          goto LAB_080577cc;
        }
        if (uVar1 != 0xffffffff) goto LAB_080577e8;
        fprintf(DAT_08060620,"  %.6lx: Premature end of macro info\n",param_1[0x85]);
      }
      uVar2 = param_1[1] + 3U & 0xfffffffc;
      uVar1 = param_1[1];
      if (uVar2 <= (uint)param_1[2]) {
        param_1[1] = uVar2;
        uVar1 = uVar2;
      }
    } while (uVar1 < (uint)param_1[2]);
  }
  return;
}



uint FUN_08057840(int *param_1)

{
  byte bVar1;
  uint uVar2;
  
  if ((uint)param_1[1] < (uint)param_1[2]) {
    bVar1 = *(byte *)(param_1[1] + *param_1);
    uVar2 = (uint)bVar1;
    param_1[1] = param_1[1] + 1;
    if ((uint)param_1[0x84] < 0x200) {
      *(byte *)(param_1[0x84] + 0x10U + (int)param_1) = bVar1;
      param_1[0x84] = param_1[0x84] + 1;
    }
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



uint FUN_08057878(int *param_1,undefined1 *param_2,int param_3)

{
  uint uVar1;
  undefined1 *puVar2;
  int iVar3;
  
  iVar3 = 0;
  if (0 < param_3 + -1) {
    iVar3 = 0;
    puVar2 = param_2;
    do {
      uVar1 = FUN_08057840(param_1);
      if (uVar1 + 1 < 2) {
        *puVar2 = 0;
        return uVar1;
      }
      *puVar2 = (char)uVar1;
      puVar2 = puVar2 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < param_3 + -1);
  }
  param_2[iVar3] = 0;
  return 1;
}



void FUN_080578cc(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  *param_1 = param_2;
  param_1[3] = param_3;
  param_1[2] = param_3;
  param_1[1] = 0;
  param_1[0x84] = 0;
  return;
}



uint FUN_080578f4(int *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  if (param_1[0x87] == 0) {
    uVar1 = FUN_08057840(param_1);
    uVar2 = FUN_08057840(param_1);
    uVar3 = FUN_08057840(param_1);
    uVar2 = uVar1 | uVar2 << 8 | uVar3 << 0x10;
    uVar1 = FUN_08057840(param_1);
    uVar1 = uVar1 << 0x18;
  }
  else {
    uVar1 = FUN_08057840(param_1);
    uVar2 = FUN_08057840(param_1);
    uVar3 = FUN_08057840(param_1);
    uVar2 = uVar1 << 0x18 | uVar2 << 0x10 | uVar3 << 8;
    uVar1 = FUN_08057840(param_1);
  }
  return uVar2 | uVar1;
}



uint FUN_08057964(int *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  if (param_1[0x87] == 0) {
    uVar1 = FUN_08057840(param_1);
    uVar2 = FUN_08057840(param_1);
    uVar3 = FUN_08057840(param_1);
    uVar2 = uVar1 | uVar2 << 8 | uVar3 << 0x10;
    uVar1 = FUN_08057840(param_1);
    uVar1 = uVar1 << 0x18;
  }
  else {
    uVar1 = FUN_08057840(param_1);
    uVar2 = FUN_08057840(param_1);
    uVar3 = FUN_08057840(param_1);
    uVar2 = uVar1 << 0x18 | uVar2 << 0x10 | uVar3 << 8;
    uVar1 = FUN_08057840(param_1);
  }
  return uVar2 | uVar1;
}



uint FUN_080579d4(int *param_1)

{
  uint uVar1;
  uint uVar2;
  
  if (param_1[0x87] == 0) {
    uVar1 = FUN_08057840(param_1);
    uVar2 = FUN_08057840(param_1);
    uVar2 = uVar2 << 8;
  }
  else {
    uVar1 = FUN_08057840(param_1);
    uVar1 = uVar1 << 8;
    uVar2 = FUN_08057840(param_1);
  }
  return (uVar1 | uVar2) & 0xffff;
}



int FUN_08057a18(int *param_1)

{
  ushort uVar1;
  uint uVar2;
  ushort uVar3;
  
  if (param_1[0x87] == 0) {
    uVar2 = FUN_08057840(param_1);
    uVar3 = (ushort)uVar2;
    uVar2 = FUN_08057840(param_1);
    uVar1 = (ushort)(uVar2 << 8);
  }
  else {
    uVar2 = FUN_08057840(param_1);
    uVar3 = (ushort)(uVar2 << 8);
    uVar2 = FUN_08057840(param_1);
    uVar1 = (ushort)uVar2;
  }
  return (int)(short)(uVar3 | uVar1);
}



uint FUN_08057a60(int *param_1)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  
  bVar2 = 0;
  uVar3 = 0;
  do {
    uVar1 = FUN_08057840(param_1);
    if (uVar1 == 0xffffffff) {
      return 0xffffffff;
    }
    uVar3 = uVar3 | (uVar1 & 0x7f) << (bVar2 & 0x1f);
    bVar2 = bVar2 + 7;
  } while ((char)uVar1 < '\0');
  return uVar3;
}



uint FUN_08057aa0(int *param_1)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  
  bVar2 = 0;
  uVar3 = 0;
  do {
    uVar1 = FUN_08057840(param_1);
    if (uVar1 == 0xffffffff) {
      return 0xffffffff;
    }
    uVar3 = uVar3 | (uVar1 & 0x7f) << (bVar2 & 0x1f);
    bVar2 = bVar2 + 7;
  } while ((char)uVar1 < '\0');
  if ((uVar1 & 0x40) != 0) {
    uVar3 = uVar3 | -1 << (bVar2 & 0x1f);
  }
  return uVar3;
}



char * FUN_08057aec(int param_1,char *param_2)

{
  char *__format;
  
  switch(param_1) {
  case 1:
    param_2 = "DW_TAG_array_type";
    break;
  case 2:
    param_2 = "DW_TAG_class_type";
    break;
  case 3:
    param_2 = "DW_TAG_entry_point";
    break;
  case 4:
    param_2 = "DW_TAG_enumeration_type";
    break;
  case 5:
    param_2 = "DW_TAG_formal_parameter";
    break;
  default:
    if (param_1 - 0x4080U < 0xbf7f) {
      __format = "DW_TAG_user_%.4lx";
    }
    else {
      __format = "DW_TAG_unknown_%lx";
    }
    sprintf(param_2,__format,param_1);
    break;
  case 8:
    param_2 = "DW_TAG_imported_declaration";
    break;
  case 10:
    param_2 = "DW_TAG_label";
    break;
  case 0xb:
    param_2 = "DW_TAG_lexical_block";
    break;
  case 0xc:
    param_2 = "DW_TAG_local_variable";
    break;
  case 0xd:
    param_2 = "DW_TAG_member";
    break;
  case 0xf:
    param_2 = "DW_TAG_pointer_type";
    break;
  case 0x10:
    param_2 = "DW_TAG_reference_type";
    break;
  case 0x11:
    param_2 = "DW_TAG_compile_unit";
    break;
  case 0x12:
    param_2 = "DW_TAG_string_type";
    break;
  case 0x13:
    param_2 = "DW_TAG_structure_type";
    break;
  case 0x15:
    param_2 = "DW_TAG_subroutine_type";
    break;
  case 0x16:
    param_2 = "DW_TAG_typedef";
    break;
  case 0x17:
    param_2 = "DW_TAG_union_type";
    break;
  case 0x18:
    param_2 = "DW_TAG_unspecified_parameters";
    break;
  case 0x19:
    param_2 = "DW_TAG_variant";
    break;
  case 0x1a:
    param_2 = "DW_TAG_common_block";
    break;
  case 0x1b:
    param_2 = "DW_TAG_common_inclusion";
    break;
  case 0x1c:
    param_2 = "DW_TAG_inheritance";
    break;
  case 0x1d:
    param_2 = "DW_TAG_inlined_subroutine";
    break;
  case 0x1e:
    param_2 = "DW_TAG_module";
    break;
  case 0x1f:
    param_2 = "DW_TAG_ptr_to_member_type";
    break;
  case 0x20:
    param_2 = "DW_TAG_set_type";
    break;
  case 0x21:
    param_2 = "DW_TAG_subrange_type";
    break;
  case 0x22:
    param_2 = "DW_TAG_with_stmt";
    break;
  case 0x23:
    param_2 = "DW_TAG_access_declaration";
    break;
  case 0x24:
    param_2 = "DW_TAG_base_type";
    break;
  case 0x25:
    param_2 = "DW_TAG_catch_block";
    break;
  case 0x26:
    param_2 = "DW_TAG_const_type";
    break;
  case 0x27:
    param_2 = "DW_TAG_constant";
    break;
  case 0x28:
    param_2 = "DW_TAG_enumerator";
    break;
  case 0x29:
    param_2 = "DW_TAG_file_type";
    break;
  case 0x2a:
    param_2 = "DW_TAG_friend";
    break;
  case 0x2b:
    param_2 = "DW_TAG_namelist";
    break;
  case 0x2c:
    param_2 = "DW_TAG_namelist_item";
    break;
  case 0x2d:
    param_2 = "DW_TAG_packed_type";
    break;
  case 0x2e:
    param_2 = "DW_TAG_subprogram";
    break;
  case 0x2f:
    param_2 = "DW_TAG_template_type_param";
    break;
  case 0x30:
    param_2 = "DW_TAG_template_value_param";
    break;
  case 0x31:
    param_2 = "DW_TAG_thrown_type";
    break;
  case 0x32:
    param_2 = "DW_TAG_try_block";
    break;
  case 0x33:
    param_2 = "DW_TAG_variant_part";
    break;
  case 0x34:
    param_2 = "DW_TAG_variable";
    break;
  case 0x35:
    param_2 = "DW_TAG_volatile_type";
  }
  return param_2;
}



char * FUN_08057de4(uint param_1,char *param_2,undefined4 *param_3)

{
  char *__format;
  
  if (param_3 != (undefined4 *)0x0) {
    *param_3 = 0;
  }
  if (param_1 == 0x31) {
    return "DW_AT_abstract_origin";
  }
  if (param_1 < 0x32) {
    if (param_1 == 0x18) {
      return "DW_AT_import";
    }
    if (param_1 < 0x19) {
      if (param_1 == 0xd) {
        return "DW_AT_bit_size";
      }
      if (param_1 < 0xe) {
        if (param_1 == 3) {
          return "DW_AT_name";
        }
        if (param_1 < 4) {
          if (param_1 == 1) {
            return "DW_AT_sibling";
          }
          if (param_1 == 2) {
            return "DW_AT_location";
          }
        }
        else {
          if (param_1 == 0xb) {
            return "DW_AT_byte_size";
          }
          if (0xb < param_1) {
            return "DW_AT_bit_offset";
          }
          if (param_1 == 9) {
            return "DW_AT_ordering";
          }
        }
      }
      else {
        if (param_1 == 0x13) {
          return "DW_AT_language";
        }
        if (param_1 < 0x14) {
          if (param_1 == 0x11) {
            return "DW_AT_low_pc";
          }
          if (0x11 < param_1) {
            return "DW_AT_high_pc";
          }
          if (param_1 == 0x10) {
            return "DW_AT_stmt_list";
          }
        }
        else {
          if (param_1 == 0x16) {
            return "DW_AT_discr_value";
          }
          if (0x16 < param_1) {
            return "DW_AT_visibility";
          }
          if (param_1 == 0x15) {
            return "DW_AT_discr";
          }
        }
      }
    }
    else {
      if (param_1 == 0x21) {
        return "DW_AT_is_optional";
      }
      if (param_1 < 0x22) {
        if (param_1 == 0x1c) {
          return "DW_AT_const_value";
        }
        if (param_1 < 0x1d) {
          if (param_1 == 0x1a) {
            return "DW_AT_common_reference";
          }
          if (param_1 < 0x1b) {
            return "DW_AT_string_length";
          }
          return "DW_AT_comp_dir";
        }
        if (param_1 == 0x1e) {
          return "DW_AT_default_value";
        }
        if (param_1 < 0x1e) {
          return "DW_AT_containing_type";
        }
        if (param_1 == 0x20) {
          return "DW_AT_inline";
        }
      }
      else {
        if (param_1 == 0x2a) {
          return "DW_AT_return_addr";
        }
        if (param_1 < 0x2b) {
          if (param_1 == 0x25) {
            return "DW_AT_producer";
          }
          if (param_1 < 0x26) {
            if (param_1 == 0x22) {
              return "DW_AT_lower_bound";
            }
          }
          else if (param_1 == 0x27) {
            return "DW_AT_prototyped";
          }
        }
        else {
          if (param_1 == 0x2e) {
            return "DW_AT_stride_size";
          }
          if (param_1 < 0x2f) {
            if (param_1 == 0x2c) {
              return "DW_AT_start_scope";
            }
          }
          else if (param_1 == 0x2f) {
            return "DW_AT_upper_bound";
          }
        }
      }
    }
  }
  else {
    if (param_1 == 0x40) {
      return "DW_AT_frame_base";
    }
    if (param_1 < 0x41) {
      if (param_1 == 0x38) {
        return "DW_AT_data_member_location";
      }
      if (0x38 < param_1) {
        if (param_1 == 0x3c) {
          return "DW_AT_declaration";
        }
        if (0x3c < param_1) {
          if (param_1 == 0x3e) {
            if (param_3 != (undefined4 *)0x0) {
              *param_3 = &PTR_DAT_0805d554;
            }
            return "DW_AT_encoding";
          }
          if (param_1 < 0x3f) {
            return "DW_AT_discr_list";
          }
          return "DW_AT_external";
        }
        if (param_1 == 0x3a) {
          return "DW_AT_decl_file";
        }
        if (param_1 < 0x3b) {
          return "DW_AT_decl_column";
        }
        return "DW_AT_decl_line";
      }
      if (param_1 == 0x34) {
        return "DW_AT_artificial";
      }
      if (0x34 < param_1) {
        if (param_1 == 0x36) {
          return "DW_AT_calling_convention";
        }
        if (param_1 < 0x37) {
          return "DW_AT_base_types";
        }
        return "DW_AT_count";
      }
      if (param_1 == 0x32) {
        return "DW_AT_accessbility";
      }
      if (param_1 == 0x33) {
        return "DW_AT_address_class";
      }
    }
    else {
      if (param_1 == 0x48) {
        return "DW_AT_static_link";
      }
      if (param_1 < 0x49) {
        if (param_1 == 0x44) {
          return "DW_AT_namelist_item";
        }
        if (0x44 < param_1) {
          if (param_1 == 0x46) {
            return "DW_AT_segment";
          }
          if (param_1 < 0x47) {
            return "DW_AT_priority";
          }
          return "DW_AT_specification";
        }
        if (param_1 == 0x42) {
          return "DW_AT_identifier_case";
        }
        if (param_1 < 0x43) {
          return "DW_AT_friend";
        }
        return "DW_AT_macro_info";
      }
      if (param_1 == 0x4c) {
        return "DW_AT_virtuality";
      }
      if (param_1 < 0x4d) {
        if (param_1 == 0x4a) {
          return "DW_AT_use_location";
        }
        if (param_1 < 0x4b) {
          return "DW_AT_type";
        }
        return "DW_AT_variable_pointer";
      }
      if (param_1 == 0x2000) {
        return "DW_AT_proc_body (DW_AT_user_0)";
      }
      if (param_1 < 0x2001) {
        if (param_1 == 0x4d) {
          return "DW_AT_vtable_elem_location";
        }
      }
      else if (param_1 == 0x2001) {
        return "DW_AT_save_offset (DW_AT_user_1)";
      }
    }
  }
  if (param_1 - 0x2000 < 0x1ff0) {
    __format = "DW_AT_user_%.4lx";
  }
  else {
    __format = "DW_AT_unknown_%lx";
  }
  sprintf(param_2,__format,param_1);
  return param_2;
}



char * FUN_08058408(ulong param_1,char *param_2)

{
  switch(param_1) {
  case 1:
    param_2 = "DW_FORM_addr";
    break;
  case 2:
    param_2 = "DW_FORM_ref";
    break;
  case 3:
    param_2 = "DW_FORM_block2";
    break;
  case 4:
    param_2 = "DW_FORM_block4";
    break;
  case 5:
    param_2 = "DW_FORM_data2";
    break;
  case 6:
    param_2 = "DW_FORM_data4";
    break;
  case 7:
    param_2 = "DW_FORM_data8";
    break;
  case 8:
    param_2 = "DW_FORM_string";
    break;
  case 9:
    param_2 = "DW_FORM_block";
    break;
  case 10:
    param_2 = "DW_FORM_block1";
    break;
  case 0xb:
    param_2 = "DW_FORM_data1";
    break;
  case 0xc:
    param_2 = "DW_FORM_flag";
    break;
  case 0xd:
    param_2 = "DW_FORM_sdata";
    break;
  case 0xe:
    param_2 = "DW_FORM_strp";
    break;
  case 0xf:
    param_2 = "DW_FORM_udata";
    break;
  case 0x10:
    param_2 = "DW_FORM_ref_addr";
    break;
  case 0x11:
    param_2 = "DW_FORM_ref1";
    break;
  case 0x12:
    param_2 = "DW_FORM_ref2";
    break;
  case 0x13:
    param_2 = "DW_FORM_ref4";
    break;
  case 0x14:
    param_2 = "DW_FORM_ref8";
    break;
  case 0x15:
    param_2 = "DW_FORM_ref_udata";
    break;
  case 0x16:
    param_2 = "DW_FORM_indirect";
    break;
  default:
    sprintf(param_2,"DW_FORM_unknown_%lx",param_1);
  }
  return param_2;
}



void FUN_08058530(void)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = &DAT_0805f03c;
  iVar1 = DAT_0805f03c;
  while (iVar1 != -1) {
    (*(code *)*piVar2)();
    piVar2 = piVar2 + -1;
    iVar1 = *piVar2;
  }
  return;
}



void FUN_08058554(void)

{
  return;
}



void _DT_FINI(void)

{
  FUN_08048bc0();
  return;
}


