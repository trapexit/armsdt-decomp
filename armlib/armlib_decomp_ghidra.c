typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
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

typedef struct stat stat, *Pstat;

typedef ulonglong __u_quad_t;

typedef __u_quad_t __dev_t;

typedef ulong __ino_t;

typedef uint __mode_t;

typedef uint __nlink_t;

typedef uint __uid_t;

typedef uint __gid_t;

typedef long __blksize_t;

typedef long __blkcnt_t;

typedef struct timespec timespec, *Ptimespec;

typedef long __time_t;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

struct stat {
    __dev_t st_dev;
    ushort __pad1;
    __ino_t st_ino;
    __mode_t st_mode;
    __nlink_t st_nlink;
    __uid_t st_uid;
    __gid_t st_gid;
    __dev_t st_rdev;
    ushort __pad2;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    ulong __unused4;
    ulong __unused5;
};

typedef struct __dirstream __dirstream, *P__dirstream;

struct __dirstream {
};

typedef struct __dirstream DIR;

typedef struct dirent dirent, *Pdirent;

struct dirent {
    __ino_t d_ino;
    __off_t d_off;
    ushort d_reclen;
    uchar d_type;
    char d_name[256];
};

typedef void *__gnuc_va_list;

typedef __time_t time_t;

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
undefined FUN_0804a988;
undefined _DT_FINI;
int DAT_0804d640;
undefined *PTR_DAT_0804d63c;
dword DWORD_0804d64c;
undefined DAT_0804d7a4;
uint DAT_0804d844;
int DAT_0804d858;
undefined4 stderr;
char *DAT_0804d814;
void *DAT_0804d818;
void *DAT_0804d800;
void *DAT_0804d84c;
char *DAT_0804d850;
char *DAT_0804d860;
int DAT_0804d824;
void *DAT_0804d810;
int DAT_0804d82c;
int DAT_0804d830;
char *DAT_0804d858;
void *DAT_0804d804;
char *DAT_0804d854;
void *DAT_0804d808;
char *DAT_0804d85c;
void *DAT_0804d80c;
uint *DAT_0804d81c;
undefined4 DAT_0804d844;
undefined4 *DAT_0804d7d0;
int DAT_0804d848;
undefined DAT_0804d83c;
int DAT_0804d840;
undefined4 *DAT_0804d7d4;
int DAT_0804d84c;
undefined4 *DAT_0804d7c8;
int DAT_0804d850;
int DAT_0804d800;
int DAT_0804d834;
int *DAT_0804d81c;
int *DAT_0804d7c8;
int DAT_0804d838;
undefined4 DAT_0804d7c0;
char *DAT_0804d820;
undefined DAT_0804bd59;
int DAT_0804d828;
uint *DAT_0804d818;
uint *DAT_0804d84c;
int *DAT_0804d7d0;
uint DAT_0804d7c0;
uint DAT_0804d7c4;
uint *DAT_0804d80c;
uint *DAT_0804d808;
uint *DAT_0804d804;
int DAT_0804d860;
uint *DAT_0804d810;
undefined DAT_0804d7e0;
uint DAT_0804d644;
undefined4 *DAT_0804d7cc;
byte *DAT_0804d820;
undefined4 DAT_0804d830;
undefined4 DAT_0804d838;
undefined4 DAT_0804d828;
undefined4 DAT_0804d82c;
undefined DAT_0804c486;
undefined DAT_0804c4d6;
undefined DAT_0804c4db;
undefined DAT_0804c4df;
undefined DAT_0804c4e3;
undefined DAT_0804c4ef;
undefined DAT_0804c4f3;
int DAT_0804d7c4;
int DAT_0804d814;
uint DAT_0804d834;
int DAT_0804d7c8;
undefined4 DAT_0804d7cc;
undefined4 DAT_0804d7c8;
undefined4 DAT_0804d7d4;
undefined4 DAT_0804d7d0;
undefined4 DAT_0804d840;
undefined4 DAT_0804d860;
undefined4 DAT_0804d85c;
undefined4 DAT_0804d858;
undefined4 DAT_0804d854;
undefined4 DAT_0804d850;
undefined4 DAT_0804d810;
undefined4 DAT_0804d81c;
undefined4 DAT_0804d818;
undefined4 DAT_0804d800;
undefined4 DAT_0804d804;
undefined4 DAT_0804d80c;
undefined4 DAT_0804d808;
undefined4 DAT_0804d848;
undefined4 DAT_0804d824;
undefined4 DAT_0804d834;
undefined4 DAT_0804d814;
undefined4 DAT_0804d820;
undefined4 DAT_0804d880;
undefined4 DAT_0804d648;
int DAT_0804d648;
undefined DAT_0804c61f;
undefined DAT_0804c625;
undefined4 DAT_0804d650;

void _DT_INIT(void)

{
  func_0x00000000();
  FUN_08048a60();
  FUN_0804bb30();
  return;
}



void FUN_080487d0(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int mkdir(char *__path,__mode_t __mode)

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

int isgraph(int param_1)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int * __errno_location(void)

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



void __deregister_frame_info(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int __xstat(int __ver,char *__filename,stat *__stat_buf)

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

time_t time(time_t *__timer)

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



void __libc_start_main(void)

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

char * strrchr(char *__s,int __c)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * ctime(time_t *__timer)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int closedir(DIR *__dirp)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

DIR * opendir(char *__name)

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

int isalpha(int param_1)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

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

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

dirent * readdir(DIR *__dirp)

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
  
  __libc_start_main(FUN_0804a988,param_2,&stack0x00000004,_DT_INIT,_DT_FINI,param_1,auStack_4);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void FUN_08048a10(void)

{
  code *pcVar1;
  
  if (DAT_0804d640 == 0) {
    while (*(int *)PTR_DAT_0804d63c != 0) {
      pcVar1 = *(code **)PTR_DAT_0804d63c;
      PTR_DAT_0804d63c = PTR_DAT_0804d63c + 4;
      (*pcVar1)();
    }
    __deregister_frame_info(&DWORD_0804d64c);
    DAT_0804d640 = 1;
  }
  return;
}



void FUN_08048a58(void)

{
  return;
}



void FUN_08048a60(void)

{
  __register_frame_info(&DWORD_0804d64c,&DAT_0804d7a4);
  return;
}



void FUN_08048a80(void)

{
  return;
}



undefined4 FUN_08048a90(uint param_1)

{
  uint uVar1;
  
  FUN_0804abe0(0);
  if (param_1 != 0xc3cbc6c5) {
    FUN_0804abe0(1);
    uVar1 = FUN_0804ac1c(param_1);
    if (uVar1 != 0xc3cbc6c5) {
      FUN_0804abe0(0);
      return 0;
    }
  }
  DAT_0804d844 = param_1;
  return 1;
}



int FUN_08048ae0(byte *param_1,byte *param_2)

{
  int iVar1;
  
  while( true ) {
    if (*param_1 == 0x2a) {
      do {
        param_1 = param_1 + 1;
      } while (*param_1 == 0x2a);
      if (*param_2 == 0) break;
      do {
        iVar1 = FUN_08048ae0(param_1,param_2);
        if (iVar1 == 0) {
          return 0;
        }
        param_2 = param_2 + 1;
      } while (*param_2 != 0);
    }
    if (*param_2 == 0) break;
    if ((*param_1 != 0x3f) && ((*param_1 | 0x20) != (*param_2 | 0x20))) {
      return 1;
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + 1;
  }
  return (int)(char)*param_1;
}



char * FUN_08048b4c(int param_1,char *param_2)

{
  char *pcVar1;
  uint uVar2;
  int iVar3;
  char *__s1;
  
  __s1 = (char *)(param_1 + 0xc);
  uVar2 = FUN_0804ac1c(*(uint *)(param_1 + 4));
  pcVar1 = __s1 + uVar2 * 0x10;
  while( true ) {
    if (pcVar1 <= __s1) {
      return (char *)0x0;
    }
    if ((*(int *)(__s1 + 8) != 0) && (iVar3 = strncmp(__s1,param_2,8), iVar3 == 0)) break;
    __s1 = __s1 + 0x10;
  }
  return __s1;
}



char * FUN_08048ba4(uint *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  int iVar5;
  time_t local_8;
  
  uVar2 = FUN_0804ac1c(param_1[1]);
  uVar3 = FUN_0804ac1c(*param_1);
  if ((DAT_0804d858 == 0) || (param_1 == (uint *)0x0)) {
    param_2 = memcpy(param_2,"<unset date>",0xd);
  }
  else {
    uVar2 = uVar2 >> 0x10 | uVar3 << 0x10;
    uVar3 = uVar3 >> 0x10;
    if (uVar2 < 0x6e996a00) {
      uVar3 = uVar3 - 1;
    }
    uVar2 = uVar2 + 0x91669600;
    iVar5 = uVar3 - 0x33;
    local_8 = 0;
    while (iVar5 != 0) {
      if (uVar2 < 4000000000) {
        iVar5 = iVar5 + -1;
      }
      uVar2 = uVar2 + 0x1194d800;
      local_8 = local_8 + 40000000;
    }
    local_8 = uVar2 / 100 + local_8;
    if (local_8 < 0) {
      local_8 = 0;
    }
    pcVar4 = ctime(&local_8);
    strcpy(param_2,pcVar4);
    uVar2 = 0xffffffff;
    pcVar4 = param_2;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    param_2[~uVar2 - 2] = '\0';
  }
  return param_2;
}



void FUN_08048c94(int param_1,char *param_2)

{
  char *__format;
  
  fprintf(stderr,"%s: ","AOF Librarian");
  if (param_1 == 1) {
    __format = "(Warning) ";
  }
  else if (param_1 == 2) {
    __format = "(Error)   ";
  }
  else {
    if (param_1 < 3) goto LAB_08048ce8;
    __format = "(Fatal)   ";
  }
  fprintf(stderr,__format);
LAB_08048ce8:
  vfprintf(stderr,param_2,&stack0x0000000c);
  fprintf(stderr,"\n");
  if (1 < param_1) {
                    // WARNING: Subroutine does not return
    exit(1);
  }
  return;
}



void * FUN_08048d28(size_t param_1)

{
  void *__s;
  
  if ((int)param_1 < 1) {
    FUN_08048c94(2,"Zero or negative memory request %d.");
  }
  __s = malloc(param_1);
  if (__s == (void *)0x0) {
    FUN_08048c94(3,"Out of memory.");
  }
  memset(__s,0,param_1);
  return __s;
}



void FUN_08048d74(void)

{
  return;
}



void FUN_08048d7c(void)

{
  void *pvVar1;
  FILE *__stream;
  uint *puVar2;
  size_t sVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  void *pvVar9;
  FILE *pFVar10;
  char *pcVar11;
  
  __stream = fopen(DAT_0804d814,"rb");
  if (__stream == (FILE *)0x0) {
    FUN_08048c94(2,"Unable to open library %s.");
  }
  puVar2 = FUN_08048d28(0x1c);
  sVar3 = fread(puVar2,0xc,1,__stream);
  if (sVar3 != 1) goto LAB_080491c4;
  iVar4 = FUN_08048a90(*puVar2);
  if (iVar4 != 0) {
    uVar5 = FUN_0804ac1c(puVar2[2]);
    uVar6 = FUN_0804ac1c(puVar2[1]);
    if ((int)uVar5 <= (int)uVar6) {
      fseek(__stream,0,0);
      uVar5 = FUN_0804ac1c(puVar2[1]);
      uVar6 = uVar5 << 4 | 0xc;
      DAT_0804d818 = FUN_08048d28(uVar6);
      sVar3 = fread(DAT_0804d818,uVar6,1,__stream);
      if (sVar3 != 1) goto LAB_080491c4;
      DAT_0804d800 = FUN_08048d28(uVar5 * 4 + 4);
      iVar4 = 0;
      if (uVar5 < 0x80000000) {
        do {
          *(undefined4 *)((int)DAT_0804d800 + iVar4 * 4) = 0;
          iVar4 = iVar4 + 1;
        } while (iVar4 <= (int)uVar5);
      }
      pvVar1 = DAT_0804d818;
      DAT_0804d84c = DAT_0804d818;
      DAT_0804d850 = FUN_08048b4c((int)DAT_0804d818,"LIB_DIRY");
      if (DAT_0804d850 != (char *)0x0) {
        DAT_0804d860 = FUN_08048b4c((int)pvVar1,"OFL_SYMT");
        if ((DAT_0804d860 != (char *)0x0) && (*(int *)(DAT_0804d860 + 0xc) != 0)) {
          DAT_0804d824 = 1;
          uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d860 + 0xc));
          DAT_0804d810 = FUN_08048d28(uVar5);
          iVar4 = 0;
          uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d860 + 8));
          fseek(__stream,uVar5,iVar4);
          sVar3 = 1;
          pFVar10 = __stream;
          uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d860 + 0xc));
          sVar3 = fread(DAT_0804d810,uVar5,sVar3,pFVar10);
          if (sVar3 != 1) goto LAB_080491c4;
        }
        if (((DAT_0804d824 == 0) && (DAT_0804d82c == 0)) && (DAT_0804d830 == 0)) goto LAB_08049069;
        DAT_0804d858 = FUN_08048b4c((int)pvVar1,"LIB_VRSN");
        DAT_0804d804 = FUN_08048d28(4);
        iVar4 = 0;
        uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d858 + 8));
        fseek(__stream,uVar5,iVar4);
        sVar3 = fread(DAT_0804d804,4,1,__stream);
        if (sVar3 == 1) {
          DAT_0804d854 = FUN_08048b4c((int)pvVar1,"LIB_TIME");
          DAT_0804d808 = FUN_08048d28(8);
          iVar4 = 0;
          uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d854 + 8));
          fseek(__stream,uVar5,iVar4);
          sVar3 = fread(DAT_0804d808,8,1,__stream);
          if (sVar3 == 1) {
            DAT_0804d85c = FUN_08048b4c((int)pvVar1,"OFL_TIME");
            if (DAT_0804d85c != (char *)0x0) {
              DAT_0804d80c = FUN_08048d28(8);
              iVar4 = 0;
              uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d85c + 8));
              fseek(__stream,uVar5,iVar4);
              sVar3 = fread(DAT_0804d80c,8,1,__stream);
              if (sVar3 != 1) goto LAB_080491c4;
            }
LAB_08049069:
            uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 0xc));
            if (uVar5 == 0) {
              DAT_0804d844 = 0;
LAB_080491ac:
              fclose(__stream);
              return;
            }
            uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 0xc));
            DAT_0804d81c = FUN_08048d28(uVar5);
            iVar4 = 0;
            uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 8));
            fseek(__stream,uVar5,iVar4);
            sVar3 = 1;
            pFVar10 = __stream;
            uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 0xc));
            sVar3 = fread(DAT_0804d81c,uVar5,sVar3,pFVar10);
            puVar2 = DAT_0804d81c;
            if (sVar3 == 1) {
              uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 0xc));
              puVar7 = (uint *)(uVar5 + (int)puVar2);
              for (; puVar2 < puVar7; puVar2 = (uint *)((int)puVar2 + uVar5)) {
                uVar5 = FUN_0804ac1c(*puVar2);
                uVar5 = FUN_0804ac1c(*(uint *)(uVar5 * 0x10 + 0x14 + (int)pvVar1));
                uVar6 = FUN_0804ac1c(*puVar2);
                uVar6 = FUN_0804ac1c(*(uint *)(uVar6 * 0x10 + 0x18 + (int)pvVar1));
                uVar8 = FUN_0804ac1c(*puVar2);
                pvVar9 = FUN_08048d28(uVar6);
                *(void **)((int)DAT_0804d800 + uVar8 * 4) = pvVar9;
                fseek(__stream,uVar5,0);
                sVar3 = 1;
                pFVar10 = __stream;
                uVar5 = FUN_0804ac1c(*puVar2);
                sVar3 = fread(*(void **)((int)DAT_0804d800 + uVar5 * 4),uVar6,sVar3,pFVar10);
                if (sVar3 != 1) goto LAB_080491c4;
                uVar5 = FUN_0804ac1c(puVar2[1]);
              }
              goto LAB_080491ac;
            }
          }
        }
LAB_080491c4:
        pcVar11 = "Unable to read %s.";
        goto LAB_080491cf;
      }
    }
  }
  pcVar11 = "%s is not a library file.";
LAB_080491cf:
  FUN_08048c94(2,pcVar11);
  return;
}



bool FUN_080491e0(int param_1,int param_2)

{
  return (*(uint *)(param_1 + (param_2 >> 5) * 4) & 1 << ((byte)param_2 & 0x1f)) != 0;
}



int FUN_0804920c(int param_1,int param_2,int param_3)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = (uint *)((param_2 >> 5) * 4 + param_1);
  uVar1 = 1 << ((byte)param_2 & 0x1f);
  if (param_3 == 0) {
    *puVar2 = *puVar2 & ~uVar1;
  }
  else {
    *puVar2 = *puVar2 | uVar1;
  }
  return param_3;
}



uint FUN_08049250(byte *param_1)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 0;
  bVar1 = *param_1;
  while (bVar1 != 0) {
    uVar2 = (uint)*param_1 + uVar2 * 0x10;
    param_1 = param_1 + 1;
    uVar3 = uVar2 & 0xf0000000;
    if (uVar3 != 0) {
      uVar2 = uVar2 ^ uVar3 >> 0x18;
    }
    uVar2 = uVar2 & ~uVar3;
    bVar1 = *param_1;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08049290(byte *param_1,undefined4 param_2,undefined4 param_3,int param_4,undefined4 param_5
                 )

{
  byte bVar1;
  undefined4 *puVar2;
  bool bVar3;
  uint uVar4;
  undefined3 extraout_var;
  int iVar5;
  undefined4 *puVar6;
  byte *pbVar7;
  
  uVar4 = FUN_08049250(param_1);
  bVar3 = FUN_080491e0(0x804d880,uVar4 & 0x7fff);
  puVar2 = DAT_0804d7d0;
  if (CONCAT31(extraout_var,bVar3) == 0) {
    FUN_0804920c(0x804d880,uVar4 & 0x7fff,1);
  }
  else {
    for (; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      iVar5 = strcmp((char *)(puVar2 + 5),(char *)param_1);
      if (iVar5 == 0) {
        FUN_08048c94(2,"Duplicate library member %s.");
        return;
      }
    }
  }
  DAT_0804d848 = DAT_0804d848 + 1;
  _DAT_0804d83c = _DAT_0804d83c + (param_4 + 3U & 0xfffffffc);
  uVar4 = 0xffffffff;
  pbVar7 = param_1;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    bVar1 = *pbVar7;
    pbVar7 = pbVar7 + 1;
  } while (bVar1 != 0);
  uVar4 = ~uVar4 + 3 & 0xfffffffc;
  DAT_0804d840 = DAT_0804d840 + uVar4;
  puVar6 = FUN_08048d28(uVar4 + 0x18);
  strcpy((char *)(puVar6 + 5),(char *)param_1);
  puVar6[4] = param_2;
  puVar6[3] = param_5;
  puVar6[1] = param_3;
  puVar6[2] = param_4;
  *puVar6 = 0;
  puVar2 = puVar6;
  if (DAT_0804d7d4 != (undefined4 *)0x0) {
    *DAT_0804d7d4 = puVar6;
    puVar2 = DAT_0804d7d0;
  }
  DAT_0804d7d0 = puVar2;
  DAT_0804d7d4 = puVar6;
  return;
}



void FUN_08049394(void)

{
  uint *puVar1;
  undefined4 uVar2;
  bool bVar3;
  int iVar4;
  uint uVar5;
  uint *puVar6;
  int iVar7;
  uint uVar8;
  undefined4 *puVar9;
  uint *puVar10;
  uint *puVar11;
  
  iVar4 = DAT_0804d84c;
  puVar9 = DAT_0804d7c8;
  do {
    if (puVar9 == (undefined4 *)0x0) {
      return;
    }
    bVar3 = false;
    FUN_08048d74();
    puVar10 = DAT_0804d81c;
    if (DAT_0804d850 == 0) {
LAB_08049493:
      FUN_08048c94(2,"No match for %s.");
    }
    else {
      uVar5 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 0xc));
      puVar6 = (uint *)(uVar5 + (int)puVar10);
      for (; puVar10 < puVar6; puVar10 = (uint *)((int)puVar10 + uVar5)) {
        if (*puVar10 != 0) {
          puVar1 = puVar10 + 3;
          iVar7 = FUN_08048ae0((byte *)(puVar9 + 1),(byte *)puVar1);
          if (iVar7 == 0) {
            uVar5 = 0xffffffff;
            puVar11 = puVar1;
            do {
              if (uVar5 == 0) break;
              uVar5 = uVar5 - 1;
              uVar8 = *puVar11;
              puVar11 = (uint *)((int)puVar11 + 1);
            } while ((byte)uVar8 != 0);
            uVar8 = FUN_0804ac1c(*puVar10);
            uVar2 = *(undefined4 *)(DAT_0804d800 + uVar8 * 4);
            uVar8 = FUN_0804ac1c(*(uint *)(uVar8 * 0x10 + 0x18 + iVar4));
            bVar3 = true;
            if (DAT_0804d834 != 3) {
              FUN_08049290((byte *)puVar1,0,uVar2,uVar8,
                           (int)puVar10 + (~uVar5 + 3 & 0xfffffffc) + 0xc);
            }
            *puVar10 = 0;
          }
        }
        uVar5 = FUN_0804ac1c(puVar10[1]);
      }
      if (!bVar3) goto LAB_08049493;
    }
    puVar9 = (undefined4 *)*puVar9;
  } while( true );
}



void FUN_080494c0(byte *param_1)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  
  piVar4 = DAT_0804d81c;
  if (DAT_0804d850 != 0) {
    uVar2 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 0xc));
    piVar1 = (int *)(uVar2 + (int)piVar4);
    for (; piVar4 < piVar1; piVar4 = (int *)((int)piVar4 + uVar2)) {
      if (*piVar4 != 0) {
        iVar3 = FUN_08048ae0(param_1,(byte *)(piVar4 + 3));
        if (iVar3 == 0) {
          *piVar4 = 0;
        }
      }
      uVar2 = FUN_0804ac1c(piVar4[1]);
    }
  }
  return;
}



long FUN_0804951c(char *param_1)

{
  FILE *__stream;
  long lVar1;
  
  __stream = fopen(param_1,"rb");
  if (__stream == (FILE *)0x0) {
    lVar1 = -1;
  }
  else {
    fseek(__stream,0,2);
    lVar1 = ftell(__stream);
    fclose(__stream);
  }
  return lVar1;
}



void FUN_08049560(void)

{
  size_t sVar1;
  byte bVar2;
  byte *pbVar3;
  char *__dest;
  long lVar4;
  uint uVar5;
  int iVar6;
  byte *pbVar7;
  int local_30;
  byte *local_2c;
  int *local_28;
  undefined4 local_24 [2];
  int local_1c;
  int local_18;
  undefined4 local_14;
  byte local_c;
  byte local_b;
  undefined1 local_a;
  undefined1 local_9;
  undefined1 local_7;
  char local_6;
  
  local_28 = DAT_0804d7c8;
  if (DAT_0804d7c8 != (int *)0x0) {
    do {
      local_2c = (byte *)0x0;
      local_30 = 0;
      local_7 = 3;
      FUN_0804b15c((char *)(local_28 + 1),"o",&local_1c);
      if ((local_18 != 0) || (local_1c != 0)) {
        local_a = 0;
        local_9 = 0;
        sVar1 = local_c + 2 + (uint)local_b;
        local_2c = FUN_08048d28(sVar1);
        FUN_0804b2cc(&local_1c,0,local_2c,sVar1);
        uVar5 = 0xffffffff;
        pbVar3 = local_2c;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          bVar2 = *pbVar3;
          pbVar3 = pbVar3 + 1;
        } while (bVar2 != 0);
        local_30 = ~uVar5 - 1;
      }
      pbVar3 = (byte *)FUN_0804b900((char *)local_2c,local_14,local_24);
      if (pbVar3 == (byte *)0x0) {
        FUN_08048c94(2,"Can\'t find file %s.");
      }
      else {
        do {
          iVar6 = -1;
          pbVar7 = pbVar3;
          do {
            if (iVar6 == 0) break;
            iVar6 = iVar6 + -1;
            bVar2 = *pbVar7;
            pbVar7 = pbVar7 + 1;
          } while (bVar2 != 0);
          __dest = FUN_08048d28(local_30 - iVar6);
          if ((local_2c != (byte *)0x0) && (strcpy(__dest,(char *)local_2c), local_b != 0)) {
            __dest[local_30] = local_6;
            local_30 = local_30 + 1;
          }
          strcpy(__dest + local_30,(char *)pbVar3);
          lVar4 = FUN_0804951c(__dest);
          if (lVar4 < 0) {
            FUN_08048c94(2,"Can\'t find file %s.");
          }
          else {
            if (DAT_0804d838 != 0) {
              pbVar3 = (byte *)(__dest + local_c);
            }
            FUN_08049290(pbVar3,__dest,0,lVar4,&DAT_0804d7c0);
            FUN_080494c0(pbVar3);
          }
          pbVar3 = (byte *)FUN_0804b950(local_24);
        } while (pbVar3 != (byte *)0x0);
      }
      FUN_0804b998(local_24);
      local_28 = (int *)*local_28;
    } while (local_28 != (int *)0x0);
  }
  return;
}



void FUN_08049718(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  uint *puVar6;
  int iVar7;
  
  iVar1 = DAT_0804d84c;
  puVar5 = DAT_0804d81c;
  if (DAT_0804d850 != 0) {
    uVar2 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 0xc));
    puVar4 = (uint *)(uVar2 + (int)puVar5);
    for (; puVar5 < puVar4; puVar5 = (uint *)((int)puVar5 + uVar2)) {
      if (*puVar5 != 0) {
        uVar2 = 0xffffffff;
        puVar6 = puVar5 + 3;
        do {
          if (uVar2 == 0) break;
          uVar2 = uVar2 - 1;
          uVar3 = *puVar6;
          puVar6 = (uint *)((int)puVar6 + 1);
        } while ((byte)uVar3 != 0);
        iVar7 = (int)puVar5 + (~uVar2 + 3 & 0xfffffffc) + 0xc;
        uVar2 = FUN_0804ac1c(*puVar5);
        uVar2 = FUN_0804ac1c(*(uint *)(uVar2 * 0x10 + 0x18 + iVar1));
        uVar3 = FUN_0804ac1c(*puVar5);
        FUN_08049290((byte *)(puVar5 + 3),0,*(undefined4 *)(DAT_0804d800 + uVar3 * 4),uVar2,iVar7);
      }
      uVar2 = FUN_0804ac1c(puVar5[1]);
    }
  }
  return;
}



uint FUN_080497d0(char *param_1)

{
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  undefined1 local_7;
  
  local_7 = 3;
  FUN_0804b15c(param_1,"o",&local_1c);
  if (((DAT_0804d838 == 0) || (local_18 == 0)) &&
     ((local_10 == 0 || (local_18 = local_10, local_14 < local_10)))) {
    local_18 = local_14;
  }
  return local_18;
}



void FUN_0804980c(void)

{
  int iVar1;
  char cVar2;
  char *__src;
  char *pcVar3;
  FILE *__s;
  size_t sVar4;
  undefined4 *puVar5;
  uint uVar6;
  int iVar7;
  
  puVar5 = DAT_0804d7d0;
  do {
    if (puVar5 == (undefined4 *)0x0) {
      return;
    }
    __src = (char *)FUN_080497d0((char *)(puVar5 + 5));
    if (DAT_0804d820 != (char *)0x0) {
      uVar6 = 0xffffffff;
      pcVar3 = DAT_0804d820;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        cVar2 = *pcVar3;
        pcVar3 = pcVar3 + 1;
      } while (cVar2 != '\0');
      iVar1 = ~uVar6 - 1;
      iVar7 = -1;
      pcVar3 = __src;
      do {
        if (iVar7 == 0) break;
        iVar7 = iVar7 + -1;
        cVar2 = *pcVar3;
        pcVar3 = pcVar3 + 1;
      } while (cVar2 != '\0');
      pcVar3 = FUN_08048d28(iVar1 - iVar7);
      strcpy(pcVar3,DAT_0804d820);
      pcVar3[iVar1] = '/';
      strcpy(pcVar3 + ~uVar6,__src);
      __src = pcVar3;
    }
    __s = fopen(__src,"wb");
    if (__s == (FILE *)0x0) {
      FUN_08048c94(2,"Unable to open file %s.");
    }
    else {
      sVar4 = fwrite((void *)puVar5[1],puVar5[2],1,__s);
      if (sVar4 != 1) {
        FUN_08048c94(2,"Unable to write file %s.");
      }
      fclose(__s);
    }
    puVar5 = (undefined4 *)*puVar5;
  } while( true );
}



char * FUN_0804990c(char *param_1,char *param_2,uint param_3,uint param_4)

{
  uint uVar1;
  
  strncpy(param_1,param_2,8);
  uVar1 = FUN_0804ac1c(param_3);
  *(uint *)(param_1 + 8) = uVar1;
  uVar1 = FUN_0804ac1c(param_4);
  *(uint *)(param_1 + 0xc) = uVar1;
  return param_1;
}



void FUN_08049948(void)

{
  uint uVar1;
  char cVar2;
  int iVar3;
  uint *__ptr;
  FILE *__s;
  size_t sVar4;
  FILE *__stream;
  uint uVar5;
  uint *puVar6;
  uint uVar7;
  uint *puVar8;
  uint *puVar9;
  void *pvVar10;
  size_t sVar11;
  uint uVar12;
  int *__src;
  uint *puVar13;
  uint *puVar14;
  int *piVar15;
  size_t *psVar16;
  uint uVar17;
  int iVar18;
  char *pcVar19;
  size_t *local_50;
  size_t *local_34;
  uint *local_2c;
  int *local_28;
  uint *local_20;
  int local_1c;
  uint local_18;
  size_t local_14;
  uint local_10;
  uint local_8;
  
  local_14 = 0;
  local_1c = 0;
  local_34 = (size_t *)0x0;
  if (DAT_0804d848 != 0) {
    local_34 = FUN_08048d28(DAT_0804d848 * 8);
  }
  local_18 = DAT_0804d848 + 3;
  if (DAT_0804d828 != 0) {
    local_18 = DAT_0804d848 + 5;
  }
  uVar1 = DAT_0804d840 + DAT_0804d848 * 0x14;
  iVar3 = local_18 * 0x10;
  local_8 = iVar3 + 0x18 + uVar1;
  __ptr = FUN_08048d28(local_8 + 8);
  local_2c = __ptr + local_18 * 4 + 6;
  DAT_0804d818 = __ptr;
  DAT_0804d81c = local_2c;
  DAT_0804d84c = __ptr;
  __s = fopen(DAT_0804d814,"wb");
  if (__s == (FILE *)0x0) {
    FUN_08048c94(2,"Unable to open file %s.");
  }
  sVar4 = fwrite(__ptr,1,local_8,__s);
  if (sVar4 != local_8) {
    FUN_08048c94(2,"Error writing file %s.");
  }
  local_10 = 3;
  local_28 = DAT_0804d7d0;
  local_20 = __ptr + 0xf;
  if (DAT_0804d7d0 != (int *)0x0) {
    local_50 = local_34;
    do {
      __src = local_28 + 5;
      pvVar10 = (void *)local_28[1];
      if (pvVar10 == (void *)0x0) {
        piVar15 = (int *)local_28[4];
        if ((int *)local_28[4] == (int *)0x0) {
          piVar15 = __src;
        }
        if (local_28[2] == 0) {
          pcVar19 = "Zero-length file: %s";
        }
        else {
          __stream = fopen((char *)piVar15,"rb");
          pvVar10 = FUN_08048d28(local_28[2]);
          local_28[1] = (int)pvVar10;
          if (__stream != (FILE *)0x0) {
            sVar4 = fread((void *)local_28[1],local_28[2],1,__stream);
            if (sVar4 != 1) {
              FUN_08048c94(2,"Unable to read %s.");
            }
            fclose(__stream);
            pvVar10 = (void *)local_28[1];
            goto LAB_08049b1a;
          }
          pcVar19 = "Unable to open file %s.";
        }
        FUN_08048c94(2,pcVar19);
        pvVar10 = (void *)local_28[1];
      }
LAB_08049b1a:
      sVar4 = fwrite(pvVar10,1,local_28[2],__s);
      if (sVar4 != local_28[2]) {
        FUN_08048c94(2,"Error writing file %s.");
      }
      puVar9 = (uint *)local_28[1];
      if ((DAT_0804d844 == 0) && (local_28 == DAT_0804d7d0)) {
        FUN_08048a90(*puVar9);
      }
      puVar13 = local_20 + 4;
      FUN_0804990c((char *)local_20,"LIB_DATA",local_8,local_28[2]);
      for (local_8 = local_8 + local_28[2]; (local_8 & 3) != 0; local_8 = local_8 + 1) {
        sVar4 = fwrite(&DAT_0804bd59,1,1,__s);
        if (sVar4 != 1) {
          FUN_08048c94(2,"Error writing file %s.");
        }
      }
      uVar5 = FUN_0804ac1c(local_10);
      *local_2c = uVar5;
      uVar5 = 0xffffffff;
      piVar15 = __src;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        iVar18 = *piVar15;
        piVar15 = (int *)((int)piVar15 + 1);
      } while ((char)iVar18 != '\0');
      uVar17 = ~uVar5 + 3 & 0xfffffffc;
      uVar5 = FUN_0804ac1c(uVar17 + 8);
      local_2c[2] = uVar5;
      uVar5 = FUN_0804ac1c(uVar17 + 0x14);
      local_2c[1] = uVar5;
      strncpy((char *)(local_2c + 3),(char *)__src,uVar17);
      uVar5 = FUN_0804ac1c(local_2c[1]);
      local_2c = (uint *)((int)local_2c + uVar5);
      uVar5 = ((uint *)local_28[3])[1];
      local_2c[-2] = *(uint *)local_28[3];
      local_2c[-1] = uVar5;
      if (DAT_0804d828 != 0) {
        if ((*puVar9 ^ DAT_0804d844) == 0x60d0d06) {
          pcVar19 = "Library member %s has different bytesex.";
          iVar18 = 2;
        }
        else if (*puVar9 == DAT_0804d844) {
          if (0x1b < (uint)local_28[2]) {
            uVar5 = FUN_0804ac1c(puVar9[2]);
            uVar17 = FUN_0804ac1c(puVar9[1]);
            if (((int)uVar5 <= (int)uVar17) &&
               (pcVar19 = FUN_08048b4c((int)puVar9,"OBJ_HEAD"), pcVar19 != (char *)0x0)) {
              uVar5 = FUN_0804ac1c(*(uint *)(pcVar19 + 8));
              pcVar19 = FUN_08048b4c((int)puVar9,"OBJ_SYMT");
              if (pcVar19 == (char *)0x0) {
                pcVar19 = "No symbol table in %s.";
              }
              else {
                uVar17 = FUN_0804ac1c(*(uint *)(pcVar19 + 8));
                puVar6 = (uint *)(uVar17 + (int)puVar9);
                pcVar19 = FUN_08048b4c((int)puVar9,"OBJ_STRT");
                if (pcVar19 == (char *)0x0) {
                  pcVar19 = "No string table in %s.";
                  iVar18 = 2;
                  goto LAB_08049dd6;
                }
                uVar17 = FUN_0804ac1c(*(uint *)(pcVar19 + 8));
                uVar5 = FUN_0804ac1c(*(uint *)((int)puVar9 + uVar5 + 0xc));
                sVar4 = 0;
                for (puVar8 = puVar6; puVar8 < puVar6 + uVar5 * 4; puVar8 = puVar8 + 4) {
                  uVar7 = FUN_0804ac1c(puVar8[1]);
                  if ((uVar7 & 3) == 3) {
                    uVar7 = FUN_0804ac1c(*puVar8);
                    uVar12 = 0xffffffff;
                    pcVar19 = (char *)((int)puVar9 + uVar7 + uVar17);
                    do {
                      if (uVar12 == 0) break;
                      uVar12 = uVar12 - 1;
                      cVar2 = *pcVar19;
                      pcVar19 = pcVar19 + 1;
                    } while (cVar2 != '\0');
                    sVar4 = (~uVar12 + 3 & 0xfffffffc) + 0xc + sVar4;
                  }
                }
                local_14 = local_14 + sVar4;
                if (sVar4 != 0) {
                  *local_50 = sVar4;
                  puVar8 = FUN_08048d28(sVar4);
                  local_34[local_1c * 2 + 1] = (size_t)puVar8;
                  local_50 = local_50 + 2;
                  local_1c = local_1c + 1;
                  puVar14 = puVar6 + uVar5 * 4;
                  for (; puVar6 < puVar14; puVar6 = puVar6 + 4) {
                    uVar5 = FUN_0804ac1c(puVar6[1]);
                    if ((uVar5 & 3) == 3) {
                      uVar5 = FUN_0804ac1c(*puVar6);
                      uVar7 = 0xffffffff;
                      pcVar19 = (char *)((int)puVar9 + uVar5 + uVar17);
                      do {
                        if (uVar7 == 0) break;
                        uVar7 = uVar7 - 1;
                        cVar2 = *pcVar19;
                        pcVar19 = pcVar19 + 1;
                      } while (cVar2 != '\0');
                      uVar12 = ~uVar7 + 3 & 0xfffffffc;
                      uVar5 = FUN_0804ac1c(local_10);
                      *puVar8 = uVar5;
                      uVar5 = FUN_0804ac1c(uVar12);
                      puVar8[2] = uVar5;
                      uVar5 = uVar12 + 0xc;
                      uVar7 = FUN_0804ac1c(uVar5);
                      puVar8[1] = uVar7;
                      uVar7 = FUN_0804ac1c(*puVar6);
                      strncpy((char *)(puVar8 + 3),(char *)((int)puVar9 + uVar7 + uVar17),uVar12);
                      puVar8 = (uint *)((int)puVar8 + uVar5);
                    }
                  }
                  goto LAB_08049eb9;
                }
                pcVar19 = "No exported symbols in %s.";
              }
              iVar18 = 1;
              goto LAB_08049dd6;
            }
          }
          pcVar19 = "Bad library member %s.";
          iVar18 = 2;
        }
        else {
          pcVar19 = "Library member %s is not a chunk file.";
          iVar18 = 2;
        }
LAB_08049dd6:
        FUN_08048c94(iVar18,pcVar19);
      }
LAB_08049eb9:
      local_10 = local_10 + 1;
      local_28 = (int *)*local_28;
      local_20 = puVar13;
    } while (local_28 != (int *)0x0);
  }
  if (DAT_0804d844 == 0xc5c6cbc3) {
    DAT_0804d7c0 = FUN_0804ac1c(DAT_0804d7c0);
    DAT_0804d7c4 = FUN_0804ac1c(DAT_0804d7c4);
  }
  if (DAT_0804d828 != 0) {
    DAT_0804d85c = FUN_0804990c((char *)local_20,"OFL_TIME",local_8,8);
    puVar9 = FUN_08048d28(8);
    uVar5 = DAT_0804d7c4;
    DAT_0804d80c = puVar9;
    *puVar9 = DAT_0804d7c0;
    puVar9[1] = uVar5;
    sVar4 = fwrite(DAT_0804d80c,8,1,__s);
    if (sVar4 != 1) {
      FUN_08048c94(2,"Error writing file %s.");
    }
    DAT_0804d860 = FUN_0804990c((char *)(local_20 + 4),"OFL_SYMT",local_8 + 8,local_14);
    if (0 < (int)local_14) {
      pvVar10 = FUN_08048d28(local_14);
      local_1c = 0;
      DAT_0804d810 = pvVar10;
      if (0 < DAT_0804d848) {
        psVar16 = local_34 + 1;
        do {
          memcpy(pvVar10,(void *)*psVar16,*local_34);
          pvVar10 = (void *)((int)pvVar10 + *local_34);
          local_34 = local_34 + 2;
          psVar16 = psVar16 + 2;
          local_1c = local_1c + 1;
        } while (local_1c < DAT_0804d848);
      }
      sVar4 = fwrite(DAT_0804d810,local_14,1,__s);
      if (sVar4 != 1) {
        FUN_08048c94(2,"Error writing file %s.");
      }
    }
  }
  uVar5 = DAT_0804d844;
  if (DAT_0804d844 == 0) {
    uVar5 = 0xc3cbc6c5;
  }
  *__ptr = uVar5;
  uVar5 = FUN_0804ac1c(local_18);
  __ptr[2] = uVar5;
  __ptr[1] = uVar5;
  DAT_0804d854 = FUN_0804990c((char *)(__ptr + 3),"LIB_TIME",iVar3 + 0xc,8);
  uVar5 = DAT_0804d7c4;
  puVar9 = __ptr + local_18 * 4 + 3;
  DAT_0804d808 = puVar9;
  *puVar9 = DAT_0804d7c0;
  puVar9[1] = uVar5;
  DAT_0804d858 = FUN_0804990c((char *)(__ptr + 7),"LIB_VRSN",iVar3 + 0x14,4);
  DAT_0804d804 = __ptr + local_18 * 4 + 5;
  uVar5 = FUN_0804ac1c(1);
  *DAT_0804d804 = uVar5;
  DAT_0804d850 = FUN_0804990c((char *)(__ptr + 0xb),"LIB_DIRY",iVar3 + 0x18,uVar1);
  sVar4 = uVar1 + 0x18 + iVar3;
  fseek(__s,0,0);
  sVar11 = fwrite(__ptr,1,sVar4,__s);
  if (sVar11 != sVar4) {
    FUN_08048c94(2,"Error writing file %s.");
  }
  fclose(__s);
  return;
}



void FUN_0804a170(void)

{
  uint *puVar1;
  undefined4 *puVar2;
  char *pcVar3;
  uint uVar4;
  void *pvVar5;
  uint *puVar6;
  uint *puVar7;
  uint *puVar8;
  char local_54 [80];
  
  if (DAT_0804d82c != 0) {
    if (DAT_0804d858 == 0) {
      printf("\nFormat version: (no version number)\n");
    }
    else {
      uVar4 = FUN_0804ac1c(*DAT_0804d804);
      printf("\nFormat version: %d\n",uVar4);
    }
    pcVar3 = FUN_08048ba4(DAT_0804d808,local_54);
    printf("Last Modification: %s\n",pcVar3);
    printf("\nContents:\n\n");
    for (puVar2 = DAT_0804d7d0; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      pcVar3 = FUN_08048ba4((uint *)puVar2[3],local_54);
      printf("  %-40s %10d   %s\n",(char *)(puVar2 + 5),puVar2[2],pcVar3);
    }
    printf("\nEnd of Library\n");
  }
  if (DAT_0804d830 != 0) {
    if (DAT_0804d860 == 0) {
      FUN_08048c94(2,"No external symbol table.");
    }
    if (DAT_0804d82c != 0) {
      printf("\n");
    }
    uVar4 = FUN_0804ac1c(*(uint *)(DAT_0804d84c + 4));
    pvVar5 = FUN_08048d28(uVar4 << 2);
    uVar4 = FUN_0804ac1c(*(uint *)(DAT_0804d84c + 4));
    puVar6 = FUN_08048d28(uVar4 * 4 + 4);
    puVar7 = DAT_0804d81c;
    uVar4 = FUN_0804ac1c(*(uint *)(DAT_0804d850 + 0xc));
    puVar1 = (uint *)(uVar4 + (int)puVar7);
    puVar8 = puVar6;
    for (; puVar7 < puVar1; puVar7 = (uint *)((int)puVar7 + uVar4)) {
      uVar4 = FUN_0804ac1c(*puVar7);
      *(uint **)((int)pvVar5 + uVar4 * 4) = puVar7 + 3;
      uVar4 = FUN_0804ac1c(*puVar7);
      puVar8 = puVar8 + 1;
      *puVar8 = uVar4;
      uVar4 = FUN_0804ac1c(puVar7[1]);
    }
    pcVar3 = FUN_08048ba4(DAT_0804d80c,local_54);
    printf("External Symbol Table, generated: %s\n\n",pcVar3);
    puVar8 = DAT_0804d810;
    uVar4 = FUN_0804ac1c(*(uint *)(DAT_0804d860 + 0xc));
    puVar1 = (uint *)(uVar4 + (int)puVar8);
    for (; puVar8 < puVar1; puVar8 = (uint *)((int)puVar8 + uVar4)) {
      uVar4 = *puVar8;
      if (uVar4 != 0) {
        if (DAT_0804d858 == 0) {
          uVar4 = puVar6[uVar4];
          *puVar8 = uVar4;
        }
        uVar4 = FUN_0804ac1c(uVar4);
        printf("  %-40s from   %s\n",(char *)(puVar8 + 3),*(char **)((int)pvVar5 + uVar4 * 4));
      }
      uVar4 = FUN_0804ac1c(puVar8[1]);
    }
    printf("\nEnd of Table\n");
  }
  return;
}



void FUN_0804a378(void)

{
  printf("%s version %s [%s]\n       - AOF library creation and maintenance tool\n\nCommand format:\n\n%s options library [ file_list | member_list ]\n\n"
         ,"AOF Librarian","4.50 (ARM Ltd SDT2.51)","Build number 130",&DAT_0804d7e0);
  printf("Wildcards \'%c\' and \'*\' may be used in <member_list>\n\n",'?');
  printf(
        "Options:-\n\n-c      Create a new library containing files in <file_list>.\n-i      Insert files in <file_list>, replace existing members of the same name.\n-d      Delete the members in <member_list>.\n-e      Extract members in <member_list> placing in files of the same name.\n"
        );
  printf(
        "-o      Add an external symbol table to an object library (DEFAULT).\n-n      Do not add an external symbol table to an object library.\n-p      Respect paths of files and objects.\n-l      List library, may be specified with any other option.\n-s      List symbol table, may be specified with any other option.\n-t dir  Extract files to <dir> directory.\n-v file Take additional arguments from via file.\n\n"
        );
  printf("Examples:-\n\n        %s -c mylib obj1 obj2 obj3...\n        %s -e mylib %csort*\n        %s -d mylib hash.o\n        %s -i mylib quick_sort.o quick_hash1.o\n        %s -l -s ansilib\n\n"
         ,&DAT_0804d7e0,&DAT_0804d7e0,'?',&DAT_0804d7e0,&DAT_0804d7e0,&DAT_0804d7e0);
  return;
}



char * FUN_0804a3e4(char *param_1)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  char *pcVar4;
  
  bVar2 = false;
  cVar1 = *param_1;
  pcVar4 = param_1;
  while (iVar3 = (int)cVar1, iVar3 != 0) {
    if (iVar3 == 0x27) {
      bVar2 = (bool)(bVar2 ^ 1);
    }
    else {
      iVar3 = isgraph(iVar3);
      if ((iVar3 == 0) && (!bVar2)) break;
      if (pcVar4 != param_1) {
        *pcVar4 = cVar1;
      }
      pcVar4 = pcVar4 + 1;
    }
    param_1 = param_1 + 1;
    cVar1 = *param_1;
  }
  while ((*param_1 != '\0' && (iVar3 = isgraph((int)*param_1), iVar3 == 0))) {
    param_1 = param_1 + 1;
  }
  *pcVar4 = '\0';
  return param_1;
}



void FUN_0804a458(byte *param_1)

{
  byte bVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  char *pcVar4;
  byte *pbVar5;
  FILE *__stream;
  size_t __size;
  byte *__ptr;
  size_t sVar6;
  int iVar7;
  uint uVar8;
  int local_c;
  byte *local_8;
  
  for (; (bVar1 = *param_1, bVar1 != 0 && ((char)bVar1 < '!')); param_1 = param_1 + 1) {
  }
  do {
    if (bVar1 == 0) {
      return;
    }
    local_8 = (byte *)FUN_0804a3e4((char *)param_1);
    if (*param_1 == 0x2d) {
      while (param_1 = param_1 + 1, puVar2 = DAT_0804d7c8, puVar3 = DAT_0804d7cc, *param_1 != 0) {
        DAT_0804d644 = (uint)(DAT_0804d814 != (char *)0x0);
        local_c = 0;
        switch(*param_1 | 0x20) {
        case 0x66:
        case 0x6d:
          iVar7 = FUN_08048ae0((byte *)"files",param_1);
          if ((iVar7 == 0) || (iVar7 = FUN_08048ae0((byte *)"memb*",param_1), iVar7 == 0)) {
            param_1 = &DAT_0804c486;
          }
          DAT_0804d644 = 1;
          break;
        default:
          pcVar4 = "Unrecognised option(s) -%s.";
LAB_0804a5ba:
          FUN_08048c94(2,pcVar4);
          break;
        case 0x68:
          FUN_0804a378();
                    // WARNING: Subroutine does not return
          exit(0);
        case 0x69:
          iVar7 = FUN_08048ae0(&DAT_0804c4e3,param_1);
          if (iVar7 == 0) {
            param_1 = &DAT_0804c486;
          }
          local_c = 1;
        case 100:
          iVar7 = FUN_08048ae0((byte *)"delet*",param_1);
          if (iVar7 == 0) {
            param_1 = &DAT_0804c486;
          }
          local_c = local_c + 1;
        case 0x65:
          iVar7 = FUN_08048ae0(&DAT_0804c4ef,param_1);
          if (iVar7 == 0) {
            param_1 = &DAT_0804c486;
          }
          local_c = local_c + 1;
        case 99:
          iVar7 = FUN_08048ae0(&DAT_0804c4f3,param_1);
          if (iVar7 == 0) {
            param_1 = &DAT_0804c486;
          }
          local_c = local_c + 1;
          break;
        case 0x6c:
          iVar7 = FUN_08048ae0(&DAT_0804c4d6,param_1);
          if (iVar7 == 0) {
            DAT_0804d644 = 0;
            param_1 = &DAT_0804c486;
          }
          else {
            DAT_0804d82c = 1;
          }
          break;
        case 0x6e:
          DAT_0804d828 = 0;
          break;
        case 0x6f:
          iVar7 = FUN_08048ae0(&DAT_0804c4db,param_1);
          if (iVar7 == 0) {
            param_1 = &DAT_0804c486;
          }
          DAT_0804d828 = 1;
          break;
        case 0x70:
          DAT_0804d838 = 1;
          break;
        case 0x73:
          iVar7 = FUN_08048ae0(&DAT_0804c4df,param_1);
          if (iVar7 == 0) {
            param_1 = &DAT_0804c486;
          }
          DAT_0804d830 = 1;
          break;
        case 0x74:
          DAT_0804d820 = local_8;
          if (*local_8 == 0) {
            FUN_08048c94(2,"No directory path supplied for -d option.");
          }
          local_8 = (byte *)FUN_0804a3e4((char *)DAT_0804d820);
          break;
        case 0x76:
          if (*local_8 == 0) {
            FUN_08048c94(2,"No filename supplied for -via option.");
          }
          pbVar5 = (byte *)FUN_0804a3e4((char *)local_8);
          __stream = fopen((char *)local_8,"rb");
          if (__stream == (FILE *)0x0) {
            pcVar4 = "Can\'t find file %s.";
            param_1 = local_8;
            local_8 = pbVar5;
            goto LAB_0804a5ba;
          }
          fseek(__stream,0,2);
          __size = ftell(__stream);
          fseek(__stream,0,0);
          __ptr = FUN_08048d28(__size + 1);
          sVar6 = fread(__ptr,__size,1,__stream);
          if (sVar6 == 1) {
            __ptr[__size] = 0;
            FUN_0804a458(__ptr);
            local_8 = &DAT_0804c486;
          }
          else {
            FUN_08048c94(2,"Unable to read %s.");
          }
          fclose(__stream);
          param_1 = local_8;
          local_8 = pbVar5;
        }
        if (local_c != 0) {
          if (DAT_0804d834 != 0) {
            FUN_08048c94(2,"Only one of -c, -i, -d and -e may be used.");
          }
          DAT_0804d834 = local_c;
        }
      }
    }
    else if (DAT_0804d644 == 0) {
      if (DAT_0804d814 != (char *)0x0) {
        FUN_08048c94(2,"Multiple libraries: %s amd %s.");
      }
      uVar8 = 0xffffffff;
      pbVar5 = param_1;
      do {
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        bVar1 = *pbVar5;
        pbVar5 = pbVar5 + 1;
      } while (bVar1 != 0);
      pcVar4 = FUN_08048d28(~uVar8);
      DAT_0804d814 = strcpy(pcVar4,(char *)param_1);
      DAT_0804d644 = 1;
      puVar2 = DAT_0804d7c8;
      puVar3 = DAT_0804d7cc;
    }
    else {
      uVar8 = 0xffffffff;
      pbVar5 = param_1;
      do {
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        bVar1 = *pbVar5;
        pbVar5 = pbVar5 + 1;
      } while (bVar1 != 0);
      puVar3 = FUN_08048d28(~uVar8 + 7);
      strcpy((char *)(puVar3 + 1),(char *)param_1);
      *puVar3 = 0;
      puVar2 = puVar3;
      if (DAT_0804d7cc != (undefined4 *)0x0) {
        *DAT_0804d7cc = puVar3;
        puVar2 = DAT_0804d7c8;
      }
    }
    DAT_0804d7cc = puVar3;
    DAT_0804d7c8 = puVar2;
    bVar1 = *local_8;
    param_1 = local_8;
  } while( true );
}



void FUN_0804a820(byte *param_1,int *param_2)

{
  DAT_0804d7c4 = *param_2 << 0x10;
  DAT_0804d7c0 = (uint)*(uint3 *)((int)param_2 + 2);
  for (; (*param_1 != 0 && ((char)*param_1 < '!')); param_1 = param_1 + 1) {
  }
  FUN_0804a458(param_1);
  if (DAT_0804d814 == 0) {
    FUN_08048c94(2,"No library file specified.");
  }
  if ((((DAT_0804d828 == 0) && (DAT_0804d82c == 0)) && (DAT_0804d834 == 0)) && (DAT_0804d830 == 0))
  {
    FUN_08048c94(2,"Please use at least one of -c, -i, -d, -e, -o, -l or -s.");
  }
  if (DAT_0804d834 < 2) {
LAB_0804a8d0:
    if (DAT_0804d7c8 == 0) goto LAB_0804a8f1;
  }
  else if (DAT_0804d7c8 == 0) {
    FUN_08048c94(2,"No file or member list specified.");
    goto LAB_0804a8d0;
  }
  if (DAT_0804d834 == 0) {
    FUN_08048c94(2,"Invalid file or member list.");
  }
LAB_0804a8f1:
  FUN_08048d74();
  if (DAT_0804d834 != 1) {
    FUN_08048d7c();
  }
  if (DAT_0804d834 - 2 < 2) {
    FUN_08049394();
    if (DAT_0804d834 == 2) {
      FUN_0804980c();
      DAT_0804d834 = 0;
    }
  }
  else {
    FUN_08049560();
  }
  FUN_08049718();
  if (DAT_0804d824 != 0) {
    DAT_0804d828 = DAT_0804d824;
  }
  if (((DAT_0804d834 == 1) || (DAT_0804d834 == 3)) ||
     ((DAT_0804d834 == 4 || (DAT_0804d828 != DAT_0804d824)))) {
    FUN_08049948();
  }
  FUN_0804a170();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0804a988(int param_1,undefined4 *param_2)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar7;
  int *piVar8;
  int *piVar9;
  undefined4 *puVar10;
  char *pcVar11;
  byte *pbVar12;
  int local_1c;
  uint local_c;
  int local_8;
  
  FUN_0804b7f0((char *)*param_2,&DAT_0804d7e0,0x20);
  DAT_0804d7cc = 0;
  DAT_0804d7c8 = 0;
  DAT_0804d7d4 = 0;
  DAT_0804d7d0 = 0;
  puVar10 = &DAT_0804d880;
  for (iVar5 = 0x400; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  DAT_0804d844 = 0;
  DAT_0804d840 = 0;
  _DAT_0804d83c = 0;
  DAT_0804d860 = 0;
  DAT_0804d85c = 0;
  DAT_0804d858 = 0;
  DAT_0804d854 = 0;
  DAT_0804d850 = 0;
  DAT_0804d810 = 0;
  DAT_0804d81c = 0;
  DAT_0804d818 = 0;
  DAT_0804d800 = 0;
  DAT_0804d804 = 0;
  DAT_0804d80c = 0;
  DAT_0804d808 = 0;
  DAT_0804d848 = 0;
  DAT_0804d830 = 0;
  DAT_0804d82c = 0;
  DAT_0804d824 = 0;
  DAT_0804d834 = 0;
  DAT_0804d838 = 0;
  DAT_0804d814 = 0;
  DAT_0804d820 = 0;
  DAT_0804d828 = 1;
  if (param_1 < 2) {
    FUN_0804a378();
                    // WARNING: Subroutine does not return
    exit(1);
  }
  piVar8 = param_2 + 1;
  iVar5 = 0;
  iVar3 = param_2[1];
  piVar9 = piVar8;
  while (iVar3 != 0) {
    uVar6 = 0xffffffff;
    pcVar11 = (char *)*piVar9;
    do {
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      cVar1 = *pcVar11;
      pcVar11 = pcVar11 + 1;
    } while (cVar1 != '\0');
    iVar5 = iVar5 + 2 + ~uVar6;
    piVar9 = piVar9 + 1;
    iVar3 = *piVar9;
  }
  pbVar4 = FUN_08048d28(iVar5 + 1);
  iVar5 = param_2[1];
  pbVar7 = pbVar4;
  do {
    if (iVar5 == 0) {
      pbVar7[-1] = 0;
      uVar6 = time((time_t *)0x0);
      local_8 = 0;
      local_1c = 0;
      local_c = 0;
      do {
        local_c = local_c + uVar6;
        if (local_c < uVar6) {
          local_8 = local_8 + 1;
        }
        local_1c = local_1c + 1;
      } while (local_1c < 100);
      local_c = local_c + 0x6e996a00;
      if (local_c < 0x6e996a00) {
        local_8 = local_8 + 1;
      }
      local_8 = local_8 + 0x33;
      FUN_0804a820(pbVar4,(int *)&local_c);
      return 0;
    }
    *pbVar7 = 0x27;
    strcpy((char *)(pbVar7 + 1),(char *)*piVar8);
    uVar6 = 0xffffffff;
    pbVar12 = pbVar7 + 1;
    do {
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      bVar2 = *pbVar12;
      pbVar12 = pbVar12 + 1;
    } while (bVar2 != 0);
    pbVar7 = pbVar7 + ~uVar6;
    *pbVar7 = 0x27;
    pbVar7[1] = 0x20;
    pbVar7 = pbVar7 + 2;
    piVar8 = piVar8 + 1;
    iVar5 = *piVar8;
  } while( true );
}



void FUN_0804abe0(undefined4 param_1)

{
  DAT_0804d648 = param_1;
  return;
}



undefined4 FUN_0804ac00(void)

{
  return DAT_0804d648;
}



uint FUN_0804ac1c(uint param_1)

{
  if (DAT_0804d648 != 0) {
    param_1 = (param_1 << 0x18 | param_1 >> 8) ^
              (((param_1 << 0x10 | param_1 >> 0x10) ^ param_1) & 0xff00ffff) >> 8;
  }
  return param_1;
}



uint FUN_0804ac54(uint param_1)

{
  if (DAT_0804d648 != 0) {
    param_1 = (param_1 & 0xff) << 8 | (int)param_1 >> 8 & 0xffU;
  }
  return param_1;
}



void FUN_0804ac88(uint *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = param_3 >> 2;
  if (uVar2 != 0) {
    do {
      uVar1 = *param_2;
      param_2 = param_2 + 1;
      uVar1 = FUN_0804ac1c(uVar1);
      *param_1 = uVar1;
      param_1 = param_1 + 1;
      uVar2 = uVar2 - 1;
    } while (0 < (int)uVar2);
  }
  return;
}



void FUN_0804acd0(char *param_1,int *param_2,int param_3)

{
  char *pcVar1;
  byte bVar2;
  char *pcVar3;
  char cVar4;
  
  param_2[3] = 0;
  param_2[2] = 0;
  param_2[1] = 0;
  *param_2 = 0;
  *(undefined1 *)((int)param_2 + 0x13) = 0;
  *(undefined1 *)((int)param_2 + 0x12) = 0;
  *(undefined1 *)((int)param_2 + 0x11) = 0;
  *(undefined1 *)(param_2 + 4) = 0;
  *(undefined1 *)((int)param_2 + 0x17) = 0;
  *(undefined1 *)((int)param_2 + 0x16) = 0;
  *(undefined1 *)(param_2 + 5) = 0;
  cVar4 = *param_1;
  pcVar3 = param_1;
  if ((cVar4 == '\\') && (param_1[1] == '\\')) {
    *param_2 = (int)param_1;
    for (pcVar3 = param_1 + 2; (*pcVar3 != '\0' && (*pcVar3 != '\\')); pcVar3 = pcVar3 + 1) {
    }
    param_1._0_1_ = (char)pcVar3;
    *(char *)(param_2 + 4) = (char)param_1 - (char)*param_2;
    param_1 = pcVar3;
  }
  else {
    while ((cVar4 != '\0' && (*pcVar3 != param_3))) {
      if (((*pcVar3 == ':') && (pcVar3 != param_1)) && (*param_2 == 0)) {
        *param_2 = (int)param_1;
        pcVar3 = pcVar3 + 1;
        *(char *)(param_2 + 4) = (char)pcVar3 - (char)param_1;
        if (*pcVar3 == '/') {
          *(byte *)(param_2 + 5) = *(byte *)(param_2 + 5) | 0x40;
        }
        if (*pcVar3 == param_3) {
          bVar2 = *(byte *)(param_2 + 5) | 0x18;
        }
        else {
          bVar2 = *(byte *)(param_2 + 5) | 0x20;
        }
        *(byte *)(param_2 + 5) = bVar2;
        param_1 = pcVar3;
        if (*pcVar3 == '\0') break;
      }
      cVar4 = pcVar3[1];
      pcVar3 = pcVar3 + 1;
    }
  }
  if (*param_1 == param_3) {
    *(byte *)(param_2 + 5) = *(byte *)(param_2 + 5) | 0x18;
    param_1 = param_1 + 1;
  }
  param_2[1] = (int)param_1;
  cVar4 = *pcVar3;
  while (cVar4 != '\0') {
    if (*pcVar3 == param_3) {
      param_1 = pcVar3 + 1;
      *(byte *)(param_2 + 5) = *(byte *)(param_2 + 5) | 0x10;
    }
    pcVar3 = pcVar3 + 1;
    cVar4 = *pcVar3;
  }
  param_2[2] = (int)param_1;
  if ((*param_1 == '.') && ((param_1[1] == '\0' || ((param_1[1] == '.' && (param_1[2] == '\0'))))))
  {
    *(byte *)(param_2 + 5) = *(byte *)(param_2 + 5) | 0x10;
    *(char *)((int)param_2 + 0x11) = (char)pcVar3 - (char)param_2[1];
    param_1 = pcVar3;
  }
  else if ((char *)param_2[1] == param_1) {
    param_2[1] = 0;
  }
  else {
    *(char *)((int)param_2 + 0x11) = ((char)param_1 - (char)param_2[1]) + -1;
  }
  *(char *)((int)param_2 + 0x12) = (char)pcVar3 - (char)param_1;
  do {
    pcVar1 = pcVar3;
    if (pcVar1 == param_1) goto LAB_0804ae63;
    pcVar3 = pcVar1 + -1;
  } while (*pcVar3 != '.');
  param_2[3] = (int)pcVar1;
  cVar4 = (char)pcVar3 - (char)param_1;
  *(char *)((int)param_2 + 0x13) = (*(char *)((int)param_2 + 0x12) - cVar4) + -1;
  *(char *)((int)param_2 + 0x12) = cVar4;
LAB_0804ae63:
  *(char *)((int)param_2 + 0x16) = (char)param_3;
  return;
}



undefined4 FUN_0804ae70(int param_1,int param_2,char *param_3)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  
  cVar1 = *param_3;
  pcVar3 = param_3 + 1;
  if (cVar1 == '\0') {
    return 0;
  }
  do {
    while (cVar1 == ' ') {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    }
    iVar2 = 0;
    if (param_2 < 1) {
LAB_0804aeac:
      if ((cVar1 == ' ') || (cVar1 == '\0')) {
        return 1;
      }
    }
    else {
      do {
        if (*(char *)(iVar2 + param_1) != cVar1) break;
        iVar2 = iVar2 + 1;
        cVar1 = *pcVar3;
        pcVar3 = pcVar3 + 1;
      } while (iVar2 < param_2);
      if (param_2 <= iVar2) goto LAB_0804aeac;
    }
    while (cVar1 != ' ') {
      if (cVar1 == '\0') {
        return 0;
      }
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    }
  } while( true );
}



void FUN_0804aedc(char *param_1,char *param_2,char *param_3)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  char cVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  
  bVar1 = param_2[0x14];
  pcVar6 = param_1;
  if ((bVar1 & 0x20) != 0) {
    pcVar6 = param_1 + (byte)param_2[0x10];
  }
  cVar2 = *pcVar6;
  if (cVar2 == ':') {
LAB_0804af44:
    pcVar5 = *(char **)param_2;
    if (*(char **)param_2 == (char *)0x0) {
      *(char **)param_2 = param_1;
      pcVar5 = param_1;
    }
    do {
      pcVar7 = pcVar6;
      pcVar6 = pcVar7 + 1;
      cVar2 = *pcVar6;
      if (cVar2 == '.') break;
    } while (cVar2 != '\0');
    if (cVar2 == '.') {
      pcVar6 = pcVar7 + 2;
    }
    if (pcVar5 != (char *)0x0) {
      param_2[0x10] = ((char)pcVar6 - *param_2) + -1;
    }
    param_2[0x14] = '\0';
LAB_0804af8b:
    if ((*pcVar6 == '&') || (*pcVar6 == '$')) {
      pcVar6 = pcVar6 + 2;
    }
    param_2[0x14] = param_2[0x14] | 8;
  }
  else {
    if ((cVar2 == '&') || (cVar2 == '$')) {
      if (cVar2 == ':') goto LAB_0804af44;
      param_2[0x14] = bVar1 & 0x20;
      goto LAB_0804af8b;
    }
    if (((cVar2 != '^') && (cVar2 != '@')) && ((bVar1 & 0x10) != 0)) {
      return;
    }
    param_2[0x14] = bVar1 & 0x20;
  }
  *(char **)(param_2 + 4) = pcVar6;
  cVar2 = *pcVar6;
  pcVar5 = pcVar6;
  pcVar7 = pcVar6;
  while (param_1 = pcVar5, cVar2 != '\0') {
    pcVar5 = param_1;
    if (*pcVar6 == '.') {
      pcVar5 = pcVar6 + 1;
      pcVar7 = param_1;
    }
    param_1 = pcVar7;
    pcVar6 = pcVar6 + 1;
    pcVar7 = param_1;
    cVar2 = *pcVar6;
  }
  cVar2 = (char)pcVar6;
  cVar4 = (char)param_1;
  if (pcVar7 == param_1) {
LAB_0804b032:
    param_2[0xc] = '\0';
    param_2[0xd] = '\0';
    param_2[0xe] = '\0';
    param_2[0xf] = '\0';
    param_2[0x13] = '\0';
    *(char **)(param_2 + 8) = param_1;
    cVar2 = cVar2 - cVar4;
  }
  else {
    iVar3 = FUN_0804ae70((int)pcVar7,(int)(param_1 + (-1 - (int)pcVar7)),param_3);
    if (iVar3 != 0) {
      *(char **)(param_2 + 0xc) = pcVar7;
      param_2[0x13] = (cVar4 - (char)pcVar7) + -1;
      *(char **)(param_2 + 8) = param_1;
      param_2[0x12] = cVar2 - cVar4;
      param_1 = pcVar7;
      goto LAB_0804b04f;
    }
    iVar3 = FUN_0804ae70((int)param_1,(int)pcVar6 - (int)param_1,param_3);
    if (iVar3 == 0) goto LAB_0804b032;
    *(char **)(param_2 + 0xc) = param_1;
    param_2[0x13] = cVar2 - cVar4;
    *(char **)(param_2 + 8) = pcVar7;
    cVar2 = (cVar4 - (char)pcVar7) + -1;
    param_1 = pcVar7;
  }
  param_2[0x12] = cVar2;
LAB_0804b04f:
  if (*(char **)(param_2 + 4) == param_1) {
    param_2[4] = '\0';
    param_2[5] = '\0';
    param_2[6] = '\0';
    param_2[7] = '\0';
    param_2[0x11] = '\0';
  }
  else {
    param_2[0x11] = ((char)param_1 - param_2[4]) + -1;
  }
  param_2[0x16] = '.';
  return;
}



void FUN_0804b084(char *param_1,int *param_2)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  char *local_8;
  
  if ((*(byte *)(param_2 + 5) & 0x10) == 0) {
    *(undefined1 *)(param_2 + 5) = 0;
    param_2[1] = 0;
    *param_2 = 0;
    *(undefined1 *)(param_2 + 4) = 0;
    *(undefined1 *)((int)param_2 + 0x11) = 0;
    local_8 = (char *)0x0;
    cVar3 = *param_1;
    pcVar2 = param_1;
    while( true ) {
      if (cVar3 == '\0') break;
      pcVar1 = pcVar2;
      if ((*param_1 == ':') && (pcVar1 = param_1, local_8 == (char *)0x0)) {
        if ((param_1 == pcVar2) || (*param_2 != 0)) {
          local_8 = pcVar2 + 1;
          param_2[1] = (int)local_8;
        }
        else {
          *param_2 = (int)pcVar2;
          *(char *)(param_2 + 4) = ((char)param_1 - (char)pcVar2) + '\x01';
          *(byte *)(param_2 + 5) = *(byte *)(param_2 + 5) | 8;
          local_8 = (char *)param_2[1];
        }
      }
      param_1 = param_1 + 1;
      cVar3 = *param_1;
      pcVar2 = pcVar1;
    }
    if (local_8 == pcVar2 + 1) {
      param_2[1] = 0;
    }
    else if (local_8 != (char *)0x0) {
      *(char *)((int)param_2 + 0x11) = (char)pcVar2 - (char)param_2[1];
    }
    if (*pcVar2 == ':') {
      pcVar2 = pcVar2 + 1;
    }
    param_2[2] = (int)pcVar2;
    cVar3 = (char)param_1 - (char)pcVar2;
    *(char *)((int)param_2 + 0x12) = cVar3;
    if ((char *)param_2[3] != (char *)0x0) {
      if (pcVar2 < (char *)param_2[3]) {
        *(char *)((int)param_2 + 0x12) = (cVar3 + -1) - *(char *)((int)param_2 + 0x13);
      }
      else {
        param_2[3] = 0;
        *(undefined1 *)((int)param_2 + 0x13) = 0;
      }
    }
    *(undefined1 *)((int)param_2 + 0x16) = 0x3a;
  }
  return;
}



void FUN_0804b15c(char *param_1,char *param_2,int *param_3)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  byte bVar4;
  
  bVar2 = *(byte *)((int)param_3 + 0x15) & 7;
  if ((*param_1 == '\\') ||
     (((iVar3 = isalpha((int)*param_1), iVar3 != 0 && (param_1[1] == ':')) && (param_1[2] == '\\')))
     ) {
    FUN_0804acd0(param_1,param_3,0x5c);
    *(byte *)((int)param_3 + 0x15) = *(byte *)(param_3 + 5) & 8 | 2;
    return;
  }
  FUN_0804acd0(param_1,param_3,0x2f);
  if (((bVar2 == 3) || (bVar4 = *(byte *)(param_3 + 5), (bVar4 & 0x40) != 0)) ||
     (((*param_3 == 0 && ((bVar4 & 0x10) != 0)) &&
      ((bVar2 != 1 ||
       (((cVar1 = *param_1, cVar1 != ':' && (cVar1 != '$')) &&
        ((cVar1 != '&' && ((cVar1 != '^' && (cVar1 != '@')))))))))))) {
    *(byte *)((int)param_3 + 0x15) = *(byte *)(param_3 + 5) & 8 | 3;
    return;
  }
  if (bVar2 == 1) {
    FUN_0804aedc(param_1,(char *)param_3,param_2);
  }
  else if (bVar2 == 4) {
    FUN_0804b084(param_1,param_3);
  }
  else {
    if (bVar2 != 2) goto LAB_0804b243;
    FUN_0804acd0(param_1,param_3,0x5c);
  }
  bVar4 = *(byte *)(param_3 + 5);
LAB_0804b243:
  *(byte *)((int)param_3 + 0x15) = bVar4 & 8 | bVar2;
  return;
}



void FUN_0804b254(char *param_1,char *param_2,int *param_3)

{
  *(undefined1 *)((int)param_3 + 0x15) = 3;
  FUN_0804b15c(param_1,param_2,param_3);
  return;
}



byte * FUN_0804b27c(byte *param_1,byte *param_2,int param_3,byte *param_4,uint param_5)

{
  byte bVar1;
  byte local_8;
  
  if (param_1 != param_4) {
    do {
      if (param_3 < 1) {
        return param_1;
      }
      bVar1 = *param_2;
      *param_1 = bVar1;
      param_2 = param_2 + 1;
      if ((uint)bVar1 == (param_5 & 0xff)) {
        local_8 = (byte)(param_5 >> 8);
        *param_1 = local_8;
      }
      param_1 = param_1 + 1;
      param_3 = param_3 + -1;
    } while (param_1 != param_4);
  }
  return param_1;
}



int FUN_0804b2cc(undefined4 *param_1,uint param_2,byte *param_3,int param_4)

{
  uint uVar1;
  byte *pbVar2;
  char cVar3;
  byte bVar4;
  byte *pbVar5;
  byte *pbVar6;
  byte *pbVar7;
  int iVar8;
  uint uVar9;
  byte *pbVar10;
  byte *local_20;
  uint local_14;
  
  uVar9 = *(byte *)((int)param_1 + 0x15) & 7;
  uVar1 = param_2 & 0x10;
  pbVar2 = param_3 + param_4;
  param_2 = param_2 & 7;
  if (param_2 == 0) {
    param_2 = 3;
  }
  if (uVar9 == 1) {
    if (param_2 == 1) goto LAB_0804b340;
    local_14 = 0x2e2f;
  }
  else if (param_2 == 1) {
    local_14 = 0x2f2e;
  }
  else {
LAB_0804b340:
    local_14 = 0;
  }
  if ((byte *)*param_1 == (byte *)0x0) {
    pbVar5 = param_3;
    if ((*(byte *)((int)param_1 + 0x15) & 8) == 0) {
      if ((param_2 != 4) || (param_3 == pbVar2)) goto LAB_0804b468;
      *param_3 = 0x3a;
    }
    else {
      if ((param_2 == 1) && (param_3 != pbVar2)) {
        *param_3 = 0x24;
        pbVar5 = param_3 + 1;
      }
      if ((param_2 == 4) || (pbVar5 == pbVar2)) goto LAB_0804b468;
      *pbVar5 = (&DAT_0804c61f)[param_2];
    }
  }
  else {
    pbVar5 = FUN_0804b27c(param_3,(byte *)*param_1,(uint)*(byte *)(param_1 + 4),pbVar2,0);
    if ((((param_2 != 3) && (param_2 != uVar9)) && (pbVar5[-1] != 0x3a)) && (pbVar5 != pbVar2)) {
      *pbVar5 = 0x3a;
      pbVar5 = pbVar5 + 1;
    }
    bVar4 = *(byte *)(param_1 + 5);
    if ((bVar4 & 0x40) == 0) {
      if (((bVar4 & 8) == 0) && (param_2 != 3)) goto LAB_0804b468;
      if (((param_2 == 1) && ((uVar9 != 1 || ((bVar4 & 0x20) != 0)))) && (pbVar5 != pbVar2)) {
        *pbVar5 = 0x24;
        pbVar5 = pbVar5 + 1;
      }
      if ((param_2 == 4) || (pbVar5 == pbVar2)) goto LAB_0804b468;
      *pbVar5 = (&DAT_0804c61f)[param_2];
    }
    else if (param_2 == 1) {
      if (pbVar5 == pbVar2) goto LAB_0804b468;
      *pbVar5 = 0x3a;
    }
    else {
      if ((param_2 == 4) || (pbVar5 == pbVar2)) goto LAB_0804b468;
      *pbVar5 = (&DAT_0804c61f)[param_2];
    }
  }
  pbVar5 = pbVar5 + 1;
LAB_0804b468:
  pbVar10 = (byte *)param_1[1];
  if (pbVar10 != (byte *)0x0) {
    pbVar6 = pbVar10 + *(byte *)((int)param_1 + 0x11);
    bVar4 = (&DAT_0804c61f)[uVar9];
    local_20 = pbVar10;
    for (; pbVar10 <= pbVar6; pbVar10 = pbVar10 + 1) {
      if ((pbVar6 <= pbVar10) || (*pbVar10 == bVar4)) {
        iVar8 = (int)pbVar10 - (int)local_20;
        if (((uVar9 == 4) && (iVar8 == 0)) ||
           ((((uVar9 == 1 && (iVar8 == 1)) && (*local_20 == 0x5e)) ||
            ((((uVar9 - 2 < 2 && (iVar8 == 2)) && (*local_20 == 0x2e)) && (local_20[1] == 0x2e))))))
        {
          pbVar7 = pbVar5;
          if (param_2 == 1) {
            if (pbVar5 != pbVar2) {
              *pbVar5 = 0x5e;
              pbVar7 = pbVar5 + 1;
            }
LAB_0804b54e:
            pbVar5 = pbVar7;
            if (((param_2 != 4) && (pbVar6 <= pbVar10)) &&
               ((uint)*(byte *)((int)param_1 + 0x12) + (uint)*(byte *)((int)param_1 + 0x13) == 0))
            goto LAB_0804b57c;
          }
          else if (param_2 != 4) {
            if (pbVar5 != pbVar2) {
              *pbVar5 = 0x2e;
              pbVar7 = pbVar5 + 1;
              if (pbVar7 != pbVar2) {
                *pbVar7 = 0x2e;
                pbVar7 = pbVar5 + 2;
              }
            }
            goto LAB_0804b54e;
          }
          if (pbVar5 != pbVar2) {
            *pbVar5 = (&DAT_0804c61f)[param_2];
            pbVar5 = pbVar5 + 1;
          }
        }
        else if ((iVar8 != 1) || (*local_20 != (&DAT_0804c625)[uVar9])) {
          pbVar7 = FUN_0804b27c(pbVar5,local_20,iVar8,pbVar2,local_14);
          goto LAB_0804b54e;
        }
LAB_0804b57c:
        local_20 = pbVar10 + 1;
      }
    }
  }
  cVar3 = (char)pbVar5 - (char)param_3;
  *(char *)((int)param_1 + 0x17) = cVar3;
  if (((param_2 == 4) && (pbVar5 != param_3)) && (pbVar5[-1] == 0x3a)) {
    *(char *)((int)param_1 + 0x17) = cVar3 + -1;
  }
  if (((param_2 == 1) && (*(char *)((int)param_1 + 0x13) != '\0')) &&
     (((*(byte *)(param_1 + 5) & 0x40) == 0 &&
      ((pbVar5 = FUN_0804b27c(pbVar5,(byte *)param_1[3],(uint)*(byte *)((int)param_1 + 0x13),pbVar2,
                              0), *(char *)((int)param_1 + 0x12) != '\0' && (pbVar5 != pbVar2))))))
  {
    *pbVar5 = 0x2e;
    pbVar5 = pbVar5 + 1;
  }
  pbVar5 = FUN_0804b27c(pbVar5,(byte *)param_1[2],(uint)*(byte *)((int)param_1 + 0x12),pbVar2,
                        local_14);
  if ((*(char *)((int)param_1 + 0x13) != '\0') &&
     ((param_2 != 1 || ((*(byte *)(param_1 + 5) & 0x40) != 0)))) {
    pbVar10 = pbVar5;
    if (pbVar5 != pbVar2) {
      pbVar10 = pbVar5 + 1;
      if (param_2 == 1) {
        bVar4 = 0x2f;
      }
      else {
        bVar4 = 0x2e;
      }
      *pbVar5 = bVar4;
    }
    pbVar5 = FUN_0804b27c(pbVar10,(byte *)param_1[3],(uint)*(byte *)((int)param_1 + 0x13),pbVar2,0);
  }
  if (uVar1 != 0) {
    if (param_2 == 4) {
      if ((param_3 < pbVar5) && (pbVar5[-1] == 0x3a)) {
        pbVar5 = pbVar5 + -1;
      }
    }
    else if ((pbVar5 != param_3) && (pbVar5 != pbVar2)) {
      *pbVar5 = (&DAT_0804c61f)[param_2];
      pbVar5 = pbVar5 + 1;
    }
    *(char *)((int)param_1 + 0x17) = (char)pbVar5 - (char)param_3;
  }
  if (pbVar5 == pbVar2) {
    iVar8 = -1;
  }
  else {
    *pbVar5 = 0;
    iVar8 = (int)pbVar5 - (int)param_3;
  }
  return iVar8;
}



void FUN_0804b6a8(char param_1,char *param_2,char *param_3)

{
  char cVar1;
  
  if (param_2[0x10] == '\0') {
    cVar1 = '\0';
  }
  else {
    cVar1 = *param_2 - param_1;
  }
  *param_3 = cVar1;
  if (param_2[0x11] == '\0') {
    cVar1 = '\0';
  }
  else {
    cVar1 = param_2[4] - param_1;
  }
  param_3[1] = cVar1;
  param_3[2] = param_2[8] - param_1;
  if (param_2[0x13] == '\0') {
    cVar1 = '\0';
  }
  else {
    cVar1 = param_2[0xc] - param_1;
  }
  param_3[3] = cVar1;
  param_3[4] = param_2[0x10];
  param_3[5] = param_2[0x11];
  param_3[6] = param_2[0x12];
  param_3[7] = param_2[0x13];
  param_3[8] = param_2[0x14];
  param_3[9] = param_2[0x15];
  param_3[10] = param_2[0x16];
  param_3[0xb] = param_2[0x17];
  return;
}



void FUN_0804b744(int param_1,byte *param_2,int *param_3)

{
  int iVar1;
  
  if (param_2[4] == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = (uint)*param_2 + param_1;
  }
  *param_3 = iVar1;
  if (param_2[5] == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = (uint)param_2[1] + param_1;
  }
  param_3[1] = iVar1;
  param_3[2] = (uint)param_2[2] + param_1;
  if (param_2[7] == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = (uint)param_2[3] + param_1;
  }
  param_3[3] = iVar1;
  *(byte *)(param_3 + 4) = param_2[4];
  *(byte *)((int)param_3 + 0x11) = param_2[5];
  *(byte *)((int)param_3 + 0x12) = param_2[6];
  *(byte *)((int)param_3 + 0x13) = param_2[7];
  *(byte *)(param_3 + 5) = param_2[8];
  *(byte *)((int)param_3 + 0x15) = param_2[9];
  *(byte *)((int)param_3 + 0x16) = param_2[10];
  *(byte *)((int)param_3 + 0x17) = param_2[0xb];
  return;
}



byte FUN_0804b7cc(int param_1)

{
  byte bVar1;
  
  if (param_1 == 0) {
    bVar1 = 3;
  }
  else {
    bVar1 = *(byte *)(param_1 + 9) & 7;
  }
  return bVar1;
}



char * FUN_0804b7f0(char *param_1,char *param_2,int param_3)

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
      if (!bVar7) goto LAB_0804b87e;
    }
    local_10 = ~uVar2 - 5;
    local_8 = pcVar4;
  }
LAB_0804b87e:
  iVar3 = local_10 + -2;
  do {
    if (iVar3 < 0) {
LAB_0804b8b3:
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
      goto LAB_0804b8b3;
    }
    iVar3 = iVar3 + -1;
  } while( true );
}



char * FUN_0804b900(char *param_1,undefined4 param_2,undefined4 *param_3)

{
  DIR *pDVar1;
  char *pcVar2;
  
  if (param_1 == (char *)0x0) {
    param_1 = ".";
  }
  param_3[1] = param_2;
  pDVar1 = opendir(param_1);
  *param_3 = pDVar1;
  if (pDVar1 == (DIR *)0x0) {
    pcVar2 = (char *)0x0;
  }
  else {
    pcVar2 = FUN_0804b950(param_3);
  }
  return pcVar2;
}



char * FUN_0804b950(undefined4 *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  dirent *pdVar2;
  
  do {
    pdVar2 = readdir((DIR *)*param_1);
    if (pdVar2 == (dirent *)0x0) {
      return (char *)0x0;
    }
    bVar1 = FUN_0804ba90((char *)param_1[1],pdVar2->d_name);
  } while (CONCAT31(extraout_var,bVar1) == 0);
  return pdVar2->d_name;
}



void FUN_0804b998(undefined4 *param_1)

{
  if ((param_1 != (undefined4 *)0x0) && ((DIR *)*param_1 != (DIR *)0x0)) {
    closedir((DIR *)*param_1);
  }
  return;
}



int FUN_0804b9c0(char *param_1)

{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  stat local_5c;
  
  iVar1 = __xstat(3,param_1,&local_5c);
  if (iVar1 == 0) {
    if ((local_5c.st_mode & 0xf000) != 0x4000) {
      return 0x11;
    }
  }
  else {
    iVar1 = mkdir(param_1,0x1ff);
    if (iVar1 != 0) {
      piVar2 = __errno_location();
      if (*piVar2 != 2) {
        return *piVar2;
      }
      pcVar3 = strrchr(param_1,0x2f);
      iVar1 = 2;
      if (pcVar3 != (char *)0x0) {
        *pcVar3 = '\0';
        iVar1 = FUN_0804b9c0(param_1);
        *pcVar3 = '/';
      }
      if (iVar1 != 0) {
        return iVar1;
      }
      iVar1 = mkdir(param_1,0x1ff);
      if (iVar1 == 0) {
        return 0;
      }
      return *piVar2;
    }
  }
  return 0;
}



bool FUN_0804ba90(char *param_1,char *param_2)

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
        bVar1 = FUN_0804ba90(param_1,param_2);
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



void FUN_0804bb30(void)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = &DAT_0804d650;
  iVar1 = DAT_0804d650;
  while (iVar1 != -1) {
    (*(code *)*piVar2)();
    piVar2 = piVar2 + -1;
    iVar1 = *piVar2;
  }
  return;
}



void FUN_0804bb54(void)

{
  return;
}



void _DT_FINI(void)

{
  FUN_08048a10();
  return;
}


