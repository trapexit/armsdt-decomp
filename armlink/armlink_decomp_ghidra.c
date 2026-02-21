typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned int    uint3;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
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

typedef void *__gnuc_va_list;

typedef __time_t time_t;

typedef struct _IO_FILE FILE;

typedef struct __jmp_buf_tag __jmp_buf_tag, *P__jmp_buf_tag;

typedef int __jmp_buf[6];

typedef struct __sigset_t __sigset_t, *P__sigset_t;

struct __sigset_t {
    ulong __val[32];
};

struct __jmp_buf_tag {
    __jmp_buf __jmpbuf;
    int __mask_was_saved;
    struct __sigset_t __saved_mask;
};

typedef int __ssize_t;

typedef __ssize_t ssize_t;

typedef void (*__sighandler_t)(int);

typedef struct utimbuf utimbuf, *Putimbuf;

struct utimbuf {
    __time_t actime;
    __time_t modtime;
};

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

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
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



undefined FUN_0805b1b0;
undefined _DT_INIT;
undefined _DT_FINI;
int DAT_080686c8;
undefined *PTR_DAT_080686c4;
dword DWORD_08068ac4;
undefined DAT_08068c88;
undefined4 DAT_0806ab68;
undefined4 DAT_0806ab64;
undefined4 DAT_0806ab70;
undefined1 DAT_0806ab60;
undefined1 DAT_0806ab6d;
undefined1 DAT_0806ab6e;
undefined1 DAT_0806ab6c;
undefined FUN_080491b8;
undefined DAT_0806216d;
undefined DAT_08062221;
undefined DAT_08062435;
undefined DAT_080626ea;
undefined DAT_0806ab70;
undefined DAT_08062170;
undefined DAT_08062447;
undefined DAT_0806244a;
undefined DAT_080627fe;
undefined DAT_08062428;
undefined FUN_0804b1e8;
undefined FUN_0804b3ac;
int DAT_0806ab74;
undefined4 *DAT_08068ca0;
undefined4 *DAT_08068ca4;
int DAT_08068ca0;
undefined4 DAT_08068ca4;
undefined4 DAT_08068ca0;
undefined4 *DAT_0806ab74;
undefined4 DAT_08068ca8;
undefined4 DAT_08068cac;
undefined4 DAT_08068cb4;
int *DAT_08068cbc;
int DAT_08068cac;
int *DAT_08068cc4;
int DAT_08068cb4;
undefined4 *DAT_08068cc4;
int *DAT_08068cc0;
int DAT_08068ca8;
int DAT_08068cb0;
undefined4 *DAT_08068cc8;
undefined4 *DAT_08068cc0;
undefined4 *DAT_08068cb8;
undefined4 DAT_08068cb8;
undefined4 DAT_08068cc4;
undefined4 DAT_08068cb0;
undefined4 DAT_08068cc0;
undefined4 DAT_08068cbc;
undefined4 DAT_08068cc8;
uint DAT_08068ccc;
uint DAT_0806ab78;
int DAT_0806ab78;
undefined *PTR_strcmp_080686cc;
undefined4 DAT_08068ccc;
undefined4 DAT_0806ab78;
undefined strcmp;
undefined DAT_080686e0;
undefined DAT_08068764;
undefined DAT_080687b0;
undefined1 DAT_08068ce0;
undefined4 *DAT_0806ab9c;
undefined4 *DAT_0806ab90;
int DAT_08069d10;
undefined1 DAT_08062c38;
int DAT_08069d08;
undefined DAT_08069cfc;
undefined4 DAT_08069d00;
int DAT_08069d04;
int DAT_08069d0c;
undefined *DAT_08069d04;
undefined4 DAT_08069d10;
undefined DAT_08069cee;
int DAT_08069d00;
int DAT_0806abc4;
undefined4 DAT_08062c68;
undefined1 DAT_08062c6c;
pointer PTR_s_area-alignment_08062c70;
undefined UNK_08062d4b;
int *DAT_0806ab74;
undefined FUN_0804b6c0;
undefined DAT_0806ab68;
int DAT_0806ab64;
int DAT_0806ab94;
int *DAT_0806ab84;
int *DAT_0806ab80;
undefined4 DAT_0806ab9c;
undefined4 DAT_0806abc0;
undefined4 DAT_08069d14;
int DAT_08068874;
int DAT_08068870;
uint DAT_0806ab70;
uint DAT_0806ab98;
int DAT_0806ab7c;
uint DAT_0806abbc;
undefined *PTR_DAT_08068760;
undefined *PTR_DAT_08068868;
uint DAT_0806886c;
undefined *PTR_DAT_080687a8;
uint DAT_080687ac;
char DAT_08069cf8;
char DAT_08069cf9;
undefined4 *DAT_08069cf4;
undefined4 DAT_08069d18;
int *DAT_08069d18;
int *DAT_0806ab8c;
int *DAT_08069cf4;
undefined1 *DAT_08069d04;
char DAT_0806ab6e;
undefined4 *DAT_0806ab8c;
int *DAT_0806ab88;
char DAT_0806ab60;
undefined4 DAT_08069d0c;
undefined4 *DAT_0806ab80;
undefined4 DAT_08068870;
undefined4 DAT_08068874;
undefined4 DAT_0806ab7c;
undefined4 DAT_0806aba0;
undefined4 DAT_0806abbc;
undefined4 DAT_0806ab90;
undefined4 DAT_0806aba8;
undefined4 DAT_0806abd4;
undefined4 DAT_0806ab88;
undefined4 *DAT_0806ab84;
undefined4 DAT_0806ac4c;
undefined4 DAT_0806ac48;
undefined4 DAT_0806ac54;
undefined4 DAT_0806ac50;
undefined4 DAT_0806abcc;
undefined4 DAT_0806abc8;
undefined4 DAT_0806abd0;
undefined4 DAT_0806abb8;
undefined4 DAT_0806abe0;
undefined4 DAT_08069d04;
undefined4 DAT_08069d08;
undefined4 DAT_0806ab94;
undefined4 DAT_0806abc4;
undefined DAT_08069cf8;
undefined4 DAT_0806abb0;
char *DAT_0806abe4;
undefined4 *DAT_08069d14;
char *DAT_0806abb8;
char *DAT_0806abd0;
char *DAT_0806abe0;
int *DAT_0806ab7c;
FILE *DAT_0806a0ac;
undefined4 DAT_08069e50;
uint DAT_0806abb0;
int DAT_0806a0b0;
int DAT_08069dbc;
undefined *PTR_DAT_08068878;
undefined4 DAT_08069d28;
int DAT_080687ac;
uint DAT_08069dc8;
uint DAT_08069dbc;
undefined4 DAT_0806a0b0;
undefined4 DAT_08069dc0;
int DAT_0806a078;
int DAT_0806a068;
char DAT_0806ab6d;
uint DAT_0806abd8;
uint DAT_08069e44;
undefined DAT_08069e48;
uint DAT_0806abdc;
int *DAT_0806a098;
int *DAT_08069dac;
int DAT_0806aba0;
int DAT_0806a07c;
int DAT_0806a080;
int DAT_0806886c;
int DAT_0806abbc;
uint DAT_0806a068;
int DAT_08069e38;
undefined4 *DAT_08069e3c;
int DAT_0806a06c;
uint DAT_0806ab68;
int DAT_08069e34;
short DAT_08069e42;
uint *DAT_08069e38;
long DAT_08069dc0;
ushort DAT_08069e40;
undefined4 *DAT_08069e34;
uint *DAT_08069e3c;
ushort DAT_08069e42;
uint DAT_08069df0;
uint *DAT_08069de8;
uint DAT_08069df4;
uint *DAT_08069dec;
uint DAT_0806a078;
uint DAT_0806a07c;
uint DAT_0806a080;
undefined DAT_0806a084;
uint DAT_0806a088;
int DAT_08069dc0;
int DAT_08069db4;
uint DAT_08069db0;
undefined DAT_08063972;
int DAT_08069de0;
int DAT_08069dec;
int DAT_08069de8;
byte *DAT_08069de8;
byte *DAT_08069dec;
undefined4 DAT_08069dd8;
undefined DAT_0806a0bc;
undefined DAT_0806a0f8;
undefined DAT_0806a0c0;
uint DAT_0806a100;
undefined DAT_0806a0c4;
uint DAT_0806a104;
undefined DAT_0806a0c6;
undefined DAT_0806a10c;
undefined DAT_0806a0c8;
uint DAT_0806a110;
undefined DAT_0806a0cc;
undefined DAT_0806a0d4;
undefined DAT_0806a0d8;
undefined DAT_0806a0dc;
undefined DAT_0806a0e0;
undefined DAT_0806a0e2;
undefined DAT_0806a0e4;
undefined DAT_0806a0e8;
undefined DAT_0806a0ec;
undefined DAT_0806a0f0;
undefined DAT_0806a0f4;
int DAT_0806a118;
undefined DAT_0806a114;
int DAT_0806a11c;
int DAT_0806a120;
int DAT_0806a124;
char *DAT_08069d28;
undefined4 DAT_08069dcc;
int DAT_0806a08c;
int DAT_08069ddc;
uint DAT_08069e4c;
int *DAT_08069dd4;
byte DAT_0806ab6f;
undefined4 DAT_08069d90;
char *DAT_0806abc8;
undefined4 DAT_08069dac;
char *DAT_0806aba4;
char *DAT_0806ac5c;
undefined4 *DAT_08069d90;
undefined4 *DAT_0806ab88;
int *DAT_0806ac58;
int *DAT_0806ac68;
int *DAT_0806ac88;
int *DAT_0806abb4;
undefined DAT_08069d24;
byte DAT_08069d24;
undefined4 *DAT_0806abd4;
undefined4 *DAT_0806aba8;
byte DAT_0806ab6c;
int DAT_08069db8;
undefined4 *DAT_08069dd4;
undefined *PTR_DAT_0806887c;
int *DAT_08069d90;
undefined DAT_0806a090;
int DAT_08069d80;
int DAT_08069db0;
int *DAT_0806ac60;
int DAT_08068920;
char *DAT_0806ac64;
int *DAT_0806a0a0;
uint DAT_0806a08c;
int *DAT_0806a09c;
uint *DAT_08069dac;
undefined DAT_08069d60;
int DAT_0806a0a0;
int DAT_08069dc8;
undefined4 DAT_08069e44;
int *DAT_0806ac70;
int DAT_0806ac84;
int *DAT_0806ac78;
int *DAT_0806a0a4;
int DAT_08069de4;
int *DAT_0806a0a8;
int DAT_0806ac48;
int DAT_08069dd8;
int *DAT_08069ddc;
byte *DAT_08069dcc;
int DAT_08069dc4;
char *DAT_08069e50;
undefined1 DAT_0806a05f;
int *DAT_0806ac74;
int DAT_0806ab98;
int DAT_08069dd0;
uint DAT_0806a108;
undefined4 DAT_0806a100;
undefined4 DAT_0806a10c;
int *DAT_0806ac6c;
int *DAT_08069d20;
undefined4 DAT_0806a104;
undefined4 DAT_0806a110;
undefined DAT_08069e60;
undefined4 *DAT_08069dac;
char *DAT_0806a070;
int DAT_0806a074;
int DAT_08069e3c;
int DAT_08069d7c;
int DAT_08069d50;
char *DAT_08069d98;
int DAT_0806ac74;
int DAT_0806ac7c;
int *DAT_0806a094;
uint DAT_0806ac84;
uint DAT_08068920;
char DAT_0806ac80;
byte *DAT_0806891c;
size_t DAT_0806a0b8;
char *DAT_0806a0b4;
int DAT_0806ac54;
int DAT_0806ac50;
char *DAT_0806a060;
uint DAT_08069dc0;
uint DAT_0806a0b0;
char *DAT_0806a064;
undefined4 DAT_0806abdc;
uint DAT_0806a06c;
undefined1 *DAT_0806a074;
uint DAT_08069de4;
int DAT_0806a088;
undefined DAT_08064afc;
undefined DAT_08064aff;
undefined4 DAT_0806a140;
undefined4 DAT_0806a13c;
undefined4 DAT_0806a138;
undefined4 DAT_0806a134;
undefined4 DAT_0806a130;
undefined4 DAT_0806a12c;
undefined4 DAT_0806a128;
undefined4 DAT_0806a15c;
undefined4 DAT_0806a158;
undefined4 DAT_0806a154;
undefined4 DAT_0806a150;
undefined4 DAT_0806a14c;
undefined4 DAT_0806a148;
undefined4 DAT_0806a144;
int DAT_0806a0b4;
undefined4 DAT_0806a0b8;
undefined4 *DAT_0806a09c;
undefined4 DAT_0806a0a0;
undefined4 DAT_0806891c;
undefined4 DAT_08068920;
undefined4 DAT_0806ac7c;
undefined4 DAT_0806ac6c;
undefined4 DAT_0806ac74;
undefined4 DAT_0806ac84;
undefined4 DAT_0806a120;
undefined4 DAT_0806a118;
undefined4 DAT_0806a124;
undefined4 DAT_0806a11c;
undefined4 DAT_08069db0;
undefined4 DAT_08069db4;
undefined4 DAT_08069db8;
undefined4 DAT_08069dc8;
undefined4 DAT_08069dbc;
undefined4 DAT_08069dc4;
undefined4 DAT_08069dd0;
undefined4 DAT_08069dd4;
undefined4 DAT_08069ddc;
undefined4 DAT_08069de4;
undefined4 DAT_08069de0;
undefined4 DAT_08069de8;
undefined4 DAT_08069dec;
undefined4 DAT_08069df4;
undefined4 DAT_08069df0;
undefined *DAT_08069e34;
undefined4 DAT_08069e38;
undefined4 DAT_08069e3c;
undefined2 DAT_08069e42;
undefined2 DAT_08069e40;
undefined4 DAT_08069e4c;
undefined1 DAT_08069e60;
undefined *DAT_0806a060;
undefined *DAT_0806a064;
undefined4 DAT_0806a06c;
undefined4 DAT_0806a068;
undefined4 DAT_0806a074;
undefined4 DAT_0806a070;
undefined4 DAT_0806a078;
undefined4 DAT_0806a088;
undefined4 DAT_0806a080;
undefined4 DAT_0806a07c;
undefined4 DAT_0806a08c;
undefined4 DAT_0806a098;
undefined4 DAT_0806a094;
undefined4 DAT_0806abb4;
undefined DAT_08065036;
undefined DAT_0806503a;
undefined4 DAT_08069d40;
undefined DAT_08069e00;
ulong DAT_0806aba0;
undefined4 DAT_0806ac08;
char *DAT_0806ac44;
char *DAT_0806abac;
int DAT_08069dac;
undefined4 DAT_0806ab98;
undefined4 DAT_0806aba4;
undefined4 DAT_0806abe4;
undefined4 DAT_0806abac;
undefined4 DAT_0806abd8;
undefined4 DAT_0806ac44;
FILE *DAT_0806ac40;
int DAT_0806ac4c;
undefined DAT_0806a160;
int *DAT_08068880;
undefined DAT_080653e6;
undefined4 DAT_0806ac04;
undefined *DAT_0806ac00;
undefined4 *DAT_08068880;
undefined4 *DAT_08068884;
__sighandler_t DAT_0806a1fc;
__sighandler_t DAT_0806a200;
__sighandler_t DAT_0806a204;
__sighandler_t DAT_0806a208;
__sighandler_t DAT_0806a20c;
undefined FUN_080597bc;
undefined FUN_08059d04;
undefined FUN_08059d6c;
undefined FUN_08059db0;
undefined DAT_0806ac20;
void *DAT_0806ac44;
void *DAT_0806aba4;
void *DAT_0806abcc;
void *DAT_0806abe4;
void *DAT_0806abb8;
void *DAT_0806abd0;
undefined *DAT_0806abc8;
undefined FUN_08059eb8;
void *DAT_0806abac;
undefined FUN_08059f60;
void *DAT_0806abe0;
undefined1 DAT_0806ab6f;
int DAT_0806abd8;
int DAT_0806abc0;
int DAT_0806abdc;
undefined DAT_080662b7;
undefined DAT_080662d2;
undefined DAT_0806632c;
undefined DAT_08066520;
undefined DAT_08066570;
undefined DAT_08066138;
undefined DAT_08066152;
undefined DAT_080665fe;
undefined DAT_08066600;
undefined DAT_08066604;
undefined DAT_08066608;
undefined4 DAT_0806ac00;
undefined4 DAT_0806ac40;
undefined *PTR_FUN_08066760;
int DAT_08068880;
pointer PTR_s_.format_08066788;
int *DAT_08068884;
undefined4 stdout;
FILE *DAT_0806ac08;
int DAT_0806ac04;
undefined1 DAT_0806a220;
undefined DAT_080668ec;
FILE *DAT_0806a620;
int DAT_0806a620;
undefined4 DAT_0806a620;
undefined DAT_080669a0;
undefined FUN_0805b178;
undefined4 stderr;
pointer PTR_s_RO-CODE_08068888;
undefined4 DAT_0806888c;
int DAT_0806a624;
undefined DAT_08066dbc;
undefined4 DAT_0806a624;
void *DAT_0806891c;
size_t DAT_08068920;
uint DAT_08068918;
int *DAT_0806a740;
int DAT_0806a744;
int DAT_0806a748;
int DAT_0806ac6c;
int DAT_0806891c;
undefined4 DAT_0806a74c;
undefined4 DAT_0806ac60;
undefined4 DAT_0806ac68;
undefined1 DAT_08066eea;
int DAT_0806a740;
undefined1 DAT_08066f34;
undefined1 DAT_0806a642;
undefined1 DAT_0806ac80;
char *DAT_0806abcc;
void *DAT_0806ac5c;
void *DAT_0806ac64;
undefined4 DAT_08068918;
undefined4 DAT_0806a748;
undefined4 DAT_0806ac64;
undefined4 DAT_0806ac5c;
int *DAT_0806a74c;
undefined4 DAT_0806ac78;
undefined4 DAT_0806ac70;
undefined4 DAT_0806ac88;
undefined4 DAT_0806ac58;
pointer PTR_s_=-elf_080672c4;
undefined1 DAT_08067380;
undefined FUN_0805d798;
undefined FUN_0805d9ac;
undefined FUN_0805da90;
void *DAT_08068924;
int DAT_08068930;
int DAT_0806892c;
uint DAT_08068928;
undefined4 DAT_08068934;
undefined4 DAT_08068930;
undefined4 DAT_0806892c;
int DAT_08068924;
int DAT_08068934;
undefined4 DAT_08068928;
undefined4 DAT_08068938;
int DAT_08068938;
pointer PTR_DAT_0806893c;
undefined *PTR_DAT_08068a8c;
undefined1 DAT_0806741d;
undefined1 DAT_08067420;
undefined4 *DAT_08068aa8;
undefined4 *DAT_08068aac;
undefined4 DAT_08068ab0;
undefined4 DAT_08068aac;
int *DAT_08068aac;
undefined4 DAT_08068ab4;
int DAT_08068abc;
undefined *DAT_08068ab4;
undefined4 *DAT_08068ab8;
undefined4 DAT_08068ab8;
int *DAT_08068abc;
undefined4 DAT_08068abc;
char *DAT_08068ac0;
undefined DAT_0806a760;
undefined4 DAT_08068ac8;

void _DT_INIT(void)

{
  func_0x00000000();
  FUN_08049050();
  FUN_080620f0();
  return;
}



void FUN_08048bfc(void)

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



// WARNING: Unknown calling convention -- yet parameter storage is locked

int ferror(FILE *__stream)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
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



// WARNING: Unknown calling convention -- yet parameter storage is locked

int feof(FILE *__stream)

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

int fileno(FILE *__stream)

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

int isspace(int param_1)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int close(int __fd)

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

char * getenv(char *__name)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int isalnum(int param_1)

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

int chmod(char *__file,__mode_t __mode)

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

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int isxdigit(int param_1)

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



// WARNING: Unknown calling convention -- yet parameter storage is locked

int remove(char *__filename)

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



void __sigsetjmp(void)

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



// WARNING: Unknown calling convention -- yet parameter storage is locked

void longjmp(__jmp_buf_tag *__env,int __val)

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

int iscntrl(int param_1)

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

void * realloc(void *__ptr,size_t __size)

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

__off_t lseek(int __fd,__off_t __offset,int __whence)

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

int isdigit(int param_1)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int open(char *__file,int __oflag,...)

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

int utime(char *__file,utimbuf *__file_times)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int isatty(int __fd)

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



void __strtoul_internal(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strtok(char *__s,char *__delim)

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

int _IO_getc(_IO_FILE *__fp)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t read(int __fd,void *__buf,size_t __nbytes)

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
  
  __libc_start_main(FUN_0805b1b0,param_2,&stack0x00000004,_DT_INIT,_DT_FINI,param_1,auStack_4);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void FUN_08049000(void)

{
  code *pcVar1;
  
  if (DAT_080686c8 == 0) {
    while (*(int *)PTR_DAT_080686c4 != 0) {
      pcVar1 = *(code **)PTR_DAT_080686c4;
      PTR_DAT_080686c4 = PTR_DAT_080686c4 + 4;
      (*pcVar1)();
    }
    __deregister_frame_info(&DWORD_08068ac4);
    DAT_080686c8 = 1;
  }
  return;
}



void FUN_08049048(void)

{
  return;
}



void FUN_08049050(void)

{
  __register_frame_info(&DWORD_08068ac4,&DAT_08068c88);
  return;
}



void FUN_08049070(void)

{
  return;
}



void FUN_08049078(void)

{
  DAT_0806ab68 = 0;
  DAT_0806ab64 = 6;
  DAT_0806ab70 = 0;
  DAT_0806ab60 = 0;
  DAT_0806ab6d = 0;
  DAT_0806ab6e = 0;
  DAT_0806ab6c = 0;
  return;
}



int FUN_080490c0(char *param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_8;
  
  local_8 = 10;
  iVar4 = 0;
  cVar1 = *param_1;
  if ((cVar1 == '&') || ((cVar1 == '0' && ((param_1[1] == 'x' || (param_1[1] == 'X')))))) {
    local_8 = 0x10;
    if (cVar1 == '&') {
      param_1 = param_1 + 1;
    }
    else {
      param_1 = param_1 + 2;
    }
  }
  while( true ) {
    iVar2 = (int)*param_1;
    param_1 = param_1 + 1;
    iVar3 = 0;
    if (iVar2 == 0) break;
    iVar3 = isdigit(iVar2);
    if (iVar3 == 0) {
      iVar3 = tolower(iVar2);
      if (((local_8 != 0x10) || (iVar3 < 0x61)) || (0x66 < iVar3)) break;
      iVar4 = iVar3 + -0x57 + iVar4 * 0x10;
    }
    else {
      iVar4 = iVar2 + -0x30 + local_8 * iVar4;
    }
  }
  if ((iVar3 == 0x6b) || (iVar2 = iVar4, iVar3 == 0x6d)) {
    iVar2 = iVar4 << 10;
    if (iVar3 == 0x6d) {
      iVar2 = iVar4 << 0x14;
    }
    iVar3 = (int)*param_1;
  }
  if (iVar3 != 0) {
    FUN_0805b0d8(param_2);
  }
  return iVar2;
}



void FUN_0804917c(int *param_1,byte *param_2,char *param_3,int param_4)

{
  char local_24 [32];
  
  if (param_4 != 0) {
    local_24[0] = 'n';
    local_24[1] = 'o';
    strcpy(local_24 + 2,param_3);
    param_3 = local_24;
  }
  FUN_08061478(param_1,param_2,0x23,param_3);
  return;
}



undefined4 FUN_080491b8(undefined4 *param_1,char *param_2)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = strncmp(param_2,(char *)*param_1,param_1[1]);
  if ((iVar1 == 0) && (param_2[param_1[1]] == '.')) {
    uVar2 = __strtoul_internal(param_2 + param_1[1] + 1,0,0x10,0);
    if ((uint)param_1[2] < uVar2) {
      param_1[2] = uVar2;
    }
  }
  return 0;
}



undefined4 FUN_08049200(int *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  char *local_10;
  int local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  uVar2 = 0xffffffff;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *param_2;
    param_2 = param_2 + 1;
  } while (cVar1 != '\0');
  local_c = ~uVar2 - 1;
  local_8 = 0;
  FUN_080618f4(param_1,FUN_080491b8,&local_10);
  return local_8;
}



void FUN_08049240(int *param_1,char *param_2,char *param_3)

{
  int iVar1;
  byte local_1014 [4112];
  
  iVar1 = FUN_08049200(param_1,param_2);
  sprintf((char *)local_1014,"%s.%lx.%s",param_2,iVar1 + 0x1fffffU & 0xfff00000,param_3);
  FUN_0805d60c(param_1,local_1014,0x23,param_3);
  return;
}



undefined4 * FUN_08049290(undefined4 *param_1,undefined4 param_2)

{
  *param_1 = param_2;
  param_1[1] = &DAT_0806216d;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  return param_1;
}



undefined4 FUN_080492bc(int *param_1,int *param_2,int *param_3)

{
  char cVar1;
  int iVar2;
  FILE *__stream;
  size_t sVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  char *pcVar7;
  char *pcVar8;
  size_t sVar9;
  char *pcVar10;
  int iVar11;
  int *local_118;
  char local_114 [16];
  char local_104;
  char local_103 [255];
  
  iVar11 = *param_1;
  param_1[4] = param_1[4] + 1;
LAB_0804a9dd:
  local_118 = param_3 + 1;
  pcVar10 = (char *)*local_118;
  if (pcVar10 == (char *)0x0) {
    iVar2 = param_1[4];
    param_1[4] = iVar2 + -1;
    if (iVar2 != 1 && -1 < iVar2 + -1) {
      return 1;
    }
    if (((param_1[2] & 0x20aU) == 0x208) && (param_1[2] = param_1[2] & 0xfffffdff, iVar11 == 0)) {
      FUN_0805b0d8("2Relocatable is incompatible with plain binary format (-r ignored).");
    }
    uVar5 = param_1[2];
    if ((uVar5 & 0x840) == 0x840) {
      if (iVar11 == 0) {
        FUN_0805b0d8("1-SPLIT incompatible with -SCATTER. -SPLIT will be ignored.");
        uVar5 = param_1[2];
      }
      uVar5 = uVar5 & 0xfffff7ff;
      param_1[2] = uVar5;
    }
    if (uVar5 == 0x48) {
      pcVar10 = "=-scf -bin";
    }
    else if ((int)uVar5 < 0x49) {
      if (uVar5 == 8) {
        pcVar10 = "=-bin";
      }
      else if ((int)uVar5 < 9) {
        if (uVar5 == 1) {
          pcVar10 = "=-aof";
        }
        else {
          if ((int)uVar5 < 2) {
            uVar6 = 0;
            if (uVar5 != 0) goto LAB_0804acd0;
            goto LAB_0804acf0;
          }
          if (uVar5 == 2) {
            pcVar10 = "=-aif";
          }
          else {
            if (uVar5 != 4) goto LAB_0804acd0;
            if ((*(byte *)((int)param_1 + 0xd) & 2) != 0) {
              if (iVar11 == 0) {
                FUN_0805b0d8(
                            "1-RW-base/-DATA incompatible with -IHF without -SPLIT\n    (-RW-base/-DATA ignored)."
                            );
              }
              FUN_080614f4(param_2,(byte *)"-rw-base","=");
            }
            pcVar10 = "=-ihf";
          }
        }
      }
      else if (uVar5 == 0x20) {
        pcVar10 = "=-elf";
      }
      else if ((int)uVar5 < 0x21) {
        if (uVar5 == 10) {
          pcVar10 = "=-aif -bin";
        }
        else {
          if (uVar5 != 0x10) goto LAB_0804acd0;
          pcVar10 = "=-rmf";
        }
      }
      else {
        if (uVar5 != 0x40) {
          if (uVar5 != 0x42) goto LAB_0804acd0;
          if (iVar11 == 0) {
            FUN_0805b0d8("1-AIF specified with -SCATTER is equivalent to -AIF -BIN.");
          }
          goto LAB_0804ac86;
        }
LAB_0804ac47:
        pcVar10 = "=-scf -elf";
      }
    }
    else if ((int)uVar5 < 0x402) {
      if ((int)uVar5 < 0x400) {
        if (uVar5 == 0x80) {
          pcVar10 = "=-ovf";
        }
        else if ((int)uVar5 < 0x81) {
          if (uVar5 != 0x4a) {
            if (uVar5 != 0x60) goto LAB_0804acd0;
            goto LAB_0804ac47;
          }
LAB_0804ac86:
          pcVar10 = "=-scf -aif -bin";
        }
        else {
          if ((uVar5 != 0x200) && (uVar5 != 0x202)) goto LAB_0804acd0;
          pcVar10 = "=-aif -reloc";
        }
      }
      else {
        pcVar10 = "=-shf";
      }
    }
    else if (uVar5 == 0x804) {
      pcVar10 = "=-ihf -split";
    }
    else if ((int)uVar5 < 0x805) {
      if ((0x501 < (int)uVar5) || ((int)uVar5 < 0x500)) {
LAB_0804acd0:
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8(
                    "3Bad output specification: use one of -aif, -elf, -aof, -scf, -ovf, -shl, -bin, -ihf or -rmf."
                    );
        return 0;
      }
      pcVar10 = "=-shf -reent";
    }
    else {
      if (uVar5 != 0x808) goto LAB_0804acd0;
      pcVar10 = "=-bin -split";
    }
    FUN_080614f4(param_2,(byte *)".format",pcVar10);
    uVar6 = param_1[2];
LAB_0804acf0:
    if (((((uVar6 & 10) == 8) || ((uVar6 & 4) != 0)) && ((*(byte *)((int)param_1 + 0xd) & 4) != 0))
       && (iVar11 == 0)) {
      FUN_0805b0d8("1Debug data incompatible with plain binary format (-d ignored).");
    }
    return 1;
  }
  if (*pcVar10 != '-') {
    uVar5 = 0xffffffff;
    pcVar7 = pcVar10;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar7 + 1;
    } while (cVar1 != '\0');
    iVar2 = tolower((int)pcVar10[~uVar5 - 2]);
    if (((iVar2 == 0x61) || (iVar2 == 0x6c)) && (pcVar10[~uVar5 - 3] == '/')) {
      param_1[1] = (int)&DAT_08062170;
    }
    pcVar7 = (char *)param_1[1];
LAB_0804a97a:
    FUN_08049240(param_2,pcVar7,pcVar10);
    param_3 = local_118;
    goto LAB_0804a9dd;
  }
  pcVar7 = pcVar10 + 1;
  iVar2 = tolower((int)*pcVar7);
  switch(iVar2) {
  case 0x61:
    iVar2 = FUN_0804b6c0(pcVar7,"aif");
    if (iVar2 == 0) {
      *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 2;
      param_3 = local_118;
    }
    else {
      iVar2 = FUN_0804b6c0(pcVar7,"aof");
      if (iVar2 != 0) goto switchD_08049359_caseD_67;
      *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 1;
      param_3 = local_118;
    }
    goto LAB_0804a9dd;
  case 0x62:
    if ((pcVar10[2] == '\0') || (iVar2 = FUN_0804b6c0(pcVar7,"base"), iVar2 == 0)) {
      FUN_0805b0d8(
                  "1\'%s\' will not be supported by future releases of armlink. Please use alias \'%s\' instead."
                  );
      goto LAB_08049ef1;
    }
    iVar2 = FUN_0804b6c0(pcVar7,"bin");
    if (iVar2 != 0) goto switchD_08049359_caseD_67;
    *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 8;
    param_3 = local_118;
    goto LAB_0804a9dd;
  case 99:
    if ((pcVar10[2] != '\0') && (iVar2 = FUN_0804b6c0(pcVar7,"case"), iVar2 != 0)) {
      iVar2 = FUN_0804b6c0(pcVar7,"config");
      if (iVar2 != 0) goto switchD_08049359_caseD_67;
      DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ | 4;
      param_3 = local_118;
      goto LAB_0804a9dd;
    }
    pcVar10 = "=-case";
    pcVar7 = ".case";
    break;
  case 100:
    iVar2 = FUN_0804b6c0(pcVar7,"dde");
    if (iVar2 == 0) {
      FUN_080614f4(param_2,&DAT_08062221,"=-dde");
      *(byte *)((int)param_1 + 0xd) = *(byte *)((int)param_1 + 0xd) | 8;
      param_3 = local_118;
      goto LAB_0804a9dd;
    }
    iVar2 = FUN_0804b6c0(pcVar7,"dupok");
    if (iVar2 == 0) {
      pcVar10 = "=-dupok";
      pcVar7 = ".dupok";
    }
    else {
      iVar2 = FUN_0804b6c0(pcVar7,"data");
      if (iVar2 == 0) {
        pcVar10 = ".dat";
        FUN_0805b0d8(
                    "1\'%s\' will not be supported by future releases of armlink. Please use alias \'%s\' instead."
                    );
LAB_08049f9d:
        if ((*(byte *)((int)param_1 + 0xd) & 2) != 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3Multiple -%s options.");
          return 0;
        }
        param_3 = param_3 + 2;
        if (*param_3 == 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3No argument to -%s.");
          return 0;
        }
        FUN_08061478(param_2,(byte *)"-rw-ext",0x23,pcVar10);
        FUN_08061478(param_2,(byte *)"-rw-base",0x23,(char *)*param_3);
        *(byte *)((int)param_1 + 0xd) = *(byte *)((int)param_1 + 0xd) | 2;
        goto LAB_0804a9dd;
      }
      if (((pcVar10[2] != '\0') && (iVar2 = FUN_0804b6c0(pcVar7,"debug"), iVar2 != 0)) &&
         ((iVar2 = FUN_0804b6c0(pcVar7,"dbug"), iVar2 != 0 &&
          (iVar2 = FUN_0804b6c0(pcVar7,"dsuppress"), iVar2 != 0)))) goto switchD_08049359_caseD_67;
      FUN_080614f4(param_2,(byte *)".debug","=-debug");
      uVar5 = param_1[3];
      param_1[3] = uVar5 | 0x400;
      if (((uVar5 & 0x800) != 0) && (iVar2 = FUN_0804b6c0(pcVar7,"dbug"), iVar2 == 0)) {
        param_1[2] = 1;
        param_3 = local_118;
        goto LAB_0804a9dd;
      }
      iVar2 = FUN_0804b6c0(pcVar7,"dsuppress");
      param_3 = local_118;
      if (iVar2 != 0) goto LAB_0804a9dd;
      pcVar10 = "=-dsuppress";
      pcVar7 = ".dsuppress";
    }
    break;
  case 0x65:
    iVar2 = FUN_0804b6c0(pcVar7,"errors");
    if (iVar2 == 0) {
      if ((*(byte *)((int)param_1 + 0xd) & 0x10) != 0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3Multiple -%s options.");
        return 0;
      }
      param_3 = param_3 + 2;
      if ((char *)*param_3 == (char *)0x0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3No argument to -%s.");
        return 0;
      }
      FUN_08061478(param_2,(byte *)"-errors",0x23,(char *)*param_3);
      *(byte *)((int)param_1 + 0xd) = *(byte *)((int)param_1 + 0xd) | 0x10;
      goto LAB_0804a9dd;
    }
    iVar2 = FUN_0804b6c0(pcVar7,"edit");
    if (iVar2 == 0) {
      if ((char)param_1[3] < '\0') {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3Multiple -%s options.");
        return 0;
      }
      local_118 = param_3 + 2;
      if (*local_118 == 0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3No argument to -%s.");
        return 0;
      }
      *(byte *)(param_1 + 3) = *(byte *)(param_1 + 3) | 0x80;
      pcVar10 = (char *)*local_118;
      iVar2 = 0x23;
      pcVar7 = "-edit";
      goto LAB_0804a88e;
    }
    iVar2 = FUN_0804b6c0(pcVar7,"echo");
    if (iVar2 != 0) {
      if (((pcVar10[2] == '\0') || (iVar2 = FUN_0804b6c0(pcVar7,"en"), iVar2 == 0)) ||
         (iVar2 = FUN_0804b6c0(pcVar7,"entry"), iVar2 == 0)) {
        if ((*(byte *)(param_1 + 3) & 0x40) != 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3Multiple -%s options.");
          return 0;
        }
        param_3 = param_3 + 2;
        if ((char *)*param_3 == (char *)0x0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3No argument to -%s.");
          return 0;
        }
        FUN_08061478(param_2,(byte *)"-entry",0x23,(char *)*param_3);
        *(byte *)(param_1 + 3) = *(byte *)(param_1 + 3) | 0x40;
      }
      else {
        iVar2 = FUN_0804b6c0(pcVar7,"elf");
        if (iVar2 != 0) goto switchD_08049359_caseD_67;
        *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 0x20;
        param_3 = local_118;
      }
      goto LAB_0804a9dd;
    }
    pcVar10 = "=-echo";
    pcVar7 = ".echo";
    break;
  case 0x66:
    iVar2 = FUN_0804b6c0(pcVar7,"first");
    if (iVar2 == 0) {
      if ((*(byte *)((int)param_1 + 0xd) & 0x20) != 0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3Multiple -%s options.");
        return 0;
      }
      param_3 = param_3 + 2;
      if ((char *)*param_3 == (char *)0x0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3No argument to -%s.");
        return 0;
      }
      FUN_08061478(param_2,(byte *)"-first",0x23,(char *)*param_3);
      *(byte *)((int)param_1 + 0xd) = *(byte *)((int)param_1 + 0xd) | 0x20;
    }
    else {
      if (pcVar10[2] != '\0') goto switchD_08049359_caseD_67;
      param_1[1] = (int)&DAT_0806216d;
      param_3 = local_118;
    }
    goto LAB_0804a9dd;
  default:
switchD_08049359_caseD_67:
    if (iVar11 != 0) {
      return 0;
    }
    FUN_0805b0d8("3Unrecognised option -%s.");
    return 0;
  case 0x68:
    param_3 = local_118;
    if (iVar11 == 0) {
      iVar11 = 0;
LAB_0804acc2:
      FUN_08059be0(iVar11);
      return 0;
    }
    goto LAB_0804a9dd;
  case 0x69:
    iVar2 = FUN_0804b6c0(pcVar7,"ihf");
    if (iVar2 == 0) {
      *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 4;
      param_3 = local_118;
    }
    else {
      iVar2 = FUN_0804b6c0(pcVar7,"info");
      if (iVar2 != 0) {
        iVar2 = FUN_0804b6c0(pcVar7,"image");
        if (iVar2 != 0) goto switchD_08049359_caseD_67;
        pcVar7 = "o";
        goto switchD_08049359_caseD_6f;
      }
      pcVar10 = &local_104;
      param_3 = param_3 + 2;
      if ((char *)*param_3 == (char *)0x0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3No argument to -%s.");
        return 0;
      }
      strcpy(pcVar10,(char *)*param_3);
      do {
        cVar1 = *pcVar10;
        pcVar7 = pcVar10;
        while ((cVar1 != '\0' && (cVar1 != ','))) {
          pcVar7 = pcVar7 + 1;
          cVar1 = *pcVar7;
        }
        *pcVar7 = '\0';
        iVar2 = strncmp(pcVar10,"no",2);
        if (iVar2 == 0) {
          pcVar10 = pcVar10 + 2;
        }
        iVar4 = FUN_0804b6c0(pcVar10,"size");
        if ((iVar4 == 0) || (iVar4 = FUN_0804b6c0(pcVar10,"sizes"), iVar4 == 0)) {
          pcVar8 = "size";
          pcVar10 = "-info.size";
        }
        else {
          iVar4 = FUN_0804b6c0(pcVar10,"inter");
          if ((iVar4 == 0) || (iVar4 = FUN_0804b6c0(pcVar10,"interwork"), iVar4 == 0)) {
            pcVar8 = "inter";
            pcVar10 = "-info.inter";
          }
          else {
            iVar4 = FUN_0804b6c0(pcVar10,"unaligned");
            if (iVar4 == 0) {
              pcVar8 = "unaligned";
              pcVar10 = "-info.unaligned";
            }
            else {
              iVar4 = FUN_0804b6c0(pcVar10,"total");
              if ((iVar4 == 0) || (iVar4 = FUN_0804b6c0(pcVar10,"totals"), iVar4 == 0)) {
                pcVar8 = "total";
                pcVar10 = "-info.total";
              }
              else {
                iVar4 = FUN_0804b6c0(pcVar10,"unused");
                if (iVar4 == 0) {
                  pcVar8 = "unused";
                  pcVar10 = "-info.unused";
                }
                else {
                  iVar4 = FUN_0804b6c0(pcVar10,"nonstrong");
                  if (iVar4 != 0) {
                    if (iVar11 != 0) {
                      return 0;
                    }
                    FUN_0805b0d8("3Unrecognised argument %s on -info option");
                    return 0;
                  }
                  pcVar8 = "nonstrong";
                  pcVar10 = "-info.nonstrong";
                }
              }
            }
          }
        }
        FUN_0804917c(param_2,(byte *)pcVar10,pcVar8,(uint)(iVar2 == 0));
        pcVar10 = pcVar7 + 1;
      } while (cVar1 != '\0');
    }
    goto LAB_0804a9dd;
  case 0x6c:
    iVar2 = FUN_0804b6c0(pcVar7,"list");
    if (iVar2 != 0) {
      iVar2 = FUN_0804b6c0(pcVar7,"last");
      if (iVar2 == 0) {
        if ((*(byte *)((int)param_1 + 0xd) & 0x40) != 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3Multiple -%s options.");
          return 0;
        }
        param_3 = param_3 + 2;
        if ((char *)*param_3 == (char *)0x0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3No argument to -%s.");
          return 0;
        }
        FUN_08061478(param_2,(byte *)"-last",0x23,(char *)*param_3);
        *(byte *)((int)param_1 + 0xd) = *(byte *)((int)param_1 + 0xd) | 0x40;
      }
      else {
        iVar2 = FUN_0804b6c0(pcVar7,"libpath");
        if (iVar2 == 0) {
          local_118 = param_3 + 2;
          pcVar10 = (char *)*local_118;
          if (pcVar10 == (char *)0x0) {
            if (iVar11 != 0) {
              return 0;
            }
            FUN_0805b0d8("3No argument to -%s.");
            return 0;
          }
          iVar2 = 0x23;
          pcVar7 = "-libpath";
          goto LAB_0804a88e;
        }
        if (pcVar10[2] != '\0') goto switchD_08049359_caseD_67;
        param_1[1] = (int)&DAT_08062170;
        param_3 = local_118;
      }
      goto LAB_0804a9dd;
    }
    if ((short)param_1[3] < 0) {
      if (iVar11 != 0) {
        return 0;
      }
      FUN_0805b0d8("3Multiple -%s options.");
      return 0;
    }
    local_118 = param_3 + 2;
    if (*local_118 == 0) {
      if (iVar11 != 0) {
        return 0;
      }
      FUN_0805b0d8("3No argument to -%s.");
      return 0;
    }
    *(byte *)((int)param_1 + 0xd) = *(byte *)((int)param_1 + 0xd) | 0x80;
    iVar2 = FUN_0804b6c0((char *)*local_118,"-");
    if (iVar2 == 0) {
      pcVar10 = "=";
      pcVar7 = "-list";
      break;
    }
    pcVar10 = (char *)*local_118;
    iVar2 = 0x23;
    pcVar7 = "-list";
    goto LAB_0804a88e;
  case 0x6d:
    iVar2 = FUN_0804b6c0(pcVar7,"map");
    if (iVar2 != 0) {
      iVar2 = FUN_0804b6c0(pcVar7,"match");
      if (iVar2 != 0) goto switchD_08049359_caseD_67;
      local_118 = param_3 + 2;
      pcVar10 = (char *)*local_118;
      if (pcVar10 == (char *)0x0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3No argument to -%s.");
        return 0;
      }
      iVar2 = 0x23;
      pcVar7 = "-match";
      goto LAB_0804a88e;
    }
    pcVar10 = "=-map";
    pcVar7 = &DAT_08062435;
    break;
  case 0x6e:
    iVar2 = FUN_0804b6c0(pcVar7,"nounusedareas");
    if (((iVar2 == 0) || (iVar2 = FUN_0804b6c0(pcVar7,"nounused"), iVar2 == 0)) ||
       ((iVar2 = FUN_0804b6c0(pcVar7,"noremove"), iVar2 == 0 ||
        (iVar2 = FUN_0804b6c0(pcVar7,"nounusedremoval"), iVar2 == 0)))) {
      if ((param_1[3] & 2U) != 0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3Conflicting options:  only one of -remove and -noremove may be used.");
        return 0;
      }
      param_1[3] = param_1[3] | 4;
      pcVar10 = "=-noremove";
      pcVar7 = ".remove";
    }
    else {
      iVar2 = FUN_0804b6c0(pcVar7,"noautoplace");
      if (iVar2 == 0) {
        pcVar10 = "=-noautoplace";
        pcVar7 = ".autoplace";
      }
      else {
        iVar2 = FUN_0804b6c0(pcVar7,"nod");
        if (((iVar2 == 0) || (iVar2 = FUN_0804b6c0(pcVar7,"nodeb"), iVar2 == 0)) ||
           (iVar2 = FUN_0804b6c0(pcVar7,"nodebug"), iVar2 == 0)) {
          pcVar10 = "=";
          pcVar7 = ".debug";
        }
        else {
          iVar2 = FUN_0804b6c0(pcVar7,"nodupok");
          if (iVar2 == 0) {
            pcVar10 = "=-nodupok";
            pcVar7 = ".dupok";
          }
          else {
            iVar2 = FUN_0804b6c0(pcVar7,"nocase");
            if (iVar2 == 0) {
              pcVar10 = "=-nocase";
              pcVar7 = ".case";
            }
            else {
              iVar2 = FUN_0804b6c0(pcVar7,"nosymb");
              if (iVar2 == 0) {
                pcVar10 = "=-nosymb";
                pcVar7 = ".symb";
              }
              else {
                iVar2 = FUN_0804b6c0(pcVar7,"nomap");
                if (iVar2 == 0) {
                  pcVar10 = "=-nomap";
                  pcVar7 = &DAT_08062435;
                }
                else {
                  iVar2 = FUN_0804b6c0(pcVar7,"noxref");
                  if (iVar2 == 0) {
                    pcVar10 = "=-noxref";
                    pcVar7 = ".xref";
                  }
                  else {
                    iVar2 = FUN_0804b6c0(pcVar7,"noz");
                    if ((((iVar2 == 0) || (iVar2 = FUN_0804b6c0(pcVar7,"nozero"), iVar2 == 0)) ||
                        (iVar2 = FUN_0804b6c0(pcVar7,"nozeros"), iVar2 == 0)) ||
                       (iVar2 = FUN_0804b6c0(pcVar7,"nozeropad"), iVar2 == 0)) {
                      pcVar10 = "=-nozeropad";
                      goto LAB_0804a99b;
                    }
                    iVar2 = FUN_0804b6c0(pcVar7,"noscan");
                    if ((iVar2 == 0) || (iVar2 = FUN_0804b6c0(pcVar7,"noscanlib"), iVar2 == 0)) {
                      pcVar10 = "=-noscanlib";
                      pcVar7 = ".scanlib";
                    }
                    else {
                      iVar2 = FUN_0804b6c0(pcVar7,"noecho");
                      if (iVar2 == 0) {
                        pcVar10 = "=";
                        pcVar7 = ".echo";
                      }
                      else {
                        iVar2 = FUN_0804b6c0(pcVar7,"nosortbyname");
                        if (iVar2 != 0) goto switchD_08049359_caseD_67;
                        pcVar10 = "=-nosortbyname";
                        pcVar7 = ".sortbyname";
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    break;
  case 0x6f:
switchD_08049359_caseD_6f:
    iVar2 = FUN_0804b6c0(pcVar7,"ovf");
    if (iVar2 != 0) {
      iVar2 = FUN_0804b6c0(pcVar7,"ov");
      if ((iVar2 == 0) || (iVar2 = FUN_0804b6c0(pcVar7,"overlay"), iVar2 == 0)) {
        if ((param_1[2] & 0x40U) != 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3Multiple -%s options.");
          return 0;
        }
        param_1[2] = param_1[2] | 0x80;
LAB_0804a572:
        if ((param_1[3] & 0x10U) != 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3Multiple -%s options.");
          return 0;
        }
        local_118 = param_3 + 2;
        if (*local_118 == 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3No argument to -%s.");
          return 0;
        }
        param_1[3] = param_1[3] | 0x10;
        pcVar10 = (char *)*local_118;
        iVar2 = 0x23;
        pcVar7 = "-scov";
      }
      else {
        if ((pcVar7[1] != '\0') && (iVar2 = FUN_0804b6c0(pcVar7,"output"), iVar2 != 0))
        goto switchD_08049359_caseD_67;
        if ((param_1[3] & 1U) != 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3Multiple -%s options.");
          return 0;
        }
        local_118 = param_3 + 2;
        if (*local_118 == 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3No argument to -%s.");
          return 0;
        }
        param_1[3] = param_1[3] | 1;
        pcVar10 = (char *)*local_118;
        iVar2 = 0x23;
        pcVar7 = &DAT_08062428;
      }
      goto LAB_0804a88e;
    }
    *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 0x80;
    param_3 = local_118;
    goto LAB_0804a9dd;
  case 0x71:
    local_118 = param_3 + 2;
    pcVar10 = (char *)*local_118;
    if (pcVar10 == (char *)0x0) {
      if (iVar11 != 0) {
        return 0;
      }
      FUN_0805b0d8("3No argument to -%s.");
      return 0;
    }
    iVar2 = 0x23;
    pcVar7 = &DAT_08062447;
    goto LAB_0804a88e;
  case 0x72:
    iVar2 = FUN_0804b6c0(pcVar7,"rmf");
    if (iVar2 == 0) {
      *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 0x10;
      param_3 = local_118;
    }
    else {
      iVar2 = FUN_0804b6c0(pcVar7,"reent");
      if ((iVar2 == 0) || (iVar2 = FUN_0804b6c0(pcVar7,"reentrant"), iVar2 == 0)) {
        *(byte *)((int)param_1 + 9) = *(byte *)((int)param_1 + 9) | 1;
        param_3 = local_118;
      }
      else {
        iVar2 = FUN_0804b6c0(pcVar7,"ro");
        if ((iVar2 == 0) || (iVar2 = FUN_0804b6c0(pcVar7,"ro-base"), iVar2 == 0)) {
          FUN_080614f4(param_2,(byte *)"-ro-ext","#.ro");
LAB_08049ef1:
          if ((*(byte *)((int)param_1 + 0xd) & 1) != 0) {
            if (iVar11 != 0) {
              return 0;
            }
            FUN_0805b0d8("3Multiple base addresses specified.");
            return 0;
          }
          param_3 = param_3 + 2;
          if ((char *)*param_3 == (char *)0x0) {
            if (iVar11 != 0) {
              return 0;
            }
            FUN_0805b0d8("3Badly formed or missing -RO-base/-Base value.");
            return 0;
          }
          FUN_08061478(param_2,(byte *)"-ro-base",0x23,(char *)*param_3);
          *(byte *)((int)param_1 + 0xd) = *(byte *)((int)param_1 + 0xd) | 1;
        }
        else {
          iVar2 = FUN_0804b6c0(pcVar7,"rw");
          if ((iVar2 == 0) || (iVar2 = FUN_0804b6c0(pcVar7,"rw-base"), iVar2 == 0)) {
            pcVar10 = ".rw";
            goto LAB_08049f9d;
          }
          iVar2 = FUN_0804b6c0(pcVar7,"remove");
          if (iVar2 == 0) {
            if ((param_1[3] & 4U) != 0) {
              if (iVar11 != 0) {
                return 0;
              }
              FUN_0805b0d8("3Conflicting options:  only one of -remove and -noremove may be used.");
              return 0;
            }
            param_1[3] = param_1[3] | 2;
            pcVar10 = "=-remove";
            pcVar7 = ".remove";
            break;
          }
          if ((((pcVar10[2] != '\0') && (iVar2 = FUN_0804b6c0(pcVar7,"rel"), iVar2 != 0)) &&
              (iVar2 = FUN_0804b6c0(pcVar7,"reloc"), iVar2 != 0)) &&
             (iVar2 = FUN_0804b6c0(pcVar7,"relocatable"), iVar2 != 0))
          goto switchD_08049359_caseD_67;
          *(byte *)((int)param_1 + 9) = *(byte *)((int)param_1 + 9) | 2;
          param_3 = local_118;
        }
      }
    }
    goto LAB_0804a9dd;
  case 0x73:
    iVar2 = FUN_0804b6c0(pcVar7,"shf");
    if (iVar2 == 0) {
      *(byte *)((int)param_1 + 9) = *(byte *)((int)param_1 + 9) | 4;
      param_3 = local_118;
    }
    else {
      iVar2 = FUN_0804b6c0(pcVar7,"shl");
      if (iVar2 == 0) {
        local_118 = param_3 + 2;
        if (*local_118 == 0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3No argument to -%s.");
          return 0;
        }
        *(byte *)((int)param_1 + 9) = *(byte *)((int)param_1 + 9) | 4;
        pcVar10 = (char *)*local_118;
        iVar2 = 0x23;
        pcVar7 = &DAT_080626ea;
        goto LAB_0804a88e;
      }
      iVar2 = FUN_0804b6c0(pcVar7,"symb");
      if (iVar2 == 0) {
        pcVar10 = "=-symb";
        pcVar7 = ".symb";
        break;
      }
      if ((((pcVar10[2] == '\0') || (iVar2 = FUN_0804b6c0(pcVar7,"sym"), iVar2 == 0)) ||
          (iVar2 = FUN_0804b6c0(pcVar7,"symbols"), iVar2 == 0)) ||
         (iVar2 = FUN_0804b6c0(pcVar7,"symbolsx"), iVar2 == 0)) {
        local_118 = param_3 + 2;
        if ((char *)*local_118 == (char *)0x0) {
          if (iVar11 != 0) {
            return 0;
          }
          FUN_0805b0d8("3No argument to -%s.");
          return 0;
        }
        iVar2 = FUN_0804b6c0((char *)*local_118,"-");
        if (iVar2 != 0) {
          FUN_08061478(param_2,(byte *)"-symfile",0x23,(char *)*local_118);
        }
        iVar2 = FUN_0804b6c0(pcVar7,"symbolsx");
        if (iVar2 == 0) {
          pcVar10 = "=-symbx";
          pcVar7 = ".symb";
        }
        else {
          pcVar10 = "=-symb";
          pcVar7 = ".symb";
        }
        break;
      }
      iVar2 = FUN_0804b6c0(pcVar7,"split");
      if (iVar2 == 0) {
        *(byte *)((int)param_1 + 9) = *(byte *)((int)param_1 + 9) | 8;
        param_3 = local_118;
      }
      else {
        iVar2 = FUN_0804b6c0(pcVar7,"scf");
        if (iVar2 != 0) {
          iVar2 = FUN_0804b6c0(pcVar7,"scatter");
          if (iVar2 == 0) {
            if ((char)param_1[2] < '\0') {
              if (iVar11 != 0) {
                return 0;
              }
              FUN_0805b0d8("3Multiple -%s options.");
              return 0;
            }
            *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 0x40;
          }
          else {
            iVar2 = FUN_0804b6c0(pcVar7,"scov");
            if (iVar2 != 0) {
              iVar2 = FUN_0804b6c0(pcVar7,"scan");
              if ((iVar2 != 0) && (iVar2 = FUN_0804b6c0(pcVar7,"scanlib"), iVar2 != 0))
              goto switchD_08049359_caseD_67;
              pcVar10 = "=-scanlib";
              pcVar7 = ".scanlib";
              break;
            }
          }
          goto LAB_0804a572;
        }
        *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 0x40;
        param_3 = local_118;
      }
    }
    goto LAB_0804a9dd;
  case 0x75:
    if ((pcVar10[2] == '\0') || (iVar2 = FUN_0804b6c0(pcVar7,"unresolved"), iVar2 == 0)) {
      local_118 = param_3 + 2;
      if (*local_118 == 0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3No argument to -%s.");
        return 0;
      }
      if ((param_1[3] & 0x20U) != 0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3Multiple -Unresolved options given.");
        return 0;
      }
      param_1[3] = param_1[3] | 0x20;
      FUN_08061478(param_2,(byte *)"-unresolved",0x23,(char *)*local_118);
      if (pcVar10[2] == '\0') {
        pcVar10 = "=-unresolvedwarn";
        pcVar7 = ".unresolvedwarn";
      }
      else {
        pcVar10 = "=-nounresolvedwarn";
        pcVar7 = ".unresolvedwarn";
      }
    }
    else {
      iVar2 = FUN_0804b6c0(pcVar7,"unused");
      if (iVar2 != 0) goto switchD_08049359_caseD_67;
      pcVar10 = "=-noremove";
      pcVar7 = ".remove";
    }
    break;
  case 0x76:
    iVar2 = FUN_0804b6c0(pcVar7,"vsn");
    if (iVar2 == 0) {
      iVar11 = 1;
      goto LAB_0804acc2;
    }
    iVar2 = FUN_0804b6c0(pcVar7,"via");
    if (iVar2 == 0) {
      param_3 = param_3 + 2;
      pcVar10 = (char *)*param_3;
      if (pcVar10 == (char *)0x0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3No argument to -%s.");
        return 0;
      }
      __stream = FUN_08060e7c(pcVar10,"r");
      if (__stream == (FILE *)0x0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3Can\'t open file \'%s\'.");
        return 0;
      }
      FUN_0804b418();
      sVar9 = 0x2000;
      iVar2 = 0;
      pcVar7 = (char *)FUN_0804b3ac(0x2000);
      setvbuf(__stream,pcVar7,iVar2,sVar9);
      sVar9 = FUN_08060f80(pcVar10);
      pcVar10 = (char *)FUN_0804b1e8(sVar9 + 1);
      sVar3 = fread(pcVar10,sVar9,1,__stream);
      if ((sVar3 != 1) || (iVar2 = ferror(__stream), iVar2 != 0)) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3Error reading file %s.");
        return 0;
      }
      pcVar10[sVar9] = '\0';
      FUN_08060ec8(__stream);
      FUN_0804b434();
      iVar2 = FUN_0804ad2c(param_1,param_2,pcVar10);
      if (iVar2 == 0) {
        return 0;
      }
    }
    else {
      iVar2 = isdigit((int)pcVar10[2]);
      if (iVar2 != 0) {
        pcVar10 = pcVar10 + 2;
        iVar2 = 0x3d;
        pcVar7 = &DAT_080627fe;
        goto LAB_0804a88e;
      }
      cVar1 = *pcVar7;
      pcVar10 = pcVar10 + 2;
      iVar2 = 0;
      while ((iVar4 = tolower((int)cVar1), iVar4 == 0x65 || (iVar4 == 0x76))) {
        iVar2 = iVar2 + 1;
        cVar1 = *pcVar10;
        pcVar10 = pcVar10 + 1;
      }
      sprintf(local_114,"=%d",iVar2);
      FUN_080614f4(param_2,&DAT_080627fe,local_114);
      param_3 = local_118;
    }
    goto LAB_0804a9dd;
  case 0x77:
    if ((param_1[3] & 8U) != 0) {
      if (iVar11 != 0) {
        return 0;
      }
      FUN_0805b0d8("3Multiple -%s options.");
      return 0;
    }
    local_118 = param_3 + 2;
    if (*local_118 == 0) {
      if (iVar11 != 0) {
        return 0;
      }
      FUN_0805b0d8("3No argument to -%s.");
      return 0;
    }
    param_1[3] = param_1[3] | 8;
    pcVar10 = (char *)*local_118;
    iVar2 = 0x23;
    pcVar7 = &DAT_0806244a;
LAB_0804a88e:
    FUN_08061478(param_2,(byte *)pcVar7,iVar2,pcVar10);
    param_3 = local_118;
    goto LAB_0804a9dd;
  case 0x78:
    if ((pcVar10[2] != '\0') && (iVar2 = FUN_0804b6c0(pcVar7,"xref"), iVar2 != 0)) {
      iVar2 = FUN_0804b6c0(pcVar7,"xreffrom");
      if ((iVar2 != 0) && (iVar2 = FUN_0804b6c0(pcVar7,"xrefto"), iVar2 != 0))
      goto switchD_08049359_caseD_67;
      local_118 = param_3 + 2;
      pcVar10 = (char *)*local_118;
      if (pcVar10 == (char *)0x0) {
        if (iVar11 != 0) {
          return 0;
        }
        FUN_0805b0d8("3No argument to -%s.");
        return 0;
      }
      goto LAB_0804a97a;
    }
    pcVar10 = "=-xref";
    pcVar7 = ".xref";
    break;
  case 0x7a:
    iVar2 = FUN_0804b6c0(pcVar7,"zeropad");
    if (iVar2 != 0) goto switchD_08049359_caseD_67;
    pcVar10 = "=-zeropad";
LAB_0804a99b:
    pcVar7 = ".zeropad";
  }
  FUN_080614f4(param_2,(byte *)pcVar7,pcVar10);
  param_3 = local_118;
  goto LAB_0804a9dd;
}



undefined4 FUN_0804ad2c(int *param_1,int *param_2,char *param_3)

{
  char *pcVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  char *pcVar6;
  int local_18;
  char *local_14;
  int local_c;
  int *local_8;
  
  local_8 = (int *)0x0;
  iVar2 = *param_1;
  local_14 = param_3;
  do {
    while (iVar3 = isspace((int)*local_14), iVar3 != 0) {
      local_14 = local_14 + 1;
    }
    local_c = 1;
    while (iVar3 = (int)*local_14, iVar3 != 0) {
      if (iVar3 == 0x22) {
        pcVar1 = local_14 + 1;
        do {
          if (iVar3 == 0x22) break;
          iVar3 = (int)*local_14;
          local_14 = local_14 + 1;
        } while (iVar3 != 0);
        pcVar6 = local_14 + -1;
        local_14 = pcVar1;
      }
      else {
        local_18 = 0;
        pcVar6 = local_14;
        while ((iVar3 != 0 && ((iVar4 = isspace(iVar3), iVar4 == 0 || (0 < local_18))))) {
          if (iVar3 == 0x29) {
            local_18 = local_18 + -1;
          }
          else if (iVar3 == 0x28) {
            local_18 = local_18 + 1;
          }
          pcVar6 = pcVar6 + 1;
          iVar3 = (int)*pcVar6;
        }
      }
      if (local_8 != (int *)0x0) {
        local_8[local_c] = (int)local_14;
      }
      if (iVar3 != 0) {
        if (local_8 != (int *)0x0) {
          *pcVar6 = '\0';
        }
        do {
          pcVar6 = pcVar6 + 1;
          iVar3 = isspace((int)*pcVar6);
        } while (iVar3 != 0);
      }
      local_c = local_c + 1;
      local_14 = pcVar6;
    }
    if (local_8 != (int *)0x0) {
      local_8[local_c] = 0;
      uVar5 = FUN_080492bc(param_1,param_2,local_8);
      free(local_8);
      return uVar5;
    }
    local_8 = malloc(local_c * 4 + 4);
    local_14 = param_3;
    if (local_8 == (int *)0x0) {
      if (iVar2 == 0) {
        FUN_0805b0d8("3Out of memory.");
      }
      return 0;
    }
  } while( true );
}



uint FUN_0804ae80(char *param_1,int param_2)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 0;
  cVar1 = *param_1;
  while (cVar1 != '\0') {
    iVar2 = tolower((int)*param_1);
    uVar3 = iVar2 + uVar3 * 0x25;
    param_1 = param_1 + 1;
    cVar1 = *param_1;
  }
  return uVar3 & param_2 - 1U;
}



undefined4 * FUN_0804aebc(int param_1,int param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  code *pcVar4;
  
  if (param_2 == 1) {
    pcVar4 = FUN_0804b1e8;
  }
  else {
    pcVar4 = FUN_0804b3ac;
  }
  puVar2 = (undefined4 *)(*pcVar4)(0xc);
  puVar2[1] = param_1;
  puVar2[2] = pcVar4;
  puVar3 = (undefined4 *)(*pcVar4)(param_1 * 4);
  *puVar2 = puVar3;
  puVar1 = puVar3 + param_1;
  for (; puVar3 < puVar1; puVar3 = puVar3 + 1) {
    *puVar3 = 0;
  }
  return puVar2;
}



undefined4 FUN_0804af0c(undefined4 *param_1,char *param_2,int *param_3,undefined *param_4)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  int *piVar6;
  char *pcVar7;
  
  uVar2 = FUN_0804ae80(param_2,param_3[1]);
  piVar6 = *(int **)(*param_3 + uVar2 * 4);
  if (piVar6 != (int *)0x0) {
    do {
      iVar3 = (*(code *)param_4)(piVar6 + 2,param_2);
      if (iVar3 == 0) break;
      piVar6 = (int *)*piVar6;
    } while (piVar6 != (int *)0x0);
    if (piVar6 != (int *)0x0) {
      *param_1 = piVar6 + 1;
      return 0;
    }
  }
  uVar5 = 0xffffffff;
  pcVar7 = param_2;
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar7 + 1;
  } while (cVar1 != '\0');
  puVar4 = (undefined4 *)(*(code *)param_3[2])(~uVar5 + 0xb);
  strcpy((char *)(puVar4 + 2),param_2);
  *puVar4 = *(undefined4 *)(*param_3 + uVar2 * 4);
  puVar4[1] = 0;
  *(undefined4 **)(*param_3 + uVar2 * 4) = puVar4;
  *param_1 = puVar4 + 1;
  return 1;
}



undefined4 * FUN_0804afc4(char *param_1,int *param_2)

{
  char cVar1;
  uint uVar2;
  undefined4 *puVar3;
  uint uVar4;
  char *pcVar5;
  
  uVar2 = FUN_0804ae80(param_1,param_2[1]);
  uVar4 = 0xffffffff;
  pcVar5 = param_1;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  puVar3 = (undefined4 *)(*(code *)param_2[2])(~uVar4 + 0xb);
  strcpy((char *)(puVar3 + 2),param_1);
  *puVar3 = *(undefined4 *)(*param_2 + uVar2 * 4);
  puVar3[1] = 0;
  *(undefined4 **)(*param_2 + uVar2 * 4) = puVar3;
  return puVar3 + 1;
}



int * FUN_0804b030(char *param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  
  uVar1 = FUN_0804ae80(param_1,param_2[1]);
  piVar3 = *(int **)(*param_2 + uVar1 * 4);
  if (piVar3 != (int *)0x0) {
    do {
      iVar2 = strcmp((char *)(piVar3 + 2),param_1);
      if (iVar2 == 0) break;
      piVar3 = (int *)*piVar3;
    } while (piVar3 != (int *)0x0);
    if (piVar3 != (int *)0x0) {
      return piVar3 + 1;
    }
  }
  return (int *)0x0;
}



undefined4 * FUN_0804b07c(int param_1)

{
  char cVar1;
  undefined4 *puVar2;
  uint uVar3;
  char *pcVar4;
  
  uVar3 = 0xffffffff;
  pcVar4 = (char *)(param_1 + 4);
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  puVar2 = (undefined4 *)(**(code **)(DAT_0806ab74 + 8))(~uVar3 + 8);
  strcpy((char *)(puVar2 + 2),(char *)(param_1 + 4));
  *puVar2 = *(undefined4 *)(param_1 + -4);
  puVar2[1] = 0;
  *(undefined4 **)(param_1 + -4) = puVar2;
  return puVar2 + 1;
}



int FUN_0804b0dc(int param_1)

{
  int iVar1;
  
  iVar1 = 0;
  if (param_1 != 0) {
    if (*(int *)(param_1 + -4) == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = *(int *)(param_1 + -4) + 4;
    }
  }
  return iVar1;
}



void FUN_0804b0f8(undefined4 param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)FUN_0804b1e8(8);
  *puVar2 = 0;
  puVar2[1] = param_1;
  puVar1 = puVar2;
  if (DAT_08068ca0 != (undefined4 *)0x0) {
    *DAT_08068ca4 = puVar2;
    puVar1 = DAT_08068ca0;
  }
  DAT_08068ca0 = puVar1;
  DAT_08068ca4 = puVar2;
  return;
}



undefined4 FUN_0804b134(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = DAT_08068ca0;
  *param_1 = DAT_08068ca0;
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = *(undefined4 *)(iVar1 + 4);
  }
  return uVar2;
}



undefined4 FUN_0804b154(int *param_1)

{
  int iVar1;
  
  if ((int *)*param_1 != (int *)0x0) {
    iVar1 = *(int *)*param_1;
    *param_1 = iVar1;
    if (iVar1 != 0) {
      return *(undefined4 *)(iVar1 + 4);
    }
  }
  return 0;
}



void FUN_0804b174(void)

{
  DAT_08068ca4 = 0;
  DAT_08068ca0 = 0;
  DAT_0806ab74 = FUN_0804aebc(0x1000,1);
  return;
}



bool FUN_0804b1a0(uint param_1,uint param_2)

{
  bool bVar1;
  
  bVar1 = false;
  if (param_1 < param_2) {
    bVar1 = param_2 < param_1 + *(int *)(param_1 + 8);
  }
  return bVar1;
}



void FUN_0804b1c0(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  *param_1 = DAT_08068ca8;
  *param_2 = DAT_08068cac;
  *param_3 = DAT_08068cb4;
  return;
}



int FUN_0804b1e8(int param_1)

{
  uint uVar1;
  int *piVar2;
  
  uVar1 = FUN_0804b574(param_1);
  if (DAT_08068cbc != (int *)0x0) {
    piVar2 = DAT_08068cbc;
    do {
      if (uVar1 + 0xc <= (uint)(piVar2[1] - (int)piVar2)) break;
      piVar2 = (int *)*piVar2;
    } while (piVar2 != (int *)0x0);
    if (piVar2 != (int *)0x0) goto LAB_0804b244;
  }
  piVar2 = FUN_0804b4c8(uVar1);
  memset(piVar2 + 3,0,piVar2[2] - 0xc);
  *piVar2 = (int)DAT_08068cbc;
  DAT_08068cbc = piVar2;
LAB_0804b244:
  piVar2[1] = piVar2[1] - uVar1;
  DAT_08068cac = DAT_08068cac + uVar1;
  return piVar2[1];
}



void * FUN_0804b258(char *param_1)

{
  char cVar1;
  void *__dest;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0xffffffff;
  pcVar3 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  __dest = (void *)FUN_0804b1e8(~uVar2);
  memcpy(__dest,param_1,~uVar2);
  return __dest;
}



void * FUN_0804b28c(char *param_1)

{
  char cVar1;
  void *__dest;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0xffffffff;
  pcVar3 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  __dest = (void *)FUN_0804b3ac(~uVar2);
  memcpy(__dest,param_1,~uVar2);
  return __dest;
}



int FUN_0804b2c0(int param_1)

{
  uint uVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  
  uVar1 = FUN_0804b574(param_1);
  if ((DAT_08068cc4 == (int *)0x0) ||
     (iVar4 = DAT_08068cc4[1], (uint)(iVar4 - (int)DAT_08068cc4) < uVar1 + 0xc)) {
    uVar2 = uVar1;
    if (uVar1 < 0xff00) {
      uVar2 = 0xff00;
    }
    piVar3 = FUN_08060cfc(uVar2 + 0xc,0);
    if (piVar3 == (int *)0x0) {
      return 0;
    }
    iVar4 = FUN_08060d70((int)piVar3);
    piVar3[2] = iVar4;
    piVar3[1] = iVar4 + (int)piVar3;
    *piVar3 = (int)DAT_08068cc4;
    iVar4 = piVar3[1];
    DAT_08068cc4 = piVar3;
  }
  DAT_08068cc4[1] = iVar4 - uVar1;
  DAT_08068cb4 = DAT_08068cb4 + uVar1;
  return iVar4 - uVar1;
}



undefined4 * FUN_0804b344(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  
  puVar2 = DAT_08068cc4;
  if (param_1 != (undefined4 *)0x0) {
    for (; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      iVar1 = puVar2[2];
      iVar3 = iVar1;
      if (iVar1 < 0) {
        iVar3 = -iVar1;
      }
      if ((puVar2 <= param_1) && (param_1 < (undefined4 *)(iVar3 + (int)puVar2))) {
        if (iVar1 < 0) {
          return (undefined4 *)0x0;
        }
        puVar2[2] = -iVar3;
        return puVar2;
      }
    }
  }
  return (undefined4 *)0x0;
}



void FUN_0804b394(int param_1)

{
  int iVar1;
  
  if (param_1 != 0) {
    iVar1 = *(int *)(param_1 + 8);
    if (iVar1 < 0) {
      iVar1 = -iVar1;
    }
    *(int *)(param_1 + 8) = iVar1;
  }
  return;
}



int FUN_0804b3ac(int param_1)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  
  uVar1 = FUN_0804b574(param_1);
  if ((DAT_08068cc0 == (int *)0x0) ||
     (iVar3 = DAT_08068cc0[1], (uint)(iVar3 - (int)DAT_08068cc0) < uVar1 + 0xc)) {
    piVar2 = FUN_0804b4c8(uVar1);
    *piVar2 = (int)DAT_08068cc0;
    iVar3 = piVar2[1];
    DAT_08068cc0 = piVar2;
  }
  piVar2 = DAT_08068cc0;
  DAT_08068cc0[1] = iVar3 - uVar1;
  DAT_08068ca8 = DAT_08068ca8 + uVar1;
  if (DAT_08068cb0 < DAT_08068ca8) {
    DAT_08068cb0 = DAT_08068ca8;
  }
  return piVar2[1];
}



void FUN_0804b418(void)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0804b3ac(4);
  *puVar1 = DAT_08068cc8;
  DAT_08068cc8 = puVar1;
  return;
}



void FUN_0804b434(void)

{
  undefined4 *__s;
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  puVar2 = DAT_08068cc0;
  while( true ) {
    puVar1 = puVar2;
    if (puVar1 == (undefined4 *)0x0) {
      DAT_08068cc0 = puVar1;
      return;
    }
    puVar2 = (undefined4 *)*puVar1;
    __s = (undefined4 *)puVar1[1];
    if ((__s <= DAT_08068cc8) && (DAT_08068cc8 < (undefined4 *)((int)puVar1 + puVar1[2]))) break;
    puVar1[1] = (int)puVar1 + puVar1[2];
    DAT_08068ca8 = DAT_08068ca8 - (((int)puVar1 + puVar1[2]) - (int)__s);
    memset(__s,0,puVar1[1] - (int)__s);
    *puVar1 = DAT_08068cb8;
    DAT_08068cb8 = puVar1;
  }
  puVar2 = DAT_08068cc8 + 1;
  puVar1[1] = puVar2;
  DAT_08068cc8 = (undefined4 *)*DAT_08068cc8;
  DAT_08068ca8 = DAT_08068ca8 - ((int)puVar2 - (int)__s);
  memset(__s,0,(int)puVar2 - (int)__s);
  DAT_08068cc0 = puVar1;
  return;
}



undefined4 * FUN_0804b4c8(uint param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  if (param_1 < 0xff00) {
    param_1 = 0xff00;
  }
  iVar4 = param_1 + 0xc;
  puVar2 = &DAT_08068cb8;
  puVar3 = DAT_08068cb8;
  if (DAT_08068cb8 != (undefined4 *)0x0) {
    do {
      if (iVar4 <= (int)puVar3[2]) {
        *puVar2 = *puVar3;
        iVar4 = puVar3[2];
        puVar1 = puVar3;
        break;
      }
      puVar1 = (undefined4 *)*puVar3;
      puVar2 = puVar3;
      puVar3 = puVar1;
    } while (puVar1 != (undefined4 *)0x0);
    if (puVar1 != (undefined4 *)0x0) goto LAB_0804b55d;
  }
  puVar1 = FUN_08060cfc(iVar4,0);
  if (puVar1 == (undefined4 *)0x0) {
    puVar2 = &DAT_08068cc4;
    puVar3 = DAT_08068cc4;
    puVar1 = DAT_08068cc4;
    if (DAT_08068cc4 != (undefined4 *)0x0) {
      do {
        if (iVar4 <= (int)puVar3[2]) {
          *puVar2 = *puVar3;
          FUN_0804ba44((uint)puVar3);
          puVar1 = puVar3;
          break;
        }
        puVar1 = (undefined4 *)*puVar3;
        puVar2 = puVar3;
        puVar3 = puVar1;
      } while (puVar1 != (undefined4 *)0x0);
      if (puVar1 != (undefined4 *)0x0) goto LAB_0804b55d;
    }
    FUN_0805b0d8("3Out of memory.");
  }
LAB_0804b55d:
  iVar4 = FUN_08060d70((int)puVar1);
  puVar1[2] = iVar4;
  puVar1[1] = iVar4 + (int)puVar1;
  return puVar1;
}



uint FUN_0804b574(int param_1)

{
  return param_1 + 3U & 0xfffffffc;
}



void FUN_0804b584(void)

{
  DAT_08068cb4 = 0;
  DAT_08068cb0 = 0;
  DAT_08068cac = 0;
  DAT_08068ca8 = 0;
  DAT_08068cc4 = 0;
  DAT_08068cc0 = 0;
  DAT_08068cbc = 0;
  DAT_08068cb8 = 0;
  DAT_08068cc8 = 0;
  return;
}



undefined4 * FUN_0804b5e4(uint param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0804b1e8(0x10);
  *puVar1 = 0;
  puVar1[1] = param_1;
  puVar1[3] = param_1 * (int)(0x400 / (ulonglong)param_1);
  return puVar1;
}



void FUN_0804b618(int *param_1,void *param_2)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)*param_1;
  if ((piVar1 == (int *)0x0) || (iVar2 = param_1[2], iVar2 == param_1[3])) {
    piVar1 = (int *)FUN_0804b1e8(0x404);
    *piVar1 = *param_1;
    param_1[2] = 0;
    *param_1 = (int)piVar1;
    iVar2 = 0;
  }
  memcpy((void *)((int)piVar1 + iVar2 + 4),param_2,param_1[1]);
  param_1[2] = param_1[2] + param_1[1];
  return;
}



int FUN_0804b668(int *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)*param_1;
  if (puVar2 != (undefined4 *)0x0) {
    if (param_1[2] == 0) {
      puVar2 = (undefined4 *)*puVar2;
      *param_1 = (int)puVar2;
      param_1[2] = param_1[3];
    }
    if (puVar2 != (undefined4 *)0x0) {
      iVar1 = param_1[2];
      param_1[2] = iVar1 - param_1[1];
      return (int)puVar2 + (iVar1 - param_1[1]) + 4;
    }
  }
  return 0;
}



undefined4 FUN_0804b6a8(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



int FUN_0804b6c0(char *param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  do {
    while( true ) {
      iVar3 = (int)*param_1;
      param_1 = param_1 + 1;
      cVar1 = *param_2;
      param_2 = param_2 + 1;
      if (iVar3 == cVar1) break;
      iVar3 = tolower(iVar3);
      iVar2 = tolower((int)cVar1);
      if (iVar3 != iVar2) {
        return iVar3 - iVar2;
      }
    }
  } while (iVar3 != 0);
  return 0;
}



char * FUN_0804b710(char *param_1,char *param_2,uint param_3)

{
  char cVar1;
  char *pcVar2;
  
  cVar1 = *param_2;
  *param_1 = cVar1;
  pcVar2 = param_1;
  for (; (cVar1 != '\0' && (1 < param_3)); param_3 = param_3 - 1) {
    pcVar2 = pcVar2 + 1;
    param_2 = param_2 + 1;
    cVar1 = *param_2;
    *pcVar2 = cVar1;
  }
  *pcVar2 = '\0';
  return param_1;
}



undefined4 FUN_0804b744(uint param_1)

{
  uint uVar1;
  
  if (DAT_08068ccc == 0) {
    DAT_08068ccc = param_1;
    uVar1 = DAT_08068ccc;
    DAT_08068ccc._0_1_ = (char)param_1;
    DAT_0806ab78 = (uint)((char)DAT_08068ccc == -0x3b);
    DAT_08068ccc = uVar1;
    if (param_1 != 0xc3cbc6c5) {
      FUN_0805e100(1);
      uVar1 = FUN_0805e13c(param_1);
      if (uVar1 != 0xc3cbc6c5) {
        FUN_0805e100(0);
        return 0;
      }
    }
  }
  else if (param_1 != DAT_08068ccc) {
    return 0;
  }
  return 1;
}



bool FUN_0804b7ac(uint param_1)

{
  undefined4 uVar1;
  uint uVar2;
  bool bVar3;
  
  uVar1 = FUN_0805e120();
  FUN_0805e100(1);
  uVar2 = FUN_0805e13c(param_1);
  bVar3 = uVar2 == DAT_08068ccc;
  FUN_0805e100(uVar1);
  return bVar3;
}



uint FUN_0804b7e8(uint3 *param_1)

{
  uint uVar1;
  uint uVar2;
  
  if (DAT_0806ab78 == 0) {
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



undefined2 FUN_0804b838(undefined2 *param_1)

{
  undefined2 uVar1;
  
  if (DAT_0806ab78 == 0) {
    uVar1 = CONCAT11(*(undefined1 *)param_1,*(undefined1 *)param_1);
  }
  else {
    uVar1 = *param_1;
  }
  return uVar1;
}



void FUN_0804b864(undefined1 *param_1,uint param_2)

{
  undefined1 uVar1;
  undefined1 uVar2;
  
  uVar1 = (undefined1)(param_2 >> 8);
  uVar2 = (undefined1)(param_2 >> 0x10);
  if (DAT_0806ab78 == 0) {
    *param_1 = (char)(param_2 >> 0x18);
    param_1[1] = uVar2;
    param_1[2] = uVar1;
  }
  else {
    *param_1 = (char)param_2;
    param_1[1] = uVar1;
    param_1[2] = uVar2;
    param_2 = param_2 >> 0x18;
  }
  param_1[3] = (char)param_2;
  return;
}



void FUN_0804b8ac(undefined1 *param_1,uint param_2)

{
  if (DAT_0806ab78 == 0) {
    *param_1 = (char)(param_2 >> 8);
  }
  else {
    *param_1 = (char)param_2;
    param_2 = param_2 >> 8;
  }
  param_1[1] = (char)param_2;
  return;
}



void FUN_0804b8d4(uint *param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = FUN_0805e13c(*param_1);
  uVar1 = FUN_0805e13c(param_2 + uVar1);
  *param_1 = uVar1;
  return;
}



void FUN_0804b8f8(void)

{
  PTR_strcmp_080686cc = strcmp;
  DAT_08068ccc = 0;
  DAT_0806ab78 = 1;
  return;
}



undefined4 FUN_0804b91c(undefined *param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if (((param_1 == &DAT_080686e0) || (param_1 == &DAT_08068764)) || (param_1 == &DAT_080687b0)) {
    uVar1 = 1;
  }
  return uVar1;
}



undefined1 * FUN_0804b950(char *param_1,char *param_2,char *param_3)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = 0;
  iVar5 = 0;
  if (param_1 != (char *)0x0) {
    uVar3 = 0xffffffff;
    pcVar2 = param_1;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    iVar5 = ~uVar3 - 1;
    FUN_0804b710(&DAT_08068ce0,param_1,0x100e);
    uVar3 = 0xffffffff;
    pcVar2 = &DAT_08068ce0;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    iVar4 = ~uVar3 - 1;
  }
  pcVar2 = FUN_0804b710(&DAT_08068ce0 + iVar4,param_2,0x100e - iVar4);
  uVar3 = 0xffffffff;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *param_2;
    param_2 = param_2 + 1;
  } while (cVar1 != '\0');
  iVar5 = iVar5 + -1 + ~uVar3;
  if (param_3 != (char *)0x0) {
    uVar3 = 0xffffffff;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    iVar4 = iVar4 + -1 + ~uVar3;
    FUN_0804b710(&DAT_08068ce0 + iVar4,param_3,0x100e - iVar4);
    uVar3 = 0xffffffff;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *param_3;
      param_3 = param_3 + 1;
    } while (cVar1 != '\0');
    iVar5 = iVar5 + -1 + ~uVar3;
  }
  if (0x100d < iVar5) {
    FUN_0805b0d8("1\'%s\' has been truncated.");
  }
  return &DAT_08068ce0;
}



void FUN_0804ba44(uint param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  bool bVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  
  for (puVar1 = DAT_0806ab9c; puVar2 = DAT_0806ab90, puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)*puVar1) {
    if (((puVar1[5] != 0) &&
        (bVar3 = FUN_0804b1a0(param_1,puVar1[5]), CONCAT31(extraout_var,bVar3) != 0)) &&
       (puVar1[5] = 0, (DAT_0806ab70._2_1_ & 8) != 0)) {
      FUN_0805b0d8("0Memory shortage: uncaching %s.");
    }
  }
  for (; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
    if (((puVar2[4] != 0) &&
        (bVar3 = FUN_0804b1a0(param_1,puVar2[4]), CONCAT31(extraout_var_00,bVar3) != 0)) &&
       (puVar2[4] = 0, (DAT_0806ab70._2_1_ & 8) != 0)) {
      FUN_0805b0d8("0Memory shortage: uncaching %s.");
    }
  }
  return;
}



undefined1 * FUN_0804bae4(undefined1 *param_1,int param_2,size_t param_3)

{
  __off_t _Var1;
  size_t sVar2;
  
  FUN_08059b8c();
  if (((param_2 == *(int *)(DAT_08069d10 + 0x10)) ||
      (_Var1 = lseek(*(int *)(DAT_08069d10 + 0x18),param_2,0), _Var1 != -1)) &&
     (sVar2 = read(*(int *)(DAT_08069d10 + 0x18),param_1,param_3), sVar2 == param_3)) {
    *(size_t *)(DAT_08069d10 + 0x10) = param_2 + param_3;
    return param_1;
  }
  FUN_0805b0d8("3Error reading file %s.");
  return &DAT_08062c38;
}



void FUN_0804bb60(undefined4 *param_1)

{
  int iVar1;
  
  while( true ) {
    if (param_1 == (undefined4 *)0x0) {
      return;
    }
    if (-1 < (int)param_1[6]) break;
    param_1 = (undefined4 *)*param_1;
  }
  iVar1 = close(param_1[6]);
  if (iVar1 != 0) {
    FUN_0805b0d8("3Error reading file %s.");
  }
  DAT_08069d08 = DAT_08069d08 + -1;
  param_1[6] = 0xffffffff;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804bbac(int param_1)

{
  int iVar1;
  
  _DAT_08069cfc = 0;
  DAT_08069d00 = *(undefined4 *)(param_1 + 0xc);
  DAT_08069d10 = param_1;
  DAT_08069d04 = *(int *)(param_1 + 0x14);
  if ((DAT_08069d04 == 0) && (*(int *)(param_1 + 0x18) < 0)) {
    if (DAT_08069d0c <= DAT_08069d08) {
      FUN_0804bb60(DAT_0806ab9c);
    }
    iVar1 = open((char *)(param_1 + 0x24),0);
    *(int *)(param_1 + 0x18) = iVar1;
    if (iVar1 < 0) {
      FUN_0805b0d8("3Can\'t open file \'%s\'.");
    }
    *(undefined4 *)(param_1 + 0x10) = 0;
    DAT_08069d08 = DAT_08069d08 + 1;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804bc30(int param_1,int param_2,undefined4 param_3)

{
  FUN_0804bbac(param_1);
  _DAT_08069cfc = param_2;
  DAT_08069d00 = param_3;
  if (DAT_08069d04 != 0) {
    DAT_08069d04 = DAT_08069d04 + param_2;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804bc68(int param_1)

{
  if (param_1 == 0) {
    DAT_08069d04 = &DAT_08069cee;
    DAT_08069d00 = 0;
    _DAT_08069cfc = 0;
    DAT_08069d10 = 0;
  }
  else {
    DAT_08069d04 = *(undefined **)(param_1 + 0x10);
    if (DAT_08069d04 == (undefined *)0x0) {
      FUN_0804bc30(*(int *)(param_1 + 8),*(int *)(param_1 + 0x14),*(undefined4 *)(param_1 + 0x18));
    }
    else {
      _DAT_08069cfc = *(undefined4 *)(param_1 + 0x14);
      DAT_08069d00 = *(undefined4 *)(param_1 + 0x18);
      DAT_08069d10 = *(undefined4 *)(param_1 + 8);
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined1 * FUN_0804bcd8(int param_1,size_t param_2)

{
  undefined1 *puVar1;
  int iVar2;
  
  if ((param_1 < 0) || (DAT_08069d00 + _DAT_08069cfc < (int)(param_2 + param_1))) {
    FUN_0805b0d8("3Input file %s corrupt.");
  }
  DAT_0806abc4 = DAT_0806abc4 + param_2;
  if (DAT_08069d04 == 0) {
    iVar2 = param_1 + _DAT_08069cfc;
    puVar1 = (undefined1 *)FUN_0804b1e8(param_2);
    puVar1 = FUN_0804bae4(puVar1,iVar2,param_2);
  }
  else {
    puVar1 = (undefined1 *)FUN_0804b1e8(param_2);
    memcpy(puVar1,(void *)(param_1 + DAT_08069d04),param_2);
  }
  return puVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined1 * FUN_0804bd58(int param_1,size_t param_2)

{
  undefined1 *puVar1;
  int iVar2;
  
  if ((param_1 < 0) || (DAT_08069d00 + _DAT_08069cfc < (int)(param_2 + param_1))) {
    FUN_0805b0d8("3Input file %s corrupt.");
  }
  if (DAT_08069d04 == 0) {
    iVar2 = param_1 + _DAT_08069cfc;
    puVar1 = (undefined1 *)FUN_0804b3ac(param_2);
    puVar1 = FUN_0804bae4(puVar1,iVar2,param_2);
  }
  else {
    puVar1 = (undefined1 *)(DAT_08069d04 + param_1);
  }
  return puVar1;
}



void FUN_0804bdbc(uint param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = FUN_0805e13c(param_2);
  uVar2 = FUN_0805e13c(param_1);
  FUN_0804bd58(uVar2,uVar1);
  return;
}



char * FUN_0804bde0(int param_1,char *param_2)

{
  char *pcVar1;
  uint uVar2;
  int iVar3;
  char *__s1;
  
  __s1 = (char *)(param_1 + 0xc);
  uVar2 = FUN_0805e13c(*(uint *)(param_1 + 4));
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



void FUN_0804be34(char *param_1,uint param_2,uint param_3,int param_4)

{
  char cVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  byte *pbVar6;
  char *pcVar7;
  undefined **local_c;
  char *local_8;
  
  local_8 = "";
  puVar5 = &DAT_08062c68;
  local_c = &PTR_s_area_alignment_08062c70;
  pbVar6 = &DAT_08062c6c;
  do {
    if (param_4 == 0) {
      bVar2 = *pbVar6 & 2;
    }
    else {
      bVar2 = *pbVar6 & 1;
    }
    if ((bVar2 == 0) && ((param_3 & *puVar5) != 0)) {
      uVar3 = 0xffffffff;
      pcVar7 = *local_c;
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar7 + 1;
      } while (cVar1 != '\0');
      uVar4 = 0xffffffff;
      pcVar7 = local_8;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar7 + 1;
      } while (cVar1 != '\0');
      uVar3 = (~uVar3 - 2) + ~uVar4;
      if (uVar3 < param_2) {
        param_2 = param_2 - uVar3;
        sprintf(param_1,"%s%s",local_8,*local_c);
        param_1 = param_1 + uVar3;
        local_8 = ", ";
      }
    }
    pbVar6 = pbVar6 + 0xc;
    local_c = local_c + 3;
    puVar5 = puVar5 + 3;
    if (&UNK_08062d4b < puVar5) {
      return;
    }
  } while( true );
}



int * FUN_0804bee8(char *param_1,int *param_2,char *param_3)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  char *pcVar4;
  uint uVar5;
  int iVar6;
  code *pcVar7;
  int *piVar8;
  int *piVar9;
  uint local_1014;
  int *local_1008;
  char local_1004;
  char local_1003;
  char local_1002 [4094];
  
  uVar5 = 0xffffffff;
  pcVar4 = param_1;
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  if (0xffd < ~uVar5 - 1) {
    FUN_0805b0d8("1\'%s\' has been truncated.");
  }
  local_1004 = *param_3;
  local_1003 = param_3[1];
  FUN_0804b710(local_1002,param_1,0xffe);
  pcVar7 = (code *)PTR_strcmp_080686cc;
  if ((*(byte *)(param_2 + 2) & 8) != 0) {
    pcVar7 = FUN_0804b6c0;
  }
  iVar2 = FUN_0804af0c(&local_1008,&local_1004,DAT_0806ab74,pcVar7);
  if (iVar2 != 0) {
LAB_0804c018:
    piVar3 = local_1008;
    if (iVar2 == 0) {
      if ((param_2[2] & 3U) == 3) {
        FUN_0805b0d8("0Both ARM & Thumb versions of %s present in image.");
      }
      piVar3 = FUN_0804b07c((int)local_1008);
    }
    iVar2 = FUN_0804b1e8(0x1c);
    *piVar3 = iVar2;
    piVar8 = param_2;
    piVar9 = (int *)(iVar2 + 8);
    for (iVar6 = 5; iVar6 != 0; iVar6 = iVar6 + -1) {
      *piVar9 = *piVar8;
      piVar8 = piVar8 + 1;
      piVar9 = piVar9 + 1;
    }
    if ((param_2[2] & 0x13U) == 2) {
      *(byte *)(*piVar3 + 0x13) = *(byte *)(*piVar3 + 0x13) | 0x10;
    }
    *(undefined4 *)*piVar3 = 0xffffffff;
    *(undefined4 *)(*piVar3 + 4) = 0xffffffff;
    FUN_0804b0f8(piVar3);
    if ((((((ushort)DAT_0806ab70 & 0x20) != 0) && (((byte)DAT_0806ab68 & 4) == 0)) &&
        (DAT_0806ab64 == 4)) && (pcVar4 = strchr(param_1,0x24), pcVar4 != (char *)0x0)) {
      *(byte *)(*piVar3 + 0x13) = *(byte *)(*piVar3 + 0x13) | 0x40;
    }
    return local_1008;
  }
  iVar6 = *local_1008;
  local_1014 = param_2[2];
  if (((((local_1014 & 1) != 0) && (local_1014 == (*(uint *)(iVar6 + 0x10) & 0x80ffffff))) &&
      (param_2[1] == *(int *)(iVar6 + 0xc))) && (*param_2 == *(int *)(iVar6 + 8))) {
    return local_1008;
  }
  if (((local_1014 & 3) == 1) ||
     ((((local_1014 & 3) == 3 && ((*(uint *)(iVar6 + 0x10) & 3) == 3)) &&
      ((local_1014 & 0x1000) != (*(uint *)(iVar6 + 0x10) & 0x1000))))) goto LAB_0804c018;
  if ((local_1014 & 1) == 0) {
    if ((local_1014 & 0x10) != 0) {
      return local_1008;
    }
    uVar5 = *(uint *)(*local_1008 + 0x10);
    if ((uVar5 & 0x10) == 0) {
      return local_1008;
    }
    *(uint *)(*local_1008 + 0x10) = uVar5 & 0xffffffef | 0x10000000;
    return local_1008;
  }
  iVar2 = *local_1008;
  uVar5 = *(uint *)(iVar2 + 0x10);
  if (((local_1014 ^ uVar5) & 0x20) != 0) {
    if ((((byte)DAT_0806ab68 & 4) != 0) && ((uVar5 & 1) != 0)) {
      FUN_0805b0d8(
                  "2Global %s defined both strong and non-strong while partial linking (in %s and %s)."
                  );
      local_1014 = param_2[2];
    }
    if ((local_1014 & 0x20) == 0) {
      FUN_0804bee8(param_1,param_2," !");
      return local_1008;
    }
    if ((*(byte *)(iVar2 + 0x10) & 1) == 0) goto LAB_0804c1f0;
    FUN_0804bee8(param_1,(int *)(iVar2 + 8)," !");
    uVar5 = *(uint *)(iVar2 + 0x10) & 0xfffffffe;
    *(uint *)(iVar2 + 0x10) = uVar5;
  }
  if (((uVar5 & 1) != 0) && ((*(byte *)((int)param_2 + 0xb) & 1) == 0)) {
    if ((short)(ushort)DAT_0806ab70 < 0) {
      FUN_0805b0d8("1Global %s multiply defined (in %s and %s).");
      return local_1008;
    }
    FUN_0805b0d8("2Global %s multiply defined (in %s and %s).");
    return local_1008;
  }
LAB_0804c1f0:
  piVar3 = (int *)(iVar2 + 8);
  for (iVar6 = 5; iVar6 != 0; iVar6 = iVar6 + -1) {
    *piVar3 = *param_2;
    param_2 = param_2 + 1;
    piVar3 = piVar3 + 1;
  }
  return local_1008;
}



void FUN_0804c234(char *param_1,undefined4 param_2,char *param_3)

{
  int local_18 [3];
  undefined4 local_c;
  undefined4 local_8;
  
  local_18[0] = 0;
  local_18[1] = 0;
  local_18[2] = param_2;
  local_c = 0;
  local_8 = 0;
  FUN_0804bee8(param_1,local_18,param_3);
  return;
}



void FUN_0804c270(undefined4 param_1,char *param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  int local_18 [5];
  
  piVar1 = FUN_0804b030(param_2,DAT_0806ab74);
  if (piVar1 == (int *)0x0) {
    if (((byte)DAT_0806ab68 & 2) != 0) {
      return;
    }
  }
  else if ((*(byte *)(*piVar1 + 0x13) & 1) != 0) {
    *(int *)(*piVar1 + 8) = param_3;
    return;
  }
  piVar1 = local_18;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *piVar1 = 0;
    piVar1 = piVar1 + 1;
  }
  local_18[0] = param_3;
  local_18[1] = param_1;
  local_18[2] = 0x100000f;
  FUN_0804bee8(param_2 + 2,local_18,"!!");
  return;
}



void FUN_0804c2e8(undefined4 param_1,char *param_2,int param_3,int param_4,int param_5)

{
  char *pcVar1;
  
  pcVar1 = FUN_0804b950("!!",param_2,"$$Base");
  FUN_0804c270(param_1,pcVar1,param_3);
  pcVar1 = FUN_0804b950("!!",param_2,"$$Limit");
  FUN_0804c270(param_1,pcVar1,param_4);
  if (param_5 != -1) {
    pcVar1 = FUN_0804b950("!!",param_2,"$$DbgOffset");
    FUN_0804c270(param_1,pcVar1,param_5);
  }
  return;
}



undefined4 *
FUN_0804c360(char *param_1,undefined4 param_2,int param_3,size_t param_4,undefined4 param_5,
            int param_6,uint param_7,undefined4 param_8)

{
  char cVar1;
  undefined1 *puVar2;
  byte *pbVar3;
  char *pcVar4;
  undefined4 *puVar5;
  uint uVar6;
  int iVar7;
  size_t sVar8;
  undefined4 *unaff_EBX;
  byte *pbVar9;
  char *pcVar10;
  bool bVar11;
  bool bVar12;
  ushort local_10e;
  size_t local_10c;
  int *local_108;
  char local_104 [256];
  
  uVar6 = 0xffffffff;
  pcVar4 = param_1;
  do {
    if (uVar6 == 0) break;
    uVar6 = uVar6 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  local_10c = ~uVar6 - 1;
  local_10e = (ushort)param_7 & 0x8000;
  if ((param_7 & 0x8000) == 0) {
    if (((param_7 & 0xc00) != 0) || ((param_7 & 0x200200) == 0x200000)) {
      if ((param_7 & 0x400) != 0) {
        param_7 = param_7 & 0xfffff7ff;
      }
      if ((param_7 & 0x1400) == 0x1400) {
        param_7 = param_7 & 0xfffffbff;
        param_7 = param_7 | 0x800;
      }
      if ((param_7 & 0x800) != 0) {
        param_7 = param_7 | 0x1000;
      }
      if (((param_7 & 0x200200) == 0x200000) && ((param_7 & 0xc00) != 0)) {
        FUN_0805b0d8("1AREA %s(%s) has conflicting attributes COMMON,SHLDATA;    (COMMON ignored).")
        ;
        param_7 = param_7 & 0xfffff3ff;
      }
      iVar7 = FUN_0804af0c(&local_108,param_1,DAT_0806ab80,strcmp);
      local_10e = (ushort)param_7;
      if (iVar7 != 0) {
        uVar6 = 0xffffffff;
        pcVar4 = param_1;
        do {
          if (uVar6 == 0) break;
          uVar6 = uVar6 - 1;
          cVar1 = *pcVar4;
          pcVar4 = pcVar4 + 1;
        } while (cVar1 != '\0');
        puVar5 = (undefined4 *)FUN_0804b1e8(~uVar6 + 0x4b);
        *local_108 = (int)puVar5;
        local_10e = local_10e & 0x8000;
        if ((param_7 & 0x1000) == 0) {
          puVar2 = FUN_0804bcd8(param_3,param_4);
          puVar5[0x10] = puVar2;
        }
        goto LAB_0804c76e;
      }
      puVar5 = (undefined4 *)*local_108;
      if (((param_7 & 0x200) == 0) &&
         ((((param_7 ^ puVar5[0xc]) & 0x200000) != 0 ||
          (((param_7 & 0x200000) != 0 && (((param_7 ^ puVar5[0xc]) & 0x1000) != 0)))))) {
        FUN_0805b0d8("1Attribute conflict between AREAS %s(%s) and %s(%s).");
        FUN_0804be34(local_104,0x100,(param_7 ^ puVar5[0xc]) & 0x201000,0);
        FUN_0805b0d8("0(attribute difference = {%s}).");
      }
      else {
        if ((param_7 & 0x800) != 0) {
          if ((int)param_4 <= (int)puVar5[7]) {
            return unaff_EBX;
          }
          if ((*(byte *)((int)puVar5 + 0x31) & 4) != 0) {
            FUN_0805b0d8("1COMMON %s(%s) is larger than its definition %s(%s).");
            return unaff_EBX;
          }
          puVar5[7] = param_4;
          return unaff_EBX;
        }
        if ((param_7 & 0x200200) == 0x200000) {
          if ((param_7 & 0x1000) != 0) {
            if ((int)param_4 <= (int)puVar5[7]) {
              return unaff_EBX;
            }
            puVar5[7] = param_4;
            return unaff_EBX;
          }
          if ((param_4 == puVar5[7]) && (param_6 == puVar5[10])) {
            pbVar3 = FUN_0804bd58(param_3,param_4);
            bVar11 = false;
            uVar6 = 0;
            bVar12 = true;
            sVar8 = param_4;
            pbVar9 = (byte *)puVar5[0x10];
            do {
              if (sVar8 == 0) break;
              sVar8 = sVar8 - 1;
              bVar11 = *pbVar9 < *pbVar3;
              bVar12 = *pbVar9 == *pbVar3;
              pbVar9 = pbVar9 + 1;
              pbVar3 = pbVar3 + 1;
            } while (bVar12);
            if (!bVar12) {
              uVar6 = -(uint)bVar11 | 1;
            }
joined_r0x0804c666:
            if (uVar6 == 0) {
              return unaff_EBX;
            }
          }
        }
        else {
          if ((param_7 & 0x400) == 0) {
            FUN_0805b0d8("2AREA %s(%s) has unknown attributes 0x%.2x.");
            local_10e = local_10e & 0x8000;
            goto LAB_0804c721;
          }
          if ((*(byte *)((int)puVar5 + 0x31) & 4) == 0) {
            if ((int)param_4 < (int)puVar5[7]) {
              FUN_0805b0d8("1COMMON %s(%s) is larger than its definition %s(%s).");
            }
            puVar5[6] = param_3;
            puVar5[7] = param_4;
            puVar5[8] = 0;
            puVar5[9] = param_5;
            puVar5[10] = param_6;
            *puVar5 = param_2;
            puVar5[0xe] = param_8;
            puVar5[0xc] = param_7;
            return unaff_EBX;
          }
          if ((param_4 == puVar5[7]) && (param_6 == puVar5[10])) {
            pbVar3 = FUN_0804bd58(param_3,param_4);
            bVar11 = false;
            uVar6 = 0;
            bVar12 = true;
            sVar8 = param_4;
            pbVar9 = (byte *)puVar5[0x10];
            do {
              if (sVar8 == 0) break;
              sVar8 = sVar8 - 1;
              bVar11 = *pbVar9 < *pbVar3;
              bVar12 = *pbVar9 == *pbVar3;
              pbVar9 = pbVar9 + 1;
              pbVar3 = pbVar3 + 1;
            } while (bVar12);
            if (!bVar12) {
              uVar6 = -(uint)bVar11 | 1;
            }
            goto joined_r0x0804c666;
          }
        }
        FUN_0805b0d8("1AREA %s differs between object %s and object %s.");
      }
      local_10e = local_10e & 0x8000;
    }
  }
  else {
    if ((DAT_0806ab70._1_1_ & 4) == 0) {
      return unaff_EBX;
    }
    iVar7 = 9;
    bVar11 = true;
    pcVar4 = param_1;
    pcVar10 = "C$$fpmap";
    do {
      if (iVar7 == 0) break;
      iVar7 = iVar7 + -1;
      bVar11 = *pcVar4 == *pcVar10;
      pcVar4 = pcVar4 + 1;
      pcVar10 = pcVar10 + 1;
    } while (bVar11);
    if (!bVar11) {
      DAT_0806ab6d = 1;
    }
  }
LAB_0804c721:
  if (((local_10e != 0) && (((byte)DAT_0806ab68 & 4) == 0)) &&
     (pcVar4 = strstr(param_1,"$$$"), pcVar4 != (char *)0x0)) {
    local_10c = (int)pcVar4 - (int)param_1;
  }
  puVar5 = (undefined4 *)FUN_0804b1e8(local_10c + 0x4d);
  puVar5[0x10] = 0;
LAB_0804c76e:
  if ((local_10e == 0) || (((byte)DAT_0806ab68 & 4) != 0)) {
    strcpy((char *)((int)puVar5 + 0x46),param_1);
  }
  else {
    strncpy((char *)((int)puVar5 + 0x46),param_1,local_10c);
    ((char *)((int)puVar5 + 0x46))[local_10c] = '\0';
  }
  *(undefined2 *)(puVar5 + 0x11) = 0;
  iVar7 = DAT_0806ab94 + 1;
  DAT_0806ab94 = DAT_0806ab94 + 1;
  puVar5[0xf] = iVar7;
  puVar5[6] = param_3;
  puVar5[7] = param_4;
  puVar5[8] = 0;
  puVar5[0xb] = 0;
  puVar5[9] = param_5;
  puVar5[10] = param_6;
  puVar5[0xc] = param_7;
  *puVar5 = param_2;
  puVar5[0xe] = param_8;
  puVar5[0xd] = 0;
  puVar5[3] = 0;
  puVar5[4] = 0;
  *DAT_0806ab84 = (int)puVar5;
  puVar5[1] = 0;
  puVar5[2] = 0;
  DAT_0806ab84 = puVar5 + 2;
  if (((byte)DAT_0806ab68 & 4) == 0) {
    if (local_10e == 0) {
      iVar7 = -1;
    }
    else {
      iVar7 = 0;
    }
    FUN_0804c2e8(puVar5,(char *)((int)puVar5 + 0x46),0,param_4,iVar7);
  }
  return unaff_EBX;
}



undefined4 FUN_0804c880(int param_1)

{
  bool bVar1;
  uint *puVar2;
  int iVar3;
  uint uVar4;
  undefined1 *puVar5;
  char *pcVar6;
  undefined3 extraout_var;
  
  FUN_0804bbac(param_1);
  if (7 < *(int *)(param_1 + 0xc)) {
    puVar2 = (uint *)FUN_0804bcd8(0,8);
    *(uint **)(param_1 + 8) = puVar2;
    iVar3 = FUN_0804b744(*puVar2);
    if (iVar3 == 0) {
      bVar1 = FUN_0804b7ac(**(uint **)(param_1 + 8));
      if (CONCAT31(extraout_var,bVar1) != 0) {
        FUN_0805b0d8("3%s has the opposite byte order to the preceding objects.");
      }
    }
    else {
      uVar4 = FUN_0805e13c(*(uint *)(*(int *)(param_1 + 8) + 4));
      puVar5 = FUN_0804bcd8(0,uVar4 * 0x10 + 0xc);
      *(undefined1 **)(param_1 + 8) = puVar5;
      pcVar6 = FUN_0804bde0((int)puVar5,"OBJ_HEAD");
      if (pcVar6 != (char *)0x0) {
        return 1;
      }
      pcVar6 = FUN_0804bde0(*(int *)(param_1 + 8),"LIB_DIRY");
      if (pcVar6 != (char *)0x0) {
        return 2;
      }
    }
  }
  FUN_0805b0d8("3%s is not an object or library file.");
  return 0;
}



undefined4 * FUN_0804c948(undefined4 *param_1,char *param_2,int param_3,int param_4)

{
  undefined4 *puVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  __off_t _Var5;
  int iVar6;
  uint uVar7;
  undefined1 *puVar8;
  size_t sVar9;
  char *pcVar10;
  char *pcVar11;
  char *local_c;
  
  cVar2 = *param_2;
  local_c = param_2;
  while ((cVar2 != '\0' && (*local_c != '('))) {
    local_c = local_c + 1;
    cVar2 = *local_c;
  }
  sVar9 = (int)local_c - (int)param_2;
  puVar3 = (undefined4 *)FUN_0804b1e8(sVar9 + 0x28);
  pcVar11 = (char *)(puVar3 + 9);
  memcpy(pcVar11,param_2,sVar9);
  pcVar11[sVar9] = '\0';
  puVar3[8] = 0;
  if (*local_c == '(') {
    do {
      do {
        pcVar10 = local_c + 1;
        cVar2 = *pcVar10;
        local_c = pcVar10;
      } while (cVar2 == ' ');
      while ((((cVar2 != '\0' && (cVar2 != ',')) && (cVar2 != ' ')) && (*local_c != ')'))) {
        cVar2 = local_c[1];
        local_c = local_c + 1;
      }
      sVar9 = (int)local_c - (int)pcVar10;
      if (sVar9 == 0) {
        FUN_0805b0d8("3Missing library member in member list for %s.");
      }
      puVar4 = (undefined4 *)FUN_0804b1e8(sVar9 + 8);
      memcpy(puVar4 + 1,pcVar10,sVar9);
      *(undefined1 *)(sVar9 + 4 + (int)puVar4) = 0;
      *puVar4 = puVar3[8];
      puVar3[8] = puVar4;
    } while ((*local_c != '\0') && (*local_c != ')'));
    pcVar10 = local_c + 1;
    cVar2 = local_c[1];
    while (cVar2 == ' ') {
      pcVar10 = pcVar10 + 1;
      cVar2 = *pcVar10;
    }
    if (cVar2 != '\0') {
      FUN_0805b0d8("3Extra characters on end of member list for %s.");
    }
  }
  puVar3[6] = 0xffffffff;
  *puVar3 = 0;
  _Var5 = FUN_08060f80(pcVar11);
  puVar3[3] = _Var5;
  if (_Var5 == -1) {
    if (param_4 == 0) {
      pcVar11 = "1File %s not found.";
LAB_0804cad8:
      FUN_0805b0d8(pcVar11);
      return param_1;
    }
    FUN_0805b0d8("3File %s not found.");
  }
  puVar4 = &DAT_0806ab9c;
  puVar1 = DAT_0806ab9c;
  do {
    if (puVar1 == (undefined4 *)0x0) {
      *param_1 = puVar3;
      puVar3[5] = 0;
      uVar7 = FUN_0804c880((int)puVar3);
      puVar3[1] = uVar7;
      puVar3[7] = param_3;
      if (param_3 != 0) {
        if ((uVar7 & 1) == 0) {
          pcVar11 = "1Old style /a or /l qualifier on library %s.";
        }
        else {
          pcVar11 = "3/a or /l qualifier on AOF, a.out or .ar file %s.";
        }
        FUN_0805b0d8(pcVar11);
      }
      if (puVar3[1] != 10) {
        puVar8 = (undefined1 *)FUN_0804b2c0(puVar3[3]);
        if (puVar8 == (undefined1 *)0x0) {
          DAT_0806abc0 = 1;
        }
        else {
          puVar8 = FUN_0804bae4(puVar8,0,puVar3[3]);
          puVar3[5] = puVar8;
          FUN_0804bb60(puVar3);
        }
      }
      return puVar3;
    }
    iVar6 = FUN_0804b6c0(pcVar11,(char *)(puVar1 + 9));
    if (iVar6 == 0) {
      if (param_4 == 0) {
        *puVar4 = *puVar1;
        *puVar1 = 0;
        *param_1 = puVar1;
        return puVar1;
      }
      if ((puVar3[8] == 0) && (puVar1[8] == 0)) {
        pcVar11 = "1Duplicate file %s ignored.";
        goto LAB_0804cad8;
      }
    }
    puVar4 = puVar1;
    puVar1 = (undefined4 *)*puVar1;
  } while( true );
}



void FUN_0804cb9c(int param_1,int param_2)

{
  for (; param_2 < param_1; param_2 = param_2 * 2) {
  }
  return;
}



void FUN_0804cbb8(char *param_1)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  size_t __n;
  char *pcVar7;
  undefined4 *local_c;
  
  pcVar3 = strstr(param_1,"$$");
  if (pcVar3 == (char *)0x0) {
    FUN_0805b0d8("1Malformed library request: %s");
  }
  else {
    __n = (int)pcVar3 - (int)param_1;
    puVar6 = (undefined4 *)0x0;
    pcVar3 = pcVar3 + 2;
    local_c = &DAT_08069d14;
    for (puVar2 = DAT_08069d14; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      if ((puVar2[1] == __n) && (iVar4 = strncmp((char *)(puVar2 + 4),param_1,__n), iVar4 == 0)) {
        iVar4 = strcmp(pcVar3,(char *)puVar2[3]);
        if (iVar4 == 0) {
          return;
        }
        if (puVar6 == (undefined4 *)0x0) {
          puVar6 = puVar2;
        }
      }
      local_c = puVar2;
    }
    if (puVar6 != (undefined4 *)0x0) {
      FUN_0805b0d8("1Conflicting requests for library %s: variants %s and %s");
    }
    uVar5 = 0xffffffff;
    pcVar7 = pcVar3;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar7 + 1;
    } while (cVar1 != '\0');
    uVar5 = ~uVar5;
    puVar6 = (undefined4 *)FUN_0804b1e8(uVar5 + 0x14 + __n);
    puVar6[3] = (int)puVar6 + __n + 0x11;
    memcpy(puVar6 + 4,param_1,__n);
    *(undefined1 *)(__n + (int)(puVar6 + 4)) = 0;
    puVar6[1] = __n;
    puVar6[2] = uVar5 - 1;
    memcpy((void *)puVar6[3],pcVar3,uVar5);
    *puVar6 = 0;
    *local_c = puVar6;
  }
  return;
}



int FUN_0804ccd8(int param_1,size_t param_2)

{
  undefined1 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  puVar1 = FUN_0804bd58(param_1,param_2);
  iVar2 = 0;
  if (0 < (int)param_2) {
    do {
      iVar3 = iVar3 + (uint)(byte)puVar1[iVar2];
      iVar2 = iVar2 + 1;
    } while (iVar2 < (int)param_2);
  }
  return iVar3;
}



undefined4 FUN_0804cd08(int param_1,int param_2,int param_3)

{
  size_t sVar1;
  int *piVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  undefined4 extraout_EAX;
  uint uVar6;
  uint uVar7;
  undefined4 extraout_EAX_00;
  undefined4 *puVar8;
  uint local_20;
  undefined1 *local_18;
  undefined1 *local_14;
  undefined4 *local_8;
  
  local_8 = (undefined4 *)0x0;
  iVar4 = param_3 * 0x24;
  *(undefined4 *)(param_2 + 4 + iVar4) = 1;
  iVar5 = FUN_0805dfc0(*(byte **)(param_2 + iVar4),*(uint *)(param_2 + 0x14 + iVar4),
                       *(int *)(param_2 + 0x18 + iVar4),*(undefined4 *)(param_2 + 8 + iVar4),
                       &local_8);
  if ((iVar5 == 1) || (iVar5 == -1)) {
    *(undefined4 **)(param_2 + 0x20 + iVar4) = local_8;
    iVar5 = *(int *)(param_2 + 0xc + iVar4);
    sVar1 = *(size_t *)(param_2 + 0x14 + iVar4);
    puVar8 = FUN_0804c360(*(char **)(param_2 + iVar4),param_1,iVar5,sVar1,sVar1 + iVar5,
                          *(int *)(param_2 + 0x18 + iVar4),*(uint *)(param_2 + 0x10 + iVar4),param_3
                         );
    *(undefined4 *)(*(int *)(param_1 + 0x28) + param_3 * 4) = extraout_EAX;
    if (puVar8 == (undefined4 *)0x1) {
      *(undefined4 *)(*(int *)(param_2 + 0x20 + iVar4) + 0x10) =
           *(undefined4 *)(*(int *)(param_1 + 0x28) + param_3 * 4);
    }
    iVar4 = *(int *)(param_2 + 0x14 + iVar4);
  }
  else {
    do {
      puVar8 = local_8;
      bVar3 = false;
      if (local_8[4] == 0) {
        bVar3 = true;
      }
      else {
        iVar4 = param_3 * 0x24;
        if (*(int *)(param_2 + 0x18 + iVar4) != 0) {
          iVar5 = *(int *)(*(int *)(param_1 + 8) + 0x14);
          if (iVar5 == 0) {
            FUN_0804bc68(param_1);
            local_14 = FUN_0804bcd8(*(int *)(param_2 + 0x14 + iVar4) +
                                    *(int *)(param_2 + 0xc + iVar4),
                                    *(int *)(param_2 + 0x18 + iVar4) * 8);
          }
          else {
            local_14 = (undefined1 *)
                       (*(int *)(param_2 + 0xc + iVar4) + *(int *)(param_1 + 0x14) +
                        *(int *)(param_2 + 0x14 + iVar4) + iVar5);
          }
          piVar2 = (int *)local_8[4];
          iVar4 = *piVar2;
          iVar5 = *(int *)(*(int *)(iVar4 + 8) + 0x14);
          if (iVar5 == 0) {
            FUN_0804bc68(iVar4);
            local_18 = FUN_0804bcd8(*(int *)(local_8[4] + 0x1c) + *(int *)(local_8[4] + 0x18),
                                    *(int *)(local_8[4] + 0x28) << 3);
          }
          else {
            local_18 = (undefined1 *)(piVar2[6] + *(int *)(iVar4 + 0x14) + piVar2[7] + iVar5);
          }
          local_20 = 0;
          while ((local_20 < *(uint *)(param_2 + 0x18 + param_3 * 0x24) && (!bVar3))) {
            uVar6 = FUN_0805e13c(*(uint *)(local_14 + local_20 * 8 + 4));
            uVar7 = FUN_0805e13c(*(uint *)(local_18 + local_20 * 8 + 4));
            if ((*(int *)(local_14 + local_20 * 8) != *(int *)(local_18 + local_20 * 8)) ||
               ((uVar6 & 0xff000000) != (uVar7 & 0xff000000))) {
              bVar3 = true;
            }
            if ((uVar6 & 0x8000000) == 0) {
              uVar6 = uVar6 & 0xffffff;
              iVar5 = *(int *)(*(int *)(param_1 + 0x28) + uVar6 * 4);
              iVar4 = *(int *)(*(int *)(*(int *)local_8[4] + 0x28) + (uVar7 & 0xffffff) * 4);
              if (iVar5 == 0) {
                if (*(int *)(param_2 + 4 + uVar6 * 0x24) != 0) goto LAB_0804cfdd;
                iVar5 = FUN_0804cd08(param_1,param_2,uVar6);
                if (iVar5 == 1) goto LAB_0804cfd6;
                iVar5 = *(int *)(*(int *)(param_2 + 0x20 + uVar6 * 0x24) + 0x10);
              }
              if (iVar5 != iVar4) goto LAB_0804cfd6;
            }
            else if (*(int *)(*(int *)(param_1 + 0x20) + (uVar6 & 0xffffff) * 4) !=
                     *(int *)(*(int *)(*(int *)local_8[4] + 0x20) + (uVar7 & 0xffffff) * 4)) {
LAB_0804cfd6:
              bVar3 = true;
            }
LAB_0804cfdd:
            local_20 = local_20 + 1;
          }
        }
      }
      if (!bVar3) break;
      iVar4 = param_3 * 0x24;
      local_8 = FUN_0805df34((int)local_8,*(char **)(param_2 + iVar4),
                             *(undefined4 *)(param_2 + 0x14 + iVar4),
                             *(undefined4 *)(param_2 + 0x18 + iVar4),
                             *(undefined4 *)(param_2 + 8 + iVar4));
    } while (local_8 != (undefined4 *)0x0);
    if (!bVar3) {
      *(undefined4 **)(param_2 + 0x20 + param_3 * 0x24) = puVar8;
      *(undefined4 *)(*(int *)(param_1 + 0x28) + param_3 * 4) = puVar8[4];
      DAT_08068870 = DAT_08068870 + *(int *)(param_2 + 0x14 + param_3 * 0x24);
      return 0;
    }
    iVar5 = param_3 * 0x24;
    puVar8 = FUN_0805de8c(*(char **)(param_2 + iVar5),*(undefined4 *)(param_2 + 0x14 + iVar5),
                          *(undefined4 *)(param_2 + 0x18 + iVar5),
                          *(undefined4 *)(param_2 + 8 + iVar5),(int)puVar8);
    *(undefined4 **)(param_2 + 0x20 + iVar5) = puVar8;
    iVar4 = *(int *)(param_2 + 0xc + iVar5);
    sVar1 = *(size_t *)(param_2 + 0x14 + iVar5);
    puVar8 = FUN_0804c360(*(char **)(param_2 + iVar5),param_1,iVar4,sVar1,sVar1 + iVar4,
                          *(int *)(param_2 + 0x18 + iVar5),*(uint *)(param_2 + 0x10 + iVar5),param_3
                         );
    *(undefined4 *)(*(int *)(param_1 + 0x28) + param_3 * 4) = extraout_EAX_00;
    *(undefined4 *)(*(int *)(param_2 + 0x20 + (int)puVar8) + 0x10) =
         *(undefined4 *)(*(int *)(param_1 + 0x28) + param_3 * 4);
    iVar4 = *(int *)(param_2 + 0x14 + (int)puVar8);
  }
  DAT_08068874 = DAT_08068874 + iVar4;
  return 1;
}



void FUN_0804d0c8(int param_1)

{
  char *pcVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int *piVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  int extraout_EAX;
  int *piVar13;
  uint *puVar14;
  undefined4 *puVar15;
  uint *puVar16;
  int iVar17;
  uint uVar18;
  undefined4 *local_84;
  uint *local_80;
  uint *local_7c;
  undefined4 *local_78;
  int local_74;
  uint *local_70;
  uint *local_6c;
  uint *local_68;
  uint *local_64;
  uint *local_60;
  uint *local_5c;
  uint *local_38;
  uint *local_34;
  int local_28;
  uint local_24;
  char *local_20;
  uint local_18;
  int local_14;
  uint local_10;
  int local_8;
  
  local_38 = (uint *)0x0;
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_HEAD");
  iVar2 = FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
  uVar3 = FUN_0805e13c(*(uint *)(iVar2 + 0xc));
  uVar4 = FUN_0805e13c(*(uint *)(iVar2 + 4));
  if (0 < (int)uVar3) {
    pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_SYMT");
    local_38 = (uint *)FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
  }
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_STRT");
  iVar5 = FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_AREA");
  local_24 = FUN_0805e13c(*(uint *)(pcVar1 + 8));
  uVar6 = FUN_0805e13c(*(uint *)(iVar2 + 8));
  iVar7 = FUN_0804b1e8(uVar6 << 2);
  *(int *)(param_1 + 0x28) = iVar7;
  uVar6 = FUN_0805e13c(*(uint *)(iVar2 + 8));
  *(uint *)(param_1 + 0x24) = uVar6;
  FUN_0804b418();
  iVar17 = 2;
  iVar7 = FUN_0804cb9c(uVar6,0x10);
  piVar8 = FUN_0804aebc(iVar7,iVar17);
  iVar7 = FUN_0804b3ac(*(int *)(param_1 + 0x24) * 0x24);
  local_28 = 0;
  puVar14 = (uint *)(iVar2 + 0x18);
  if (0 < (int)uVar6) {
    local_60 = (uint *)(iVar2 + 0x28);
    local_64 = (uint *)(iVar7 + 0x10);
    local_68 = (uint *)(iVar7 + 0xc);
    local_6c = (uint *)(iVar7 + 0x18);
    local_70 = (uint *)(iVar7 + 0x14);
    local_74 = 0;
    local_78 = (undefined4 *)(iVar7 + 4);
    local_80 = (uint *)(iVar2 + 0x24);
    local_34 = puVar14;
    do {
      uVar9 = FUN_0805e13c(local_80[-1]);
      uVar10 = FUN_0805e13c(local_80[-2]);
      uVar11 = FUN_0805e13c(*local_34);
      pcVar1 = (char *)(uVar11 + iVar5);
      if ((short)uVar10 < 0) {
        local_84 = (undefined4 *)0x0;
        *(undefined4 *)(*(int *)(param_1 + 0x28) + local_28 * 4) = 0;
        if ((DAT_0806ab70 & 0x400) == 0) {
          iVar17 = 0;
        }
        else {
          iVar17 = FUN_0804ccd8(local_24,uVar9);
        }
        *(int *)(iVar7 + 8 + local_74) = iVar17;
        *local_78 = 0;
        puVar15 = (undefined4 *)(uVar10 & 0x1000);
      }
      else {
        uVar18 = uVar10;
        iVar17 = local_28;
        uVar12 = FUN_0805e13c(*local_80);
        uVar11 = local_24;
        if ((uVar10 & 0x1000) == 0) {
          uVar11 = local_24 + uVar9;
        }
        puVar15 = FUN_0804c360(pcVar1,param_1,local_24,uVar9,uVar11,uVar12,uVar18,iVar17);
        *(int *)(*(int *)(param_1 + 0x28) + local_28 * 4) = extraout_EAX;
        *local_78 = 1;
        local_84 = (undefined4 *)extraout_EAX;
      }
      *(char **)(iVar7 + local_74) = pcVar1;
      *local_70 = uVar9;
      uVar11 = FUN_0805e13c(*local_80);
      *local_6c = uVar11;
      *local_68 = local_24;
      *local_64 = uVar10;
      uVar11 = FUN_0805e13c(*local_80);
      local_24 = local_24 + uVar11 * 8;
      if (puVar15 == (undefined4 *)0x0) {
        local_24 = local_24 + uVar9;
      }
      if (local_84 != (undefined4 *)0x0) {
        uVar9 = FUN_0805e13c(*local_60);
        *(uint *)((int)local_84 + 0x2c) = uVar9;
        if (((uVar10 & 0x100) != 0) && ((DAT_0806ab70 & 0x40) == 0)) {
          DAT_0806ab70 = DAT_0806ab70 | 0x40;
          DAT_0806ab98 = uVar9;
        }
        if ((int)uVar4 < 300) {
          *(byte *)((int)local_84 + 0x34) = *(byte *)((int)local_84 + 0x34) | 4;
        }
        piVar13 = FUN_0804afc4(pcVar1,piVar8);
        *piVar13 = (int)local_84;
      }
      local_64 = local_64 + 9;
      local_68 = local_68 + 9;
      local_6c = local_6c + 9;
      local_70 = local_70 + 9;
      local_74 = local_74 + 0x24;
      local_78 = local_78 + 9;
      local_28 = local_28 + 1;
      local_80 = local_80 + 5;
      local_60 = local_60 + 5;
      local_34 = local_34 + 5;
    } while (local_28 < (int)uVar6);
  }
  *(uint *)(param_1 + 0x1c) = uVar3;
  local_84 = (undefined4 *)FUN_0804b1e8(uVar3 * 4);
  *(undefined4 **)(param_1 + 0x20) = local_84;
  puVar15 = local_84 + uVar3;
  if (local_84 < puVar15) {
    local_5c = local_38 + 3;
    local_7c = local_38 + 2;
    do {
      puVar16 = &local_18;
      for (iVar17 = 5; iVar17 != 0; iVar17 = iVar17 + -1) {
        *puVar16 = 0;
        puVar16 = puVar16 + 1;
      }
      uVar3 = FUN_0805e13c(local_7c[-1]);
      local_8 = param_1;
      local_10 = uVar3;
      local_18 = FUN_0805e13c(*local_7c);
      if (((uVar3 & 1) != 0) && ((uVar3 & 0x24) != 4)) {
        piVar13 = piVar8;
        uVar9 = FUN_0805e13c(*local_5c);
        piVar13 = FUN_0804b030((char *)(uVar9 + iVar5),piVar13);
        if (piVar13 == (int *)0x0) {
          local_14 = 0;
        }
        else {
          local_14 = *piVar13;
        }
      }
      if ((uVar3 & 3) == 1) {
        local_20 = (char *)(param_1 + 0x2c);
      }
      else {
        local_20 = "!!";
      }
      uVar3 = FUN_0805e13c(*local_38);
      pcVar1 = (char *)(iVar5 + uVar3);
      iVar17 = strncmp(pcVar1,"Lib$$Request$$",0xe);
      if (iVar17 == 0) {
        FUN_0804cbb8(pcVar1 + 0xe);
      }
      piVar13 = FUN_0804bee8(pcVar1,(int *)&local_18,local_20);
      *local_84 = piVar13;
      local_84 = local_84 + 1;
      local_7c = local_7c + 4;
      local_5c = local_5c + 4;
      local_38 = local_38 + 4;
    } while (local_84 < puVar15);
  }
  if ((DAT_0806ab70 & 0x400) != 0) {
    local_28 = 0;
    if (0 < (int)uVar6) {
      piVar13 = (int *)(iVar7 + 4);
      local_34 = puVar14;
      do {
        uVar3 = FUN_0805e13c(local_34[1]);
        if (((short)uVar3 < 0) && (*piVar13 == 0)) {
          FUN_0804cd08(param_1,iVar7,local_28);
        }
        piVar13 = piVar13 + 9;
        local_28 = local_28 + 1;
        local_34 = local_34 + 5;
      } while (local_28 < (int)uVar6);
    }
    pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_AREA");
    FUN_0805e13c(*(uint *)(pcVar1 + 8));
    local_28 = 0;
    if (0 < (int)uVar6) {
      puVar16 = (uint *)(iVar2 + 0x28);
      local_34 = puVar14;
      do {
        uVar3 = FUN_0805e13c(puVar16[-3]);
        uVar9 = FUN_0805e13c(*local_34);
        if (((short)uVar3 < 0) &&
           (iVar7 = *(int *)(*(int *)(param_1 + 0x28) + local_28 * 4), iVar7 != 0)) {
          uVar10 = FUN_0805e13c(*puVar16);
          *(uint *)(iVar7 + 0x2c) = uVar10;
          if (((uVar3 & 0x100) != 0) && ((DAT_0806ab70 & 0x40) == 0)) {
            DAT_0806ab70 = DAT_0806ab70 | 0x40;
            DAT_0806ab98 = uVar10;
          }
          if ((int)uVar4 < 300) {
            *(byte *)(iVar7 + 0x34) = *(byte *)(iVar7 + 0x34) | 4;
          }
          piVar13 = FUN_0804afc4((char *)(uVar9 + iVar5),piVar8);
          *piVar13 = iVar7;
        }
        local_28 = local_28 + 1;
        puVar16 = puVar16 + 5;
        local_34 = local_34 + 5;
      } while (local_28 < (int)uVar6);
    }
  }
  if (*(uint *)(iVar2 + 0x10) != 0) {
    uVar3 = FUN_0805e13c(*(uint *)(iVar2 + 0x10));
    uVar3 = FUN_0805e13c(puVar14[uVar3 * 5 + -5]);
    piVar8 = FUN_0804b030((char *)(uVar3 + iVar5),piVar8);
    if (piVar8 == (int *)0x0) {
      iVar5 = 0;
    }
    else {
      iVar5 = *piVar8;
    }
    if (DAT_0806ab7c != 0) {
      FUN_0805b0d8("2Multiple entry points found in %s(%s) and %s(%s).");
    }
    DAT_0806ab7c = iVar5;
    DAT_0806abbc = FUN_0805e13c(*(uint *)(iVar2 + 0x14));
    DAT_0806ab70 = DAT_0806ab70 | 0x200;
  }
  FUN_0804b434();
  return;
}



void FUN_0804d71c(int param_1)

{
  undefined4 *puVar1;
  
  DAT_0806ab60 = 1;
  puVar1 = *(undefined4 **)(param_1 + 0x10);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = *(undefined4 **)(*(int *)(param_1 + 8) + 0x14);
  }
  puVar1 = FUN_0804b344(puVar1);
  FUN_0804b418();
  FUN_0804d0c8(param_1);
  FUN_0804b434();
  FUN_0804b394((int)puVar1);
  return;
}



uint FUN_0804d764(int param_1)

{
  char *pcVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  char *pcVar8;
  char *pcVar9;
  bool bVar10;
  uint *local_28;
  uint *local_24;
  uint *local_1c;
  int local_14;
  uint local_10;
  uint local_8;
  
  local_8 = 0;
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_HEAD");
  iVar2 = FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
  uVar3 = FUN_0805e13c(*(uint *)(iVar2 + 0xc));
  if (0 < (int)uVar3) {
    pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_SYMT");
    FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
  }
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_STRT");
  iVar4 = FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 0xc),"OBJ_AREA");
  local_10 = FUN_0805e13c(*(uint *)(pcVar1 + 8));
  uVar3 = FUN_0805e13c(*(uint *)(iVar2 + 8));
  local_14 = 0;
  local_1c = (uint *)(iVar2 + 0x18);
  if (0 < (int)uVar3) {
    local_24 = (uint *)(iVar2 + 0x24);
    local_28 = (uint *)(iVar2 + 0x1c);
    do {
      uVar5 = FUN_0805e13c(local_28[1]);
      uVar6 = FUN_0805e13c(*local_28);
      uVar7 = FUN_0805e13c(*local_1c);
      pcVar1 = (char *)(uVar7 + iVar4);
      iVar2 = 8;
      bVar10 = true;
      pcVar8 = pcVar1;
      pcVar9 = "AIF_HDR";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar10 = *pcVar8 == *pcVar9;
        pcVar8 = pcVar8 + 1;
        pcVar9 = pcVar9 + 1;
      } while (bVar10);
      if ((bVar10) && (uVar5 == 0x80)) {
        PTR_DAT_08068760 = FUN_0804bcd8(local_10,0x80);
LAB_0804d8d8:
        local_8 = local_8 + 1;
      }
      else {
        iVar2 = 10;
        bVar10 = true;
        pcVar8 = pcVar1;
        pcVar9 = "AIF_RELOC";
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar10 = *pcVar8 == *pcVar9;
          pcVar8 = pcVar8 + 1;
          pcVar9 = pcVar9 + 1;
        } while (bVar10);
        if (bVar10) {
          PTR_DAT_08068868 = FUN_0804bcd8(local_10,uVar5);
          DAT_0806886c = uVar5;
          goto LAB_0804d8d8;
        }
        iVar2 = 10;
        bVar10 = true;
        pcVar8 = "AMF_RELOC";
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar10 = *pcVar1 == *pcVar8;
          pcVar1 = pcVar1 + 1;
          pcVar8 = pcVar8 + 1;
        } while (bVar10);
        if (bVar10) {
          PTR_DAT_080687a8 = FUN_0804bcd8(local_10,uVar5);
          DAT_080687ac = uVar5;
          goto LAB_0804d8d8;
        }
      }
      if ((uVar6 & 0x1000) == 0) {
        local_10 = local_10 + uVar5;
      }
      uVar5 = FUN_0805e13c(*local_24);
      local_10 = local_10 + uVar5 * 8;
      local_14 = local_14 + 1;
      local_28 = local_28 + 5;
      local_24 = local_24 + 5;
      local_1c = local_1c + 5;
    } while (local_14 < (int)uVar3);
  }
  if ((0 < (int)local_8) && (local_8 != uVar3)) {
    FUN_0805b0d8("2Special AOF file %s out of specification.");
  }
  return local_8;
}



bool FUN_0804d948(char *param_1,char *param_2)

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
        bVar1 = FUN_0804d948(param_1,param_2);
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



undefined4 *
FUN_0804d9d4(undefined4 *param_1,char *param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6)

{
  char cVar1;
  char cVar2;
  undefined4 *puVar3;
  void *pvVar4;
  char *pcVar5;
  
  cVar1 = *param_2;
  pcVar5 = param_2;
  while (cVar1 != '\0') {
    param_2 = param_2 + 1;
    if (cVar1 == '/') {
      pcVar5 = param_2;
    }
    cVar1 = *param_2;
  }
  puVar3 = (undefined4 *)FUN_0804b1e8(0x30);
  *param_1 = puVar3;
  pvVar4 = FUN_0804b258(pcVar5);
  puVar3[1] = pvVar4;
  puVar3[2] = param_3;
  puVar3[3] = param_4;
  puVar3[5] = param_5;
  puVar3[6] = param_6;
  cVar2 = DAT_08069cf9;
  cVar1 = DAT_08069cf8;
  DAT_08069cf8 = DAT_08069cf8 + '\x01';
  if ('Z' < cVar1) {
    DAT_08069cf8 = '!';
    DAT_08069cf9 = DAT_08069cf9 + '\x01';
    if ('Z' < cVar2) {
      FUN_0805b0d8("3Can\'t link more than %d object files.");
    }
  }
  *(char *)(puVar3 + 0xb) = DAT_08069cf8;
  *(char *)((int)puVar3 + 0x2d) = DAT_08069cf9;
  *puVar3 = 0;
  return puVar3;
}



undefined4 FUN_0804da7c(char *param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_08069cf4;
  DAT_08069cf4 = FUN_0804d9d4(DAT_08069cf4,param_1,param_2,0,0,*(undefined4 *)(param_2 + 0xc));
  return *puVar1;
}



void FUN_0804daa8(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  if (DAT_08069d18 != (undefined4 *)0x0) {
    puVar1 = DAT_08069d18;
    puVar2 = &DAT_08069d18;
    do {
      puVar3 = puVar1;
      if ((*(byte *)(puVar1[1] + 0x10) & 1) != 0) {
        FUN_0805b0d8("0              def:  %s");
        *puVar2 = *puVar1;
        puVar3 = puVar2;
      }
      puVar1 = (undefined4 *)*puVar3;
      puVar2 = puVar3;
    } while (puVar1 != (undefined4 *)0x0);
  }
  return;
}



void FUN_0804daf0(void)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  char *pcVar4;
  int local_8;
  
  piVar2 = (int *)FUN_0804b134(&local_8);
  do {
    if (piVar2 == (int *)0x0) {
      return;
    }
    iVar1 = *piVar2;
    if ((*(uint *)(iVar1 + 0x10) & 1) == 0) {
      piVar3 = DAT_08069d18;
      if (DAT_08069d18 != (int *)0x0) {
        do {
          if (piVar3[1] == iVar1) break;
          piVar3 = (int *)*piVar3;
        } while (piVar3 != (int *)0x0);
        if (piVar3 != (int *)0x0) goto LAB_0804db67;
      }
      if ((*(uint *)(iVar1 + 0x10) & 0x10) == 0) {
        pcVar4 = "0              ref:  %s";
      }
      else {
        pcVar4 = "0              ref:  %s (weak)";
      }
      FUN_0805b0d8(pcVar4);
      piVar3 = (int *)FUN_0804b1e8(0xc);
      *piVar3 = (int)DAT_08069d18;
      piVar3[1] = iVar1;
      piVar3[2] = (int)piVar2 + 6;
      DAT_08069d18 = piVar3;
    }
LAB_0804db67:
    piVar2 = (int *)FUN_0804b154(&local_8);
  } while( true );
}



uint FUN_0804db7c(int param_1)

{
  char *pcVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  uint uVar5;
  int *piVar6;
  uint uVar7;
  undefined1 *puVar8;
  uint *puVar9;
  int iVar10;
  uint *puVar11;
  int iVar12;
  uint *local_8;
  
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 8),"LIB_DIRY");
  local_8 = (uint *)FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
  uVar2 = FUN_0805e13c(*(uint *)(pcVar1 + 0xc));
  puVar3 = (uint *)(uVar2 + (int)local_8);
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 8),"LIB_VRSN");
  uVar2 = (uint)(pcVar1 == (char *)0x0);
  if (*(int *)(param_1 + 0x1c) == 0x61) {
    return uVar2;
  }
  if ((uVar2 != 0) && (*(int *)(param_1 + 0x1c) != 0x6c)) {
    *(undefined4 *)(param_1 + 0x1c) = 0x61;
    return uVar2;
  }
  pcVar1 = FUN_0804bde0(*(int *)(param_1 + 8),"OFL_TIME");
  if (pcVar1 == (char *)0x0) {
    pcVar1 = "1Library %s has no symbol table.";
  }
  else {
    puVar4 = (uint *)FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
    pcVar1 = FUN_0804bde0(*(int *)(param_1 + 8),"LIB_TIME");
    puVar9 = (uint *)FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
    uVar7 = FUN_0805e13c(puVar4[1]);
    uVar5 = FUN_0805e13c(puVar9[1]);
    if ((uVar5 & 0xffff) <= (uVar7 & 0xffff)) {
      if ((uVar7 & 0xffff) != (uVar5 & 0xffff)) {
LAB_0804dca5:
        pcVar1 = FUN_0804bde0(*(int *)(param_1 + 8),"OFL_SYMT");
        puVar4 = (uint *)FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
        uVar7 = FUN_0805e13c(*(uint *)(pcVar1 + 0xc));
        puVar3 = (uint *)(uVar7 + (int)puVar4);
        for (; puVar4 < puVar3; puVar4 = (uint *)((int)puVar4 + uVar7)) {
          if (*puVar4 != 0) {
            piVar6 = FUN_0804afc4((char *)(puVar4 + 3),DAT_0806ab8c);
            uVar7 = FUN_0805e13c(*puVar4);
            *piVar6 = uVar7 - uVar2;
          }
          uVar7 = FUN_0805e13c(puVar4[1]);
        }
        return uVar2;
      }
      uVar7 = FUN_0805e13c(*puVar9);
      uVar5 = FUN_0805e13c(*puVar4);
      if ((int)uVar7 <= (int)uVar5) goto LAB_0804dca5;
    }
    pcVar1 = "1Out of date symbol table in library %s.";
  }
  FUN_0805b0d8(pcVar1);
  for (; local_8 < puVar3; local_8 = (uint *)((int)local_8 + uVar2)) {
    if (*local_8 != 0) {
      uVar2 = FUN_0805e13c(*local_8);
      iVar12 = uVar2 * 0x10 + 0xc + *(int *)(param_1 + 8);
      uVar2 = FUN_0805e13c(*(uint *)(iVar12 + 0xc));
      uVar7 = FUN_0805e13c(*(uint *)(iVar12 + 8));
      FUN_0804bc30(param_1,uVar7,uVar2);
      puVar8 = FUN_0804bd58(0,0x1c);
      uVar2 = FUN_0805e13c(*(uint *)(puVar8 + 4));
      puVar8 = FUN_0804bd58(0,uVar2 * 0x10 + 0x1c);
      pcVar1 = FUN_0804bde0((int)puVar8,"OBJ_HEAD");
      iVar12 = FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
      pcVar1 = FUN_0804bde0((int)puVar8,"OBJ_SYMT");
      puVar9 = (uint *)FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
      pcVar1 = FUN_0804bde0((int)puVar8,"OBJ_STRT");
      iVar10 = FUN_0804bdbc(*(uint *)(pcVar1 + 8),*(uint *)(pcVar1 + 0xc));
      uVar2 = FUN_0805e13c(*(uint *)(iVar12 + 0xc));
      puVar4 = puVar9 + uVar2 * 4;
      for (; puVar9 < puVar4; puVar9 = puVar9 + 4) {
        uVar2 = FUN_0805e13c(puVar9[1]);
        if ((uVar2 & 3) == 3) {
          piVar6 = DAT_0806ab8c;
          uVar2 = FUN_0805e13c(*puVar9);
          puVar11 = FUN_0804afc4((char *)(uVar2 + iVar10),piVar6);
          uVar2 = FUN_0805e13c(*local_8);
          *puVar11 = uVar2;
        }
      }
      FUN_0804bbac(param_1);
    }
    uVar2 = FUN_0805e13c(local_8[1]);
  }
  return 0;
}



undefined4 FUN_0804de78(int *param_1,char *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 uVar2;
  
  if (param_1 == (int *)0x0) {
LAB_0804dea2:
    uVar2 = 1;
  }
  else {
    do {
      bVar1 = FUN_0804d948((char *)(param_1 + 1),param_2);
      if (CONCAT31(extraout_var,bVar1) != 0) goto LAB_0804dea2;
      param_1 = (int *)*param_1;
    } while (param_1 != (int *)0x0);
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_0804deb0(int param_1)

{
  int *piVar1;
  char *pcVar2;
  uint *puVar3;
  uint uVar4;
  uint *puVar5;
  int iVar6;
  uint uVar7;
  undefined1 *puVar8;
  uint uVar9;
  
  pcVar2 = FUN_0804bde0(*(int *)(param_1 + 8),"LIB_DIRY");
  puVar3 = (uint *)FUN_0804bdbc(*(uint *)(pcVar2 + 8),*(uint *)(pcVar2 + 0xc));
  uVar4 = FUN_0805e13c(*(uint *)(pcVar2 + 0xc));
  puVar5 = (uint *)(uVar4 + (int)puVar3);
  do {
    if (puVar5 <= puVar3) {
      return;
    }
    if (*puVar3 != 0) {
      if (*(int *)(param_1 + 0x1c) != 0x61) {
        iVar6 = FUN_0804de78(*(int **)(param_1 + 0x20),(char *)(puVar3 + 3));
        if (iVar6 == 0) goto LAB_0804e002;
        if ((DAT_0806ab70._2_1_ & 8) != 0) {
          FUN_0805b0d8("0  Loading named member %s from %s.");
        }
      }
      uVar4 = FUN_0805e13c(*puVar3);
      iVar6 = uVar4 * 0x10 + 0xc + *(int *)(param_1 + 8);
      uVar4 = FUN_0805e13c(*(uint *)(iVar6 + 8));
      uVar7 = FUN_0805e13c(*(uint *)(iVar6 + 0xc));
      FUN_0804bc30(param_1,uVar4,uVar7);
      piVar1 = DAT_08069cf4;
      if ((DAT_08069d04 == (undefined1 *)0x0) &&
         (puVar8 = (undefined1 *)FUN_0804b2c0(uVar7), puVar8 != (undefined1 *)0x0)) {
        DAT_08069d04 = FUN_0804bae4(puVar8,uVar4,uVar7);
      }
      puVar8 = FUN_0804bcd8(0,0x1c);
      uVar9 = FUN_0805e13c(*(uint *)(puVar8 + 4));
      puVar8 = FUN_0804bcd8(0,uVar9 * 0x10 + 0x1c);
      DAT_08069cf4 = FUN_0804d9d4(DAT_08069cf4,(char *)(puVar3 + 3),param_1,puVar8,uVar4,uVar7);
      *(undefined1 **)(*piVar1 + 0x10) = DAT_08069d04;
      FUN_0804d71c(*piVar1);
      FUN_0804bbac(param_1);
    }
LAB_0804e002:
    uVar4 = FUN_0805e13c(puVar3[1]);
    puVar3 = (uint *)((int)puVar3 + uVar4);
  } while( true );
}



void FUN_0804e020(int param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  char *pcVar3;
  uint *puVar4;
  int *piVar5;
  uint *puVar6;
  undefined1 *puVar7;
  uint uVar8;
  uint *puVar9;
  int iVar10;
  uint *local_14;
  int local_10;
  int local_8;
  
  local_10 = 0;
  local_14 = (uint *)0x0;
  uVar1 = FUN_0804db7c(param_1);
  if (*(int *)(param_1 + 0x1c) != 0x61) {
    uVar2 = FUN_0805e13c(*(uint *)(*(int *)(param_1 + 8) + 4));
    local_10 = FUN_0804b3ac(uVar2 * 4);
    if (uVar1 != 0) {
      local_14 = (uint *)FUN_0804b3ac(uVar2 * 4);
    }
    pcVar3 = FUN_0804bde0(*(int *)(param_1 + 8),"LIB_DIRY");
    puVar4 = (uint *)FUN_0804bdbc(*(uint *)(pcVar3 + 8),*(uint *)(pcVar3 + 0xc));
    uVar2 = FUN_0805e13c(*(uint *)(pcVar3 + 0xc));
    puVar6 = (uint *)(uVar2 + (int)puVar4);
    puVar9 = local_14;
    for (; puVar4 < puVar6; puVar4 = (uint *)((int)puVar4 + uVar2)) {
      uVar2 = FUN_0805e13c(*puVar4);
      *(uint **)(local_10 + uVar2 * 4) = puVar4 + 3;
      if (uVar1 != 0) {
        uVar2 = FUN_0805e13c(*puVar4);
        *puVar9 = uVar2;
      }
      puVar9 = puVar9 + 1;
      uVar2 = FUN_0805e13c(puVar4[1]);
    }
  }
  if ((*(int *)(param_1 + 0x1c) == 0x61) || (*(int *)(param_1 + 0x20) != 0)) {
    if ((DAT_0806ab70._2_1_ & 8) != 0) {
      FUN_0805b0d8("0  Loading whole library %s.");
    }
    if (param_2 != 0) {
      FUN_0804deb0(param_1);
    }
  }
  else {
    iVar10 = 1;
    do {
      if ((DAT_0806ab70._2_1_ & 8) != 0) {
        if (iVar10 == 2) {
          pcVar3 = "0  Re-scanning library %s for referenced modules.";
        }
        else {
          pcVar3 = "0  Scanning library %s for referenced modules.";
        }
        FUN_0805b0d8(pcVar3);
      }
      iVar10 = 0;
      piVar5 = (int *)FUN_0804b134(&local_8);
      while (piVar5 != (int *)0x0) {
        if (((((*(byte *)(*piVar5 + 0x13) & 0x10) != 0) && (*(int *)(*piVar5 + 8) == 0)) &&
            ((short)piVar5[1] == 0x2121)) &&
           (puVar6 = (uint *)FUN_0804b030((char *)((int)piVar5 + 6),DAT_0806ab8c),
           puVar6 != (uint *)0x0)) {
          *(byte *)(*piVar5 + 0x13) = *(byte *)(*piVar5 + 0x13) & 0xef;
          uVar1 = *puVar6;
          if (local_14 != (uint *)0x0) {
            uVar1 = local_14[uVar1];
          }
          pcVar3 = *(char **)(local_10 + uVar1 * 4);
          iVar10 = uVar1 * 0x10 + 0xc + *(int *)(param_1 + 8);
          uVar1 = FUN_0805e13c(*(uint *)(iVar10 + 8));
          uVar2 = FUN_0805e13c(*(uint *)(iVar10 + 0xc));
          FUN_0804bc30(param_1,uVar1,uVar2);
          if ((DAT_08069d04 == (undefined1 *)0x0) &&
             (puVar7 = (undefined1 *)FUN_0804b2c0(uVar2), puVar7 != (undefined1 *)0x0)) {
            DAT_08069d04 = FUN_0804bae4(puVar7,uVar1,uVar2);
          }
          puVar7 = FUN_0804bcd8(0,0x1c);
          uVar8 = FUN_0805e13c(*(uint *)(puVar7 + 4));
          puVar7 = FUN_0804bcd8(0,uVar8 * 0x10 + 0x1c);
          if ((DAT_0806ab70._2_1_ & 8) != 0) {
            FUN_0805b0d8("0    Loading %s to resolve %s.");
          }
          piVar5 = DAT_08069cf4;
          DAT_08069cf4 = FUN_0804d9d4(DAT_08069cf4,pcVar3,param_1,puVar7,uVar1,uVar2);
          *(undefined1 **)(*piVar5 + 0x10) = DAT_08069d04;
          FUN_0804d71c(*piVar5);
          if (((DAT_0806ab70._2_1_ & 8) != 0) && ('\x02' < DAT_0806ab6e)) {
            FUN_0804daf0();
            FUN_0804daa8();
          }
          iVar10 = 2;
        }
        piVar5 = (int *)FUN_0804b154(&local_8);
      }
    } while (iVar10 != 0);
  }
  return;
}



void FUN_0804e2f8(int param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_0804b344(*(undefined4 **)(param_1 + 0x14));
  FUN_0804b418();
  FUN_0804bbac(param_1);
  DAT_0806ab8c = FUN_0804aebc(0x200,2);
  if (*(int *)(param_1 + 4) != 10) {
    FUN_0804e020(param_1,param_2);
  }
  FUN_0804b434();
  FUN_0804b394((int)puVar1);
  return;
}



int * FUN_0804e350(char *param_1)

{
  int *piVar1;
  bool bVar2;
  undefined4 *puVar3;
  int *piVar4;
  int iVar5;
  char cVar6;
  uint uVar7;
  char *pcVar8;
  undefined1 *puVar9;
  int *local_10;
  char *local_c;
  char *local_8;
  
  local_8 = param_1;
  local_c = (char *)0x0;
  FUN_0804b418();
  for (pcVar8 = param_1; *pcVar8 != '\0'; pcVar8 = pcVar8 + 1) {
    if (*pcVar8 == '(') {
      local_8 = FUN_0804b28c(param_1);
      local_8[(int)pcVar8 - (int)param_1] = '\0';
      pcVar8 = pcVar8 + 1;
      local_c = local_8 + ((int)pcVar8 - (int)param_1);
      cVar6 = *pcVar8;
      if (cVar6 != ')') goto LAB_0804e3b1;
      goto LAB_0804e3e0;
    }
  }
  goto LAB_0804e3e9;
  while( true ) {
    pcVar8 = pcVar8 + 1;
    cVar6 = *pcVar8;
    if (cVar6 == ')') break;
LAB_0804e3b1:
    if (cVar6 == '0') break;
  }
  if (cVar6 != ')') {
    puVar9 = &stack0xffffffd0;
    FUN_0805b0d8("2(%s) bad object(area) name %s(%s) ignored.");
    goto LAB_0804e4e4;
  }
LAB_0804e3e0:
  local_8[(int)pcVar8 - (int)param_1] = '\0';
LAB_0804e3e9:
  uVar7 = 0xffffffff;
  pcVar8 = local_8;
  do {
    if (uVar7 == 0) break;
    uVar7 = uVar7 - 1;
    cVar6 = *pcVar8;
    pcVar8 = pcVar8 + 1;
  } while (cVar6 != '\0');
  pcVar8 = local_8 + (~uVar7 - 2);
  puVar3 = DAT_0806ab90;
  if (pcVar8 != local_8) {
    do {
      if (*pcVar8 == '/') break;
      pcVar8 = pcVar8 + -1;
    } while (pcVar8 != local_8);
    if (local_8 < pcVar8) {
      local_8 = pcVar8 + 1;
    }
  }
  for (; puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3) {
    iVar5 = FUN_0804b6c0((char *)puVar3[1],local_8);
    if (iVar5 == 0) {
      local_10 = (int *)0x0;
      bVar2 = false;
      piVar4 = local_10;
      for (piVar1 = DAT_0806ab88; piVar1 != (int *)0x0; piVar1 = (int *)piVar1[2]) {
        local_10 = piVar4;
        if (((undefined4 *)*piVar1 == puVar3) &&
           ((local_c == (char *)0x0 ||
            (iVar5 = FUN_0804b6c0(local_c,(char *)((int)piVar1 + 0x46)), iVar5 == 0)))) {
          local_10 = piVar1;
          if (bVar2) {
            FUN_0805b0d8("2(%s) object %s contains more than one AREA.");
            local_10 = piVar4;
          }
          bVar2 = true;
        }
        piVar4 = local_10;
      }
      if (!bVar2) {
        FUN_0805b0d8("2(%s) AREA %s not found in object %s.");
      }
      FUN_0804b434();
      return piVar4;
    }
  }
  puVar9 = &stack0xffffffd4;
  FUN_0805b0d8("2(%s) object %s not found.");
LAB_0804e4e4:
  *(undefined4 *)(puVar9 + -4) = 0x804e4e9;
  FUN_0804b434();
  return (int *)0x0;
}



void FUN_0804e4f4(char *param_1,uint param_2)

{
  int *piVar1;
  
  if (param_1 != (char *)0x0) {
    piVar1 = FUN_0804e350(param_1);
    if (piVar1 != (int *)0x0) {
      piVar1[0xd] = piVar1[0xd] | param_2;
    }
  }
  return;
}



void FUN_0804e514(undefined4 *param_1)

{
  undefined4 *puVar1;
  bool bVar2;
  int *piVar3;
  int iVar4;
  int local_8;
  
  DAT_0806ab60 = '\0';
  for (puVar1 = param_1; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
    if ((*(byte *)(puVar1 + 1) & 2) != 0) {
      FUN_0804e2f8((int)puVar1,1);
    }
  }
  do {
    if (DAT_0806ab60 == '\0') {
      return;
    }
    DAT_0806ab60 = '\0';
    for (puVar1 = param_1; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      if ((*(byte *)(puVar1 + 1) & 2) != 0) {
        bVar2 = false;
        piVar3 = (int *)FUN_0804b134(&local_8);
        while (piVar3 != (int *)0x0) {
          if ((((*(uint *)(*piVar3 + 0x10) & 0x13) == 2) && (*(int *)(*piVar3 + 8) == 0)) &&
             ((short)piVar3[1] == 0x2121)) {
            iVar4 = strncmp((char *)(piVar3 + 1),"!!Image$$",9);
            if ((iVar4 != 0) && (iVar4 = strncmp((char *)(piVar3 + 1),"!!Load$$",8), iVar4 != 0)) {
              *(byte *)(*piVar3 + 0x13) = *(byte *)(*piVar3 + 0x13) | 0x10;
              bVar2 = true;
            }
          }
          piVar3 = (int *)FUN_0804b154(&local_8);
        }
        if (!bVar2) {
          return;
        }
        FUN_0804e2f8((int)puVar1,0);
      }
    }
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804e618(void)

{
  FUN_08058de8();
  DAT_08069d18 = 0;
  DAT_08069d0c = 0x10;
  FUN_0804b174();
  DAT_0806ab80 = FUN_0804aebc(0x80,1);
  DAT_08068870 = 0;
  DAT_08068874 = 0;
  DAT_0806ab7c = 0;
  DAT_0806aba0 = 0;
  DAT_0806abbc = 0;
  DAT_0806ab90 = 0;
  DAT_08069cf4 = &DAT_0806ab90;
  DAT_0806aba8 = 0;
  DAT_0806abd4 = 0;
  DAT_0806ab88 = 0;
  DAT_0806ab84 = &DAT_0806ab88;
  DAT_0806ac4c = 0;
  DAT_0806ac48 = 0;
  DAT_0806ac54 = 0;
  DAT_0806ac50 = 0;
  PTR_strcmp_080686cc = strcmp;
  DAT_0806abcc = 0;
  DAT_0806abc8 = 0;
  DAT_0806abd0 = 0;
  DAT_0806abb8 = 0;
  DAT_0806abe0 = 0;
  DAT_08069d00 = 0;
  _DAT_08069cfc = 0;
  DAT_08069d04 = 0;
  DAT_08069d0c = 0;
  DAT_08069d08 = 0;
  DAT_08069d10 = 0;
  DAT_0806ab94 = 0;
  DAT_0806abc4 = 0;
  _DAT_08069cf8 = 0x2121;
  FUN_0805e100(0);
  DAT_0806abb0 = 0;
  DAT_08069d14 = 0;
  return;
}



void FUN_0804e798(void)

{
  char cVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int *piVar6;
  char *pcVar7;
  char *__dest;
  undefined4 **ppuVar8;
  undefined4 *local_18;
  size_t local_14;
  undefined4 *local_c;
  int local_8;
  
  uVar4 = FUN_0805de00(0xffb);
  for (puVar2 = DAT_0806ab9c; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
    if ((*(byte *)(puVar2 + 1) & 1) != 0) {
      FUN_0804bbac((int)puVar2);
      piVar6 = DAT_08069cf4;
      DAT_08069cf4 = FUN_0804d9d4(DAT_08069cf4,(char *)(puVar2 + 9),puVar2,puVar2[2],0,puVar2[3]);
      if ((piVar6 != &DAT_0806ab90) || (uVar5 = FUN_0804d764(DAT_0806ab90), uVar5 == 0)) {
        if ((DAT_0806ab70._2_1_ & 8) != 0) {
          FUN_0805b0d8("0  Loading object file %s.");
        }
        FUN_0804d71c(*piVar6);
        if (((DAT_0806ab70._2_1_ & 8) != 0) && ('\x01' < DAT_0806ab6e)) {
          FUN_0804daf0();
          FUN_0804daa8();
        }
      }
    }
  }
  if ((DAT_0806ab64 == 1) && (((byte)DAT_0806ab68 & 4) != 0)) {
    DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ & 0xfb;
  }
  FUN_0804e514(DAT_0806ab9c);
  if ((((byte)DAT_0806ab68 & 4) == 0) && ((DAT_0806ab70._2_1_ & 2) != 0)) {
    piVar6 = (int *)FUN_0804b134(&local_8);
    if (piVar6 != (int *)0x0) {
      do {
        if (((*(byte *)(*piVar6 + 0x10) & 0x11) == 0) &&
           (pcVar7 = strstr((char *)(piVar6 + 1),"$$"), pcVar7 == (char *)0x0)) break;
        piVar6 = (int *)FUN_0804b154(&local_8);
      } while (piVar6 != (int *)0x0);
      if (piVar6 != (int *)0x0) {
        if (DAT_0806abe4 == (char *)0x0) {
          local_14 = 0;
        }
        else {
          uVar5 = 0xffffffff;
          pcVar7 = DAT_0806abe4;
          do {
            if (uVar5 == 0) break;
            uVar5 = uVar5 - 1;
            cVar1 = *pcVar7;
            pcVar7 = pcVar7 + 1;
          } while (cVar1 != '\0');
          local_14 = ~uVar5 - 1;
        }
        local_c = (undefined4 *)0x0;
        ppuVar8 = &local_c;
        for (puVar2 = DAT_08069d14; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
          __dest = (char *)FUN_0804b1e8(local_14 + puVar2[1] + puVar2[2] + 2);
          pcVar7 = __dest;
          if (DAT_0806abe4 != (char *)0x0) {
            memcpy(__dest,DAT_0806abe4,local_14);
            __dest[local_14] = '/';
            pcVar7 = __dest + local_14 + 1;
          }
          memcpy(pcVar7,puVar2 + 4,puVar2[1]);
          iVar3 = puVar2[1];
          memcpy(pcVar7 + iVar3,(void *)puVar2[3],puVar2[2]);
          (pcVar7 + iVar3)[puVar2[2]] = '\0';
          ppuVar8 = (undefined4 **)FUN_0804c948(ppuVar8,__dest,0,0);
        }
        FUN_0804e514(local_c);
        local_18 = &DAT_0806ab9c;
        puVar2 = DAT_0806ab9c;
        while (puVar2 != (undefined4 *)0x0) {
          local_18 = (undefined4 *)*local_18;
          puVar2 = (undefined4 *)*local_18;
        }
        *local_18 = local_c;
      }
    }
  }
  FUN_0804e4f4(DAT_0806abb8,1);
  FUN_0804e4f4(DAT_0806abd0,2);
  if (DAT_0806abe0 != (char *)0x0) {
    if (DAT_0806ab7c != (int *)0x0) {
      FUN_0805b0d8("1Implicit entry point in %s(%s) redefined to %s.");
    }
    DAT_0806ab7c = FUN_0804e350(DAT_0806abe0);
    if (DAT_0806ab7c != (int *)0x0) {
      DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 2;
    }
  }
  *DAT_0806ab84 = 0;
  if (uVar4 != 0) {
    FUN_0805dd68();
    FUN_0805e0d0();
    FUN_0805e0dc();
    FUN_0805e0e8();
    FUN_0805e0f4();
  }
  return;
}



void FUN_0804ea80(void)

{
  FUN_0804e798();
  FUN_08059060();
  return;
}



int FUN_0804ea90(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_1 + 100);
  if (iVar1 == 0) {
    iVar2 = *(int *)(param_1 + 0x44);
  }
  else {
    iVar2 = *(int *)(iVar1 + 0xc);
    for (iVar1 = *(int *)(iVar1 + 4); iVar1 != param_1; iVar1 = *(int *)(iVar1 + 0x60)) {
      iVar2 = iVar2 + (*(int *)(iVar1 + 0x48) - *(int *)(iVar1 + 0x44));
    }
  }
  return iVar2;
}



void FUN_0804eacc(void *param_1,size_t param_2)

{
  size_t sVar1;
  
  sVar1 = fwrite(param_1,1,param_2,DAT_0806a0ac);
  if (sVar1 != param_2) {
    FUN_0805b0d8("3Error writing %s.");
  }
  return;
}



void FUN_0804eb00(byte *param_1,uint param_2)

{
  byte bVar1;
  uint param2;
  uint uVar2;
  int local_70;
  uint local_60;
  uint local_5c;
  char local_58 [12];
  char local_4c [72];
  
  if (DAT_0806ab78 == 0) {
    local_60 = 0;
  }
  else {
    local_60 = 6;
  }
  local_5c = DAT_0806abb0;
  if ((param_2 & 3) != 0) {
    FUN_0805b0d8("3%lu bytes of part-word lost after word 0x%.lx of IHF output.\n");
    param_2 = param_2 & 0xfffffffc;
  }
  if (0 < (int)param_2) {
    do {
      if ((int)param_2 < 0x20) {
        param2 = param_2 >> 2;
      }
      else {
        param2 = 8;
      }
      sprintf(local_58,":%.2X %.4X 00 ",param2,local_5c);
      local_70 = (local_5c >> 8 & 0xff) + param2 + (local_5c & 0xff);
      local_5c = local_5c + param2;
      uVar2 = 0;
      if (param2 << 3 != 0) {
        do {
          bVar1 = *param_1;
          param_1 = param_1 + 1;
          local_70 = local_70 + (uint)bVar1;
          local_4c[uVar2 ^ local_60] = "0123456789ABCDEF"[bVar1 >> 4];
          local_4c[(uVar2 ^ local_60) + 1] = "0123456789ABCDEF"[bVar1 & 0xf];
          uVar2 = uVar2 + 2;
        } while (uVar2 < param2 << 3);
      }
      sprintf(local_4c + uVar2," %.2X\n",-local_70 & 0xff);
      fputs(local_58,DAT_0806a0ac);
      param_2 = param_2 - 0x20;
    } while (0 < (int)param_2);
  }
  DAT_0806abb0 = local_5c;
  return;
}



void FUN_0804ec48(int param_1,byte *param_2,uint param_3)

{
  FUN_08059b8c();
  if (((byte)DAT_0806ab68 & 2) == 0) {
    if (param_1 != DAT_0806a0b0) {
      fseek(DAT_0806a0ac,param_1,0);
    }
    FUN_0804eacc(param_2,param_3);
  }
  else {
    FUN_0804eb00(param_2,param_3);
  }
  DAT_0806a0b0 = param_1 + param_3;
  return;
}



void FUN_0804eca0(void)

{
  FUN_0804ec48(DAT_08069dbc,&stack0x00000004,4);
  DAT_08069dbc = DAT_08069dbc + 4;
  return;
}



void FUN_0804ecc0(int *param_1)

{
  uint uVar1;
  byte *pbVar2;
  
  uVar1 = FUN_0804b6a8((int)param_1);
  while( true ) {
    pbVar2 = (byte *)FUN_0804b668(param_1);
    if (pbVar2 == (byte *)0x0) break;
    FUN_0804ec48(DAT_08069dbc,pbVar2,uVar1);
    DAT_08069dbc = DAT_08069dbc + uVar1;
  }
  return;
}



void FUN_0804ed00(uint param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  if ((param_1 < *(uint *)(PTR_DAT_08068878 + 0x44)) ||
     (*(uint *)(PTR_DAT_08068878 + 0x48) <= param_1)) {
    iVar3 = 0;
    piVar1 = *(int **)(PTR_DAT_08068878 + 0x50);
    do {
      if (piVar1 == (int *)0x0) break;
      for (iVar3 = *piVar1;
          (iVar3 != 0 &&
          ((param_1 < *(uint *)(iVar3 + 0x44) || (*(uint *)(iVar3 + 0x48) <= param_1))));
          iVar3 = *(int *)(iVar3 + 0x54)) {
      }
      piVar1 = (int *)piVar1[1];
    } while (iVar3 == 0);
    if (iVar3 == 0) {
      FUN_0805b0d8("2Entry point 0x%lx+%s(%s) is not in the image.");
    }
    else if (*(int *)(iVar3 + 100) == 0) {
      FUN_0805b0d8("2Entry point 0x%lx+%s(%s) is in an overlay segment (%s).");
    }
    else {
      iVar2 = FUN_0804ea90(iVar3);
      if (iVar2 != *(int *)(iVar3 + 0x44)) {
        FUN_0805b0d8(
                    "2Entry point 0x%lx+%s(%s) is in a non-ROOT execution region (%s in load region %s)."
                    );
      }
    }
  }
  return;
}



void FUN_0804edf0(uint *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = param_3 >> 2;
  if (uVar2 != 0) {
    do {
      uVar1 = FUN_0805e13c(*param_2);
      *param_1 = uVar1;
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      uVar2 = uVar2 - 1;
    } while (0 < (int)uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804ee28(undefined *param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  uint local_88;
  uint local_84 [32];
  
  puVar5 = (uint *)PTR_DAT_08068760;
  if ((DAT_0806ab68 & 8) == 0) {
    if (((DAT_0806ab68 & 0x400) == 0) && (param_1 == PTR_DAT_08068878)) {
      iVar2 = FUN_0804b91c(PTR_DAT_08068760);
      if (iVar2 != 0) {
        FUN_0804edf0(local_84,puVar5,0x80);
        puVar5 = local_84;
      }
      uVar3 = *(uint *)(param_1 + 0x14);
      if ((DAT_0806ab68 & 0x600) == 0) {
        uVar3 = uVar3 + 0x80;
      }
      uVar3 = FUN_0805e13c(uVar3);
      puVar5[5] = uVar3;
      uVar3 = FUN_0805e13c(*(uint *)(param_1 + 0x18));
      puVar5[6] = uVar3;
      puVar5[7] = 0;
      if ((DAT_0806ab70 & 0x400) != 0) {
        iVar2 = DAT_0806a068 + 0x24 + DAT_0806a078 * 8;
        uVar3 = FUN_0805e13c(iVar2 + *(int *)(param_1 + 0x20));
        puVar5[7] = uVar3;
        if ((char)DAT_0806ab68 < '\0') {
          uVar3 = FUN_0805e13c(0xef041d41);
          puVar5[0x10] = uVar3;
        }
        bVar1 = 0 < DAT_0806a078;
        if (DAT_0806ab6d != '\0') {
          bVar1 = bVar1 | 2;
        }
        uVar3 = FUN_0805e13c((uint)bVar1 | iVar2 * 0x10);
        puVar5[9] = uVar3;
      }
      uVar3 = FUN_0805e13c(*(uint *)(param_1 + 0x1c));
      puVar5[8] = uVar3;
      uVar3 = FUN_0805e13c(DAT_0806abd8);
      puVar5[0xb] = uVar3;
      uVar3 = FUN_0805e13c(DAT_0806ab98);
      puVar5[10] = uVar3;
      if ((DAT_08069e44 & _DAT_08069e48 & 0x10000) == 0) {
        if ((DAT_08069e44 & 0x10000) == 0) {
          uVar3 = 0x1a;
        }
        else {
          uVar3 = 0x20;
        }
      }
      else {
        uVar3 = 0;
      }
      if ((char)DAT_0806ab70 < '\0') {
        uVar3 = uVar3 | 0x100;
        uVar4 = FUN_0805e13c(DAT_0806abdc);
        puVar5[0xd] = uVar4;
      }
      uVar3 = FUN_0805e13c(uVar3);
      puVar5[0xc] = uVar3;
      if ((*(int *)(param_1 + 0x1c) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
        uVar3 = FUN_0805e13c(0xeb00000c);
        puVar5[2] = uVar3;
      }
      if ((DAT_0806ab68 & 0x800) != 0) {
        uVar3 = FUN_0805e13c((*(int *)(*DAT_0806a098 + 8) + -8) - (DAT_0806ab98 + 8) >> 2 |
                             0xeb000000);
        puVar5[2] = uVar3;
      }
      local_88 = DAT_0806ab70;
      if (((DAT_0806ab68 & 0x1000) != 0) && (*DAT_08069dac != 0)) {
        uVar3 = DAT_08069dac[5] + 0x80;
        if ((DAT_0806ab70 & 0x400) != 0) {
          uVar3 = DAT_08069dac[5] + 0xa4 + DAT_0806a078 * 8 + DAT_0806a068;
        }
        uVar3 = FUN_0805e13c(uVar3);
        puVar5[0xe] = uVar3;
        local_88 = DAT_0806ab70;
      }
      if ((local_88 & 0x100) == 0) {
        if (((local_88 & 0x200) == 0) || (DAT_0806ab7c == 0)) {
          uVar3 = 0;
        }
        else {
          uVar3 = (DAT_0806abbc + *(int *)(DAT_0806ab7c + 0x2c)) - DAT_0806ab98;
        }
      }
      else {
        uVar3 = DAT_0806aba0 - DAT_0806ab98;
      }
      if ((DAT_0806ab68 & 0x600) == 0) {
        uVar3 = uVar3 - 0x14 >> 2 & 0xffffff | 0xeb000000;
      }
      DAT_0806ab70 = local_88;
      uVar3 = FUN_0805e13c(uVar3);
      puVar5[3] = uVar3;
      uVar3 = FUN_0805e13c(puVar5[7]);
      iVar2 = uVar3 + *(int *)(param_1 + 0x14) + *(int *)(param_1 + 0x18);
      DAT_08069dc8 = iVar2 + 0x80;
      DAT_0806a07c = *(int *)(param_1 + 0x18) + *(int *)(param_1 + 0x14) + *(int *)(param_1 + 0x20)
                     + 0xa4;
      DAT_0806a080 = DAT_0806a07c + DAT_0806a078 * 8;
      DAT_08069dbc = DAT_0806886c + DAT_08069dc8;
      if ((DAT_0806ab68 & 1) != 0) {
        if ((DAT_0806ab68 & 0x600) == 0) {
          uVar3 = FUN_0805e13c(iVar2 + 0x74U >> 2 | 0xeb000000);
          puVar5[1] = uVar3;
        }
        else {
          uVar3 = FUN_0805e13c(DAT_08069dc8);
          puVar5[1] = uVar3;
          DAT_08069dbc = DAT_08069dc8;
        }
      }
      FUN_0804ec48(0,(byte *)puVar5,0x80);
    }
  }
  else {
    DAT_08069dbc = DAT_080687ac + DAT_08069dc8;
  }
  DAT_08069dc0 = DAT_0806a0b0;
  return;
}



int FUN_0804f1a4(int param_1,char *param_2,uint param_3,int param_4)

{
  char *__dest;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar1 = FUN_0805e13c(*(uint *)(param_1 + 8));
  uVar3 = param_4 + 3U & 0xfffffffc;
  __dest = (char *)(param_1 + 0xc + uVar1 * 0x10);
  strncpy(__dest,param_2,8);
  uVar2 = FUN_0805e13c(param_3);
  *(uint *)(__dest + 8) = uVar2;
  uVar2 = FUN_0805e13c(uVar3);
  *(uint *)(__dest + 0xc) = uVar2;
  uVar1 = FUN_0805e13c(uVar1 + 1);
  *(uint *)(param_1 + 8) = uVar1;
  return param_3 + uVar3;
}



void FUN_0804f210(int param_1,int param_2,uint param_3,uint param_4,uint param_5,int param_6,
                 uint param_7)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = (uint *)(param_2 * 0x14 + 0x18 + param_1);
  uVar1 = FUN_0805e13c(DAT_0806a068);
  *puVar2 = uVar1;
  uVar1 = FUN_0805e13c(param_3);
  puVar2[1] = uVar1;
  uVar1 = FUN_0805e13c(param_4);
  puVar2[2] = uVar1;
  uVar1 = FUN_0805e13c(param_5);
  puVar2[3] = uVar1;
  uVar1 = FUN_0805e13c(param_7);
  puVar2[4] = uVar1;
  DAT_0806a068 = DAT_0806a068 + param_6;
  return;
}



void FUN_0804f274(void)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  char *pcVar10;
  int local_28;
  int *local_24;
  int local_20;
  undefined *local_1c;
  undefined4 local_8;
  
  iVar7 = DAT_08069e34;
  if (DAT_08069e38 != 0) {
    return;
  }
  if (DAT_08069e3c != (undefined4 *)0x0) {
    return;
  }
  DAT_0806a06c = 0;
  iVar8 = 0;
  local_28 = 0;
  if ((DAT_0806ab68 & 0x1800) == 0) {
    local_1c = PTR_DAT_08068878;
    local_8 = *(undefined4 *)(PTR_DAT_08068878 + 0x58);
    local_20 = 0;
    local_24 = &local_20;
  }
  else {
    local_24 = DAT_08069dac;
  }
  if (local_24 != (int *)0x0) {
    do {
      if (((DAT_0806ab68 & 0x1800) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
        uVar4 = 0xffffffff;
        pcVar10 = (char *)local_24[6];
        do {
          if (uVar4 == 0) break;
          uVar4 = uVar4 - 1;
          cVar1 = *pcVar10;
          pcVar10 = pcVar10 + 1;
        } while (cVar1 != '\0');
        DAT_0806a06c = DAT_0806a06c + ~uVar4;
      }
      iVar6 = local_24[1];
      if (iVar6 != 0) {
        uVar4 = DAT_0806ab68 & 0x1800;
        uVar9 = DAT_0806ab70 & 0x400;
        do {
          if ((*(int *)(iVar6 + 0x14) != 0) &&
             ((local_28 = local_28 + 1, uVar4 != 0 || (uVar9 != 0)))) {
            iVar8 = iVar8 + 1;
          }
          if ((*(int *)(iVar6 + 0x18) != 0) &&
             ((local_28 = local_28 + 1, uVar4 != 0 || (uVar9 != 0)))) {
            iVar8 = iVar8 + 1;
          }
          if (*(int *)(iVar6 + 0x1c) == 0) {
LAB_0804f392:
            if (uVar9 != 0) {
              for (iVar2 = *(int *)(iVar6 + 8); iVar2 != 0; iVar2 = *(int *)(iVar2 + 8)) {
                if (*(short *)(iVar2 + 0x30) < 0) {
                  iVar8 = iVar8 + 1;
                  uVar5 = 0xffffffff;
                  pcVar10 = (char *)(iVar2 + 0x46);
                  do {
                    if (uVar5 == 0) break;
                    uVar5 = uVar5 - 1;
                    cVar1 = *pcVar10;
                    pcVar10 = pcVar10 + 1;
                  } while (cVar1 != '\0');
                  DAT_0806a06c = DAT_0806a06c + ~uVar5;
                }
              }
            }
          }
          else {
            local_28 = local_28 + 1;
            if ((uVar4 != 0) || (uVar9 != 0)) {
              iVar8 = iVar8 + 1;
              goto LAB_0804f392;
            }
          }
          iVar6 = *(int *)(iVar6 + 0x60);
        } while (iVar6 != 0);
      }
      local_24 = (int *)*local_24;
    } while (local_24 != (int *)0x0);
  }
  if ((DAT_0806ab70 & 0x400) != 0) {
    DAT_0806a06c = DAT_0806a06c + 0x10;
    iVar8 = iVar8 + 2;
  }
  if (iVar8 != 0) {
    DAT_0806a06c = DAT_0806a06c + 10;
    iVar8 = iVar8 + 1;
  }
  *(short *)(DAT_08069e34 + 0x2c) = (short)local_28;
  *(undefined2 *)(iVar7 + 0x2a) = 0x20;
  *(short *)(iVar7 + 0x30) = (short)iVar8;
  *(undefined2 *)(iVar7 + 0x2e) = 0x28;
  *(undefined2 *)(iVar7 + 0x10) = 2;
  *(undefined2 *)(iVar7 + 0x12) = 0x28;
  *(undefined4 *)(iVar7 + 0x14) = 1;
  iVar6 = DAT_08069e34;
  iVar2 = DAT_0806aba0;
  if ((DAT_0806ab70 & 0x100) == 0) {
    if (((DAT_0806ab70 & 0x200) == 0) || (DAT_0806ab7c == 0)) {
      *(undefined4 *)(DAT_08069e34 + 0x18) = 0xffffffff;
      *(undefined4 *)(iVar6 + 0x24) = 0;
      goto LAB_0804f493;
    }
    iVar2 = DAT_0806abbc + *(int *)(DAT_0806ab7c + 0x2c);
    iVar7 = DAT_08069e34;
  }
  *(int *)(iVar7 + 0x18) = iVar2;
  *(byte *)(iVar7 + 0x24) = *(byte *)(iVar7 + 0x24) | 2;
LAB_0804f493:
  *(undefined2 *)(DAT_08069e34 + 0x28) = 0x34;
  if (local_28 != 0) {
    DAT_08069e38 = FUN_0804b1e8(local_28 << 5);
  }
  if (iVar8 != 0) {
    puVar3 = (undefined4 *)FUN_0804b1e8((iVar8 * 5 + 5) * 8);
    DAT_08069e3c = puVar3;
    *puVar3 = 0;
    puVar3[2] = 0;
    puVar3[3] = 0;
    puVar3[4] = 0;
    puVar3[5] = 0;
    puVar3[6] = 0;
    puVar3[7] = 0;
    puVar3[8] = 0;
    puVar3[9] = 0;
    DAT_08069e42 = DAT_08069e42 + 1;
  }
  DAT_08069dc0 = 0x34;
  return;
}



void FUN_0804f52c(void)

{
  int iVar1;
  
  iVar1 = 0;
  if (DAT_08069e38 != (uint *)0x0) {
    iVar1 = FUN_0806013c(DAT_0806a0ac,(int)DAT_08069e34,DAT_08069e38,(uint)DAT_08069e40,DAT_08069dc0
                        );
  }
  if (DAT_08069e3c != (uint *)0x0) {
    if (iVar1 != 0) goto LAB_0804f5a5;
    FUN_080603dc(DAT_0806a0ac,(int)DAT_08069e34,DAT_08069e3c,(uint)DAT_08069e42,0);
  }
  if (iVar1 == 0) {
    FUN_0805fe4c(DAT_0806a0ac,DAT_08069e34);
    return;
  }
LAB_0804f5a5:
  FUN_0805b0d8("3Error writing %s.");
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804f5bc(undefined *param_1)

{
  byte bVar1;
  char cVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  byte *pbVar10;
  uint *puVar11;
  char *pcVar12;
  byte local_104 [256];
  
  if (param_1 == PTR_DAT_08068878) {
    uVar8 = *(uint *)(param_1 + 0x3c);
    if ((DAT_0806ab68 & 4) == 0) {
      uVar8 = (uint)(*(int *)(param_1 + 0x14) != 0);
      if (*(int *)(param_1 + 0x18) != 0) {
        uVar8 = uVar8 + 1;
      }
      if ((DAT_0806ab70._1_1_ & 4) != 0) {
        uVar8 = uVar8 + 1;
      }
      if (*(int *)(param_1 + 0x1c) != 0) {
        uVar8 = uVar8 + 1;
      }
    }
    sprintf((char *)local_104,"%s %s","ARM Linker","5.20 (ARM Ltd SDT2.51)");
    uVar5 = 0xffffffff;
    pbVar10 = local_104;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      bVar1 = *pbVar10;
      pbVar10 = pbVar10 + 1;
    } while (bVar1 != 0);
    uVar7 = ~uVar5 - 1;
    DAT_08069df0 = 0x8c;
    DAT_08069de8 = (uint *)FUN_0804b3ac(0x8c);
    DAT_08069df4 = (uVar8 * 5 + -5) * 4 + 0x2c;
    DAT_08069dec = (uint *)FUN_0804b3ac(DAT_08069df4);
    uVar4 = FUN_0805e13c(0xc3cbc6c5);
    *DAT_08069de8 = uVar4;
    uVar4 = FUN_0805e13c(8);
    puVar11 = DAT_08069de8;
    DAT_08069de8[1] = uVar4;
    puVar11[2] = 0;
    puVar11 = puVar11 + 3;
    for (iVar6 = 0x20; iVar6 != 0; iVar6 = iVar6 + -1) {
      *puVar11 = 0;
      puVar11 = puVar11 + 1;
    }
    uVar4 = FUN_0805e13c(0xc5e2d080);
    *DAT_08069dec = uVar4;
    uVar4 = FUN_0805e13c(0x137);
    DAT_08069dec[1] = uVar4;
    uVar8 = FUN_0805e13c(uVar8);
    DAT_08069dec[2] = uVar8;
    uVar8 = FUN_0805e13c(DAT_0806a078);
    puVar11 = DAT_08069dec;
    DAT_08069dec[3] = uVar8;
    uVar8 = DAT_0806a068;
    puVar3 = DAT_08069dec;
    DAT_0806a068 = 4;
    if ((DAT_0806ab68 & 4) == 0) {
      iVar6 = 0;
      puVar11[4] = 0;
      puVar11[5] = 0;
      if (*(uint *)(param_1 + 0x14) != 0) {
        iVar6 = 1;
        FUN_0804f210((int)DAT_08069dec,0,0x2300,*(uint *)(param_1 + 0x14),0,10,DAT_0806ab98);
        if (DAT_0806ab7c != 0) {
          uVar4 = FUN_0805e13c(1);
          DAT_08069dec[4] = uVar4;
          uVar4 = FUN_0805e13c(*(int *)(DAT_0806ab7c + 0x2c) - DAT_0806ab98);
          DAT_08069dec[5] = uVar4;
        }
      }
      iVar9 = iVar6;
      if (*(uint *)(param_1 + 0x18) != 0) {
        iVar9 = iVar6 + 1;
        FUN_0804f210((int)DAT_08069dec,iVar6,0x100,*(uint *)(param_1 + 0x18),0,10,
                     *(int *)(param_1 + 0x14) + DAT_0806ab98);
      }
      iVar6 = iVar9;
      if (*(uint *)(param_1 + 0x1c) != 0) {
        iVar6 = iVar9 + 1;
        FUN_0804f210((int)DAT_08069dec,iVar9,0x1100,*(uint *)(param_1 + 0x1c),0,10,
                     *(int *)(param_1 + 0x14) + DAT_0806ab98 + *(int *)(param_1 + 0x18));
      }
      if (((DAT_0806ab70._1_1_ & 4) != 0) && ((DAT_0806ab68 & 2) == 0)) {
        FUN_0804f210((int)DAT_08069dec,iVar6,0x8100,*(uint *)(param_1 + 0x20),0,0xb,
                     *(int *)(param_1 + 0x14) + DAT_0806ab98 + *(int *)(param_1 + 0x18));
      }
    }
    else {
      DAT_08069dec[4] = 0;
      puVar3[5] = 0;
      iVar6 = 0;
      if (0 < *(int *)(param_1 + 0x3c)) {
        do {
          iVar9 = *(int *)(*(int *)(param_1 + 0x10) + iVar6 * 4);
          if (iVar9 == DAT_08069db4) {
            uVar4 = FUN_0805e13c(iVar6 + 1);
            DAT_08069dec[4] = uVar4;
            uVar4 = FUN_0805e13c(DAT_08069db0);
            DAT_08069dec[5] = uVar4;
          }
          uVar4 = 0xffffffff;
          pcVar12 = (char *)(*(int *)(iVar9 + 4) + 4);
          do {
            if (uVar4 == 0) break;
            uVar4 = uVar4 - 1;
            cVar2 = *pcVar12;
            pcVar12 = pcVar12 + 1;
          } while (cVar2 != '\0');
          FUN_0804f210((int)DAT_08069dec,iVar6,*(uint *)(iVar9 + 0x30),*(uint *)(iVar9 + 0x1c),
                       *(uint *)(iVar9 + 0x28),~uVar4,*(uint *)(iVar9 + 0x2c));
          iVar6 = iVar6 + 1;
        } while (iVar6 < *(int *)(param_1 + 0x3c));
      }
    }
    DAT_0806a068 = (uVar8 + DAT_0806a068) - 1 & 0xfffffffc;
    uVar8 = FUN_0804f1a4((int)DAT_08069de8,"OBJ_HEAD",0x8c,DAT_08069df4);
    uVar8 = FUN_0804f1a4((int)DAT_08069de8,"OBJ_IDFN",uVar8,~uVar5);
    uVar8 = FUN_0804f1a4((int)DAT_08069de8,"OBJ_AREA",uVar8,
                         *(int *)(param_1 + 0x18) + *(int *)(param_1 + 0x14) +
                         *(int *)(param_1 + 0x20));
    DAT_0806a07c = uVar8;
    if (((DAT_0806ab70._1_1_ & 4) != 0) || ((DAT_0806ab68 & 4) != 0)) {
      DAT_0806a080 = FUN_0804f1a4((int)DAT_08069de8,"OBJ_SYMT",uVar8,DAT_0806a078 << 4);
      uVar8 = FUN_0804f1a4((int)DAT_08069de8,"OBJ_STRT",DAT_0806a080,DAT_0806a068);
    }
    if ((DAT_0806ab68 & 0x2000) != 0) {
      _DAT_0806a084 = uVar8;
      DAT_0806a088 = FUN_0805e13c(DAT_08069de8[2]);
      FUN_0804f1a4((int)DAT_08069de8,"SHL_LIBY",uVar8,0);
    }
    FUN_0804ec48(0,(byte *)DAT_08069de8,DAT_08069df0);
    FUN_0804ec48(DAT_08069df0,(byte *)DAT_08069dec,DAT_08069df4);
    FUN_0804ec48(DAT_0806a0b0,local_104,uVar7);
    FUN_0804ec48(DAT_0806a0b0,&DAT_08063972,4 - (uVar7 & 3));
  }
  DAT_08069dc0 = DAT_0806a0b0;
  DAT_08069dbc = DAT_0806a0b0;
  if ((0 < *(int *)(param_1 + 0x3c)) && ((*(byte *)(**(int **)(param_1 + 0x10) + 0x31) & 0x10) == 0)
     ) {
    DAT_08069dbc = DAT_0806a0b0 + *(int *)(**(int **)(param_1 + 0x10) + 0x1c);
  }
  return;
}



void FUN_0804fad0(void)

{
  undefined *puVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  
  puVar1 = PTR_DAT_08068878;
  iVar3 = DAT_08069de0 * 8;
  DAT_0806a07c = DAT_0806a07c + iVar3;
  DAT_0806a080 = DAT_0806a080 + iVar3;
  iVar4 = 0;
  if (0 < *(int *)(PTR_DAT_08068878 + 0x3c)) {
    iVar5 = 0;
    do {
      uVar2 = FUN_0805e13c(*(uint *)(*(int *)(*(int *)(puVar1 + 0x10) + iVar4 * 4) + 0x28));
      *(uint *)(iVar5 + DAT_08069dec + 0x24) = uVar2;
      iVar5 = iVar5 + 0x14;
      iVar4 = iVar4 + 1;
    } while (iVar4 < *(int *)(puVar1 + 0x3c));
  }
  iVar4 = DAT_08069de8;
  FUN_0804b8d4((uint *)(DAT_08069de8 + 0x38),iVar3);
  uVar2 = FUN_0805e13c(*(uint *)(DAT_08069de8 + 8));
  if (3 < (int)uVar2) {
    puVar6 = (uint *)(iVar4 + 0x14 + uVar2 * 0x10);
    do {
      puVar6 = puVar6 + -4;
      uVar2 = uVar2 - 1;
      FUN_0804b8d4(puVar6,iVar3);
    } while (3 < (int)uVar2);
  }
  return;
}



void FUN_0804fb80(void)

{
  FUN_0804ec48(0,DAT_08069de8,DAT_08069df0);
  FUN_0804ec48(DAT_08069df0,DAT_08069dec,DAT_08069df4);
  return;
}



void FUN_0804fbb0(undefined *param_1)

{
  if (DAT_0806ab64 == 4) {
    FUN_0804ee28(param_1);
  }
  else if (DAT_0806ab64 == 1) {
    FUN_0804f5bc(param_1);
  }
  else if (DAT_0806ab64 == 6) {
    FUN_0804f274();
  }
  else {
    FUN_0805b0d8("3Unknown output type[%d].");
  }
  DAT_08069dd8 = **(undefined4 **)(param_1 + 0x10);
  return;
}



void FUN_0804fc0c(void)

{
  if (DAT_0806ab64 == 1) {
    FUN_0804fad0();
  }
  else {
    FUN_0805b0d8("3Unknown output type[%d].");
  }
  return;
}



void FUN_0804fc30(void)

{
  if (DAT_0806ab64 == 1) {
    FUN_0804fb80();
  }
  else if (DAT_0806ab64 == 6) {
    FUN_0804f52c();
  }
  else {
    FUN_0805b0d8("3Unknown output type[%d].");
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804fc60(void)

{
  uint uVar1;
  
  _DAT_0806a0bc = FUN_0805e13c(0xe28fe001);
  _DAT_0806a0c0 = FUN_0805e13c(0xe12fff1e);
  uVar1 = FUN_0805e174(0xf000);
  _DAT_0806a0c4 = (undefined2)uVar1;
  uVar1 = FUN_0805e174(0xf800);
  _DAT_0806a0c6 = (undefined2)uVar1;
  uVar1 = FUN_0805e174(0x4778);
  _DAT_0806a0c8 = (undefined2)uVar1;
  _DAT_0806a0cc = FUN_0805e13c(0xeafffffa);
  _DAT_0806a0d4 = FUN_0805e13c(0xe92d4000);
  _DAT_0806a0d8 = FUN_0805e13c(0xe28fe001);
  _DAT_0806a0dc = FUN_0805e13c(0xe12fff1e);
  uVar1 = FUN_0805e174(0xf000);
  _DAT_0806a0e0 = (undefined2)uVar1;
  uVar1 = FUN_0805e174(0xf800);
  _DAT_0806a0e2 = (undefined2)uVar1;
  uVar1 = FUN_0805e174(0x4778);
  _DAT_0806a0e4 = (undefined2)uVar1;
  _DAT_0806a0e8 = FUN_0805e13c(0xe8bd8000);
  uVar1 = FUN_0805e174(0x4778);
  _DAT_0806a0ec = (undefined2)uVar1;
  _DAT_0806a0f0 = FUN_0805e13c(0xeb000000);
  _DAT_0806a0f4 = FUN_0805e13c(0xe59fe000);
  _DAT_0806a0f8 = FUN_0805e13c(0xe12fff1e);
  DAT_0806a100 = FUN_0805e13c(0xe59fc000);
  DAT_0806a104 = FUN_0805e13c(0xe12fff1c);
  uVar1 = FUN_0805e174(0x4778);
  DAT_0806a10c._0_2_ = (undefined2)uVar1;
  DAT_0806a110 = FUN_0805e13c(0xea000000);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int * FUN_0804fdd4(int *param_1)

{
  char cVar1;
  int *extraout_EAX;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  char *pcVar7;
  
  iVar6 = DAT_0806a124 * 8 +
          DAT_0806a11c * 0x14 + (DAT_0806a118 + _DAT_0806a114) * 0x18 + DAT_0806a120 * 0xc;
  if (param_1 == (int *)0x0) {
    if (iVar6 == 0) {
      return (int *)0x0;
    }
    if (((byte)DAT_0806ab68 & 4) != 0) {
      _DAT_0806a114 = 0;
      DAT_0806a118 = 0;
      DAT_0806a11c = 0;
      DAT_0806a120 = 0;
      DAT_0806a124 = 0;
      return (int *)0x0;
    }
    FUN_0804c360("IWV$$Code",0,0,0,0,0,0x2200,0);
    param_1 = extraout_EAX;
  }
  uVar5 = 0xffffffff;
  pcVar7 = DAT_08069d28;
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar7 + 1;
  } while (cVar1 != '\0');
  iVar2 = FUN_0804b1e8(~uVar5 + 0x27);
  *(int *)(iVar2 + 0xc) = iVar6;
  strcpy((char *)(iVar2 + 0x24),DAT_08069d28);
  iVar3 = FUN_0804b1e8(*(int *)(iVar2 + 0xc));
  *(int *)(iVar2 + 0x14) = iVar3;
  iVar3 = FUN_0804da7c((char *)(iVar2 + 0x24),iVar2);
  *(undefined4 *)(iVar3 + 0x24) = 1;
  iVar4 = FUN_0804b1e8(4);
  *(int *)(iVar3 + 0x28) = iVar4;
  param_1[9] = iVar6;
  param_1[7] = iVar6;
  *param_1 = iVar3;
  **(undefined4 **)(iVar3 + 0x28) = param_1;
  DAT_08069dcc = *(undefined4 *)(iVar2 + 0x14);
  FUN_0804fc60();
  return param_1;
}



void FUN_0804ff1c(int *param_1)

{
  int iVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  
  iVar1 = DAT_0806a08c * 0xc + 4;
  uVar5 = 0xffffffff;
  pcVar6 = DAT_08069d28;
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar2 = *pcVar6;
    pcVar6 = pcVar6 + 1;
  } while (cVar2 != '\0');
  iVar3 = FUN_0804b1e8(~uVar5 + 0x27);
  *(int *)(iVar3 + 0xc) = iVar1;
  strcpy((char *)(iVar3 + 0x24),DAT_08069d28);
  iVar4 = FUN_0804b1e8(iVar1);
  *(int *)(iVar3 + 0x14) = iVar4;
  iVar3 = FUN_0804da7c((char *)(iVar3 + 0x24),iVar3);
  *(undefined4 *)(iVar3 + 0x24) = 1;
  iVar4 = FUN_0804b1e8(4);
  *(int *)(iVar3 + 0x28) = iVar4;
  param_1[7] = iVar1;
  *param_1 = iVar3;
  *(byte *)(param_1 + 0xd) = *(byte *)(param_1 + 0xd) | 0x20;
  **(undefined4 **)(iVar3 + 0x28) = param_1;
  return;
}



int FUN_0804ffac(uint param_1,uint param_2)

{
  int iVar1;
  
  if ((short)param_1 < 0) {
    iVar1 = 0xb;
  }
  else if ((param_1 & 0x1000) == 0) {
    if ((param_2 & 1) == 0) {
      if ((param_2 & 2) == 0) {
        iVar1 = 1;
        if ((param_1 & 0x2000) == 0) {
          iVar1 = 4;
        }
        if ((param_1 & 0x200) == 0) {
          if ((param_1 & 0x100000) == 0) {
            iVar1 = iVar1 + 1;
          }
          iVar1 = iVar1 + 1;
        }
      }
      else {
        iVar1 = 7;
      }
    }
    else {
      iVar1 = 0;
    }
  }
  else if ((param_2 & 1) == 0) {
    if ((param_2 & 2) == 0) {
      iVar1 = 9;
    }
    else {
      iVar1 = 10;
    }
  }
  else {
    iVar1 = 8;
  }
  return iVar1;
}



undefined4 FUN_08050020(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  char *__s2;
  undefined4 uVar3;
  char *__s1;
  
  iVar1 = FUN_0804ffac(*(uint *)(param_1 + 0x30),*(uint *)(param_1 + 0x34));
  iVar2 = FUN_0804ffac(*(uint *)(param_2 + 0x30),*(uint *)(param_2 + 0x34));
  if (iVar2 < iVar1) goto LAB_0805006e;
  if (iVar1 == iVar2) {
    __s1 = (char *)(*(int *)(param_1 + 4) + 4);
    __s2 = (char *)(*(int *)(param_2 + 4) + 4);
    if ((__s1 == __s2) || ((DAT_0806ab70._2_1_ & 0x20) != 0)) {
      if (*(int *)(param_1 + 0x3c) <= *(int *)(param_2 + 0x3c)) goto LAB_08050080;
    }
    else {
      iVar1 = strcmp(__s1,__s2);
      if (iVar1 < 1) goto LAB_08050080;
    }
LAB_0805006e:
    uVar3 = 1;
  }
  else {
LAB_08050080:
    uVar3 = 0;
  }
  return uVar3;
}



void FUN_0805008c(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *local_14;
  int local_c;
  
  iVar3 = param_1 + -4;
  iVar6 = 1;
  do {
    iVar6 = iVar6 * 3 + 1;
  } while (iVar6 <= param_2);
  do {
    iVar6 = iVar6 / 3;
    local_c = iVar6 + 1;
    if (local_c <= param_2) {
      local_14 = (int *)(iVar3 + local_c * 4);
      do {
        iVar1 = *local_14;
        iVar2 = local_c;
        while (iVar6 < iVar2) {
          iVar5 = iVar2 - iVar6;
          iVar4 = FUN_08050020(*(int *)(iVar3 + iVar5 * 4),iVar1);
          if (iVar4 == 0) break;
          *(undefined4 *)(iVar3 + iVar2 * 4) = *(undefined4 *)(iVar3 + iVar5 * 4);
          iVar2 = iVar5;
        }
        *(int *)(iVar3 + iVar2 * 4) = iVar1;
        local_14 = local_14 + 1;
        local_c = local_c + 1;
      } while (local_c <= param_2);
    }
    if (iVar6 < 2) {
      return;
    }
  } while( true );
}



void FUN_08050140(int param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint *local_14;
  int local_10;
  int local_c;
  
  iVar5 = param_1 + -8;
  local_c = 1;
  do {
    local_c = local_c * 3 + 1;
  } while (local_c <= param_2);
  do {
    local_c = local_c / 3;
    local_10 = local_c + 1;
    if (local_10 <= param_2) {
      local_14 = (uint *)(iVar5 + local_10 * 8);
      do {
        uVar1 = *local_14;
        uVar2 = local_14[1];
        iVar4 = local_10;
        while ((local_c < iVar4 && (iVar6 = iVar4 - local_c, uVar1 < *(uint *)(iVar5 + iVar6 * 8))))
        {
          uVar3 = *(undefined4 *)(param_1 + -4 + iVar6 * 8);
          *(undefined4 *)(iVar5 + iVar4 * 8) = *(undefined4 *)(iVar5 + iVar6 * 8);
          *(undefined4 *)(param_1 + -4 + iVar4 * 8) = uVar3;
          iVar4 = iVar6;
        }
        *(uint *)(iVar5 + iVar4 * 8) = uVar1;
        *(uint *)(param_1 + -4 + iVar4 * 8) = uVar2;
        local_14 = local_14 + 2;
        local_10 = local_10 + 1;
      } while (local_10 <= param_2);
    }
  } while (1 < local_c);
  return;
}



void FUN_08050214(char *param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = FUN_0804afc4(param_1,DAT_0806ab74);
  iVar2 = FUN_0804b1e8(0x1c);
  *piVar1 = iVar2;
  *(undefined4 *)(iVar2 + 8) = param_2;
  *(undefined4 *)(iVar2 + 0xc) = 0;
  *(undefined4 *)(iVar2 + 0x10) = param_3;
  *(undefined4 *)(iVar2 + 0x14) = 0;
  *(undefined4 *)(iVar2 + 0x18) = 0;
  *(undefined4 *)*piVar1 = 0xffffffff;
  *(undefined4 *)(*piVar1 + 4) = 0xffffffff;
  FUN_0804b0f8(piVar1);
  return;
}



void FUN_08050278(char *param_1,int param_2)

{
  char *pcVar1;
  
  pcVar1 = FUN_0804b950("!!",param_1,(char *)0x0);
  FUN_0804c270(0,pcVar1,param_2);
  return;
}



void FUN_0805029c(char *param_1,undefined4 param_2,int param_3)

{
  int *piVar1;
  
  piVar1 = FUN_0804b030(param_1,DAT_0806ab74);
  if (piVar1 != (int *)0x0) {
    FUN_0805b0d8("1Symbol %s referenced, %s used.");
    FUN_0804c270(0,param_1,param_3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_080502d8(int param_1,int param_2,char *param_3)

{
  uint uVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  uint local_1018;
  uint local_1010;
  uint local_100c;
  undefined4 local_1008;
  char local_1004 [4096];
  
  local_100c = *(uint *)(param_2 + 0x30);
  if (((local_100c & 0x200) != 0) && (param_2 != DAT_08069ddc)) {
    DAT_08069e44 = local_100c & 0xb0000 | DAT_08069e44;
    _DAT_08069e48 = ~local_100c & 0xb0000 | _DAT_08069e48;
    uVar4 = DAT_08069e44 & _DAT_08069e48 & ~DAT_08069e4c;
    if (uVar4 == 0) {
      if (((local_100c & 0x40000) != 0) && ((DAT_0806ab6f & 0x20) != 0)) {
        FUN_0805b0d8("1AREA %s(%s) uses revision-3 FP instructions.");
      }
    }
    else {
      FUN_0805b0d8("1Attribute conflict between AREA %s(%s) and image code.");
      FUN_0804be34(local_1004,0x1000,uVar4,local_100c & 0x200);
      FUN_0805b0d8("0(attribute difference = {%s}).");
      DAT_08069e4c = DAT_08069e4c | uVar4;
    }
  }
  while( true ) {
    iVar3 = FUN_0804af0c(&local_1008,param_3,*(int **)(param_1 + 0x5c),strcmp);
    if (iVar3 != 0) break;
    uVar4 = *(uint *)(*local_1008 + 0x30);
    if (local_100c == uVar4) goto LAB_08050767;
    uVar1 = local_100c & 0x40000;
    *(uint *)(*local_1008 + 0x30) = uVar4 | uVar1;
    local_1018 = uVar4 & 0xfffbffff;
    local_1018 = local_1018 | uVar1;
    local_1010 = local_100c & 0x200;
    if (((((DAT_0806ab70._2_1_ & 0x40) != 0) && ((uVar4 & 0x2000) != 0)) &&
        ((local_100c & 0x2000) != 0)) && (((local_1018 ^ local_100c) & 0x200) != 0)) {
      iVar3 = 0xd;
      bVar7 = true;
      pcVar5 = param_3;
      pcVar6 = "C$$constdata";
      do {
        if (iVar3 == 0) break;
        iVar3 = iVar3 + -1;
        bVar7 = *pcVar5 == *pcVar6;
        pcVar5 = pcVar5 + 1;
        pcVar6 = pcVar6 + 1;
      } while (bVar7);
      if (bVar7) {
        if (local_1010 == 0) {
          local_1018 = uVar4 & 0xff80fdff | uVar1;
        }
        else {
          local_100c = local_100c & 0xff84fdff;
          local_1010 = 0;
        }
      }
    }
    uVar4 = local_1018;
    if ((local_1018 & 0x200) != 0) {
      local_1018 = local_1018 & 0xff8fffff;
      local_1018 = local_1018 | local_100c & 0x700000;
    }
    if (((-1 < *(short *)(param_2 + 0x30)) && (param_2 != DAT_08069ddc)) &&
       ((local_100c != local_1018 && ((*(byte *)(*local_1008 + 0x34) & 0x10) == 0)))) {
      FUN_0805b0d8("1Attribute conflict within AREA %s\n    (conflict first found with %s(%s)).");
      FUN_0804be34(local_1004,0x1000,local_1018 ^ local_100c,uVar4 & 0x200);
      FUN_0805b0d8("0(attribute difference = {%s}).");
      *(byte *)(*local_1008 + 0x34) = *(byte *)(*local_1008 + 0x34) | 0x10;
    }
    if ((local_1010 == 0) && ((local_100c & 0x109000) != 0)) {
      local_100c = local_100c & 0xf109000;
    }
    else {
      local_100c = local_100c & 0x2200;
    }
    if (((uVar4 & 0x200) == 0) && ((local_1018 & 0x109000) != 0)) {
      local_1018 = local_1018 & 0xf109000;
    }
    else {
      local_1018 = local_1018 & 0x2200;
    }
    if (local_100c == local_1018) goto LAB_08050767;
    sprintf(local_1004,"%lx",local_100c);
    uVar4 = 0xffffffff;
    pcVar5 = local_1004;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar2 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar2 != '\0');
    FUN_0804b710(local_1004 + (~uVar4 - 1),param_3,0x1000 - (~uVar4 - 1));
    param_3 = local_1004;
  }
  uVar4 = 0xffffffff;
  pcVar5 = param_3;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar2 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar2 != '\0');
  iVar3 = FUN_0804b1e8(~uVar4 + 0x4b);
  *local_1008 = iVar3;
  *(undefined2 *)(*local_1008 + 0x44) = 0;
  iVar3 = DAT_0806ab94 + 1;
  DAT_0806ab94 = DAT_0806ab94 + 1;
  *(int *)(*local_1008 + 0x3c) = iVar3;
  *(uint *)(*local_1008 + 0x30) = local_100c;
  *(undefined4 *)(*local_1008 + 0x18) = 0;
  *(undefined4 *)(*local_1008 + 0x1c) = 0;
  *(undefined4 *)(*local_1008 + 0x28) = 0;
  *(undefined4 *)(*local_1008 + 0x2c) = 0xffffffff;
  *(int **)(*local_1008 + 4) = local_1008;
  *(undefined4 *)(*local_1008 + 8) = 0;
  *(undefined4 *)*local_1008 = 0;
  strcpy((char *)(*local_1008 + 0x46),param_3);
  *(int *)(param_1 + 0x3c) = *(int *)(param_1 + 0x3c) + 1;
  *DAT_08069dd4 = *local_1008;
  DAT_08069dd4 = (int *)(*local_1008 + 8);
LAB_08050767:
  *(int **)(param_2 + 4) = local_1008;
  return;
}



void FUN_08050780(int *param_1,char *param_2,char *param_3)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  void *pvVar4;
  uint uVar5;
  uint uVar6;
  char *__src;
  
  *param_1 = (int)(param_1 + 1);
  param_1[0xe] = 0;
  param_1[1] = 0;
  param_1[0x15] = 0;
  param_1[0x14] = 0;
  param_1[0xf] = 0;
  param_1[2] = 0;
  param_1[9] = -1;
  param_1[10] = 0;
  param_1[0x11] = -1;
  param_1[0x19] = 0;
  param_1[0x18] = 0;
  param_1[0x1a] = 0;
  puVar2 = FUN_0804aebc(0x200,1);
  param_1[0x17] = (int)puVar2;
  if ((DAT_0806ab68 & 0x800) == 0) {
    if ((DAT_0806ab68 & 0x1000) == 0) {
      pvVar4 = FUN_0804b258(param_2);
      param_1[0x16] = (int)pvVar4;
    }
    else {
      pvVar4 = FUN_0804b258(param_3);
      param_1[0x16] = (int)pvVar4;
    }
  }
  else {
    uVar5 = 0xffffffff;
    pcVar3 = param_2;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    uVar6 = 0xffffffff;
    pcVar3 = param_3;
    do {
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    pcVar3 = (char *)FUN_0804b1e8(~uVar5 + ~uVar6);
    param_1[0x16] = (int)pcVar3;
    __src = "/";
    pcVar3 = strcpy(pcVar3,param_2);
    pcVar3 = strcat(pcVar3,__src);
    strcat(pcVar3,param_3);
  }
  return;
}



int * FUN_08050888(char *param_1)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  uint uVar5;
  char *pcVar6;
  char *pcVar7;
  uint local_14;
  size_t local_10;
  int *local_c;
  int *local_8;
  
  local_10 = 0;
  local_14 = 0;
  cVar1 = *param_1;
  pcVar6 = param_1;
  while ((cVar1 != '\0' && (*pcVar6 != '_'))) {
    pcVar6 = pcVar6 + 1;
    local_10 = local_10 + 1;
    cVar1 = *pcVar6;
  }
  local_c = (int *)&DAT_08069d90;
  piVar3 = DAT_08069d90;
  if (DAT_08069d90 != (int *)0x0) {
    do {
      pcVar6 = *(char **)(*piVar3 + 0x58);
      if ((*(byte *)(*piVar3 + 0x68) & 1) != 0) {
        if ((DAT_0806ab68._1_1_ & 8) == 0) {
          iVar2 = strncmp(pcVar6,param_1,local_10);
          if (iVar2 == 0) {
            local_14 = 0;
            break;
          }
        }
        else {
          uVar5 = 0xffffffff;
          pcVar7 = pcVar6;
          do {
            if (uVar5 == 0) break;
            uVar5 = uVar5 - 1;
            cVar1 = *pcVar7;
            pcVar7 = pcVar7 + 1;
          } while (cVar1 != '\0');
          for (pcVar7 = pcVar6 + (~uVar5 - 1); (pcVar7 != pcVar6 && (*pcVar7 != '/'));
              pcVar7 = pcVar7 + -1) {
          }
          iVar2 = strncmp(pcVar7 + 1,param_1,local_10);
          if (iVar2 == 0) {
            local_14 = (int)pcVar7 - (*(int *)(*piVar3 + 0x58) + -1);
            break;
          }
        }
      }
      local_c = piVar3 + 1;
      piVar3 = (int *)piVar3[1];
    } while (piVar3 != (int *)0x0);
    if (piVar3 != (int *)0x0) goto LAB_0805098d;
  }
  piVar3 = (int *)FUN_0804b1e8(0xc);
  *local_c = (int)piVar3;
  piVar3[1] = 0;
  piVar3[2] = -1;
  *piVar3 = 0;
LAB_0805098d:
  piVar4 = (int *)*piVar3;
  local_8 = piVar3;
  if (piVar4 != (int *)0x0) {
    do {
      uVar5 = 0xffffffff;
      pcVar6 = (char *)piVar4[0x16];
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar6;
        pcVar6 = pcVar6 + 1;
      } while (cVar1 != '\0');
      if ((local_14 < ~uVar5 - 1) &&
         (iVar2 = strcmp((char *)piVar4[0x16] + local_14,param_1), iVar2 == 0)) break;
      local_8 = piVar4 + 0x15;
      piVar4 = (int *)piVar4[0x15];
    } while (piVar4 != (int *)0x0);
    if (piVar4 != (int *)0x0) {
      return piVar4;
    }
  }
  piVar4 = (int *)FUN_0804b1e8(0x6c);
  *local_8 = (int)piVar4;
  FUN_08050780(piVar4,DAT_0806abc8,param_1);
  DAT_0806a08c = DAT_0806a08c + 1;
  piVar4[0x13] = (int)piVar3;
  piVar3[2] = piVar3[2] + 1;
  return piVar4;
}



undefined4 FUN_08050a0c(int *param_1,int param_2,undefined4 *param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined4 *puVar2;
  undefined4 uVar3;
  int iVar4;
  char *pcVar5;
  
  pcVar5 = DAT_08069d28;
  if (*param_1 != 0) {
    pcVar5 = *(char **)(*param_1 + 4);
  }
  bVar1 = FUN_0804d948((char *)*param_3,pcVar5);
  if ((CONCAT31(extraout_var,bVar1) == 0) &&
     (((*param_1 == 0 || (iVar4 = *(int *)(*param_1 + 8), (*(byte *)(iVar4 + 4) & 1) != 0)) ||
      (bVar1 = FUN_0804d948((char *)*param_3,(char *)(iVar4 + 0x24)),
      CONCAT31(extraout_var_00,bVar1) == 0)))) {
    uVar3 = 0;
  }
  else {
    iVar4 = 1;
    if (((param_1[4] != 0) && (param_1[4] != param_2)) &&
       (iVar4 = FUN_0805b2fc((undefined4 *)param_1[5],param_3), iVar4 == 0)) {
      FUN_0805b0d8("2AREA %s(%s) already matches an AREA selector for region \'%s\'.");
    }
    if (iVar4 != -1) {
      param_1[4] = param_2;
    }
    if (iVar4 == 1) {
      puVar2 = FUN_0805b210(param_3,pcVar5,(char *)((int)param_1 + 0x46));
      param_1[5] = (int)puVar2;
    }
    uVar3 = 1;
  }
  return uVar3;
}



int FUN_08050ad0(int param_1,undefined4 *param_2,int *param_3)

{
  char *pcVar1;
  int *piVar2;
  bool bVar3;
  uint uVar4;
  undefined3 extraout_var;
  int *piVar5;
  undefined3 extraout_var_00;
  int iVar6;
  int iVar7;
  int local_8;
  
  iVar7 = 0;
  if (param_1 == 0) {
    uVar4 = *(uint *)(*param_3 + 0x34);
    if ((*(byte *)(param_2 + 2) & 2) == 0) {
      uVar4 = uVar4 | 2;
    }
    else {
      uVar4 = uVar4 | 1;
    }
    *(uint *)(*param_3 + 0x34) = uVar4;
    iVar7 = 0;
  }
  else {
    piVar5 = DAT_0806ab88;
    if (param_3 != (int *)0x0) {
      *param_3 = 0;
      piVar5 = DAT_0806ab88;
    }
    for (; piVar5 != (int *)0x0; piVar5 = (int *)piVar5[2]) {
      if (-1 < (short)piVar5[0xc]) {
        pcVar1 = (char *)param_2[2];
        if (param_2[1] == 0) {
          bVar3 = FUN_0804d948(pcVar1,(char *)((int)piVar5 + 0x46));
          if (CONCAT31(extraout_var,bVar3) != 0) goto LAB_08050b51;
        }
        else if (((pcVar1 == (char *)0x1) && (piVar5 == DAT_0806ab7c)) ||
                ((char *)(param_2[1] & piVar5[0xc]) == pcVar1)) {
LAB_08050b51:
          iVar6 = FUN_08050a0c(piVar5,param_1,param_2);
          if (iVar6 != 0) {
            if (param_3 != (int *)0x0) {
              if (iVar7 == 0) {
                *param_3 = (int)piVar5;
              }
              else {
                *param_3 = 0;
              }
            }
            iVar7 = 1;
          }
        }
      }
    }
    if (((iVar7 == 0) && ((DAT_0806ab68._1_1_ & 8) != 0)) && (param_2[1] == 0)) {
      piVar5 = (int *)FUN_0804b134(&local_8);
      while (piVar5 != (int *)0x0) {
        piVar2 = *(int **)(*piVar5 + 0xc);
        if (((piVar2 != (int *)0x0) && (*piVar2 != 0)) &&
           ((bVar3 = FUN_0804d948((char *)param_2[2],(char *)((int)piVar5 + 6)),
            CONCAT31(extraout_var_00,bVar3) != 0 &&
            (iVar6 = FUN_08050a0c(piVar2,param_1,param_2), iVar6 != 0)))) {
          if (param_3 != (int *)0x0) {
            if (iVar7 == 0) {
              *param_3 = (int)piVar2;
            }
            else {
              *param_3 = 0;
            }
          }
          iVar7 = 1;
        }
        piVar5 = (int *)FUN_0804b154(&local_8);
      }
    }
  }
  return iVar7;
}



void FUN_08050c1c(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_c = 0;
  local_8 = param_3;
  iVar1 = FUN_08050ad0(param_1,&local_10,(int *)0x0);
  if (iVar1 == 0) {
    FUN_0805b0d8("2No object(AREA) matches %s(%s).");
  }
  return;
}



void FUN_08050c60(int param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_c = 0x9200;
  local_8 = 0x200;
  iVar1 = FUN_08050ad0(param_1,&local_10,(int *)0x0);
  if (iVar1 == 0) {
    FUN_0805b0d8("2No object(+ATTRIBUTES) matches %s(+%s).");
  }
  return;
}



undefined4 * FUN_08050ca8(char *param_1,undefined *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  undefined4 *puVar2;
  void *pvVar3;
  undefined4 *unaff_EBX;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  puVar5 = &DAT_08069dac;
  puVar2 = DAT_08069dac;
  if (DAT_08069dac != (undefined4 *)0x0) {
    do {
      puVar4 = puVar2;
      iVar1 = FUN_0804b6c0((char *)puVar4[6],param_1);
      puVar2 = puVar4;
      if (iVar1 == 0) break;
      puVar2 = (undefined4 *)*puVar4;
      puVar5 = puVar4;
    } while (puVar2 != (undefined4 *)0x0);
    if (puVar2 != (undefined4 *)0x0) {
      if (puVar2[1] != 0) {
        return unaff_EBX;
      }
      goto LAB_08050d07;
    }
  }
  puVar2 = (undefined4 *)FUN_0804b1e8(0x1c);
  pvVar3 = FUN_0804b258(param_1);
  puVar2[6] = pvVar3;
  *puVar2 = 0;
  puVar2[5] = 0;
  *puVar5 = puVar2;
LAB_08050d07:
  puVar2[3] = param_3;
  puVar2[4] = param_4;
  puVar2[2] = param_2;
  puVar2[1] = param_2;
  if (param_2 == PTR_DAT_08068878) {
    *(undefined4 **)(param_2 + 100) = puVar2;
  }
  return unaff_EBX;
}



int * FUN_08050d34(int param_1,char *param_2,uint param_3,uint param_4)

{
  int iVar1;
  undefined4 *puVar2;
  int *piVar3;
  
  piVar3 = &DAT_08069d90;
  for (iVar1 = DAT_08069d90; iVar1 != 0; iVar1 = *(int *)(iVar1 + 4)) {
    piVar3 = (int *)(iVar1 + 4);
  }
  puVar2 = (undefined4 *)FUN_0804b1e8(0xc);
  *piVar3 = (int)puVar2;
  puVar2[1] = 0;
  puVar2[2] = 0;
  piVar3 = (int *)FUN_0804b1e8(0x6c);
  *puVar2 = piVar3;
  FUN_08050780(piVar3,DAT_0806abc8,param_2);
  piVar3[0x13] = (int)puVar2;
  piVar3[0x19] = param_1;
  if ((param_4 & 2) == 0) {
    piVar3[9] = param_3;
  }
  else {
    param_4 = param_4 & 3 | param_3;
  }
  piVar3[0x1a] = param_4;
  if ((param_4 & 1) != 0) {
    DAT_0806a08c = DAT_0806a08c + 1;
  }
  if (*(int *)(param_1 + 8) == 0) {
    *(int **)(param_1 + 4) = piVar3;
  }
  else {
    *(int **)(*(int *)(param_1 + 8) + 0x60) = piVar3;
  }
  *(int **)(param_1 + 8) = piVar3;
  return piVar3;
}



int FUN_08050de8(int param_1)

{
  int iVar1;
  
  iVar1 = 0;
  for (; param_1 != 0; param_1 = *(int *)(param_1 + 8)) {
    if (-1 < *(short *)(param_1 + 0x30)) {
      iVar1 = iVar1 + (*(int *)(param_1 + 0x1c) + 3U & 0xfffffffc);
    }
  }
  return iVar1;
}



void FUN_08050e10(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  uint uVar8;
  int *local_18;
  int *local_14;
  int *local_10;
  uint local_c;
  
  if (DAT_0806a08c != 0) {
    local_c = 0;
    for (piVar7 = DAT_08069d90; piVar7 != (int *)0x0; piVar7 = (int *)piVar7[1]) {
      local_c = local_c + 1;
    }
    FUN_0804b418();
    iVar4 = FUN_0804b3ac(local_c * 8);
    local_c = 0;
    iVar5 = 0;
    if (DAT_08069d90 != (int *)0x0) {
      local_14 = (int *)(iVar4 + -8);
      local_18 = (int *)(iVar4 + -4);
      piVar7 = DAT_08069d90;
      do {
        local_14 = local_14 + 2;
        local_18 = local_18 + 2;
        local_c = local_c + 1;
        iVar1 = *piVar7;
        *local_18 = iVar1;
        if (*(int *)(iVar1 + 0x24) != -1) {
          iVar5 = *(int *)(iVar1 + 0x24);
        }
        if ((*(uint *)(iVar1 + 0x68) & 2) != 0) {
          iVar2 = *(int *)(iVar1 + 100);
          if ((iVar2 != 0) && (*(int *)(iVar2 + 4) == iVar1)) {
            iVar5 = *(int *)(iVar2 + 0xc);
          }
          iVar5 = iVar5 + (*(uint *)(iVar1 + 0x68) & 0xfffffffc);
        }
        *(int *)(iVar1 + 0x44) = iVar5;
        *local_14 = iVar5;
        iVar5 = FUN_08050de8(*(int *)(iVar1 + 4));
        iVar5 = iVar5 + *(int *)(iVar1 + 0x44);
        *(int *)(iVar1 + 0x48) = iVar5;
        piVar7 = (int *)piVar7[1];
      } while (piVar7 != (int *)0x0);
    }
    FUN_08050140(iVar4,local_c);
    piVar7 = (int *)0x0;
    uVar8 = 0;
    uVar6 = 0;
    local_18 = (int *)0x0;
    if (local_c != 0) {
      local_10 = (int *)(iVar4 + 4);
      do {
        iVar5 = *local_10;
        if ((*(byte *)(iVar5 + 0x68) & 1) != 0) {
          if (piVar7 == (int *)0x0) {
            piVar7 = *(int **)(iVar5 + 0x4c);
            uVar8 = *(uint *)(iVar5 + 0x48);
            uVar6 = *(uint *)(iVar5 + 0x44);
          }
          else if ((*(uint *)(iVar5 + 0x44) < uVar8) && (uVar6 < *(uint *)(iVar5 + 0x48))) {
            **(undefined4 **)(iVar5 + 0x4c) = 0;
            *(int *)(iVar5 + 0x54) = *piVar7;
            *piVar7 = iVar5;
            piVar7[2] = piVar7[2] + 1;
            *(int **)(iVar5 + 0x4c) = piVar7;
            if (uVar8 < *(uint *)(iVar5 + 0x48)) {
              uVar8 = *(uint *)(iVar5 + 0x48);
            }
            if (*(uint *)(iVar5 + 0x44) <= uVar6) {
              uVar6 = *(uint *)(iVar5 + 0x44);
            }
          }
          else {
            piVar7 = (int *)0x0;
          }
        }
        local_10 = local_10 + 2;
        local_18 = (int *)((int)local_18 + 1);
      } while (local_18 < local_c);
    }
    FUN_0804b434();
    piVar7 = (int *)&DAT_08069d90;
    piVar3 = DAT_08069d90;
    while (piVar3 != (int *)0x0) {
      if (*piVar3 == 0) {
        *piVar7 = piVar3[1];
      }
      else {
        piVar7 = piVar3 + 1;
      }
      piVar3 = (int *)*piVar7;
    }
  }
  return;
}



void FUN_08050fa4(void)

{
  bool bVar1;
  bool bVar2;
  FILE *__stream;
  char *__buf;
  int iVar3;
  int iVar4;
  int iVar5;
  size_t __n;
  int *local_1048;
  char *local_1044;
  int local_1040;
  char local_102c [4096];
  char local_2c [10];
  undefined1 local_22;
  
  local_1044 = (char *)0x0;
  local_1048 = (int *)0x0;
  __stream = FUN_08060e7c(DAT_0806aba4,"r");
  if (__stream == (FILE *)0x0) {
    FUN_0805b0d8("3Can\'t open file \'%s\'.");
  }
  FUN_0804b418();
  __n = 0x2000;
  iVar5 = 0;
  __buf = (char *)FUN_0804b3ac(0x2000);
  setvbuf(__stream,__buf,iVar5,__n);
  bVar1 = false;
  iVar5 = 0;
  bVar2 = false;
  local_1040 = 0;
  do {
    iVar3 = _IO_getc(__stream);
    if (iVar3 == -1) {
      iVar3 = 10;
      bVar2 = true;
    }
    if (bVar1) {
      if (iVar3 == 10) {
        bVar1 = false;
        goto LAB_08051093;
      }
    }
    else {
LAB_08051093:
      if (iVar3 == 0x3b) {
        bVar1 = true;
      }
      else {
        if (iVar3 == 0x5c) {
          iVar3 = _IO_getc(__stream);
          if (iVar3 != 10) {
            FUN_0805b0d8("3%s, line %lu: misplaced \'\'.");
          }
          iVar3 = 0x20;
        }
        iVar4 = isspace(iVar3);
        if ((iVar4 == 0) || (iVar5 == 8)) {
          if (iVar3 != 0x28) {
LAB_0805124a:
            if (iVar3 == 0x29) {
              if (iVar5 == 3) {
                *local_1044 = '\0';
                iVar5 = FUN_080490c0(local_102c,
                                     "3Badly formed segment base address in overlay description file."
                                    );
                local_1048[9] = iVar5;
                iVar5 = 4;
                goto LAB_080513b3;
              }
LAB_08051296:
              if (iVar5 == 8) {
                *local_1044 = '\0';
                if (local_1040 < 1) {
                  FUN_0805b0d8("3Name %s has been truncated.");
                }
                FUN_08050c1c((int)local_1048,local_2c,local_102c);
                iVar5 = 4;
                if (iVar3 == 0x2c) {
                  iVar5 = 7;
                }
                goto LAB_080513b3;
              }
              FUN_0805b0d8("3%s, line %lu: misplaced \')\' or \',\'.");
            }
            else if ((iVar3 == 0x2c) || (iVar4 = isspace(iVar3), iVar4 != 0)) goto LAB_08051296;
            iVar4 = iscntrl(iVar3);
            if (iVar4 != 0) {
              FUN_0805b0d8("3%s, line %lu: invalid character, code %d.");
            }
            if (iVar5 == 0) {
              local_1044 = local_2c;
              iVar5 = 1;
              local_1040 = 0x28;
            }
            else if (iVar5 == 4) {
              local_1044 = local_2c;
              iVar5 = 5;
              local_1040 = 0x28;
            }
            else if (iVar5 - 6U < 2) {
              local_1044 = local_102c;
              iVar5 = 8;
              local_1040 = 0x1000;
            }
            local_1040 = local_1040 + -1;
            if (0 < local_1040) {
              *local_1044 = (char)iVar3;
              local_1044 = local_1044 + 1;
            }
            goto LAB_080513b3;
          }
          if (iVar5 != 1) {
            if (iVar5 == 5) {
              *local_1044 = '\0';
              if (local_1040 < 1) {
                FUN_0805b0d8("3Name %s has been truncated.");
              }
              iVar5 = 6;
            }
            else {
              if (iVar5 != 1) {
                FUN_0805b0d8("3%s, line %lu: misplaced \'(\'.");
                goto LAB_0805124a;
              }
              *local_1044 = '\0';
              iVar5 = 3;
            }
            goto LAB_080513b3;
          }
        }
        if (iVar5 == 1) {
          *local_1044 = '\0';
          if (10 < (int)local_1044 - (int)local_2c) {
            FUN_0805b0d8("1Overlay segment name %s too long - truncated to %d characters.");
            local_22 = 0;
          }
          local_1048 = FUN_08050888(local_2c);
          *(byte *)(local_1048 + 0x1a) = *(byte *)(local_1048 + 0x1a) | 1;
          if (iVar3 == 0x28) {
            local_1044 = local_102c;
            local_1040 = 0x1000;
            iVar5 = 3;
          }
          else {
            iVar5 = 4;
          }
        }
        else if (iVar5 == 5) {
          *local_1044 = '\0';
          if (local_1040 < 1) {
            FUN_0805b0d8("3Name %s has been truncated.");
          }
          FUN_08050c60((int)local_1048,local_2c);
          iVar5 = 4;
        }
        if (iVar3 == 10) {
          if (iVar5 == 7) {
            FUN_0805b0d8("3%s, line %lu: newline in area list - use \'\' to continue line.");
          }
          iVar5 = 0;
        }
      }
    }
LAB_080513b3:
    if (bVar2) {
      iVar5 = ferror(__stream);
      if (iVar5 != 0) {
        FUN_0805b0d8("3Error reading file %s.");
      }
      FUN_08060ec8(__stream);
      FUN_0804b434();
      return;
    }
  } while( true );
}



uint FUN_08051404(uint param_1)

{
  char cVar1;
  uint uVar2;
  
  cVar1 = (char)((param_1 & 0xfff) >> 8);
  uVar2 = param_1 & 0xff;
  if ((param_1 & 0xfff) >> 8 != 0) {
    uVar2 = uVar2 << (cVar1 * -2 + 0x20U & 0x1f) | uVar2 >> cVar1 * '\x02';
  }
  return uVar2;
}



uint FUN_08051444(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = 0xc0000000;
  iVar3 = 0x18;
  uVar1 = param_1 & 0xc0000000;
  while (uVar1 == 0) {
    iVar3 = iVar3 + -2;
    uVar2 = uVar2 >> 2;
    if (iVar3 < 1) break;
    uVar1 = param_1 & uVar2;
  }
  return (0x20U - iVar3 & 0x1e) << 7 | param_1 >> ((byte)iVar3 & 0x1f) & 0xff;
}



void FUN_08051480(void)

{
  byte *pbVar1;
  uint uVar2;
  undefined4 *puVar3;
  int *piVar4;
  int extraout_EAX;
  int extraout_EAX_00;
  int iVar5;
  
  if (DAT_0806ac5c != (char *)0x0) {
    puVar3 = (undefined4 *)FUN_0804b1e8(0xc);
    DAT_08069d90 = puVar3;
    puVar3[1] = 0;
    puVar3[2] = 0;
    piVar4 = (int *)FUN_0804b1e8(0x6c);
    *puVar3 = piVar4;
    FUN_08050780(piVar4,DAT_0806ac5c,(char *)0x0);
    piVar4[0x13] = (int)puVar3;
    iVar5 = 0;
    for (puVar3 = DAT_0806ab88; puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)puVar3[2]) {
      uVar2 = puVar3[0xc];
      if ((uVar2 & 0x2200) == 0x2200) {
        if ((uVar2 & 0x20000) == 0) {
          FUN_0805b0d8("1AREA %s from object %s(%s) is not REENTRANT.");
        }
        puVar3[4] = piVar4;
      }
      else if ((*(byte *)(puVar3 + 0xd) & 8) != 0) {
        puVar3 = FUN_0804c360("SHL$$data",*puVar3,puVar3[6],puVar3[7],puVar3[9],puVar3[10],
                              (uint)CONCAT11(0x20,(char)uVar2),puVar3[0xe]);
        *(int **)(extraout_EAX + 0x10) = piVar4;
        *(byte *)(extraout_EAX + 0x35) = *(byte *)(extraout_EAX + 0x35) | 1;
        *(undefined4 *)((int)puVar3 + 0x46) = 0x302424;
        puVar3[0xc] = (uint)CONCAT11(0x10,*(undefined1 *)(puVar3 + 0xc));
        puVar3[10] = 0;
        if (iVar5 == 0) {
          *(undefined4 **)(*DAT_0806ac68 + 0xc) = puVar3;
          *(int *)(*DAT_0806ac88 + 0xc) = extraout_EAX;
          puVar3 = FUN_0804c360("$$0",*puVar3,0,4,0,0,
                                (uint)CONCAT11(0x10,*(undefined1 *)(puVar3 + 0xc)),0);
          *(int *)(extraout_EAX_00 + 0x3c) = puVar3[0xf] + -1;
        }
        iVar5 = iVar5 + puVar3[7];
      }
    }
    *(int *)(*DAT_0806ac58 + 8) = iVar5;
    if (*(int *)(*DAT_0806ac68 + 0xc) == 0) {
      pbVar1 = (byte *)(*DAT_0806ac68 + 0x10);
      *pbVar1 = *pbVar1 | 4;
      *(undefined4 *)(*DAT_0806ac68 + 8) = 0xffffffff;
    }
  }
  return;
}



undefined4 FUN_080515f4(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if ((DAT_0806abb4 == (int *)0x0) || ((*(byte *)(*DAT_0806abb4 + 0x10) & 1) == 0)) {
    uVar1 = 0;
  }
  else {
    puVar3 = (undefined4 *)(*DAT_0806abb4 + 8);
    puVar4 = (undefined4 *)(param_1 + 8);
    for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + 1;
      puVar4 = puVar4 + 1;
    }
    uVar1 = 1;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0805162c(int param_1,uint param_2)

{
  if ((0 < *(int *)(param_1 + 0x1c)) &&
     (((DAT_0806ab70._2_1_ & 8) != 0 || ((_DAT_08069d24 & param_2) == 0)))) {
    if ((param_2 & 1) != 0) {
      FUN_0805b0d8("2Can\'t default-place %s(%s): no default ROOT region.");
    }
    if ((param_2 & 2) != 0) {
      FUN_0805b0d8("2Can\'t default-place %s(%s): no default ROOT-DATA region.");
    }
    _DAT_08069d24 = _DAT_08069d24 | param_2;
  }
  return;
}



void FUN_080516a8(int param_1)

{
  undefined *puVar1;
  undefined *puVar2;
  uint uVar3;
  
  puVar1 = PTR_DAT_08068878;
  puVar2 = puVar1;
  if (((DAT_0806ab68._1_1_ & 0x10) != 0) && (-1 < *(short *)(param_1 + 0x30))) {
    if (((char)DAT_0806ab70 < '\0') &&
       (((*(byte *)(param_1 + 0x31) & 0x20) == 0 && (*(int *)(PTR_DAT_08068878 + 100) != 0)))) {
      puVar2 = *(undefined **)(*(int *)(PTR_DAT_08068878 + 100) + 4);
      if ((puVar2 != (undefined *)0x0) || (puVar2 = puVar1, (DAT_08069d24 & 2) != 0))
      goto LAB_08051712;
      uVar3 = 2;
    }
    else {
      if ((*(int *)(PTR_DAT_08068878 + 100) != 0) || ((DAT_08069d24 & 1) != 0)) goto LAB_08051712;
      uVar3 = 1;
    }
    FUN_0805162c(param_1,uVar3);
    puVar2 = puVar1;
  }
LAB_08051712:
  *(undefined **)(param_1 + 0x10) = puVar2;
  return;
}



void FUN_0805171c(void)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  
  piVar3 = (int *)&DAT_0806ab88;
  piVar2 = DAT_0806ab88;
  do {
    while( true ) {
      if (piVar2 == (int *)0x0) {
        return;
      }
      piVar1 = (int *)piVar2[2];
      if (*piVar2 != 0) break;
      if (piVar2[4] == 0) {
        FUN_080516a8((int)piVar2);
        break;
      }
LAB_08051773:
      *piVar3 = piVar2[2];
      **(undefined4 **)piVar2[4] = piVar2;
      *(int **)piVar2[4] = piVar2 + 2;
      piVar2[2] = 0;
      *(int *)(piVar2[4] + 0x38) = *(int *)(piVar2[4] + 0x38) + 1;
      piVar2 = piVar1;
    }
    if (piVar2[4] != 0) goto LAB_08051773;
    if ((((*(byte *)(*(int *)(*piVar2 + 8) + 4) & 2) == 0) ||
        ((*(byte *)((int)piVar2 + 0x31) & 2) == 0)) || (piVar2[3] == 0)) {
      FUN_080516a8((int)piVar2);
      goto LAB_08051773;
    }
    piVar3 = piVar2 + 2;
    piVar2 = piVar1;
  } while( true );
}



void FUN_080517a8(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  bool bVar6;
  bool bVar7;
  int iVar8;
  undefined4 *local_10;
  
  iVar8 = DAT_0806ab88;
  if (((byte)DAT_0806ab70 & 0x10) == 0) {
    do {
      local_10 = &DAT_0806ab88;
      bVar7 = false;
      iVar8 = DAT_0806ab88;
      while (iVar8 != 0) {
        iVar1 = *(int *)(iVar8 + 8);
        piVar2 = *(int **)(iVar8 + 0xc);
        bVar6 = false;
        iVar3 = *piVar2;
        iVar4 = *(int *)(iVar3 + 0x10);
        iVar5 = iVar4;
        while (iVar5 != 0) {
          if (*(int *)(iVar3 + 0x10) != iVar4) {
            bVar6 = true;
          }
          piVar2 = (int *)piVar2[1];
          if (piVar2 == (int *)0x0) goto LAB_08051811;
          iVar3 = *piVar2;
          iVar5 = *(int *)(iVar3 + 0x10);
        }
        if (piVar2 == (int *)0x0) {
LAB_08051811:
          *(int *)(iVar8 + 0x10) = iVar4;
          if (bVar6) {
            *(undefined **)(iVar8 + 0x10) = PTR_DAT_08068878;
          }
          bVar7 = true;
          *local_10 = *(undefined4 *)(iVar8 + 8);
          *(int *)**(undefined4 **)(iVar8 + 0x10) = iVar8;
          **(int **)(iVar8 + 0x10) = iVar8 + 8;
          *(undefined4 *)(iVar8 + 8) = 0;
          piVar2 = (int *)(*(int *)(iVar8 + 0x10) + 0x38);
          *piVar2 = *piVar2 + 1;
          iVar8 = iVar1;
        }
        else {
          local_10 = (undefined4 *)(iVar8 + 8);
          iVar8 = iVar1;
        }
      }
      iVar8 = DAT_0806ab88;
    } while (bVar7);
  }
  while (iVar8 != 0) {
    DAT_0806ab88 = *(int *)(iVar8 + 8);
    *(undefined4 *)(iVar8 + 8) = 0;
    FUN_080516a8(iVar8);
    *(int *)**(undefined4 **)(iVar8 + 0x10) = iVar8;
    **(int **)(iVar8 + 0x10) = iVar8 + 8;
    piVar2 = (int *)(*(int *)(iVar8 + 0x10) + 0x38);
    *piVar2 = *piVar2 + 1;
    iVar8 = DAT_0806ab88;
  }
  DAT_0806ab88 = iVar8;
  return;
}



undefined4 FUN_080518b8(char *param_1,char *param_2,int param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  for (puVar1 = DAT_0806abd4; puVar2 = DAT_0806aba8, puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)*puVar1) {
    iVar3 = strcmp((char *)puVar1[1],param_1);
    if (iVar3 == 0) {
      return 1;
    }
  }
  while( true ) {
    if (puVar2 == (undefined4 *)0x0) {
      return 0;
    }
    iVar3 = strcmp((char *)puVar2[1],param_2);
    if ((iVar3 == 0) ||
       ((param_3 != 0 && (iVar3 = strcmp((char *)puVar2[1],(char *)(param_3 + 6)), iVar3 == 0))))
    break;
    puVar2 = (undefined4 *)*puVar2;
  }
  return 1;
}



void FUN_08051934(int param_1,int param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xc);
  while( true ) {
    if (piVar2 == (int *)0x0) {
      if (((DAT_0806ab70 & 0x3000) != 0) &&
         (((DAT_0806ab70 & 0x1000) != 0 ||
          (iVar1 = FUN_080518b8((char *)(param_1 + 0x46),(char *)(param_2 + 0x46),param_3),
          iVar1 != 0)))) {
        if (param_3 == 0) {
          FUN_0805af4c("%s(%s) refers to %s(%s)\n");
        }
        else {
          FUN_0805af4c("%s(%s) refers to %s(%s) for %s\n");
        }
      }
      piVar2 = (int *)FUN_0804b1e8(8);
      *piVar2 = param_2;
      piVar2[1] = *(int *)(param_1 + 0xc);
      *(int **)(param_1 + 0xc) = piVar2;
      return;
    }
    if (*piVar2 == param_2) break;
    piVar2 = (int *)piVar2[1];
  }
  return;
}



void FUN_08051a24(int *param_1)

{
  size_t sVar1;
  int *piVar2;
  uint *puVar3;
  uint *puVar4;
  uint uVar5;
  int *piVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  uint *puVar11;
  undefined1 *local_24;
  uint local_20;
  uint local_18;
  uint local_14;
  int local_8;
  
  local_24 = (undefined1 *)0x0;
  if ((param_1[10] != 0) &&
     ((((byte)DAT_0806ab68 & 0x10) == 0 || ((*(byte *)((int)param_1 + 0x31) & 2) == 0)))) {
    FUN_0804bc68(*param_1);
    sVar1 = param_1[7];
    puVar3 = (uint *)FUN_0804bd58(param_1[9],param_1[10] * 8);
    puVar4 = puVar3 + param_1[10] * 2;
    for (; puVar3 < puVar4; puVar3 = puVar3 + 2) {
      local_20 = FUN_0805e13c(*puVar3);
      uVar5 = FUN_0805e13c(puVar3[1]);
      if (uVar5 >> 0x18 != 0xf0) {
        local_18 = 0;
        if ((int)uVar5 < 0) {
          uVar9 = uVar5 & 0xffffff;
          local_14 = uVar5 >> 0x18 & 3;
          uVar7 = uVar5 >> 0x1b & 1;
          if (((*(byte *)(param_1 + 0xd) & 4) != 0) && ((uVar5 >> 0x1a & 1) != 0)) {
            local_14 = 3;
          }
          if (local_14 == 3) {
            local_18 = local_20 & 1;
            local_20 = local_20 & 0xfffffffe;
          }
        }
        else {
          uVar9 = uVar5 & 0xffff;
          local_14 = uVar5 >> 0x10 & 3;
          uVar7 = uVar5 >> 0x13 & 1;
          if ((uVar5 & 0x40000) != 0) {
            uVar7 = 1;
            local_14 = 3;
          }
          if (uVar7 == 0) {
            uVar9 = param_1[0xe];
          }
        }
        if ((local_18 != 0) && ((DAT_0806ab70 & 0x420) == 0x400)) {
          DAT_0806a078 = DAT_0806a078 + 1;
        }
        if ((int)sVar1 <= (int)local_20) {
          FUN_0805b0d8("3Input file %s corrupt.");
        }
        if (uVar7 == 0) {
          iVar8 = *(int *)(*(int *)(*param_1 + 0x28) + uVar9 * 4);
        }
        else {
          piVar2 = *(int **)(*(int *)(*param_1 + 0x20) + uVar9 * 4);
          iVar10 = *piVar2;
          local_8 = iVar10 + 8;
          iVar8 = 0;
          uVar5 = *(uint *)(iVar10 + 0x10);
          if (((uVar5 & 0x11) == 0) && (DAT_0806abb4 != (int *)0x0)) {
            iVar10 = *DAT_0806abb4;
            local_8 = iVar10 + 8;
            uVar5 = *(uint *)(iVar10 + 0x10);
          }
          if (((uVar5 & 0x20) != 0) && (*(int **)(local_8 + 4) == param_1)) {
            *(undefined1 *)(piVar2 + 1) = 0x20;
            piVar6 = FUN_0804b030((char *)(piVar2 + 1),DAT_0806ab74);
            if (piVar6 != (int *)0x0) {
              iVar10 = *piVar6;
              local_8 = iVar10 + 8;
            }
            *(undefined1 *)(piVar2 + 1) = 0x21;
            uVar5 = *(uint *)(local_8 + 8);
          }
          if ((uVar5 & 1) != 0) {
            if (local_14 == 3) {
              if ((uVar5 & 0x1000) == 0) {
                if (local_18 != 0) goto LAB_08051c42;
              }
              else if (local_18 != 1) {
LAB_08051c42:
                piVar6 = (int *)FUN_0804b0dc((int)piVar2);
                if ((piVar6 == (int *)0x0) ||
                   (iVar8 = strcmp((char *)(piVar2 + 1),(char *)(piVar6 + 1)), iVar8 != 0)) {
                  if ((*(int *)(local_8 + 4) != 0) &&
                     (((*(byte *)(*(int *)(local_8 + 4) + 0x32) & 0x40) != 0 &&
                      (*(int *)(iVar10 + 4) == -1)))) {
                    *(undefined4 *)(iVar10 + 4) = 0;
                    if (local_24 == (undefined1 *)0x0) {
                      local_24 = FUN_0804bd58(param_1[6],sVar1);
                    }
                    puVar11 = (uint *)(local_24 + local_20);
                    if (local_18 == 0) {
                      uVar5 = FUN_0805e13c(*puVar11);
                      if ((uVar5 & 0xfe000000) != 0xfa000000) {
                        DAT_0806a120 = DAT_0806a120 + 1;
                      }
                    }
                    else {
                      uVar5 = FUN_0805e174((uint)(ushort)*puVar11);
                      uVar9 = FUN_0805e174((uint)*(ushort *)((int)puVar11 + 2));
                      if (((uVar5 & 0xf800) == 0xf000) && ((uVar9 & 0xf800) == 0xf800)) {
                        DAT_0806a124 = DAT_0806a124 + 1;
                      }
                    }
                  }
                }
                else {
                  local_8 = *piVar6 + 8;
                }
              }
            }
            iVar8 = *(int *)(local_8 + 4);
          }
        }
        if ((((iVar8 != 0) && ((DAT_0806ab70 & 0x420) == 0x400)) && (-1 < (short)param_1[0xc])) &&
           (((*(byte *)(iVar8 + 0x31) & 2) != 0 && (local_14 == 2)))) {
          DAT_0806a078 = DAT_0806a078 + 1;
        }
      }
    }
  }
  return;
}



void FUN_08051d7c(int *param_1)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  uint uVar10;
  int *piVar11;
  int iVar12;
  uint local_1c;
  uint local_14;
  uint local_10;
  
  if ((param_1[10] != 0) &&
     ((((byte)DAT_0806ab68 & 0x10) == 0 || ((*(byte *)((int)param_1 + 0x31) & 2) == 0)))) {
    FUN_0804bc68(*param_1);
    iVar1 = param_1[7];
    puVar2 = (uint *)FUN_0804bd58(param_1[9],param_1[10] * 8);
    puVar3 = puVar2 + param_1[10] * 2;
    for (; puVar2 < puVar3; puVar2 = puVar2 + 2) {
      uVar4 = FUN_0805e13c(*puVar2);
      uVar5 = FUN_0805e13c(puVar2[1]);
      local_14 = 0;
      if ((int)uVar5 < 0) {
        uVar10 = uVar5 & 0xffffff;
        local_10 = uVar5 >> 0x18 & 3;
        uVar8 = uVar5 >> 0x1b & 1;
        if (((*(byte *)(param_1 + 0xd) & 4) != 0) && ((uVar5 >> 0x1a & 1) != 0)) {
          local_10 = 3;
        }
        if (local_10 == 3) {
          local_14 = uVar4 & 1;
          uVar4 = uVar4 & 0xfffffffe;
        }
      }
      else {
        uVar10 = uVar5 & 0xffff;
        local_10 = uVar5 >> 0x10 & 3;
        uVar8 = uVar5 >> 0x13 & 1;
        if ((uVar5 & 0x40000) != 0) {
          uVar8 = 1;
          local_10 = 3;
        }
        if (uVar8 == 0) {
          uVar10 = param_1[0xe];
        }
      }
      if (iVar1 <= (int)uVar4) {
        FUN_0805b0d8("3Input file %s corrupt.");
      }
      if (uVar8 == 0) {
        piVar9 = *(int **)(*(int *)(*param_1 + 0x28) + uVar10 * 4);
        piVar11 = (int *)0x0;
      }
      else {
        piVar11 = *(int **)(*(int *)(*param_1 + 0x20) + uVar10 * 4);
        iVar12 = *piVar11 + 8;
        piVar9 = (int *)0x0;
        local_1c = *(uint *)(*piVar11 + 0x10);
        if (((local_1c & 1) == 0) && (DAT_0806abb4 != (int *)0x0)) {
          iVar12 = *DAT_0806abb4 + 8;
          local_1c = *(uint *)(*DAT_0806abb4 + 0x10);
        }
        if (((local_1c & 0x20) != 0) && (*(int **)(iVar12 + 4) == param_1)) {
          *(undefined1 *)(piVar11 + 1) = 0x20;
          piVar6 = FUN_0804b030((char *)(piVar11 + 1),DAT_0806ab74);
          if (piVar6 != (int *)0x0) {
            iVar12 = *piVar6 + 8;
          }
          *(undefined1 *)(piVar11 + 1) = 0x21;
          local_1c = *(uint *)(iVar12 + 8);
        }
        if ((local_1c & 1) != 0) {
          if (local_10 == 3) {
            if ((local_1c & 0x1000) == 0) {
              if (local_14 != 0) goto LAB_08051f4a;
            }
            else if (local_14 != 1) {
LAB_08051f4a:
              piVar9 = (int *)FUN_0804b0dc((int)piVar11);
              if ((piVar9 != (int *)0x0) &&
                 (iVar7 = strcmp((char *)(piVar11 + 1),(char *)(piVar9 + 1)), iVar7 == 0)) {
                iVar12 = *piVar9 + 8;
                piVar11 = piVar9;
              }
            }
          }
          piVar9 = *(int **)(iVar12 + 4);
        }
      }
      if ((piVar9 != (int *)0x0) && (piVar9 != param_1)) {
        FUN_08051934((int)param_1,(int)piVar9,(int)piVar11);
      }
    }
  }
  return;
}



void FUN_08051fbc(int param_1)

{
  int *piVar1;
  
  if (param_1 != 0) {
    *(byte *)(param_1 + 0x34) = *(byte *)(param_1 + 0x34) | 0x20;
    for (piVar1 = *(int **)(param_1 + 0xc); piVar1 != (int *)0x0; piVar1 = (int *)piVar1[1]) {
      if ((*(byte *)(*piVar1 + 0x34) & 0x20) == 0) {
        FUN_08051fbc(*piVar1);
      }
    }
  }
  return;
}



void FUN_08051ff0(void)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int *piVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  uint uVar7;
  int *piVar8;
  uint uVar9;
  uint uVar10;
  int local_1c;
  int *local_c;
  
  if (DAT_0806ab7c != 0) {
    FUN_08051fbc(DAT_0806ab7c);
  }
  local_c = (int *)&DAT_0806ab88;
  piVar1 = DAT_0806ab88;
  while (piVar4 = piVar1, piVar4 != (int *)0x0) {
    piVar1 = (int *)piVar4[2];
    if (((*(byte *)(piVar4 + 0xd) & 0x20) == 0) && (-1 < (short)piVar4[0xc])) {
      if (((DAT_0806ab6c & 0x10) != 0) && (0 < piVar4[7])) {
        if (*piVar4 == 0) {
          FUN_0805b0d8("0Unreferenced AREA (%s) omitted from output.");
        }
        else {
          FUN_0805b0d8("0Unreferenced AREA %s(%s) (file %s) omitted from output.");
        }
      }
      DAT_08069db8 = DAT_08069db8 + piVar4[7];
      *(byte *)(piVar4 + 0xd) = *(byte *)(piVar4 + 0xd) | 0x40;
      *local_c = (int)piVar1;
    }
    else {
      local_c = piVar4 + 2;
      if (0 < piVar4[10]) {
        FUN_0804bc68(*piVar4);
        puVar5 = FUN_0804bd58(piVar4[9],piVar4[10] * 8);
        puVar6 = puVar5 + piVar4[10] * 8;
        for (; puVar5 < puVar6; puVar5 = puVar5 + 8) {
          uVar7 = FUN_0805e13c(*(uint *)(puVar5 + 4));
          if ((int)uVar7 < 0) {
            uVar9 = uVar7 & 0xffffff;
            uVar10 = uVar7 >> 0x1b & 1;
          }
          else {
            uVar9 = uVar7 & 0xffff;
            uVar10 = 0;
            if (((uVar7 & 0x40000) != 0) || ((uVar7 & 0x80000) != 0)) {
              uVar10 = 1;
            }
          }
          if (uVar10 != 0) {
            piVar2 = *(int **)(*(int *)(*piVar4 + 0x20) + uVar9 * 4);
            iVar3 = *piVar2;
            local_1c = iVar3 + 8;
            uVar7 = *(uint *)(iVar3 + 0x10);
            if (((uVar7 & 0x20) != 0) && (*(int **)(iVar3 + 0xc) == piVar4)) {
              *(undefined1 *)(piVar2 + 1) = 0x20;
              piVar8 = FUN_0804b030((char *)(piVar2 + 1),DAT_0806ab74);
              if (piVar8 != (int *)0x0) {
                local_1c = *piVar8 + 8;
              }
              *(undefined1 *)(piVar2 + 1) = 0x21;
              uVar7 = *(uint *)(local_1c + 8);
            }
            *(uint *)(local_1c + 8) = uVar7 | 0x20000000;
          }
        }
      }
    }
  }
  DAT_0806ab84 = local_c;
  return;
}



uint FUN_080521a4(int param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = 4;
  uVar1 = param_2 & 0x1f;
  if (((byte)DAT_0806ab68 & 4) == 0) {
    while (uVar1 = uVar1 - 1, 1 < (int)uVar1) {
      iVar2 = iVar2 * 2;
    }
  }
  return param_1 + (iVar2 - 1U) & ~(iVar2 - 1U);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_080521d4(undefined *param_1,uint param_2)

{
  byte *pbVar1;
  uint uVar2;
  int *piVar3;
  bool bVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  int *piVar10;
  char *pcVar11;
  int iVar12;
  undefined4 uVar13;
  char *pcVar14;
  int local_90;
  short local_88;
  int local_84;
  int local_80;
  int local_7c;
  short local_78;
  int local_74;
  uint local_70;
  int local_6c;
  uint local_68;
  uint local_64;
  uint local_60;
  int local_5c;
  int local_58;
  int local_54;
  int *local_48;
  char local_44 [64];
  
  local_48 = (int *)FUN_0804b1e8(*(int *)(param_1 + 0x38) * 4);
  *(int **)(param_1 + 0xc) = local_48;
  DAT_08069dd4 = (undefined4 *)(param_1 + 8);
  for (iVar12 = *(int *)(param_1 + 4); iVar12 != 0; iVar12 = *(int *)(iVar12 + 8)) {
    pcVar11 = (char *)(iVar12 + 0x46);
    if (((DAT_0806ab68 & 0x10) == 0) || (param_1 != PTR_DAT_08068878)) {
      if ((DAT_0806ab64 == 4) &&
         (((param_1 == PTR_DAT_08068878 && ((*(uint *)(iVar12 + 0x30) & 0x100200) == 0x100000)) &&
          ((DAT_0806ab68 & 0x20) != 0)))) {
        pcVar11 = "sb$$interLUdata";
      }
LAB_080522fe:
      FUN_080502d8((int)param_1,iVar12,pcVar11);
      *local_48 = iVar12;
      local_48 = local_48 + 1;
    }
    else {
      uVar2 = *(uint *)(iVar12 + 0x30);
      if ((uVar2 & 0x100200) == 0x100000) {
        pcVar11 = "sb$$interLUdata";
        *(uint *)(iVar12 + 0x30) = uVar2 & 0xffffdfff;
        goto LAB_080522fe;
      }
      if ((uVar2 & 0x200200) != 0x200000) {
        if ((uVar2 & 0x200) == 0) {
          if ((uVar2 & 0x1000) == 0) {
            pcVar11 = "$$data";
          }
          else {
            pcVar11 = "$$zidata";
          }
          pcVar11 = FUN_0804b950((char *)0x0,DAT_0806ac64,pcVar11);
          *(byte *)(iVar12 + 0x32) = *(byte *)(iVar12 + 0x32) | 0x20;
        }
        goto LAB_080522fe;
      }
      pcVar14 = "!!";
      uVar13 = 0x1000002;
      pcVar11 = FUN_0804b950((char *)0x0,pcVar11,"$$Base");
      uVar13 = FUN_0804c234(pcVar11,uVar13,pcVar14);
      *(undefined4 *)(iVar12 + 4) = uVar13;
      *(byte *)(iVar12 + 0x34) = *(byte *)(iVar12 + 0x34) | 0x80;
      *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    }
  }
  piVar3 = *(int **)(param_1 + 0xc);
  FUN_0805008c((int)piVar3,*(int *)(param_1 + 0x38));
  bVar4 = false;
  local_60 = 0;
  local_5c = 0;
  local_58 = 0;
  local_54 = 0;
  local_64 = param_2;
  for (piVar10 = piVar3; piVar10 < local_48; piVar10 = piVar10 + 1) {
    uVar2 = *(uint *)(*piVar10 + 0x30);
    iVar12 = *(int *)(*piVar10 + 0x1c);
    if (((uVar2 & 0x2000) == 0) && (!bVar4)) {
      if (((char)DAT_0806ab70 < '\0') && (param_1 == PTR_DAT_08068878)) {
        local_64 = DAT_0806abdc;
      }
      bVar4 = true;
    }
    uVar5 = FUN_080521a4(local_64,uVar2);
    iVar12 = (iVar12 + 3U & 0xfffffffc) + (uVar5 - local_64);
    local_64 = local_64 + iVar12;
    local_78 = (short)uVar2;
    if (local_78 < 0) {
      local_54 = local_54 + iVar12;
    }
    else if ((uVar2 & 0x1000) == 0) {
      if ((uVar2 & 0x2000) == 0) {
        local_5c = local_5c + iVar12;
      }
      else {
        local_60 = local_60 + iVar12;
      }
    }
    else {
      local_58 = local_58 + iVar12;
    }
  }
  local_74 = 0;
  if (0 < DAT_0806a08c) {
    if (param_1 == PTR_DAT_0806887c) {
      iVar12 = 0;
      for (piVar10 = DAT_08069d90; piVar10 != (int *)0x0; piVar10 = (int *)piVar10[1]) {
        iVar6 = *piVar10;
        if (iVar6 != 0) {
          do {
            iVar12 = iVar12 + piVar10[2];
            iVar6 = *(int *)(iVar6 + 0x54);
          } while (iVar6 != 0);
        }
      }
      local_74 = DAT_0806a08c * 0x24 + _DAT_0806a090 * 4 + iVar12 * 4;
      uVar2 = DAT_0806abdc;
      if (-1 < (char)DAT_0806ab70) {
        uVar2 = param_2 + local_60;
      }
      DAT_08069d80 = local_5c + uVar2;
      if (*(int *)(param_1 + 100) != 0) {
        *(int *)(*(int *)(param_1 + 100) + 0x14) = local_74;
      }
    }
    else if ((param_1[0x68] & 1) != 0) {
      local_74 = *(int *)(param_1 + 0x28) * 4;
      *(int *)(param_1 + 0x40) = DAT_08069d80;
      DAT_08069d80 = DAT_08069d80 + local_74 + 0x24 + *(int *)(*(int *)(param_1 + 0x4c) + 8) * 4;
    }
    local_5c = local_5c + local_74;
  }
  local_68 = param_2;
  local_70 = local_60 + local_5c + local_58;
  if ((DAT_0806ab68 & 4) != 0) {
    if ((DAT_0806ab68 & 0x10) == 0) {
      local_68 = local_60;
    }
    local_6c = local_68 + local_5c;
    goto LAB_080525d3;
  }
  if (((char)DAT_0806ab70 < '\0') && (param_1 == PTR_DAT_08068878)) {
    local_68 = DAT_0806abdc;
  }
  else {
    local_68 = param_2 + local_60;
  }
  local_6c = local_68 + local_5c;
  if (-1 < (char)DAT_0806ab70) goto LAB_080525d3;
  if (local_68 < param_2) {
LAB_0805258f:
    if (param_2 < (uint)(local_6c + local_58)) {
LAB_0805259a:
      FUN_0805b0d8("2Data based at %lx overlaps code based at %lx.");
    }
  }
  else {
    if (local_68 < param_2 + local_60) goto LAB_0805259a;
    if (local_68 < param_2) goto LAB_0805258f;
  }
  if (((char)DAT_0806ab70 < '\0') && (param_1 == PTR_DAT_08068878)) {
    local_74 = 0;
    local_70 = local_60;
  }
LAB_080525d3:
  local_7c = 0;
  local_80 = 0;
  local_84 = 0;
  *(uint *)(param_1 + 0x2c) = param_2;
  *(uint *)(param_1 + 0x30) = local_68;
  *(int *)(param_1 + 0x34) = local_6c;
  *(uint *)(param_1 + 0x44) = param_2;
  piVar10 = piVar3;
  local_64 = param_2;
  do {
    if (local_48 <= piVar10) {
      *DAT_08069dd4 = 0;
      iVar12 = *(int *)(param_1 + 0x3c);
      if ((DAT_0806ab68 & 0x10) != 0) {
        iVar12 = iVar12 + 1;
      }
      piVar10 = (int *)FUN_0804b1e8(iVar12 << 2);
      *(int **)(param_1 + 0x10) = piVar10;
      for (iVar12 = *(int *)(param_1 + 8); iVar12 != 0; iVar12 = *(int *)(iVar12 + 8)) {
        *piVar10 = iVar12;
        piVar10 = piVar10 + 1;
        if ((DAT_0806ab68 & 4) == 0) {
          FUN_0804c2e8(iVar12,(char *)(iVar12 + 0x46),*(int *)(iVar12 + 0x2c),
                       *(int *)(iVar12 + 0x1c) + *(int *)(iVar12 + 0x2c),-1);
        }
        else if ((((DAT_0806ab68 & 0x10) != 0) && (param_1 == PTR_DAT_08068878)) &&
                (iVar6 = strcmp((char *)(*(int *)(iVar12 + 4) + 4),"sb$$interLUdata"), iVar6 == 0))
        {
          iVar6 = *DAT_0806ac60;
          pbVar1 = (byte *)(iVar6 + 0x10);
          *pbVar1 = *pbVar1 | 5;
          *(int *)(iVar6 + 8) = *(int *)(iVar12 + 0x1c) - DAT_08068920;
        }
      }
      FUN_0805008c(*(int *)(param_1 + 0x10),*(int *)(param_1 + 0x3c));
      iVar12 = *(int *)(param_1 + 0x3c) + -1;
      if (-1 < iVar12) {
        piVar10 = (int *)(*(int *)(param_1 + 0x10) + iVar12 * 4);
        do {
          *(int *)(*piVar10 + 0x38) = iVar12;
          piVar10 = piVar10 + -1;
          iVar12 = iVar12 + -1;
        } while (-1 < iVar12);
      }
      *(uint *)(param_1 + 0x14) = local_60;
      *(int *)(param_1 + 0x18) = local_5c;
      *(int *)(param_1 + 0x1c) = local_58;
      *(int *)(param_1 + 0x20) = local_54;
      *(uint *)(param_1 + 0x48) = (local_70 + *(int *)(param_1 + 0x44)) - local_74;
      return local_70;
    }
    iVar12 = *piVar10;
    uVar2 = *(uint *)(iVar12 + 0x30);
    uVar5 = *(int *)(iVar12 + 0x1c) + 3U & 0xfffffffc;
    if ((*(uint *)(iVar12 + 0x34) & 3) != 0) {
      if (((*(uint *)(iVar12 + 0x34) & 1) == 0) || (local_48 <= piVar10 + 1)) {
LAB_08052679:
        if (((*(byte *)(iVar12 + 0x34) & 2) != 0) && (piVar3 < piVar10)) {
          iVar6 = FUN_0804ffac(*(uint *)(piVar10[-1] + 0x30) & 0xb000,0);
          iVar7 = FUN_0804ffac(*(uint *)(iVar12 + 0x30) & 0xb000,0);
          if (iVar7 < iVar6) goto LAB_080526be;
        }
      }
      else {
        iVar6 = FUN_0804ffac(uVar2 & 0xb000,0);
        iVar7 = FUN_0804ffac(*(uint *)(piVar10[1] + 0x30) & 0xb000,0);
        if (iVar6 <= iVar7) goto LAB_08052679;
LAB_080526be:
        if ((*(byte *)(iVar12 + 0x34) & 1) == 0) {
          iVar6 = piVar10[-1];
        }
        else {
          iVar6 = piVar10[1];
        }
        FUN_0804be34(local_44,0x40,(*(uint *)(iVar12 + 0x30) ^ *(uint *)(iVar6 + 0x30)) & 0xb000,
                     *(uint *)(iVar12 + 0x30) & 0x200);
        FUN_0805b0d8(
                    "2Attributes of -FIRST/LAST AREA incompatible with neighbouring %s(%s)\n    (missing/extra attributes are {%s})."
                    );
      }
    }
    iVar6 = *(int *)(iVar12 + 0x2c);
    piVar10 = piVar10 + 1;
    if ((uVar2 & 0x1000) == 0) {
      local_88 = (short)uVar2;
      if (local_88 < 0) {
        if (*(int *)(iVar12 + 4) != local_7c) {
          if ((DAT_0806ab68 & 4) == 0) {
            iVar7 = local_84;
            pcVar11 = FUN_0804b950("!!",(char *)(iVar12 + 0x46),"$$DbgOffset");
            FUN_0804c270(iVar12,pcVar11,iVar7);
          }
          local_80 = 0;
        }
        uVar8 = FUN_080521a4(local_80,uVar2);
        *(uint *)(iVar12 + 0x2c) = uVar8;
        *(uint *)(iVar12 + 0x20) = uVar8 - local_80;
        local_90 = uVar5 + (uVar8 - local_80);
        local_80 = local_80 + local_90;
        local_84 = local_84 + local_90;
        local_7c = *(int *)(iVar12 + 4);
      }
      else if ((uVar2 & 0x2000) == 0) {
        uVar8 = FUN_080521a4(local_68,uVar2);
        *(uint *)(iVar12 + 0x2c) = uVar8;
        *(uint *)(iVar12 + 0x20) = uVar8 - local_68;
        local_90 = uVar5 + (uVar8 - local_68);
        local_68 = local_68 + local_90;
      }
      else {
        uVar8 = FUN_080521a4(local_64,uVar2);
        *(uint *)(iVar12 + 0x2c) = uVar8;
        *(uint *)(iVar12 + 0x20) = uVar8 - local_64;
        local_90 = uVar5 + (uVar8 - local_64);
        local_64 = local_64 + local_90;
      }
    }
    else {
      uVar8 = FUN_080521a4(local_6c,uVar2);
      *(uint *)(iVar12 + 0x2c) = uVar8;
      *(uint *)(iVar12 + 0x20) = uVar8 - local_6c;
      local_90 = uVar5 + (uVar8 - local_6c);
      local_6c = local_6c + local_90;
    }
    if (((uVar2 & 0x100) != 0) && (iVar6 != *(int *)(iVar12 + 0x2c))) {
      FUN_0805b0d8("3Absolute AREA %s based at %x has been placed at %x.");
    }
    piVar9 = *(int **)(iVar12 + 4);
    if (*(int *)(*piVar9 + 0x2c) == -1) {
      *(undefined4 *)(*piVar9 + 0x2c) = *(undefined4 *)(iVar12 + 0x2c);
      piVar9 = *(int **)(iVar12 + 4);
    }
    if (iVar12 == DAT_0806ab7c) {
      DAT_08069db4 = *piVar9;
      DAT_08069db0 = (*(int *)(iVar12 + 0x2c) + DAT_0806abbc) - *(int *)(DAT_08069db4 + 0x2c);
      piVar9 = *(int **)(iVar12 + 4);
    }
    *(int *)(*piVar9 + 0x1c) = *(int *)(*piVar9 + 0x1c) + local_90;
  } while( true );
}



void FUN_080529b8(void)

{
  char *pcVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  char cVar5;
  int *piVar6;
  int iVar7;
  char *pcVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  char *pcVar11;
  uint uVar12;
  int local_1010;
  int local_1008;
  char local_1004 [4096];
  
  bVar4 = DAT_0806ab6f;
  local_1010 = 0;
  if (((byte)DAT_0806ab68 & 4) == 0) {
    piVar6 = (int *)FUN_0804b134(&local_1008);
    while (piVar6 != (int *)0x0) {
      iVar2 = *piVar6;
      if ((*(byte *)(iVar2 + 0x10) & 1) == 0) {
        iVar7 = *(int *)(iVar2 + 8);
        local_1004[0] = (char)piVar6[1];
        local_1004[1] = *(undefined1 *)((int)piVar6 + 5);
        pcVar1 = (char *)((int)piVar6 + 6);
        local_1004[2] = 0;
        cVar5 = *(char *)((int)piVar6 + 6);
        if (cVar5 == '@') {
          if ((bVar4 & 0x40) != 0) {
            uVar12 = 0xffe;
            pcVar8 = local_1004 + 2;
            pcVar11 = (char *)((int)piVar6 + 7);
            goto LAB_08052b32;
          }
        }
        else {
          pcVar8 = pcVar1;
          if (cVar5 == '_') {
            if ((bVar4 & 1) != 0) {
              uVar12 = 0xffe;
              pcVar8 = local_1004 + 2;
              pcVar11 = (char *)((int)piVar6 + 7);
LAB_08052b32:
              FUN_0804b710(pcVar8,pcVar11,uVar12);
            }
          }
          else {
            while (cVar5 != '\0') {
              if (cVar5 == '_') {
                FUN_0804b710(local_1004,(char *)(piVar6 + 1),0x1000);
                cVar5 = pcVar8[1];
                if (((cVar5 == '_') && ((bVar4 & 8) != 0)) &&
                   (pcVar8 + (-4 - (int)piVar6) < (char *)0x1000)) {
                  local_1004[(int)(pcVar8 + (-4 - (int)piVar6))] = '\0';
                  cVar5 = pcVar8[1];
                }
                if (((cVar5 != '_') && ((bVar4 & 4) != 0)) &&
                   (pcVar8 + (-4 - (int)piVar6) < (char *)0x1000)) {
                  local_1004[(int)(pcVar8 + (-4 - (int)piVar6))] = '.';
                }
                goto LAB_08052b3b;
              }
              pcVar8 = pcVar8 + 1;
              cVar5 = *pcVar8;
            }
            if ((bVar4 & 2) != 0) {
              local_1004[2] = 0x5f;
              uVar12 = 0xffd;
              pcVar8 = local_1004 + 3;
              pcVar11 = pcVar1;
              goto LAB_08052b32;
            }
          }
        }
LAB_08052b3b:
        piVar6 = FUN_0804b030(local_1004,DAT_0806ab74);
        if ((piVar6 == (int *)0x0) || ((*(byte *)(*piVar6 + 0x10) & 1) == 0)) {
          piVar6 = FUN_0804b030(pcVar1,DAT_0806ab80);
          if (piVar6 == (int *)0x0) {
            if ((iVar7 != 0) && ((*(byte *)(iVar2 + 0x10) & 0x10) == 0)) {
              *(undefined4 *)(iVar2 + 0x10) = 3;
              if (iVar7 < 3) {
                if (iVar7 == 2) {
                  uVar12 = 1;
                }
                else {
                  uVar12 = 0;
                }
              }
              else {
                uVar12 = 3;
              }
              uVar12 = local_1010 + uVar12 & ~uVar12;
              *(uint *)(iVar2 + 8) = uVar12;
              local_1010 = uVar12 + iVar7;
            }
          }
          else {
            iVar3 = *piVar6;
            if (*(int *)(iVar3 + 0x1c) < iVar7) {
              if ((*(byte *)(iVar3 + 0x31) & 0x10) == 0) {
                FUN_0805b0d8("1COMMON symbol %s is larger than COMMON AREA %s (in object %s).");
              }
              else {
                *(int *)(iVar3 + 0x1c) = iVar7;
              }
            }
            *(undefined4 *)(iVar2 + 0x10) = 3;
            *(int *)(iVar2 + 0xc) = iVar3;
            *(undefined4 *)(iVar2 + 8) = 0;
          }
        }
        else {
          puVar9 = (undefined4 *)(*piVar6 + 8);
          puVar10 = (undefined4 *)(iVar2 + 8);
          for (iVar7 = 5; iVar7 != 0; iVar7 = iVar7 + -1) {
            *puVar10 = *puVar9;
            puVar9 = puVar9 + 1;
            puVar10 = puVar10 + 1;
          }
          if ((bVar4 & 0x80) == 0) {
            FUN_0805b0d8("1Reference to symbol %s matched to definition of %s.");
          }
        }
      }
      piVar6 = (int *)FUN_0804b154(&local_1008);
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08052c80(void)

{
  undefined4 *puVar1;
  int iVar2;
  undefined *puVar3;
  int *piVar4;
  int local_8;
  
  if ((((byte)DAT_0806ab68 & 4) == 0) && (DAT_0806a08c != 0)) {
    piVar4 = (int *)FUN_0804b134(&local_8);
    while (piVar4 != (int *)0x0) {
      puVar1 = (undefined4 *)*piVar4;
      if (((((puVar1[4] & 0x101) == 1) && (iVar2 = puVar1[3], iVar2 != 0)) &&
          ((*(byte *)(iVar2 + 0x31) & 2) != 0)) &&
         (((puVar3 = *(undefined **)(iVar2 + 0x10), puVar3 != (undefined *)0x0 &&
           (puVar3 != PTR_DAT_08068878)) && ((puVar3[0x68] & 1) != 0)))) {
        *puVar1 = *(undefined4 *)(puVar3 + 0x28);
        *(int *)(puVar3 + 0x28) = *(int *)(puVar3 + 0x28) + 1;
        _DAT_0806a090 = _DAT_0806a090 + 1;
      }
      piVar4 = (int *)FUN_0804b154(&local_8);
    }
  }
  return;
}



void FUN_08052cf8(void)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  puVar1 = *(uint **)(*(int *)(*DAT_0806a0a0 + 8) + 0x14);
  uVar2 = FUN_0805e13c(DAT_0806a08c);
  *puVar1 = uVar2;
  puVar4 = puVar1 + 1;
  while( true ) {
    puVar3 = (uint *)FUN_0804b668(DAT_0806a09c);
    if (puVar3 == (uint *)0x0) break;
    uVar2 = FUN_0805e13c(*puVar3);
    *puVar3 = uVar2;
    uVar2 = FUN_0805e13c(puVar3[2]);
    puVar3[2] = uVar2;
    uVar2 = FUN_0805e13c(puVar3[1]);
    puVar3[1] = uVar2;
    *puVar4 = *puVar3;
    puVar1[2] = puVar3[1];
    puVar1[3] = puVar3[2];
    puVar4 = puVar4 + 3;
    puVar1 = puVar1 + 3;
  }
  return;
}



char * FUN_08052d78(undefined *param_1)

{
  int iVar1;
  char *pcVar2;
  
  pcVar2 = *(char **)(param_1 + 0x58);
  iVar1 = FUN_0804b6c0(pcVar2,"root");
  if ((iVar1 == 0) && (param_1 != PTR_DAT_08068878)) {
    pcVar2 = "ROOT-data";
  }
  return pcVar2;
}



void FUN_08052da8(void)

{
  int iVar1;
  
  if (((*(int *)(PTR_DAT_08068878 + 0x14) != 0) || (*(int *)(PTR_DAT_08068878 + 0x18) != 0)) ||
     (*(int *)(PTR_DAT_08068878 + 0x1c) != 0)) {
    FUN_0805b0d8("2Some AREAs could not be assigned to any region:");
    for (iVar1 = *(int *)(PTR_DAT_08068878 + 4); iVar1 != 0; iVar1 = *(int *)(iVar1 + 8)) {
      if ((-1 < *(short *)(iVar1 + 0x30)) && (*(int *)(iVar1 + 0x1c) != 0)) {
        FUN_0805b0d8("0    %s(%s)");
      }
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08052e10(void)

{
  uint uVar1;
  uint *puVar2;
  undefined *puVar3;
  uint *puVar4;
  int iVar5;
  char *pcVar6;
  undefined *puVar7;
  int iVar8;
  char *pcVar9;
  uint *local_1048;
  uint *local_1044;
  int *local_1038;
  uint local_1024;
  int local_1020;
  int local_101c;
  int local_1018;
  undefined4 local_1010;
  undefined4 local_100c;
  int local_10;
  int local_c;
  uint local_8;
  
  if (DAT_08069dac[1] == 0) {
    DAT_08069dac[1] = (uint)PTR_DAT_08068878;
    FUN_08052da8();
  }
  local_101c = 0;
  local_1018 = 0;
  for (puVar2 = DAT_08069dac; puVar2 != (uint *)0x0; puVar2 = (uint *)*puVar2) {
    for (uVar1 = puVar2[1]; uVar1 != 0; uVar1 = *(uint *)(uVar1 + 0x60)) {
      local_1018 = local_1018 + 1;
    }
    local_101c = local_101c + 1;
  }
  puVar4 = (uint *)FUN_0804b1e8(local_101c * 8);
  iVar5 = FUN_0804b1e8(local_1018 * 8);
  local_101c = 0;
  local_1018 = 0;
  for (puVar2 = DAT_08069dac; puVar2 != (uint *)0x0; puVar2 = (uint *)*puVar2) {
    if (((undefined *)puVar2[1] == PTR_DAT_0806887c) && ((undefined *)puVar2[1] != PTR_DAT_08068878)
       ) {
      puVar2[3] = *(int *)(PTR_DAT_08068878 + 0x14) + *(int *)(PTR_DAT_08068878 + 0x2c);
    }
    local_1024 = puVar2[3];
    puVar4[local_101c * 2 + 1] = (uint)puVar2;
    puVar4[local_101c * 2] = local_1024;
    local_101c = local_101c + 1;
    puVar7 = (undefined *)puVar2[1];
    if (puVar7 != (undefined *)0x0) {
      do {
        *(undefined4 *)(iVar5 + local_1018 * 8) = *(undefined4 *)(puVar7 + 0x44);
        *(undefined **)(iVar5 + 4 + local_1018 * 8) = puVar7;
        local_1018 = local_1018 + 1;
        iVar8 = *(int *)(puVar7 + 0x18) + *(int *)(puVar7 + 0x14);
        if ((puVar7[0x68] & 1) == 0) {
          if (puVar7 != PTR_DAT_08068878) {
            if (iVar8 != 0) {
              pcVar9 = "$$Base";
              local_1010 = 0x67616d49;
              local_100c = 0x242465;
              pcVar6 = strcat((char *)&local_1010,*(char **)(puVar7 + 0x58));
              strcat(pcVar6,pcVar9);
              FUN_08050278((char *)&local_1010,*(int *)(puVar7 + 0x44));
              pcVar9 = "$$Length";
              local_1010 = 0x67616d49;
              local_100c = 0x242465;
              pcVar6 = strcat((char *)&local_1010,*(char **)(puVar7 + 0x58));
              strcat(pcVar6,pcVar9);
              FUN_08050278((char *)&local_1010,iVar8);
              pcVar9 = "$$Base";
              local_1010 = 0x64616f4c;
              local_100c = CONCAT13(local_100c._3_1_,0x2424);
              pcVar6 = strcat((char *)&local_1010,*(char **)(puVar7 + 0x58));
              strcat(pcVar6,pcVar9);
              FUN_08050278((char *)&local_1010,local_1024);
            }
            if ((puVar7 != PTR_DAT_08068878) && (*(int *)(puVar7 + 0x1c) != 0)) {
              pcVar9 = "$$ZI$$Base";
              local_1010 = 0x67616d49;
              local_100c = 0x242465;
              pcVar6 = strcat((char *)&local_1010,*(char **)(puVar7 + 0x58));
              strcat(pcVar6,pcVar9);
              FUN_08050278((char *)&local_1010,iVar8 + *(int *)(puVar7 + 0x44));
              pcVar9 = "$$ZI$$Length";
              local_1010 = 0x67616d49;
              local_100c = 0x242465;
              pcVar6 = strcat((char *)&local_1010,*(char **)(puVar7 + 0x58));
              strcat(pcVar6,pcVar9);
              FUN_08050278((char *)&local_1010,*(int *)(puVar7 + 0x1c));
            }
          }
          local_1024 = local_1024 +
                       ((*(int *)(puVar7 + 0x48) - *(int *)(puVar7 + 0x44)) -
                       *(int *)(puVar7 + 0x1c));
          if (puVar7 == PTR_DAT_0806887c) {
            local_1024 = local_1024 + puVar2[5];
          }
        }
        else {
          local_10 = (*(int *)(puVar7 + 0x48) - *(int *)(puVar7 + 0x44)) +
                     *(int *)(puVar7 + 0x28) * 4;
          local_c = *(int *)(puVar7 + 0x28) * 4 + *(int *)(puVar7 + 0x40) + 8;
          local_8 = local_1024;
          local_1024 = local_1024 + local_10;
          FUN_0804b618(DAT_0806a09c,&local_10);
        }
        puVar7 = *(undefined **)(puVar7 + 0x60);
      } while (puVar7 != (undefined *)0x0);
    }
    puVar2[5] = local_1024 - puVar2[3];
    if ((puVar2[4] != 0) && ((int)puVar2[4] < (int)(local_1024 - puVar2[3]))) {
      FUN_0805b0d8("2Load region %s (size %d) exceeds specified limit.");
    }
    if (((undefined *)puVar2[1] == PTR_DAT_08068878) && ((DAT_0806ab70._1_1_ & 4) != 0)) {
      puVar2[5] = puVar2[5] + *(int *)((undefined *)puVar2[1] + 0x20);
    }
  }
  FUN_08050140((int)puVar4,local_101c);
  local_1020 = 0;
  if (0 < local_101c + -1) {
    local_1044 = puVar4 + 1;
    local_1048 = puVar4;
    do {
      local_1048 = local_1048 + 2;
      iVar8 = *(int *)(*local_1044 + 0x14);
      if ((*(undefined **)(*local_1044 + 4) == PTR_DAT_08068878) && ((DAT_0806ab70._1_1_ & 4) != 0))
      {
        iVar8 = iVar8 - _DAT_08069d60;
      }
      if (*local_1048 < iVar8 + *puVar4) {
        FUN_0805b0d8("2Load region %s (size %d) overlaps load region %s");
      }
      puVar4 = puVar4 + 2;
      local_1044 = local_1044 + 2;
      local_1020 = local_1020 + 1;
    } while (local_1020 < local_101c + -1);
  }
  FUN_08050140(iVar5,local_1018);
  local_1020 = 0;
  if (0 < local_1018 + -1) {
    do {
      puVar7 = *(undefined **)(iVar5 + 4 + local_1020 * 8);
      if ((puVar7[0x68] & 1) == 0) {
        uVar1 = *(uint *)(iVar5 + 8 + local_1020 * 8);
        if ((uVar1 < *(uint *)(puVar7 + 0x48)) &&
           (puVar3 = *(undefined **)(iVar5 + 0xc + local_1020 * 8), uVar1 < *(uint *)(puVar3 + 0x48)
           )) {
          FUN_08052d78(puVar3);
          FUN_08052d78(puVar7);
          FUN_0805b0d8("2Execution region %s (size %d) overlaps execution region %s");
        }
      }
      else {
        local_1044 = (uint *)(local_1020 + 1);
        if ((int)local_1044 < local_1018) {
          local_1038 = (int *)(iVar5 + 4 + (int)local_1044 * 8);
          local_1048 = (uint *)(iVar5 + (int)local_1044 * 8);
          do {
            if (*local_1048 < *(uint *)(puVar7 + 0x48)) {
              if ((*(byte *)(*local_1038 + 0x68) & 1) == 0) {
                FUN_0805b0d8("2Execution region %s (size %d) overlaps execution region %s");
              }
              else if (*(int *)(puVar7 + 0x4c) != *(int *)(*local_1038 + 0x4c)) {
                FUN_0805b0d8("2Overlayed regions %s and %s clash unexpectedly");
              }
            }
            local_1038 = local_1038 + 2;
            local_1048 = local_1048 + 2;
            local_1044 = (uint *)((int)local_1044 + 1);
          } while ((int)local_1044 < local_1018);
        }
      }
      local_1020 = local_1020 + 1;
    } while (local_1020 < local_1018 + -1);
  }
  if (0 < DAT_0806a08c) {
    FUN_08052cf8();
  }
  return;
}



void FUN_08053448(void)

{
  if (((byte)DAT_0806ab68 & 4) == 0) {
    FUN_08050278("_etext",*(int *)(PTR_DAT_08068878 + 0x14) + *(int *)(PTR_DAT_08068878 + 0x2c));
    FUN_08050278("_edata",*(int *)(PTR_DAT_0806887c + 0x18) + *(int *)(PTR_DAT_0806887c + 0x30));
    FUN_08050278("_end",*(int *)(PTR_DAT_0806887c + 0x1c) + *(int *)(PTR_DAT_0806887c + 0x34));
    FUN_0804c2e8(0,"Image$$RO",*(int *)(PTR_DAT_08068878 + 0x2c),
                 *(int *)(PTR_DAT_08068878 + 0x14) + *(int *)(PTR_DAT_08068878 + 0x2c),-1);
    FUN_0804c2e8(0,"Image$$RW",*(int *)(PTR_DAT_0806887c + 0x30),
                 *(int *)(PTR_DAT_0806887c + 0x1c) + *(int *)(PTR_DAT_0806887c + 0x34),-1);
    FUN_0804c2e8(0,"Image$$ZI",*(int *)(PTR_DAT_0806887c + 0x34),
                 *(int *)(PTR_DAT_0806887c + 0x1c) + *(int *)(PTR_DAT_0806887c + 0x34),-1);
    FUN_0805029c("!!Image$$CodeBase","Image$$RO$$Base",*(int *)(PTR_DAT_08068878 + 0x2c));
    FUN_0805029c("!!Image$$CodeLimit","Image$$RO$$Limit",
                 *(int *)(PTR_DAT_08068878 + 0x14) + *(int *)(PTR_DAT_08068878 + 0x2c));
    FUN_0805029c("!!Image$$DataBase","Image$$RW$$Base",*(int *)(PTR_DAT_0806887c + 0x30));
    FUN_0805029c("!!Image$$DataLimit","Image$$RW$$Limit",
                 *(int *)(PTR_DAT_0806887c + 0x1c) + *(int *)(PTR_DAT_0806887c + 0x34));
    if ((0 < DAT_0806a08c) && ((DAT_0806ab68._1_1_ & 0x10) != 0)) {
      FUN_08050278("Root$$OverlayTable",*(int *)(DAT_0806a0a0 + 0x2c));
    }
    if (((byte)DAT_0806ab68 & 8) != 0) {
      FUN_08050278("__RelocCode",DAT_08069dc8 + *(int *)(PTR_DAT_08068878 + 0x2c));
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_080535b4(int param_1)

{
  char cVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  uint uVar6;
  int *piVar7;
  int iVar8;
  undefined4 uVar9;
  uint uVar10;
  uint uVar11;
  char *pcVar12;
  int local_108;
  undefined1 local_104 [256];
  
  uVar10 = DAT_0806ab98;
  if ((DAT_0806ab64 == 4) && ((DAT_0806ab68 & 0x608) == 0)) {
    uVar10 = DAT_0806ab98 + 0x80;
  }
  uVar6 = FUN_080521d4(PTR_DAT_08068878,uVar10);
  uVar10 = uVar10 + uVar6;
  if ((DAT_0806ab68 & 8) != 0) {
    DAT_08069dc8 = *(int *)(PTR_DAT_08068878 + 0x18) + *(int *)(PTR_DAT_08068878 + 0x14);
    *(int *)(PTR_DAT_08068878 + 0x18) = *(int *)(PTR_DAT_08068878 + 0x18) + DAT_080687ac;
  }
  puVar5 = DAT_08069d90;
  if ((DAT_0806ab68 & 0x10) == 0) {
    for (; puVar5 != (undefined4 *)0x0; puVar5 = (undefined4 *)puVar5[1]) {
      uVar6 = 0;
      if ((DAT_0806ab68 & 1) != 0) {
        uVar10 = 0;
      }
      for (puVar2 = (undefined *)*puVar5; puVar2 != (undefined *)0x0;
          puVar2 = *(undefined **)(puVar2 + 0x54)) {
        uVar11 = *(uint *)(puVar2 + 0x24);
        if ((uVar11 == 0xffffffff) && (uVar11 = uVar10, (*(uint *)(puVar2 + 0x68) & 2) != 0)) {
          iVar3 = *(int *)(puVar2 + 100);
          if ((iVar3 != 0) && (*(undefined **)(iVar3 + 4) == puVar2)) {
            uVar10 = *(uint *)(iVar3 + 0xc);
          }
          uVar11 = uVar10 + (*(uint *)(puVar2 + 0x68) & 0xfffffffc);
        }
        uVar10 = FUN_080521d4(puVar2,uVar11);
        if ((int)uVar6 < (int)uVar10) {
          uVar6 = uVar10;
        }
        uVar10 = uVar11;
      }
      uVar10 = uVar10 + uVar6;
    }
    if ((DAT_0806ab68 & 0x1000) != 0) {
      FUN_08052e10();
    }
    FUN_08053448();
  }
  else {
    puVar2 = (undefined *)*DAT_08069d90;
    _DAT_08069e48 = 0;
    DAT_08069e44 = 0;
    FUN_080521d4(puVar2,0);
    *(int *)(*DAT_0806ac70 + 8) =
         (*(int *)(puVar2 + 0x48) - *(int *)(puVar2 + 0x44)) + (DAT_0806ac84 + 1) * 4;
    *(int *)(*DAT_0806ac78 + 8) = *(int *)(puVar2 + 0x48) - *(int *)(puVar2 + 0x44);
    iVar3 = *(int *)(*DAT_0806ac88 + 0xc);
    if (iVar3 == 0) {
      uVar9 = 0;
    }
    else {
      uVar9 = *(undefined4 *)(iVar3 + 0x2c);
    }
    *(undefined4 *)(*DAT_0806ac88 + 8) = uVar9;
  }
  piVar7 = (int *)FUN_0804b134(&local_108);
  do {
    if (piVar7 == (int *)0x0) {
      DAT_0806a068 = DAT_0806a068 + 3 & 0xfffffffc;
      return;
    }
    iVar3 = *piVar7;
    uVar10 = *(uint *)(iVar3 + 0x10);
    if ((uVar10 & 1) == 0) {
      if ((param_1 == 0) || ((uVar10 & 0x20000000) != 0)) {
        if ((uVar10 & 0x10) == 0) {
          if (((DAT_0806ab68 & 4) == 0) ||
             (((DAT_0806ab68 & 0x10) != 0 && ((uVar10 & 0x1000000) == 0)))) {
            iVar4 = *(int *)(iVar3 + 0x18);
            iVar8 = FUN_080515f4(iVar3);
            if ((iVar8 == 0) || ((DAT_0806ab70 & 0x800) != 0)) {
              FUN_0805fba0((byte *)((int)piVar7 + 6),local_104,0x100);
              if (iVar4 == 0) {
                if (iVar8 == 0) {
                  pcVar12 = "2Undefined symbol \'%s\'.";
                }
                else {
                  pcVar12 = "1Undefined symbol \'%s\'.";
                }
                FUN_0805b0d8(pcVar12);
              }
              else if ((*(byte *)(*(int *)(iVar4 + 8) + 4) & 2) == 0) {
                if (iVar8 == 0) {
                  pcVar12 = "2Undefined symbol \'%s\', referred to from %s.";
                }
                else {
                  pcVar12 = "1Undefined symbol \'%s\', referred to from %s.";
                }
                FUN_0805b0d8(pcVar12);
              }
              else {
                if (iVar8 == 0) {
                  pcVar12 = "2Undefined symbol \'%s\', referred to from %s(%s).";
                }
                else {
                  pcVar12 = "1Undefined symbol \'%s\', referred to from %s(%s).";
                }
                FUN_0805b0d8(pcVar12);
              }
            }
          }
        }
        else {
          *(undefined4 *)(iVar3 + 8) = 0;
        }
      }
    }
    else if (((uVar10 & 4) == 0) && (*(int *)(iVar3 + 0xc) != 0)) {
      *(int *)(iVar3 + 8) = *(int *)(iVar3 + 8) + *(int *)(*(int *)(iVar3 + 0xc) + 0x2c);
    }
    if (((((DAT_0806ab70 & 0x400) != 0) ||
         (((DAT_0806ab68 & 4) != 0 && ((*(uint *)(iVar3 + 0x10) & 3) != 1)))) &&
        ((*(uint *)(iVar3 + 0x10) & 0x40000000) == 0)) &&
       ((((DAT_0806ab68 & 0x10) == 0 || ((*(uint *)(iVar3 + 0x10) & 0x3000000) != 0)) &&
        ((*(int *)(iVar3 + 0xc) == 0 || ((*(byte *)(*(int *)(iVar3 + 0xc) + 0x34) & 0x40) == 0))))))
    {
      *(int *)(iVar3 + 0x14) = DAT_0806a078;
      DAT_0806a078 = DAT_0806a078 + 1;
      if (((((DAT_0806ab70 & 0x420) != 0x400) || (*(char *)((int)piVar7 + 6) != '$')) ||
          ((cVar1 = *(char *)((int)piVar7 + 7), cVar1 != '$' && ((cVar1 != 'T' && (cVar1 != 'A')))))
          ) || ((char)piVar7[2] != '\0')) {
        uVar10 = 0xffffffff;
        piVar7 = piVar7 + 1;
        do {
          if (uVar10 == 0) break;
          uVar10 = uVar10 - 1;
          iVar3 = *piVar7;
          piVar7 = (int *)((int)piVar7 + 1);
        } while ((char)iVar3 != '\0');
        DAT_0806a068 = ~uVar10 + DAT_0806a068 + -2;
      }
    }
    piVar7 = (int *)FUN_0804b154(&local_108);
  } while( true );
}



void FUN_08053994(uint param_1)

{
  uint local_8;
  
  local_8 = FUN_0805e13c(param_1);
  FUN_0804b618(DAT_0806a0a4,&local_8);
  DAT_08069de4 = DAT_08069de4 + 1;
  return;
}



void FUN_080539bc(uint param_1,uint param_2)

{
  uint local_c;
  uint local_8;
  
  local_c = FUN_0805e13c(param_1);
  local_8 = FUN_0805e13c(param_2);
  FUN_0804b618(DAT_0806a0a8,&local_c);
  DAT_08069de0 = DAT_08069de0 + 1;
  return;
}



uint FUN_080539f8(uint *param_1,int param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint local_14;
  uint *local_10;
  uint local_c;
  
  if (param_3 == 0) {
    uVar1 = FUN_0805e13c(*param_1);
    if (((uVar1 & 0xfe000000) == 0xfa000000) && (-1 < param_2)) {
      if ((uVar1 & 0x1000000) == 0) {
        iVar3 = 0;
      }
      else {
        iVar3 = 2;
      }
      return iVar3 + ((int)(uVar1 << 8) >> 6);
    }
    uVar2 = uVar1 & 0xe000000;
    if ((uVar2 == 0xa000000) || (param_2 < 0)) {
      return (int)(uVar1 << 8) >> 6;
    }
    if ((uVar1 & 0xff0041f) == 0xe000400) {
      return (int)uVar1 >> 8 & 0xff8;
    }
    if (((uVar2 == 0x4000000) || (uVar2 = uVar1 & 0xff00000, uVar2 == 0x2800000)) ||
       (uVar2 == 0x2400000)) {
      iVar3 = 0;
      local_14 = 0xffffffff;
      local_c = 0;
      if ((uVar2 == 0x2800000) || (uVar2 == 0x2400000)) {
        local_14 = uVar1 & 0xf000;
        local_10 = param_1;
        do {
          uVar1 = FUN_08051404(uVar1);
          if (uVar2 == 0x2400000) {
            uVar1 = -uVar1;
          }
          local_c = local_c + uVar1;
          local_10 = local_10 + 1;
          iVar3 = iVar3 + 1;
          if (iVar3 == param_2) {
            return local_c;
          }
          uVar1 = FUN_0805e13c(*local_10);
        } while (((iVar3 < 3) && ((uVar1 & 0xff00000) == uVar2)) &&
                (((uVar1 & 0xf000) == local_14 && ((int)(uVar1 & 0xf0000) >> 4 == local_14))));
        uVar2 = uVar1 & 0xe000000;
      }
      if (uVar2 != 0x4000000) {
        return local_c;
      }
      if ((local_14 != 0xffffffff) && ((int)(uVar1 & 0xf0000) >> 4 != local_14)) {
        return local_c;
      }
      uVar2 = uVar1 & 0xfff;
      if ((uVar1 & 0x800000) == 0) {
        uVar2 = -uVar2;
      }
      return local_c + uVar2;
    }
  }
  else {
    uVar1 = FUN_0805e174((uint)(ushort)*param_1);
    if (((uVar1 & 0xf800) == 0xf000) &&
       ((uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_1 + 2)), (uVar2 & 0xf800) == 0xf800 ||
        ((uVar2 & 0xf801) == 0xe800)))) {
      return (int)(uVar1 << 0x15 | (uVar2 & 0x7ff) << 10) >> 9;
    }
    if ((uVar1 & 0xf800) == 0x2000) {
      uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_1 + 2));
      uVar4 = (int)uVar1 >> 8 & 7;
      if (uVar2 == uVar4 * 9 + 0x1c0) {
        uVar2 = FUN_0805e174((uint)(ushort)param_1[1]);
        if (((((uVar2 & 0xffffffc7) == uVar4 + 0x4440) ||
             ((uVar2 & 0xffffffc7) == uVar4 + 0x1800 + uVar4 * 0x40)) ||
            ((uVar2 & 0xfffffe3f) == uVar4 * 8 + uVar4 + 0x1800)) &&
           (uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_1 + 6)),
           (uVar2 & 0xf838) == uVar4 * 8 + 0x6800)) {
          return ((int)uVar2 >> 4 & 0x7cU) + (uVar1 & 0xff) * 0x80;
        }
      }
    }
  }
  return 0xffffffff;
}



uint FUN_08053cc0(uint *param_1,uint param_2,int param_3,int param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  uint local_28;
  uint *local_20;
  int local_1c;
  int local_18;
  uint local_10;
  
  if (param_4 == 0) {
    local_10 = FUN_0805e13c(*param_1);
    uVar1 = (int)param_2 >> 2;
    if (((local_10 & 0xfe000000) == 0xfa000000) && (-1 < param_3)) {
      if ((param_2 & 1) == 0) {
        pcVar4 = "2B or BL to unaligned destination.";
      }
      else {
        if (uVar1 + 0x800000 < 0x1000000) {
          uVar1 = uVar1 & 0xffffff | (param_2 & 2) << 0x17 | 0xfa000000;
LAB_08053ffe:
          uVar1 = FUN_0805e13c(uVar1);
          *param_1 = uVar1;
          return 0;
        }
LAB_08053fda:
        pcVar4 = "2Relocated value too big for instruction sequence.";
      }
    }
    else {
      uVar2 = local_10 & 0xe000000;
      if ((uVar2 == 0xa000000) || (param_3 < 0)) {
        if ((param_2 & 3) == 0) {
          if (uVar1 + 0x800000 < 0x1000000) {
            uVar1 = FUN_0805e13c(uVar1 & 0xffffff | local_10 & 0xff000000);
            *param_1 = uVar1;
            return 0;
          }
          goto LAB_08053fda;
        }
        pcVar4 = "2B or BL to unaligned destination.";
      }
      else {
        if ((local_10 & 0xff0041f) != 0xe000400) {
          if (((uVar2 != 0x4000000) && (uVar2 = local_10 & 0xff00000, uVar2 != 0x2800000)) &&
             (uVar2 != 0x2400000)) goto LAB_08054217;
          local_28 = 0;
          uVar1 = local_10 & 0xf000;
          local_18 = 0;
          if ((uVar2 == 0x2800000) || (uVar3 = 0, uVar2 == 0x2400000)) {
            local_18 = 1;
            local_20 = param_1;
            do {
              local_20 = local_20 + 1;
              uVar3 = local_28;
              if (local_18 == param_3) break;
              uVar3 = FUN_0805e13c(*local_20);
              if ((((uVar3 & 0xff00000) != uVar2) || ((uVar3 & 0xf000) != uVar1)) ||
                 ((uVar3 & 0xf0000) >> 4 != uVar1)) {
                local_28 = uVar3 & 0xe000000;
                break;
              }
              local_18 = local_18 + 1;
              local_28 = uVar3;
            } while (local_18 < 3);
          }
          if ((uVar2 == 0x2800000) || (uVar2 == 0x2400000)) {
            uVar2 = param_2;
            if (((local_28 == 0x4000000) && (local_18 != param_3)) &&
               ((uVar3 == 0 || ((uVar3 & 0xf0000) >> 4 == uVar1)))) {
              uVar2 = FUN_080539f8(param_1 + local_18,1,0);
              uVar2 = param_2 - uVar2;
              uVar1 = uVar2;
              if ((int)uVar2 < 0) {
                uVar1 = -uVar2;
              }
              if ((int)uVar1 >> ((char)local_18 * '\b' & 0x1fU) == 0) goto LAB_08054153;
              param_3 = 0;
            }
            else {
LAB_08054153:
              param_3 = local_18;
              param_2 = uVar2;
            }
            if ((int)param_2 < 0) {
              local_28 = 0x2400000;
              param_2 = -param_2;
            }
            else {
              local_28 = 0x2800000;
            }
            for (local_1c = 0; local_1c < local_18; local_1c = local_1c + 1) {
              uVar1 = FUN_08051444(param_2);
              uVar2 = FUN_08051404(uVar1);
              param_2 = param_2 - uVar2;
              uVar1 = FUN_0805e13c(local_10 & 0xf00ff000 | local_28 | uVar1);
              *param_1 = uVar1;
              param_1 = param_1 + 1;
              local_10 = FUN_0805e13c(*param_1);
            }
            if (param_2 == 0) {
              return 0;
            }
            if (param_3 != 0) goto LAB_08054217;
            if (local_28 == 0x2400000) {
              param_2 = -param_2;
            }
          }
          local_28 = local_10 & 0xff7ff000;
          if ((int)param_2 < 0) {
            param_2 = -param_2;
          }
          else {
            local_28 = local_28 | 0x800000;
          }
          uVar1 = FUN_0805e13c(param_2 & 0xfff | local_28);
          *param_1 = uVar1;
          param_2 = param_2 & 0xfffff000;
          goto LAB_08054217;
        }
        if ((param_2 & 7) == 0) {
          if ((uint)((int)param_2 >> 3) < 0x200) {
            uVar1 = ((int)param_2 >> 3) << 0xb | local_10 & 0xfff007ff;
            goto LAB_08053ffe;
          }
          goto LAB_08053fda;
        }
        pcVar4 = "2B or BL to unaligned destination.";
      }
    }
    FUN_0805b0d8(pcVar4);
    param_2 = 1;
  }
  else {
    uVar1 = FUN_0805e174((uint)(ushort)*param_1);
    if ((uVar1 & 0xf800) == 0xf000) {
      uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_1 + 2));
      if ((uVar2 & 0xf800) == 0xf800) {
        if (param_2 + 0x400000 < 0x800000) {
          if ((param_2 & 1) != 0) {
            FUN_0805b0d8("2B or BL to unaligned destination.");
          }
          uVar1 = (int)param_2 >> 1 & 0x7ffU | 0xf800;
LAB_08053dac:
          uVar2 = FUN_0805e174((uint)((ushort)((int)param_2 >> 0xc) & 0x7ff | 0xf000));
          *(short *)param_1 = (short)uVar2;
          uVar1 = FUN_0805e174(uVar1);
          *(short *)((int)param_1 + 2) = (short)uVar1;
          return 0;
        }
      }
      else if (((uVar2 & 0xf801) == 0xe800) && (param_2 + 0x400000 < 0x800000)) {
        if ((param_2 & 1) != 0) {
          FUN_0805b0d8("2B or BL to unaligned destination.");
        }
        uVar1 = (int)param_2 >> 1 & 0x7ffU | 0xe800;
        goto LAB_08053dac;
      }
    }
    if ((uVar1 & 0xf800) == 0x2000) {
      uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_1 + 2));
      uVar3 = (int)uVar1 >> 8 & 7;
      if (uVar2 == uVar3 * 9 + 0x1c0) {
        uVar2 = FUN_0805e174((uint)(ushort)param_1[1]);
        if (((((uVar2 & 0xffffffc7) == uVar3 + 0x4440) ||
             ((uVar2 & 0xffffffc7) == uVar3 + 0x1800 + uVar3 * 0x40)) ||
            ((uVar2 & 0xfffffe3f) == uVar3 * 8 + uVar3 + 0x1800)) &&
           ((uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_1 + 6)),
            (uVar2 & 0xf838) == uVar3 * 8 + 0x6800 && (param_2 < 0x8000)))) {
          if ((param_2 & 3) != 0) {
            FUN_0805b0d8("2Unaligned -apcs 3/reentrant relocation.");
          }
          uVar1 = FUN_0805e174(uVar1 & 0xff00 | (int)param_2 >> 7);
          *(short *)param_1 = (short)uVar1;
          uVar1 = FUN_0805e174((param_2 & 0x7c) << 4 | uVar2 & 0xf83f);
          *(short *)((int)param_1 + 6) = (short)uVar1;
          return 0;
        }
      }
    }
LAB_08054217:
    if ((param_2 != 0) || (param_3 < 0)) {
      FUN_0805b0d8("2Relocated value too big for instruction sequence.");
    }
  }
  return param_2;
}



int FUN_08054238(int param_1,int param_2)

{
  return *(int *)(*(int *)(*(int *)(param_2 + 4) + 0x10) + 0x40) + 4 + param_1 * 4;
}



// WARNING: Removing unreachable block (ram,0x08054671)

void FUN_08054258(int *param_1)

{
  char cVar1;
  undefined *puVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  undefined2 uVar6;
  byte *pbVar7;
  uint *puVar8;
  uint *puVar9;
  undefined2 extraout_var;
  int *piVar10;
  uint uVar11;
  uint uVar12;
  uint *puVar13;
  int iVar14;
  size_t sVar15;
  char *pcVar16;
  uint uVar17;
  char *pcVar18;
  int *piVar19;
  byte *pbVar20;
  char *pcVar21;
  uint local_1a8;
  int *local_198;
  uint local_184;
  uint local_180;
  uint local_17c;
  uint local_174;
  uint local_170;
  uint local_16c;
  uint local_168;
  uint local_164;
  int *local_158;
  int *local_154;
  uint local_150;
  byte local_144 [61];
  char acStack_107 [259];
  
  uVar17 = 0;
  local_158 = (int *)0x0;
  bVar4 = false;
  bVar3 = false;
  if (0 < param_1[7]) {
    if (((DAT_0806ab70 & 0x80000) != 0) && ('\x02' < DAT_0806ab6e)) {
      pcVar21 = acStack_107 + 3;
      sprintf(pcVar21,"    Relocating AREA %s",(char *)((int)param_1 + 0x46));
      uVar11 = 0xffffffff;
      pcVar16 = pcVar21;
      do {
        if (uVar11 == 0) break;
        uVar11 = uVar11 - 1;
        cVar1 = *pcVar16;
        pcVar16 = pcVar16 + 1;
      } while (cVar1 != '\0');
      pcVar16 = acStack_107 + ~uVar11 + 2;
      if (*param_1 != 0) {
        sprintf(pcVar16," from %s",(char *)(*(int *)(*param_1 + 8) + 0x24));
        uVar12 = 0xffffffff;
        do {
          if (uVar12 == 0) break;
          uVar12 = uVar12 - 1;
          cVar1 = *pcVar16;
          pcVar16 = pcVar16 + 1;
        } while (cVar1 != '\0');
        pcVar16 = acStack_107 + ~uVar12 + ~uVar11 + 1;
        if ((*(byte *)(*(int *)(*param_1 + 8) + 4) & 2) != 0) {
          sprintf(pcVar16,"(%s)",*(char **)(*param_1 + 4));
          uVar11 = 0xffffffff;
          pcVar18 = pcVar16;
          do {
            if (uVar11 == 0) break;
            uVar11 = uVar11 - 1;
            cVar1 = *pcVar18;
            pcVar18 = pcVar18 + 1;
          } while (cVar1 != '\0');
          pcVar16 = pcVar16 + (~uVar11 - 1);
        }
      }
      pcVar16[0] = '.';
      pcVar16[1] = '\n';
      pcVar16[2] = '\0';
      FUN_0805af70(pcVar21);
      DAT_0806ac48 = DAT_0806ac48 + 1;
    }
    FUN_0804b418();
    FUN_0804bc68(*param_1);
    sVar15 = param_1[7];
    if ((*(byte *)((int)param_1 + 0x31) & 0x10) != 0) {
      sVar15 = 0;
    }
    pbVar7 = FUN_0804bd58(param_1[6],sVar15);
    if (DAT_08069dd8 != *(int *)param_1[1]) {
      DAT_08069dc0 = DAT_08069dc0 + *(int *)(DAT_08069dd8 + 0x28) * 8;
      DAT_08069dd8 = *(int *)param_1[1];
      if ((DAT_0806ab68 & 4) != 0) {
        FUN_0804ecc0(DAT_0806a0a8);
        DAT_0806a0a8 = FUN_0804b5e4(8);
        DAT_08069dbc = DAT_08069dc0;
        if ((*(byte *)(DAT_08069dd8 + 0x31) & 0x10) == 0) {
          DAT_08069dbc = DAT_08069dc0 + *(int *)(DAT_08069dd8 + 0x1c);
        }
      }
    }
    puVar8 = (uint *)FUN_0804bd58(param_1[9],param_1[10] << 3);
    puVar13 = puVar8 + param_1[10] * 2;
    for (; puVar8 < puVar13; puVar8 = puVar8 + 2) {
      local_17c = FUN_0805e13c(*puVar8);
      local_180 = FUN_0805e13c(puVar8[1]);
      if (local_180 >> 0x18 == 0xf0) {
        if ((DAT_0806ab68 & 4) != 0) {
          *(int *)(*(int *)param_1[1] + 0x28) = *(int *)(*(int *)param_1[1] + 0x28) + 1;
          local_180 = local_180 & 0xff000000 |
                      *(uint *)(**(int **)(*(int *)(*(int *)(*param_1 + 0x28) +
                                                   (local_180 & 0xffffff) * 4) + 4) + 0x38);
          local_17c = local_17c + *(int *)(*(int *)param_1[1] + 0x18);
LAB_080555de:
          FUN_080539bc(local_17c,local_180);
        }
      }
      else {
        local_170 = 0xffffffff;
        local_184 = 0;
        if ((int)local_180 < 0) {
          local_174 = local_180 & 0xffffff;
          local_164 = local_180 >> 0x18 & 3;
          local_168 = local_180 >> 0x1a & 1;
          local_16c = local_180 >> 0x1b & 1;
          if ((*(byte *)(param_1 + 0xd) & 4) == 0) {
            local_170 = local_180 >> 0x1d & 3;
          }
          else if (local_168 != 0) {
            local_164 = 3;
          }
          local_180 = local_180 & 0x90000000;
          if (local_164 == 3) {
            local_184 = local_17c & 1;
            local_17c = local_17c & 0xfffffffe;
          }
        }
        else {
          local_174 = local_180 & 0xffff;
          local_164 = local_180 >> 0x10 & 3;
          local_168 = local_180 >> 0x12 & 1;
          local_16c = local_180 >> 0x13 & 1;
          if (local_168 != 0) {
            local_16c = 1;
            local_164 = 3;
          }
          if (local_16c == 0) {
            local_174 = param_1[0xe];
          }
          local_180 = 0;
        }
        puVar9 = (uint *)(pbVar7 + local_17c);
        if (local_164 < 3) {
          if (local_164 == 0) {
            uVar17 = (uint)(char)*puVar9;
          }
          else {
            if ((local_17c & (1 << (sbyte)local_164) - 1U) != 0) {
              if ((DAT_0806ab6c & 8) == 0) {
                if (DAT_08069d20 != param_1) {
                  iVar14 = strncmp((char *)((int)param_1 + 0x46),".debug",6);
                  if (iVar14 != 0) {
                    FUN_0805b0d8("1Unaligned data in %s(%s), use \'-info unaligned\' for more info")
                    ;
                  }
                  DAT_08069d20 = param_1;
                }
              }
              else {
                FUN_0805b0d8("1Unaligned data at offset 0x%lx in %s(%s).");
              }
            }
            if (local_164 == 1) {
              uVar6 = FUN_0804b838((undefined2 *)puVar9);
              uVar17 = CONCAT22(extraout_var,uVar6);
            }
            else {
              uVar17 = FUN_0804b7e8((uint3 *)puVar9);
            }
          }
        }
        else if ((local_164 == 3) &&
                (uVar17 = FUN_080539f8(puVar9,local_170,local_184), uVar17 == 0xffffffff)) {
          if (local_184 == 0) {
            FUN_0805e13c(*puVar9);
          }
          else {
            FUN_0805e174((uint)(ushort)*puVar9);
          }
          FUN_0805b0d8("2can\'t relocate instr [%.8lx] at offset 0x%lx in %s(%s).");
          uVar17 = 0;
        }
        local_150 = 1;
        bVar5 = true;
        if (((DAT_0806ab70 & 0x80000) != 0) && ('\x02' < DAT_0806ab6e)) {
          FUN_0805af70("rel: off=0x%lx, A=%u, R=%u, len=%u, B=%u, symno=%lu\n");
        }
        if ((local_184 != 0) && ((DAT_0806ab70 & 0x420) == 0x400)) {
          FUN_08050214("!!$T",local_17c + param_1[0xb],0x1000101);
        }
        if (local_16c == 0) {
          local_154 = *(int **)(*(int *)(*param_1 + 0x28) + local_174 * 4);
          piVar19 = (int *)0x0;
          if ((local_168 == 0) || (local_154[1] != param_1[1])) {
            uVar17 = uVar17 + local_154[0xb];
            local_1a8 = DAT_0806ab68;
            if ((((DAT_0806ab68 & 4) != 0) && ((undefined *)param_1[4] == PTR_DAT_08068878)) ||
               ((local_180 & 0x10000000) != 0)) {
              if ((char)local_154[0xd] < '\0') {
                local_16c = 1;
                local_174 = *(uint *)(*(int *)local_154[1] + 0x14);
                uVar17 = uVar17 - local_154[0xb];
              }
              else {
                iVar14 = *(int *)local_154[1];
                uVar17 = uVar17 - *(int *)(iVar14 + 0x2c);
                local_174 = *(uint *)(iVar14 + 0x38);
              }
            }
          }
          else {
            bVar5 = false;
            local_1a8 = DAT_0806ab68;
          }
        }
        else {
          local_198 = *(int **)(*(int *)(*param_1 + 0x20) + local_174 * 4);
          local_158 = (int *)*local_198;
          piVar19 = local_158 + 2;
          if ((*(byte *)((int)local_158 + 0x11) & 0x10) == 0) {
            if (local_184 != 0) goto LAB_080548b0;
          }
          else if (local_184 != 1) {
LAB_080548b0:
            piVar10 = (int *)FUN_0804b0dc((int)local_198);
            if ((piVar10 != (int *)0x0) &&
               (iVar14 = strcmp((char *)(local_198 + 1),(char *)(piVar10 + 1)), iVar14 == 0)) {
              local_158 = (int *)*piVar10;
              piVar19 = local_158 + 2;
              local_198 = piVar10;
            }
          }
          uVar11 = piVar19[2];
          local_150 = (uint)((uVar11 & 0x10) == 0);
          local_154 = (int *)0x0;
          local_174 = piVar19[3];
          if (((uVar11 & 1) == 0) || (((DAT_0806ab68 & 0x14) == 4 && ((uVar11 & 3) != 1)))) {
            local_1a8 = DAT_0806ab68;
            if (((DAT_0806ab68 & 4) == 0) && ((local_164 == 3 && ((uVar11 & 0x10) != 0)))) {
              uVar17 = uVar17 + local_17c + param_1[0xb];
            }
          }
          else {
            if (((((uVar11 & 0x2000100) == 0x2000000) &&
                 ((undefined *)param_1[4] == PTR_DAT_08068878)) && (piVar19[1] != 0)) &&
               ((*(byte *)(piVar19[1] + 0x31) & 2) != 0)) {
              local_154 = DAT_0806ac74;
              if (local_164 != 3) {
                local_154 = DAT_0806ac6c;
              }
            }
            else {
              local_154 = (int *)piVar19[1];
            }
            if (((uVar11 & 0x20) != 0) && (local_154 == param_1)) {
              *(undefined1 *)(local_198 + 1) = 0x20;
              piVar10 = FUN_0804b030((char *)(local_198 + 1),DAT_0806ab74);
              if (piVar10 == (int *)0x0) {
                FUN_0805b0d8("2Undefined STRONG symbol %s.");
              }
              else {
                local_158 = (int *)*piVar10;
                piVar19 = local_158 + 2;
              }
              *(undefined1 *)(local_198 + 1) = 0x21;
              uVar11 = piVar19[2];
            }
            iVar14 = *local_158;
            if ((iVar14 < 0) || ((local_168 != 0 && (*(int *)(piVar19[1] + 0x10) == param_1[4])))) {
              uVar17 = uVar17 + *piVar19;
              if ((uVar11 & 0x1000) == 0) {
                if ((local_164 == 3) && (local_184 != 0)) {
                  if ((piVar19[1] == 0) || ((*(byte *)(piVar19[1] + 0x32) & 0x40) == 0)) {
                    pcVar21 = "2Unsupported call from Thumb code to ARM symbol %s in %s(%s).";
LAB_08054d8e:
                    FUN_0805b0d8(pcVar21);
                  }
                  else {
                    iVar14 = local_158[1];
                    if (iVar14 == -1) {
                      FUN_0805b0d8("2Phase error relocating to symbol %s in %s(%s).");
                      iVar14 = local_158[1];
                    }
                    if ((iVar14 == 0) &&
                       (uVar11 = FUN_0805e174((uint)*(ushort *)((int)puVar9 + 2)),
                       (uVar11 & 0xff01) != 0xe800)) {
                      local_158[1] = DAT_08069dd0;
                      if ((DAT_0806ab70 & 0x420) == 0x400) {
                        FUN_08050214("!!$$",DAT_08069dd0,0x1001001);
                        FUN_08050214("!!$$",DAT_08069dd0 + 4,0x1000101);
                      }
                      FUN_08053cc0(&DAT_0806a110,(*piVar19 + -0xc) - DAT_08069dd0,-1,0);
                      pbVar20 = DAT_08069dcc;
                      *(undefined4 *)DAT_08069dcc = DAT_0806a10c;
                      *(undefined4 *)(pbVar20 + 4) = DAT_0806a110;
                      DAT_08069dcc = DAT_08069dcc + 8;
                      DAT_08069dd0 = DAT_08069dd0 + 8;
                    }
                    uVar17 = (uVar17 - *piVar19) + local_158[1];
                  }
                  goto LAB_08054d96;
                }
              }
              else if (local_164 == 3) {
                if (local_184 == 0) {
                  if ((piVar19[1] == 0) || ((*(byte *)(piVar19[1] + 0x32) & 0x40) == 0)) {
                    pcVar21 = "2Unsupported call from ARM code to Thumb symbol %s in %s(%s).";
                    goto LAB_08054d8e;
                  }
                  iVar14 = local_158[1];
                  if (iVar14 == -1) {
                    FUN_0805b0d8("2Phase error relocating to symbol %s in %s(%s).");
                    iVar14 = local_158[1];
                  }
                  if ((iVar14 == 0) &&
                     (uVar11 = FUN_0805e13c(*puVar9), (uVar11 & 0xfe000000) != 0xfa000000)) {
                    local_158[1] = DAT_08069dd0;
                    if ((DAT_0806ab70 & 0x420) == 0x400) {
                      FUN_08050214("!!$$",DAT_08069dd0,0x1000001);
                      FUN_08050214("!!$$",DAT_08069dd0 + 8,0x1000101);
                    }
                    DAT_0806a108 = FUN_0805e13c(*piVar19 + 1);
                    pbVar20 = DAT_08069dcc;
                    *(undefined4 *)DAT_08069dcc = DAT_0806a100;
                    *(undefined4 *)(pbVar20 + 4) = DAT_0806a104;
                    *(uint *)(pbVar20 + 8) = DAT_0806a108;
                    DAT_08069dcc = DAT_08069dcc + 0xc;
                    if ((DAT_0806ab68 & 1) != 0) {
                      uVar11 = (DAT_08069dd0 - DAT_0806ab98) + 8;
                      if ((DAT_0806ab68 & 0x600) != 0) {
                        uVar11 = (DAT_08069dd0 - DAT_0806ab98) - 0x78;
                      }
                      FUN_08053994(uVar11);
                    }
                    DAT_08069dd0 = DAT_08069dd0 + 0xc;
                  }
                  uVar17 = (uVar17 - *piVar19) + local_158[1];
                  goto LAB_08054d96;
                }
              }
              else if (((*(byte *)((int)local_154 + 0x31) & 2) != 0) && ((uVar11 & 0x100) == 0)) {
                uVar17 = uVar17 + 1;
              }
            }
            else {
              if ((uVar11 & 0x2000000) == 0) {
                iVar14 = FUN_08054238(iVar14,(int)piVar19);
                uVar17 = uVar17 + iVar14;
              }
              else {
                iVar14 = FUN_0805c178(iVar14,local_164);
                uVar17 = uVar17 + iVar14;
              }
LAB_08054d96:
              uVar11 = piVar19[2];
            }
            local_1a8 = DAT_0806ab68;
            if (((uVar11 & 4) == 0) && ((local_168 == 0 || (local_154[1] != param_1[1])))) {
              if ((((DAT_0806ab68 & 4) != 0) && ((undefined *)param_1[4] == PTR_DAT_08068878)) ||
                 (((local_180 & 0x10000000) != 0 && (local_168 == 0)))) {
                if (local_154 == (int *)0x0) {
                  local_150 = 0;
                  bVar5 = false;
                  FUN_0805b0d8("2Relocation w.r.t. undefined %s lost at offset 0x%lx in %s(%s).");
                  local_1a8 = DAT_0806ab68;
                }
                else if ((char)local_154[0xd] < '\0') {
                  uVar17 = uVar17 - local_154[0xb];
                  local_174 = *(uint *)(*(int *)local_154[1] + 0x14);
                }
                else if ((((DAT_0806ab68 & 0x10) == 0) && ((local_180 & 0x10000000) == 0)) &&
                        ((uVar11 & 3) != 1)) {
                  uVar17 = uVar17 - *piVar19;
                }
                else {
                  uVar17 = uVar17 - *(int *)(*(int *)local_154[1] + 0x2c);
                  local_16c = 0;
                  local_174 = *(uint *)(*(int *)local_154[1] + 0x38);
                }
              }
            }
            else {
              bVar5 = false;
              if ((uVar11 & 0x1000000) == 0) {
                local_150 = 0;
              }
              if (((local_168 != 0) && ((DAT_0806ab68 & 4) != 0)) && ((uVar11 & 4) != 0)) {
                FUN_0805b0d8("2PC relative reference to absolute symbol %s.");
                local_1a8 = DAT_0806ab68;
              }
              if (((local_164 == 3) && ((local_180 & 0x10000000) != 0)) &&
                 ((*(byte *)((int)piVar19 + 9) & 8) == 0)) {
                uVar17 = uVar17 + 4;
              }
            }
          }
        }
        if (((local_1a8 & 0x10) != 0) && ((undefined *)param_1[4] != PTR_DAT_08068878)) {
          bVar5 = false;
          local_150 = 0;
          if ((((*(byte *)((int)param_1 + 0x35) & 1) == 0) &&
              ((local_168 == 0 && ((local_180 & 0x10000000) == 0)))) &&
             ((piVar19 == (int *)0x0 || ((*(byte *)(piVar19 + 2) & 4) == 0)))) {
            DAT_0806ab68 = local_1a8;
            FUN_0805b0d8("2Position-dependent reloc at 0x%lx in %s(%s)");
            local_1a8 = DAT_0806ab68;
          }
        }
        DAT_0806ab68 = local_1a8;
        if (((((local_1a8 & 0x800) != 0) && (local_154 != (int *)0x0)) &&
            ((*(byte *)((int)local_154 + 0x31) & 2) == 0)) &&
           ((puVar2 = (undefined *)local_154[4], puVar2 != PTR_DAT_08068878 &&
            (puVar2 != (undefined *)param_1[4])))) {
          if (*(int *)((undefined *)param_1[4] + 0x4c) == *(int *)(puVar2 + 0x4c)) {
            if (!bVar3) {
              FUN_0805b0d8("2%s(%s) refers to non-coresident data.");
              bVar3 = true;
            }
          }
          else if ((!bVar4) && (!bVar3)) {
            FUN_0805b0d8("1%s(%s) refers to non-coresident data.");
            bVar4 = true;
          }
        }
        if (local_168 != 0) {
          if (-1 < (int)local_180) {
            uVar17 = (uVar17 - 8) - local_17c;
          }
          uVar17 = uVar17 - param_1[0xb];
          if (((DAT_0806ab68 & 4) != 0) && (bVar5)) {
            uVar17 = uVar17 + *(int *)(*(int *)param_1[1] + 0x2c);
          }
        }
        if (local_164 == 1) {
          local_150 = 0;
          FUN_0804b8ac((undefined1 *)puVar9,uVar17);
        }
        else if (local_164 < 2) {
          if (local_164 == 0) {
            local_150 = 0;
            *(char *)puVar9 = (char)uVar17;
          }
        }
        else if (local_164 == 2) {
          if (((DAT_0806ab68 & 0x800) != 0) && (local_154 != (int *)0x0)) {
            if ((undefined *)param_1[4] == PTR_DAT_08068878) {
              local_150 = 0x80000000;
            }
            else if (((undefined *)local_154[4] == PTR_DAT_08068878) ||
                    ((local_16c != 0 && (-1 < *local_158)))) {
              local_150 = 0x10000000;
              if ((DAT_0806ab68 & 1) != 0) {
                uVar17 = uVar17 - DAT_0806ab98;
              }
            }
            else if ((undefined *)local_154[4] == (undefined *)param_1[4]) {
              local_150 = 0x20000000;
            }
          }
          if (((((DAT_0806ab68 & 0x10) != 0) && (local_154 != (int *)0x0)) &&
              ((undefined *)param_1[4] != PTR_DAT_08068878)) &&
             ((*(byte *)((int)param_1 + 0x31) & 2) == 0)) {
            local_17c = local_17c - *(int *)(*(int *)param_1[1] + 0x2c);
            if ((*(byte *)((int)local_154 + 0x31) & 2) == 0) {
              local_150 = 0x10000000;
              uVar17 = uVar17 - *(int *)(*(int *)(*DAT_0806ac68 + 0xc) + 0x2c);
            }
            else if ((piVar19 == (int *)0x0) || ((piVar19[2] & 0x2000100U) != 0x2000000)) {
              FUN_0805b0d8(
                          "2Stub AREA %s(%s) directly addresses\n              sharable library AREA %s(%s)."
                          );
              local_150 = 0;
            }
            else {
              local_150 = 0x20000000;
              uVar17 = uVar17 - *(int *)(*DAT_0806ac60 + 8);
            }
          }
          FUN_0804b864((undefined1 *)puVar9,uVar17);
          if ((((DAT_0806ab70 & 0x420) == 0x400) && (-1 < (short)param_1[0xc])) &&
             ((local_154 != (int *)0x0 && ((*(byte *)((int)local_154 + 0x31) & 2) != 0)))) {
            FUN_08050214("!!$A",local_17c + param_1[0xb],0x1000101);
          }
        }
        else if (local_164 == 3) {
          if ((local_168 != 0) && (local_154 != (int *)0x0)) {
            if (((undefined *)param_1[4] == PTR_DAT_08068878) ||
               ((undefined *)param_1[4] == (undefined *)local_154[4])) {
              local_150 = 0;
            }
            else {
              local_150 = 0x30000000;
              if ((DAT_0806ab68 & 1) != 0) {
                uVar17 = uVar17 - DAT_0806ab98;
              }
            }
          }
          uVar11 = FUN_08053cc0(puVar9,uVar17,local_170,local_184);
          if (uVar11 != 0) {
            FUN_0805b0d8("0(at 0x%lx in %s(%s): offset/value = 0x%lx bytes)");
          }
        }
        local_1a8 = DAT_0806ab68;
        if ((((DAT_0806ab68 & 0x10) != 0) && ((undefined *)param_1[4] != PTR_DAT_08068878)) &&
           (local_150 != 0)) {
          FUN_08053994(local_17c + DAT_08069dc0 + local_150);
          local_1a8 = DAT_0806ab68;
        }
        if ((((local_1a8 & 9) != 0) && (local_150 != 0)) && ((local_180 & 0x10000000) == 0)) {
          uVar11 = local_17c + DAT_08069dc0 + (local_150 & 0x70000000);
          if ((local_1a8 & 0x600) != 0) {
            uVar11 = uVar11 - 0x80;
          }
          DAT_0806ab68 = local_1a8;
          FUN_08053994(uVar11);
          local_1a8 = DAT_0806ab68;
        }
        DAT_0806ab68 = local_1a8;
        if (((local_1a8 & 4) != 0) && (bVar5)) {
          *(int *)(*(int *)param_1[1] + 0x28) = *(int *)(*(int *)param_1[1] + 0x28) + 1;
          local_180 = local_180 | local_174 + 0x80000000 + local_164 * 0x1000000;
          if (local_168 != 0) {
            local_180 = local_180 | 0x4000000;
          }
          if (local_16c != 0) {
            local_180 = local_180 | 0x8000000;
          }
          local_17c = local_17c + *(int *)(*(int *)param_1[1] + 0x18);
          if (local_184 != 0) {
            local_17c = local_17c + 1;
          }
          goto LAB_080555de;
        }
      }
    }
    if ((param_1[0xc] & 0x1000U) == 0) {
      uVar17 = param_1[8];
      if (0 < (int)uVar17) {
        pbVar20 = local_144;
        for (iVar14 = 0x10; iVar14 != 0; iVar14 = iVar14 + -1) {
          pbVar20[0] = 0;
          pbVar20[1] = 0;
          pbVar20[2] = 0;
          pbVar20[3] = 0;
          pbVar20 = pbVar20 + 4;
        }
        do {
          uVar11 = uVar17;
          if (0x40 < uVar17) {
            uVar11 = 0x40;
          }
          FUN_0804ec48(DAT_08069dc0,local_144,uVar11);
          DAT_08069dc0 = DAT_0806a0b0;
          uVar17 = uVar17 - uVar11;
        } while (0 < (int)uVar17);
      }
      if (((param_1 == DAT_08069ddc) && (0 < param_1[7])) && (DAT_08069dcc < pbVar7 + param_1[7])) {
        DAT_08069dc4 = DAT_08069dc0;
        strncpy(&DAT_08069e60,DAT_08069e50,0x1ff);
        DAT_0806a05f = 0;
      }
      FUN_0804ec48(DAT_08069dc0,pbVar7,param_1[7]);
      DAT_08069dc0 = DAT_0806a0b0;
      *(int *)(*(int *)param_1[1] + 0x18) =
           *(int *)(*(int *)param_1[1] + 0x18) + param_1[8] + param_1[7];
    }
    FUN_0804b434();
  }
  return;
}



char * FUN_08055704(char *param_1,char *param_2)

{
  char cVar1;
  
  do {
    cVar1 = *param_2;
    *param_1 = cVar1;
    param_2 = param_2 + 1;
    param_1 = param_1 + 1;
  } while (cVar1 != '\0');
  return param_1;
}



void FUN_08055720(void)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  ushort uVar4;
  uint *puVar5;
  uint uVar6;
  int *piVar7;
  undefined1 *puVar8;
  int iVar9;
  uint *puVar10;
  short sVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  char *pcVar15;
  undefined1 *puVar16;
  int iVar17;
  char *pcVar18;
  int *local_c8;
  int local_b4;
  uint *local_b0;
  int local_ac;
  short *local_a8;
  short *local_a4;
  uint *local_a0;
  uint *local_8c;
  int *local_88;
  int local_84;
  int local_80;
  char *local_78;
  char *local_74;
  char *local_70;
  uint *local_60;
  char *local_5c;
  char *local_58;
  uint *local_54;
  uint *local_4c;
  uint *local_48;
  uint *local_44;
  uint local_40;
  uint local_3c;
  uint local_38;
  uint local_34;
  int local_2c;
  uint local_28;
  undefined1 local_24;
  undefined1 local_21;
  uint local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_c;
  uint local_8;
  
  local_34 = 0;
  local_38 = 0;
  local_3c = 0;
  local_40 = 0;
  if (DAT_0806ab64 == 4) {
    local_54 = (uint *)0x0;
    local_58 = (char *)0x0;
    local_5c = (char *)0x0;
    puVar5 = &local_28;
    for (iVar9 = 9; iVar9 != 0; iVar9 = iVar9 + -1) {
      *puVar5 = 0;
      puVar5 = puVar5 + 1;
    }
    local_28 = FUN_0805e13c(0x240001);
    local_24 = 0;
    local_21 = 2;
    local_20 = FUN_0805e13c(*(uint *)(PTR_DAT_08068878 + 0x2c));
    local_1c = FUN_0805e13c(*(uint *)(PTR_DAT_0806887c + 0x30));
    local_18 = FUN_0805e13c(*(uint *)(PTR_DAT_08068878 + 0x14));
    local_14 = FUN_0805e13c(*(uint *)(PTR_DAT_0806887c + 0x18));
    local_c = FUN_0805e13c(DAT_0806a068 + 0x24 + DAT_0806a078 * 8);
    local_8 = FUN_0805e13c(DAT_0806a078);
    FUN_0804ec48(DAT_0806a07c + -0x24,(byte *)&local_28,0x24);
    puVar5 = (uint *)FUN_0804b3ac(DAT_0806a078 << 3);
    local_48 = (uint *)FUN_0804b3ac(DAT_0806a068);
    uVar6 = FUN_0805e13c(DAT_0806a068);
    *local_48 = uVar6;
    puVar10 = local_48 + 1;
    local_44 = puVar10;
    if ((DAT_0806ab70 & 0x420) == 0x400) {
      local_58 = FUN_08055704((char *)puVar10,"$$");
      local_5c = FUN_08055704(local_58,"$T");
      local_44 = (uint *)FUN_08055704(local_5c,"$A");
      local_54 = puVar10;
    }
    piVar7 = (int *)FUN_0804b134(&local_2c);
    local_4c = puVar5;
    while (piVar7 != (int *)0x0) {
      iVar9 = *piVar7;
      uVar6 = *(uint *)(iVar9 + 0x10);
      if ((uVar6 & 0x40000000) == 0) {
        iVar17 = *(int *)(iVar9 + 0xc);
        if (iVar17 == 0) {
          uVar12 = 0;
        }
        else {
          if ((*(byte *)(iVar17 + 0x34) & 0x40) != 0) goto LAB_08055a82;
          if ((*(uint *)(iVar17 + 0x30) & 0x1000) == 0) {
            if (((*(uint *)(iVar17 + 0x30) & 0x2000) == 0) || ((uVar6 & 0x100) != 0)) {
              uVar12 = 0x4000000;
            }
            else {
              uVar12 = 0x2000000;
            }
          }
          else {
            uVar12 = 0x6000000;
          }
        }
        if ((uVar6 & 3) != 1) {
          uVar12 = uVar12 | 0x1000000;
        }
        if ((uVar6 & 0x1100) == 0x1000) {
          uVar12 = uVar12 | 0x10000000;
        }
        if ((((*(char *)((int)piVar7 + 6) == '$') && ((DAT_0806ab70 & 0x420) == 0x400)) &&
            ((cVar2 = *(char *)((int)piVar7 + 7), cVar2 == '$' || ((cVar2 == 'T' || (cVar2 == 'A')))
             ))) && ((char)piVar7[2] == '\0')) {
          if (cVar2 == '$') {
            uVar6 = FUN_0805e13c((int)local_54 + ((uVar12 & 0x10000000) - (int)local_48) | 0x2000000
                                );
            *local_4c = uVar6;
          }
          else if (cVar2 == 'T') {
            uVar6 = FUN_0805e13c((uint)(local_58 + (0x10000000 - (int)local_48)) | 0x2000000);
            *local_4c = uVar6;
          }
          else if (cVar2 == 'A') {
            uVar6 = FUN_0805e13c((uint)(local_5c + (0x4000000 - (int)local_48)));
            *local_4c = uVar6;
          }
        }
        else {
          uVar6 = FUN_0805e13c((int)local_44 + (uVar12 - (int)local_48));
          *local_4c = uVar6;
          local_44 = (uint *)FUN_08055704((char *)local_44,(char *)((int)piVar7 + 6));
        }
        uVar6 = FUN_0805e13c(*(uint *)(iVar9 + 8));
        local_4c[1] = uVar6;
        local_4c = local_4c + 2;
      }
LAB_08055a82:
      piVar7 = (int *)FUN_0804b154(&local_2c);
    }
    if (DAT_0806a078 == 0) goto LAB_08056864;
    if (DAT_0806a078 != (int)local_4c - (int)puVar5 >> 3) {
      FUN_0805b0d8("2Phase error: symbol count different (middle = %ld, write = %ld)");
    }
    if (DAT_0806a068 != ((int)local_44 + (3 - (int)local_48) & 0xfffffffcU)) {
      FUN_0805b0d8("2Phase error: string table size different (middle = %ld, write = %ld)");
    }
    uVar6 = DAT_0806a078 << 3;
  }
  else {
    if (DAT_0806ab64 == 6) {
      local_70 = (char *)0x0;
      local_74 = (char *)0x0;
      local_78 = (char *)0x0;
      puVar5 = (uint *)FUN_0804b3ac((DAT_0806a078 + 1) * 0x10);
      puVar8 = (undefined1 *)FUN_0804b3ac(DAT_0806a068);
      *puVar8 = 0;
      pcVar18 = puVar8 + 1;
      if (((DAT_0806ab68 & 0x1800) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
        local_80 = 0;
        local_84 = 1;
        if (DAT_08069dac == (undefined4 *)0x0) {
          local_88 = (int *)0x0;
        }
        else {
          local_88 = (int *)*DAT_08069dac;
        }
        uVar6 = DAT_0806ab68;
        if (local_88 != (int *)0x0) {
          local_b4 = 0x28;
          do {
            if (((uVar6 & 0x1800) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
              local_80 = (int)DAT_0806a070 - DAT_0806a074;
              DAT_0806a070 = FUN_08055704(DAT_0806a070,(char *)local_88[6]);
              uVar6 = DAT_0806ab68;
            }
            iVar17 = local_b4;
            for (iVar9 = local_88[1]; iVar9 != 0; iVar9 = *(int *)(iVar9 + 0x60)) {
              if (((uVar6 & 0x1800) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
                if (*(int *)(iVar9 + 0x14) != 0) {
                  *(int *)(DAT_08069e3c + iVar17) = local_80;
                  iVar17 = iVar17 + 0x28;
                  local_b4 = local_b4 + 0x28;
                  local_84 = local_84 + 1;
                }
                if (*(int *)(iVar9 + 0x18) != 0) {
                  *(int *)(DAT_08069e3c + iVar17) = local_80;
                  iVar17 = iVar17 + 0x28;
                  local_b4 = local_b4 + 0x28;
                  local_84 = local_84 + 1;
                }
                if (*(int *)(iVar9 + 0x1c) != 0) {
                  *(int *)(DAT_08069e3c + iVar17) = local_80;
                  iVar17 = iVar17 + 0x28;
                  local_b4 = local_b4 + 0x28;
                  local_84 = local_84 + 1;
                }
                if ((DAT_0806ab70 & 0x400) != 0) {
                  iVar14 = 0;
                  iVar13 = *(int *)(iVar9 + 0x3c);
                  if (0 < iVar13) {
                    local_ac = local_b4;
                    do {
                      iVar3 = *(int *)(*(int *)(iVar9 + 0x10) + iVar14 * 4);
                      if (*(short *)(iVar3 + 0x30) < 0) {
                        *(int *)(DAT_08069e3c + local_ac) = (int)DAT_0806a070 - DAT_0806a074;
                        local_ac = local_ac + 0x28;
                        iVar17 = iVar17 + 0x28;
                        local_b4 = local_b4 + 0x28;
                        local_84 = local_84 + 1;
                        DAT_0806a070 = FUN_08055704(DAT_0806a070,(char *)(iVar3 + 0x46));
                        iVar13 = *(int *)(iVar9 + 0x3c);
                      }
                      iVar14 = iVar14 + 1;
                    } while (iVar14 < iVar13);
                  }
                }
              }
              uVar6 = DAT_0806ab68;
            }
            local_88 = (int *)*local_88;
          } while (local_88 != (int *)0x0);
        }
        if (((uVar6 & 0x1800) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
          iVar9 = (int)DAT_0806a070 - DAT_0806a074;
          pcVar15 = DAT_08069d98;
          if (DAT_08069dac != (undefined4 *)0x0) {
            pcVar15 = (char *)DAT_08069dac[6];
          }
          DAT_0806a070 = FUN_08055704(DAT_0806a070,pcVar15);
          if (*(int *)(PTR_DAT_08068878 + 0x14) != 0) {
            *(int *)(DAT_08069e3c + local_84 * 0x28) = iVar9;
            local_84 = local_84 + 1;
          }
          if (*(int *)(PTR_DAT_08068878 + 0x18) != 0) {
            *(int *)(DAT_08069e3c + local_84 * 0x28) = iVar9;
            local_84 = local_84 + 1;
          }
          if (*(int *)(PTR_DAT_08068878 + 0x1c) != 0) {
            *(int *)(DAT_08069e3c + local_84 * 0x28) = iVar9;
            local_84 = local_84 + 1;
          }
          if (((DAT_0806ab70 & 0x400) != 0) && (iVar9 = 0, 0 < DAT_08069d7c)) {
            local_84 = local_84 * 0x28;
            iVar17 = DAT_08069d7c;
            do {
              iVar13 = *(int *)(DAT_08069d50 + iVar9 * 4);
              if (*(short *)(iVar13 + 0x30) < 0) {
                *(int *)(DAT_08069e3c + local_84) = (int)DAT_0806a070 - DAT_0806a074;
                local_84 = local_84 + 0x28;
                DAT_0806a070 = FUN_08055704(DAT_0806a070,(char *)(iVar13 + 0x46));
                iVar17 = DAT_08069d7c;
              }
              iVar9 = iVar9 + 1;
            } while (iVar9 < iVar17);
          }
        }
      }
      uVar4 = DAT_08069e42;
      piVar7 = (int *)(DAT_08069e3c + (uint)DAT_08069e42 * 0x28);
      DAT_08069e42 = DAT_08069e42 + 1;
      piVar1 = (int *)(DAT_08069e3c + (uint)DAT_08069e42 * 0x28);
      DAT_08069e42 = uVar4 + 2;
      *(short *)(DAT_08069e34 + 0x32) = (short)(((int)piVar1 - DAT_08069e3c) * -0x33333333 >> 3);
      *piVar7 = (int)DAT_0806a070 - DAT_0806a074;
      DAT_0806a070 = FUN_08055704(DAT_0806a070,".symtab");
      piVar7[1] = 2;
      piVar7[2] = 0;
      piVar7[3] = 0;
      piVar7[6] = ((int)piVar1 - DAT_08069e3c) * -0x33333333 >> 3;
      *piVar1 = (int)DAT_0806a070 - DAT_0806a074;
      DAT_0806a070 = FUN_08055704(DAT_0806a070,".strtab");
      piVar1[1] = 3;
      piVar1[2] = 0;
      piVar1[3] = 0;
      piVar1[6] = 0;
      piVar1[7] = 0;
      local_44 = (uint *)pcVar18;
      if ((DAT_0806ab70 & 0x420) == 0x400) {
        local_74 = FUN_08055704(pcVar18,"$$");
        local_78 = FUN_08055704(local_74,"$T");
        local_44 = (uint *)FUN_08055704(local_78,"$A");
        local_70 = pcVar18;
      }
      *puVar5 = 0;
      puVar5[1] = 0;
      puVar5[2] = 0;
      *(undefined1 *)(puVar5 + 3) = 0;
      *(undefined1 *)((int)puVar5 + 0xd) = 0;
      *(undefined2 *)((int)puVar5 + 0xe) = 0;
      local_60 = puVar5 + 4;
      local_c8 = (int *)FUN_0804b134(&local_2c);
      if (local_c8 != (int *)0x0) {
        local_a8 = (short *)((int)puVar5 + 0x1e);
        puVar16 = (undefined1 *)((int)puVar5 + 0x1d);
        do {
          iVar9 = *local_c8;
          if (((*(uint *)(iVar9 + 0x10) & 0x40000000) == 0) &&
             ((iVar17 = *(int *)(iVar9 + 0xc), iVar17 == 0 ||
              ((*(byte *)(iVar17 + 0x34) & 0x40) == 0)))) {
            if ((*(char *)((int)local_c8 + 6) == '$') &&
               (((DAT_0806ab70 & 0x420) == 0x400 &&
                ((((cVar2 = *(char *)((int)local_c8 + 7), cVar2 == '$' || (cVar2 == 'T')) ||
                  (cVar2 == 'A')) && ((char)local_c8[2] == '\0')))))) {
              if (cVar2 == '$') {
                *local_60 = (int)local_70 - (int)puVar8;
              }
              else if (cVar2 == 'T') {
                *local_60 = (int)local_74 - (int)puVar8;
              }
              else if (cVar2 == 'A') {
                *local_60 = (int)local_78 - (int)puVar8;
              }
            }
            else {
              if ((*(uint *)(iVar9 + 0x10) & 3) != 1) goto LAB_0805629e;
              *local_60 = (int)local_44 - (int)puVar8;
              local_44 = (uint *)FUN_08055704((char *)local_44,(char *)((int)local_c8 + 6));
            }
            *(undefined4 *)(puVar16 + -9) = *(undefined4 *)(iVar9 + 8);
            *(undefined4 *)(puVar16 + -5) = 0;
            puVar16[-1] = 2;
            if ((*(byte *)(iVar9 + 0x11) & 0x10) != 0) {
              puVar16[-1] = 0xd;
            }
            if (iVar17 == 0) {
              if (*(char *)((int)local_c8 + 6) == '$') {
                cVar2 = *(char *)((int)local_c8 + 7);
                if ((cVar2 == '$') && ((char)local_c8[2] == '\0')) {
                  if ((*(uint *)(iVar9 + 0x10) & 0x1000) == 0) {
                    if ((*(uint *)(iVar9 + 0x10) & 0x100) == 0) {
                      puVar16[-1] = 2;
                      goto LAB_08056266;
                    }
LAB_08056262:
                    puVar16[-1] = 1;
                    goto LAB_08056266;
                  }
                }
                else if ((cVar2 != 'T') || ((char)local_c8[2] != '\0')) {
                  if ((cVar2 == 'A') && ((char)local_c8[2] == '\0')) goto LAB_08056262;
                  goto LAB_08056244;
                }
                puVar16[-1] = 0xd;
              }
              else {
LAB_08056244:
                puVar16[-1] = 0;
              }
            }
            else if (((*(byte *)(iVar17 + 0x31) & 2) == 0) || ((*(byte *)(iVar9 + 0x11) & 1) != 0))
            goto LAB_08056262;
LAB_08056266:
            *puVar16 = 0;
            if ((iVar17 == 0) || (sVar11 = *(short *)(**(int **)(iVar17 + 4) + 0x44), sVar11 == 0))
            {
              sVar11 = -0xf;
            }
            *local_a8 = sVar11;
            puVar16 = puVar16 + 0x10;
            local_a8 = local_a8 + 8;
            local_60 = local_60 + 4;
          }
LAB_0805629e:
          local_c8 = (int *)FUN_0804b154(&local_2c);
        } while (local_c8 != (int *)0x0);
      }
      piVar7[7] = (int)local_60 - (int)puVar5 >> 4;
      local_c8 = (int *)FUN_0804b134(&local_2c);
      if (local_c8 != (int *)0x0) {
        local_a4 = (short *)((int)local_60 + 0xe);
        puVar16 = (undefined1 *)((int)local_60 + 0xd);
        do {
          iVar9 = *local_c8;
          if (((((*(uint *)(iVar9 + 0x10) & 0x40000000) == 0) &&
               ((iVar17 = *(int *)(iVar9 + 0xc), iVar17 == 0 ||
                ((*(byte *)(iVar17 + 0x34) & 0x40) == 0)))) &&
              (((*(char *)((int)local_c8 + 6) != '$' ||
                (((cVar2 = *(char *)((int)local_c8 + 7), cVar2 != '$' && (cVar2 != 'T')) &&
                 (cVar2 != 'A')))) || ((char)local_c8[2] != '\0')))) &&
             ((*(uint *)(iVar9 + 0x10) & 3) != 1)) {
            *local_60 = (int)local_44 - (int)puVar8;
            local_44 = (uint *)FUN_08055704((char *)local_44,(char *)((int)local_c8 + 6));
            *(undefined4 *)(puVar16 + -9) = *(undefined4 *)(iVar9 + 8);
            *(undefined4 *)(puVar16 + -5) = 0;
            puVar16[-1] = 0x12;
            if ((*(byte *)(iVar9 + 0x11) & 0x10) != 0) {
              puVar16[-1] = 0x1d;
            }
            if (iVar17 == 0) {
              if (*(char *)((int)local_c8 + 6) == '$') {
                cVar2 = *(char *)((int)local_c8 + 7);
                if ((cVar2 == '$') && ((char)local_c8[2] == '\0')) {
                  if ((*(uint *)(iVar9 + 0x10) & 0x1000) == 0) {
                    if ((*(uint *)(iVar9 + 0x10) & 0x100) == 0) {
                      puVar16[-1] = 0x12;
                      goto LAB_08056436;
                    }
LAB_08056432:
                    puVar16[-1] = 0x11;
                    goto LAB_08056436;
                  }
                }
                else if ((cVar2 != 'T') || ((char)local_c8[2] != '\0')) {
                  if ((cVar2 == 'A') && ((char)local_c8[2] == '\0')) goto LAB_08056432;
                  goto LAB_08056414;
                }
                puVar16[-1] = 0x1d;
              }
              else {
LAB_08056414:
                puVar16[-1] = 0x10;
              }
            }
            else if (((*(byte *)(iVar17 + 0x31) & 2) == 0) || ((*(byte *)(iVar9 + 0x11) & 1) != 0))
            goto LAB_08056432;
LAB_08056436:
            *puVar16 = 0;
            if ((iVar17 == 0) || (sVar11 = *(short *)(**(int **)(iVar17 + 4) + 0x44), sVar11 == 0))
            {
              sVar11 = -0xf;
            }
            *local_a4 = sVar11;
            puVar16 = puVar16 + 0x10;
            local_a4 = local_a4 + 8;
            local_60 = local_60 + 4;
          }
          local_c8 = (int *)FUN_0804b154(&local_2c);
        } while (local_c8 != (int *)0x0);
      }
      uVar6 = (int)local_44 - (int)puVar8;
      while ((uVar6 & 3) != 0) {
        *(char *)local_44 = '\0';
        local_44 = (uint *)((int)local_44 + 1);
        uVar6 = (int)local_44 - (int)puVar8;
      }
      iVar9 = FUN_08060838(DAT_0806a0ac,(int)piVar7,puVar5,(int)local_60 - (int)puVar5 >> 4,0);
      if ((iVar9 != 0) ||
         (iVar9 = FUN_080606cc(DAT_0806a0ac,(int)piVar1,puVar8,uVar6,0), iVar9 != 0)) {
        FUN_0805b0d8("3Error writing %s.");
      }
      DAT_08069dc0 = ftell(DAT_0806a0ac);
      return;
    }
    puVar5 = (uint *)FUN_0804b3ac(DAT_0806a078 << 4);
    local_48 = (uint *)FUN_0804b3ac(DAT_0806a068);
    uVar6 = FUN_0805e13c(DAT_0806a068);
    *local_48 = uVar6;
    local_44 = local_48 + 1;
    if ((DAT_0806ab68 & 4) == 0) {
      if (*(int *)(PTR_DAT_08068878 + 0x14) != 0) {
        local_40 = (int)local_44 - (int)local_48;
        local_44 = (uint *)FUN_08055704((char *)local_44,"Image$$RO");
      }
      if (*(int *)(PTR_DAT_0806887c + 0x18) != 0) {
        local_3c = (int)local_44 - (int)local_48;
        local_44 = (uint *)FUN_08055704((char *)local_44,"Image$$RW");
      }
      if (*(int *)(PTR_DAT_0806887c + 0x1c) != 0) {
        local_38 = (int)local_44 - (int)local_48;
        local_44 = (uint *)FUN_08055704((char *)local_44,"Image$$ZI");
      }
      if ((DAT_0806ab70 & 0x400) != 0) {
        local_34 = (int)local_44 - (int)local_48;
        local_44 = (uint *)FUN_08055704((char *)local_44,"Image$$RW0");
      }
    }
    else {
      iVar9 = 0;
      if (0 < DAT_08069d7c) {
        do {
          iVar17 = *(int *)(DAT_08069d50 + iVar9 * 4);
          *(int *)(iVar17 + 0x18) = (int)local_44 - (int)local_48;
          local_44 = (uint *)FUN_08055704((char *)local_44,(char *)(*(int *)(iVar17 + 4) + 4));
          iVar9 = iVar9 + 1;
        } while (iVar9 < DAT_08069d7c);
      }
    }
    local_c8 = (int *)FUN_0804b134(&local_2c);
    if (local_c8 != (int *)0x0) {
      local_a0 = puVar5 + 3;
      local_b0 = puVar5 + 2;
      local_8c = puVar5;
      do {
        piVar7 = (int *)*local_c8;
        if (((((DAT_0806ab68 & 4) == 0) || ((DAT_0806ab70 & 0x400) != 0)) || ((piVar7[4] & 3U) != 1)
            ) && (((DAT_0806ab68 & 0x10) == 0 || ((*(byte *)((int)piVar7 + 0x13) & 3) != 0)))) {
          uVar6 = FUN_0805e13c((int)local_44 - (int)local_48);
          *local_8c = uVar6;
          if (((*(byte *)((int)piVar7 + 0x13) & 2) == 0) || (*piVar7 < 0)) {
            uVar6 = piVar7[2];
            iVar9 = piVar7[3];
          }
          else {
            uVar6 = *piVar7 * DAT_0806ac7c + *(int *)(DAT_0806ac74 + 0x2c);
            iVar9 = DAT_0806ac74;
          }
          uVar6 = FUN_0805e13c(uVar6);
          *local_b0 = uVar6;
          uVar6 = piVar7[4] & 0x80ffffff;
          if (((DAT_0806ab68 & 4) == 0) || (iVar9 == 0)) {
            uVar6 = uVar6 | 4;
          }
          uVar6 = FUN_0805e13c(uVar6);
          local_b0[-1] = uVar6;
          *local_a0 = 0;
          if (iVar9 != 0) {
            uVar6 = FUN_0805e13c(uVar6);
            if ((DAT_0806ab68 & 4) == 0) {
              if ((*(byte *)(iVar9 + 0x34) & 0x40) != 0) goto LAB_08056824;
              uVar12 = local_40;
              if ((((uVar6 & 0x200) == 0) && (uVar12 = local_34, -1 < (short)uVar6)) &&
                 (uVar12 = local_3c, (uVar6 & 0x1000) != 0)) {
                uVar12 = local_38;
              }
            }
            else {
              uVar6 = FUN_0805e13c(*local_b0);
              uVar6 = FUN_0805e13c(uVar6 - *(int *)(**(int **)(iVar9 + 4) + 0x2c));
              *local_b0 = uVar6;
              uVar12 = *(uint *)(**(int **)(iVar9 + 4) + 0x18);
            }
            uVar6 = FUN_0805e13c(uVar12);
            *local_a0 = uVar6;
          }
          local_44 = (uint *)FUN_08055704((char *)local_44,(char *)((int)local_c8 + 6));
          local_b0 = local_b0 + 4;
          local_a0 = local_a0 + 4;
          local_8c = local_8c + 4;
        }
LAB_08056824:
        local_c8 = (int *)FUN_0804b154(&local_2c);
      } while (local_c8 != (int *)0x0);
    }
    if (DAT_0806a078 == 0) goto LAB_08056864;
    uVar6 = DAT_0806a078 << 4;
  }
  FUN_0804ec48(DAT_0806a07c,(byte *)puVar5,uVar6);
LAB_08056864:
  if ((int)local_44 - (int)local_48 < (int)DAT_0806a068) {
    do {
      *(undefined1 *)local_44 = 0;
      local_44 = (uint *)((int)local_44 + 1);
    } while ((int)local_44 - (int)local_48 < (int)DAT_0806a068);
  }
  if (4 < (int)DAT_0806a068) {
    FUN_0804ec48(DAT_0806a080,(byte *)local_48,DAT_0806a068);
  }
  return;
}



void FUN_080568b0(void)

{
  char cVar1;
  int *piVar2;
  uint uVar3;
  char *pcVar4;
  int local_58;
  char local_54 [80];
  
  piVar2 = (int *)FUN_0804b134(&local_58);
  if (piVar2 != (int *)0x0) {
    do {
      sprintf(local_54,"#* %.8lx %.64s\n",*(ulong *)(*piVar2 + 8),(char *)((int)piVar2 + 6));
      uVar3 = 0xffffffff;
      pcVar4 = local_54;
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      FUN_0804eacc(local_54,~uVar3 - 1);
      piVar2 = (int *)FUN_0804b154(&local_58);
    } while (piVar2 != (int *)0x0);
  }
  return;
}



void FUN_08056914(int param_1)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  uint local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  char local_14 [12];
  uint local_8;
  
  local_24 = FUN_0805e13c((uint)((*(int *)(*DAT_0806a094 + 8) + -0xc) -
                                (*(int *)(param_1 + 0x28) * 4 + *(int *)(param_1 + 0x40))) >> 2 &
                          0xffffff | 0xeb000000);
  local_20 = FUN_0805e13c(*(int *)(param_1 + 0x28) * 4);
  local_1c = FUN_0805e13c(*(uint *)(param_1 + 0x44));
  local_18 = FUN_0805e13c(*(uint *)(param_1 + 0x48));
  pcVar4 = *(char **)(param_1 + 0x58);
  uVar3 = 0;
  cVar1 = *pcVar4;
  while (cVar1 != '\0') {
    pcVar4 = pcVar4 + 1;
    if (uVar3 < 10) {
      local_14[uVar3] = cVar1;
    }
    uVar3 = uVar3 + 1;
    if (cVar1 == '/') {
      uVar3 = 0;
    }
    cVar1 = *pcVar4;
  }
  for (; uVar3 < 0xc; uVar3 = uVar3 + 1) {
    local_14[uVar3] = '\0';
  }
  local_8 = FUN_0805e13c(*(int *)(*(int *)(param_1 + 0x4c) + 8) << 2);
  FUN_0804ec48(DAT_0806a0b0,(byte *)&local_24,0x20);
  for (iVar2 = **(int **)(param_1 + 0x4c); iVar2 != 0; iVar2 = *(int *)(iVar2 + 0x54)) {
    if (iVar2 != param_1) {
      if ((((byte)DAT_0806ab68 & 1) == 0) && ((DAT_0806ab70._2_1_ & 0x10) == 0)) {
        local_28 = *(int *)(iVar2 + 0x28) * 4 + *(int *)(iVar2 + 0x40) + 8;
      }
      else {
        local_28 = (*(int *)(iVar2 + 0x40) - *(int *)(param_1 + 0x40)) +
                   (*(int *)(iVar2 + 0x28) - *(int *)(param_1 + 0x28)) * 4;
      }
      local_28 = FUN_0805e13c(local_28);
      FUN_0804ec48(DAT_0806a0b0,(byte *)&local_28,4);
    }
  }
  return;
}



void FUN_08056a64(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  uint local_8;
  
  local_8 = FUN_0805e13c(0xe50fe008);
  for (piVar2 = DAT_08069d90; piVar2 != (int *)0x0; piVar2 = (int *)piVar2[1]) {
    for (iVar1 = *piVar2; iVar1 != 0; iVar1 = *(int *)(iVar1 + 0x54)) {
      if ((*(byte *)(iVar1 + 0x68) & 1) != 0) {
        iVar3 = *(int *)(iVar1 + 0x28);
        if (-1 < iVar3) {
          do {
            iVar3 = iVar3 + -1;
            FUN_0804ec48(DAT_0806a0b0,(byte *)&local_8,4);
          } while (-1 < iVar3);
        }
        FUN_08056914(iVar1);
      }
    }
  }
  return;
}



void FUN_08056af0(int param_1)

{
  int *piVar1;
  int iVar2;
  uint local_c;
  int local_8;
  
  iVar2 = *(int *)(param_1 + 0x40) + 0xc;
  piVar1 = (int *)FUN_0804b134(&local_8);
  while (piVar1 != (int *)0x0) {
    piVar1 = (int *)*piVar1;
    if ((-1 < *piVar1) && (*(int *)(piVar1[3] + 0x10) == param_1)) {
      local_c = piVar1[2] - iVar2;
      iVar2 = iVar2 + 4;
      if (((byte)DAT_0806ab68 & 1) != 0) {
        FUN_08053994(DAT_0806a0b0 + 0x70000000);
        local_c = local_c + DAT_0806ab98;
      }
      local_c = FUN_0805e13c((int)local_c >> 2 & 0xffffffU | 0xea000000);
      FUN_0804ec48(DAT_0806a0b0,(byte *)&local_c,4);
    }
    piVar1 = (int *)FUN_0804b154(&local_8);
  }
  return;
}



void FUN_08056b98(int param_1)

{
  int iVar1;
  byte *pbVar2;
  int *piVar3;
  uint uVar4;
  uint local_10;
  int local_c;
  uint local_8;
  
  local_8 = FUN_0805e13c(DAT_0806ac84);
  FUN_0804ec48(DAT_0806a0b0,(byte *)&local_8,4);
  if ((DAT_0806ab70._2_1_ & 8) != 0) {
    FUN_0805b0d8("0Size of EFT parameter block = %u bytes");
    FUN_0805b0d8("0The EFT has %lu entries");
  }
  if (DAT_0806ac84 != 0) {
    FUN_0804b418();
    pbVar2 = (byte *)FUN_0804b3ac(DAT_0806ac84 * 4);
    piVar3 = (int *)FUN_0804b134(&local_c);
    while (piVar3 != (int *)0x0) {
      piVar3 = (int *)*piVar3;
      if (((piVar3[4] & 0x2000000U) != 0) && (iVar1 = *piVar3, -1 < iVar1)) {
        uVar4 = piVar3[2] - (*(int *)(param_1 + 0x48) - *(int *)(param_1 + 0x44));
        if ((piVar3[4] & 0x800U) == 0) {
          uVar4 = uVar4 + 4;
        }
        uVar4 = FUN_0805e13c(uVar4);
        *(uint *)(pbVar2 + iVar1 * 4) = uVar4;
        if ((DAT_0806ab70._2_1_ & 8) != 0) {
          FUN_0805b0d8("0    eft[%3lu] = 0x%6lx %s");
        }
      }
      piVar3 = (int *)FUN_0804b154(&local_c);
    }
    FUN_0804ec48(DAT_0806a0b0,pbVar2,DAT_0806ac84 * 4);
    FUN_0804b434();
  }
  if (DAT_0806ac80 != '\0') {
    local_10 = FUN_0805e13c(*(uint *)(*DAT_0806ac58 + 8));
    FUN_0804ec48(DAT_0806a0b0,(byte *)&local_10,4);
    DAT_08069dbc = DAT_0806a0b0;
    FUN_0804ecc0(DAT_0806a0a4);
    local_10 = FUN_0805e13c(0xffffffff);
    FUN_0804ec48(DAT_0806a0b0,(byte *)&local_10,4);
  }
  FUN_0804ec48(DAT_0806a0b0,DAT_0806891c,DAT_08068920);
  return;
}



void FUN_08056d40(char *param_1,char *param_2)

{
  size_t __n;
  char cVar1;
  char *pcVar2;
  FILE *__stream;
  uint uVar3;
  
  if (DAT_0806a0ac != (FILE *)0x0) {
    FUN_08060ec8(DAT_0806a0ac);
  }
  if ((((param_2 == (char *)0x0) || (*param_2 == '\0')) || ((DAT_0806ab68 & 0x40) == 0)) ||
     ((DAT_0806ab68 & 0x402) == 0)) {
    DAT_08069e50 = param_1;
  }
  else {
    uVar3 = 0xffffffff;
    pcVar2 = param_1;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    __n = ~uVar3 - 1;
    uVar3 = 0xffffffff;
    pcVar2 = param_2;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    pcVar2 = (char *)FUN_0804b1e8(__n + ~uVar3);
    memcpy(pcVar2,param_1,__n);
    memcpy(pcVar2 + __n,param_2,~uVar3);
    DAT_08069e50 = pcVar2;
  }
  if ((DAT_0806ab68 & 2) == 0) {
    pcVar2 = "wb";
  }
  else {
    pcVar2 = "w";
  }
  __stream = FUN_08060e7c(DAT_08069e50,pcVar2);
  DAT_0806a0ac = __stream;
  if (__stream == (FILE *)0x0) {
    FUN_0805b0d8("3Can\'t open file \'%s\'.");
  }
  setvbuf(__stream,DAT_0806a0b4,0,DAT_0806a0b8);
  return;
}



void FUN_08056e40(void)

{
  if (DAT_0806a0ac != (FILE *)0x0) {
    FUN_08060ec8(DAT_0806a0ac);
    if ((DAT_0806ac54 != 0) || (DAT_0806ac50 != 0)) {
      remove(DAT_08069e50);
      FUN_0805af4c("%s: garbage output file %s removed\n");
    }
    DAT_0806a0ac = (FILE *)0x0;
  }
  return;
}



void FUN_08056e94(void)

{
  undefined4 *puVar1;
  
  FUN_08056e40();
  for (puVar1 = DAT_0806ab9c; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
    if (-1 < (int)puVar1[6]) {
      close(puVar1[6]);
    }
  }
  return;
}



void FUN_08056ecc(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  *param_1 = 1;
  param_1[1] = 0;
  param_1[4] = param_2;
  param_1[5] = param_3;
  param_1[6] = param_4;
  param_1[7] = 4;
  param_1[2] = 0;
  param_1[3] = 0;
  return;
}



void FUN_08056f0c(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = param_2;
  return;
}



void FUN_08056f40(char *param_1,ulong param_2)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  time_t local_58;
  char local_54 [80];
  
  sprintf(local_54,"# Created by %s [%s]\n","5.20 (ARM Ltd SDT2.51)","Jun 23 2000");
  uVar3 = 0xffffffff;
  pcVar2 = local_54;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  FUN_0804eacc(local_54,~uVar3 - 1);
  time(&local_58);
  pcVar2 = ctime(&local_58);
  sprintf(local_54,"#         on %s",pcVar2);
  uVar3 = 0xffffffff;
  pcVar2 = local_54;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  FUN_0804eacc(local_54,~uVar3 - 1);
  sprintf(local_54,"# %s segment based at 0x%lx\n\n",param_1,param_2);
  uVar3 = 0xffffffff;
  pcVar2 = local_54;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  FUN_0804eacc(local_54,~uVar3 - 1);
  return;
}



void FUN_08056fe4(undefined *param_1)

{
  int iVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  int *piVar5;
  char *pcVar6;
  uint *puVar7;
  uint uVar8;
  uint uVar9;
  undefined4 *puVar10;
  int iVar11;
  undefined4 *puVar12;
  uint uVar13;
  byte *pbVar14;
  int local_1074;
  int local_106c;
  int local_1068;
  int local_1064;
  undefined4 *local_1060;
  undefined4 *local_105c;
  undefined4 *local_1058;
  int local_1054;
  byte local_1044 [63];
  char cStack_1005;
  undefined2 local_1004;
  char local_1002 [4094];
  
  if ((DAT_0806ab68 & 4) == 0) {
    local_1004 = 0x2121;
    local_1002[0] = '\0';
    for (iVar11 = *(int *)(param_1 + 8); iVar11 != 0; iVar11 = *(int *)(iVar11 + 8)) {
      FUN_0804b710(local_1002,(char *)(*(int *)(iVar11 + 4) + 4),0xffe);
      uVar9 = 0xffffffff;
      pcVar6 = (char *)&local_1004;
      do {
        if (uVar9 == 0) break;
        uVar9 = uVar9 - 1;
        cVar2 = *pcVar6;
        pcVar6 = pcVar6 + 1;
      } while (cVar2 != '\0');
      iVar1 = ~uVar9 - 1;
      FUN_0804b710((char *)((int)&local_1004 + iVar1),"$$Base",0x1000 - iVar1);
      piVar5 = FUN_0804b030((char *)&local_1004,DAT_0806ab74);
      if (piVar5 != (int *)0x0) {
        if (*(uint *)(iVar11 + 0x2c) < *(uint *)(*piVar5 + 8)) {
          *(uint *)(*piVar5 + 8) = *(uint *)(iVar11 + 0x2c);
        }
      }
      FUN_0804b710((char *)((int)&local_1004 + iVar1),"$$Limit",0x1000 - iVar1);
      piVar5 = FUN_0804b030((char *)&local_1004,DAT_0806ab74);
      if (piVar5 != (int *)0x0) {
        uVar9 = *(int *)(iVar11 + 0x1c) + *(int *)(iVar11 + 0x2c);
        if (*(uint *)(*piVar5 + 8) < uVar9) {
          *(uint *)(*piVar5 + 8) = uVar9;
        }
      }
    }
  }
  FUN_0804b418();
  if ((DAT_0806ab68 & 0x1000) == 0) {
    FUN_08056d40(*(char **)(param_1 + 0x58),DAT_0806a060);
    DAT_08069dc0 = 0;
    DAT_0806a0b0 = 0;
  }
  FUN_0804fbb0(param_1);
  if ((DAT_0806ab68 & 2) != 0) {
    FUN_08056f40(&DAT_08064afc,DAT_0806ab98);
  }
  DAT_0806a0a8 = FUN_0804b5e4(8);
  DAT_0806a0a4 = FUN_0804b5e4(4);
  local_105c = (undefined4 *)0xffffff00;
  local_1058 = (undefined4 *)0xffffff00;
  local_1060 = (undefined4 *)0xffffff00;
  local_1064 = 0;
  local_1068 = 0;
  local_106c = 0;
  while( true ) {
    if (DAT_0806ab64 == 6) {
      if (*(int *)(param_1 + 100) == 0) {
        iVar11 = *(int *)(param_1 + 0x44);
      }
      else {
        iVar11 = *(int *)(*(int *)(param_1 + 100) + 0xc);
      }
      if (*(int *)(param_1 + 0x14) != 0) {
        local_1058 = (undefined4 *)((uint)DAT_08069e40 * 0x20 + DAT_08069e38);
        DAT_08069e40 = DAT_08069e40 + 1;
        FUN_08056ecc(local_1058,*(undefined4 *)(param_1 + 0x14),*(undefined4 *)(param_1 + 0x14),5);
        local_1058[2] = iVar11;
        if (((DAT_0806ab68 & 0x1800) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
          local_1064 = DAT_08069e3c + (uint)DAT_08069e42 * 0x28;
          DAT_08069e42 = DAT_08069e42 + 1;
          FUN_08056f0c(local_1064,*(undefined4 *)(param_1 + 0x14));
          *(undefined4 *)(local_1064 + 4) = 1;
          *(undefined4 *)(local_1064 + 8) = 0x20000006;
          *(int *)(local_1064 + 0xc) = iVar11;
        }
        iVar11 = iVar11 + *(int *)(param_1 + 0x14);
      }
      if (*(int *)(param_1 + 0x18) != 0) {
        local_105c = (undefined4 *)((uint)DAT_08069e40 * 0x20 + DAT_08069e38);
        DAT_08069e40 = DAT_08069e40 + 1;
        FUN_08056ecc(local_105c,*(undefined4 *)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x18),6);
        local_105c[2] = iVar11;
        if (((DAT_0806ab68 & 0x1800) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
          local_1068 = DAT_08069e3c + (uint)DAT_08069e42 * 0x28;
          DAT_08069e42 = DAT_08069e42 + 1;
          FUN_08056f0c(local_1068,*(undefined4 *)(param_1 + 0x18));
          *(undefined4 *)(local_1068 + 4) = 1;
          *(undefined4 *)(local_1068 + 8) = 0x20000003;
          *(int *)(local_1068 + 0xc) = iVar11;
        }
        iVar11 = iVar11 + *(int *)(param_1 + 0x18);
      }
      if (*(int *)(param_1 + 0x1c) != 0) {
        local_1060 = (undefined4 *)((uint)DAT_08069e40 * 0x20 + DAT_08069e38);
        DAT_08069e40 = DAT_08069e40 + 1;
        FUN_08056ecc(local_1060,0,*(undefined4 *)(param_1 + 0x1c),6);
        local_1060[2] = iVar11;
        if (((DAT_0806ab68 & 0x1800) != 0) || ((DAT_0806ab70 & 0x400) != 0)) {
          local_106c = DAT_08069e3c + (uint)DAT_08069e42 * 0x28;
          DAT_08069e42 = DAT_08069e42 + 1;
          FUN_08056f0c(local_106c,*(undefined4 *)(param_1 + 0x1c));
          *(undefined4 *)(local_106c + 4) = 8;
          *(undefined4 *)(local_106c + 8) = 0x20000003;
          *(int *)(local_106c + 0xc) = iVar11;
        }
      }
      if (*(int *)(param_1 + 100) != 0) {
        *(int *)(*(int *)(param_1 + 100) + 0xc) = iVar11;
      }
    }
    if (param_1 != PTR_DAT_08068878) {
      DAT_08069dbc = *(int *)(param_1 + 0x18) + *(int *)(param_1 + 0x14) + *(int *)(param_1 + 0x1c);
    }
    local_1054 = 0;
    iVar11 = 0;
    puVar3 = *(undefined4 **)(param_1 + 0xc);
    puVar10 = puVar3 + *(int *)(param_1 + 0x38);
    uVar9 = DAT_08069dc0;
    uVar8 = DAT_0806a0b0;
    for (; DAT_08069dc0 = uVar9, DAT_0806a0b0 = uVar8, puVar3 < puVar10; puVar3 = puVar3 + 1) {
      piVar5 = (int *)*puVar3;
      if ((((-1 < (short)piVar5[0xc]) || ((DAT_0806ab70 & 0x400) != 0)) || ((DAT_0806ab68 & 4) != 0)
          ) && (0 < piVar5[7])) {
        if ((((DAT_0806ab68 & 0x40) != 0) && ((DAT_0806ab68 & 0x402) != 0)) &&
           ((*(int *)(param_1 + 0x30) == piVar5[0xb] &&
            ((*(byte *)((int)piVar5 + 0x31) & 0x20) == 0)))) {
          FUN_08056d40(*(char **)(param_1 + 0x58),DAT_0806a064);
          DAT_0806a0b0 = 0;
          DAT_08069dc0 = 0;
          if ((DAT_0806ab68 & 2) != 0) {
            FUN_08056f40(&DAT_08064aff,DAT_0806abdc);
            DAT_0806abb0 = 0;
          }
        }
        if (DAT_0806ab64 == 6) {
          iVar1 = *(int *)piVar5[1];
          if (((local_1054 != iVar1) &&
              (iVar11 = 0, local_1054 = iVar1, (DAT_0806ab70 & 0x400) != 0)) &&
             (*(short *)(iVar1 + 0x30) < 0)) {
            *(ushort *)(iVar1 + 0x44) = DAT_08069e42;
            iVar11 = DAT_08069e3c + (uint)DAT_08069e42 * 0x28;
            DAT_08069e42 = DAT_08069e42 + 1;
            *(undefined4 *)(iVar11 + 4) = 1;
            *(undefined4 *)(iVar11 + 8) = 0x40000000;
            *(undefined4 *)(iVar11 + 0x18) = 0;
            *(undefined4 *)(iVar11 + 0x1c) = 0;
            *(uint *)(iVar11 + 0x10) = DAT_08069dc0;
            *(undefined4 *)(iVar11 + 0x14) = 0;
          }
          if (iVar11 != 0) {
            *(int *)(iVar11 + 0x14) = *(int *)(iVar11 + 0x14) + piVar5[7];
          }
          if (-1 < (short)piVar5[0xc]) {
            local_1074 = local_1064;
            puVar12 = local_1058;
            if (((piVar5[0xc] & 0x2000U) == 0) &&
               (local_1074 = local_1068, puVar12 = local_105c, (piVar5[0xc] & 0x1000U) != 0)) {
              local_1074 = local_106c;
              puVar12 = local_1060;
            }
            *(short *)(local_1054 + 0x44) = (short)((local_1074 - DAT_08069e3c) * -0x33333333 >> 3);
            uVar9 = DAT_08069dc0;
            if ((puVar12[1] == 0) && (puVar12[1] = DAT_08069dc0, local_1074 != 0)) {
              *(uint *)(local_1074 + 0x10) = uVar9;
            }
          }
        }
        FUN_08054258(piVar5);
      }
      uVar9 = DAT_08069dc0;
      uVar8 = DAT_0806a0b0;
    }
    if (0 < DAT_0806a08c) {
      if (param_1 == PTR_DAT_0806887c) {
        FUN_08056a64();
        DAT_08069dc0 = DAT_0806a0b0;
        iVar11 = DAT_0806a0b0 - uVar8;
        if ((DAT_0806ab70 & 0x400) != 0) {
          puVar3 = *(undefined4 **)(param_1 + 0xc);
          puVar10 = puVar3 + *(int *)(param_1 + 0x38);
          DAT_08069dc0 = DAT_0806a0b0;
          for (; puVar3 < puVar10; puVar3 = puVar3 + 1) {
            piVar5 = (int *)*puVar3;
            if ((short)piVar5[0xc] < 0) {
              piVar5[0xb] = piVar5[0xb] + iVar11;
              FUN_08054258(piVar5);
            }
          }
        }
      }
      else if ((param_1[0x68] & 1) != 0) {
        if (((DAT_0806ab64 == 6) && (0 < *(int *)(param_1 + 0x18))) && (local_105c[1] == 0)) {
          *(uint *)(local_1068 + 0x10) = uVar9;
          local_105c[1] = uVar9;
        }
        FUN_08056af0((int)param_1);
        DAT_08069dc0 = DAT_0806a0b0;
      }
    }
    FUN_0804ecc0(DAT_0806a0a8);
    if (((DAT_0806ab68 & 0x1400) == 0x400) && ((DAT_0806ab70 & 1) == 0)) {
      uVar9 = *(uint *)(param_1 + 0x1c);
      pbVar14 = local_1044;
      for (iVar11 = 0x10; iVar11 != 0; iVar11 = iVar11 + -1) {
        pbVar14[0] = 0;
        pbVar14[1] = 0;
        pbVar14[2] = 0;
        pbVar14[3] = 0;
        pbVar14 = pbVar14 + 4;
      }
      for (; 0x40 < uVar9; uVar9 = uVar9 - 0x40) {
        FUN_0804ec48(DAT_0806a0b0,local_1044,0x40);
      }
      FUN_0804ec48(DAT_0806a0b0,local_1044,uVar9);
    }
    if (((DAT_0806ab68 & 4) != 0) && (param_1 == PTR_DAT_08068878)) {
      FUN_0804fc0c();
    }
    if ((DAT_0806a06c != 0) && (param_1 == PTR_DAT_08068878)) {
      DAT_0806a06c = DAT_0806a06c + 4 & 0xfffffffc;
      DAT_0806a070 = (char *)FUN_0804b3ac(DAT_0806a06c);
      DAT_0806a074 = DAT_0806a070;
      *DAT_0806a070 = 0;
      DAT_0806a070 = DAT_0806a070 + 1;
    }
    if ((DAT_0806ab68 & 2) != 0) break;
    if ((((DAT_0806ab70 & 0x400) == 0) && ((DAT_0806ab68 & 4) == 0)) ||
       (param_1 != PTR_DAT_08068878)) {
      if ((((DAT_0806ab68 & 0x10) != 0) && (param_1 != PTR_DAT_08068878)) &&
         (FUN_08056b98((int)param_1), (DAT_0806ab68 & 0x2000) != 0)) {
        param_1 = PTR_DAT_08068878;
      }
      goto LAB_08057962;
    }
    FUN_08055720();
    if ((DAT_0806ab68 & 0x2000) == 0) goto LAB_08057962;
    param_1 = (undefined *)*DAT_08069d90;
    DAT_08069d90 = (int *)0x0;
    if ((DAT_0806a0b0 & 3) != 0) {
      FUN_0804ec48(DAT_0806a0b0,&DAT_08063972,4 - (DAT_0806a0b0 & 3));
    }
    DAT_08069dc0 = DAT_0806a0b0;
    uVar9 = FUN_0805e13c(*(int *)(param_1 + 0x14) + (DAT_0806ac84 + 1) * 4 + DAT_08068920);
    *(uint *)(DAT_0806a088 * 0x10 + DAT_08069de8 + 0x18) = uVar9;
  }
  FUN_0804eacc(":00 0000 01 FF\n\n",0x10);
  if ((DAT_0806ab70 & 0x400) != 0) {
    FUN_080568b0();
  }
LAB_08057962:
  if ((DAT_0806a06c != 0) && (param_1 == PTR_DAT_08068878)) {
    piVar5 = (int *)(DAT_08069e3c + (uint)DAT_08069e42 * 0x28);
    DAT_08069e42 = DAT_08069e42 + 1;
    *(short *)(DAT_08069e34 + 0x32) = (short)(((int)piVar5 - DAT_08069e3c) * -0x33333333 >> 3);
    *piVar5 = (int)DAT_0806a070 - (int)DAT_0806a074;
    pcVar6 = FUN_08055704(DAT_0806a070,".shstrtab");
    DAT_0806a070 = pcVar6;
    piVar5[1] = 3;
    piVar5[2] = 0;
    piVar5[3] = 0;
    piVar5[6] = 0;
    piVar5[7] = 0;
    uVar9 = (int)pcVar6 - (int)DAT_0806a074;
    while ((uVar9 & 3) != 0) {
      *pcVar6 = '\0';
      DAT_0806a070 = DAT_0806a070 + 1;
      pcVar6 = DAT_0806a070;
      uVar9 = (int)DAT_0806a070 - (int)DAT_0806a074;
    }
    iVar11 = FUN_080606cc(DAT_0806a0ac,(int)piVar5,DAT_0806a074,(int)pcVar6 - (int)DAT_0806a074,0);
    if (iVar11 != 0) {
      FUN_0805b0d8("3Error writing %s.");
    }
    DAT_08069dc0 = ftell(DAT_0806a0ac);
  }
  if ((DAT_0806ab68 & 1) != 0) {
    if ((DAT_0806ab68 & 0x600) == 0) {
      if (param_1 == PTR_DAT_08068878) {
        iVar11 = FUN_0804b91c(PTR_DAT_08068868);
        if (iVar11 == 0) {
          FUN_0804ec48(DAT_08069dc8,PTR_DAT_08068868,DAT_0806886c);
        }
        else {
          FUN_0804b418();
          puVar7 = (uint *)FUN_0804b3ac(DAT_0806886c);
          FUN_0804edf0(puVar7,(uint *)PTR_DAT_08068868,DAT_0806886c);
          FUN_0804ec48(DAT_08069dc8,(byte *)puVar7,DAT_0806886c);
          FUN_0804b434();
        }
      }
    }
    else {
      FUN_0805e13c(DAT_08069de4);
      FUN_0804eca0();
    }
    FUN_0804ecc0(DAT_0806a0a4);
    if ((DAT_0806ab68 & 0x600) == 0) {
      FUN_0804eca0();
    }
  }
  uVar9 = DAT_080687ac;
  puVar4 = PTR_DAT_080687a8;
  if ((DAT_0806ab68 & 8) != 0) {
    uVar13 = DAT_080687ac & 0xfffffffc;
    uVar8 = FUN_0805e13c(DAT_0806ab98 + DAT_08069dc8);
    *(uint *)(puVar4 + (uVar13 - 8)) = uVar8;
    uVar8 = FUN_0805e13c(DAT_0806ab98);
    *(uint *)(puVar4 + (uVar13 - 4)) = uVar8;
    FUN_0804ec48(DAT_08069dc8,PTR_DAT_080687a8,uVar9);
    FUN_0804ecc0(DAT_0806a0a4);
    FUN_0804eca0();
    FUN_0804eca0();
    FUN_0804eca0();
  }
  if (((DAT_0806ab64 == 6) || ((DAT_0806ab68 & 4) != 0)) && (param_1 == PTR_DAT_08068878)) {
    FUN_0804fc30();
  }
  if ((DAT_0806ab68 & 0x1000) == 0) {
    FUN_08056e40();
  }
  FUN_0804b434();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08057c70(void)

{
  char cVar1;
  undefined4 *puVar2;
  undefined *puVar3;
  uint uVar4;
  undefined1 *puVar5;
  int *piVar6;
  char *__dest;
  uint local_130;
  uint local_12c;
  uint local_128;
  char local_124 [31];
  char local_105 [257];
  
  if ((DAT_0806ab68._1_1_ & 4) == 0) {
    FUN_08056d40(DAT_0806abc8,DAT_0806a060);
    DAT_0806a0b0 = 0;
    if ((DAT_0806ab64 != 6) &&
       (DAT_08069dc0 = *(int *)(PTR_DAT_08068878 + 0x18) + 0x80 + *(int *)(PTR_DAT_08068878 + 0x14),
       (DAT_0806ab70._1_1_ & 4) != 0)) {
      DAT_08069dc0 = DAT_08069dc0 + _DAT_08069d60 + 0x24 + DAT_0806a078 * 8 + DAT_0806a068;
    }
    for (piVar6 = (int *)*DAT_08069dac; piVar6 != (int *)0x0; piVar6 = (int *)*piVar6) {
      if (DAT_0806ab64 != 6) {
        if (*piVar6 == 0) {
          local_130 = 0;
        }
        else {
          local_130 = FUN_0805e13c(piVar6[5] + DAT_08069dc0 + 0x2c);
        }
        local_12c = FUN_0805e13c(piVar6[3]);
        local_128 = FUN_0805e13c(piVar6[5]);
        strncpy(local_124,(char *)piVar6[6],0x1f);
        local_105[0] = '\0';
        FUN_0804ec48(DAT_08069dc0,(byte *)&local_130,0x2c);
      }
      for (puVar3 = (undefined *)piVar6[1]; puVar3 != (undefined *)0x0;
          puVar3 = *(undefined **)(puVar3 + 0x60)) {
        FUN_08056fe4(puVar3);
      }
    }
    if (DAT_0806ab64 != 6) {
      DAT_08069dc0 = 0;
    }
    puVar5 = &stack0xfffffeb8;
    FUN_08056fe4(PTR_DAT_08068878);
  }
  else {
    __dest = local_105 + 1;
    strcpy(__dest,DAT_0806abc8);
    strcat(__dest,"/");
    uVar4 = 0xffffffff;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *__dest;
      __dest = __dest + 1;
    } while (cVar1 != '\0');
    for (puVar2 = (undefined4 *)*DAT_08069dac; puVar2 != (undefined4 *)0x0;
        puVar2 = (undefined4 *)*puVar2) {
      if ((((DAT_0806ab70._2_1_ & 0x40) == 0) || ((undefined *)puVar2[1] != PTR_DAT_0806887c)) ||
         ((undefined *)puVar2[1] == PTR_DAT_08068878)) {
        strcpy(local_105 + ~uVar4,(char *)puVar2[6]);
        FUN_08056d40(local_105 + 1,DAT_0806a060);
        DAT_08069dc0 = 0;
        DAT_0806a0b0 = 0;
        for (puVar3 = (undefined *)puVar2[1]; puVar3 != (undefined *)0x0;
            puVar3 = *(undefined **)(puVar3 + 0x60)) {
          FUN_08056fe4(puVar3);
        }
        FUN_08056e40();
      }
    }
    strcpy(local_105 + ~uVar4,(char *)DAT_08069dac[6]);
    FUN_08056d40(local_105 + 1,DAT_0806a060);
    DAT_08069dc0 = 0;
    DAT_0806a0b0 = 0;
    FUN_08056fe4(PTR_DAT_08068878);
    puVar5 = &stack0xfffffebc;
    if (((DAT_0806ab70._2_1_ & 0x40) != 0) &&
       (puVar5 = &stack0xfffffebc, PTR_DAT_0806887c != PTR_DAT_08068878)) {
      FUN_08056fe4(PTR_DAT_0806887c);
      puVar5 = &stack0xfffffebc;
    }
  }
  *(undefined **)(puVar5 + -4) = PTR_DAT_08068878;
  *(undefined4 *)(puVar5 + -8) = 0x8057f2d;
  FUN_08056e40();
  return;
}



void FUN_08057f38(int param_1)

{
  char *param0;
  char cVar1;
  int *piVar2;
  int *piVar3;
  char *pcVar4;
  uint uVar5;
  uint uVar6;
  char *param4;
  int *piVar7;
  ulong param3;
  ulong local_110;
  char acStack_106 [258];
  
  FUN_0805af4c("AREA map of %s:\n\n");
  FUN_0805af4c("Base     Size     Type RO? Name\n");
  piVar2 = *(int **)(param_1 + 0xc);
  piVar7 = piVar2 + *(int *)(param_1 + 0x38);
  do {
    if (piVar7 <= piVar2) {
      FUN_0805af70("\n");
      return;
    }
    piVar3 = (int *)*piVar2;
    local_110 = piVar3[0xb];
    param3 = piVar3[7];
    if (param3 != 0) {
      param0 = acStack_106 + 2;
      if (((byte)DAT_0806ab68 & 8) != 0) {
        local_110 = local_110 - DAT_0806ab98;
      }
      if (0 < piVar3[8]) {
        if ((*(byte *)((int)piVar3 + 0x31) & 0x20) == 0) {
          pcVar4 = "RW";
        }
        else {
          pcVar4 = "RO";
        }
        sprintf(param0,"%-8lx %-8lx PAD  %s  %s",local_110 - piVar3[8],piVar3[8],pcVar4,
                (char *)((int)piVar3 + 0x46));
        uVar5 = 0xffffffff;
        pcVar4 = param0;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          cVar1 = *pcVar4;
          pcVar4 = pcVar4 + 1;
        } while (cVar1 != '\0');
        pcVar4 = acStack_106 + ~uVar5 + 1;
        if (*piVar3 != 0) {
          sprintf(pcVar4," from object file %s",*(char **)(*piVar3 + 4));
          uVar6 = 0xffffffff;
          do {
            if (uVar6 == 0) break;
            uVar6 = uVar6 - 1;
            cVar1 = *pcVar4;
            pcVar4 = pcVar4 + 1;
          } while (cVar1 != '\0');
          pcVar4 = acStack_106 + ~uVar6 + ~uVar5;
        }
        pcVar4[0] = '\n';
        pcVar4[1] = '\0';
        FUN_0805af70(param0);
        param3 = piVar3[7];
      }
      uVar5 = piVar3[0xc];
      if ((uVar5 & 0x2000) == 0) {
        pcVar4 = "RW";
      }
      else {
        pcVar4 = "RO";
      }
      if ((uVar5 & 0x200) == 0) {
        if ((uVar5 & 0x1000) == 0) {
          if ((short)piVar3[0xc] < 0) {
            param4 = "DBUG";
          }
          else {
            param4 = "DATA";
          }
        }
        else {
          param4 = "ZERO";
        }
      }
      else {
        param4 = "CODE";
      }
      sprintf(param0,"%-8lx %-8lx %s %s  %s",local_110,param3,param4,pcVar4,
              (char *)((int)piVar3 + 0x46));
      uVar5 = 0xffffffff;
      pcVar4 = param0;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      pcVar4 = acStack_106 + ~uVar5 + 1;
      if (*piVar3 != 0) {
        sprintf(pcVar4," from object file %s",*(char **)(*piVar3 + 4));
        uVar6 = 0xffffffff;
        do {
          if (uVar6 == 0) break;
          uVar6 = uVar6 - 1;
          cVar1 = *pcVar4;
          pcVar4 = pcVar4 + 1;
        } while (cVar1 != '\0');
        pcVar4 = acStack_106 + ~uVar6 + ~uVar5;
      }
      pcVar4[0] = '\n';
      pcVar4[1] = '\0';
      FUN_0805af70(param0);
    }
    piVar2 = piVar2 + 1;
  } while( true );
}



int FUN_0805815c(int param_1,int param_2)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined4 *local_10;
  
  iVar3 = param_1 + -4;
  iVar4 = 1;
  do {
    iVar4 = iVar4 * 3 + 1;
  } while (iVar4 <= param_2);
  do {
    iVar5 = iVar4 * 0x55555556;
    iVar4 = iVar4 / 3;
    iVar8 = iVar4 + 1;
    if (iVar8 <= param_2) {
      local_10 = (undefined4 *)(iVar3 + iVar8 * 4);
      do {
        piVar1 = (int *)*local_10;
        uVar2 = *(uint *)(*piVar1 + 8);
        iVar5 = iVar8;
        if (iVar4 < iVar8) {
          uVar6 = *(uint *)(**(int **)(iVar3 + (iVar8 - iVar4) * 4) + 8);
          iVar7 = iVar8;
          while ((uVar2 < uVar6 ||
                 ((iVar5 = iVar7, uVar6 == uVar2 &&
                  (*(char *)(*(int *)(iVar3 + (iVar7 - iVar4) * 4) + 6) == '$'))))) {
            iVar5 = iVar7 - iVar4;
            *(undefined4 *)(iVar3 + iVar7 * 4) = *(undefined4 *)(iVar3 + iVar5 * 4);
            if (iVar5 <= iVar4) break;
            uVar6 = *(uint *)(**(int **)(iVar3 + (iVar5 - iVar4) * 4) + 8);
            iVar7 = iVar5;
          }
        }
        *(int **)(iVar3 + iVar5 * 4) = piVar1;
        local_10 = local_10 + 1;
        iVar8 = iVar8 + 1;
        iVar5 = iVar3;
      } while (iVar8 <= param_2);
    }
    if (iVar4 < 2) {
      return iVar5;
    }
  } while( true );
}



void FUN_08058240(int param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  char *pcVar8;
  char *pcVar9;
  int *piVar10;
  char *pcVar11;
  bool bVar12;
  int local_144;
  int local_140;
  int local_13c;
  int local_138;
  int local_12c;
  int local_128;
  undefined4 local_124;
  char local_120 [256];
  int local_20 [4];
  int local_10;
  int local_c;
  int local_8;
  
  piVar10 = local_20;
  for (iVar6 = 7; iVar6 != 0; iVar6 = iVar6 + -1) {
    *piVar10 = 0;
    piVar10 = piVar10 + 1;
  }
  local_12c = 0;
  if (1 < *(int *)(param_1 + 0x1c)) {
    FUN_0805815c(*(int *)(param_1 + 0x20),*(int *)(param_1 + 0x1c));
  }
  local_124 = 0;
  iVar6 = *(int *)(param_1 + 0x24);
  if (0 < iVar6) {
    do {
      piVar10 = *(int **)(*(int *)(param_1 + 0x28) + local_124 * 4);
      if (((piVar10 != (int *)0x0) && ((*(byte *)(piVar10 + 0xd) & 0x40) == 0)) &&
         (*piVar10 == param_1)) {
        iVar2 = piVar10[7];
        uVar7 = piVar10[0xc];
        if ((uVar7 & 0x200) == 0) {
          if ((short)piVar10[0xc] < 0) {
            local_8 = local_8 + iVar2;
          }
          else if ((uVar7 & 0x1000) == 0) {
            if ((uVar7 & 0x800) != 0) goto LAB_0805850f;
            if ((uVar7 & 0x2000) == 0) {
              local_10 = local_10 + iVar2;
            }
            else {
              local_20[3] = local_20[3] + iVar2;
            }
          }
          else {
            local_c = local_c + iVar2;
          }
          iVar6 = *(int *)(param_1 + 0x24);
        }
        else {
          local_138 = 0;
          local_13c = 0;
          local_140 = 0;
          local_144 = -1;
          local_128 = 0;
          if (0 < *(int *)(param_1 + 0x1c)) {
            do {
              piVar3 = *(int **)(*(int *)(param_1 + 0x20) + local_128 * 4);
              uVar7 = *(uint *)(*piVar3 + 8);
              uVar4 = piVar10[0xb];
              if ((uVar4 <= uVar7) && (uVar7 < iVar2 + uVar4)) {
                pcVar8 = (char *)((int)piVar3 + 6);
                iVar6 = uVar7 - uVar4;
                if ((local_144 < 0) || (iVar5 = strncmp(pcVar8,"x$litpool_e$",0xc), iVar5 != 0)) {
                  if (*pcVar8 == '$') {
                    if (*(char *)((int)piVar3 + 7) == 'S') {
                      iVar6 = __strtol_internal(piVar3 + 2,0,10,0);
                      uVar7 = iVar6 + 3U & 0xfffffffc;
                      local_140 = local_140 + uVar7;
                      local_12c = local_12c + uVar7;
                    }
                  }
                  else {
                    iVar5 = 0xc;
                    bVar12 = true;
                    pcVar9 = pcVar8;
                    pcVar11 = "x$constdata";
                    do {
                      if (iVar5 == 0) break;
                      iVar5 = iVar5 + -1;
                      bVar12 = *pcVar9 == *pcVar11;
                      pcVar9 = pcVar9 + 1;
                      pcVar11 = pcVar11 + 1;
                    } while (bVar12);
                    if (bVar12) {
                      local_138 = iVar2 - iVar6;
                      break;
                    }
                    iVar5 = strncmp(pcVar8,"x$litpool$",10);
                    if (iVar5 == 0) {
                      local_12c = 0;
                      local_144 = iVar6;
                    }
                  }
                }
                else {
                  local_13c = local_13c + (((iVar6 + 3U & 0xfffffffc) - local_144) - local_12c);
                  local_144 = -1;
                }
              }
              local_128 = local_128 + 1;
            } while (local_128 < *(int *)(param_1 + 0x1c));
          }
          local_20[3] = local_20[3] + local_138;
          local_20[1] = local_20[1] + local_13c;
          local_20[2] = local_20[2] + local_140;
          local_20[0] = local_20[0] + (((iVar2 - local_138) - local_13c) - local_140);
          iVar6 = *(int *)(param_1 + 0x24);
        }
      }
LAB_0805850f:
      local_124 = local_124 + 1;
    } while (local_124 < iVar6);
  }
  if ((DAT_0806ab6c & 1) != 0) {
    sprintf(local_120,"%-16s",*(char **)(param_1 + 4));
    uVar7 = 0xffffffff;
    pcVar8 = local_120;
    do {
      if (uVar7 == 0) break;
      uVar7 = uVar7 - 1;
      cVar1 = *pcVar8;
      pcVar8 = pcVar8 + 1;
    } while (cVar1 != '\0');
    pcVar8 = local_120 + (~uVar7 - 1);
    uVar7 = 0xffffffff;
    pcVar9 = *(char **)(param_1 + 4);
    do {
      if (uVar7 == 0) break;
      uVar7 = uVar7 - 1;
      cVar1 = *pcVar9;
      pcVar9 = pcVar9 + 1;
    } while (cVar1 != '\0');
    if (0x10 < ~uVar7 - 1) {
      pcVar8[0] = '\n';
      pcVar8[1] = '\0';
      FUN_0805af70(local_120);
      sprintf(local_120,"%-16c",' ');
      uVar7 = 0xffffffff;
      pcVar8 = local_120;
      do {
        if (uVar7 == 0) break;
        uVar7 = uVar7 - 1;
        cVar1 = *pcVar8;
        pcVar8 = pcVar8 + 1;
      } while (cVar1 != '\0');
      pcVar8 = local_120 + (~uVar7 - 1);
    }
    sprintf(pcVar8," %7ld  %7ld  %7ld  %7ld  %7ld  %7ld  %7ld\n",local_20[0],local_20[1],local_20[2]
            ,local_20[3],local_10,local_c,local_8);
    FUN_0805af70(local_120);
  }
  *param_2 = *param_2 + local_20[0];
  param_2[1] = param_2[1] + local_20[1];
  param_2[2] = param_2[2] + local_20[2];
  param_2[3] = param_2[3] + local_20[3];
  param_2[4] = param_2[4] + local_10;
  param_2[5] = param_2[5] + local_c;
  param_2[6] = param_2[6] + local_8;
  return;
}



void FUN_08058604(undefined4 *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  
  bVar1 = false;
  iVar3 = DAT_08068870 + DAT_08068874;
  DAT_0806a140 = 0;
  DAT_0806a13c = 0;
  DAT_0806a138 = 0;
  DAT_0806a134 = 0;
  DAT_0806a130 = 0;
  DAT_0806a12c = 0;
  DAT_0806a128 = 0;
  DAT_0806a15c = 0;
  DAT_0806a158 = 0;
  DAT_0806a154 = 0;
  DAT_0806a150 = 0;
  DAT_0806a14c = 0;
  DAT_0806a148 = 0;
  DAT_0806a144 = 0;
  puVar2 = param_1;
  if ((DAT_0806ab6c & 1) != 0) {
    FUN_0805af70(
                "object file         code   inline   inline  \'const\'       RW   0-Init    debug\n"
                );
    FUN_0805af70("%-20csize     data  strings     data     data     data     data\n");
  }
  for (; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
    if ((*(byte *)(puVar2[2] + 4) & 2) == 0) {
      FUN_08058240((int)puVar2,&DAT_0806a128);
    }
    else {
      bVar1 = true;
    }
  }
  if (bVar1) {
    if ((DAT_0806ab6c & 1) != 0) {
      FUN_0805af70("\n");
      FUN_0805af70(
                  "library member      code   inline   inline  \'const\'       RW   0-Init    debug\n"
                  );
      FUN_0805af70("%-20csize     data  strings     data     data     data     data\n");
    }
    for (; param_1 != (undefined4 *)0x0; param_1 = (undefined4 *)*param_1) {
      if ((*(byte *)(param_1[2] + 4) & 2) != 0) {
        FUN_08058240((int)param_1,&DAT_0806a144);
      }
    }
  }
  if ((DAT_0806ab6c & 1) != 0) {
    FUN_0805af70("\n");
  }
  FUN_0805af70("%-20ccode   inline   inline  \'const\'       RW   0-Init    debug\n");
  FUN_0805af70("%-20csize     data  strings     data     data     data     data\n");
  FUN_0805af70("Object totals    %7ld  %7ld  %7ld  %7ld  %7ld  %7ld  %7ld\n");
  if (bVar1) {
    FUN_0805af70("Library totals   %7ld  %7ld  %7ld  %7ld  %7ld  %7ld  %7ld\n");
    FUN_0805af70("Grand totals     %7ld  %7ld  %7ld  %7ld  %7ld  %7ld  %7ld\n");
  }
  if (iVar3 != 0) {
    FUN_0805af70("\n\nDebug Area Optimization Statistics\n\n");
    FUN_0805af70("Input debug total(excluding low level debug areas)\t%ld (%.2fKb)\n");
    FUN_0805af70("Output debug total\t\t\t\t\t%ld (%.2fKb)\n");
    FUN_0805af70("%% reduction  \t\t\t\t\t\t%.2f%%\n\n");
  }
  return;
}



void FUN_080588f0(void)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  char *pcVar5;
  uint uVar6;
  uint uVar7;
  char *pcVar8;
  int iVar9;
  char *pcVar10;
  undefined4 local_108;
  char local_104 [256];
  
  FUN_0805af4c("\nSymbol Table\n\n");
  piVar4 = (int *)FUN_0804b134(&local_108);
  do {
    if (piVar4 == (int *)0x0) {
      FUN_0805af70("\n");
      return;
    }
    iVar2 = *piVar4;
    piVar3 = *(int **)(iVar2 + 0xc);
    if (((*(byte *)(iVar2 + 0x13) & 0x40) == 0) &&
       ((piVar3 == (int *)0x0 || ((*(byte *)(piVar3 + 0xd) & 0x40) == 0)))) {
      sprintf(local_104,"%-24s",(char *)((int)piVar4 + 6));
      uVar6 = 0xffffffff;
      pcVar8 = local_104;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        cVar1 = *pcVar8;
        pcVar8 = pcVar8 + 1;
      } while (cVar1 != '\0');
      pcVar8 = local_104 + (~uVar6 - 1);
      if ((DAT_0806ab70._2_1_ & 0x80) != 0) {
        sprintf(pcVar8," %08lx",*(ulong *)(iVar2 + 0x10));
        uVar7 = 0xffffffff;
        do {
          if (uVar7 == 0) break;
          uVar7 = uVar7 - 1;
          cVar1 = *pcVar8;
          pcVar8 = pcVar8 + 1;
        } while (cVar1 != '\0');
        pcVar8 = local_104 + ~uVar7 + ~uVar6 + -2;
      }
      if ((*(uint *)(iVar2 + 0x10) & 1) == 0) {
        if ((*(uint *)(iVar2 + 0x10) & 0x10) == 0) {
          pcVar10 = " ?????? Undefined, Reference";
        }
        else {
          pcVar10 = " ?????? Undefined, WEAK Reference";
        }
        sprintf(pcVar8,pcVar10);
        uVar6 = 0xffffffff;
        pcVar10 = pcVar8;
        do {
          if (uVar6 == 0) break;
          uVar6 = uVar6 - 1;
          cVar1 = *pcVar10;
          pcVar10 = pcVar10 + 1;
        } while (cVar1 != '\0');
        pcVar8 = pcVar8 + (~uVar6 - 1);
        iVar9 = *(int *)(iVar2 + 0x18);
      }
      else {
        sprintf(pcVar8," %06lx",*(ulong *)(iVar2 + 8));
        uVar6 = 0xffffffff;
        pcVar10 = pcVar8;
        do {
          if (uVar6 == 0) break;
          uVar6 = uVar6 - 1;
          cVar1 = *pcVar10;
          pcVar10 = pcVar10 + 1;
        } while (cVar1 != '\0');
        pcVar8 = pcVar8 + (~uVar6 - 1);
        iVar9 = 0;
        if (piVar3 != (int *)0x0) {
          if ((DAT_0806ab68 & 4) == 0) {
            if (((undefined *)piVar3[4] != PTR_DAT_08068878) && ((DAT_0806ab68 & 0x801) == 0x801)) {
              pcVar10 = *(char **)((undefined *)piVar3[4] + 0x58);
              pcVar5 = strrchr(pcVar10,0x2f);
              if (pcVar5 != (char *)0x0) {
                pcVar10 = pcVar5 + 1;
              }
              sprintf(pcVar8," + |%s|",pcVar10);
              uVar6 = 0xffffffff;
              pcVar10 = pcVar8;
              do {
                if (uVar6 == 0) break;
                uVar6 = uVar6 - 1;
                cVar1 = *pcVar10;
                pcVar10 = pcVar10 + 1;
              } while (cVar1 != '\0');
              pcVar8 = pcVar8 + (~uVar6 - 1);
            }
          }
          else {
            sprintf(pcVar8," + |%s|",(char *)((int)piVar3 + 0x46));
            uVar6 = 0xffffffff;
            pcVar10 = pcVar8;
            do {
              if (uVar6 == 0) break;
              uVar6 = uVar6 - 1;
              cVar1 = *pcVar10;
              pcVar10 = pcVar10 + 1;
            } while (cVar1 != '\0');
            pcVar8 = pcVar8 + (~uVar6 - 1);
            iVar9 = *piVar3;
          }
        }
      }
      if ((iVar9 != 0) && ((DAT_0806ab68 & 4) != 0)) {
        sprintf(pcVar8," from object file %s",(char *)(*(int *)(iVar9 + 8) + 0x24));
        uVar6 = 0xffffffff;
        pcVar10 = pcVar8;
        do {
          if (uVar6 == 0) break;
          uVar6 = uVar6 - 1;
          cVar1 = *pcVar10;
          pcVar10 = pcVar10 + 1;
        } while (cVar1 != '\0');
        pcVar8 = pcVar8 + (~uVar6 - 1);
        if ((*(byte *)(*(int *)(iVar9 + 8) + 4) & 2) != 0) {
          sprintf(pcVar8,"(%s)",*(char **)(iVar9 + 4));
          uVar6 = 0xffffffff;
          pcVar10 = pcVar8;
          do {
            if (uVar6 == 0) break;
            uVar6 = uVar6 - 1;
            cVar1 = *pcVar10;
            pcVar10 = pcVar10 + 1;
          } while (cVar1 != '\0');
          pcVar8 = pcVar8 + (~uVar6 - 1);
        }
      }
      if ((*(uint *)(iVar2 + 0x10) & 0x21) == 0x21) {
        sprintf(pcVar8," [strong]");
        uVar6 = 0xffffffff;
        pcVar10 = pcVar8;
        do {
          if (uVar6 == 0) break;
          uVar6 = uVar6 - 1;
          cVar1 = *pcVar10;
          pcVar10 = pcVar10 + 1;
        } while (cVar1 != '\0');
        pcVar8 = pcVar8 + (~uVar6 - 1);
      }
      pcVar8[0] = '\n';
      pcVar8[1] = '\0';
      FUN_0805af70(local_104);
    }
    piVar4 = (int *)FUN_0804b154(&local_108);
  } while( true );
}



void FUN_08058bac(void)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  uint uVar5;
  uint uVar6;
  char *pcVar7;
  char *pcVar8;
  undefined4 local_108;
  char local_104 [256];
  
  FUN_0805af4c("\nNon-Strong Symbols\n\n");
  piVar4 = (int *)FUN_0804b134(&local_108);
  do {
    if (piVar4 == (int *)0x0) {
      return;
    }
    iVar2 = *piVar4;
    piVar3 = *(int **)(iVar2 + 0xc);
    if (((*(uint *)(iVar2 + 0x10) & 0x41000021) == 1) &&
       (((piVar3 == (int *)0x0 || ((*(byte *)(piVar3 + 0xd) & 0x40) == 0)) &&
        ((short)piVar4[1] == 0x2121)))) {
      sprintf(local_104,"%-24s %06lx",(char *)((int)piVar4 + 6),*(ulong *)(iVar2 + 8));
      uVar5 = 0xffffffff;
      pcVar7 = local_104;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar7 + 1;
      } while (cVar1 != '\0');
      pcVar7 = (char *)((int)&local_108 + ~uVar5 + 3);
      if (piVar3 != (int *)0x0) {
        iVar2 = *piVar3;
        sprintf(pcVar7," in area |%s|",(char *)((int)piVar3 + 0x46));
        uVar6 = 0xffffffff;
        do {
          if (uVar6 == 0) break;
          uVar6 = uVar6 - 1;
          cVar1 = *pcVar7;
          pcVar7 = pcVar7 + 1;
        } while (cVar1 != '\0');
        pcVar7 = (char *)((int)&local_108 + ~uVar6 + ~uVar5 + 2);
        if (iVar2 != 0) {
          sprintf(pcVar7," from object file %s",(char *)(*(int *)(iVar2 + 8) + 0x24));
          uVar5 = 0xffffffff;
          pcVar8 = pcVar7;
          do {
            if (uVar5 == 0) break;
            uVar5 = uVar5 - 1;
            cVar1 = *pcVar8;
            pcVar8 = pcVar8 + 1;
          } while (cVar1 != '\0');
          pcVar7 = pcVar7 + (~uVar5 - 1);
          if ((*(byte *)(*(int *)(iVar2 + 8) + 4) & 2) != 0) {
            sprintf(pcVar7,"(%s)",*(char **)(iVar2 + 4));
            uVar5 = 0xffffffff;
            pcVar8 = pcVar7;
            do {
              if (uVar5 == 0) break;
              uVar5 = uVar5 - 1;
              cVar1 = *pcVar8;
              pcVar8 = pcVar8 + 1;
            } while (cVar1 != '\0');
            pcVar7 = pcVar7 + (~uVar5 - 1);
          }
        }
      }
      pcVar7[0] = '\n';
      pcVar7[1] = '\0';
      FUN_0805af70(local_104);
    }
    piVar4 = (int *)FUN_0804b154(&local_108);
  } while( true );
}



void FUN_08058d28(void)

{
  char *pcVar1;
  FILE *__stream;
  byte *pbVar2;
  uint uVar3;
  
  if (DAT_0806a0ac != (FILE *)0x0) {
    FUN_08060ec8(DAT_0806a0ac);
  }
  if (((byte)DAT_0806ab68 & 2) == 0) {
    pcVar1 = "r+b";
  }
  else {
    pcVar1 = "r+";
  }
  __stream = FUN_08060e7c(&DAT_08069e60,pcVar1);
  DAT_0806a0ac = __stream;
  if (__stream == (FILE *)0x0) {
    FUN_0805b0d8("3Can\'t open file \'%s\'.");
  }
  setvbuf(__stream,DAT_0806a0b4,0,DAT_0806a0b8);
  DAT_08069dc0 = 0;
  DAT_0806a0b0 = 0;
  FUN_0804bc68(*DAT_08069ddc);
  uVar3 = DAT_08069ddc[7];
  pbVar2 = FUN_0804bd58(DAT_08069ddc[6],DAT_08069ddc[7]);
  FUN_0804ec48(DAT_08069dc4,pbVar2,uVar3);
  FUN_08060ec8(__stream);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08058de8(void)

{
  DAT_0806a0b4 = FUN_0804b1e8(0x2000);
  DAT_0806a0b8 = 0x2000;
  DAT_0806a09c = FUN_0804b5e4(0xc);
  DAT_0806a0a0 = 0;
  _DAT_08069d24 = 0;
  DAT_08069d28 = "<anon>";
  DAT_0806891c = 0;
  DAT_08068920 = 0;
  DAT_0806ac7c = 0;
  DAT_0806ac6c = 0;
  DAT_0806ac74 = 0;
  DAT_0806ac84 = 0;
  DAT_0806a120 = 0;
  DAT_0806a118 = 0;
  _DAT_0806a114 = 0;
  DAT_0806a124 = 0;
  DAT_0806a11c = 0;
  DAT_08069db0 = 0;
  DAT_08069db4 = 0;
  DAT_08069db8 = 0;
  DAT_08069dc8 = 0;
  DAT_08069dc0 = 0;
  DAT_08069dbc = 0;
  DAT_08069dc4 = 0xffffffff;
  DAT_08069dcc = 0;
  DAT_08069dd0 = 0;
  PTR_DAT_0806887c = (undefined *)&DAT_08069d40;
  PTR_DAT_08068878 = (undefined *)&DAT_08069d40;
  DAT_08069dac = 0;
  DAT_08069dd4 = 0;
  DAT_08069ddc = 0;
  DAT_08069dd8 = 0;
  DAT_08069de4 = 0;
  DAT_08069de0 = 0;
  DAT_08069de8 = 0;
  DAT_08069dec = 0;
  DAT_08069df4 = 0;
  DAT_08069df0 = 0;
  DAT_08069e34 = &DAT_08069e00;
  DAT_08069e38 = 0;
  DAT_08069e3c = 0;
  DAT_08069e42 = 0;
  DAT_08069e40 = 0;
  DAT_08069e4c = 0;
  _DAT_08069e48 = 0;
  DAT_08069e44 = 0;
  DAT_08069e50 = 0;
  DAT_08069e60 = 0;
  DAT_0806a060 = &DAT_08065036;
  DAT_0806a064 = &DAT_0806503a;
  DAT_0806a06c = 0;
  DAT_0806a068 = 0;
  DAT_0806a074 = 0;
  DAT_0806a070 = 0;
  DAT_0806a078 = 0;
  DAT_0806a088 = 0;
  _DAT_0806a084 = 0;
  DAT_0806a080 = 0;
  DAT_0806a07c = 0;
  _DAT_0806a090 = 0;
  DAT_0806a08c = 0;
  DAT_0806a094 = DAT_0806a098;
  DAT_0806abb4 = 0;
  return;
}



void FUN_08059060(void)

{
  char cVar1;
  int *piVar2;
  undefined *puVar3;
  undefined4 uVar4;
  int *extraout_EAX;
  int *extraout_EAX_00;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  char *pcVar8;
  char *pcVar9;
  char acStack_105 [257];
  
  FUN_08050780((int *)PTR_DAT_08068878,DAT_0806abc8,"root");
  if ((DAT_0806ab68 & 0x10) == 0) {
    if ((DAT_0806ab68 & 0x1800) != 0) {
      FUN_0804c360("Overlay$$Data",0,0,0,0,0,0x800,0);
      FUN_0804c360("Root$$OverlayInfo",0,0,0,0,0,0x2000,0);
      DAT_0806a0a0 = extraout_EAX;
      puVar7 = FUN_0804c360("IWV$$Code",0,0,0,0,0,0x2200,0);
      DAT_08069ddc = extraout_EAX_00;
      *(byte *)(extraout_EAX_00 + 0xd) = *(byte *)(extraout_EAX_00 + 0xd) | 0x20;
      if ((DAT_0806ab68 & 0x1000) == 0) {
        if ((DAT_0806ab68 & 0x800) != 0) {
          FUN_08050fa4();
          goto LAB_0805915a;
        }
LAB_08059165:
        if ((DAT_0806ab68 & 0x1400) == 0x1400) goto LAB_08059173;
      }
      else {
        FUN_0805bf30(DAT_0806aba4);
        DAT_0806ab98 = *(undefined4 *)(DAT_08069dac + 0xc);
LAB_0805915a:
        if ((DAT_0806ab68 & 0x800) == 0) goto LAB_08059165;
LAB_08059173:
        mkdir(DAT_0806abc8,0x1fd);
      }
      if (0 < DAT_0806a08c) {
        puVar7[7] = 0x400;
        FUN_0804ff1c(DAT_0806a0a0);
        DAT_0806a094 = FUN_0804b030("!!Image$$load_seg",DAT_0806ab74);
        if (DAT_0806a094 == (int *)0x0) {
          DAT_0806a094 = (int *)FUN_0804c234("Image$$load_seg",2,"!!");
        }
        DAT_0806a098 = FUN_0804b030("!!Image$$overlay_init",DAT_0806ab74);
        if (DAT_0806a098 == (int *)0x0) {
          DAT_0806a098 = (int *)FUN_0804c234("Image$$overlay_init",2,"!!");
        }
      }
    }
  }
  else {
    FUN_0805d254();
    FUN_0805cf54();
    FUN_08051480();
    FUN_0805ca44();
  }
  if (DAT_0806ab7c != (int *)0x0) {
    if ((DAT_0806ab70 & 8) != 0) {
      DAT_0806ab70 = DAT_0806ab70 & 0xfffffffb;
      goto LAB_08059252;
    }
    if (((DAT_0806ab64 == 4) && ((DAT_0806ab68 & 0x600) == 0)) && (DAT_0806ab6d == '\0'))
    goto LAB_08059252;
  }
  DAT_0806ab70 = DAT_0806ab70 | 4;
LAB_08059252:
  FUN_080529b8();
  piVar2 = DAT_0806ab88;
  if ((DAT_0806ab70 & 0x1000) != 0) {
    FUN_0805af4c("\nInter-AREA References\n\n");
    piVar2 = DAT_0806ab88;
  }
  for (; piVar2 != (int *)0x0; piVar2 = (int *)piVar2[2]) {
    FUN_08051d7c(piVar2);
  }
  if ((DAT_0806ab70 & 0x1000) != 0) {
    FUN_0805af70("\n");
  }
  if (((0 < DAT_0806a08c) && (DAT_0806ab7c != (int *)0x0)) && (*(int *)(*DAT_0806a098 + 0xc) != 0))
  {
    FUN_08051934((int)DAT_0806ab7c,*(int *)(*DAT_0806a098 + 0xc),(int)DAT_0806a098);
  }
  if (((DAT_0806ab70 & 4) == 0) &&
     ((FUN_08051ff0(), (DAT_0806ab70 & 0x80000) != 0 || ((DAT_0806ab6c & 0x10) != 0)))) {
    FUN_0805b0d8("0%d bytes of unused areas omitted.");
  }
  FUN_08053448();
  for (piVar2 = DAT_0806ab88; piVar2 != (int *)0x0; piVar2 = (int *)piVar2[2]) {
    FUN_08051a24(piVar2);
  }
  DAT_08069ddc = FUN_0804fdd4(DAT_08069ddc);
  FUN_0805171c();
  FUN_080517a8();
  if (((DAT_0806ab68 & 0x1000) != 0) && (0 < DAT_0806a08c)) {
    FUN_08050e10();
  }
  FUN_08052c80();
  if (DAT_0806ab64 == 6) {
    DAT_0806a068 = 1;
  }
  else {
    DAT_0806a068 = 4;
  }
  if ((DAT_0806ab70 & 0x420) == 0x400) {
    DAT_0806a068 = DAT_0806a068 + 9;
    DAT_0806a078 = DAT_0806a078 + (DAT_0806a124 + DAT_0806a120) * 2;
  }
  FUN_080535b4((DAT_0806ab70 >> 2 ^ 1) & 1);
  if ((DAT_0806ab68 & 4) == 0) {
    if ((DAT_0806ab70 & 0x100) == 0) {
      if (((DAT_0806ab70 & 0x200) == 0) || (DAT_0806ab7c == (int *)0x0)) {
        if (((DAT_0806ab68 & 0x600) == 0) && (DAT_0806ab64 == 4)) {
          pcVar9 = "3No entry point for image.";
        }
        else {
          pcVar9 = "1No entry point for image.";
        }
        FUN_0805b0d8(pcVar9);
      }
      else {
        FUN_0804ed00(DAT_0806abbc + DAT_0806ab7c[0xb]);
      }
    }
    else {
      if ((DAT_0806ab7c != (int *)0x0) && (DAT_0806abbc + DAT_0806ab7c[0xb] != DAT_0806aba0)) {
        FUN_0805b0d8("2Conflict between -entry option and ENTRY in AREA %s(%s)");
      }
      FUN_0804ed00(DAT_0806aba0);
    }
  }
  pcVar9 = DAT_0806ac44;
  uVar4 = DAT_0806ac08;
  DAT_0806ac08 = uVar4;
  DAT_0806ac44 = pcVar9;
  if ((DAT_0806ab70 & 0x10000) != 0) {
    if ((DAT_0806abac != (char *)0x0) &&
       ((DAT_0806ac44 == (char *)0x0 ||
        (iVar5 = FUN_0804b6c0(DAT_0806abac,DAT_0806ac44), iVar5 != 0)))) {
      DAT_0806ac08 = 0;
      DAT_0806ac44 = DAT_0806abac;
    }
    FUN_080588f0();
    DAT_0806ac44 = pcVar9;
    if ((DAT_0806abac != (char *)0x0) &&
       ((pcVar9 == (char *)0x0 || (iVar5 = FUN_0804b6c0(DAT_0806abac,pcVar9), iVar5 != 0)))) {
      DAT_0806ac08 = uVar4;
    }
  }
  if (DAT_08069ddc != (int *)0x0) {
    DAT_08069dd0 = DAT_08069ddc[0xb];
  }
  if (DAT_0806ac50 == 0) {
    if ((DAT_0806ab70 & 0x4000) != 0) {
      FUN_08057f38((int)PTR_DAT_08068878);
      for (piVar2 = DAT_08069d90; piVar2 != (int *)0x0; piVar2 = (int *)piVar2[1]) {
        for (iVar5 = *piVar2; iVar5 != 0; iVar5 = *(int *)(iVar5 + 0x54)) {
          FUN_0805af70("\n");
          FUN_08057f38(iVar5);
        }
      }
      if ((DAT_0806ab70 & 0x100) == 0) {
        if (((DAT_0806ab70 & 0x200) == 0) || (DAT_0806ab7c == (int *)0x0)) {
          FUN_0805af70("\nImage entry point : Not specified.\nEntry area : Not specified.\n");
        }
        else {
          pcVar9 = acStack_105 + 1;
          sprintf(pcVar9,"\nImage entry point : %lx\n",DAT_0806abbc + DAT_0806ab7c[0xb]);
          FUN_0805af70(pcVar9);
          sprintf(pcVar9,"Entry area : \"%s\"",(char *)((int)DAT_0806ab7c + 0x46));
          if (*DAT_0806ab7c != 0) {
            uVar6 = 0xffffffff;
            pcVar8 = pcVar9;
            do {
              if (uVar6 == 0) break;
              uVar6 = uVar6 - 1;
              cVar1 = *pcVar8;
              pcVar8 = pcVar8 + 1;
            } while (cVar1 != '\0');
            sprintf(acStack_105 + ~uVar6," from object file %s",*(char **)(*DAT_0806ab7c + 4));
          }
          FUN_0805af70(pcVar9);
          FUN_0805af70("\n");
        }
      }
      else {
        sprintf(acStack_105 + 1,"\nImage entry point : %lx\n",DAT_0806aba0);
        FUN_0805af70(acStack_105 + 1);
      }
    }
    if ((DAT_0806ab70 & 0x80000) != 0) {
      FUN_0805b0d8("0Opening output file %s.");
    }
    if ((DAT_0806ab68 & 0x1000) == 0) {
      FUN_08056fe4(PTR_DAT_08068878);
      for (piVar2 = DAT_08069d90; piVar2 != (int *)0x0; piVar2 = (int *)piVar2[1]) {
        for (puVar3 = (undefined *)*piVar2; puVar3 != (undefined *)0x0;
            puVar3 = *(undefined **)(puVar3 + 0x54)) {
          FUN_08056fe4(puVar3);
        }
      }
    }
    else {
      FUN_08057c70();
    }
    if ((DAT_08069ddc != (int *)0x0) && (DAT_08069dc4 != -1)) {
      FUN_08058d28();
    }
    if ((DAT_0806ab6c & 3) != 0) {
      FUN_08058604(DAT_0806ab90);
    }
    if ((DAT_0806ab6c & 0x20) != 0) {
      FUN_08058bac();
    }
  }
  else {
    FUN_0805b0d8("0Errors in link, no output generated.");
  }
  return;
}



void FUN_080596d0(void)

{
  DAT_0806abcc = 0;
  DAT_0806aba4 = 0;
  DAT_0806abe4 = 0;
  DAT_0806abe0 = 0;
  DAT_0806abac = 0;
  DAT_0806abc8 = 0;
  DAT_0806abd0 = 0;
  DAT_0806abb8 = 0;
  DAT_0806aba8 = 0;
  DAT_0806abd4 = 0;
  DAT_0806abb4 = 0;
  DAT_0806aba0 = 0;
  DAT_0806abbc = 0;
  DAT_0806abdc = 0;
  DAT_0806ab98 = 0;
  DAT_0806abb0 = 0;
  DAT_0806abd8 = 0;
  DAT_0806ab9c = 0;
  DAT_0806abc4 = 0;
  DAT_0806abc0 = 0;
  FUN_0804b8f8();
  DAT_0806ac44 = 0;
  DAT_0806ac08 = 0;
  FUN_0804e618();
  return;
}



void FUN_080597bc(int param_1)

{
  int __val;
  char *pcVar1;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  if (param_1 == 0) {
    if (DAT_0806ac54 < 1) {
      if (DAT_0806ac4c + DAT_0806ac48 + DAT_0806ac50 != 0) {
        FUN_0805af4c("%s: finished,  %d informational, %d warning and %d error messages.\n");
      }
    }
    else {
      FUN_0805af4c(
                  "%s: finished,  %d informational, %d warning, %d error and %d fatal error messages.\n"
                  );
    }
  }
  else {
    if ((param_1 == 2) || (param_1 == 0xf)) {
      pcVar1 = "%s: Interrupted by user.\n";
    }
    else {
      pcVar1 = "%s: Internal error.\n";
    }
    FUN_0805af4c(pcVar1);
    DAT_0806ac54 = DAT_0806ac54 + 1;
  }
  if (((DAT_0806ab70._2_1_ & 8) != 0) && (DAT_0806ac54 == 0)) {
    FUN_0804b1c0(&local_10,&local_c,&local_8);
    FUN_0805b0d8("0Memory usage: heap=%d, heap perm=%d, temp=%d, cache=%d.");
  }
  FUN_08056e94();
  if ((param_1 == 0) && (DAT_0806ac50 == -DAT_0806ac54)) {
    __val = 1;
  }
  else {
    __val = 2;
  }
  if (DAT_0806ac40 != (FILE *)0x0) {
    fclose(DAT_0806ac40);
  }
                    // WARNING: Subroutine does not return
  longjmp((__jmp_buf_tag *)&DAT_0806a160,__val);
}



void FUN_080598e4(int *param_1)

{
  bool bVar1;
  char *pcVar2;
  char *pcVar3;
  int iVar4;
  char *pcVar5;
  bool bVar6;
  
  pcVar2 = (char *)FUN_08061444(param_1,(byte *)"-ro-base");
  pcVar3 = (char *)FUN_08061444(DAT_08068880,(byte *)"-ro-base");
  iVar4 = FUN_08061444(param_1,(byte *)".format");
  pcVar5 = (char *)(iVar4 + 1);
  bVar1 = false;
  if (pcVar2 == (char *)0x0) {
LAB_08059941:
    bVar1 = true;
  }
  else if (pcVar3 != (char *)0x0) {
    iVar4 = strcmp(pcVar2,pcVar3);
    if (iVar4 == 0) goto LAB_08059941;
  }
  iVar4 = 10;
  bVar6 = true;
  pcVar2 = pcVar5;
  pcVar3 = "-aif -bin";
  do {
    if (iVar4 == 0) break;
    iVar4 = iVar4 + -1;
    bVar6 = *pcVar2 == *pcVar3;
    pcVar2 = pcVar2 + 1;
    pcVar3 = pcVar3 + 1;
  } while (bVar6);
  if (!bVar6) {
    iVar4 = strncmp(pcVar5,"-bin",4);
    if (iVar4 != 0) {
      iVar4 = strncmp(pcVar5,"-ihf",4);
      if (iVar4 != 0) {
        iVar4 = 5;
        bVar6 = true;
        pcVar2 = pcVar5;
        pcVar3 = "-aif";
        do {
          if (iVar4 == 0) break;
          iVar4 = iVar4 + -1;
          bVar6 = *pcVar2 == *pcVar3;
          pcVar2 = pcVar2 + 1;
          pcVar3 = pcVar3 + 1;
        } while (bVar6);
        if (!bVar6) {
          iVar4 = 0xc;
          bVar6 = true;
          pcVar2 = pcVar5;
          pcVar3 = "-aif -reloc";
          do {
            if (iVar4 == 0) break;
            iVar4 = iVar4 + -1;
            bVar6 = *pcVar2 == *pcVar3;
            pcVar2 = pcVar2 + 1;
            pcVar3 = pcVar3 + 1;
          } while (bVar6);
          if (!bVar6) {
            iVar4 = 5;
            bVar6 = true;
            pcVar2 = pcVar5;
            pcVar3 = "-ovf";
            do {
              if (iVar4 == 0) break;
              iVar4 = iVar4 + -1;
              bVar6 = *pcVar2 == *pcVar3;
              pcVar2 = pcVar2 + 1;
              pcVar3 = pcVar3 + 1;
            } while (bVar6);
            if (!bVar6) {
              iVar4 = 5;
              bVar6 = true;
              pcVar2 = "-elf";
              do {
                if (iVar4 == 0) break;
                iVar4 = iVar4 + -1;
                bVar6 = *pcVar5 == *pcVar2;
                pcVar5 = pcVar5 + 1;
                pcVar2 = pcVar2 + 1;
              } while (bVar6);
              if (!bVar6) {
                pcVar5 = "=";
                goto LAB_080599ed;
              }
            }
          }
        }
        pcVar5 = "#0x8000";
        goto LAB_080599ed;
      }
    }
  }
  pcVar5 = "#0";
LAB_080599ed:
  FUN_080614f4(DAT_08068880,(byte *)"-ro-base",pcVar5);
  if (bVar1) {
    FUN_080614f4(param_1,(byte *)"-ro-base",pcVar5);
  }
  return;
}



bool FUN_08059a20(int *param_1,byte *param_2,char *param_3)

{
  char *__s1;
  int iVar1;
  bool bVar2;
  
  __s1 = (char *)FUN_08061444(param_1,param_2);
  if (__s1 == (char *)0x0) {
    bVar2 = false;
  }
  else {
    iVar1 = strcmp(__s1,param_3);
    bVar2 = iVar1 == 0;
  }
  return bVar2;
}



void * FUN_08059a54(char *param_1)

{
  void *pvVar1;
  
  if (param_1 == (char *)0x0) {
    pvVar1 = (void *)0x0;
  }
  else {
    pvVar1 = FUN_0804b258(param_1);
  }
  return pvVar1;
}



void * FUN_08059a6c(int *param_1,byte *param_2)

{
  int iVar1;
  void *pvVar2;
  
  iVar1 = FUN_08061444(param_1,param_2);
  if (iVar1 == 0) {
    pvVar2 = (void *)0x0;
  }
  else {
    pvVar2 = FUN_08059a54((char *)(iVar1 + 1));
  }
  return pvVar2;
}



void FUN_08059a90(int *param_1,int *param_2)

{
  int iVar1;
  char *pcVar2;
  int *piVar3;
  int *piVar4;
  int local_18 [5];
  
  FUN_08049290(local_18,1);
  iVar1 = FUN_08061444(param_1,&DAT_080653e6);
  if (iVar1 != 0) {
    pcVar2 = FUN_0804b258((char *)(iVar1 + 1));
    FUN_0804ad2c(local_18,param_1,pcVar2);
  }
  pcVar2 = (char *)FUN_08061444(param_1,(byte *)"-errors");
  if (pcVar2 != (char *)0x0) {
    pcVar2 = pcVar2 + 1;
  }
  iVar1 = *param_2;
  piVar3 = param_2;
  piVar4 = param_2;
  do {
    if (iVar1 == 0) {
LAB_08059b22:
      if ((pcVar2 != (char *)0x0) &&
         (DAT_0806ac40 = FUN_08060e7c(pcVar2,"w"), DAT_0806ac40 == (FILE *)0x0)) {
        FUN_0805b0d8("3Can\'t reopen stderr to file %s.");
      }
      FUN_08049290(local_18,0);
      iVar1 = FUN_080492bc(local_18,param_1,param_2);
      if (iVar1 == 0) {
        FUN_080597bc(0);
      }
      DAT_0806abb0 = 0;
      return;
    }
    piVar4 = piVar4 + 1;
    iVar1 = FUN_0804b6c0((char *)*piVar3,"-errors");
    if (iVar1 == 0) {
      pcVar2 = (char *)*piVar4;
      goto LAB_08059b22;
    }
    piVar3 = piVar3 + 1;
    iVar1 = *piVar3;
  } while( true );
}



void FUN_08059b8c(void)

{
  (*DAT_0806ac00)(DAT_0806ac04,0,0);
  return;
}



undefined4 FUN_08059ba4(int param_1)

{
  if ((param_1 != 0) && (DAT_08068880 != (undefined4 *)0x0)) {
    FUN_08061258(DAT_08068880);
    FUN_08061258(DAT_08068884);
    DAT_08068880 = (undefined4 *)0x0;
    DAT_08068884 = (undefined4 *)0x0;
  }
  return 0;
}



void FUN_08059be0(int param_1)

{
  FUN_0805af4c("%s vsn %s [%s]\n");
  if (param_1 == 0) {
    FUN_0805af4c(
                "\nUsage: %s option-list input-file-list\n\nwhere\n\n    option-list      is a list of case-insensitive options.\n    input-file-list  is a list of input object and library files.\n\n"
                );
    FUN_0805af4c(
                "List of options (abbreviations shown capitalised):\n\nGeneral options:\n\n    -Help              Print this summary.\n    -Output file       Specify the name of the output file.\n    -vsn               Print version information.\n\n"
                );
    FUN_0805af4c(
                "Options for selecting output file format:\n\n    -elf       Generate the image in ELF format.(Default).\n    -aof       Generate the consolidated object in AOF.\n    -aif       Generate the image in Executable AIF Format.\n    -aif -bin  Generate the image in Non-executable AIF Format.\n    -bin       Generate the image in plain binary format.\n\n"
                );
    FUN_0805af4c(
                "Options for specifying memory map information:\n\n    -scatter file  Create the memory map as described in file.\n    -ro-base n     Set execution address of the region containing the RO section to n.\n    -rw-base n     Set execution address of the second execution region to n.\n\n"
                );
    FUN_0805af4c(
                "Options for controlling image construction:\n\n    -debug         Include debug information in the output.(Default).\n    -nodebug       Do not include debug information in the output.\n    -nozeropad     Do not expand zero-init areas in a binary image.\n    -noremove      Do not remove unused areas from the image.\n    -remove        Remove unused areas from the image.\n    -dupok         Allow duplicate symbols.\n    -entry         See product documentation for details.\n    -first         See product documentation for details.\n    -last          See product documentation for details.\n\n"
                );
    FUN_0805af4c(
                "Options for generating image-related information:\n\n    -info topic-list  Print information about each comma separated topic keyword.\n\n          Totals      Report the total code and data sizes in the image.\n          Sizes       Give a detailed breakdown of the code and data sizes per input object.\n          Interwork   List all calls requiring ARM/Thumb interworking veneers.\n          Unused      List all unused AREAs, when used with the -remove option.\n\n    -map              Create an image map listing the base and size of each constituent area.\n    -symbols file     Lists each symbol and its value to file.\n    -xref             Lists cross references between input areas.\n\n"
                );
    FUN_0805af4c(
                "Options for controlling the linker:\n\n    -errors file        Redirect stderr to file.\n    -list file          Redirect stdout to file.Useful in conjunction with -map, -xrefs and -symbols\n    -verbose            Print messages indicating progress of the link operation.\n    -via file           Read a further list of input filenames from file.\n    -case               Use case-sensitive symbol name matching.(Default).\n    -nocase             Use case-insensitive symbol name matching.\n    -match flags        Sets the symbol-matching options. See product documentation for details.\n    -unresolved symbol  Match references to undefined symbols to the global definition of symbol.\n    -u symbol           As for -unresolved, but displays warnings for each unused symbol encountered.\n\n"
                );
  }
  return;
}



void FUN_08059c58(void)

{
  DAT_0806a1fc = __sysv_signal(2,FUN_080597bc);
  DAT_0806a200 = __sysv_signal(0xf,FUN_080597bc);
  DAT_0806a204 = __sysv_signal(4,FUN_080597bc);
  DAT_0806a208 = __sysv_signal(6,FUN_080597bc);
  DAT_0806a20c = __sysv_signal(0xb,FUN_080597bc);
  return;
}



void FUN_08059cb8(void)

{
  __sysv_signal(2,DAT_0806a1fc);
  __sysv_signal(0xf,DAT_0806a200);
  __sysv_signal(4,DAT_0806a204);
  __sysv_signal(6,DAT_0806a208);
  __sysv_signal(0xb,DAT_0806a20c);
  return;
}



undefined4 FUN_08059d04(undefined4 *param_1,char *param_2)

{
  int iVar1;
  
  if ((param_1[1] != 0) && (iVar1 = strncmp(param_2,(char *)*param_1,param_1[1]), iVar1 != 0)) {
    return 0;
  }
  param_1[2] = param_1[2] + 1;
  return 0;
}



undefined4 FUN_08059d2c(int *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  char *local_10;
  int local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  uVar2 = 0xffffffff;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *param_2;
    param_2 = param_2 + 1;
  } while (cVar1 != '\0');
  local_c = ~uVar2 - 1;
  local_8 = 0;
  FUN_080618f4(param_1,FUN_08059d04,&local_10);
  return local_8;
}



undefined4 FUN_08059d6c(int param_1,char *param_2,undefined4 param_3)

{
  int iVar1;
  
  if ((*(size_t *)(param_1 + 0x10) != 0) &&
     (iVar1 = strncmp(param_2,*(char **)(param_1 + 0xc),*(size_t *)(param_1 + 0x10)), iVar1 != 0)) {
    return 0;
  }
  *(char **)(*(int *)(param_1 + 0x18) + *(int *)(param_1 + 0x14) * 8) = param_2;
  *(undefined4 *)(*(int *)(param_1 + 0x18) + 4 + *(int *)(param_1 + 0x14) * 8) = param_3;
  *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + 1;
  return 0;
}



uint FUN_08059db0(int *param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = __strtoul_internal(*param_1 + 3,0,0x10,0);
  uVar2 = __strtoul_internal(*param_2 + 3,0,0x10,0);
  if (uVar1 < uVar2) {
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = (uint)(uVar1 != uVar2);
  }
  return uVar1;
}



int FUN_08059dfc(int *param_1,char *param_2,undefined *param_3,undefined4 param_4)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *local_20;
  undefined *local_1c;
  undefined4 local_18;
  char *local_14;
  int local_10;
  size_t local_c;
  void *local_8;
  
  iVar2 = FUN_08059d2c(param_1,param_2);
  iVar4 = 0;
  local_20 = param_1;
  local_1c = param_3;
  local_18 = param_4;
  local_14 = param_2;
  uVar3 = 0xffffffff;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *param_2;
    param_2 = param_2 + 1;
  } while (cVar1 != '\0');
  local_10 = ~uVar3 - 1;
  if (iVar2 != 0) {
    local_8 = malloc(iVar2 * 8);
    local_c = 0;
    FUN_080618f4(param_1,FUN_08059d6c,&local_20);
    qsort(local_8,local_c,8,FUN_08059db0);
    uVar3 = 0;
    if (local_c != 0) {
      do {
        iVar4 = (*(code *)param_3)(param_4,*(undefined4 *)((int)local_8 + uVar3 * 8),
                                   *(undefined4 *)((int)local_8 + uVar3 * 8 + 4),0);
        if (iVar4 != 0) break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < local_c);
    }
    free(local_8);
  }
  return iVar4;
}



undefined4 FUN_08059eb8(int *param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  char *__src;
  char *pcVar5;
  size_t __n;
  int local_1008;
  char local_1004 [4096];
  
  local_1008 = *param_1;
  __src = (char *)(param_3 + 1);
  pcVar5 = __src;
  if (local_1008 == 0x6c) {
    uVar4 = 0xffffffff;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    __n = ~uVar4 - 1;
    local_1008 = 0;
    if (*(char *)(param_3 + -1 + __n) == '/') {
      iVar2 = tolower((int)*(char *)(param_3 + __n));
      if ((iVar2 == 0x61) || (iVar2 == 0x6c)) {
        local_1008 = (int)*(char *)(param_3 + __n);
        __n = ~uVar4 - 3;
      }
    }
    pcVar5 = local_1004;
    strncpy(pcVar5,__src,__n);
  }
  puVar3 = FUN_0804c948((undefined4 *)param_1[1],pcVar5,local_1008,1);
  param_1[1] = (int)puVar3;
  return 0;
}



undefined4 FUN_08059f60(undefined4 *param_1,undefined4 param_2,int param_3)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0804b1e8(8);
  *puVar1 = *(undefined4 *)*param_1;
  puVar1[1] = param_3 + 1;
  *(undefined4 **)*param_1 = puVar1;
  DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 0x20;
  return 0;
}



void FUN_08059f94(int param_1,int *param_2,int *param_3)

{
  char cVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  int iVar4;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  undefined3 extraout_var_08;
  undefined3 extraout_var_09;
  undefined3 extraout_var_10;
  undefined3 extraout_var_11;
  undefined3 extraout_var_12;
  undefined3 extraout_var_13;
  undefined3 extraout_var_14;
  undefined3 extraout_var_15;
  undefined3 extraout_var_16;
  undefined3 extraout_var_17;
  undefined3 extraout_var_18;
  undefined3 extraout_var_19;
  undefined3 extraout_var_20;
  undefined3 extraout_var_21;
  char *pcVar5;
  uint uVar6;
  code *pcVar7;
  char *pcVar8;
  char *local_188;
  char *local_178;
  int local_174;
  undefined4 *local_170;
  undefined4 local_16c;
  undefined4 *local_168;
  char local_164 [32];
  char local_144 [256];
  char local_44 [64];
  
  FUN_08059c58();
  FUN_0805e1f0((char *)*param_2,&DAT_0806ac20,0x20);
  if (param_1 < 2) {
    FUN_08059be0(0);
    FUN_080597bc(0);
  }
  FUN_080596d0();
  FUN_080614f4(param_3,(byte *)".debug","=-debug");
  FUN_08059a90(param_3,param_2);
  if ((DAT_0806ab70._2_1_ & 4) != 0) {
    FUN_08061b58(param_3);
    return;
  }
  FUN_080598e4(param_3);
  bVar2 = FUN_08059a20(param_3,(byte *)".echo","=-echo");
  if (CONCAT31(extraout_var,bVar2) != 0) {
    local_174 = 1;
    local_178 = (char *)0x0;
    local_188 = local_144;
    if ((char *)*param_2 != (char *)0x0) {
      uVar6 = 0xffffffff;
      pcVar8 = (char *)*param_2;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        cVar1 = *pcVar8;
        pcVar8 = pcVar8 + 1;
      } while (cVar1 != '\0');
      local_174 = ~uVar6 + 1;
    }
    uVar6 = FUN_0805da2c(param_3,(int)(local_188 + local_174),0xfeU - local_174);
    if (0xfeU - local_174 < uVar6) {
      local_188 = malloc(uVar6 + 2 + local_174);
      uVar6 = FUN_0805da2c(param_3,(int)(local_188 + local_174),uVar6 + 2);
      local_178 = local_188;
    }
    *local_188 = '[';
    if ((char *)*param_2 != (char *)0x0) {
      strcpy(local_188 + 1,(char *)*param_2);
      local_188[local_174 + -1] = ' ';
    }
    pcVar8 = local_188 + uVar6 + local_174;
    pcVar8[-1] = ']';
    *pcVar8 = '\n';
    pcVar8[1] = '\0';
    FUN_0805ae70(local_188,1);
    if (local_178 != (char *)0x0) {
      free(local_178);
    }
  }
  iVar3 = FUN_08061444(param_3,(byte *)".format");
  local_188 = (char *)(iVar3 + 1);
  iVar4 = strncmp(local_188,"-scf ",5);
  if (iVar4 == 0) {
    DAT_0806ab68 = DAT_0806ab68 | 0x1000;
    DAT_0806ab70._0_1_ = (byte)DAT_0806ab70 | 0x10;
    local_188 = (char *)(iVar3 + 6);
  }
  strcpy(local_44,local_188);
  iVar3 = 5;
  bVar2 = true;
  pcVar8 = local_188;
  pcVar5 = "-aif";
  do {
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    bVar2 = *pcVar8 == *pcVar5;
    pcVar8 = pcVar8 + 1;
    pcVar5 = pcVar5 + 1;
  } while (bVar2);
  if (bVar2) {
    DAT_0806ab64 = 4;
  }
  else {
    iVar3 = 0xc;
    bVar2 = true;
    pcVar8 = local_188;
    pcVar5 = "-aif -reloc";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar2 = *pcVar8 == *pcVar5;
      pcVar8 = pcVar8 + 1;
      pcVar5 = pcVar5 + 1;
    } while (bVar2);
    if (bVar2) {
      DAT_0806ab64 = 4;
      DAT_0806ab68 = DAT_0806ab68 | 1;
    }
    else {
      iVar3 = 10;
      bVar2 = true;
      pcVar8 = local_188;
      pcVar5 = "-aif -bin";
      do {
        if (iVar3 == 0) break;
        iVar3 = iVar3 + -1;
        bVar2 = *pcVar8 == *pcVar5;
        pcVar8 = pcVar8 + 1;
        pcVar5 = pcVar5 + 1;
      } while (bVar2);
      if (bVar2) {
        DAT_0806ab64 = 4;
        DAT_0806ab68 = DAT_0806ab68 | 0x200;
      }
      else {
        iVar3 = 5;
        bVar2 = true;
        pcVar8 = local_188;
        pcVar5 = "-bin";
        do {
          if (iVar3 == 0) break;
          iVar3 = iVar3 + -1;
          bVar2 = *pcVar8 == *pcVar5;
          pcVar8 = pcVar8 + 1;
          pcVar5 = pcVar5 + 1;
        } while (bVar2);
        if (bVar2) {
          DAT_0806ab64 = 4;
          DAT_0806ab68 = DAT_0806ab68 | 0x400;
        }
        else {
          iVar3 = 0xc;
          bVar2 = true;
          pcVar8 = local_188;
          pcVar5 = "-bin -split";
          do {
            if (iVar3 == 0) break;
            iVar3 = iVar3 + -1;
            bVar2 = *pcVar8 == *pcVar5;
            pcVar8 = pcVar8 + 1;
            pcVar5 = pcVar5 + 1;
          } while (bVar2);
          if (bVar2) {
            DAT_0806ab64 = 4;
            DAT_0806ab68 = DAT_0806ab68 | 0x440;
          }
          else {
            iVar3 = 5;
            bVar2 = true;
            pcVar8 = local_188;
            pcVar5 = "-aof";
            do {
              if (iVar3 == 0) break;
              iVar3 = iVar3 + -1;
              bVar2 = *pcVar8 == *pcVar5;
              pcVar8 = pcVar8 + 1;
              pcVar5 = pcVar5 + 1;
            } while (bVar2);
            if (bVar2) {
              DAT_0806ab64 = 1;
              DAT_0806ab68 = DAT_0806ab68 | 4;
            }
            else {
              iVar3 = 5;
              bVar2 = true;
              pcVar8 = local_188;
              pcVar5 = "-elf";
              do {
                if (iVar3 == 0) break;
                iVar3 = iVar3 + -1;
                bVar2 = *pcVar8 == *pcVar5;
                pcVar8 = pcVar8 + 1;
                pcVar5 = pcVar5 + 1;
              } while (bVar2);
              if (bVar2) {
                DAT_0806ab64 = 6;
              }
              else {
                iVar3 = 5;
                bVar2 = true;
                pcVar8 = local_188;
                pcVar5 = "-ihf";
                do {
                  if (iVar3 == 0) break;
                  iVar3 = iVar3 + -1;
                  bVar2 = *pcVar8 == *pcVar5;
                  pcVar8 = pcVar8 + 1;
                  pcVar5 = pcVar5 + 1;
                } while (bVar2);
                if (bVar2) {
                  DAT_0806ab64 = 4;
                  DAT_0806ab68 = DAT_0806ab68 | 0x402;
                }
                else {
                  iVar3 = 0xc;
                  bVar2 = true;
                  pcVar8 = local_188;
                  pcVar5 = "-ihf -split";
                  do {
                    if (iVar3 == 0) break;
                    iVar3 = iVar3 + -1;
                    bVar2 = *pcVar8 == *pcVar5;
                    pcVar8 = pcVar8 + 1;
                    pcVar5 = pcVar5 + 1;
                  } while (bVar2);
                  if (bVar2) {
                    DAT_0806ab64 = 4;
                    DAT_0806ab68 = DAT_0806ab68 | 0x442;
                  }
                  else {
                    iVar3 = 5;
                    bVar2 = true;
                    pcVar8 = local_188;
                    pcVar5 = "-ovf";
                    do {
                      if (iVar3 == 0) break;
                      iVar3 = iVar3 + -1;
                      bVar2 = *pcVar8 == *pcVar5;
                      pcVar8 = pcVar8 + 1;
                      pcVar5 = pcVar5 + 1;
                    } while (bVar2);
                    if (bVar2) {
                      DAT_0806ab64 = 4;
                      DAT_0806ab68 = DAT_0806ab68 | 0x800;
                    }
                    else {
                      iVar3 = 5;
                      bVar2 = true;
                      pcVar8 = local_188;
                      pcVar5 = "-rmf";
                      do {
                        if (iVar3 == 0) break;
                        iVar3 = iVar3 + -1;
                        bVar2 = *pcVar8 == *pcVar5;
                        pcVar8 = pcVar8 + 1;
                        pcVar5 = pcVar5 + 1;
                      } while (bVar2);
                      if (bVar2) {
                        DAT_0806ab64 = 4;
                        DAT_0806ab68 = DAT_0806ab68 | 8;
                      }
                      else {
                        iVar3 = 5;
                        bVar2 = true;
                        pcVar8 = local_188;
                        pcVar5 = "-shf";
                        do {
                          if (iVar3 == 0) break;
                          iVar3 = iVar3 + -1;
                          bVar2 = *pcVar8 == *pcVar5;
                          pcVar8 = pcVar8 + 1;
                          pcVar5 = pcVar5 + 1;
                        } while (bVar2);
                        if (bVar2) {
                          DAT_0806ab64 = 1;
                          DAT_0806ab68 = DAT_0806ab68 | 0x14;
                        }
                        else {
                          iVar3 = 0xc;
                          bVar2 = true;
                          pcVar8 = "-shf -reent";
                          do {
                            if (iVar3 == 0) break;
                            iVar3 = iVar3 + -1;
                            bVar2 = *local_188 == *pcVar8;
                            local_188 = local_188 + 1;
                            pcVar8 = pcVar8 + 1;
                          } while (bVar2);
                          if (bVar2) {
                            DAT_0806ab64 = 1;
                            DAT_0806ab68 = DAT_0806ab68 | 0x34;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".case","=-case");
  if (CONCAT31(extraout_var_00,bVar2) == 0) {
    pcVar7 = strcmp;
  }
  else {
    pcVar7 = FUN_0804b6c0;
  }
  PTR_strcmp_080686cc = pcVar7;
  bVar2 = FUN_08059a20(param_3,&DAT_08066138,"=-dde");
  if (CONCAT31(extraout_var_01,bVar2) != 0) {
    DAT_0806ab68 = DAT_0806ab68 | 0x80;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".dupok","=-dupok");
  if (CONCAT31(extraout_var_02,bVar2) != 0) {
    DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 0x80;
  }
  bVar2 = FUN_08059a20(param_3,&DAT_08066152,"=-map");
  if (CONCAT31(extraout_var_03,bVar2) != 0) {
    DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 0x40;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".symb","=-symb");
  if (CONCAT31(extraout_var_04,bVar2) != 0) {
    DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ | 1;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".symb","=-symbx");
  if (CONCAT31(extraout_var_05,bVar2) != 0) {
    DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ | 0x81;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".xref","=-xref");
  if (CONCAT31(extraout_var_06,bVar2) != 0) {
    DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 0x10;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".zeropad","=-nozeropad");
  if (CONCAT31(extraout_var_07,bVar2) != 0) {
    DAT_0806ab70._0_1_ = (byte)DAT_0806ab70 | 1;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".scanlib","=-scanlib");
  if (CONCAT31(extraout_var_08,bVar2) != 0) {
    DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ | 2;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".autoplace","=-noautoplace");
  if (CONCAT31(extraout_var_09,bVar2) != 0) {
    DAT_0806ab70._0_1_ = (byte)DAT_0806ab70 | 0x10;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".unresolvedwarn","=-unresolvedwarn");
  if (CONCAT31(extraout_var_10,bVar2) != 0) {
    DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 8;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".debug","=-debug");
  if ((CONCAT31(extraout_var_11,bVar2) == 0) || ((DAT_0806ab68 & 0x410) != 0)) {
    DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ & 0xfb;
  }
  else {
    DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 4;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".dsuppress","=-dsuppress");
  if (CONCAT31(extraout_var_12,bVar2) != 0) {
    DAT_0806ab70._0_1_ = (byte)DAT_0806ab70 | 0x20;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".remove","=-noremove");
  if (CONCAT31(extraout_var_13,bVar2) == 0) {
    bVar2 = FUN_08059a20(param_3,(byte *)".remove","=-remove");
    if (CONCAT31(extraout_var_14,bVar2) != 0) {
      DAT_0806ab70._0_1_ = (byte)DAT_0806ab70 | 8;
    }
  }
  else {
    DAT_0806ab70._0_1_ = (byte)DAT_0806ab70 | 4;
  }
  DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ | 0x40;
  bVar2 = FUN_08059a20(param_3,(byte *)"-info.size","#size");
  if (CONCAT31(extraout_var_15,bVar2) != 0) {
    DAT_0806ab6c = DAT_0806ab6c | 1;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)"-info.inter","#inter");
  if (CONCAT31(extraout_var_16,bVar2) != 0) {
    DAT_0806ab6c = DAT_0806ab6c | 4;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)"-info.unaligned","#unaligned");
  if (CONCAT31(extraout_var_17,bVar2) != 0) {
    DAT_0806ab6c = DAT_0806ab6c | 8;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)"-info.total","#total");
  if (CONCAT31(extraout_var_18,bVar2) != 0) {
    DAT_0806ab6c = DAT_0806ab6c | 2;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)"-info.unused","#unused");
  if (CONCAT31(extraout_var_19,bVar2) != 0) {
    DAT_0806ab6c = DAT_0806ab6c | 0x10;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)"-info.nonstrong","#nonstrong");
  if (CONCAT31(extraout_var_20,bVar2) != 0) {
    DAT_0806ab6c = DAT_0806ab6c | 0x20;
  }
  bVar2 = FUN_08059a20(param_3,(byte *)".sortbyname","=-nosortbyname");
  if (CONCAT31(extraout_var_21,bVar2) != 0) {
    DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ | 0x20;
  }
  DAT_0806ac44 = FUN_08059a6c(param_3,(byte *)"-list");
  DAT_0806aba4 = FUN_08059a6c(param_3,(byte *)"-scov");
  DAT_0806abcc = FUN_08059a6c(param_3,&DAT_080662b7);
  DAT_0806abe4 = FUN_08059a6c(param_3,(byte *)"-libpath");
  DAT_0806abb8 = FUN_08059a6c(param_3,(byte *)"-first");
  DAT_0806abd0 = FUN_08059a6c(param_3,(byte *)"-last");
  DAT_0806abc8 = FUN_08059a6c(param_3,&DAT_080662d2);
  DAT_0806abac = FUN_08059a6c(param_3,(byte *)"-symfile");
  iVar3 = FUN_08061444(param_3,(byte *)"-errors");
  if (iVar3 != 0) {
    if (DAT_0806ac40 != (FILE *)0x0) {
      FUN_08060ec8(DAT_0806ac40);
    }
    DAT_0806ac40 = FUN_08060e7c((char *)(iVar3 + 1),"w");
    if (DAT_0806ac40 == (FILE *)0x0) {
      FUN_0805b0d8("3Can\'t reopen stderr to file %s.");
    }
  }
  iVar3 = FUN_08061444(param_3,(byte *)"-unresolved");
  if (iVar3 != 0) {
    DAT_0806abb4 = FUN_0804c234((char *)(iVar3 + 1),2,"!!");
  }
  iVar3 = FUN_08061444(param_3,(byte *)"-entry");
  if (iVar3 != 0) {
    pcVar8 = (char *)(iVar3 + 1);
    pcVar5 = strchr(pcVar8,0x2b);
    if (pcVar5 == (char *)0x0) {
      DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 1;
      DAT_0806aba0 = FUN_080490c0(pcVar8,"3Badly formed constant on -Entry qualifier.");
    }
    else {
      memcpy(local_164,pcVar8,(int)pcVar5 - (int)pcVar8);
      local_164[(int)pcVar5 - (int)pcVar8] = '\0';
      DAT_0806ab70._1_1_ = DAT_0806ab70._1_1_ | 2;
      DAT_0806abe0 = FUN_08059a54(pcVar5 + 1);
      DAT_0806abbc = FUN_080490c0(local_164,"3Badly formed constant on -Entry qualifier.");
    }
  }
  iVar3 = FUN_08061444(param_3,&DAT_0806632c);
  if (iVar3 != 0) {
    DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ | 8;
    iVar3 = FUN_080490c0((char *)(iVar3 + 1),"1Badly formed constant on -v qualifier.");
    DAT_0806ab6e = (undefined1)iVar3;
  }
  iVar3 = FUN_08061444(param_3,(byte *)"-match");
  if (iVar3 != 0) {
    iVar3 = FUN_080490c0((char *)(iVar3 + 1),"3Badly formed constant on -Match qualifier.");
    DAT_0806ab6f = (undefined1)iVar3;
  }
  iVar3 = FUN_08061444(param_3,(byte *)"-ro-base");
  if (iVar3 != 0) {
    iVar3 = FUN_080490c0((char *)(iVar3 + 1),"3Badly formed or missing -RO-base/-Base value.");
    if ((DAT_0806ab68 & 0x1000) == 0) {
      if ((DAT_0806ab68 & 4) == 0) {
        DAT_0806ab70._0_1_ = (byte)DAT_0806ab70 | 0x40;
        DAT_0806ab98 = iVar3;
        goto LAB_0805a9f1;
      }
      pcVar8 = "1-RO-base is incompatible with partially linked output. -RO-base ignored.";
    }
    else {
      pcVar8 = "1-RO-base incompatible with -SCATTER. -RO-base will be ignored.";
    }
    FUN_0805b0d8(pcVar8);
  }
LAB_0805a9f1:
  iVar3 = FUN_08061444(param_3,(byte *)"-rw-base");
  if (iVar3 != 0) {
    iVar3 = FUN_080490c0((char *)(iVar3 + 1),"3Badly formed or missing -RW-base/-DATAbase value.");
    if ((DAT_0806ab68 & 0x1000) == 0) {
      DAT_0806ab70._0_1_ = (byte)DAT_0806ab70 | 0x80;
      DAT_0806abdc = iVar3;
    }
    else {
      FUN_0805b0d8("1-RW-base incompatible with -SCATTER. -RW-base will be ignored.");
    }
  }
  iVar3 = FUN_08061444(param_3,&DAT_08066520);
  if (iVar3 != 0) {
    iVar3 = FUN_080490c0((char *)(iVar3 + 1),"3Badly formed constant on -Workspace qualifier.");
    if (iVar3 == 0) {
      DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ & 0xef;
    }
    else {
      DAT_0806ab70._2_1_ = DAT_0806ab70._2_1_ | 0x10;
    }
  }
  iVar3 = FUN_08061444(param_3,&DAT_08066570);
  if (iVar3 != 0) {
    DAT_0806abd8 = FUN_080490c0((char *)(iVar3 + 1),
                                "3Badly formed constant on -Workspace qualifier.");
    DAT_0806ab68 = DAT_0806ab68 | 0x100;
  }
  local_16c = 0;
  local_168 = &DAT_0806ab9c;
  FUN_08059dfc(param_3,"-F.",FUN_08059eb8,&local_16c);
  local_16c = 0x6c;
  FUN_08059dfc(param_3,"-L.",FUN_08059eb8,&local_16c);
  if (DAT_0806abc0 != 0) {
    FUN_0805b0d8("1Memory shortage, increase memory allocation.");
  }
  if (DAT_0806ab9c == 0) {
    FUN_0805b0d8("3No files to link, use %s -help for help.");
  }
  local_170 = &DAT_0806abd4;
  FUN_08059dfc(param_3,"-xreffrom.",FUN_08059f60,&local_170);
  local_170 = &DAT_0806aba8;
  FUN_08059dfc(param_3,"-xrefto.",FUN_08059f60,&local_170);
  if (DAT_0806abc8 == (undefined *)0x0) {
    if (DAT_0806ab64 == 4) {
      if ((DAT_0806ab68 & 0x1800) == 0) {
        DAT_0806abc8 = &DAT_08066600;
      }
      else {
        DAT_0806abc8 = &DAT_080665fe;
      }
    }
    else if (DAT_0806ab64 == 6) {
      DAT_0806abc8 = &DAT_08066604;
    }
    else {
      DAT_0806abc8 = &DAT_08066608;
    }
  }
  if ((DAT_0806ab68 & 0x10) != 0) {
    FUN_0805b0d8("3%s is not supported by this release of the toolkit.");
  }
  if ((DAT_0806ab68 & 2) != 0) {
    FUN_0805b0d8("3%s is not supported by this release of the toolkit.");
  }
  if ((DAT_0806ab64 != 6) && ((DAT_0806ab68 & 4) == 0)) {
    strcat(local_44," output file format");
    FUN_0805b0d8("1%s will not be supported by future releases of armlink.");
  }
  if ((DAT_0806ab68 & 0x800) != 0) {
    FUN_0805b0d8("1%s will not be supported by future releases of the toolkit.");
  }
  if ((DAT_0806ab68 & 0x100) != 0) {
    FUN_0805b0d8("1%s will not be supported by future releases of the toolkit.");
  }
  FUN_0804ea80();
  FUN_080597bc(0);
  return;
}



bool FUN_0805ac90(int param_1,int *param_2,int *param_3,undefined4 param_4,undefined4 param_5)

{
  int iVar1;
  
  DAT_0806ac00 = param_4;
  DAT_0806ac04 = param_5;
  DAT_0806ac40 = 0;
  FUN_08049078();
  FUN_08060c80();
  FUN_0804b584();
  FUN_08060e20(FUN_0804b1e8);
  iVar1 = __sigsetjmp(&DAT_0806a160,0);
  if (iVar1 == 0) {
    FUN_08059f94(param_1,param_2,param_3);
  }
  FUN_08059cb8();
  FUN_08060f28();
  FUN_08060db4();
  return iVar1 != 1;
}



int FUN_0805ad10(int *param_1,char *param_2)

{
  int iVar1;
  
  FUN_08049078();
  FUN_08060c80();
  FUN_0804b584();
  FUN_08060e20(FUN_0804b1e8);
  iVar1 = FUN_08061a48(param_1,param_2);
  if (iVar1 == 0) {
    FUN_0805dc78(param_1);
  }
  FUN_08060f28();
  FUN_08060db4();
  return iVar1;
}



undefined4 FUN_0805ad60(int *param_1)

{
  undefined4 uVar1;
  
  FUN_08049078();
  FUN_08060c80();
  FUN_0804b584();
  FUN_08060e20(FUN_0804b1e8);
  FUN_080598e4(param_1);
  uVar1 = FUN_0805b19c();
  FUN_08060f28();
  FUN_08060db4();
  return uVar1;
}



undefined ** FUN_0805ada8(void)

{
  return &PTR_FUN_08066760;
}



undefined ** FUN_0805adb4(uint *param_1)

{
  if (param_1 != (uint *)0x0) {
    *param_1 = (uint)(DAT_08068880 != 0);
  }
  return &PTR_FUN_08066760;
}



int FUN_0805add8(int *param_1)

{
  int iVar1;
  char *pcVar2;
  undefined **ppuVar3;
  
  ppuVar3 = &PTR_s__format_08066788;
  do {
    iVar1 = FUN_080614f4(param_1,*ppuVar3,ppuVar3[1]);
    if (iVar1 != 0) {
      return iVar1;
    }
    ppuVar3 = ppuVar3 + 2;
  } while (*ppuVar3 != (undefined *)0x0);
  pcVar2 = getenv("ARMLIB");
  if ((pcVar2 == (char *)0x0) ||
     (iVar1 = FUN_08061478(param_1,(byte *)"-libpath",0x23,pcVar2), iVar1 == 0)) {
    FUN_0805dc78(param_1);
    if (DAT_08068880 == (int *)0x0) {
      DAT_08068880 = FUN_08061688(param_1);
      DAT_08068884 = FUN_080611f0(0);
    }
    iVar1 = 0;
  }
  return iVar1;
}



char * FUN_0805ae64(void)

{
  return "armlink";
}



void FUN_0805ae70(char *param_1,int param_2)

{
  int iVar1;
  undefined *local_1c;
  undefined4 local_18;
  char *local_14;
  undefined2 local_10;
  undefined2 local_e;
  undefined4 local_c;
  undefined4 local_8;
  
  if (DAT_0806ac44 == (char *)0x0) {
    if (param_2 == 0) {
      local_1c = &DAT_0806ac20;
    }
    else {
      local_1c = (undefined *)0x0;
    }
    local_18 = 0;
    local_14 = param_1;
    local_10 = (undefined2)param_2;
    local_e = 0xffff;
    local_c = 0xffffffff;
    local_8 = 0xffffffff;
    iVar1 = DAT_0806ac04;
    if (DAT_0806ac04 == 0) {
      iVar1 = stdout;
    }
    (*DAT_0806ac00)(iVar1,1,&local_1c);
  }
  else {
    if (DAT_0806ac08 == (FILE *)0x0) {
      DAT_0806ac08 = FUN_08060e7c(DAT_0806ac44,"w");
      if (DAT_0806ac08 == (FILE *)0x0) {
        FUN_0805b0d8("3Can\'t open file \'%s\'.");
      }
    }
    fputs(param_1,DAT_0806ac08);
    iVar1 = ferror(DAT_0806ac08);
    if (iVar1 != 0) {
      FUN_0805b0d8("3Error writing %s.");
    }
  }
  return;
}



void FUN_0805af4c(char *param_1)

{
  vsprintf(&DAT_0806a220,param_1,&stack0x00000008);
  FUN_0805ae70(&DAT_0806a220,0);
  return;
}



void FUN_0805af70(char *param_1)

{
  vsprintf(&DAT_0806a220,param_1,&stack0x00000008);
  FUN_0805ae70(&DAT_0806a220,0);
  return;
}



void FUN_0805af94(int param_1,char *param_2,__gnuc_va_list param_3)

{
  int iVar1;
  char cVar2;
  uint uVar3;
  char *pcVar4;
  int iVar5;
  undefined *local_1c;
  undefined4 local_18;
  undefined1 *local_14;
  undefined2 local_10;
  undefined2 local_e;
  undefined4 local_c;
  undefined4 local_8;
  
  iVar5 = 0;
  pcVar4 = &DAT_0806a220;
  if (param_1 != 0) {
    sprintf(&DAT_0806a220,"\"%s\", line %d (near column %d) ",*(char **)(param_1 + 0xc),
            *(int *)(param_1 + 4),*(int *)(param_1 + 8));
    uVar3 = 0xffffffff;
    pcVar4 = &DAT_0806a220;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar2 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar2 != '\0');
    pcVar4 = (char *)(~uVar3 + 0x806a21f);
  }
  iVar1 = *param_2 + -0x30;
  vsprintf(pcVar4,param_2 + 1,param_3);
  (&DAT_0806ac48)[iVar1] = (&DAT_0806ac48)[iVar1] + 1;
  if (DAT_0806ac40 == (FILE *)0x0) {
    local_1c = &DAT_0806ac20;
    local_18 = 0;
    local_14 = &DAT_0806a220;
    local_10 = *(undefined2 *)(&DAT_080668ec + iVar1 * 4);
    local_e = 0xffff;
    local_c = 0xffffffff;
    local_8 = 0xffffffff;
    iVar5 = DAT_0806ac04;
    if (DAT_0806ac04 == 0) {
      iVar5 = stdout;
    }
    iVar5 = (*DAT_0806ac00)(iVar5,1,&local_1c);
    goto LAB_0805b0be;
  }
  if (iVar1 == 1) {
    pcVar4 = "(Warning) ";
  }
  else if (iVar1 < 2) {
    if (iVar1 == 0) {
      pcVar4 = "";
    }
    else {
LAB_0805b090:
      pcVar4 = "(Fatal) ";
    }
  }
  else {
    if (iVar1 != 2) goto LAB_0805b090;
    pcVar4 = "(Error) ";
  }
  fprintf(DAT_0806ac40,"%s: %s","ARM Linker",pcVar4);
  fprintf(DAT_0806ac40,"%s\n",&DAT_0806a220);
LAB_0805b0be:
  if ((iVar1 == 3) || (iVar5 != 0)) {
    FUN_080597bc(0);
  }
  return;
}



void FUN_0805b0d8(char *param_1)

{
  FUN_0805af94(0,param_1,&stack0x00000008);
  return;
}



void FUN_0805b0ec(int param_1,char *param_2)

{
  FUN_0805af94(param_1,param_2,&stack0x0000000c);
  return;
}



void FUN_0805b100(int param_1)

{
  char *param2;
  char *param3;
  
  param2 = *(char **)(param_1 + 8);
  switch(*(undefined2 *)(param_1 + 0xc)) {
  case 0:
    fputs(param2,DAT_0806a620);
    return;
  case 1:
    param3 = "";
    break;
  case 2:
    param3 = "(Warning) ";
    break;
  case 3:
    param3 = "(Error) ";
    break;
  default:
    param3 = "(Fatal) ";
  }
  fprintf(DAT_0806a620,"%s: %s","ARM Linker",param3);
  fprintf(DAT_0806a620,"%s\n",param2);
  return;
}



undefined4 FUN_0805b178(int param_1,int param_2,int param_3)

{
  if (param_2 == 1) {
    if (param_1 != 0) {
      DAT_0806a620 = param_1;
    }
    FUN_0805b100(param_3);
  }
  return 0;
}



undefined4 FUN_0805b19c(void)

{
  return 0;
}



undefined4 FUN_0805b1a4(void)

{
  return 1;
}



undefined4 FUN_0805b1b0(undefined4 param_1,undefined4 param_2)

{
  undefined **ppuVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  DAT_0806a620 = stderr;
  ppuVar1 = FUN_0805ada8();
  uVar2 = (*(code *)ppuVar1[2])();
  (*(code *)ppuVar1[5])(uVar2);
  (*(code *)ppuVar1[4])(uVar2,&DAT_080669a0);
  uVar3 = (*(code *)ppuVar1[1])(param_1,param_2,uVar2,FUN_0805b178,0);
  (*(code *)ppuVar1[3])(uVar2);
  (*(code *)*ppuVar1)(ppuVar1);
  return uVar3;
}



undefined4 * FUN_0805b210(undefined4 *param_1,char *param_2,char *param_3)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = (undefined4 *)FUN_0804b3ac(0xc);
  iVar2 = FUN_0804b6c0((char *)*param_1,param_2);
  if (iVar2 != 0) {
    param_2 = FUN_0804b28c((char *)*param_1);
  }
  *puVar1 = param_2;
  puVar1[1] = param_1[1];
  if (param_1[1] == 0) {
    iVar2 = FUN_0804b6c0((char *)param_1[2],param_3);
    if (iVar2 != 0) {
      param_3 = FUN_0804b28c((char *)param_1[2]);
    }
  }
  else {
    param_3 = (char *)param_1[2];
  }
  puVar1[2] = param_3;
  return puVar1;
}



undefined4 FUN_0805b288(char *param_1)

{
  char cVar1;
  
  do {
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    if (cVar1 == '\0') {
      return 1;
    }
  } while ((cVar1 != '*') && (cVar1 != '?'));
  return 0;
}



undefined4 FUN_0805b2b0(char *param_1,char *param_2)

{
  bool bVar1;
  bool bVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  
  bVar1 = FUN_0804d948(param_1,param_2);
  bVar2 = FUN_0804d948(param_2,param_1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    if (CONCAT31(extraout_var_00,bVar2) != 0) {
      return 0xffffffff;
    }
  }
  else if (CONCAT31(extraout_var_00,bVar2) == 0) {
    return 1;
  }
  return 0;
}



int FUN_0805b2fc(undefined4 *param_1,undefined4 *param_2)

{
  uint uVar1;
  int iVar2;
  
  if ((param_2[1] == 0) || ((*(byte *)(param_2 + 2) & 1) != 0)) {
LAB_0805b336:
    if (param_1[1] == 0) {
LAB_0805b361:
      iVar2 = FUN_0805b2b0((char *)*param_1,(char *)*param_2);
      if (iVar2 != 0) {
        return iVar2;
      }
      if (param_1[1] == 0) {
        if (param_2[1] != 0) {
          return 0;
        }
        iVar2 = FUN_0805b2b0((char *)param_1[2],(char *)param_2[2]);
        return iVar2;
      }
      if (param_2[1] == 0) {
        return 0;
      }
      uVar1 = param_2[2];
      if (((param_1[2] & 1) == 0 && (uVar1 & 1) == 0) ||
         (((byte)param_1[2] & 1 & (byte)uVar1 & 1) != 0)) {
        return 0;
      }
      if ((uVar1 & 1) == 0) goto LAB_0805b32c;
    }
    else {
LAB_0805b33c:
      if ((((*(byte *)(param_1 + 2) & 1) != 0) || (param_2[1] != 0)) ||
         (iVar2 = FUN_0805b288((char *)param_2[2]), iVar2 == 0)) goto LAB_0805b361;
    }
    iVar2 = 1;
  }
  else {
    if (param_1[1] != 0) goto LAB_0805b33c;
    iVar2 = FUN_0805b288((char *)param_1[2]);
    if (iVar2 == 0) goto LAB_0805b336;
LAB_0805b32c:
    iVar2 = -1;
  }
  return iVar2;
}



void FUN_0805b3e8(int param_1,undefined4 *param_2)

{
  if (param_1 == 10) {
    param_2[1] = param_2[1] + 1;
    param_2[2] = 0;
    param_2[4] = 0;
  }
  if (param_1 != -1) {
    param_2[4] = param_2[4] + 1;
    _IO_getc((_IO_FILE *)*param_2);
  }
  return;
}



int FUN_0805b418(int param_1,undefined4 *param_2)

{
  int iVar1;
  
  if (param_1 != -1) {
    do {
      while( true ) {
        while (iVar1 = isspace(param_1), iVar1 != 0) {
          param_1 = FUN_0805b3e8(param_1,param_2);
        }
        if ((param_1 != 0x3b) && ((param_1 != 0x23 || (param_2[2] != 0)))) break;
        do {
          param_1 = FUN_0805b3e8(param_1,param_2);
          if (param_1 == -1) goto LAB_0805b476;
        } while (param_1 != 10);
      }
LAB_0805b476:
    } while (param_1 == 10);
    param_2[2] = param_2[4];
  }
  return param_1;
}



undefined4 FUN_0805b48c(int param_1,char *param_2)

{
  char cVar1;
  
  cVar1 = *param_2;
  while( true ) {
    if (cVar1 == '\0') {
      return 0;
    }
    if (*param_2 == param_1) break;
    param_2 = param_2 + 1;
    cVar1 = *param_2;
  }
  return 1;
}



int FUN_0805b4bc(int param_1,undefined4 *param_2,undefined4 *param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  char local_10 [12];
  
  uVar5 = 1;
  if (param_1 == 0x26) {
    local_10[0] = '0';
    iVar4 = 0x78;
  }
  else {
    local_10[0] = (char)param_1;
    iVar4 = FUN_0805b3e8(param_1,param_3);
  }
  if ((local_10[0] == '0') && ((iVar4 == 0x78 || (iVar4 == 0x58)))) {
    do {
      if (uVar5 < 0xc) {
        local_10[uVar5] = (char)iVar4;
        uVar5 = uVar5 + 1;
      }
      iVar4 = FUN_0805b3e8(iVar4,param_3);
      iVar1 = isxdigit(iVar4);
    } while (iVar1 != 0);
  }
  else {
    for (; (iVar1 = isdigit(iVar4), iVar1 != 0 && ((local_10[0] != '\0' || (1 < iVar4 - 0x38U))));
        iVar4 = FUN_0805b3e8(iVar4,param_3)) {
      if (uVar5 < 0xc) {
        local_10[uVar5] = (char)iVar4;
        uVar5 = uVar5 + 1;
      }
    }
    if (local_10[0] == '0') {
      uVar2 = 0xb;
      goto LAB_0805b57a;
    }
  }
  uVar2 = 10;
LAB_0805b57a:
  if (uVar5 == 0xc) {
    local_10[0xb] = 0;
  }
  else {
    local_10[uVar5] = '\0';
  }
  if (uVar2 < uVar5) {
    FUN_0805b0ec((int)param_3,"2Number \'%s...\' is too long.");
    *param_2 = 0;
  }
  else {
    uVar3 = __strtoul_internal(local_10,0,0,0);
    *param_2 = uVar3;
  }
  return iVar4;
}



void FUN_0805b5c4(undefined4 *param_1,int param_2)

{
  if (param_2 == -1) {
    *param_1 = 0x464f45;
  }
  else {
    *(char *)param_1 = (char)param_2;
    *(undefined4 *)((int)param_1 + 1) = 0x2e2e2e;
  }
  return;
}



int FUN_0805b5ec(int param_1,int param_2,undefined4 *param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  
  bVar1 = false;
  iVar3 = 0;
  do {
    if (param_1 == 0x22) {
      if (bVar1) {
        param_1 = FUN_0805b3e8(0x22,param_3);
        if (param_1 != 0x22) {
          bVar1 = false;
        }
        goto LAB_0805b687;
      }
      bVar1 = true;
    }
    else {
LAB_0805b687:
      if ((param_1 == -1) || (param_1 == 10)) {
        if (bVar1) {
          FUN_0805b0ec((int)param_3,"2Expected \'%s\', found \'%s\'.");
LAB_0805b6cc:
          if (iVar3 < 0x20) {
            *(undefined1 *)(iVar3 + param_2) = 0;
          }
          else {
            *(undefined1 *)(param_2 + 0x1f) = 0;
            FUN_0805b0ec((int)param_3,"1\'%s\' has been truncated.");
          }
          return param_1;
        }
LAB_0805b618:
        iVar2 = isspace(param_1);
        if ((iVar2 != 0) || (iVar2 = FUN_0805b48c(param_1,"{}(),+"), iVar2 != 0)) goto LAB_0805b6cc;
      }
      else {
        if (!bVar1) goto LAB_0805b618;
        iVar2 = isspace(param_1);
        if (iVar2 != 0) {
          param_1 = 0x20;
        }
      }
      if (iVar3 < 0x20) {
        *(char *)(iVar3 + param_2) = (char)param_1;
        iVar3 = iVar3 + 1;
      }
    }
    param_1 = FUN_0805b3e8(param_1,param_3);
  } while( true );
}



undefined4 FUN_0805b704(char *param_1)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = 0;
  do {
    iVar1 = FUN_0804b6c0((&PTR_s_RO_CODE_08068888)[uVar2 * 2],param_1);
    if (iVar1 == 0) {
      return (&DAT_0806888c)[uVar2 * 2];
    }
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x12);
  return 8;
}



int FUN_0805b748(int param_1,int param_2,undefined4 *param_3)

{
  bool bVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  bool bVar5;
  undefined4 *puVar6;
  int local_58;
  int local_54;
  char *local_50;
  uint local_4c;
  char *local_48;
  char local_44 [32];
  char local_24 [32];
  
  iVar2 = FUN_0805b5ec(param_1,(int)local_24,param_3);
  if ((local_24[0] == '\0') &&
     (FUN_0805b0ec((int)param_3,"2Missing module selector."), iVar2 != 0x28)) {
    iVar2 = FUN_0805b3e8(iVar2,param_3);
  }
  iVar2 = FUN_0805b418(iVar2,param_3);
  local_50 = local_24;
  if (iVar2 == 0x2b) {
    FUN_0805b0ec((int)param_3,"2Expected \'%s\', found \'%s\'.");
    iVar2 = 0x2b;
  }
  else {
    if (iVar2 != 0x28) {
      local_4c = 0xb000;
      local_48 = (char *)0x2000;
      iVar4 = FUN_08050ad0(param_2,&local_50,(int *)0x0);
      if (iVar4 != 0) {
        return iVar2;
      }
      FUN_0805b0d8("2No object(+ATTRIBUTES) matches %s(+%s).");
      return iVar2;
    }
    puVar6 = param_3;
    iVar2 = FUN_0805b3e8(0x28,param_3);
    iVar2 = FUN_0805b418(iVar2,puVar6);
  }
  local_58 = 0;
  bVar1 = false;
  local_54 = 0;
LAB_0805b85c:
  bVar5 = iVar2 != 0x2b;
  if (!bVar5) {
    puVar6 = param_3;
    iVar2 = FUN_0805b3e8(0x2b,param_3);
    iVar2 = FUN_0805b418(iVar2,puVar6);
  }
  iVar2 = FUN_0805b5ec(iVar2,(int)local_44,param_3);
  if (local_44[0] == '\0') {
    FUN_0805b0ec((int)param_3,"2Missing AREA selector.");
    bVar1 = true;
  }
  else {
    if (bVar5) {
      local_4c = 0;
      local_48 = local_44;
LAB_0805b9a5:
      iVar4 = FUN_08050ad0(param_2,&local_50,&local_54);
      if (iVar4 != 0) {
        bVar1 = true;
      }
    }
    else {
      pcVar3 = (char *)FUN_0805b704(local_44);
      if (pcVar3 == (char *)0x8) {
        pcVar3 = "2Unknown AREA selector \'+%s\'.";
LAB_0805b900:
        FUN_0805b0ec((int)param_3,pcVar3);
      }
      else {
        if ((pcVar3 != (char *)0x2) && (pcVar3 != (char *)0x4)) {
          local_4c = 0xb200;
          if (pcVar3 == (char *)0x1) {
            local_4c = 0xb201;
          }
          if (((uint)pcVar3 & 0x10) != 0) {
            local_4c = local_4c & 0xfffffdff;
            pcVar3 = (char *)((uint)pcVar3 & 0xffffffef);
          }
          local_48 = pcVar3;
          if (((uint)pcVar3 & 0x300000) != 0) {
            local_4c = local_4c | 0x300000;
          }
          goto LAB_0805b9a5;
        }
        if ((local_58 != 1) || (iVar2 = FUN_0805b418(iVar2,param_3), iVar2 != 0x29)) {
          pcVar3 = "2%s must follow a single selector.";
          goto LAB_0805b900;
        }
        if (local_54 == 0) {
          if (bVar1) {
            pcVar3 = "2More than one AREA matches - cannot all be FIRST/LAST.";
          }
          else {
            pcVar3 = "2No AREA matches - no AREA to be FIRST/LAST.";
          }
          FUN_0805b0ec((int)param_3,pcVar3);
        }
        else {
          local_48 = pcVar3;
          FUN_08050ad0(0,&local_50,&local_54);
        }
      }
    }
    iVar2 = FUN_0805b418(iVar2,param_3);
    local_58 = local_58 + 1;
  }
  if (iVar2 - 0x2bU < 2) {
    if (iVar2 == 0x2c) {
      puVar6 = param_3;
      iVar2 = FUN_0805b3e8(0x2c,param_3);
      iVar2 = FUN_0805b418(iVar2,puVar6);
    }
    goto LAB_0805b85c;
  }
  if (iVar2 == 0x29) {
    if (!bVar1) {
      FUN_0805b0ec((int)param_3,"1No AREAs selected by \'%s(...)\'.");
    }
LAB_0805ba39:
    if (iVar2 != 0x29) {
      return iVar2;
    }
  }
  else {
    FUN_0805b5c4((undefined4 *)local_44,iVar2);
    FUN_0805b0ec((int)param_3,"2Expected \'%s\', found \'%s\'.");
    do {
      if ((iVar2 == 0x7d) || (iVar2 == -1)) goto LAB_0805ba39;
      puVar6 = param_3;
      iVar2 = FUN_0805b3e8(iVar2,param_3);
      iVar2 = FUN_0805b418(iVar2,puVar6);
    } while (iVar2 != 0x29);
  }
  iVar2 = FUN_0805b3e8(iVar2,param_3);
  iVar2 = FUN_0805b418(iVar2,param_3);
  return iVar2;
}



// WARNING: Removing unreachable block (ram,0x0805bc1a)
// WARNING: Removing unreachable block (ram,0x0805bc24)

int FUN_0805ba5c(int param_1,int param_2,int param_3,undefined4 *param_4)

{
  int iVar1;
  undefined4 *puVar2;
  int extraout_EAX;
  int extraout_EAX_00;
  int extraout_EAX_01;
  int *piVar3;
  undefined4 uVar4;
  char *pcVar5;
  uint local_60;
  undefined4 local_5c;
  uint local_58;
  char *local_54;
  undefined *local_50;
  undefined4 local_4c;
  undefined4 local_48;
  char local_44 [32];
  char local_24;
  char local_23 [31];
  
  local_60 = 0;
  iVar1 = FUN_0805b5ec(param_1,(int)&local_24,param_4);
  if (local_24 == '\0') {
    FUN_0805b0ec((int)param_4,"2Missing region name.");
  }
  local_58 = 0xffffffff;
  puVar2 = (undefined4 *)FUN_0805b418(iVar1,param_4);
  if (((puVar2 == (undefined4 *)0x26) || (iVar1 = isdigit((int)puVar2), iVar1 != 0)) ||
     ((puVar2 == (undefined4 *)0x2b && (param_3 == 2)))) {
    if (puVar2 == (undefined4 *)0x2b) {
      puVar2 = param_4;
      iVar1 = FUN_0805b3e8(0x2b,param_4);
      puVar2 = (undefined4 *)FUN_0805b418(iVar1,puVar2);
      local_60 = 2;
      if ((puVar2 != (undefined4 *)0x26) && (iVar1 = isdigit((int)puVar2), iVar1 == 0)) {
        FUN_0805b0ec((int)param_4,"2Missing base address.");
        if ((puVar2 == (undefined4 *)0x7d) || (puVar2 == (undefined4 *)0xffffffff))
        goto LAB_0805bf14;
        local_58 = 0;
      }
    }
    if ((local_58 == 0xffffffff) &&
       (puVar2 = (undefined4 *)FUN_0805b4bc((int)puVar2,&local_58,param_4), (local_58 & 3) != 0)) {
      FUN_0805b0ec((int)param_4,"2Non-word-aligned base address.");
      local_58 = local_58 & 0xfffffffc;
    }
  }
  else {
    local_54 = (char *)0x0;
    if (local_24 == '&') {
      uVar4 = 0x10;
      pcVar5 = local_23;
LAB_0805bb0d:
      __strtoul_internal(pcVar5,&local_54,uVar4,0);
    }
    else {
      iVar1 = isdigit((int)local_24);
      if (iVar1 != 0) {
        uVar4 = 0;
        pcVar5 = &local_24;
        goto LAB_0805bb0d;
      }
    }
    if ((local_54 == (char *)0x0) || (*local_54 != '\0')) {
      pcVar5 = "2Missing base address.";
    }
    else {
      pcVar5 = "2Missing region name.";
    }
    FUN_0805b0ec((int)param_4,pcVar5);
    if ((puVar2 == (undefined4 *)0x7d) || (puVar2 == (undefined4 *)0xffffffff)) goto LAB_0805bf14;
  }
  local_5c = 0;
  if (param_3 == 1) {
    iVar1 = FUN_0804b6c0(&local_24,"ROOT-DATA");
    if ((iVar1 == 0) && (DAT_0806a624 == 0)) {
      FUN_0805b0ec((int)param_4,"2No default ROOT definition precedes this ROOT-DATA definition.");
    }
    puVar2 = (undefined4 *)FUN_0805b418((int)puVar2,param_4);
    if ((puVar2 == (undefined4 *)0x26) || (iVar1 = isdigit((int)puVar2), iVar1 != 0)) {
      puVar2 = (undefined4 *)FUN_0805b4bc((int)puVar2,&local_5c,param_4);
    }
    iVar1 = FUN_0804b6c0(&local_24,"ROOT");
    if (iVar1 == 0) {
      FUN_0805b0ec((int)param_4,"1%s will not be supported by future releases of the toolkit.");
      if (DAT_0806a624 == 0) {
        puVar2 = FUN_08050ca8("ROOT",PTR_DAT_08068878,local_58,local_5c);
        DAT_0806a624 = extraout_EAX;
      }
      else {
        FUN_0805b0ec((int)param_4,"2Load region %s has already been defined.");
      }
LAB_0805bd5e:
      iVar1 = FUN_0805b418((int)puVar2,param_4);
      return iVar1;
    }
    iVar1 = FUN_0804b6c0(&local_24,"ROOT-DATA");
    if (iVar1 == 0) {
      FUN_0805b0ec((int)param_4,"1%s will not be supported by future releases of the toolkit.");
      if (DAT_0806a624 != 0) {
        puVar2 = FUN_08050ca8("ROOT-DATA",(undefined *)0x0,local_58,local_5c);
        local_50 = &DAT_08066dbc;
        local_4c = 0xa000;
        local_48 = 0;
        PTR_DAT_0806887c = (undefined *)FUN_08050d34(extraout_EAX_00,"root",local_58,0);
        FUN_08050ad0((int)PTR_DAT_0806887c,&local_50,(int *)0x0);
      }
      DAT_0806abdc = local_58;
      goto LAB_0805bd5e;
    }
  }
  else {
    puVar2 = (undefined4 *)FUN_0805b418((int)puVar2,param_4);
    if ((param_3 == 2) && (iVar1 = FUN_0805b48c((int)puVar2,"{}(),+"), iVar1 == 0)) {
      puVar2 = (undefined4 *)FUN_0805b5ec((int)puVar2,(int)local_44,param_4);
      iVar1 = FUN_0804b6c0(local_44,"overlay");
      if (iVar1 == 0) {
        local_60 = local_60 | 1;
        FUN_0805b0ec((int)param_4,"1%s will not be supported by future releases of the toolkit.");
      }
      else {
        FUN_0805b0ec((int)param_4,"2Expected \'%s\', found \'%s\'.");
      }
    }
  }
  iVar1 = FUN_0805b418((int)puVar2,param_4);
  if (iVar1 != 0x7b) {
    FUN_0805b5c4((undefined4 *)local_44,iVar1);
    FUN_0805b0ec((int)param_4,"2Expected \'%s\', found \'%s\'.");
    return -1;
  }
  puVar2 = param_4;
  iVar1 = FUN_0805b3e8(0x7b,param_4);
  puVar2 = (undefined4 *)FUN_0805b418(iVar1,puVar2);
  if (puVar2 == (undefined4 *)0x7d) {
    if (param_3 == 1) {
      pcVar5 = "1Empty LOAD region.";
    }
    else {
      pcVar5 = "1Empty EXEC region.";
    }
    FUN_0805b0ec((int)param_4,pcVar5);
    puVar2 = (undefined4 *)0x7d;
  }
  else if (param_3 == 1) {
    puVar2 = FUN_08050ca8(&local_24,(undefined *)0x0,local_58,local_5c);
    if (extraout_EAX_01 == 0) {
      FUN_0805b0ec((int)param_4,"2Load region %s has already been defined.");
    }
    do {
      puVar2 = (undefined4 *)FUN_0805ba5c((int)puVar2,extraout_EAX_01,2,param_4);
      if (puVar2 == (undefined4 *)0xffffffff) goto LAB_0805befc;
    } while (puVar2 != (undefined4 *)0x7d);
  }
  else {
    piVar3 = FUN_08050d34(param_2,&local_24,local_58,local_60);
    do {
      puVar2 = (undefined4 *)FUN_0805b748((int)puVar2,(int)piVar3,param_4);
      if (puVar2 == (undefined4 *)0xffffffff) break;
    } while (puVar2 != (undefined4 *)0x7d);
  }
  if (puVar2 == (undefined4 *)0xffffffff) {
LAB_0805befc:
    FUN_0805b0ec((int)param_4,"2Expected \'%s\', found \'%s\'.");
  }
LAB_0805bf14:
  iVar1 = FUN_0805b3e8((int)puVar2,param_4);
  iVar1 = FUN_0805b418(iVar1,param_4);
  return iVar1;
}



void FUN_0805bf30(char *param_1)

{
  char *__buf;
  int iVar1;
  int iVar2;
  size_t __n;
  FILE *local_18;
  undefined4 local_14;
  char *local_c;
  
  if (param_1 != (char *)0x0) {
    local_18 = FUN_08060e7c(param_1,"r");
    if (local_18 != (FILE *)0x0) {
      FUN_0804b418();
      __n = 0x2000;
      iVar2 = 0;
      __buf = (char *)FUN_0804b3ac(0x2000);
      setvbuf(local_18,__buf,iVar2,__n);
      FUN_08050ca8("ROOT",(undefined *)0x0,0,0);
      DAT_0806a624 = 0;
      local_14 = 0;
      local_c = param_1;
      iVar2 = 0;
      iVar1 = FUN_0805b418(10,&local_18);
      while (iVar1 != -1) {
        iVar1 = FUN_0805ba5c(iVar1,0,1,&local_18);
        iVar2 = iVar2 + 1;
      }
      FUN_08060ec8(local_18);
      FUN_0804b434();
      if (iVar2 != 0) {
        return;
      }
      FUN_0805b0ec((int)&local_18,"2Scatter description file \'%s\' is empty.");
      return;
    }
    local_18 = (FILE *)0x0;
  }
  FUN_0805b0d8("3Can\'t open file \'%s\'.");
  return;
}



void FUN_0805c010(void *param_1,uint param_2)

{
  void *pvVar1;
  uint uVar2;
  
  uVar2 = param_2 + 3 & 0xfffffffc;
  if ((DAT_0806891c == (void *)0x0) || (pvVar1 = DAT_0806891c, DAT_08068918 < uVar2 + DAT_08068920))
  {
    for (; DAT_08068918 < uVar2 + DAT_08068920; DAT_08068918 = DAT_08068918 * 2) {
    }
    pvVar1 = (void *)FUN_0804b1e8(DAT_08068918);
    if (DAT_0806891c != (void *)0x0) {
      memcpy(pvVar1,DAT_0806891c,DAT_08068920);
    }
  }
  DAT_0806891c = pvVar1;
  pvVar1 = memcpy((void *)(DAT_08068920 + (int)DAT_0806891c),param_1,param_2);
  for (; param_2 < uVar2; param_2 = param_2 + 1) {
    *(undefined1 *)(param_2 + (int)pvVar1) = 0;
  }
  DAT_08068920 = DAT_08068920 + uVar2;
  return;
}



void FUN_0805c0c0(void)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int local_8;
  
  iVar2 = DAT_0806ac84;
  iVar5 = DAT_0806ac84 * 4;
  piVar3 = (int *)FUN_0804b1e8(iVar5);
  DAT_0806a740 = piVar3;
  DAT_0806a744 = FUN_0804b1e8(iVar5);
  piVar4 = (int *)FUN_0804b134(&local_8);
  while (piVar4 != (int *)0x0) {
    uVar1 = ((int *)*piVar4)[4];
    if (((uVar1 & 0x2000000) != 0) && (iVar5 = *(int *)*piVar4, -1 < iVar5)) {
      if ((uVar1 & 0x8000000) == 0) {
        iVar6 = 8;
      }
      else {
        iVar6 = 0x10;
      }
      piVar3[iVar5] = iVar6;
    }
    piVar4 = (int *)FUN_0804b154(&local_8);
  }
  iVar5 = 0;
  iVar6 = 0;
  if (0 < iVar2) {
    do {
      *(int *)(DAT_0806a744 + iVar6 * 4) = iVar5;
      iVar5 = iVar5 + *piVar3;
      piVar3 = piVar3 + 1;
      iVar6 = iVar6 + 1;
    } while (iVar6 < iVar2);
  }
  if (iVar5 != (iVar2 + DAT_0806a748) * 8) {
    FUN_0805b0d8("3EFT map botch: len = %lu, should be %lu.");
  }
  return;
}



int FUN_0805c178(int param_1,int param_2)

{
  int iVar1;
  
  if (((byte)DAT_0806ab68 & 0x20) == 0) {
    iVar1 = param_1 * 0x10 + *(int *)(DAT_0806ac6c + 0x2c);
  }
  else if (param_2 == 3) {
    iVar1 = *(int *)(DAT_0806ac74 + 0x2c) + param_1 * 0xc;
  }
  else {
    iVar1 = *(int *)(DAT_0806a744 + param_1 * 4) + *(int *)(DAT_0806ac6c + 0x2c);
  }
  return iVar1;
}



void FUN_0805c1c4(uint *param_1,int param_2,uint *param_3)

{
  uint uVar1;
  uint *puVar2;
  
  uVar1 = FUN_0805e13c(0xe92d407f);
  *param_1 = uVar1;
  uVar1 = FUN_0805e13c(0xe24f000c);
  param_1[1] = uVar1;
  uVar1 = FUN_0805e13c(0xe59ff008);
  param_1[2] = uVar1;
  param_1[3] = 0;
  uVar1 = FUN_0805e13c(*(uint *)(*DAT_0806ac58 + 8));
  param_1[4] = uVar1;
  param_1[5] = 0;
  param_1[6] = 0;
  puVar2 = param_1 + 7;
  for (uVar1 = 0; uVar1 < DAT_08068920 >> 2; uVar1 = uVar1 + 1) {
    *puVar2 = *(uint *)(DAT_0806891c + uVar1 * 4);
    puVar2 = puVar2 + 1;
  }
  uVar1 = FUN_0805e13c(param_2 + 0xc);
  *param_3 = uVar1;
  uVar1 = FUN_0805e13c(0x8a000001);
  param_3[1] = uVar1;
  uVar1 = FUN_0805e13c(param_2 + 0x14);
  param_3[2] = uVar1;
  uVar1 = FUN_0805e13c(0x8a000002);
  param_3[3] = uVar1;
  uVar1 = FUN_0805e13c(param_2 + 0x18);
  param_3[4] = uVar1;
  uVar1 = FUN_0805e13c(0x8a000000);
  param_3[5] = uVar1;
  return;
}



void FUN_0805c2a8(int param_1)

{
  undefined4 *puVar1;
  
  *(undefined4 *)(param_1 + 0x1c) = 3;
  puVar1 = (undefined4 *)FUN_0804b1e8(0xc);
  *(undefined4 **)(param_1 + 0x20) = puVar1;
  *puVar1 = DAT_0806a74c;
  *(undefined4 *)(*(int *)(param_1 + 0x20) + 4) = DAT_0806ac60;
  *(undefined4 *)(*(int *)(param_1 + 0x20) + 8) = DAT_0806ac68;
  return;
}



void FUN_0805c2e4(void)

{
  size_t sVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined4 extraout_EAX;
  undefined4 extraout_EAX_00;
  uint uVar7;
  uint uVar8;
  undefined4 uVar9;
  uint uVar10;
  uint uVar11;
  size_t sVar12;
  undefined4 *puVar13;
  char *pcVar14;
  uint *local_30;
  char *local_28;
  uint *local_c;
  
  uVar4 = DAT_0806ac84;
  sVar12 = DAT_0806ac84 * 0xc;
  sVar1 = DAT_08068920 + 0x1c + (DAT_0806ac84 + DAT_0806a748) * 8;
  uVar11 = DAT_0806ac84 * 8 + 0x18;
  DAT_0806ac7c = 0xc;
  uVar8 = 0xffffffff;
  pcVar14 = "<anon>";
  do {
    if (uVar8 == 0) break;
    uVar8 = uVar8 - 1;
    cVar2 = *pcVar14;
    pcVar14 = pcVar14 + 1;
  } while (cVar2 != '\0');
  iVar5 = FUN_0804b1e8(~uVar8 + 0x27);
  uVar8 = 0xffffffff;
  pcVar14 = "<anon>";
  do {
    if (uVar8 == 0) break;
    uVar8 = uVar8 - 1;
    cVar2 = *pcVar14;
    pcVar14 = pcVar14 + 1;
  } while (cVar2 != '\0');
  if (~uVar8 < 9) {
    uVar8 = 0xffffffff;
    pcVar14 = "<anon>";
    do {
      if (uVar8 == 0) break;
      uVar8 = uVar8 - 1;
      cVar2 = *pcVar14;
      pcVar14 = pcVar14 + 1;
    } while (cVar2 != '\0');
    puVar13 = (undefined4 *)(iVar5 + 0x24);
    switch(~uVar8) {
    case 1:
      *(undefined1 *)puVar13 = 0;
      break;
    case 2:
      *(undefined2 *)puVar13 = 0x613c;
      break;
    case 3:
      *(undefined2 *)puVar13 = 0x613c;
      *(undefined1 *)(iVar5 + 0x26) = 0;
      break;
    case 4:
      *puVar13 = 0x6f6e613c;
      break;
    case 5:
      *puVar13 = 0x6f6e613c;
      *(undefined1 *)(iVar5 + 0x28) = 0;
      break;
    case 6:
      *puVar13 = 0x6f6e613c;
      *(undefined2 *)(iVar5 + 0x28) = 0x3e6e;
      break;
    case 7:
      *puVar13 = 0x6f6e613c;
      *(undefined2 *)(iVar5 + 0x28) = 0x3e6e;
      *(undefined1 *)(iVar5 + 0x2a) = 0;
      break;
    case 8:
      *puVar13 = 0x6f6e613c;
      *(undefined4 *)(iVar5 + 0x28) = 0x3e6e;
    }
  }
  else {
    uVar8 = 0xffffffff;
    pcVar14 = "<anon>";
    do {
      if (uVar8 == 0) break;
      uVar8 = uVar8 - 1;
      cVar2 = *pcVar14;
      pcVar14 = pcVar14 + 1;
    } while (cVar2 != '\0');
    memcpy((void *)(iVar5 + 0x24),&DAT_08066eea,~uVar8);
  }
  local_28 = (char *)(iVar5 + 0x24);
  iVar3 = uVar4 * 0x14;
  iVar6 = sVar1 + iVar3 + uVar11;
  *(int *)(iVar5 + 0xc) = iVar6;
  local_c = (uint *)FUN_0804b1e8(iVar6);
  *(uint **)(iVar5 + 0x14) = local_c;
  iVar5 = FUN_0804da7c(local_28,iVar5);
  if (*(int *)(*DAT_0806ac68 + 0xc) == 0) {
    uVar9 = 2;
  }
  else {
    uVar9 = 3;
  }
  *(undefined4 *)(iVar5 + 0x24) = uVar9;
  iVar6 = FUN_0804b1e8(0xc);
  *(int *)(iVar5 + 0x28) = iVar6;
  *(undefined4 *)(iVar6 + 8) = *(undefined4 *)(*DAT_0806ac68 + 0xc);
  puVar13 = FUN_0804c360("sb$$interLUcode",iVar5,0,sVar12,sVar12,uVar4 & 0x1fffffff,0x32202,0);
  DAT_0806ac74 = extraout_EAX;
  *(undefined4 *)puVar13[10] = extraout_EAX;
  puVar13 = FUN_0804c360("sb$$interLUdata",puVar13,iVar3,sVar1,iVar3 + sVar1,uVar11 >> 3,0x9100002,1
                        );
  DAT_0806ac6c = extraout_EAX_00;
  *(undefined4 *)(puVar13[10] + 4) = extraout_EAX_00;
  FUN_0805c2a8((int)puVar13);
  FUN_0805c0c0();
  uVar11 = 0;
  if (uVar4 != 0) {
    do {
      uVar10 = *(int *)(DAT_0806a744 + uVar11 * 4) + -8 + *(int *)(DAT_0806a740 + uVar11 * 4);
      uVar8 = FUN_08051444(uVar10);
      uVar7 = FUN_0805e13c(uVar8 + 0xe289c000);
      *local_c = uVar7;
      uVar8 = FUN_08051404(uVar8);
      uVar8 = FUN_08051444(uVar10 - uVar8);
      uVar8 = FUN_0805e13c(uVar8 + 0xe28cc000);
      local_c[1] = uVar8;
      uVar8 = FUN_0805e13c(0xe89c9000);
      local_c[2] = uVar8;
      local_c = local_c + 3;
      uVar11 = uVar11 + 1;
    } while (uVar11 < uVar4);
  }
  local_30 = local_c;
  if (uVar4 != 0) {
    uVar11 = 0;
    uVar8 = 0;
    do {
      uVar7 = FUN_0805e13c(uVar11);
      *local_30 = uVar7;
      uVar7 = FUN_0805e13c(0x93000001);
      local_30[1] = uVar7;
      local_30 = local_30 + 2;
      uVar11 = uVar11 + 0xc;
      uVar8 = uVar8 + 1;
    } while (uVar8 < uVar4);
  }
  local_c = local_30;
  local_30 = (uint *)((int)local_30 + sVar1);
  uVar11 = (uVar4 + DAT_0806a748) * 8;
  iVar5 = 0;
  uVar8 = 0;
  if (uVar4 != 0) {
    do {
      if (*(int *)(DAT_0806a740 + uVar8 * 4) == 0x10) {
        uVar7 = FUN_0805e13c(0xe28fc000);
        *local_c = uVar7;
        uVar7 = FUN_0805e13c(0xe89c9000);
        local_c[1] = uVar7;
        local_c = local_c + 2;
        iVar5 = iVar5 + 8;
      }
      uVar7 = FUN_0805e13c(uVar8);
      *local_c = uVar7;
      uVar7 = FUN_0805e13c(uVar11);
      local_c[1] = uVar7;
      local_c = local_c + 2;
      uVar7 = FUN_0805e13c(iVar5 + 4);
      *local_30 = uVar7;
      uVar7 = FUN_0805e13c(0x82000001);
      local_30[1] = uVar7;
      local_30 = local_30 + 2;
      iVar5 = iVar5 + 8;
      uVar8 = uVar8 + 1;
    } while (uVar8 < uVar4);
  }
  FUN_0805c1c4(local_c,uVar11,local_30);
  return;
}



void FUN_0805c738(void)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 extraout_EAX;
  uint uVar6;
  undefined4 uVar7;
  uint uVar8;
  uint *puVar9;
  size_t sVar10;
  undefined4 *puVar11;
  char *pcVar12;
  uint *local_2c;
  uint local_24;
  char *local_20;
  
  uVar3 = DAT_0806ac84;
  uVar2 = DAT_0806ac84 * 0x10;
  sVar10 = DAT_08068920 + 0x1c + uVar2;
  uVar8 = DAT_0806ac84 * 8 + 0x18;
  DAT_0806ac7c = 0x10;
  uVar6 = 0xffffffff;
  pcVar12 = "<anon>";
  do {
    if (uVar6 == 0) break;
    uVar6 = uVar6 - 1;
    cVar1 = *pcVar12;
    pcVar12 = pcVar12 + 1;
  } while (cVar1 != '\0');
  iVar4 = FUN_0804b1e8(~uVar6 + 0x27);
  uVar6 = 0xffffffff;
  pcVar12 = "<anon>";
  do {
    if (uVar6 == 0) break;
    uVar6 = uVar6 - 1;
    cVar1 = *pcVar12;
    pcVar12 = pcVar12 + 1;
  } while (cVar1 != '\0');
  if (~uVar6 < 9) {
    uVar6 = 0xffffffff;
    pcVar12 = "<anon>";
    do {
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar12 + 1;
    } while (cVar1 != '\0');
    puVar11 = (undefined4 *)(iVar4 + 0x24);
    switch(~uVar6) {
    case 1:
      *(undefined1 *)puVar11 = 0;
      break;
    case 2:
      *(undefined2 *)puVar11 = 0x613c;
      break;
    case 3:
      *(undefined2 *)puVar11 = 0x613c;
      *(undefined1 *)(iVar4 + 0x26) = 0;
      break;
    case 4:
      *puVar11 = 0x6f6e613c;
      break;
    case 5:
      *puVar11 = 0x6f6e613c;
      *(undefined1 *)(iVar4 + 0x28) = 0;
      break;
    case 6:
      *puVar11 = 0x6f6e613c;
      *(undefined2 *)(iVar4 + 0x28) = 0x3e6e;
      break;
    case 7:
      *puVar11 = 0x6f6e613c;
      *(undefined2 *)(iVar4 + 0x28) = 0x3e6e;
      *(undefined1 *)(iVar4 + 0x2a) = 0;
      break;
    case 8:
      *puVar11 = 0x6f6e613c;
      *(undefined4 *)(iVar4 + 0x28) = 0x3e6e;
    }
  }
  else {
    uVar6 = 0xffffffff;
    pcVar12 = "<anon>";
    do {
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar12 + 1;
    } while (cVar1 != '\0');
    memcpy((void *)(iVar4 + 0x24),&DAT_08066eea,~uVar6);
  }
  local_20 = (char *)(iVar4 + 0x24);
  iVar5 = sVar10 + uVar8;
  *(int *)(iVar4 + 0xc) = iVar5;
  local_2c = (uint *)FUN_0804b1e8(iVar5);
  *(uint **)(iVar4 + 0x14) = local_2c;
  iVar4 = FUN_0804da7c(local_20,iVar4);
  if (*(int *)(*DAT_0806ac68 + 0xc) == 0) {
    uVar7 = 1;
  }
  else {
    uVar7 = 2;
  }
  *(undefined4 *)(iVar4 + 0x24) = uVar7;
  iVar5 = FUN_0804b1e8(8);
  *(int *)(iVar4 + 0x28) = iVar5;
  *(undefined4 *)(iVar5 + 4) = *(undefined4 *)(*DAT_0806ac68 + 0xc);
  puVar11 = FUN_0804c360("sb$$interLUdata",iVar4,0,sVar10,sVar10,uVar8 >> 3,0x9100002,0);
  DAT_0806ac6c = extraout_EAX;
  DAT_0806ac74 = extraout_EAX;
  *(undefined4 *)puVar11[10] = extraout_EAX;
  FUN_0805c2a8((int)puVar11);
  uVar8 = 0;
  if (uVar3 != 0) {
    do {
      uVar6 = FUN_0805e13c(0xe28fc000);
      *local_2c = uVar6;
      uVar6 = FUN_0805e13c(0xe89c9000);
      local_2c[1] = uVar6;
      uVar6 = FUN_0805e13c(uVar8);
      local_2c[2] = uVar6;
      uVar6 = FUN_0805e13c(uVar2);
      local_2c[3] = uVar6;
      local_2c = local_2c + 4;
      uVar8 = uVar8 + 1;
    } while (uVar8 < uVar3);
  }
  puVar9 = (uint *)((int)local_2c + DAT_08068920 + 0x1c);
  uVar8 = 0;
  if (uVar3 != 0) {
    local_24 = 0xc;
    do {
      uVar6 = FUN_0805e13c(local_24);
      *puVar9 = uVar6;
      uVar6 = FUN_0805e13c(0x82000000);
      puVar9[1] = uVar6;
      puVar9 = puVar9 + 2;
      local_24 = local_24 + 0x10;
      uVar8 = uVar8 + 1;
    } while (uVar8 < uVar3);
  }
  FUN_0805c1c4(local_2c,uVar2,puVar9);
  return;
}



void FUN_0805ca44(void)

{
  if (((byte)DAT_0806ab68 & 0x20) == 0) {
    FUN_0805c738();
  }
  else {
    FUN_0805c2e4();
  }
  return;
}



void FUN_0805ca60(uint param_1)

{
  uint local_8;
  
  local_8 = FUN_0805e13c(param_1);
  FUN_0805c010(&local_8,4);
  return;
}



char * FUN_0805ca80(int param_1)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  
  pcVar3 = (char *)(param_1 + 1);
  cVar1 = *pcVar3;
  pcVar2 = (char *)(param_1 + 2);
  pcVar4 = pcVar3;
  pcVar5 = pcVar3;
  while( true ) {
    if (cVar1 == '\0') {
      return pcVar4;
    }
    if ((cVar1 == '\\') && ((*pcVar2 == '\"' || (*pcVar2 == '\\')))) {
      cVar1 = *pcVar2;
    }
    else if (cVar1 == '\"') {
      cVar1 = '\0';
    }
    *pcVar5 = cVar1;
    pcVar5 = pcVar5 + 1;
    if (cVar1 == '\0') break;
    pcVar2 = pcVar2 + 1;
    pcVar4 = pcVar4 + 1;
    cVar1 = *pcVar4;
  }
  FUN_0805c010(pcVar3,(int)pcVar5 - (int)pcVar3);
  return pcVar4 + 1;
}



undefined4 * FUN_0805cae4(char *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = DAT_0806ab90;
  if (*param_1 == '\0') {
    puVar1 = (undefined4 *)&DAT_08066f34;
  }
  else {
    for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      iVar2 = FUN_0804b6c0((char *)puVar1[1],param_1);
      if (iVar2 == 0) {
        return puVar1 + 0xb;
      }
    }
    puVar1 = (undefined4 *)0x0;
  }
  return puVar1;
}



undefined1 * FUN_0805cb30(_IO_FILE *param_1)

{
  int iVar1;
  int iVar2;
  undefined1 *puVar3;
  
  iVar2 = 0xfd;
  puVar3 = &DAT_0806a642;
  while ((iVar1 = _IO_getc(param_1), iVar1 != -1 && (iVar1 != 10))) {
    if (0 < iVar2) {
      *puVar3 = (char)iVar1;
      puVar3 = puVar3 + 1;
      iVar2 = iVar2 + -1;
    }
  }
  if (iVar2 == 0) {
    FUN_0805b0d8("2%s, line %u: line truncated");
  }
  *puVar3 = 0;
  if ((puVar3 == &DAT_0806a642) && (iVar2 = feof(param_1), iVar2 != 0)) {
    return (undefined1 *)0x0;
  }
  return &DAT_0806a642;
}



void FUN_0805cba0(char *param_1)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  uint uVar8;
  char *local_8;
  
  local_8 = "!!";
  pcVar7 = param_1;
  while (((iVar5 = (int)*pcVar7, iVar5 != 0 && (iVar5 != 0x28)) &&
         (iVar3 = isspace(iVar5), iVar3 == 0))) {
    pcVar7 = pcVar7 + 1;
  }
  *pcVar7 = '\0';
  pcVar6 = pcVar7;
  while (iVar3 = isspace(iVar5), iVar3 != 0) {
    pcVar6 = pcVar6 + 1;
    iVar5 = (int)*pcVar6;
  }
  if (iVar5 == 0x28) {
    do {
      pcVar6 = pcVar6 + 1;
      iVar5 = isspace((int)*pcVar6);
    } while (iVar5 != 0);
    cVar1 = *pcVar6;
    pcVar7 = pcVar6;
    while( true ) {
      if (cVar1 == '\0') {
        FUN_0805b0d8("2Missing \')\' in EFT entry name %s(%s).");
        return;
      }
      if (cVar1 == ')') break;
      pcVar7 = pcVar7 + 1;
      cVar1 = *pcVar7;
    }
    while ((pcVar6 < pcVar7 && (iVar5 = isspace((int)pcVar7[-1]), iVar5 != 0))) {
      pcVar7 = pcVar7 + -1;
    }
    *pcVar7 = '\0';
    local_8 = (char *)FUN_0805cae4(pcVar6);
    if (local_8 == (char *)0x0) {
      FUN_0805b0d8("2Object \'%s\' not found.");
      return;
    }
    uVar8 = 0x8000000;
    pcVar7 = pcVar6;
  }
  else {
    uVar8 = 0x4000000;
  }
  param_1[-2] = *local_8;
  param_1[-1] = local_8[1];
  piVar4 = FUN_0804b030(param_1 + -2,DAT_0806ab74);
  if (piVar4 == (int *)0x0) {
    if (*pcVar7 == '\0') {
      FUN_0805b0d8("2External symbol \'%s\' not found.");
      return;
    }
    FUN_0805b0d8("2Symbol \'%s\' not found in object \'%s\'.");
    return;
  }
  piVar4 = (int *)*piVar4;
  if (piVar4[3] == 0) {
    if ((piVar4[4] & 4U) != 0) {
      piVar4[4] = piVar4[4] | 0x1000000;
      FUN_0805b0d8("1Constant symbol %s has migrated to the stub.");
      return;
    }
    FUN_0805b0d8("2Symbol %s cannot be exported from shared-library.");
    return;
  }
  if (((*(byte *)(piVar4[3] + 0x31) & 2) == 0) || (uVar2 = piVar4[4], (uVar2 & 0x100) != 0)) {
    if (uVar8 != 0x8000000) goto LAB_0805cd8b;
    pcVar7 = "2EFT name %s(%s) is non-code symbol.";
  }
  else {
    if ((uVar8 & uVar2) == 0) {
      if ((uVar2 & 0x2000000) == 0) {
        *piVar4 = DAT_0806ac84;
        DAT_0806ac84 = DAT_0806ac84 + 1;
      }
      if (uVar8 == 0x8000000) {
        DAT_0806a748 = DAT_0806a748 + 1;
      }
      goto LAB_0805cd8b;
    }
    if (uVar8 == 0x4000000) {
      FUN_0805b0d8("1Duplicate EFT entry %s ignored.");
      goto LAB_0805cd8b;
    }
    pcVar7 = "1Duplicate EFT entry %s(%s) ignored.";
  }
  FUN_0805b0d8(pcVar7);
LAB_0805cd8b:
  piVar4[4] = piVar4[4] | uVar8 + 0x2000000;
  return;
}



void FUN_0805cd9c(char *param_1,char *param_2)

{
  int *piVar1;
  bool bVar2;
  int iVar3;
  
  bVar2 = false;
  DAT_0806ac80 = 1;
  for (piVar1 = DAT_0806ab88; piVar1 != (int *)0x0; piVar1 = (int *)piVar1[2]) {
    if ((((param_1 == (char *)0x0) ||
         (iVar3 = FUN_0804b6c0(param_1,*(char **)(*piVar1 + 4)), iVar3 == 0)) &&
        ((param_2 == (char *)0x0 ||
         ((*param_2 == '\0' ||
          (iVar3 = FUN_0804b6c0(param_2,(char *)((int)piVar1 + 0x46)), iVar3 == 0)))))) &&
       ((piVar1[0xc] & 0x30de00U) == 0)) {
      *(byte *)(piVar1 + 0xd) = *(byte *)(piVar1 + 0xd) | 8;
      bVar2 = true;
    }
  }
  if (!bVar2) {
    FUN_0805b0d8("1No object(AREA) matches \'+ %s(%s)\'.");
  }
  return;
}



void FUN_0805ce38(char *param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  char *local_8;
  
  if (*param_1 != '\0') {
    do {
      iVar3 = (int)*param_1;
      pcVar4 = param_1 + 1;
      if (iVar3 == 0) {
        return;
      }
      if (iVar3 == 0x3b) {
        return;
      }
      iVar2 = isspace(iVar3);
      if ((iVar2 == 0) && (iVar3 != 0x2c)) {
        if (iVar3 == 0x28) {
          local_8 = (char *)0x0;
        }
        else {
          while ((((iVar3 != 0 && (iVar2 = isspace(iVar3), iVar2 == 0)) && (iVar3 != 0x2c)) &&
                 (iVar3 != 0x28))) {
            cVar1 = *pcVar4;
            pcVar4 = pcVar4 + 1;
            iVar3 = (int)cVar1;
          }
          pcVar4[-1] = '\0';
          while (iVar2 = isspace(iVar3), local_8 = param_1, iVar2 != 0) {
            iVar3 = (int)*pcVar4;
            pcVar4 = pcVar4 + 1;
          }
        }
        if (iVar3 == 0x28) {
          while (iVar3 != 0x29) {
            do {
              do {
                pcVar5 = pcVar4;
                iVar3 = (int)*pcVar5;
                pcVar4 = pcVar5 + 1;
                iVar2 = isspace(iVar3);
              } while (iVar2 != 0);
            } while (iVar3 == 0x2c);
            while (((iVar3 != 0 && (iVar2 = isspace(iVar3), iVar2 == 0)) &&
                   ((iVar3 != 0x2c && (iVar3 != 0x29))))) {
              cVar1 = *pcVar4;
              pcVar4 = pcVar4 + 1;
              iVar3 = (int)cVar1;
            }
            pcVar4[-1] = '\0';
            FUN_0805cd9c(local_8,pcVar5);
            if (iVar3 == 0) {
              return;
            }
          }
        }
        else {
          FUN_0805cd9c(local_8,(char *)0x0);
        }
      }
      param_1 = pcVar4;
    } while (iVar3 != 0);
  }
  return;
}



void FUN_0805cf54(void)

{
  FILE *__stream;
  char *__buf;
  int iVar1;
  uint uVar2;
  int *piVar3;
  byte *pbVar4;
  byte *pbVar5;
  byte *pbVar6;
  byte *pbVar7;
  int iVar8;
  size_t __n;
  byte *local_8;
  
  __stream = FUN_08060e7c(DAT_0806abcc,"r");
  if (__stream == (FILE *)0x0) {
    FUN_0805b0d8("3Can\'t open file \'%s\'.");
  }
  FUN_0804b418();
  __n = 0x2000;
  iVar8 = 0;
  __buf = (char *)FUN_0804b3ac(0x2000);
  setvbuf(__stream,__buf,iVar8,__n);
  iVar8 = 0;
LAB_0805d1d9:
  do {
    while( true ) {
      pbVar4 = FUN_0805cb30(__stream);
      if (pbVar4 == (byte *)0x0) {
        iVar8 = ferror(__stream);
        if (iVar8 != 0) {
          FUN_0805b0d8("3Error reading file %s.");
        }
        if (DAT_0806ac5c == (void *)0x0) {
          FUN_0805b0d8("3No shared library image file named in %s.");
        }
        FUN_08060ec8(__stream);
        FUN_0804b434();
        return;
      }
      while (iVar1 = isspace((int)(char)*pbVar4), iVar1 != 0) {
        pbVar4 = pbVar4 + 1;
      }
      if ((iVar8 == 0x5c) || (iVar8 = (int)(char)*pbVar4, iVar8 == 0x3e)) break;
      if ((iVar8 != 0x3b) && (iVar8 != 0)) {
        if (iVar8 == 0x2b) {
          FUN_0805ce38((char *)(pbVar4 + 1));
        }
        else {
          FUN_0805cba0((char *)pbVar4);
        }
      }
    }
    if (iVar8 == 0x3e) {
      pbVar5 = pbVar4;
      if (DAT_0806ac5c != (void *)0x0) {
        FUN_0805b0d8("1%s, line %u: duplicate output line ignored.");
        goto LAB_0805d1d9;
      }
      do {
        pbVar5 = pbVar5 + 1;
        iVar8 = isspace((int)(char)*pbVar5);
        pbVar6 = pbVar5;
      } while (iVar8 != 0);
      while (((iVar8 = (int)(char)*pbVar6, iVar8 != 0 && (iVar8 != 0x28)) &&
             (iVar1 = isspace(iVar8), iVar1 == 0))) {
        pbVar6 = pbVar6 + 1;
      }
      *pbVar6 = 0;
      pbVar7 = pbVar6 + 1;
      pbVar4 = pbVar7;
      if (iVar8 == 0x28) {
        DAT_0806ac64 = FUN_0804b258((char *)pbVar5);
        for (; *pbVar4 != 0; pbVar4 = pbVar4 + 1) {
          if (*pbVar4 == 0x29) {
            *pbVar4 = 0;
            pbVar4 = pbVar4 + 1;
            iVar8 = (int)(char)*pbVar4;
            goto LAB_0805d097;
          }
        }
        FUN_0805b0d8("1%s, line %u: missing \')\'.");
        iVar8 = 0;
LAB_0805d097:
        uVar2 = *pbVar7 - 0x2d;
        if (uVar2 == 0) {
          uVar2 = (uint)pbVar6[2];
        }
        pbVar5 = pbVar7;
        if (uVar2 == 0) {
          DAT_0806ab68._1_1_ = DAT_0806ab68._1_1_ | 0x20;
        }
      }
      DAT_0806ac5c = FUN_0804b258((char *)pbVar5);
      if (DAT_0806ac64 == (void *)0x0) {
        DAT_0806ac64 = DAT_0806ac5c;
      }
    }
    if (iVar8 != 0) {
      do {
        while (iVar8 = isspace((int)(char)*pbVar4), iVar8 != 0) {
          pbVar4 = pbVar4 + 1;
        }
        iVar8 = (int)(char)*pbVar4;
        if (iVar8 == 0x22) {
          pbVar4 = (byte *)FUN_0805ca80((int)pbVar4);
        }
        else {
          if (iVar8 == 0x3b) goto LAB_0805d1d9;
          if (iVar8 == 0x5c) {
            while( true ) {
              iVar8 = (int)(char)pbVar4[1];
              if (iVar8 == 0) goto LAB_0805d134;
              if ((iVar8 == 0x3b) || (iVar1 = isspace(iVar8), iVar1 == 0)) break;
              pbVar4 = pbVar4 + 1;
            }
            if ((iVar8 == 0) || (iVar8 == 0x3b)) {
LAB_0805d134:
              iVar8 = 0x5c;
              goto LAB_0805d1d9;
            }
          }
          else if (iVar8 != 0) {
            piVar3 = __errno_location();
            *piVar3 = 0;
            uVar2 = __strtoul_internal(pbVar4,&local_8,0,0);
            FUN_0805ca60(uVar2);
            do {
              pbVar4 = pbVar4 + 1;
              if (*pbVar4 == 0) break;
              iVar8 = isspace((int)(char)*pbVar4);
            } while (iVar8 == 0);
            if ((pbVar4 != local_8) || (piVar3 = __errno_location(), *piVar3 == 0x22)) {
              *pbVar4 = 0;
              FUN_0805b0d8("2EFT parameter \'%s\' is not a number.");
            }
          }
        }
      } while (*pbVar4 != 0);
      iVar8 = 0;
    }
  } while( true );
}



void FUN_0805d254(void)

{
  char *pcVar1;
  undefined4 uVar2;
  char *pcVar3;
  
  DAT_08068920 = 0;
  DAT_08068918 = 0x40;
  DAT_0806a748 = 0;
  DAT_0806ac80 = 0;
  DAT_0806ac64 = 0;
  DAT_0806ac5c = 0;
  DAT_0806a74c = (int *)FUN_0804c234("__rt_dynlink",2,"!!");
  *(byte *)(*DAT_0806a74c + 0x13) = *(byte *)(*DAT_0806a74c + 0x13) | 1;
  DAT_0806ac78 = FUN_0804c234("EFT$$Offset",0xf,"!!");
  DAT_0806ac70 = FUN_0804c234("EFT$$Params",0xf,"!!");
  DAT_0806ac88 = FUN_0804c234("SHL$$Data$$Offset",0xf,"!!");
  DAT_0806ac58 = FUN_0804c234("SHL$$Data$$Size",0xf,"!!");
  pcVar3 = "!!";
  uVar2 = 5;
  pcVar1 = FUN_0804b950((char *)0x0,"sb$$interLUdata","$$Limit");
  DAT_0806ac60 = FUN_0804c234(pcVar1,uVar2,pcVar3);
  DAT_0806ac68 = FUN_0804c234("$$0$$Base",3,"!!");
  return;
}



// WARNING: Type propagation algorithm not settling

bool FUN_0805d350(int *param_1,char *param_2)

{
  char *pcVar1;
  int iVar2;
  char *pcVar3;
  bool bVar4;
  
  iVar2 = 5;
  bVar4 = true;
  pcVar1 = param_2;
  pcVar3 = "-shl";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar4 = *pcVar1 == *pcVar3;
    pcVar1 = pcVar1 + 1;
    pcVar3 = pcVar3 + 1;
  } while (bVar4);
  if (bVar4) {
    pcVar1 = (char *)FUN_08061444(param_1,(byte *)".format");
    iVar2 = strncmp(pcVar1,"=-shf",5);
    return iVar2 != 0;
  }
  iVar2 = 6;
  bVar4 = true;
  pcVar1 = param_2;
  pcVar3 = "-scov";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar4 = *pcVar1 == *pcVar3;
    pcVar1 = pcVar1 + 1;
    pcVar3 = pcVar3 + 1;
  } while (bVar4);
  if (bVar4) {
    pcVar1 = (char *)FUN_08061444(param_1,(byte *)".format");
    iVar2 = strncmp(pcVar1,"=-scf",5);
    if (iVar2 == 0) {
      return false;
    }
    iVar2 = 6;
    bVar4 = true;
    pcVar3 = "=-ovf";
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar4 = *pcVar1 == *pcVar3;
      pcVar1 = pcVar1 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar4);
    return !bVar4;
  }
  iVar2 = 9;
  bVar4 = true;
  pcVar1 = param_2;
  pcVar3 = "-ro-base";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar4 = *pcVar1 == *pcVar3;
    pcVar1 = pcVar1 + 1;
    pcVar3 = pcVar3 + 1;
  } while (bVar4);
  if (bVar4) {
    pcVar1 = (char *)FUN_08061444(param_1,(byte *)".format");
    iVar2 = strncmp(pcVar1,"=-scf",5);
  }
  else {
    iVar2 = 9;
    bVar4 = true;
    pcVar1 = param_2;
    pcVar3 = "-rw-base";
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar4 = *pcVar1 == *pcVar3;
      pcVar1 = pcVar1 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar4);
    if (!bVar4) {
      iVar2 = 7;
      bVar4 = true;
      pcVar1 = "-entry";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar4 = *param_2 == *pcVar1;
        param_2 = param_2 + 1;
        pcVar1 = pcVar1 + 1;
      } while (bVar4);
      if (!bVar4) {
        return false;
      }
      pcVar1 = (char *)FUN_08061444(param_1,(byte *)".format");
      goto LAB_0805d495;
    }
    pcVar1 = (char *)FUN_08061444(param_1,(byte *)".format");
    iVar2 = strncmp(pcVar1,"=-scf",5);
  }
  if (iVar2 == 0) {
    return true;
  }
LAB_0805d495:
  iVar2 = strncmp(pcVar1,"=-shf",5);
  if (iVar2 != 0) {
    iVar2 = 6;
    bVar4 = true;
    pcVar3 = "=-aof";
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar4 = *pcVar1 == *pcVar3;
      pcVar1 = pcVar1 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar4);
    if (!bVar4) {
      return false;
    }
  }
  return true;
}



bool FUN_0805d4cc(int *param_1,byte *param_2,int param_3,char *param_4)

{
  char *pcVar1;
  int iVar2;
  bool bVar3;
  
  pcVar1 = (char *)FUN_08061444(param_1,param_2);
  bVar3 = false;
  if ((pcVar1 != (char *)0x0) && (param_3 == *pcVar1)) {
    iVar2 = strcmp(param_4,pcVar1 + 1);
    bVar3 = iVar2 == 0;
  }
  return bVar3;
}



int FUN_0805d508(int *param_1,char *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  char *pcVar3;
  
  bVar1 = FUN_0805d350(param_1,param_2);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    iVar2 = 8;
    bVar1 = true;
    pcVar3 = ".format";
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar1 = *param_2 == *pcVar3;
      param_2 = param_2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar1);
    if (bVar1) {
      iVar2 = 0;
      do {
        iVar2 = iVar2 + 1;
      } while ((&PTR_s___elf_080672c4)[iVar2] != (undefined *)0x0);
      return iVar2;
    }
  }
  return -1;
}



int FUN_0805d55c(undefined4 param_1,char *param_2,undefined *param_3,undefined4 param_4)

{
  int iVar1;
  undefined **ppuVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  iVar1 = 8;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = ".format";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (bVar5) {
    ppuVar2 = &PTR_s___elf_080672c4;
    do {
      iVar1 = (*(code *)param_3)(param_4,param_2,*ppuVar2);
      if (iVar1 != 0) {
        return iVar1;
      }
      ppuVar2 = ppuVar2 + 1;
    } while (*ppuVar2 != (undefined *)0x0);
    iVar1 = 0;
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}



void FUN_0805d5b4(int *param_1,char *param_2)

{
  char cVar1;
  char *__dest;
  int *piVar2;
  uint uVar3;
  char *pcVar4;
  undefined4 local_18 [5];
  
  uVar3 = 0xffffffff;
  pcVar4 = param_2;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  __dest = malloc(~uVar3);
  memcpy(__dest,param_2,~uVar3);
  pcVar4 = __dest;
  piVar2 = FUN_08049290(local_18,1);
  FUN_0804ad2c(piVar2,param_1,pcVar4);
  free(__dest);
  return;
}



undefined4 FUN_0805d60c(int *param_1,byte *param_2,int param_3,char *param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar2;
  byte *pbVar3;
  byte *pbVar4;
  
  bVar1 = FUN_0805d350(param_1,(char *)param_2);
  if ((CONCAT31(extraout_var,bVar1) == 0) &&
     ((((param_3 == 0x3d || (param_3 == 0x23)) || (param_3 == 0x3f)) || (*param_4 == '\0')))) {
    bVar1 = FUN_0805d4cc(param_1,param_2,param_3,param_4);
    if (CONCAT31(extraout_var_00,bVar1) != 0) {
      return 1;
    }
    iVar2 = FUN_08061478(param_1,param_2,param_3,param_4);
    if (iVar2 == 0) {
      iVar2 = 8;
      bVar1 = true;
      pbVar3 = param_2;
      pbVar4 = (byte *)".format";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar1 = *pbVar3 == *pbVar4;
        pbVar3 = pbVar3 + 1;
        pbVar4 = pbVar4 + 1;
      } while (bVar1);
      if (bVar1) {
        FUN_080598e4(param_1);
      }
      else {
        iVar2 = 5;
        bVar1 = true;
        pbVar3 = &DAT_08067380;
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar1 = *param_2 == *pbVar3;
          param_2 = param_2 + 1;
          pbVar3 = pbVar3 + 1;
        } while (bVar1);
        if (!bVar1) {
          return 1;
        }
        FUN_0805d5b4(param_1,param_4);
        FUN_0805db48(param_1);
      }
      return 2;
    }
  }
  return 0;
}



void FUN_0805d6d4(int *param_1,byte *param_2,char *param_3)

{
  FUN_0805d60c(param_1,param_2,(int)*param_3,param_3 + 1);
  return;
}



char * FUN_0805d6f0(int *param_1,byte *param_2,int *param_3)

{
  bool bVar1;
  char *pcVar2;
  char *pcVar3;
  undefined3 extraout_var;
  int **ppiVar4;
  int *piStackY_30;
  byte *pbStackY_2c;
  
  pcVar2 = (char *)FUN_08061444(param_1,param_2);
  pcVar3 = (char *)FUN_08061444(DAT_08068884,param_2);
  pbStackY_2c = (byte *)0x805d71d;
  bVar1 = FUN_0805d350(param_1,(char *)param_2);
  *param_3 = CONCAT31(extraout_var,bVar1);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    if (pcVar3 == (char *)0x0) {
      return pcVar2;
    }
    FUN_080614f4(param_1,param_2,pcVar3);
    pcVar2 = (char *)FUN_08061444(param_1,param_2);
    pbStackY_2c = param_2;
    ppiVar4 = &piStackY_30;
    piStackY_30 = DAT_08068884;
  }
  else {
    if (pcVar2 == (char *)0x0) {
      return (char *)0x0;
    }
    if (pcVar3 != (char *)0x0) {
      return pcVar2;
    }
    ppiVar4 = (int **)&stack0xffffffe4;
    FUN_080614f4(DAT_08068884,param_2,pcVar2);
    pcVar2 = (char *)FUN_08061444(DAT_08068880,param_2);
  }
  ppiVar4[-1] = (int *)0x805d78c;
  FUN_080614f4(*ppiVar4,(byte *)ppiVar4[1],(char *)ppiVar4[2]);
  return pcVar2;
}



undefined4 FUN_0805d798(undefined4 *param_1,char *param_2,undefined4 param_3)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  
  if ((param_1[4] != 0) && (iVar2 = strncmp(param_2,(char *)param_1[3],param_1[4]), iVar2 != 0)) {
    return 0;
  }
  bVar1 = FUN_0805d350((int *)*param_1,param_2);
  uVar3 = (*(code *)param_1[1])(param_1[2],param_2,param_3,bVar1);
  return uVar3;
}



void FUN_0805d7dc(int *param_1,char *param_2,undefined4 param_3,undefined4 param_4)

{
  char cVar1;
  uint uVar2;
  int *local_18;
  undefined4 local_14;
  undefined4 local_10;
  char *local_c;
  int local_8;
  
  local_14 = param_3;
  local_18 = param_1;
  local_10 = param_4;
  local_c = param_2;
  uVar2 = 0xffffffff;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *param_2;
    param_2 = param_2 + 1;
  } while (cVar1 != '\0');
  local_8 = ~uVar2 - 1;
  FUN_080618f4(param_1,FUN_0805d798,&local_18);
  return;
}



void FUN_0805d824(int *param_1,char *param_2,char *param_3,int param_4)

{
  char cVar1;
  char cVar2;
  int iVar3;
  bool bVar4;
  char *pcVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  char *pcVar9;
  int iVar10;
  size_t local_c;
  
  pcVar5 = strchr(param_2,0x2e);
  if ((pcVar5 == (char *)0x0) ||
     ((iVar6 = isalnum((int)pcVar5[1]), iVar6 == 0 && (pcVar5[1] != '-')))) {
    uVar8 = 0xffffffff;
    pcVar9 = param_2;
    do {
      if (uVar8 == 0) break;
      uVar8 = uVar8 - 1;
      cVar1 = *pcVar9;
      pcVar9 = pcVar9 + 1;
    } while (cVar1 != '\0');
    local_c = ~uVar8 - 1;
  }
  else {
    local_c = (int)pcVar5 - (int)param_2;
  }
  iVar6 = param_1[1];
  cVar1 = *param_3;
  bVar4 = false;
  uVar8 = 0xffffffff;
  pcVar9 = param_3;
  do {
    if (uVar8 == 0) break;
    uVar8 = uVar8 - 1;
    cVar2 = *pcVar9;
    pcVar9 = pcVar9 + 1;
  } while (cVar2 != '\0');
  uVar8 = ~uVar8;
  if (iVar6 != 0) {
    iVar6 = iVar6 + 1;
  }
  iVar6 = iVar6 + local_c;
  if (cVar1 != '?') {
    if (param_4 != 0) {
      pcVar9 = param_3 + 1;
      cVar2 = param_3[1];
      while (cVar2 != '\0') {
        iVar7 = isspace((int)*pcVar9);
        if (iVar7 != 0) {
          bVar4 = true;
          break;
        }
        pcVar9 = pcVar9 + 1;
        cVar2 = *pcVar9;
      }
      if ((pcVar5 == param_2) && (bVar4)) {
        bVar4 = false;
      }
    }
    iVar6 = iVar6 + (uVar8 - 1);
    if (cVar1 == '=') {
      iVar6 = iVar6 + -1;
    }
    if (bVar4) {
      iVar6 = iVar6 + 2;
    }
  }
  if (iVar6 + 1 <= param_1[2]) {
    iVar7 = param_1[1];
    iVar3 = *param_1;
    if (iVar7 != 0) {
      *(undefined1 *)(iVar7 + iVar3) = 0x20;
      iVar7 = iVar7 + 1;
    }
    if ((cVar1 == '=') && (bVar4)) {
      *(undefined1 *)(iVar7 + iVar3) = 0x22;
      iVar7 = iVar7 + 1;
    }
    memcpy((void *)(iVar7 + iVar3),param_2,local_c);
    iVar7 = iVar7 + local_c;
    iVar10 = iVar7;
    if (cVar1 == '#') {
      *(undefined1 *)(iVar7 + iVar3) = 0x20;
      iVar10 = iVar7 + 1;
      if (bVar4) {
        *(undefined1 *)(iVar10 + iVar3) = 0x22;
        iVar10 = iVar7 + 2;
      }
    }
    if (cVar1 != '?') {
      memcpy((void *)(iVar10 + iVar3),param_3 + 1,uVar8 - 2);
      if (bVar4) {
        *(undefined1 *)((uVar8 - 2) + iVar10 + iVar3) = 0x22;
      }
    }
  }
  param_1[1] = iVar6;
  return;
}



undefined4 FUN_0805d9ac(int *param_1,byte *param_2,char *param_3)

{
  bool bVar1;
  char *__s2;
  int iVar2;
  undefined3 extraout_var;
  byte *pbVar3;
  byte *pbVar4;
  
  __s2 = (char *)FUN_08061444(DAT_08068880,param_2);
  if ((__s2 != (char *)0x0) && (iVar2 = strcmp(param_3,__s2), iVar2 == 0)) {
    return 0;
  }
  bVar1 = FUN_0805d350((int *)param_1[3],(char *)param_2);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    iVar2 = 5;
    bVar1 = true;
    pbVar3 = param_2;
    pbVar4 = &DAT_08067380;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar1 = *pbVar3 == *pbVar4;
      pbVar3 = pbVar3 + 1;
      pbVar4 = pbVar4 + 1;
    } while (bVar1);
    if (bVar1) {
      param_1[4] = (int)param_3;
    }
    else {
      FUN_0805d824(param_1,(char *)param_2,param_3,1);
    }
  }
  return 0;
}



int FUN_0805da2c(int *param_1,int param_2,int param_3)

{
  int local_18;
  int local_14;
  int local_10;
  int *local_c;
  char *local_8;
  
  local_8 = (char *)0x0;
  local_c = param_1;
  local_18 = param_2;
  local_14 = 0;
  local_10 = param_3;
  FUN_080618f4(param_1,FUN_0805d9ac,&local_18);
  if (local_8 != (char *)0x0) {
    FUN_0805d824(&local_18,".etc",local_8,0);
  }
  if (local_14 < param_3) {
    *(undefined1 *)(local_14 + param_2) = 0;
  }
  return local_14 + 1;
}



undefined4 FUN_0805da90(int param_1,byte *param_2,char *param_3)

{
  char *__s2;
  int iVar1;
  void *pvVar2;
  byte *pbVar3;
  byte *pbVar4;
  bool bVar5;
  
  if (DAT_08068880 != (int *)0x0) {
    __s2 = (char *)FUN_08061444(DAT_08068880,param_2);
    if ((__s2 != (char *)0x0) && (iVar1 = strcmp(param_3,__s2), iVar1 == 0)) {
      return 0;
    }
    iVar1 = 0xd;
    bVar5 = true;
    pbVar3 = param_2;
    pbVar4 = (byte *)".defaulttime";
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar5 = *pbVar3 == *pbVar4;
      pbVar3 = pbVar3 + 1;
      pbVar4 = pbVar4 + 1;
    } while (bVar5);
    if (!bVar5) {
      iVar1 = 5;
      bVar5 = true;
      pbVar3 = param_2;
      pbVar4 = &DAT_08067380;
      do {
        if (iVar1 == 0) break;
        iVar1 = iVar1 + -1;
        bVar5 = *pbVar3 == *pbVar4;
        pbVar3 = pbVar3 + 1;
        pbVar4 = pbVar4 + 1;
      } while (bVar5);
      if ((!bVar5) && (iVar1 = FUN_0805b1a4(), iVar1 == 0)) {
        iVar1 = *(int *)(param_1 + 4);
        if (iVar1 == *(int *)(param_1 + 8)) {
          *(int *)(param_1 + 8) = iVar1 + 10;
          pvVar2 = realloc(*(void **)(param_1 + 0xc),(iVar1 + 10) * 8);
          *(void **)(param_1 + 0xc) = pvVar2;
          iVar1 = *(int *)(param_1 + 4);
        }
        *(byte **)(*(int *)(param_1 + 0xc) + iVar1 * 8) = param_2;
        *(char **)(*(int *)(param_1 + 0xc) + 4 + *(int *)(param_1 + 4) * 8) = param_3;
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
      }
    }
  }
  return 0;
}



void FUN_0805db48(int *param_1)

{
  uint uVar1;
  char *local_20;
  int local_1c;
  int local_18;
  int *local_14;
  uint local_10;
  undefined4 local_c;
  void *local_8;
  
  local_14 = param_1;
  local_10 = 0;
  local_c = 10;
  local_8 = malloc(0x50);
  FUN_080618f4(param_1,FUN_0805da90,&local_14);
  if (local_10 == 0) {
    FUN_080614f4(param_1,&DAT_08067380,"=");
  }
  else {
    local_20 = (char *)0x0;
    local_1c = 0;
    local_18 = 0;
    uVar1 = 0;
    if (local_10 != 0) {
      do {
        FUN_0805d824((int *)&local_20,*(char **)((int)local_8 + uVar1 * 8),
                     *(char **)((int)local_8 + uVar1 * 8 + 4),1);
        uVar1 = uVar1 + 1;
      } while (uVar1 < local_10);
    }
    local_20 = malloc(local_1c + 1);
    local_18 = local_1c + 1;
    local_1c = 0;
    uVar1 = 0;
    if (local_10 != 0) {
      do {
        FUN_0805d824((int *)&local_20,*(char **)((int)local_8 + uVar1 * 8),
                     *(char **)((int)local_8 + uVar1 * 8 + 4),1);
        uVar1 = uVar1 + 1;
      } while (uVar1 < local_10);
    }
    local_20[local_1c] = '\0';
    FUN_08061478(param_1,&DAT_08067380,0x3d,local_20);
    uVar1 = 0;
    if (local_10 != 0) {
      do {
        FUN_080614f4(param_1,*(byte **)((int)local_8 + uVar1 * 8),"=");
        uVar1 = uVar1 + 1;
      } while (uVar1 < local_10);
    }
    free(local_20);
  }
  free(local_8);
  return;
}



void FUN_0805dc78(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_08061444(param_1,&DAT_08067380);
  if (iVar1 != 0) {
    FUN_0805d5b4(param_1,(char *)(iVar1 + 1));
  }
  FUN_0805db48(param_1);
  return;
}



uint FUN_0805dcb0(byte *param_1,uint param_2,int param_3,ushort param_4)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = param_3 << 0x18 | param_2 | (uint)param_4;
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



undefined4 FUN_0805dd00(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  
  if ((((param_1[2] == param_2[2]) && (param_1[3] == param_2[3])) &&
      (iVar1 = strcmp((char *)*param_1,(char *)*param_2), iVar1 == 0)) && (param_1[1] == param_2[1])
     ) {
    return 0;
  }
  return 1;
}



void FUN_0805dd40(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    if ((void *)*param_1 != (void *)0x0) {
      free((void *)*param_1);
    }
    free(param_1);
  }
  return;
}



undefined4 FUN_0805dd68(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  
  if (DAT_08068924 != (void *)0x0) {
    DAT_08068930 = 0;
    DAT_0806892c = 0;
    uVar3 = 0;
    if (DAT_08068928 != 0) {
      do {
        if (*(int *)((int)DAT_08068924 + uVar3 * 4) != 0) {
          DAT_0806892c = DAT_0806892c + 1;
          puVar2 = *(undefined4 **)((int)DAT_08068924 + uVar3 * 4);
          while (puVar2 != (undefined4 *)0x0) {
            DAT_08068930 = DAT_08068930 + 1;
            puVar1 = (undefined4 *)puVar2[5];
            FUN_0805dd40(puVar2);
            puVar2 = puVar1;
          }
        }
        *(undefined4 *)((int)DAT_08068924 + uVar3 * 4) = 0;
        uVar3 = uVar3 + 1;
      } while (uVar3 < DAT_08068928);
    }
    free(DAT_08068924);
    DAT_08068924 = (void *)0x0;
  }
  return 1;
}



uint FUN_0805de00(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  if (DAT_08068924 != (void *)0x0) {
    FUN_0805dd68();
  }
  DAT_08068934 = 0;
  DAT_08068930 = 0;
  DAT_0806892c = 0;
  DAT_08068928 = param_1;
  if (param_1 == 0) {
    DAT_08068928 = 0xffd;
  }
  DAT_08068924 = malloc(DAT_08068928 * 4);
  if (DAT_08068924 == (void *)0x0) {
    uVar1 = 0;
  }
  else {
    for (uVar2 = 0; uVar1 = DAT_08068928, uVar2 < DAT_08068928; uVar2 = uVar2 + 1) {
      *(undefined4 *)((int)DAT_08068924 + uVar2 * 4) = 0;
    }
  }
  return uVar1;
}



undefined4 *
FUN_0805de8c(char *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5)

{
  char cVar1;
  undefined4 *puVar2;
  void *pvVar3;
  uint uVar4;
  char *pcVar5;
  
  puVar2 = malloc(0x18);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    uVar4 = 0xffffffff;
    pcVar5 = param_1;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    pvVar3 = malloc(~uVar4);
    *puVar2 = pvVar3;
    strcpy((char *)*puVar2,param_1);
    puVar2[1] = param_4;
    puVar2[2] = param_2;
    puVar2[3] = param_3;
    puVar2[5] = *(undefined4 *)(param_5 + 0x14);
    *(undefined4 **)(param_5 + 0x14) = puVar2;
  }
  return puVar2;
}



undefined4 * FUN_0805df00(undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  
  while( true ) {
    if (param_1 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    iVar1 = FUN_0805dd00(param_1,param_2);
    if (iVar1 == 0) break;
    param_1 = (undefined4 *)param_1[5];
  }
  return param_1;
}



undefined4 *
FUN_0805df34(int param_1,char *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  void *pvVar4;
  uint uVar5;
  char *pcVar6;
  
  puVar2 = malloc(0x18);
  if (((param_1 == 0) || (*(int *)(param_1 + 0x14) == 0)) || (puVar2 == (undefined4 *)0x0)) {
    puVar3 = (undefined4 *)0x0;
  }
  else {
    uVar5 = 0xffffffff;
    pcVar6 = param_2;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar1 != '\0');
    pvVar4 = malloc(~uVar5);
    *puVar2 = pvVar4;
    strcpy((char *)*puVar2,param_2);
    puVar2[1] = param_5;
    puVar2[2] = param_3;
    puVar2[3] = param_4;
    puVar2[5] = 0;
    puVar3 = FUN_0805df00(*(undefined4 **)(param_1 + 0x14),puVar2);
    FUN_0805dd40(puVar2);
  }
  return puVar3;
}



undefined4
FUN_0805dfc0(byte *param_1,uint param_2,int param_3,undefined4 param_4,undefined4 *param_5)

{
  byte bVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  void *pvVar4;
  undefined4 *puVar5;
  uint uVar6;
  byte *pbVar7;
  
  if (DAT_08068924 == 0) {
    *param_5 = 0;
    uVar2 = 0xffffffff;
  }
  else {
    puVar3 = malloc(0x18);
    if (puVar3 == (undefined4 *)0x0) {
      *param_5 = 0;
      uVar2 = 0xffffffff;
    }
    else {
      uVar6 = 0xffffffff;
      pbVar7 = param_1;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        bVar1 = *pbVar7;
        pbVar7 = pbVar7 + 1;
      } while (bVar1 != 0);
      pvVar4 = malloc(~uVar6);
      *puVar3 = pvVar4;
      strcpy((char *)*puVar3,(char *)param_1);
      puVar3[1] = param_4;
      puVar3[2] = param_2;
      puVar3[3] = param_3;
      puVar3[5] = 0;
      uVar6 = FUN_0805dcb0(param_1,param_2,param_3,(ushort)param_4);
      uVar6 = uVar6 % DAT_08068928;
      if (*(int *)(DAT_08068924 + uVar6 * 4) == 0) {
        *(undefined4 **)(DAT_08068924 + uVar6 * 4) = puVar3;
        *param_5 = puVar3;
        uVar2 = 1;
      }
      else {
        puVar5 = FUN_0805df00(*(undefined4 **)(DAT_08068924 + uVar6 * 4),puVar3);
        if (puVar5 == (undefined4 *)0x0) {
          puVar3[5] = *(undefined4 *)(DAT_08068924 + uVar6 * 4);
          *(undefined4 **)(DAT_08068924 + uVar6 * 4) = puVar3;
          *param_5 = puVar3;
          DAT_08068934 = DAT_08068934 + 1;
          uVar2 = 1;
        }
        else {
          FUN_0805dd40(puVar3);
          *param_5 = puVar5;
          uVar2 = 0;
        }
      }
    }
  }
  return uVar2;
}



undefined4 FUN_0805e0d0(void)

{
  return DAT_08068928;
}



undefined4 FUN_0805e0dc(void)

{
  return DAT_0806892c;
}



undefined4 FUN_0805e0e8(void)

{
  return DAT_08068930;
}



undefined4 FUN_0805e0f4(void)

{
  return DAT_08068934;
}



void FUN_0805e100(undefined4 param_1)

{
  DAT_08068938 = param_1;
  return;
}



undefined4 FUN_0805e120(void)

{
  return DAT_08068938;
}



uint FUN_0805e13c(uint param_1)

{
  if (DAT_08068938 != 0) {
    param_1 = (param_1 << 0x18 | param_1 >> 8) ^
              (((param_1 << 0x10 | param_1 >> 0x10) ^ param_1) & 0xff00ffff) >> 8;
  }
  return param_1;
}



uint FUN_0805e174(uint param_1)

{
  if (DAT_08068938 != 0) {
    param_1 = (param_1 & 0xff) << 8 | (int)param_1 >> 8 & 0xffU;
  }
  return param_1;
}



void FUN_0805e1a8(uint *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = param_3 >> 2;
  if (uVar2 != 0) {
    do {
      uVar1 = *param_2;
      param_2 = param_2 + 1;
      uVar1 = FUN_0805e13c(uVar1);
      *param_1 = uVar1;
      param_1 = param_1 + 1;
      uVar2 = uVar2 - 1;
    } while (0 < (int)uVar2);
  }
  return;
}



char * FUN_0805e1f0(char *param_1,char *param_2,int param_3)

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
      if (!bVar7) goto LAB_0805e27e;
    }
    local_10 = ~uVar2 - 5;
    local_8 = pcVar4;
  }
LAB_0805e27e:
  iVar3 = local_10 + -2;
  do {
    if (iVar3 < 0) {
LAB_0805e2b3:
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
      goto LAB_0805e2b3;
    }
    iVar3 = iVar3 + -1;
  } while( true );
}



void FUN_0805e300(int *param_1,void *param_2,size_t param_3,void *param_4)

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



void FUN_0805e3c4(int *param_1,undefined1 *param_2,size_t param_3)

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
      FUN_0805e300(param_1,param_2,param_3,puVar1);
    }
  }
  return;
}



void FUN_0805e438(int *param_1,undefined1 param_2)

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
      FUN_0805e300(param_1,&local_5,1,puVar1);
    }
  }
  return;
}



undefined4 FUN_0805e494(int *param_1,char *param_2,uint param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined **ppuVar4;
  char *pcVar5;
  
  ppuVar4 = &PTR_DAT_0806893c;
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
    if (&PTR_DAT_08068a8c <= ppuVar4) {
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
  FUN_0805e3c4(param_1,"operator",~uVar3 - 1);
  uVar3 = 0xffffffff;
  pcVar5 = ppuVar4[1];
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  FUN_0805e3c4(param_1,ppuVar4[1],~uVar3 - 1);
  return 1;
}



byte * FUN_0805e544(int *param_1,byte *param_2,byte *param_3,int param_4)

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
      pbVar3 = FUN_0805f580(param_1,param_2,sVar1);
      return pbVar3;
    }
  }
  return (byte *)0x0;
}



byte * FUN_0805e5a8(int *param_1,byte *param_2,byte *param_3,int param_4,int param_5)

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
      while (pbVar4 = FUN_0805e544(param_1,pbVar4,param_3,param_5), pbVar4 != (byte *)0x0) {
        if (param_5 != 0) {
          uVar3 = 0xffffffff;
          pcVar5 = "::";
          do {
            if (uVar3 == 0) break;
            uVar3 = uVar3 - 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          FUN_0805e3c4(param_1,&DAT_0806741d,~uVar3 - 1);
        }
        local_8 = local_8 + -1;
        if (local_8 < 2) {
          if (param_4 != 0) {
            return pbVar4;
          }
          pbVar4 = FUN_0805e544(param_1,pbVar4,param_3,param_5);
          return pbVar4;
        }
      }
    }
  }
  return (byte *)0x0;
}



byte * FUN_0805e65c(int *param_1,char *param_2,char *param_3,int param_4)

{
  byte *pbVar1;
  
  if (param_2 < param_3) {
    if (*param_2 == 'Q') {
      pbVar1 = FUN_0805e5a8(param_1,(byte *)(param_2 + 1),(byte *)param_3,0,param_4);
    }
    else {
      pbVar1 = FUN_0805e544(param_1,(byte *)param_2,(byte *)param_3,param_4);
    }
  }
  else {
    pbVar1 = (byte *)0x0;
  }
  return pbVar1;
}



void FUN_0805e6a4(int *param_1,uint param_2,int param_3,int param_4)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  if ((param_3 != 0) && ((param_2 & 7) != 0)) {
    FUN_0805e438(param_1,0x20);
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
    FUN_0805e3c4(param_1,"__packed",~uVar2 - 1);
    if ((param_2 & 3) != 0) {
      FUN_0805e438(param_1,0x20);
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
    FUN_0805e3c4(param_1,"const",~uVar2 - 1);
    if ((param_2 & 2) != 0) {
      FUN_0805e438(param_1,0x20);
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
    FUN_0805e3c4(param_1,"volatile",~uVar2 - 1);
  }
  if ((param_4 != 0) && ((param_2 & 7) != 0)) {
    FUN_0805e438(param_1,0x20);
  }
  return;
}



void FUN_0805e7a8(int *param_1,undefined4 *param_2,char *param_3,int param_4)

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
          FUN_0805e438(param_1,0x20);
          pcVar2 = (char *)param_2[1];
        }
        FUN_0805e65c(param_1,pcVar2 + 1,param_3,1);
        uVar1 = 0xffffffff;
        pcVar2 = "::";
        do {
          if (uVar1 == 0) break;
          uVar1 = uVar1 - 1;
          cVar3 = *pcVar2;
          pcVar2 = pcVar2 + 1;
        } while (cVar3 != '\0');
        FUN_0805e3c4(param_1,&DAT_0806741d,~uVar1 - 1);
        FUN_0805e438(param_1,0x2a);
        goto LAB_0805e854;
      }
    }
    else if (cVar3 == 'R') {
      cVar3 = '&';
      goto LAB_0805e84b;
    }
    cVar3 = *pcVar2;
  }
LAB_0805e84b:
  FUN_0805e438(param_1,cVar3);
LAB_0805e854:
  FUN_0805e6a4(param_1,param_2[2],0,0);
  FUN_0805e7a8(param_1,(undefined4 *)*param_2,param_3,1);
  return;
}



byte * FUN_0805e880(int *param_1,byte *param_2,byte *param_3,uint param_4,undefined4 *param_5,
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
LAB_0805f3b3:
  if (!bVar2) {
    uVar9 = (uint)*param_2;
    pbVar7 = param_2 + 1;
    iVar3 = islower(uVar9);
    if (((iVar3 != 0) || (iVar3 = isdigit(uVar9), iVar3 != 0)) || (uVar9 == 0x51)) {
      FUN_0805e6a4(param_1,param_4,0,1);
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
        pbVar7 = FUN_0805e544(param_1,param_2,param_3,1);
        goto LAB_0805ec93;
      default:
        pbVar7 = (byte *)0x0;
        goto LAB_0805ec93;
      case 0x51:
        pbVar7 = FUN_0805e5a8(param_1,pbVar7,param_3,0,1);
        goto LAB_0805ec93;
      case 0x62:
        local_9c = "bool";
        goto LAB_0805ec36;
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
        goto LAB_0805ec36;
      case 0x65:
        local_9c = "...";
        goto LAB_0805ec36;
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
        goto LAB_0805ec36;
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
        goto LAB_0805ec36;
      case 0x78:
        local_9c = "long long";
LAB_0805ec36:
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
      FUN_0805e3c4(param_1,local_9c,sVar5);
LAB_0805ec93:
      FUN_0805e7a8(param_1,param_5,(char *)param_3,1);
LAB_0805efef:
      bVar2 = true;
      param_2 = pbVar7;
      goto LAB_0805f3b3;
    }
    switch(uVar9) {
    case 0:
    case 0x5f:
      break;
    default:
      goto LAB_0805f3f2;
    case 0x41:
      uVar9 = param_1[2];
      if (param_5 != (undefined4 *)0x0) {
        FUN_0805e438(param_1,0x28);
        FUN_0805e7a8(param_1,param_5,(char *)param_3,0);
        param_1[2] = param_1[1];
        if (param_6 != (undefined4 *)0x0) {
          *param_6 = 1;
        }
        FUN_0805e438(param_1,0x29);
      }
      while( true ) {
        bVar12 = 0x5b;
        for (; FUN_0805e438(param_1,bVar12), *pbVar7 != 0x5f; pbVar7 = pbVar7 + 1) {
          if (param_3 <= pbVar7) {
            return (byte *)0x0;
          }
          bVar12 = *pbVar7;
        }
        pbVar8 = pbVar7 + 1;
        if (param_3 <= pbVar8) {
          return (byte *)0x0;
        }
        FUN_0805e438(param_1,0x5d);
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
      param_2 = FUN_0805e880(param_1,pbVar8,param_3,param_4,(undefined4 *)0x0,&local_60,param_7);
      if (local_60 == 0) {
        FUN_0805e438(param_1,0x20);
      }
      if (uVar10 != 0) {
        param_1[2] = uVar10 + (param_1[1] - iVar3);
      }
      break;
    case 0x43:
      param_4 = param_4 | 1;
      param_2 = pbVar7;
      goto LAB_0805f3b3;
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
        FUN_0805e438(param_1,0x28);
        FUN_0805e7a8(param_1,param_5,(char *)param_3,0);
        param_1[2] = param_1[1];
        if (param_6 != (undefined4 *)0x0) {
          *param_6 = 1;
        }
        FUN_0805e438(param_1,0x29);
      }
      FUN_0805e438(param_1,0x28);
      if (*pbVar7 == 0x76) {
        pbVar7 = param_2 + 2;
      }
      else {
        while( true ) {
          pbVar7 = FUN_0805e880(param_1,pbVar7,param_3,0,(undefined4 *)0x0,(undefined4 *)0x0,
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
          FUN_0805e3c4(param_1,&DAT_08067420,~uVar10 - 1);
        }
      }
      FUN_0805e438(param_1,0x29);
      if (*pbVar7 == 0x5f) {
        uVar10 = param_1[2];
        if (uVar10 < uVar9) {
          uVar10 = 0;
        }
        iVar3 = param_1[1];
        local_5c = 0;
        param_1[2] = uVar9;
        pbVar7 = FUN_0805e880(param_1,pbVar7 + 1,param_3,0,(undefined4 *)0x0,&local_5c,local_4c);
        if (local_5c == 0) {
          FUN_0805e438(param_1,0x20);
        }
        if (uVar10 != 0) {
          param_1[2] = uVar10 + (param_1[1] - iVar3);
        }
      }
      FUN_0805e6a4(param_1,param_4,1,0);
      goto LAB_0805efef;
    case 0x4b:
      param_4 = param_4 | 4;
      param_2 = pbVar7;
      goto LAB_0805f3b3;
    case 0x4d:
    case 0x50:
    case 0x52:
      local_58 = param_5;
      local_50 = param_4;
      local_54 = param_2;
      if ((uVar9 == 0x4d) &&
         (pbVar7 = (byte *)FUN_0805e65c(param_1,(char *)pbVar7,(char *)param_3,0),
         pbVar7 == (byte *)0x0)) {
        return (byte *)0x0;
      }
      if (param_3 <= pbVar7) {
        return (byte *)0x0;
      }
      param_2 = FUN_0805e880(param_1,pbVar7,param_3,0,&local_58,param_6,param_7);
      bVar2 = true;
      goto LAB_0805f3b3;
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
        FUN_0805e3c4(param_1,(undefined1 *)param_7[iVar4 * 2 + 1],param_7[iVar4 * 2]);
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
          FUN_0805e3c4(param_1,&DAT_08067420,~uVar9 - 1);
        }
      }
      break;
    case 0x53:
      FUN_0805e6a4(param_1,param_4,0,1);
      local_9c = "signed ";
      uVar9 = 0xffffffff;
      pcVar11 = "signed ";
      do {
        if (uVar9 == 0) break;
        uVar9 = uVar9 - 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar11 + 1;
      } while (cVar1 != '\0');
      goto LAB_0805f0a9;
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
      FUN_0805e3c4(param_1,(undefined1 *)param_7[iVar3 * 2 + 1],param_7[iVar3 * 2]);
      bVar2 = true;
      param_2 = param_2 + 2;
      goto LAB_0805f3b3;
    case 0x55:
      FUN_0805e6a4(param_1,param_4,0,1);
      local_9c = "unsigned ";
      uVar9 = 0xffffffff;
      pcVar11 = local_9c;
      do {
        if (uVar9 == 0) break;
        uVar9 = uVar9 - 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar11 + 1;
      } while (cVar1 != '\0');
LAB_0805f0a9:
      param_4 = 0;
      FUN_0805e3c4(param_1,local_9c,~uVar9 - 1);
      param_2 = pbVar7;
      goto LAB_0805f3b3;
    case 0x56:
      goto switchD_0805ecc2_caseD_56;
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
LAB_0805f3f2:
  return (byte *)0x0;
switchD_0805ecc2_caseD_56:
  param_4 = param_4 | 2;
  param_2 = pbVar7;
  goto LAB_0805f3b3;
}



byte * FUN_0805f400(int *param_1,byte *param_2,byte *param_3)

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
      FUN_0805e438(param_1,0x20);
    }
    uVar7 = 0x3c;
  }
  FUN_0805e438(param_1,uVar7);
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
        FUN_0805e3c4(param_1,param_2 + 1,(size_t)(pcVar4 + (-1 - (int)param_2)));
        param_2 = param_2 + (int)(pcVar4 + (1 - (int)param_2));
      }
      else {
        param_2 = FUN_0805e880(param_1,param_2,param_3,0,(undefined4 *)0x0,(undefined4 *)0x0,
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
      FUN_0805e3c4(param_1,&DAT_08067420,~uVar6 - 1);
      bVar8 = *param_2;
      pbVar3 = param_2;
    }
  }
  if ((char)param_1[5] == '>') {
    FUN_0805e438(param_1,0x20);
  }
  if (bVar2 == 0x46) {
    uVar7 = 0x29;
  }
  else {
    uVar7 = 0x3e;
  }
  FUN_0805e438(param_1,uVar7);
  return param_2;
}



byte * FUN_0805f580(int *param_1,byte *param_2,size_t param_3)

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
    FUN_0805e3c4(param_1,param_2,(int)pcVar3 - (int)param_2);
    param_2 = FUN_0805f400(param_1,param_2 + ((int)pcVar3 - (int)param_2) + 2,param_2 + param_3);
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
    FUN_0805e3c4(param_1,pbVar2,param_3);
    param_2 = pbVar2 + param_3;
  }
  return param_2;
}



void FUN_0805f654(int *param_1,byte *param_2,byte *param_3)

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
  FUN_0805e3c4(param_1,"operator",~uVar2 - 1);
  FUN_0805e438(param_1,0x20);
  FUN_0805e880(param_1,param_2,param_3,0,(undefined4 *)0x0,(undefined4 *)0x0,(int *)0x0);
  return;
}



int FUN_0805f6b4(byte *param_1,byte *param_2,size_t param_3,undefined1 *param_4,int param_5,
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
LAB_0805f7f2:
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
      if (pcVar5 == (char *)0x0) goto LAB_0805f7f2;
      pcVar5 = strchr(pcVar5 + 2,0x3e);
      if (pcVar5 == (char *)0x0) {
        return 0;
      }
      local_28 = strstr(pcVar5 + 1,"__");
    }
    if (local_28 == (char *)0x0) goto LAB_0805f7f2;
    local_28 = local_28 + -(int)param_1;
    param_1 = param_1 + (int)(local_28 + 2);
    if (*param_1 == 0x51) {
      if ((param_6 & 1) != 0) {
        local_1c = local_1c + 1;
      }
      param_1 = FUN_0805e5a8(&local_1c,param_1 + 1,pbVar10,1,1);
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
LAB_0805f9b4:
    if (0 < (int)local_28) {
      if (local_24 == (byte *)0x0) {
        local_3c = local_28;
      }
      else {
        local_3c = (char *)(local_24 + (-4 - (int)local_20));
      }
      iVar3 = 0;
      if (((3 < (int)local_3c) && (*local_20 == 0x5f)) && (local_20[1] == 0x5f)) {
        iVar3 = FUN_0805e494(&local_1c,(char *)(local_20 + 2),(uint)(local_3c + -2));
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
          pbVar7 = (byte *)FUN_0805f654(&local_1c,local_20 + (~uVar8 - 1),local_20 + (int)local_3c);
          if (pbVar7 != local_20 + (int)local_3c) {
            return 0;
          }
          bVar11 = true;
        }
        if (!bVar11) {
          if (bVar2) {
            return 0;
          }
          FUN_0805e3c4(&local_1c,local_20,(size_t)local_3c);
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
        FUN_0805f400(&local_1c,local_24,local_20 + (int)local_28);
      }
    }
  }
  else {
    if ((param_6 & 1) == 0) {
      pbVar6 = FUN_0805f580(&local_1c,param_2,param_3);
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
      FUN_0805e3c4(&local_1c,&DAT_0806741d,~uVar8 - 1);
    }
    if ((iVar3 != 0) && (!bVar11)) goto LAB_0805f9b4;
    if (bVar11) {
      FUN_0805e438(&local_1c,0x7e);
    }
    pbVar6 = FUN_0805f580(&local_1c,param_2,param_3);
    if (pbVar6 == (byte *)0x0) {
      return 0;
    }
    if (local_24 != (byte *)0x0) {
      local_28 = local_28 + -((int)local_24 - (int)(pbVar7 + 4));
      local_20 = local_24 + -4;
      goto LAB_0805f9b4;
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
      FUN_0805e300(&local_1c,"static ",~uVar8 - 1,param_4);
    }
    param_1 = param_1 + 1;
  }
  else {
    if (*param_1 == 0x43) {
      pbVar7 = param_1 + 1;
    }
    bVar9 = *pbVar7;
    if (bVar9 != 0x56) goto LAB_0805fb36;
  }
  bVar9 = pbVar7[1];
LAB_0805fb36:
  if (bVar9 == 0x46) {
    if ((param_6 & 4) != 0) {
      local_1c = local_1c + 1;
    }
    param_1 = FUN_0805e880(&local_1c,param_1,pbVar10,0,(undefined4 *)0x0,(undefined4 *)0x0,
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



void FUN_0805fba0(byte *param_1,undefined1 *param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  uint __n;
  byte *pbVar4;
  
  iVar2 = FUN_0805f6b4(param_1,(byte *)0x0,0,param_2,param_3,0);
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



byte * FUN_0805fc0c(byte *param_1,byte *param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_0805f6b4(param_1,(byte *)0x0,0,param_2,param_3,0);
  if ((0 < iVar1) && (iVar1 <= param_3)) {
    param_1 = param_2;
  }
  return param_1;
}



byte * FUN_0805fc4c(byte *param_1,byte *param_2,size_t param_3,byte *param_4,int param_5)

{
  int iVar1;
  
  iVar1 = FUN_0805f6b4(param_1,param_2,param_3,param_4,param_5,0);
  if ((0 < iVar1) && (iVar1 <= param_5)) {
    param_1 = param_4;
  }
  return param_1;
}



void FUN_0805fc8c(byte *param_1,undefined1 *param_2,int param_3,uint param_4)

{
  FUN_0805f6b4(param_1,(byte *)0x0,0,param_2,param_3,param_4);
  return;
}



void FUN_0805fcb8(byte *param_1,byte *param_2,size_t param_3,undefined1 *param_4,int param_5,
                 uint param_6)

{
  FUN_0805f6b4(param_1,param_2,param_3,param_4,param_5,param_6);
  return;
}



int FUN_0805fce4(byte *param_1,undefined1 *param_2,int param_3)

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
    FUN_0805e3c4(&local_1c,param_1,(int)pcVar2 - (int)param_1);
    pbVar3 = FUN_0805f400(&local_1c,param_1 + ((int)pcVar2 - (int)param_1) + 2,pbVar5);
    if (pbVar3 == pbVar5) {
      if (0 < param_3) {
        *local_18 = 0;
      }
      return local_c + 1;
    }
  }
  return 0;
}



byte * FUN_0805fdb0(byte *param_1,byte *param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_0805fce4(param_1,param_2,param_3);
  if ((0 < iVar1) && (iVar1 <= param_3)) {
    param_1 = param_2;
  }
  return param_1;
}



undefined4 FUN_0805fdf0(void)

{
  return 1;
}



long FUN_0805fdfc(FILE *param_1,long param_2)

{
  long lVar1;
  int iVar2;
  
  if (param_2 == 0) {
    lVar1 = ftell(param_1);
    if (lVar1 != 0) {
      return lVar1;
    }
    param_2 = 0x34;
  }
  iVar2 = fseek(param_1,param_2,0);
  if (iVar2 != 0) {
    param_2 = 0;
  }
  return param_2;
}



undefined4 FUN_0805fe4c(FILE *param_1,undefined4 *param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  size_t sVar4;
  undefined4 *__ptr;
  undefined4 local_38 [4];
  undefined2 local_28;
  undefined2 local_26;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  undefined2 local_10;
  undefined2 local_e;
  undefined2 local_c;
  undefined2 local_a;
  undefined2 local_8;
  undefined2 local_6;
  
  iVar1 = FUN_0805e120();
  __ptr = param_2;
  if (iVar1 != 0) {
    __ptr = local_38;
    uVar2 = FUN_0805e174((uint)*(ushort *)(param_2 + 4));
    local_28 = (undefined2)uVar2;
    uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_2 + 0x12));
    local_26 = (undefined2)uVar2;
    local_24 = FUN_0805e13c(param_2[5]);
    local_20 = FUN_0805e13c(param_2[6]);
    local_1c = FUN_0805e13c(param_2[7]);
    local_18 = FUN_0805e13c(param_2[8]);
    local_14 = FUN_0805e13c(param_2[9]);
    uVar2 = FUN_0805e174((uint)*(ushort *)(param_2 + 10));
    local_10 = (undefined2)uVar2;
    uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_2 + 0x2a));
    local_e = (undefined2)uVar2;
    uVar2 = FUN_0805e174((uint)*(ushort *)(param_2 + 0xb));
    local_c = (undefined2)uVar2;
    uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_2 + 0x2e));
    local_a = (undefined2)uVar2;
    uVar2 = FUN_0805e174((uint)*(ushort *)(param_2 + 0xc));
    local_8 = (undefined2)uVar2;
    uVar2 = FUN_0805e174((uint)*(ushort *)((int)param_2 + 0x32));
    local_6 = (undefined2)uVar2;
  }
  *__ptr = 0;
  __ptr[1] = 0;
  __ptr[2] = 0;
  __ptr[3] = 0;
  *(undefined1 *)__ptr = 0x7f;
  *(undefined1 *)((int)__ptr + 1) = 0x45;
  *(undefined1 *)((int)__ptr + 2) = 0x4c;
  *(undefined1 *)((int)__ptr + 3) = 0x46;
  *(undefined1 *)(__ptr + 1) = 1;
  *(undefined1 *)((int)__ptr + 5) = 1;
  *(undefined1 *)((int)__ptr + 6) = 1;
  iVar1 = FUN_0805e120();
  iVar3 = FUN_0805fdf0();
  if (iVar1 == iVar3) {
    *(undefined1 *)((int)__ptr + 5) = 2;
  }
  iVar1 = fseek(param_1,0,0);
  if ((iVar1 == 0) && (sVar4 = fwrite(__ptr,0x34,1,param_1), 0 < (int)sVar4)) {
    return 0;
  }
  return 1;
}



undefined4 FUN_0805ffc8(FILE *param_1,int *param_2)

{
  int iVar1;
  size_t sVar2;
  uint uVar3;
  
  iVar1 = fseek(param_1,0,0);
  if ((iVar1 != 0) || (sVar2 = fread(param_2,0x34,1,param_1), (int)sVar2 < 1)) {
    return 2;
  }
  if (*param_2 != 0x464c457f) {
    return 3;
  }
  if ((char)param_2[1] != '\x01') {
    return 5;
  }
  uVar3 = FUN_0805fdf0();
  FUN_0805e100((uint)((*(char *)((int)param_2 + 5) == '\x01') != uVar3));
  iVar1 = FUN_0805e120();
  if (iVar1 != 0) {
    uVar3 = FUN_0805e174((uint)*(ushort *)(param_2 + 4));
    *(short *)(param_2 + 4) = (short)uVar3;
    uVar3 = FUN_0805e174((uint)*(ushort *)((int)param_2 + 0x12));
    *(short *)((int)param_2 + 0x12) = (short)uVar3;
    uVar3 = FUN_0805e13c(param_2[5]);
    param_2[5] = uVar3;
    uVar3 = FUN_0805e13c(param_2[6]);
    param_2[6] = uVar3;
    uVar3 = FUN_0805e13c(param_2[7]);
    param_2[7] = uVar3;
    uVar3 = FUN_0805e13c(param_2[8]);
    param_2[8] = uVar3;
    uVar3 = FUN_0805e13c(param_2[9]);
    param_2[9] = uVar3;
    uVar3 = FUN_0805e174((uint)*(ushort *)(param_2 + 10));
    *(short *)(param_2 + 10) = (short)uVar3;
    uVar3 = FUN_0805e174((uint)*(ushort *)((int)param_2 + 0x2a));
    *(short *)((int)param_2 + 0x2a) = (short)uVar3;
    uVar3 = FUN_0805e174((uint)*(ushort *)(param_2 + 0xb));
    *(short *)(param_2 + 0xb) = (short)uVar3;
    uVar3 = FUN_0805e174((uint)*(ushort *)((int)param_2 + 0x2e));
    *(short *)((int)param_2 + 0x2e) = (short)uVar3;
    uVar3 = FUN_0805e174((uint)*(ushort *)(param_2 + 0xc));
    *(short *)(param_2 + 0xc) = (short)uVar3;
    uVar3 = FUN_0805e174((uint)*(ushort *)((int)param_2 + 0x32));
    *(short *)((int)param_2 + 0x32) = (short)uVar3;
  }
  return 0;
}



undefined4 FUN_0806013c(FILE *param_1,int param_2,uint *param_3,size_t param_4,long param_5)

{
  long lVar1;
  int iVar2;
  size_t sVar3;
  undefined4 uVar4;
  uint *puVar5;
  uint *local_2c;
  int local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  lVar1 = FUN_0805fdfc(param_1,param_5);
  if (lVar1 == 0) {
LAB_0806019c:
    uVar4 = 1;
  }
  else {
    *(long *)(param_2 + 0x1c) = lVar1;
    *(undefined2 *)(param_2 + 0x2a) = 0x20;
    *(short *)(param_2 + 0x2c) = (short)param_4;
    iVar2 = FUN_0805e120();
    if (iVar2 == 0) {
      sVar3 = fwrite(param_3,0x20,param_4,param_1);
      if ((int)sVar3 < (int)param_4) goto LAB_0806019c;
    }
    else {
      local_28 = 0;
      if (0 < (int)param_4) {
        local_2c = param_3 + 7;
        puVar5 = param_3 + 6;
        do {
          local_24 = FUN_0805e13c(*param_3);
          local_20 = FUN_0805e13c(puVar5[-5]);
          local_1c = FUN_0805e13c(puVar5[-4]);
          local_18 = FUN_0805e13c(puVar5[-3]);
          local_14 = FUN_0805e13c(puVar5[-2]);
          local_10 = FUN_0805e13c(puVar5[-1]);
          local_c = FUN_0805e13c(*puVar5);
          local_8 = FUN_0805e13c(*local_2c);
          sVar3 = fwrite(&local_24,0x20,1,param_1);
          if ((int)sVar3 < 1) goto LAB_0806019c;
          local_28 = local_28 + 1;
          puVar5 = puVar5 + 8;
          local_2c = local_2c + 8;
          param_3 = param_3 + 8;
        } while (local_28 < (int)param_4);
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}



undefined4 FUN_08060274(FILE *param_1,int param_2,uint *param_3)

{
  int iVar1;
  size_t sVar2;
  uint uVar3;
  uint *puVar4;
  uint *local_20;
  uint *local_1c;
  uint *local_18;
  uint *local_14;
  uint *local_10;
  uint *local_c;
  int local_8;
  
  iVar1 = fseek(param_1,*(long *)(param_2 + 0x1c),0);
  if (iVar1 == 0) {
    sVar2 = fread(param_3,0x20,(uint)*(ushort *)(param_2 + 0x2c),param_1);
    if ((int)(uint)*(ushort *)(param_2 + 0x2c) <= (int)sVar2) {
      local_8 = 0;
      if (*(ushort *)(param_2 + 0x2c) != 0) {
        local_c = param_3 + 7;
        local_10 = param_3 + 6;
        local_14 = param_3 + 5;
        local_18 = param_3 + 4;
        local_1c = param_3 + 3;
        local_20 = param_3 + 2;
        puVar4 = param_3 + 1;
        do {
          iVar1 = FUN_0805e120();
          if (iVar1 != 0) {
            uVar3 = FUN_0805e13c(*param_3);
            *param_3 = uVar3;
            uVar3 = FUN_0805e13c(*puVar4);
            *puVar4 = uVar3;
            uVar3 = FUN_0805e13c(*local_20);
            *local_20 = uVar3;
            uVar3 = FUN_0805e13c(*local_1c);
            *local_1c = uVar3;
            uVar3 = FUN_0805e13c(*local_18);
            *local_18 = uVar3;
            uVar3 = FUN_0805e13c(*local_14);
            *local_14 = uVar3;
            uVar3 = FUN_0805e13c(*local_10);
            *local_10 = uVar3;
            uVar3 = FUN_0805e13c(*local_c);
            *local_c = uVar3;
          }
          local_c = local_c + 8;
          local_10 = local_10 + 8;
          local_14 = local_14 + 8;
          local_18 = local_18 + 8;
          local_1c = local_1c + 8;
          local_20 = local_20 + 8;
          puVar4 = puVar4 + 8;
          param_3 = param_3 + 8;
          local_8 = local_8 + 1;
        } while (local_8 < (int)(uint)*(ushort *)(param_2 + 0x2c));
      }
      return 0;
    }
  }
  return 2;
}



undefined4 FUN_080603dc(FILE *param_1,int param_2,uint *param_3,size_t param_4,long param_5)

{
  long lVar1;
  int iVar2;
  size_t sVar3;
  undefined4 uVar4;
  uint *puVar5;
  uint *local_34;
  int local_30;
  uint local_2c;
  uint local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  lVar1 = FUN_0805fdfc(param_1,param_5);
  if (lVar1 == 0) {
LAB_0806043c:
    uVar4 = 1;
  }
  else {
    *(long *)(param_2 + 0x20) = lVar1;
    *(undefined2 *)(param_2 + 0x2e) = 0x28;
    *(short *)(param_2 + 0x30) = (short)param_4;
    iVar2 = FUN_0805e120();
    if (iVar2 == 0) {
      sVar3 = fwrite(param_3,0x28,param_4,param_1);
      if ((int)sVar3 < (int)param_4) goto LAB_0806043c;
    }
    else {
      local_30 = 0;
      if (0 < (int)param_4) {
        local_34 = param_3 + 9;
        puVar5 = param_3 + 8;
        do {
          local_2c = FUN_0805e13c(*param_3);
          local_28 = FUN_0805e13c(puVar5[-7]);
          local_24 = FUN_0805e13c(puVar5[-6]);
          local_20 = FUN_0805e13c(puVar5[-5]);
          local_1c = FUN_0805e13c(puVar5[-4]);
          local_18 = FUN_0805e13c(puVar5[-3]);
          local_14 = FUN_0805e13c(puVar5[-2]);
          local_10 = FUN_0805e13c(puVar5[-1]);
          local_c = FUN_0805e13c(*puVar5);
          local_8 = FUN_0805e13c(*local_34);
          sVar3 = fwrite(&local_2c,0x28,1,param_1);
          if ((int)sVar3 < 1) goto LAB_0806043c;
          local_30 = local_30 + 1;
          puVar5 = puVar5 + 10;
          local_34 = local_34 + 10;
          param_3 = param_3 + 10;
        } while (local_30 < (int)param_4);
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}



undefined4 FUN_08060530(FILE *param_1,int param_2,uint *param_3)

{
  int iVar1;
  size_t sVar2;
  uint uVar3;
  uint *puVar4;
  uint *local_28;
  uint *local_24;
  uint *local_20;
  uint *local_1c;
  uint *local_18;
  uint *local_14;
  uint *local_10;
  uint *local_c;
  int local_8;
  
  iVar1 = fseek(param_1,*(long *)(param_2 + 0x20),0);
  if (iVar1 == 0) {
    sVar2 = fread(param_3,0x28,(uint)*(ushort *)(param_2 + 0x30),param_1);
    if ((int)(uint)*(ushort *)(param_2 + 0x30) <= (int)sVar2) {
      local_8 = 0;
      if (*(ushort *)(param_2 + 0x30) != 0) {
        local_c = param_3 + 9;
        local_10 = param_3 + 8;
        local_14 = param_3 + 7;
        local_18 = param_3 + 6;
        local_1c = param_3 + 5;
        local_20 = param_3 + 4;
        local_24 = param_3 + 3;
        local_28 = param_3 + 2;
        puVar4 = param_3 + 1;
        do {
          iVar1 = FUN_0805e120();
          if (iVar1 != 0) {
            uVar3 = FUN_0805e13c(*param_3);
            *param_3 = uVar3;
            uVar3 = FUN_0805e13c(*puVar4);
            *puVar4 = uVar3;
            uVar3 = FUN_0805e13c(*local_28);
            *local_28 = uVar3;
            uVar3 = FUN_0805e13c(*local_24);
            *local_24 = uVar3;
            uVar3 = FUN_0805e13c(*local_20);
            *local_20 = uVar3;
            uVar3 = FUN_0805e13c(*local_1c);
            *local_1c = uVar3;
            uVar3 = FUN_0805e13c(*local_18);
            *local_18 = uVar3;
            uVar3 = FUN_0805e13c(*local_14);
            *local_14 = uVar3;
            uVar3 = FUN_0805e13c(*local_10);
            *local_10 = uVar3;
            uVar3 = FUN_0805e13c(*local_c);
            *local_c = uVar3;
          }
          local_c = local_c + 10;
          local_10 = local_10 + 10;
          local_14 = local_14 + 10;
          local_18 = local_18 + 10;
          local_1c = local_1c + 10;
          local_20 = local_20 + 10;
          local_24 = local_24 + 10;
          local_28 = local_28 + 10;
          puVar4 = puVar4 + 10;
          param_3 = param_3 + 10;
          local_8 = local_8 + 1;
        } while (local_8 < (int)(uint)*(ushort *)(param_2 + 0x30));
      }
      return 0;
    }
  }
  return 2;
}



undefined4 FUN_080606cc(FILE *param_1,int param_2,void *param_3,size_t param_4,long param_5)

{
  long lVar1;
  size_t sVar2;
  
  lVar1 = FUN_0805fdfc(param_1,param_5);
  if (lVar1 != 0) {
    *(long *)(param_2 + 0x10) = lVar1;
    *(size_t *)(param_2 + 0x14) = param_4;
    sVar2 = fwrite(param_3,1,param_4,param_1);
    if ((int)param_4 <= (int)sVar2) {
      return 0;
    }
  }
  return 1;
}



undefined4 FUN_08060724(FILE *param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  void *__ptr;
  size_t sVar2;
  
  *param_3 = 0;
  iVar1 = fseek(param_1,*(long *)(param_2 + 0x10),0);
  if (iVar1 == 0) {
    __ptr = malloc(*(size_t *)(param_2 + 0x14));
    if (__ptr == (void *)0x0) {
      return 6;
    }
    sVar2 = fread(__ptr,1,*(size_t *)(param_2 + 0x14),param_1);
    if (*(uint *)(param_2 + 0x14) <= sVar2) {
      *param_3 = __ptr;
      return 0;
    }
    free(__ptr);
  }
  return 2;
}



undefined4 FUN_080607a4(FILE *param_1,int param_2,undefined4 *param_3)

{
  void *__ptr;
  int iVar1;
  size_t sVar2;
  undefined4 uVar3;
  uint uVar4;
  
  __ptr = malloc(*(size_t *)(param_2 + 0x14));
  if (__ptr == (void *)0x0) {
    return 6;
  }
  uVar4 = 0;
  if (*(int *)(param_2 + 0x10) == 0) {
LAB_08060813:
    if (uVar4 < *(uint *)(param_2 + 0x14)) {
      memset((void *)(uVar4 + (int)__ptr),0,*(uint *)(param_2 + 0x14) - uVar4);
    }
    *param_3 = __ptr;
    uVar3 = 0;
  }
  else {
    iVar1 = fseek(param_1,*(long *)(param_2 + 4),0);
    if (iVar1 == 0) {
      sVar2 = fread(__ptr,1,*(size_t *)(param_2 + 0x10),param_1);
      uVar4 = *(uint *)(param_2 + 0x10);
      if (uVar4 <= sVar2) goto LAB_08060813;
    }
    free(__ptr);
    uVar3 = 2;
  }
  return uVar3;
}



undefined4 FUN_08060838(FILE *param_1,int param_2,uint *param_3,size_t param_4,long param_5)

{
  long lVar1;
  int iVar2;
  size_t sVar3;
  undefined4 uVar4;
  uint uVar5;
  undefined1 *puVar6;
  ushort *local_1c;
  int local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  undefined1 local_8;
  undefined1 local_7;
  undefined2 local_6;
  
  lVar1 = FUN_0805fdfc(param_1,param_5);
  if (lVar1 == 0) {
LAB_080608a2:
    uVar4 = 1;
  }
  else {
    *(long *)(param_2 + 0x10) = lVar1;
    *(size_t *)(param_2 + 0x14) = param_4 << 4;
    *(undefined4 *)(param_2 + 0x24) = 0x10;
    *(undefined4 *)(param_2 + 4) = 2;
    iVar2 = FUN_0805e120();
    if (iVar2 == 0) {
      sVar3 = fwrite(param_3,0x10,param_4,param_1);
      if ((int)sVar3 < (int)param_4) goto LAB_080608a2;
    }
    else {
      local_18 = 0;
      if (0 < (int)param_4) {
        local_1c = (ushort *)((int)param_3 + 0xe);
        puVar6 = (undefined1 *)((int)param_3 + 0xd);
        do {
          local_14 = FUN_0805e13c(*param_3);
          local_10 = FUN_0805e13c(*(uint *)(puVar6 + -9));
          local_c = FUN_0805e13c(*(uint *)(puVar6 + -5));
          local_8 = puVar6[-1];
          local_7 = *puVar6;
          uVar5 = FUN_0805e174((uint)*local_1c);
          local_6 = (undefined2)uVar5;
          sVar3 = fwrite(&local_14,0x10,1,param_1);
          if ((int)sVar3 < 1) goto LAB_080608a2;
          local_18 = local_18 + 1;
          puVar6 = puVar6 + 0x10;
          local_1c = local_1c + 8;
          param_3 = param_3 + 4;
        } while (local_18 < (int)param_4);
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}



undefined4 FUN_08060954(FILE *param_1,int param_2,uint *param_3,size_t param_4,long param_5)

{
  long lVar1;
  int iVar2;
  size_t sVar3;
  undefined4 uVar4;
  uint local_c;
  uint local_8;
  
  lVar1 = FUN_0805fdfc(param_1,param_5);
  if (lVar1 == 0) {
LAB_080609ba:
    uVar4 = 1;
  }
  else {
    *(long *)(param_2 + 0x10) = lVar1;
    *(size_t *)(param_2 + 0x14) = param_4 << 3;
    *(undefined4 *)(param_2 + 0x24) = 8;
    *(undefined4 *)(param_2 + 4) = 9;
    iVar2 = FUN_0805e120();
    if (iVar2 == 0) {
      sVar3 = fwrite(param_3,8,param_4,param_1);
      if ((int)sVar3 < (int)param_4) goto LAB_080609ba;
    }
    else {
      iVar2 = 0;
      if (0 < (int)param_4) {
        do {
          local_c = FUN_0805e13c(*param_3);
          local_8 = FUN_0805e13c(param_3[1]);
          sVar3 = fwrite(&local_c,8,1,param_1);
          if ((int)sVar3 < 1) goto LAB_080609ba;
          iVar2 = iVar2 + 1;
          param_3 = param_3 + 2;
        } while (iVar2 < (int)param_4);
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}



undefined4 FUN_08060a1c(FILE *param_1,int param_2,uint *param_3,size_t param_4,long param_5)

{
  long lVar1;
  int iVar2;
  size_t sVar3;
  undefined4 uVar4;
  uint *puVar5;
  int local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  lVar1 = FUN_0805fdfc(param_1,param_5);
  if (lVar1 == 0) {
LAB_08060a87:
    uVar4 = 1;
  }
  else {
    *(long *)(param_2 + 0x10) = lVar1;
    *(size_t *)(param_2 + 0x14) = param_4 * 0xc;
    *(undefined4 *)(param_2 + 0x24) = 0xc;
    *(undefined4 *)(param_2 + 4) = 9;
    iVar2 = FUN_0805e120();
    if (iVar2 == 0) {
      sVar3 = fwrite(param_3,0xc,param_4,param_1);
      if ((int)sVar3 < (int)param_4) goto LAB_08060a87;
    }
    else {
      local_14 = 0;
      if (0 < (int)param_4) {
        puVar5 = param_3 + 2;
        do {
          local_10 = FUN_0805e13c(*param_3);
          local_c = FUN_0805e13c(puVar5[-1]);
          local_8 = FUN_0805e13c(*puVar5);
          sVar3 = fwrite(&local_10,0xc,1,param_1);
          if ((int)sVar3 < 1) goto LAB_08060a87;
          local_14 = local_14 + 1;
          puVar5 = puVar5 + 3;
          param_3 = param_3 + 3;
        } while (local_14 < (int)param_4);
      }
    }
    uVar4 = 0;
  }
  return uVar4;
}



int FUN_08060b00(FILE *param_1,undefined4 param_2,int param_3,undefined4 *param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  ushort *local_14;
  int local_10;
  uint *local_8;
  
  iVar1 = FUN_08060724(param_1,param_3,&local_8);
  if (iVar1 == 0) {
    uVar3 = *(uint *)(param_3 + 0x14) >> 4;
    iVar1 = FUN_0805e120();
    if (iVar1 != 0) {
      local_10 = 0;
      if (uVar3 != 0) {
        local_14 = (ushort *)((int)local_8 + 0xe);
        puVar4 = local_8 + 2;
        puVar5 = local_8;
        do {
          uVar2 = FUN_0805e13c(*puVar5);
          *puVar5 = uVar2;
          uVar2 = FUN_0805e13c(puVar4[-1]);
          puVar4[-1] = uVar2;
          uVar2 = FUN_0805e13c(*puVar4);
          *puVar4 = uVar2;
          uVar2 = FUN_0805e174((uint)*local_14);
          *local_14 = (ushort)uVar2;
          local_10 = local_10 + 1;
          puVar4 = puVar4 + 4;
          local_14 = local_14 + 8;
          puVar5 = puVar5 + 4;
        } while (local_10 < (int)uVar3);
      }
    }
    *param_4 = local_8;
    iVar1 = 0;
  }
  return iVar1;
}



int FUN_08060bc4(FILE *param_1,undefined4 param_2,int param_3,undefined4 *param_4)

{
  uint *puVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint local_c;
  uint *local_8;
  
  if (*(int *)(param_3 + 4) == 4) {
    local_c = 0xc;
  }
  else {
    local_c = 8;
  }
  uVar2 = *(uint *)(param_3 + 0x14) / local_c;
  iVar3 = FUN_08060724(param_1,param_3,&local_8);
  if (iVar3 == 0) {
    iVar3 = FUN_0805e120();
    puVar1 = local_8;
    if ((iVar3 != 0) && (iVar3 = 0, 0 < (int)uVar2)) {
      do {
        uVar4 = FUN_0805e13c(*puVar1);
        *puVar1 = uVar4;
        uVar4 = FUN_0805e13c(puVar1[1]);
        puVar1[1] = uVar4;
        if (local_c == 0xc) {
          uVar4 = FUN_0805e13c(puVar1[2]);
          puVar1[2] = uVar4;
        }
        iVar3 = iVar3 + 1;
      } while (iVar3 < (int)uVar2);
    }
    *param_4 = local_8;
    iVar3 = 0;
  }
  return iVar3;
}



void FUN_08060c80(void)

{
  undefined4 *puVar1;
  
  DAT_08068aac = DAT_08068aa8;
  puVar1 = DAT_08068aa8;
  while (puVar1 != (undefined4 *)0x0) {
    puVar1[2] = (undefined4 *)*puVar1;
    puVar1 = (undefined4 *)*puVar1;
  }
  DAT_08068ab0 = FUN_08061054();
  return;
}



int FUN_08060cbc(uint param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = &DAT_08068aac;
  while( true ) {
    iVar1 = *piVar2;
    if (iVar1 == 0) {
      return 0;
    }
    if (param_1 <= *(uint *)(iVar1 + 4)) break;
    piVar2 = (int *)(iVar1 + 8);
  }
  *piVar2 = *(int *)(iVar1 + 8);
  return iVar1;
}



undefined4 * FUN_08060cfc(int param_1,uint param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  
  uVar2 = param_1 + 3U & 0xfffffffc;
  puVar1 = (undefined4 *)FUN_08060cbc(uVar2);
  if (puVar1 == (undefined4 *)0x0) {
    if (uVar2 < 0xff8) {
      uVar2 = 0xff8;
    }
    if (uVar2 < param_2) {
      uVar2 = param_2 + 3 & 0xfffffffc;
    }
    puVar1 = malloc(uVar2 + 8);
    if (puVar1 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    puVar1[1] = uVar2;
    *puVar1 = DAT_08068aa8;
    DAT_08068aa8 = puVar1;
  }
  return puVar1 + 2;
}



undefined4 FUN_08060d70(int param_1)

{
  undefined4 uVar1;
  
  if (param_1 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(param_1 + -4);
  }
  return uVar1;
}



void FUN_08060d84(int *param_1)

{
  if (param_1 != (int *)0x0) {
    *param_1 = (int)DAT_08068aac;
    DAT_08068aac = param_1 + -2;
  }
  return;
}



void FUN_08060db4(void)

{
  undefined4 *puVar1;
  undefined4 *__ptr;
  
  __ptr = DAT_08068aa8;
  while (__ptr != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*__ptr;
    free(__ptr);
    __ptr = puVar1;
  }
  DAT_08068aac = 0;
  DAT_08068aa8 = (undefined4 *)0x0;
  FUN_0806109c(DAT_08068ab0);
  DAT_08068ab0 = 0;
  return;
}



void FUN_08060e20(undefined4 param_1)

{
  DAT_08068ab4 = param_1;
  return;
}



int FUN_08060e40(void)

{
  int iVar1;
  
  iVar1 = DAT_08068abc;
  if (DAT_08068abc == 0) {
    if (DAT_08068ab4 != (code *)0x0) {
      iVar1 = (*DAT_08068ab4)(8);
    }
  }
  else {
    DAT_08068abc = *(int *)(DAT_08068abc + 4);
  }
  return iVar1;
}



FILE * FUN_08060e7c(char *param_1,char *param_2)

{
  FILE *pFVar1;
  undefined4 *puVar2;
  
  pFVar1 = fopen(param_1,param_2);
  if (pFVar1 != (FILE *)0x0) {
    puVar2 = (undefined4 *)FUN_08060e40();
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = pFVar1;
      puVar2[1] = DAT_08068ab8;
      DAT_08068ab8 = puVar2;
    }
  }
  return pFVar1;
}



void FUN_08060ec8(FILE *param_1)

{
  int *piVar1;
  int *piVar2;
  
  piVar1 = (int *)&DAT_08068ab8;
  piVar2 = DAT_08068ab8;
  do {
    if (piVar2 == (int *)0x0) {
LAB_08060f1a:
      fclose(param_1);
      return;
    }
    if ((FILE *)*piVar2 == param_1) {
      *piVar1 = piVar2[1];
      piVar2[1] = (int)DAT_08068abc;
      DAT_08068abc = piVar2;
      goto LAB_08060f1a;
    }
    piVar1 = piVar2 + 1;
    piVar2 = (int *)piVar2[1];
  } while( true );
}



void FUN_08060f28(void)

{
  undefined4 *puVar1;
  
  for (puVar1 = DAT_08068ab8; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)puVar1[1]) {
    fclose((FILE *)*puVar1);
  }
  DAT_08068abc = 0;
  DAT_08068ab8 = (undefined4 *)0x0;
  DAT_08068ab4 = 0;
  return;
}



__off_t FUN_08060f80(char *param_1)

{
  int *piVar1;
  int iVar2;
  stat local_5c;
  
  do {
    iVar2 = __xstat(3,param_1,&local_5c);
    if (-1 < iVar2) break;
    piVar1 = __errno_location();
  } while (*piVar1 == 4);
  if (iVar2 < 0) {
    local_5c.st_size = -1;
  }
  return local_5c.st_size;
}



undefined4 FUN_08060fd8(char *param_1)

{
  int iVar1;
  stat local_5c;
  
  iVar1 = __xstat(3,param_1,&local_5c);
  if (iVar1 == 0) {
    if ((local_5c.st_mode & 0xf000) == 0x4000) {
      return 3;
    }
    if ((local_5c.st_mode & 0xf000) == 0x8000) {
      return 2;
    }
  }
  return 0;
}



void FUN_08061028(FILE *param_1)

{
  int __fd;
  
  __fd = fileno(param_1);
  isatty(__fd);
  return;
}



undefined4 FUN_0806104c(undefined4 param_1)

{
  return param_1;
}



undefined4 FUN_08061054(void)

{
  return 0;
}



void FUN_0806105c(undefined4 param_1)

{
  FUN_0806104c(param_1);
  return;
}



void FUN_0806107c(undefined4 param_1)

{
  FUN_0806104c(param_1);
  return;
}



void FUN_0806109c(undefined4 param_1)

{
  FUN_0806104c(param_1);
  return;
}



int FUN_080610c0(byte *param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  iVar2 = 0;
  while( true ) {
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    if (bVar1 == 0) break;
    iVar2 = iVar2 + (uint)bVar1;
    iVar3 = iVar3 + iVar2;
  }
  return iVar3;
}



void FUN_080610e8(uint param_1)

{
  uint uVar1;
  
  uVar1 = 2;
  if (2 < param_1) {
    do {
      uVar1 = uVar1 * 2;
    } while (uVar1 < param_1);
  }
  return;
}



char * FUN_08061100(char *param_1)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  
  if (param_1 == (char *)0x0) {
    pcVar2 = (char *)0x0;
  }
  else {
    uVar3 = 0xffffffff;
    pcVar2 = param_1;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    pcVar2 = malloc(~uVar3);
    pcVar2 = strcpy(pcVar2,param_1);
  }
  return pcVar2;
}



void FUN_0806114c(char *param_1,size_t param_2)

{
  char *pcVar1;
  size_t __n;
  
  __n = param_2;
  pcVar1 = malloc(param_2 + 1);
  pcVar1 = strncpy(pcVar1,param_1,__n);
  pcVar1[param_2] = '\0';
  return;
}



void FUN_08061184(void *param_1)

{
  if (param_1 != (void *)0x0) {
    free(param_1);
  }
  return;
}



void FUN_080611a8(void *param_1)

{
  void *pvVar1;
  
  FUN_08061184(*(void **)((int)param_1 + 4));
  pvVar1 = *(void **)((int)param_1 + 8);
  if (*(void **)((int)param_1 + 0xc) != pvVar1) {
    FUN_08061184(*(void **)((int)param_1 + 0xc));
    pvVar1 = *(void **)((int)param_1 + 8);
  }
  FUN_08061184(pvVar1);
  free(param_1);
  return;
}



int * FUN_080611f0(uint param_1)

{
  int *piVar1;
  int iVar2;
  void *pvVar3;
  
  piVar1 = malloc(0xc);
  if (param_1 < 8) {
    param_1 = 8;
  }
  iVar2 = FUN_080610e8(param_1);
  piVar1[1] = iVar2;
  piVar1[2] = 0;
  pvVar3 = malloc(iVar2 * 4);
  *piVar1 = (int)pvVar3;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *(undefined4 *)(*piVar1 + iVar2 * 4) = 0;
  }
  return piVar1;
}



void FUN_08061258(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar3 = param_1[1];
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    puVar2 = *(undefined4 **)((int)*param_1 + iVar3 * 4);
    while (puVar2 != (undefined4 *)0x0) {
      puVar1 = (undefined4 *)*puVar2;
      FUN_080611a8(puVar2);
      puVar2 = puVar1;
    }
  }
  free((void *)*param_1);
  free(param_1);
  return;
}



undefined4 * FUN_080612b4(int *param_1,byte *param_2,char *param_3,uint param_4)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  char *pcVar5;
  
  uVar2 = FUN_080610c0(param_2);
  puVar1 = (undefined4 *)(*param_1 + (param_1[1] - 1U & uVar2) * 4);
  puVar4 = (undefined4 *)*puVar1;
  while ((puVar4 != (undefined4 *)0x0 &&
         (((char *)puVar4[1] == (char *)0x0 ||
          (iVar3 = strcmp((char *)puVar4[1],(char *)param_2), iVar3 != 0))))) {
    puVar1 = puVar4;
    puVar4 = (undefined4 *)*puVar4;
  }
  if ((param_4 & 1) == 0) {
    if (puVar4 == (undefined4 *)0x0) {
      if (param_3 == (char *)0x0) {
        return (undefined4 *)0x0;
      }
    }
    else if (param_3 == (char *)0x0) {
      param_1[2] = param_1[2] + -1;
      if ((param_4 & 2) != 0) {
        FUN_08061184(param_2);
      }
      if ((void *)puVar4[3] != (void *)0x0) {
        if ((void *)puVar4[3] != (void *)puVar4[2]) {
          FUN_08061184((void *)puVar4[2]);
        }
        puVar4[2] = 0;
        return puVar4;
      }
      *puVar1 = *puVar4;
      FUN_080611a8(puVar4);
      return (undefined4 *)0x0;
    }
    if (puVar4 == (undefined4 *)0x0) {
      puVar4 = malloc(0x10);
      *puVar4 = 0;
      *puVar1 = puVar4;
      if ((param_4 & 2) == 0) {
        pcVar5 = FUN_08061100((char *)param_2);
        puVar4[1] = pcVar5;
      }
      else {
        puVar4[1] = param_2;
      }
      puVar4[2] = 0;
      puVar4[3] = 0;
      param_1[2] = param_1[2] + 1;
    }
    else if ((param_4 & 2) != 0) {
      FUN_08061184(param_2);
    }
    if ((puVar4[2] == 0) || (iVar3 = strcmp((char *)(puVar4[2] + 1),param_3 + 1), iVar3 != 0)) {
      if ((void *)puVar4[2] != (void *)puVar4[3]) {
        FUN_08061184((void *)puVar4[2]);
      }
      if ((param_4 & 2) == 0) {
        pcVar5 = FUN_08061100(param_3);
        puVar4[2] = pcVar5;
      }
      else {
        puVar4[2] = param_3;
      }
      *(char *)puVar4[2] = *param_3;
    }
    else if ((param_4 & 2) != 0) {
      *(char *)puVar4[2] = *param_3;
      FUN_08061184(param_3);
    }
  }
  return puVar4;
}



undefined4 FUN_08061444(int *param_1,byte *param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = FUN_080612b4(param_1,param_2,(char *)0x0,1);
  if (puVar1 == (undefined4 *)0x0) {
    uVar2 = 0;
  }
  else {
    uVar2 = puVar1[2];
  }
  return uVar2;
}



undefined4 FUN_08061478(int *param_1,byte *param_2,int param_3,char *param_4)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  
  if ((*param_4 == '\0') && (param_3 != 0x3f)) {
    uVar3 = 0;
    pcVar2 = (char *)0x0;
  }
  else {
    param_2 = (byte *)FUN_08061100((char *)param_2);
    uVar3 = 0xffffffff;
    pcVar2 = param_4;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    pcVar2 = malloc(~uVar3 + 1);
    *pcVar2 = (char)param_3;
    strcpy(pcVar2 + 1,param_4);
    uVar3 = 2;
  }
  FUN_080612b4(param_1,param_2,pcVar2,uVar3);
  return 0;
}



undefined4 FUN_080614f4(int *param_1,byte *param_2,char *param_3)

{
  char cVar1;
  
  cVar1 = *param_3;
  if ((((cVar1 == '=') || (cVar1 == '#')) || (cVar1 == '^')) && (param_3[1] == '\0')) {
    param_3 = (char *)0x0;
  }
  FUN_080612b4(param_1,param_2,param_3,0);
  return 0;
}



undefined4 FUN_08061534(int *param_1,char *param_2)

{
  char cVar1;
  byte *pbVar2;
  char *pcVar3;
  char cVar4;
  
  cVar4 = *param_2;
  do {
    pcVar3 = param_2;
    if (cVar4 == '\0') {
      return 0;
    }
    do {
      if ((((cVar4 == '\n') || (cVar4 == '?')) || (cVar4 == '#')) ||
         ((cVar4 == '=' || (cVar4 == '^')))) break;
      pcVar3 = pcVar3 + 1;
      cVar4 = *pcVar3;
    } while (cVar4 != '\0');
    if ((cVar4 == '\0') || (cVar4 == '\n')) {
      return 1;
    }
    pbVar2 = (byte *)FUN_0806114c(param_2,(int)pcVar3 - (int)param_2);
    for (param_2 = pcVar3; (cVar4 = *param_2, cVar4 != '\0' && (cVar4 != '\n'));
        param_2 = param_2 + 1) {
    }
    if ((param_2 == pcVar3 + 1) &&
       (((cVar1 = *pcVar3, cVar1 == '=' || (cVar1 == '#')) || (cVar1 == '^')))) {
      pcVar3 = (char *)0x0;
    }
    else {
      pcVar3 = (char *)FUN_0806114c(pcVar3,(int)param_2 - (int)pcVar3);
      cVar4 = *param_2;
    }
    if (cVar4 == '\n') {
      param_2 = param_2 + 1;
    }
    FUN_080612b4(param_1,pbVar2,pcVar3,2);
    cVar4 = *param_2;
  } while( true );
}



void FUN_08061614(int *param_1)

{
  int iVar1;
  int *piVar2;
  void *pvVar3;
  int *piVar4;
  
  iVar1 = param_1[1];
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    piVar4 = (int *)(*param_1 + iVar1 * 4);
    while (piVar2 = (int *)*piVar4, piVar2 != (int *)0x0) {
      pvVar3 = (void *)piVar2[2];
      if ((void *)piVar2[3] != pvVar3) {
        FUN_08061184((void *)piVar2[3]);
        pvVar3 = (void *)piVar2[2];
      }
      piVar2[3] = (int)pvVar3;
      if (pvVar3 == (void *)0x0) {
        *piVar4 = *piVar2;
        FUN_080611a8(piVar2);
      }
      else {
        piVar4 = (int *)*piVar4;
      }
    }
  }
  return;
}



int * FUN_08061688(int *param_1)

{
  undefined4 *puVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = FUN_080611f0(param_1[2]);
  iVar3 = param_1[1];
  while (0 < iVar3) {
    iVar3 = iVar3 + -1;
    for (puVar1 = *(undefined4 **)(*param_1 + iVar3 * 4); puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      FUN_080612b4(piVar2,(byte *)puVar1[1],(char *)puVar1[2],0);
    }
  }
  return piVar2;
}



int FUN_080616ec(int *param_1,char *param_2,uint param_3)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  char *local_14;
  uint local_10;
  
  local_10 = 0;
  if (param_2 == (char *)0x0) {
    param_3 = 0;
  }
  iVar2 = param_1[1];
  do {
    if (iVar2 == 0) {
      return local_10 + 1;
    }
    iVar2 = iVar2 + -1;
    for (puVar3 = *(undefined4 **)(*param_1 + iVar2 * 4); puVar3 != (undefined4 *)0x0;
        puVar3 = (undefined4 *)*puVar3) {
      local_14 = (char *)puVar3[2];
      pcVar6 = (char *)puVar3[3];
      if (local_14 != pcVar6) {
        if (local_14 == (char *)0x0) {
          local_14 = "=";
        }
        else if ((pcVar6 != (char *)0x0) && (iVar4 = strcmp(local_14,pcVar6), iVar4 == 0))
        goto LAB_080618cd;
        uVar5 = 0xffffffff;
        pcVar6 = (char *)puVar3[1];
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar1 != '\0');
        local_10 = local_10 + (~uVar5 - 1);
        if (local_10 < param_3) {
          strcpy(param_2,(char *)puVar3[1]);
          param_2 = param_2 + (~uVar5 - 1);
        }
        uVar5 = 0xffffffff;
        pcVar6 = local_14;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar1 != '\0');
        local_10 = ~uVar5 + local_10;
        if (local_10 < param_3) {
          strcpy(param_2,local_14);
          pcVar6 = param_2 + (~uVar5 - 1);
          pcVar6[0] = '\n';
          pcVar6[1] = '\0';
          param_2 = pcVar6 + 1;
        }
      }
LAB_080618cd:
    }
  } while( true );
}



int FUN_080618f4(int *param_1,undefined *param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = param_1[1];
  do {
    if (iVar3 == 0) {
      return 0;
    }
    iVar3 = iVar3 + -1;
    for (puVar1 = *(undefined4 **)(*param_1 + iVar3 * 4); puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      if ((puVar1[2] != 0) && (iVar2 = (*(code *)param_2)(param_3,puVar1[1],puVar1[2]), iVar2 != 0))
      {
        return iVar2;
      }
    }
  } while( true );
}



char * FUN_08061950(char *param_1)

{
  char cVar1;
  char *__s2;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  uint uVar5;
  
  __s2 = FUN_0805ae64();
  pcVar2 = FUN_08061e7c((char *)0x0,(char *)0x0,(int)__s2,0);
  if (pcVar2 == (char *)0x0) {
    param_1 = (char *)0x0;
  }
  else {
    iVar3 = strcmp(pcVar2,__s2);
    if (iVar3 == 0) {
      sprintf(param_1,"config/%s",__s2);
    }
    else {
      pcVar4 = strrchr(pcVar2,0x2f);
      memcpy(param_1,pcVar2,(int)pcVar4 - (int)pcVar2);
      pcVar4 = param_1 + ((int)pcVar4 - (int)pcVar2);
      memcpy(pcVar4,"/config/",9);
      uVar5 = 0xffffffff;
      pcVar2 = pcVar4;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar2;
        pcVar2 = pcVar2 + 1;
      } while (cVar1 != '\0');
      strcpy(pcVar4 + (~uVar5 - 1),__s2);
    }
  }
  return param_1;
}



int * FUN_08061a08(void)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = FUN_080611f0(0x40);
  if (piVar1 != (int *)0x0) {
    iVar2 = FUN_0805add8(piVar1);
    if (iVar2 != 0) {
      FUN_08061258(piVar1);
      piVar1 = (int *)0x0;
    }
  }
  return piVar1;
}



int FUN_08061a48(int *param_1,char *param_2)

{
  int iVar1;
  char *pcVar2;
  FILE *__stream;
  size_t sVar3;
  int local_1008;
  char local_1004 [4096];
  
  if ((*param_2 == '$') && (param_2[1] == '\0')) {
    iVar1 = FUN_0805add8(param_1);
  }
  else if (*param_2 == '*') {
    if (param_2[1] == '\0') {
      pcVar2 = FUN_08061950(local_1004);
    }
    else {
      pcVar2 = param_2 + 1;
    }
    if ((pcVar2 != (char *)0x0) && (__stream = fopen(pcVar2,"r"), __stream != (FILE *)0x0)) {
      fseek(__stream,0,2);
      sVar3 = ftell(__stream);
      fseek(__stream,0,0);
      pcVar2 = malloc(sVar3 + 1);
      if (pcVar2 == (char *)0x0) {
        local_1008 = 1;
      }
      else {
        sVar3 = fread(pcVar2,1,sVar3,__stream);
        pcVar2[sVar3] = '\0';
        local_1008 = FUN_08061534(param_1,pcVar2);
        free(pcVar2);
      }
      fclose(__stream);
      return local_1008;
    }
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_08061534(param_1,param_2);
  }
  return iVar1;
}



bool FUN_08061b58(int *param_1)

{
  uint param2;
  size_t __size;
  char *pcVar1;
  FILE *pFVar2;
  size_t sVar3;
  char *__filename;
  bool bVar4;
  char local_1004 [4096];
  
  param2 = FUN_08061d6c();
  sprintf(local_1004,"?%#.8x",param2);
  FUN_080614f4(param_1,(byte *)".defaulttime",local_1004);
  __size = FUN_080616ec(param_1,(char *)0x0,0);
  if (__size == 0) {
    pcVar1 = FUN_08061950(local_1004);
    if ((pcVar1 != (char *)0x0) && (pFVar2 = fopen(pcVar1,"w"), pFVar2 != (FILE *)0x0)) {
      fclose(pFVar2);
      return false;
    }
  }
  else {
    pcVar1 = malloc(__size);
    if (pcVar1 != (char *)0x0) {
      sVar3 = FUN_080616ec(param_1,pcVar1,__size);
      if (((sVar3 == __size) && (__filename = FUN_08061950(local_1004), __filename != (char *)0x0))
         && (pFVar2 = fopen(__filename,"w"), pFVar2 != (FILE *)0x0)) {
        sVar3 = fwrite(pcVar1,1,__size,pFVar2);
        bVar4 = sVar3 != __size;
        fclose(pFVar2);
      }
      else {
        bVar4 = true;
      }
      free(pcVar1);
      return bVar4;
    }
  }
  return true;
}



__time_t FUN_08061ca0(char *param_1)

{
  int iVar1;
  stat local_5c;
  
  iVar1 = __xstat(3,param_1,&local_5c);
  if (iVar1 != 0) {
    local_5c.st_mtim.tv_sec = -1;
  }
  return local_5c.st_mtim.tv_sec;
}



undefined4 FUN_08061cd8(char *param_1,__time_t param_2)

{
  int iVar1;
  undefined4 uVar2;
  utimbuf local_c;
  
  local_c.actime = param_2;
  local_c.modtime = param_2;
  iVar1 = utime(param_1,&local_c);
  if (iVar1 == 0) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



undefined4 FUN_08061d1c(char *param_1)

{
  int iVar1;
  stat local_5c;
  
  iVar1 = __xstat(3,param_1,&local_5c);
  if ((iVar1 == 0) && (iVar1 = chmod(param_1,local_5c.st_mode | 0x40), iVar1 == 0)) {
    return 0;
  }
  return 0xffffffff;
}



time_t FUN_08061d6c(void)

{
  time_t local_8;
  
  time(&local_8);
  return local_8;
}



void FUN_08061d90(void)

{
  return;
}



bool FUN_08061da0(char *param_1)

{
  int iVar1;
  stat local_5c;
  
  iVar1 = __xstat(3,param_1,&local_5c);
  return iVar1 == 0 && (local_5c.st_mode & 0xf000) != 0x4000;
}



char * FUN_08061de4(char *param_1,char *param_2,int param_3,char *param_4)

{
  bool bVar1;
  char *param2;
  undefined3 extraout_var;
  
  param2 = strtok(param_1,":");
  while( true ) {
    if (param_3 == 0) {
      sprintf(param_4,"%s/%s",param2,param_2);
    }
    else {
      sprintf(param_4,"%s/%s.%s",param2,param_2,(char *)param_3);
    }
    bVar1 = FUN_08061da0(param_4);
    if (CONCAT31(extraout_var,bVar1) != 0) break;
    param2 = strtok((char *)0x0,":");
    if (param2 == (char *)0x0) {
      return (char *)0x0;
    }
  }
  return param_4;
}



char * FUN_08061e7c(char *param_1,char *param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  char *pcVar2;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  char local_808 [2048];
  undefined1 local_8;
  
  if (param_1 != (char *)0x0) {
    DAT_08068ac0 = param_1;
  }
  if (param_3 == 0) {
    return (char *)0x0;
  }
  local_8 = 0;
  if (param_4 == 0) {
    sprintf(&DAT_0806a760,"%s",(char *)param_3);
  }
  else {
    sprintf(&DAT_0806a760,"%s.%s",(char *)param_3,(char *)param_4);
  }
  bVar1 = FUN_08061da0(&DAT_0806a760);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    pcVar2 = (char *)0x0;
    if (DAT_08068ac0 != (char *)0x0) {
      pcVar2 = strrchr(DAT_08068ac0,0x2f);
    }
    if (pcVar2 != (char *)0x0) {
      if (param_4 == 0) {
        sprintf(&DAT_0806a760,"%.*s%s",(int)(pcVar2 + (1 - (int)DAT_08068ac0)),DAT_08068ac0,
                (char *)param_3);
      }
      else {
        sprintf(&DAT_0806a760,"%.*s%s.%s",(int)(pcVar2 + (1 - (int)DAT_08068ac0)),DAT_08068ac0,
                (char *)param_3,(char *)param_4);
      }
      bVar1 = FUN_08061da0(&DAT_0806a760);
      if (CONCAT31(extraout_var_00,bVar1) != 0) goto LAB_0806206b;
    }
    if ((param_2 != (char *)0x0) && (pcVar2 = getenv(param_2), pcVar2 != (char *)0x0)) {
      strncpy(local_808,pcVar2,0x800);
      pcVar2 = FUN_08061de4(local_808,param_3,param_4,&DAT_0806a760);
      if (pcVar2 != (char *)0x0) {
        return pcVar2;
      }
    }
    pcVar2 = getenv("ARMLIB");
    if (pcVar2 != (char *)0x0) {
      strncpy(local_808,pcVar2,0x800);
      pcVar2 = FUN_08061de4(local_808,param_3,param_4,&DAT_0806a760);
      if (pcVar2 != (char *)0x0) {
        return pcVar2;
      }
    }
    pcVar2 = getenv("HOME");
    if (pcVar2 != (char *)0x0) {
      if (param_4 == 0) {
        sprintf(&DAT_0806a760,"%s/%s",pcVar2,(char *)param_3);
      }
      else {
        sprintf(&DAT_0806a760,"%s/%s.%s",pcVar2,(char *)param_3,(char *)param_4);
      }
      bVar1 = FUN_08061da0(&DAT_0806a760);
      if (CONCAT31(extraout_var_01,bVar1) != 0) goto LAB_0806206b;
    }
    pcVar2 = getenv("PATH");
    if ((pcVar2 != (char *)0x0) && (*pcVar2 != '\0')) {
      strncpy(local_808,pcVar2,0x800);
      pcVar2 = FUN_08061de4(local_808,param_3,param_4,&DAT_0806a760);
      if (pcVar2 != (char *)0x0) {
        return pcVar2;
      }
    }
    memcpy(local_808,"/usr/local/lib/arm:/usr/local/lib:/usr/local/arm:/usr/lib/arm:/usr/lib",0x47);
    pcVar2 = FUN_08061de4(local_808,param_3,param_4,&DAT_0806a760);
  }
  else {
LAB_0806206b:
    pcVar2 = &DAT_0806a760;
  }
  return pcVar2;
}



void FUN_080620f0(void)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = &DAT_08068ac8;
  iVar1 = DAT_08068ac8;
  while (iVar1 != -1) {
    (*(code *)*piVar2)();
    piVar2 = piVar2 + -1;
    iVar1 = *piVar2;
  }
  return;
}



void FUN_08062114(void)

{
  return;
}



void _DT_FINI(void)

{
  FUN_08049000();
  return;
}


