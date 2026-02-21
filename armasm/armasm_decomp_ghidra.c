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
undefined FUN_08062290;
int DAT_080795e8;
undefined *PTR_DAT_080795e4;
dword DWORD_0807b0a0;
undefined DAT_0807b26c;
undefined DAT_08080180;
undefined DAT_08080184;
undefined DAT_08080188;
undefined DAT_0808018c;
undefined DAT_08080197;
undefined DAT_08080198;
undefined DAT_0808019c;
undefined DAT_080801a0;
int DAT_0807b2b0;
uint *DAT_0807b2b4;
uint DAT_0807b2ac;
uint DAT_0808276c;
char *DAT_0807b2b4;
undefined4 DAT_0807b2ac;
undefined4 DAT_0807b288;
undefined4 DAT_0807b284;
uint *DAT_0807b28c;
int DAT_0807b298;
int DAT_0807b284;
int DAT_0807b288;
int DAT_0807b290;
uint *DAT_0807b284;
uint *DAT_0807b288;
int DAT_0807fee0;
uint *DAT_0807b29c;
uint *DAT_0807b298;
undefined1 DAT_0807ff20;
uint *DAT_0807b2a0;
uint *DAT_0807b294;
uint *DAT_0807b290;
undefined4 DAT_0807b298;
int DAT_0807b28c;
undefined4 *DAT_0807b28c;
int DAT_0808269c;
int DAT_0808276c;
int DAT_0808014c;
int DAT_0807b2c0;
uint *DAT_0807b2bc;
undefined4 *DAT_0807b2b8;
uint *DAT_0807b2b8;
int *DAT_0807b2a0;
undefined4 DAT_0807b2bc;
int DAT_0807b2c8;
undefined DAT_0807b2cc;
uint DAT_0807b2d4;
undefined4 DAT_0807b2c4;
int DAT_0807b2d0;
undefined4 DAT_080714d4;
undefined4 *DAT_0807b2bc;
undefined DAT_080714c9;
undefined DAT_080714e8;
undefined4 DAT_08071504;
int DAT_080825d0;
undefined4 DAT_0807b290;
undefined4 DAT_0807b28c;
undefined4 *DAT_0807b294;
undefined DAT_0807b2a8;
undefined DAT_0807b2a4;
undefined4 DAT_0807b2b0;
undefined *DAT_0807b2b4;
undefined DAT_08071556;
undefined4 DAT_0807b2a0;
uint *DAT_0807b404;
uint *DAT_0807b408;
undefined4 *DAT_0807b404;
uint DAT_0807b404;
undefined4 DAT_0807b408;
int DAT_0807ff14;
undefined4 DAT_0807ff0c;
FILE *DAT_08080020;
uint *DAT_0807b40c;
uint *DAT_0807b410;
undefined4 *DAT_0807b40c;
uint *DAT_0807b2e4;
undefined DAT_0807b400;
FILE *DAT_0807ff04;
uint *DAT_0807ff00;
uint *DAT_0807ff10;
uint *DAT_0807ff08;
undefined DAT_08080040;
undefined4 DAT_0807b2e0;
undefined4 DAT_0807ff14;
undefined4 DAT_0807b2e4;
undefined1 DAT_0807b300;
undefined DAT_0808262c;
undefined4 DAT_08082640;
uint DAT_08082690;
int DAT_08082634;
int DAT_080826fc;
int DAT_08082648;
int DAT_080825d4;
int DAT_08082654;
undefined4 DAT_08082688;
int DAT_080825c4;
undefined4 DAT_0808263c;
undefined4 DAT_08082638;
undefined4 DAT_08082680;
int DAT_080826ac;
undefined4 DAT_080825cc;
undefined4 DAT_08080158;
int DAT_08080168;
int DAT_08079868;
undefined4 DAT_0808277c;
undefined4 DAT_0808264c;
undefined4 DAT_080825d0;
undefined4 DAT_080795f0;
undefined4 DAT_080795ec;
uint DAT_080826c8;
undefined4 DAT_080826d0;
undefined DAT_080826a4;
undefined4 DAT_08082768;
uint DAT_080826a0;
undefined *DAT_080795f4;
int DAT_08079804;
int DAT_08082698;
undefined4 DAT_08082594;
undefined4 DAT_080826c0;
undefined4 DAT_080826c4;
int DAT_08082628;
undefined DAT_080826cc;
int DAT_08082650;
int DAT_080826f8;
uint DAT_08082704;
uint DAT_08082618;
uint DAT_0808268c;
undefined DAT_08082660;
uint DAT_08082664;
uint DAT_08082668;
undefined DAT_0808266c;
undefined DAT_08082678;
undefined DAT_0808267c;
undefined4 DAT_080826d4;
undefined DAT_08082674;
undefined DAT_08082670;
uint DAT_08082630;
int *DAT_0807b2e4;
int DAT_0808259c;
undefined4 DAT_08079804;
long DAT_080825a0;
undefined4 DAT_08080140;
undefined4 DAT_08082624;
int DAT_0807b2e0;
undefined4 stdin;
char *DAT_08080140;
uint DAT_08082624;
char *DAT_080825a0;
int DAT_08082610;
int DAT_08082780;
uint DAT_08082768;
uint DAT_08082594;
undefined4 DAT_08082698;
undefined4 DAT_08082630;
undefined4 DAT_08082684;
undefined4 DAT_0807b410;
undefined4 DAT_0807b40c;
undefined4 DAT_08082720;
undefined DAT_0807b300;
undefined1 DAT_080716a0;
undefined4 DAT_080716cc;
pointer PTR_s_#none_0807199c;
undefined4 DAT_080719a4;
undefined FUN_0804ea64;
undefined FUN_0804eae0;
int DAT_0807b630;
undefined4 DAT_080825d8;
undefined4 DAT_08082760;
undefined4 DAT_080826f0;
undefined4 DAT_08082614;
undefined4 DAT_080825c0;
pointer PTR_s_reentrant_080720ec;
pointer PTR_s_-apcs.reent_080720f0;
pointer PTR_s_#/reent_080720f4;
undefined4 DAT_080720f8;
undefined4 DAT_080825e0;
undefined4 DAT_08082650;
undefined1 DAT_0807b420;
uint DAT_0808258c;
undefined1 DAT_0807b520;
undefined4 DAT_08080164;
undefined4 DAT_08082620;
int DAT_0807b624;
undefined4 DAT_080825c8;
undefined DAT_08082764;
undefined4 DAT_08079800;
undefined4 DAT_08079868;
undefined4 DAT_080829a0;
int DAT_0807b628;
undefined4 DAT_080826ac;
undefined4 DAT_08082610;
undefined4 DAT_08082700;
undefined4 DAT_080826f4;
undefined4 DAT_080826ec;
undefined4 DAT_08080144;
undefined DAT_0808261c;
int DAT_08082630;
FILE *DAT_0807b634;
undefined4 stdout;
uint DAT_08082590;
undefined4 DAT_0808269c;
int DAT_0807b620;
int DAT_08082608;
int DAT_0807b62c;
undefined4 DAT_0807fee0;
undefined4 DAT_08080148;
undefined4 DAT_080825fc;
undefined DAT_08082600;
uint DAT_080825f0;
int DAT_080825f4;
undefined DAT_080825f8;
undefined4 DAT_080716b0;
pointer PTR_DAT_080716b4;
undefined4 DAT_080716b8;
undefined4 DAT_080719a0;
undefined4 DAT_0807b630;
undefined4 DAT_0807b62c;
undefined4 DAT_0807b628;
undefined4 DAT_0807b624;
undefined4 DAT_0807b620;
undefined4 DAT_0807b634;
pointer PTR_FUN_08072d60;
pointer PTR_FUN_08072d68;
undefined1 DAT_0807b521;
undefined1 DAT_0807b525;
undefined1 DAT_0807b524;
undefined1 DAT_0807b523;
undefined1 DAT_0807b522;
undefined1 DAT_0807b527;
undefined1 DAT_0807b526;
undefined1 DAT_0807b421;
undefined1 DAT_0807b425;
byte DAT_0807b424;
undefined1 DAT_0807b423;
undefined1 DAT_0807b422;
undefined1 DAT_0807b427;
undefined1 DAT_0807b426;
FILE *DAT_08084dc4;
undefined *DAT_08084dc0;
uint *DAT_0807c798;
uint *DAT_0807c794;
uint *DAT_0807c7a0;
uint *DAT_0807c79c;
undefined4 DAT_0807c654;
long DAT_0807c790;
int DAT_08082774;
undefined *PTR_DAT_080795fc;
undefined4 DAT_0807c644;
int DAT_08082778;
long DAT_0807c658;
long DAT_0807c64c;
size_t DAT_0807c654;
undefined4 DAT_0807c794;
undefined4 DAT_0807c798;
int DAT_0807c654;
int DAT_08082664;
int DAT_0807c64c;
uint *DAT_0807c7a4;
uint *DAT_0807c7ac;
uint *DAT_0807c7a8;
uint *DAT_0807c7b0;
undefined4 DAT_0807c648;
uint *DAT_0807c650;
undefined4 DAT_0807c7a4;
undefined4 DAT_0807c7a8;
int DAT_0807c7ac;
int DAT_0807c7b0;
uint DAT_0807c644;
undefined *PTR_DAT_080795f8;
int DAT_0807c644;
int DAT_080826a0;
uint DAT_0807c648;
int DAT_080826f0;
int DAT_080795ec;
int DAT_0807c650;
int DAT_08082690;
int DAT_0807ff00;
undefined4 DAT_080826a0;
undefined4 DAT_080825d4;
int DAT_0807ff08;
int DAT_0807ff10;
uint *DAT_0808014c;
uint DAT_08082778;
uint DAT_08082774;
uint DAT_080795ec;
undefined4 DAT_0807c650;
int DAT_08080150;
int DAT_08082640;
int DAT_080826c8;
undefined4 DAT_0808276c;
undefined4 DAT_0808014c;
undefined4 DAT_080826f8;
undefined4 DAT_08082778;
undefined4 DAT_08082704;
undefined4 DAT_08082618;
undefined4 DAT_0808268c;
undefined4 DAT_08080150;
undefined4 DAT_08082628;
int DAT_0807c660;
undefined DAT_0807c780;
uint DAT_0807c658;
undefined DAT_0807c788;
undefined DAT_0807c78c;
uint DAT_08082648;
long DAT_0807c664;
void *DAT_0807ff10;
undefined DAT_0807c784;
undefined UNK_0807c781;
void *DAT_0807ff08;
uint DAT_0807c668;
uint DAT_0807c66c;
uint DAT_0807c660;
uint DAT_0807c664;
undefined4 DAT_0807c784;
int DAT_0807c65c;
int DAT_0807c658;
int DAT_0807c790;
int DAT_08082668;
long DAT_0807c65c;
int *DAT_0807c650;
uint DAT_0807e7c0;
undefined4 DAT_0807c7c0;
int DAT_0807e7c0;
undefined4 DAT_0807c7a0;
undefined4 DAT_08080154;
undefined4 DAT_0807e7c0;
undefined4 DAT_0807e7c4;
int DAT_0807e7c4;
undefined4 DAT_0807e7c8;
int DAT_0807e7c8;
FILE *DAT_08084dc8;
undefined4 DAT_08084dc4;
int DAT_08080158;
int DAT_08080164;
undefined4 DAT_08080160;
uint DAT_08080168;
ulong DAT_08082594;
int DAT_0807ff0c;
char *DAT_08082584;
ulong DAT_080826a0;
string s_armasm_08079858;
undefined4 DAT_0807e9e0;
int DAT_08080160;
int DAT_080801a8;
uint DAT_080801ac;
undefined1 *DAT_080801b0;
undefined DAT_08073280;
undefined1 DAT_0807e7e0;
undefined4 DAT_080801ac;
undefined4 DAT_080801c4;
int DAT_080801ac;
char *DAT_080801b0;
uint DAT_080801a8;
int DAT_080801bc;
undefined4 DAT_080801b0;
int DAT_080801c0;
undefined4 DAT_080801bc;
undefined DAT_0807e9e4;
undefined DAT_0807e9ec;
undefined DAT_0807ea08;
undefined DAT_0807ea0c;
undefined DAT_0807ea1c;
undefined DAT_0807ea00;
int DAT_080826f4;
undefined4 DAT_0807ea2c;
undefined4 DAT_0807ea30;
int DAT_0807ea2c;
uint DAT_0807ea30;
FILE *DAT_08082588;
undefined4 DAT_0807ea48;
undefined4 DAT_0807ea4c;
int DAT_08082580;
int DAT_08084dc4;
undefined DAT_0807ea60;
undefined4 DAT_08082590;
undefined4 DAT_0807ea44;
int DAT_08082590;
int DAT_0807ea44;
int DAT_0807ea4c;
ulong DAT_0807ea48;
uint DAT_0807ea40;
undefined1 DAT_08079600;
undefined1 DAT_08079700;
int DAT_08080154;
uint DAT_080825cc;
int DAT_08082644;
undefined4 DAT_080825a0;
undefined DAT_08082644;
int DAT_08082594;
undefined4 DAT_08082644;
undefined4 DAT_0808015c;
int DAT_08082770;
int DAT_08082688;
int DAT_080826a8;
char *DAT_08082598;
undefined4 DAT_08082654;
undefined1 DAT_0807ec7f;
int DAT_08082624;
int DAT_08080140;
undefined1 DAT_0807eb80;
undefined1 DAT_0807eb7f;
undefined4 DAT_08082770;
undefined4 DAT_080826a8;
int DAT_08079808;
pointer PTR_s_ALIGN_080738e4;
undefined1 DAT_0807ec80;
undefined4 DAT_080849c0;
undefined DAT_080738e0;
undefined DAT_080738e8;
undefined4 DAT_08073cf8;
pointer PTR_DAT_08073cfc;
undefined4 DAT_08073d00;
undefined DAT_08073e8c;
undefined DAT_0807ed80;
undefined DAT_08073e10;
undefined1 DAT_0807ecdb;
undefined1 DAT_0807ecfc;
undefined1 DAT_0807ecdd;
undefined1 DAT_0807eca1;
undefined1 DAT_0807eca3;
undefined1 DAT_0807ecaa;
undefined1 DAT_0807ecbd;
undefined1 DAT_0807eca5;
undefined1 DAT_0807eca6;
undefined1 DAT_0807ecde;
undefined4 DAT_080828a0;
undefined4 DAT_080828a4;
undefined DAT_080828a8;
undefined DAT_080828c8;
undefined DAT_080828e8;
undefined DAT_080828ec;
undefined DAT_080828f0;
undefined DAT_080828f8;
undefined DAT_0808298c;
undefined DAT_080827b8;
undefined DAT_080827bc;
undefined DAT_080827c0;
undefined DAT_08082890;
undefined DAT_08082828;
undefined DAT_0808282c;
undefined DAT_08082830;
undefined DAT_08082834;
undefined DAT_08082894;
undefined DAT_08082840;
undefined DAT_08082844;
undefined DAT_08082848;
undefined DAT_0808284c;
undefined DAT_08082860;
undefined DAT_0808286c;
undefined DAT_0807ed84;
undefined DAT_0807ed88;
undefined DAT_0807ed8c;
undefined DAT_0807ed90;
undefined DAT_0807ed94;
undefined DAT_0807ed98;
undefined DAT_0807ed9c;
undefined DAT_0807ee14;
undefined DAT_0807ee74;
undefined DAT_0807eda0;
undefined DAT_0807ee70;
undefined DAT_0807eda4;
undefined DAT_0807eda8;
undefined DAT_0807edac;
undefined DAT_0807edb0;
undefined DAT_0807edb4;
undefined DAT_0807edb8;
undefined DAT_0807edbc;
undefined DAT_0807edc0;
undefined DAT_0807edc4;
undefined DAT_0807ee1c;
undefined DAT_0807ee34;
undefined DAT_0807ee38;
undefined DAT_0807edc8;
undefined DAT_0807edcc;
undefined DAT_0807edd0;
undefined DAT_0807edd4;
undefined DAT_0807edd8;
undefined DAT_0807eddc;
undefined DAT_0807ede0;
undefined DAT_0807ede4;
undefined DAT_0807ede8;
undefined DAT_0807edec;
undefined DAT_0807edf0;
undefined DAT_0807edf4;
undefined DAT_0807edf8;
undefined DAT_0807edfc;
undefined DAT_0807ee00;
undefined DAT_0807ee04;
undefined DAT_0807ee08;
undefined DAT_0807ee6c;
undefined DAT_0807ee0c;
undefined DAT_0807ee10;
undefined DAT_0807ee44;
undefined DAT_0807ee48;
undefined DAT_0807ee50;
undefined DAT_0807ee60;
undefined DAT_0807ee3c;
undefined DAT_0807ee40;
undefined DAT_0807ee20;
undefined DAT_0807ee24;
undefined DAT_0807ee28;
undefined DAT_0807ee2c;
undefined DAT_0807ee30;
undefined DAT_0807ee5c;
undefined4 DAT_080827a0;
int DAT_0807f080;
undefined DAT_0807ee80;
uint DAT_0807f080;
int DAT_08082584;
int DAT_0808015c;
undefined4 DAT_0807f080;
undefined4 DAT_0807f0d0;
undefined4 DAT_0807f0c0;
undefined4 DAT_0807f0cc;
undefined4 DAT_0807f0c8;
uint *DAT_0807f0c8;
uint *DAT_0807f0c0;
undefined4 DAT_0807f0c4;
uint *DAT_0807f0c4;
uint DAT_0807f0d0;
uint DAT_0807f0c8;
uint *DAT_0807f0cc;
int DAT_0807f0c4;
undefined DAT_0807f0b0;
undefined DAT_0807f0a0;
uint *DAT_0807f0d8;
uint DAT_0807f0d4;
undefined4 DAT_0807f0dc;
uint DAT_08082780;
int DAT_0807f0d4;
undefined4 *DAT_0807f0d4;
int *DAT_0807f0dc;
int DAT_080825a0;
uint *DAT_0807f0e4;
undefined4 DAT_0807f0e8;
uint *DAT_0807f0e0;
uint *DAT_0807f0e8;
uint DAT_080825a0;
uint DAT_08082644;
undefined DAT_080825cc;
size_t DAT_08082594;
undefined4 DAT_0807f0e0;
undefined4 DAT_0807f0e4;
int DAT_0807f0e4;
undefined DAT_080744fa;
undefined1 DAT_0807ff21;
int DAT_08079848;
undefined4 DAT_08074620;
undefined4 DAT_08074624;
uint DAT_08082654;
size_t DAT_08082694;
size_t DAT_0808276c;
size_t DAT_080826f8;
size_t DAT_08082704;
undefined4 DAT_08082774;
size_t DAT_0808268c;
size_t DAT_08082618;
int DAT_080826ec;
size_t DAT_080826d0;
uint DAT_080826d4;
int DAT_08082614;
int DAT_080825d8;
int DAT_080825c0;
size_t DAT_08082768;
int DAT_0808263c;
int DAT_08082680;
int DAT_08082638;
int DAT_0808264c;
uint DAT_08082598;
int DAT_080825c8;
int DAT_080826b0;
size_t DAT_080826b8;
size_t DAT_080826b4;
undefined DAT_0807980c;
undefined DAT_08079829;
undefined DAT_0807f100;
int DAT_08082694;
uint DAT_08082694;
uint DAT_080826f8;
undefined4 DAT_08082634;
uint DAT_080826b8;
uint DAT_080826b4;
undefined DAT_0807f200;
uint *DAT_08082584;
undefined4 DAT_0807984c;
undefined4 DAT_08079850;
int DAT_0807984c;
int DAT_08079850;
undefined4 DAT_0807f300;
undefined4 DAT_0807f33c;
undefined DAT_0807f31c;
undefined4 DAT_0807f320;
undefined4 *DAT_0807f300;
uint *DAT_0807f33c;
undefined4 DAT_080829c0;
uint DAT_08080150;
undefined FUN_0805f134;
undefined FUN_0805f26c;
undefined FUN_0805f288;
undefined FUN_0805f23c;
undefined FUN_0805f250;
int DAT_080829a0;
int DAT_08082700;
undefined DAT_0807f520;
undefined4 DAT_080826b4;
int DAT_080826b8;
uint DAT_080825c0;
undefined DAT_080753cf;
undefined4 DAT_0807f340;
undefined DAT_0807f344;
undefined4 DAT_0807f4a0;
undefined DAT_0807f4a4;
int DAT_08079854;
undefined DAT_0807f620;
undefined DAT_080849f4;
undefined DAT_08084a40;
undefined DAT_08084a3c;
undefined DAT_08084aac;
undefined DAT_0807f820;
undefined4 DAT_08084dc8;
undefined FUN_080617e8;
undefined FUN_08061810;
undefined FUN_08061854;
int DAT_08080148;
undefined FUN_08061734;
int DAT_08080144;
undefined DAT_0807f720;
undefined FUN_08061610;
undefined4 DAT_08084dc0;
undefined4 DAT_08082588;
undefined4 DAT_08082580;
int DAT_0807f8bc;
undefined4 *DAT_08079864;
undefined *PTR_FUN_08075760;
pointer PTR_s_.hasthumb_08075788;
int *DAT_08079864;
FILE *DAT_0807f8c0;
undefined4 DAT_0807f8c0;
undefined DAT_08075af3;
undefined4 stderr;
undefined FUN_0806223c;
undefined1 DAT_08075b7a;
undefined1 DAT_08075b94;
undefined1 DAT_08075bcb;
undefined FUN_08062508;
undefined FUN_0806262c;
undefined *PTR_s_#callstd_08075be0;
undefined1 DAT_08075b9b;
undefined1 DAT_08075b8b;
undefined1 DAT_08075bdb;
undefined1 DAT_08075c27;
undefined FUN_08062c54;
undefined DAT_08075c2c;
undefined FUN_08062f28;
undefined FUN_08063024;
undefined FUN_0806313c;
undefined FUN_08063404;
int DAT_0807f8c4;
int DAT_0807f8c8;
undefined4 DAT_0807f8c8;
undefined4 DAT_0807f8c4;
byte DAT_080825f9;
byte DAT_080825f8;
int DAT_08082620;
int DAT_08079800;
int DAT_0807986c;
uint DAT_08079870;
undefined4 DAT_0807f8e0;
undefined4 DAT_0807f8e4;
undefined DAT_08079874;
undefined DAT_08079878;
undefined DAT_0807987c;
int DAT_08082760;
undefined FUN_080679f0;
int DAT_08082684;
pointer PTR_DAT_08079b98;
undefined4 DAT_08079b9c;
undefined4 DAT_08079ba0;
pointer PTR_DAT_0807a660;
undefined4 DAT_0807a664;
undefined4 DAT_0807a668;
int DAT_0808277c;
undefined DAT_0807a750;
undefined DAT_0807a754;
undefined DAT_0807a758;
undefined4 DAT_080826fc;
undefined DAT_0807a960;
undefined DAT_0807a964;
undefined DAT_0807a968;
undefined DAT_0807ad08;
undefined DAT_0807ad0c;
undefined DAT_0807ad10;
undefined4 DAT_0807b08c;
int DAT_0807b08c;
undefined DAT_080784ec;
undefined DAT_080784f2;
undefined4 *DAT_0807b090;
undefined4 *DAT_0807b094;
undefined4 DAT_0807b098;
undefined4 DAT_0807b094;
int *DAT_0807b094;
char *DAT_0807b09c;
undefined DAT_0807fae0;
undefined4 DAT_0807b0a4;

void _DT_INIT(void)

{
  func_0x00000000();
  FUN_08048fa0();
  FUN_08071160();
  return;
}



void FUN_08048b8c(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fgetc(FILE *__stream)

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

int fflush(FILE *__stream)

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



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strpbrk(char *__s,char *__accept)

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

char * strrchr(char *__s,int __c)

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

size_t strspn(char *__s,char *__accept)

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

char * strcpy(char *__dest,char *__src)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void processEntry entry(undefined4 param_1,undefined4 param_2)

{
  undefined1 auStack_4 [4];
  
  __libc_start_main(FUN_08062290,param_2,&stack0x00000004,_DT_INIT,_DT_FINI,param_1,auStack_4);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void FUN_08048f50(void)

{
  code *pcVar1;
  
  if (DAT_080795e8 == 0) {
    while (*(int *)PTR_DAT_080795e4 != 0) {
      pcVar1 = *(code **)PTR_DAT_080795e4;
      PTR_DAT_080795e4 = PTR_DAT_080795e4 + 4;
      (*pcVar1)();
    }
    __deregister_frame_info(&DWORD_0807b0a0);
    DAT_080795e8 = 1;
  }
  return;
}



void FUN_08048f98(void)

{
  return;
}



void FUN_08048fa0(void)

{
  __register_frame_info(&DWORD_0807b0a0,&DAT_0807b26c);
  return;
}



void FUN_08048fc0(void)

{
  return;
}



void FUN_08048fd0(uint *param_1,int *param_2,int param_3)

{
  char cVar1;
  byte bVar2;
  bool bVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar4;
  uint uVar5;
  sbyte sVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  undefined4 uVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  uint in_stack_ffffff04;
  int in_stack_ffffff08;
  undefined4 auStack_dc [5];
  undefined4 uStack_c8;
  char *pcVar14;
  char *local_28;
  char *local_24;
  int local_8;
  
  if (*param_1 < 0x1c) {
    local_8 = *param_2 + -2;
LAB_0804905f:
    puVar13 = (undefined4 *)(&DAT_08080184 + *param_2 * 0x24);
    puVar12 = auStack_dc;
    for (iVar7 = 8; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar12 = *puVar13;
      puVar13 = puVar13 + 1;
      puVar12 = puVar12 + 1;
    }
    puVar13 = (undefined4 *)(&DAT_08080184 + local_8 * 0x24);
    puVar12 = (undefined4 *)&stack0xffffff04;
    for (iVar7 = 8; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar12 = *puVar13;
      puVar13 = puVar13 + 1;
      puVar12 = puVar12 + 1;
    }
    bVar3 = FUN_080540c0(in_stack_ffffff04,in_stack_ffffff08);
    if (CONCAT31(extraout_var_00,bVar3) == 0) {
LAB_0804a1e0:
      pcVar14 = "Bad operand type";
      goto LAB_0804a1e5;
    }
  }
  else {
    local_8 = *param_2 + -1;
    puVar13 = (undefined4 *)(&DAT_08080184 + *param_2 * 0x24);
    puVar12 = auStack_dc;
    for (iVar7 = 8; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar12 = *puVar13;
      puVar13 = puVar13 + 1;
      puVar12 = puVar12 + 1;
    }
    puVar13 = (undefined4 *)(&DAT_08080184 + *param_2 * 0x24);
    puVar12 = (undefined4 *)&stack0xffffff04;
    for (iVar7 = 8; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar12 = *puVar13;
      puVar13 = puVar13 + 1;
      puVar12 = puVar12 + 1;
    }
    bVar3 = FUN_080540c0(in_stack_ffffff04,in_stack_ffffff08);
    if (CONCAT31(extraout_var,bVar3) == 0) {
      if (*param_1 < 0x1c) goto LAB_0804905f;
      goto LAB_0804a1e0;
    }
  }
  iVar7 = local_8 * 0x24;
  if ((*(int *)(&DAT_08080184 + iVar7) == 0) ||
     ((*(int *)(&DAT_08080184 + *param_2 * 0x24) == 0 && (*param_1 < 0x1c)))) {
    if (*param_1 - 7 < 6) {
      *(undefined4 *)(&DAT_08080188 + iVar7) = 1;
      *(undefined4 *)(&DAT_08080184 + iVar7) = 5;
    }
    else {
      *(undefined4 *)(&DAT_08080184 + iVar7) = 0;
    }
    goto switchD_080491dc_caseD_21;
  }
  if ((param_3 == 0) &&
     ((iVar7 = FUN_0806202c(*(undefined4 **)(&DAT_080801a0 + *param_2 * 0x24)), iVar7 != 0 ||
      ((*param_1 < 0x1c &&
       (iVar7 = FUN_0806202c(*(undefined4 **)(&DAT_080801a0 + local_8 * 0x24)), iVar7 != 0)))))) {
    pcVar14 = "Externals not valid in expressions";
LAB_0804a1e5:
    FUN_08052f1c(4,pcVar14);
    return;
  }
  uVar5 = *param_1;
  if ((((1 < uVar5 - 0xd) && (uVar5 != 0x1c)) && (uVar5 != 0x1d)) &&
     ((((uVar5 != 0x27 && (uVar5 != 0x28)) && (uVar5 != 0x29)) &&
      ((*(int *)(&DAT_080801a0 + *param_2 * 0x24) != 0 ||
       ((uVar5 < 0x1c && (*(int *)(&DAT_080801a0 + local_8 * 0x24) != 0)))))))) {
    pcVar14 = "Relocated expressions may only be added or subtracted";
    goto LAB_0804a1e5;
  }
  switch(uVar5) {
  case 4:
    *(uint *)(&DAT_08080188 + local_8 * 0x24) =
         *(uint *)(&DAT_08080188 + local_8 * 0x24) & *(uint *)(&DAT_08080188 + *param_2 * 0x24);
    break;
  case 5:
    *(uint *)(&DAT_08080188 + local_8 * 0x24) =
         *(uint *)(&DAT_08080188 + local_8 * 0x24) | *(uint *)(&DAT_08080188 + *param_2 * 0x24);
    break;
  case 6:
    *(uint *)(&DAT_08080188 + local_8 * 0x24) =
         *(uint *)(&DAT_08080188 + local_8 * 0x24) ^ *(uint *)(&DAT_08080188 + *param_2 * 0x24);
    break;
  case 7:
  case 8:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
    uStack_c8 = 0x804926f;
    uVar5 = FUN_0804a2ac(*param_2,local_8,uVar5);
    *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar5;
    *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = 5;
    break;
  case 0xd:
    if (*(int *)(&DAT_08080184 + *param_2 * 0x24) == 2) {
      *(undefined4 *)(&DAT_08080184 + *param_2 * 0x24) = 1;
      *(int *)(&DAT_08080188 + *param_2 * 0x24) = (int)**(char **)(&DAT_0808018c + *param_2 * 0x24);
    }
    iVar7 = local_8 * 0x24;
    if (*(int *)(&DAT_08080184 + iVar7) == 2) {
      *(undefined4 *)(&DAT_08080184 + iVar7) = 1;
      *(int *)(&DAT_08080188 + iVar7) = (int)**(char **)(&DAT_0808018c + iVar7);
    }
    puVar13 = (undefined4 *)(&DAT_08080184 + iVar7);
    FUN_0806206c((uint *)(&DAT_080801a0 + iVar7),(int *)(&DAT_080801a0 + *param_2 * 0x24));
    iVar8 = *param_2 * 0x24;
    uVar5 = *(uint *)(&DAT_08080184 + iVar8);
    if (uVar5 == 3) {
      uVar5 = *(uint *)(&DAT_08080184 + iVar7);
      if (uVar5 == 3) {
        iVar8 = *(int *)(&DAT_08080188 + iVar7);
        iVar4 = FUN_08062050(*(undefined4 **)(&DAT_080801a0 + iVar7));
        if (iVar4 == 0) {
          uVar11 = 1;
        }
        else {
          uVar11 = 3;
        }
        *puVar13 = uVar11;
        *(int *)(&DAT_08080188 + iVar7) = iVar8 + *(int *)(&DAT_08080188 + *param_2 * 0x24);
        break;
      }
      if (uVar5 < 4) {
        if (uVar5 == 1) {
          *(undefined4 *)(&DAT_08080184 + iVar7) = 3;
          *(int *)(&DAT_08080188 + iVar7) =
               *(int *)(&DAT_08080188 + iVar7) + *(int *)(&DAT_08080188 + *param_2 * 0x24);
        }
        break;
      }
      if (uVar5 != 4) break;
      *(int *)(&DAT_08080198 + iVar7) =
           *(int *)(&DAT_08080198 + iVar7) + *(int *)(&DAT_08080188 + iVar8);
      cVar1 = (&DAT_08080197)[iVar7];
      (&DAT_08080197)[iVar7] = cVar1 + '\x01';
      bVar3 = cVar1 == -1;
      uVar5 = 0;
      do {
        if ((&DAT_08080188)[uVar5 + iVar7] != '\0') {
          bVar3 = false;
        }
        uVar5 = uVar5 + 1;
      } while (uVar5 < 0xf);
      if (!bVar3) break;
      uVar11 = *(undefined4 *)(&DAT_08080198 + iVar7);
    }
    else {
      if (uVar5 < 4) {
        if (uVar5 == 1) {
          uVar5 = *(uint *)(&DAT_08080184 + iVar7);
          if (uVar5 == 3) {
            *(int *)(&DAT_08080188 + iVar7) =
                 *(int *)(&DAT_08080188 + iVar7) + *(int *)(&DAT_08080188 + iVar8);
          }
          else if (uVar5 < 4) {
            if (uVar5 == 1) {
              *(int *)(&DAT_08080188 + iVar7) =
                   *(int *)(&DAT_08080188 + iVar7) + *(int *)(&DAT_08080188 + iVar8);
            }
          }
          else if (uVar5 == 4) {
            *(int *)(&DAT_08080198 + iVar7) =
                 *(int *)(&DAT_08080198 + iVar7) + *(int *)(&DAT_08080188 + iVar8);
          }
        }
        break;
      }
      if (uVar5 != 4) break;
      uVar5 = *(uint *)(&DAT_08080184 + iVar7);
      if (uVar5 == 3) {
        iVar8 = *(int *)(&DAT_08080198 + iVar8);
        *(undefined4 *)(&DAT_08080184 + iVar7) = 4;
        *(int *)(&DAT_08080198 + iVar7) = iVar8 + *(int *)(&DAT_08080188 + iVar7);
        uVar5 = 0;
        do {
          (&DAT_08080188)[uVar5 + iVar7] = (&DAT_08080188)[uVar5 + *param_2 * 0x24];
          uVar5 = uVar5 + 1;
        } while (uVar5 < 0x10);
        cVar1 = (&DAT_08080197)[iVar7];
        (&DAT_08080197)[iVar7] = cVar1 + '\x01';
        bVar3 = cVar1 == -1;
        uVar5 = 0;
        do {
          if ((&DAT_08080188)[uVar5 + iVar7] != '\0') {
            bVar3 = false;
          }
          uVar5 = uVar5 + 1;
        } while (uVar5 < 0xf);
        if (!bVar3) break;
        uVar11 = *(undefined4 *)(&DAT_08080198 + iVar7);
      }
      else {
        if (uVar5 < 4) {
          if (uVar5 == 1) {
            iVar8 = *(int *)(&DAT_08080198 + iVar8);
            *(undefined4 *)(&DAT_08080184 + iVar7) = 4;
            *(int *)(&DAT_08080198 + iVar7) = iVar8 + *(int *)(&DAT_08080188 + iVar7);
            uVar5 = 0;
            do {
              (&DAT_08080188)[uVar5 + iVar7] = (&DAT_08080188)[uVar5 + *param_2 * 0x24];
              uVar5 = uVar5 + 1;
            } while (uVar5 < 0x10);
            *(undefined4 *)(&DAT_0808019c + iVar7) =
                 *(undefined4 *)(&DAT_0808019c + *param_2 * 0x24);
          }
          break;
        }
        if (uVar5 != 4) break;
        *(int *)(&DAT_08080198 + iVar7) =
             *(int *)(&DAT_08080198 + iVar7) + *(int *)(&DAT_08080198 + iVar8);
        uVar5 = 0;
        local_24 = &DAT_08080188 + iVar7;
        do {
          *local_24 = *local_24 + (&DAT_08080188)[uVar5 + *param_2 * 0x24];
          local_24 = local_24 + 1;
          uVar5 = uVar5 + 1;
        } while (uVar5 < 0x10);
        bVar2 = (&DAT_08080197)[iVar7];
        bVar3 = bVar2 < 2;
        uVar5 = 0;
        do {
          if ((&DAT_08080188 + iVar7)[uVar5] != '\0') {
            bVar3 = false;
          }
          uVar5 = uVar5 + 1;
        } while (uVar5 < 0xf);
        if (!bVar3) break;
        uVar11 = *(undefined4 *)(&DAT_08080198 + iVar7);
joined_r0x08049a2c:
        if (bVar2 != 0) goto LAB_08049a40;
      }
    }
    *puVar13 = 1;
    puVar13[1] = uVar11;
    break;
  case 0xe:
    iVar7 = *param_2 * 0x24;
    if (*(int *)(&DAT_08080184 + iVar7) == 2) {
      cVar1 = **(char **)(&DAT_0808018c + iVar7);
      *(undefined4 *)(&DAT_08080184 + iVar7) = 1;
      *(int *)(&DAT_08080188 + *param_2 * 0x24) = (int)cVar1;
    }
    iVar7 = local_8 * 0x24;
    if (*(int *)(&DAT_08080184 + iVar7) == 2) {
      cVar1 = **(char **)(&DAT_0808018c + iVar7);
      *(undefined4 *)(&DAT_08080184 + iVar7) = 1;
      *(int *)(&DAT_08080188 + iVar7) = (int)cVar1;
    }
    puVar13 = (undefined4 *)(&DAT_08080184 + iVar7);
    FUN_08062010(*(undefined4 **)(&DAT_080801a0 + *param_2 * 0x24));
    uStack_c8 = 0x8049713;
    FUN_0806206c((uint *)(&DAT_080801a0 + iVar7),(int *)(&DAT_080801a0 + *param_2 * 0x24));
    iVar8 = *param_2 * 0x24;
    uVar5 = *(uint *)(&DAT_08080184 + iVar8);
    if (uVar5 == 3) {
      uVar5 = *(uint *)(&DAT_08080184 + iVar7);
      if (uVar5 == 3) {
        iVar8 = *(int *)(&DAT_08080188 + iVar7);
        iVar4 = FUN_08062050(*(undefined4 **)(&DAT_080801a0 + iVar7));
        if (iVar4 == 0) {
          uVar11 = 1;
        }
        else {
          uVar11 = 3;
        }
        *puVar13 = uVar11;
        *(int *)(&DAT_08080188 + iVar7) = iVar8 - *(int *)(&DAT_08080188 + *param_2 * 0x24);
        break;
      }
      if (uVar5 < 4) {
        if (uVar5 == 1) {
          *(undefined4 *)(&DAT_08080184 + iVar7) = 3;
          *(int *)(&DAT_08080188 + iVar7) =
               *(int *)(&DAT_08080188 + iVar7) - *(int *)(&DAT_08080188 + *param_2 * 0x24);
        }
        break;
      }
      if (uVar5 != 4) break;
      *(int *)(&DAT_08080198 + iVar7) =
           *(int *)(&DAT_08080198 + iVar7) - *(int *)(&DAT_08080188 + iVar8);
      cVar1 = (&DAT_08080197)[iVar7];
      (&DAT_08080197)[iVar7] = cVar1 + -1;
      bVar3 = cVar1 == '\x02';
      uVar5 = 0;
      do {
        if ((&DAT_08080188)[uVar5 + iVar7] != '\0') {
          bVar3 = false;
        }
        uVar5 = uVar5 + 1;
      } while (uVar5 < 0xf);
    }
    else {
      if (uVar5 < 4) {
        if (uVar5 == 1) {
          uVar5 = *(uint *)(&DAT_08080184 + iVar7);
          if (uVar5 == 3) {
            *(int *)(&DAT_08080188 + iVar7) =
                 *(int *)(&DAT_08080188 + iVar7) - *(int *)(&DAT_08080188 + iVar8);
          }
          else if (uVar5 < 4) {
            if (uVar5 == 1) {
              *(int *)(&DAT_08080188 + iVar7) =
                   *(int *)(&DAT_08080188 + iVar7) - *(int *)(&DAT_08080188 + iVar8);
            }
          }
          else if (uVar5 == 4) {
            *(int *)(&DAT_08080198 + iVar7) =
                 *(int *)(&DAT_08080198 + iVar7) - *(int *)(&DAT_08080188 + iVar8);
          }
        }
        break;
      }
      if (uVar5 != 4) break;
      uVar5 = *(uint *)(&DAT_08080184 + iVar7);
      if (uVar5 == 3) {
        iVar8 = *(int *)(&DAT_08080198 + iVar8);
        *(undefined4 *)(&DAT_08080184 + iVar7) = 4;
        *(int *)(&DAT_08080198 + iVar7) = *(int *)(&DAT_08080188 + iVar7) - iVar8;
        uVar5 = 0;
        do {
          (&DAT_08080188)[uVar5 + iVar7] = (&DAT_08080188)[uVar5 + *param_2 * 0x24];
          uVar5 = uVar5 + 1;
        } while (uVar5 < 0x10);
        (&DAT_08080197)[iVar7] = (&DAT_08080197)[iVar7] + '\x01';
        break;
      }
      if (3 < uVar5) {
        if (uVar5 != 4) break;
        *(int *)(&DAT_08080198 + iVar7) =
             *(int *)(&DAT_08080198 + iVar7) - *(int *)(&DAT_08080198 + iVar8);
        uVar5 = 0;
        local_24 = &DAT_08080188 + iVar7;
        do {
          *local_24 = *local_24 - (&DAT_08080188)[uVar5 + *param_2 * 0x24];
          local_24 = local_24 + 1;
          uVar5 = uVar5 + 1;
        } while (uVar5 < 0x10);
        bVar2 = (&DAT_08080197)[iVar7];
        bVar3 = bVar2 < 2;
        uVar5 = 0;
        do {
          if ((&DAT_08080188 + iVar7)[uVar5] != '\0') {
            bVar3 = false;
          }
          uVar5 = uVar5 + 1;
        } while (uVar5 < 0xf);
        if (!bVar3) break;
        uVar11 = *(undefined4 *)(&DAT_08080198 + iVar7);
        goto joined_r0x08049a2c;
      }
      if (uVar5 != 1) break;
      iVar8 = *(int *)(&DAT_08080198 + iVar8);
      *(undefined4 *)(&DAT_08080184 + iVar7) = 4;
      *(int *)(&DAT_08080198 + iVar7) = *(int *)(&DAT_08080188 + iVar7) - iVar8;
      uVar5 = 0;
      do {
        (&DAT_08080188)[uVar5 + iVar7] = -(&DAT_08080188)[uVar5 + *param_2 * 0x24];
        uVar5 = uVar5 + 1;
      } while (uVar5 < 0x10);
      bVar3 = (&DAT_08080197)[iVar7] == '\x01';
      uVar5 = 0;
      do {
        if ((&DAT_08080188)[uVar5 + iVar7] != '\0') {
          bVar3 = false;
        }
        uVar5 = uVar5 + 1;
      } while (uVar5 < 0xf);
    }
    if (!bVar3) break;
    uVar11 = *(undefined4 *)(&DAT_08080198 + iVar7);
LAB_08049a40:
    *puVar13 = 3;
    puVar13[1] = uVar11;
    break;
  case 0xf:
    uVar5 = FUN_0804a200(*param_2);
    uVar10 = FUN_0804a200(local_8);
    if ((uVar5 & 0x1f) != 0) {
      sVar6 = (sbyte)(uVar5 & 0x1f);
      uVar5 = uVar10 >> sVar6;
      uVar10 = uVar10 << (0x20U - sVar6 & 0x1f);
LAB_08049ab2:
      uVar10 = uVar10 | uVar5;
    }
    goto LAB_08049ab4;
  case 0x10:
    uVar5 = FUN_0804a200(*param_2);
    uVar10 = FUN_0804a200(local_8);
    if ((uVar5 & 0x1f) != 0) {
      sVar6 = (sbyte)(uVar5 & 0x1f);
      uVar5 = uVar10 << sVar6;
      uVar10 = uVar10 >> (0x20U - sVar6 & 0x1f);
      goto LAB_08049ab2;
    }
LAB_08049ab4:
    *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = 1;
    *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar10;
    break;
  case 0x11:
    uVar5 = FUN_0804a200(*param_2);
    if (uVar5 < 0x20) {
      uVar10 = FUN_0804a200(local_8);
      *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar10 >> ((byte)uVar5 & 0x1f);
    }
    else {
LAB_08049b50:
      *(undefined4 *)(&DAT_08080188 + local_8 * 0x24) = 0;
    }
    goto LAB_08049b57;
  case 0x12:
    uVar5 = FUN_0804a200(*param_2);
    if (0x1f < uVar5) goto LAB_08049b50;
    iVar7 = FUN_0804a200(local_8);
    *(int *)(&DAT_08080188 + local_8 * 0x24) = iVar7 << ((byte)uVar5 & 0x1f);
LAB_08049b57:
    *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = 1;
    break;
  case 0x13:
    uVar5 = FUN_0804a200(local_8);
    uVar10 = FUN_0804a200(*param_2);
    uVar5 = uVar5 & uVar10;
    goto LAB_08049bda;
  case 0x14:
    uVar5 = FUN_0804a200(local_8);
    uVar10 = FUN_0804a200(*param_2);
    uVar5 = uVar5 | uVar10;
    goto LAB_08049bda;
  case 0x15:
    uVar5 = FUN_0804a200(local_8);
    uVar10 = FUN_0804a200(*param_2);
    uVar5 = uVar5 ^ uVar10;
LAB_08049bda:
    *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar5;
    *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = 1;
    break;
  case 0x16:
    uVar5 = FUN_0804a200(*param_2);
    if (*(uint *)(&DAT_08080188 + local_8 * 0x24) < uVar5) {
      pcVar14 = "String too short for operation";
      goto LAB_0804a1e5;
    }
    *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar5;
    break;
  case 0x17:
    uVar10 = FUN_0804a200(*param_2);
    uVar5 = *(uint *)(&DAT_08080188 + local_8 * 0x24);
    if (uVar5 < uVar10) {
      pcVar14 = "String too short for operation";
      goto LAB_0804a1e5;
    }
    uVar9 = 1;
    if (uVar10 != 0) {
      do {
        *(undefined1 *)(*(int *)(&DAT_0808018c + local_8 * 0x24) + -1 + uVar9) =
             *(undefined1 *)
              (*(int *)(&DAT_0808018c + local_8 * 0x24) + -1 + ((uVar5 + uVar9) - uVar10));
        uVar9 = uVar9 + 1;
      } while (uVar9 <= uVar10);
    }
    *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar10;
    break;
  case 0x18:
    FUN_0804a544(*param_2,local_8);
    break;
  case 0x19:
    iVar7 = FUN_0804a200(local_8);
    iVar8 = FUN_0804a200(*param_2);
    *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = 1;
    *(int *)(&DAT_08080188 + local_8 * 0x24) = iVar7 * iVar8;
    break;
  case 0x1a:
    uVar5 = FUN_0804a200(local_8);
    uVar10 = FUN_0804a200(*param_2);
    if (uVar10 == 0) {
      pcVar14 = "Division by zero";
      goto LAB_0804a1e5;
    }
    *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = 1;
    *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar5 / uVar10;
    break;
  case 0x1b:
    uVar5 = FUN_0804a200(local_8);
    uVar10 = FUN_0804a200(*param_2);
    if (uVar10 == 0) {
      pcVar14 = "Division by zero";
      goto LAB_0804a1e5;
    }
    *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = 1;
    *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar5 % uVar10;
    break;
  case 0x1c:
    uStack_c8 = 0x8049db2;
    FUN_08054004(local_8,*param_2,param_1);
    break;
  case 0x1d:
    iVar7 = *param_2 * 0x24;
    FUN_08062010(*(undefined4 **)(&DAT_080801a0 + iVar7));
    *(undefined4 *)(&DAT_080801a0 + local_8 * 0x24) = *(undefined4 *)(&DAT_080801a0 + iVar7);
    switch(*(undefined4 *)(&DAT_08080184 + iVar7)) {
    case 0:
    case 1:
      *(undefined4 *)(&DAT_08080180 + local_8 * 0x24) = 1;
      *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = *(undefined4 *)(&DAT_08080184 + iVar7);
      goto LAB_08049e7d;
    case 2:
      iVar8 = local_8 * 0x24;
      *(undefined4 *)(&DAT_08080180 + iVar8) = 1;
      *(undefined4 *)(&DAT_08080184 + iVar8) = 1;
      *(int *)(&DAT_08080188 + iVar8) = -(int)**(char **)(&DAT_0808018c + iVar7);
      break;
    case 3:
      *(undefined4 *)(&DAT_08080180 + local_8 * 0x24) = 1;
      *(undefined4 *)(&DAT_08080184 + local_8 * 0x24) = 3;
LAB_08049e7d:
      *(int *)(&DAT_08080188 + local_8 * 0x24) = -*(int *)(&DAT_08080188 + iVar7);
      break;
    case 4:
      iVar8 = local_8 * 0x24;
      *(undefined4 *)(&DAT_08080180 + iVar8) = 1;
      *(undefined4 *)(&DAT_08080184 + iVar8) = 4;
      uVar5 = 0;
      local_28 = &DAT_08080188 + iVar8;
      do {
        *local_28 = -(&DAT_08080188)[uVar5 + iVar7];
        local_28 = local_28 + 1;
        uVar5 = uVar5 + 1;
      } while (uVar5 < 0x10);
      iVar8 = local_8 * 0x24;
      *(int *)(&DAT_08080198 + iVar8) = -*(int *)(&DAT_08080198 + iVar7);
      bVar3 = (&DAT_08080197)[iVar8] == '\x01';
      uVar5 = 0;
      pcVar14 = &DAT_08080188 + iVar8;
      do {
        if (*pcVar14 != '\0') {
          bVar3 = false;
        }
        pcVar14 = pcVar14 + 1;
        uVar5 = uVar5 + 1;
      } while (uVar5 < 0xf);
      if (bVar3) {
        iVar7 = local_8 * 0x24;
        *(undefined4 *)(&DAT_08080184 + iVar7) = 3;
        *(undefined4 *)(&DAT_08080188 + iVar7) = *(undefined4 *)(&DAT_08080198 + iVar7);
      }
    }
    break;
  case 0x1e:
    iVar7 = local_8 * 0x24;
    *(undefined4 *)(&DAT_08080180 + iVar7) = 1;
    *(undefined4 *)(&DAT_08080184 + iVar7) = 5;
    *(uint *)(&DAT_08080188 + iVar7) = (uint)(*(int *)(&DAT_08080188 + *param_2 * 0x24) == 0);
    *(undefined4 *)(&DAT_080801a0 + iVar7) = 0;
    break;
  case 0x1f:
    iVar7 = local_8 * 0x24;
    *(undefined4 *)(&DAT_08080180 + iVar7) = 1;
    *(undefined4 *)(&DAT_08080184 + iVar7) = 1;
    *(uint *)(&DAT_08080188 + iVar7) = ~*(uint *)(&DAT_08080188 + *param_2 * 0x24);
    *(undefined4 *)(&DAT_080801a0 + iVar7) = 0;
    break;
  case 0x20:
    FUN_0804a630(*param_2,local_8);
    break;
  case 0x25:
    FUN_0804a678(*param_2,local_8);
    break;
  case 0x26:
    FUN_0804a6dc(*param_2,local_8);
    break;
  case 0x27:
    iVar7 = local_8 * 0x24;
    *(undefined4 *)(&DAT_08080180 + iVar7) = 1;
    *(undefined4 *)(&DAT_08080184 + iVar7) = 1;
    *(undefined4 *)(&DAT_080801a0 + iVar7) = 0;
    if (*(int *)(&DAT_08080184 + *param_2 * 0x24) == 3) {
      *(undefined4 *)(&DAT_08080188 + iVar7) = 0xf;
    }
    else if (*(int *)(&DAT_08080184 + *param_2 * 0x24) == 4) {
      uVar10 = 0;
      uVar5 = 0x10;
      do {
        if (((uVar5 != 0x10) ||
            (uVar9 = uVar10, (&DAT_08080188)[uVar10 + *param_2 * 0x24] != '\x01')) &&
           (uVar9 = uVar5, (&DAT_08080188)[uVar10 + *param_2 * 0x24] != '\0')) {
          FUN_08052f1c(4,"Bad operand type");
        }
        uVar10 = uVar10 + 1;
        uVar5 = uVar9;
      } while (uVar10 < 0x10);
      if (uVar9 == 0x10) {
        FUN_08052f1c(4,"Bad operand type");
      }
      *(uint *)(&DAT_08080188 + local_8 * 0x24) = uVar9;
    }
    break;
  case 0x28:
    iVar8 = local_8 * 0x24;
    *(undefined4 *)(&DAT_08080180 + iVar8) = 1;
    *(undefined4 *)(&DAT_080801a0 + iVar8) = 0;
    *(undefined4 *)(&DAT_08080184 + iVar8) = 1;
    iVar7 = *param_2;
    switch(*(undefined4 *)(&DAT_08080184 + iVar7 * 0x24)) {
    case 0:
    case 1:
      iVar7 = *(int *)(&DAT_08080188 + iVar7 * 0x24);
      break;
    case 2:
      iVar7 = (int)**(char **)(&DAT_0808018c + local_8 * 0x24);
      break;
    case 3:
      FUN_08052f1c(4,":INDEX: cannot be used on a PC Relative Expression");
      goto switchD_080491dc_caseD_21;
    case 4:
      iVar7 = *(int *)(&DAT_08080198 + iVar7 * 0x24);
      break;
    default:
      goto switchD_080491dc_caseD_21;
    }
    *(int *)(&DAT_08080188 + iVar8) = iVar7;
  }
switchD_080491dc_caseD_21:
  *param_2 = local_8;
  if (*(int *)(&DAT_08080180 + (local_8 * 9 + -9) * 4) != 0) {
    FUN_08052f1c(5,"Expression stack error");
  }
  *param_1 = *(uint *)(&DAT_08080184 + (*param_2 + -1) * 0x24);
  return;
}



int FUN_0804a200(int param_1)

{
  int iVar1;
  
  iVar1 = param_1 * 0x24;
  if (*(int *)(&DAT_08080184 + iVar1) == 2) {
    iVar1 = (int)**(char **)(&DAT_0808018c + iVar1);
  }
  else {
    iVar1 = *(int *)(&DAT_08080188 + iVar1);
  }
  return iVar1;
}



uint FUN_0804a228(uint *param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  byte *pbVar5;
  byte *pbVar6;
  bool bVar7;
  bool bVar8;
  
  *param_3 = (uint)(*param_1 == *param_2);
  uVar1 = *param_1;
  if (uVar1 == 0) {
    uVar3 = 1;
  }
  else {
    uVar2 = *param_2;
    if (uVar2 == 0) {
      uVar3 = 0;
    }
    else {
      uVar4 = uVar1;
      if (uVar2 < uVar1) {
        uVar4 = uVar2;
      }
      bVar7 = false;
      uVar3 = 0;
      bVar8 = true;
      pbVar5 = (byte *)param_1[1];
      pbVar6 = (byte *)param_2[1];
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        bVar7 = *pbVar5 < *pbVar6;
        bVar8 = *pbVar5 == *pbVar6;
        pbVar5 = pbVar5 + 1;
        pbVar6 = pbVar6 + 1;
      } while (bVar8);
      if (!bVar8) {
        uVar3 = -(uint)bVar7 | 1;
      }
      if (uVar3 == 0) {
        uVar3 = (uint)(uVar1 <= uVar2);
      }
      else {
        *param_3 = 0;
        uVar3 = uVar3 >> 0x1f;
      }
    }
  }
  return uVar3;
}



uint FUN_0804a2ac(int param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  char *pcVar6;
  bool bVar7;
  char *local_14;
  uint local_10;
  uint local_8;
  
  if ((*(int *)(&DAT_08080184 + param_1 * 0x24) != 2) ||
     (*(int *)(&DAT_08080184 + param_2 * 0x24) != 2)) {
switchD_0804a2fb_default:
    iVar3 = param_1 * 0x24;
    iVar2 = *(int *)(&DAT_08080184 + iVar3);
    if ((iVar2 == 1) || (iVar1 = param_2 * 0x24, *(int *)(&DAT_08080184 + iVar1) == 1)) {
      uVar4 = FUN_0804a200(param_2);
      uVar5 = FUN_0804a200(param_1);
    }
    else if (iVar2 == 3) {
      uVar4 = *(uint *)(&DAT_08080188 + iVar1);
      uVar5 = *(uint *)(&DAT_08080188 + iVar3);
    }
    else if (iVar2 == 5) {
      uVar4 = *(uint *)(&DAT_08080188 + iVar3);
      uVar5 = *(uint *)(&DAT_08080188 + iVar1);
    }
    else {
      uVar4 = *(uint *)(&DAT_08080198 + iVar1);
      uVar5 = *(uint *)(&DAT_08080198 + iVar3);
      local_10 = 0;
      pcVar6 = &DAT_08080188 + iVar1;
      local_14 = &DAT_08080188 + iVar3;
      do {
        if (*local_14 != *pcVar6) {
          return 0;
        }
        pcVar6 = pcVar6 + 1;
        local_14 = local_14 + 1;
        local_10 = local_10 + 1;
      } while (local_10 < 0x10);
    }
    switch(param_3) {
    case 7:
      return (uint)(uVar4 < uVar5);
    case 8:
      return (uint)(uVar4 == uVar5);
    case 9:
      return (uint)(uVar4 <= uVar5);
    case 10:
      return (uint)(uVar5 < uVar4);
    case 0xb:
      return (uint)(uVar4 != uVar5);
    case 0xc:
      return (uint)(uVar5 <= uVar4);
    default:
      return 1;
    }
  }
  switch(param_3) {
  case 7:
    iVar2 = param_2;
    param_2 = param_1;
    break;
  case 8:
    uVar4 = FUN_0804a228((uint *)(&DAT_08080188 + param_2 * 0x24),
                         (uint *)(&DAT_08080188 + param_1 * 0x24),&local_8);
    if (uVar4 == 0) {
      return 0;
    }
    bVar7 = local_8 != 0;
    goto LAB_0804a3a1;
  case 9:
    iVar2 = param_2;
    param_2 = param_1;
    goto LAB_0804a3fc;
  case 10:
    iVar2 = param_1;
    break;
  case 0xb:
    FUN_0804a228((uint *)(&DAT_08080188 + param_2 * 0x24),(uint *)(&DAT_08080188 + param_1 * 0x24),
                 &local_8);
    return (uint)(local_8 == 0);
  case 0xc:
    iVar2 = param_1;
LAB_0804a3fc:
    uVar4 = FUN_0804a228((uint *)(&DAT_08080188 + iVar2 * 0x24),
                         (uint *)(&DAT_08080188 + param_2 * 0x24),&local_8);
    return uVar4;
  default:
    goto switchD_0804a2fb_default;
  }
  uVar5 = 0;
  uVar4 = FUN_0804a228((uint *)(&DAT_08080188 + iVar2 * 0x24),
                       (uint *)(&DAT_08080188 + param_2 * 0x24),&local_8);
  if (uVar4 != 0) {
    bVar7 = local_8 == 0;
LAB_0804a3a1:
    uVar5 = (uint)bVar7;
  }
  return uVar5;
}



void FUN_0804a544(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int local_8;
  
  iVar1 = *(int *)(&DAT_08080188 + param_1 * 0x24);
  iVar2 = *(int *)(&DAT_08080188 + param_2 * 0x24);
  uVar4 = iVar2 + iVar1;
  if (uVar4 < 0x201) {
    FUN_08054424(&local_8,uVar4);
    if (iVar2 != 0) {
      uVar3 = 0;
      do {
        *(undefined1 *)(uVar3 + local_8) =
             *(undefined1 *)(uVar3 + *(int *)(&DAT_0808018c + param_2 * 0x24));
        uVar3 = uVar3 + 1;
      } while (uVar3 <= iVar2 - 1U);
    }
    if (iVar1 != 0) {
      uVar3 = 0;
      do {
        *(undefined1 *)(iVar2 + uVar3 + local_8) =
             *(undefined1 *)(uVar3 + *(int *)(&DAT_0808018c + param_1 * 0x24));
        uVar3 = uVar3 + 1;
      } while (uVar3 <= iVar1 - 1U);
    }
    *(uint *)(&DAT_08080188 + param_2 * 0x24) = uVar4;
    *(int *)(&DAT_0808018c + param_2 * 0x24) = local_8;
  }
  else {
    FUN_08052f1c(4,"String overflow");
  }
  return;
}



void FUN_0804a630(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = *(undefined4 *)(&DAT_08080188 + param_1 * 0x24);
  iVar2 = param_2 * 0x24;
  *(undefined4 *)(&DAT_08080180 + iVar2) = 1;
  *(undefined4 *)(&DAT_080801a0 + iVar2) = 0;
  *(undefined4 *)(&DAT_08080184 + iVar2) = 1;
  *(undefined4 *)(&DAT_08080188 + iVar2) = uVar1;
  return;
}



void FUN_0804a670(void)

{
  return;
}



void FUN_0804a678(int param_1,int param_2)

{
  undefined1 uVar1;
  int iVar2;
  
  uVar1 = (&DAT_08080188)[param_1 * 0x24];
  iVar2 = param_2 * 0x24;
  *(undefined4 *)(&DAT_08080180 + iVar2) = 1;
  *(undefined4 *)(&DAT_080801a0 + iVar2) = 0;
  *(undefined4 *)(&DAT_08080184 + iVar2) = 2;
  FUN_08054424((int *)(&DAT_0808018c + iVar2),1);
  **(undefined1 **)(&DAT_0808018c + iVar2) = uVar1;
  *(undefined4 *)(&DAT_08080188 + iVar2) = 1;
  return;
}



void FUN_0804a6dc(int param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  
  iVar1 = param_2 * 0x24;
  *(undefined4 *)(&DAT_08080180 + iVar1) = 1;
  *(undefined4 *)(&DAT_080801a0 + iVar1) = 0;
  iVar3 = param_1 * 0x24;
  if (*(int *)(&DAT_08080184 + iVar3) == 1) {
    uVar4 = *(uint *)(&DAT_08080188 + iVar3);
    *(undefined4 *)(&DAT_08080184 + iVar1) = 2;
    FUN_08054424((int *)(&DAT_0808018c + iVar1),8);
    *(undefined4 *)(&DAT_08080188 + iVar1) = 8;
    iVar3 = 7;
    do {
      bVar2 = (byte)(uVar4 & 0xf);
      if ((uVar4 & 0xf) < 10) {
        bVar2 = bVar2 | 0x30;
      }
      else {
        bVar2 = bVar2 + 0x37;
      }
      *(byte *)(iVar3 + *(int *)(&DAT_0808018c + iVar1)) = bVar2;
      uVar4 = uVar4 >> 4;
      iVar3 = iVar3 + -1;
    } while (-1 < iVar3);
  }
  else if (*(int *)(&DAT_08080184 + iVar3) == 5) {
    iVar3 = *(int *)(&DAT_08080188 + iVar3);
    *(undefined4 *)(&DAT_08080184 + iVar1) = 2;
    FUN_08054424((int *)(&DAT_0808018c + iVar1),1);
    *(undefined4 *)(&DAT_08080188 + iVar1) = 1;
    if (iVar3 == 0) {
      **(undefined1 **)(&DAT_0808018c + iVar1) = 0x46;
    }
    else {
      **(undefined1 **)(&DAT_0808018c + iVar1) = 0x54;
    }
  }
  return;
}



void FUN_0804a7c0(void *param_1,size_t param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_0805eeb8(param_1,param_2);
  if (DAT_0807b2b0 != 0) {
    FUN_0805ee14(DAT_0807b2b4);
  }
  DAT_0807b2b4 = puVar1;
  DAT_0807b2b0 = 1;
  return;
}



uint * FUN_0804a800(void)

{
  uint *puVar1;
  
  puVar1 = FUN_0805eddc(0x21c);
  *puVar1 = 0;
  puVar1[1] = 0;
  puVar1[2] = 0;
  puVar1[3] = 0;
  puVar1[4] = DAT_0807b2ac;
  puVar1[5] = 0;
  puVar1[6] = DAT_0808276c;
  return puVar1;
}



uint * FUN_0804a848(void)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar1 = FUN_0805eddc(0x18);
  *puVar1 = 0;
  puVar2 = FUN_0805ee84(DAT_0807b2b4);
  puVar1[1] = (uint)puVar2;
  puVar1[5] = 0;
  puVar1[3] = DAT_0808276c;
  DAT_0807b2ac = 0;
  return puVar1;
}



uint * FUN_0804a88c(char *param_1)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar1 = FUN_0805eddc(0x10);
  *puVar1 = 0;
  puVar2 = FUN_0805ee84(param_1);
  puVar1[1] = (uint)puVar2;
  puVar1[3] = 0;
  puVar1[2] = 0;
  DAT_0807b288 = 0;
  DAT_0807b284 = 0;
  return puVar1;
}



void FUN_0804a8d8(uint *param_1)

{
  uint *puVar1;
  
  while (param_1 != (uint *)0x0) {
    puVar1 = (uint *)*param_1;
    FUN_0805ee14(param_1);
    param_1 = puVar1;
  }
  return;
}



void FUN_0804a8fc(uint *param_1)

{
  uint *puVar1;
  
  while (param_1 != (uint *)0x0) {
    puVar1 = (uint *)*param_1;
    FUN_0805ee14((uint *)param_1[1]);
    FUN_0804a8d8((uint *)param_1[3]);
    FUN_0805ee14(param_1);
    param_1 = puVar1;
  }
  return;
}



void FUN_0804a930(void)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = DAT_0807b28c;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)*puVar2;
    FUN_0805ee14((uint *)puVar2[1]);
    FUN_0804a8fc((uint *)puVar2[5]);
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  return;
}



void FUN_0804a968(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = DAT_0807b288;
  if ((DAT_0807b298 != 0) && (DAT_0807b284 != 0)) {
    *(undefined4 *)(DAT_0807b288 + 0xc) = param_1;
    uVar2 = DAT_0807b2ac;
    *(undefined4 *)(iVar1 + 0x14) = DAT_0807b2ac;
    *(undefined4 *)(DAT_0807b290 + 0x10) = uVar2;
  }
  return;
}



void FUN_0804a99c(int param_1,uint param_2)

{
  uint uVar1;
  uint *puVar2;
  uint *puVar3;
  
  if (DAT_0807b298 != 0) {
    if (DAT_0807b284 == (uint *)0x0) {
      puVar2 = FUN_0804a800();
      DAT_0807b284 = puVar2;
      DAT_0807b288 = puVar2;
      *(uint **)(DAT_0807b298 + 0xc) = puVar2;
    }
    else {
      puVar2 = DAT_0807b284;
      if (DAT_0807b288[1] == 0x40) {
        FUN_0804a968(param_2);
        puVar3 = FUN_0804a800();
        *DAT_0807b288 = (uint)puVar3;
        puVar2 = DAT_0807b284;
        DAT_0807b288 = puVar3;
      }
    }
    puVar3 = DAT_0807b288;
    if (puVar2[2] == 0) {
      puVar2[2] = param_2;
      DAT_0807b284[3] = param_2;
    }
    else {
      uVar1 = DAT_0807b288[1];
      DAT_0807b288[1] = DAT_0807b288[1] + 1;
      puVar3[uVar1 * 2 + 7] = param_2;
      DAT_0807b288[uVar1 * 2 + 8] = DAT_0807b2ac;
    }
    DAT_0807b2ac = DAT_0807b2ac + param_1;
  }
  return;
}



void FUN_0804aa4c(char *param_1,undefined4 param_2)

{
  uint *puVar1;
  
  if (DAT_0807b290 != 0) {
    if (DAT_0807fee0 - 2U < 2) {
      param_1 = &DAT_0807ff20;
    }
    FUN_0804a968(param_2);
    puVar1 = FUN_0804a88c(param_1);
    DAT_0807b298 = puVar1;
    *DAT_0807b29c = (uint)puVar1;
    DAT_0807b29c = puVar1;
  }
  return;
}



void FUN_0804aa98(char *param_1)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  uint *puVar4;
  
  puVar4 = (uint *)0x0;
  if (DAT_0807b2a0 != (uint *)0x0) {
    puVar2 = DAT_0807b2a0;
    puVar4 = (uint *)0x0;
    do {
      puVar3 = puVar2;
      iVar1 = strcmp((char *)puVar3[1],param_1);
      puVar2 = puVar3;
      if (iVar1 == 0) break;
      puVar2 = (uint *)*puVar3;
      puVar4 = puVar3;
    } while (puVar2 != (uint *)0x0);
    if (puVar2 != (uint *)0x0) {
      return;
    }
  }
  puVar2 = FUN_0805eddc(8);
  *puVar2 = 0;
  puVar3 = FUN_0805ee84(param_1);
  puVar2[1] = (uint)puVar3;
  if (puVar4 != (uint *)0x0) {
    *puVar4 = (uint)puVar2;
    puVar2 = DAT_0807b2a0;
  }
  DAT_0807b2a0 = puVar2;
  return;
}



void FUN_0804aafc(void)

{
  uint *puVar1;
  
  puVar1 = FUN_0804a848();
  DAT_0807b290 = puVar1;
  *DAT_0807b294 = (uint)puVar1;
  DAT_0807b298 = 0;
  DAT_0807b29c = puVar1 + 5;
  DAT_0807b288 = 0;
  DAT_0807b284 = 0;
  DAT_0807b294 = puVar1;
  puVar1[2] = 0;
  return;
}



void FUN_0804ab4c(undefined4 param_1)

{
  if ((DAT_0807b28c != 0) && (*(int *)(DAT_0807b290 + 8) == 0)) {
    FUN_0804a968(param_1);
    *(undefined4 *)(DAT_0807b290 + 8) = 1;
  }
  return;
}



uint FUN_0804ab7c(uint *param_1,int *param_2)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint *local_20;
  uint *local_1c;
  uint *local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
  iVar6 = 0;
  local_8 = 0;
  if (param_1 != (uint *)0x0) {
    iVar6 = 0;
    do {
      uVar3 = param_1[1];
      local_10 = param_1[2];
      local_14 = param_1[4];
      iVar6 = (iVar6 + 3U & 0xfffffffc) + 0x14;
      local_c = 0;
      iVar5 = local_8 + 1;
      if (uVar3 != 0) {
        local_18 = param_1 + 8;
        local_1c = param_1 + 9;
        local_20 = param_1 + 7;
        uVar7 = uVar3;
        do {
          uVar7 = uVar7 - 1;
          uVar4 = *local_20 - local_10;
          uVar1 = *local_18 - local_14;
          if ((uVar4 != 0) || (uVar1 != 0)) {
            if ((0xffff < uVar4) || (0x10000 < uVar1)) {
              puVar2 = FUN_0805eddc(0x21c);
              *puVar2 = *param_1;
              *param_1 = (uint)puVar2;
              puVar2[2] = *local_20;
              puVar2[4] = *local_18;
              puVar2[3] = param_1[3];
              puVar2[5] = param_1[5];
              puVar2[1] = uVar7;
              puVar2[6] = param_1[6];
              if (uVar7 != 0) {
                memcpy(puVar2 + 7,local_1c,uVar7 * 8);
              }
              param_1[1] = local_c;
              param_1[3] = local_10;
              param_1[5] = *local_18;
              iVar5 = local_8 + 2;
              break;
            }
            if (((int)uVar4 < 0x40) && (uVar1 < 0x100)) {
              iVar6 = iVar6 + 2;
            }
            else {
              iVar6 = iVar6 + 6;
            }
            local_10 = local_10 + uVar4;
            local_14 = local_14 + uVar1;
          }
          local_18 = local_18 + 2;
          local_1c = local_1c + 2;
          local_20 = local_20 + 2;
          local_c = local_c + 1;
        } while (local_c < uVar3);
      }
      local_8 = iVar5;
      iVar5 = param_1[3] - local_10;
      uVar3 = param_1[5] - local_14;
      if ((((param_1[3] != local_10) || (param_1[5] != local_14)) && (iVar5 < 0x10001)) &&
         (uVar3 < 0x10001)) {
        if ((iVar5 < 0x40) && (uVar3 < 0x100)) {
          iVar6 = iVar6 + 2;
        }
        else {
          iVar6 = iVar6 + 6;
        }
      }
      param_1 = (uint *)*param_1;
    } while (param_1 != (uint *)0x0);
  }
  *param_2 = local_8;
  return iVar6 + 3U & 0xfffffffc;
}



int FUN_0804ad14(int param_1)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  int local_8;
  
  uVar3 = 0xffffffff;
  pcVar4 = *(char **)(param_1 + 4);
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  uVar2 = FUN_0804ab7c(*(uint **)(param_1 + 0xc),&local_8);
  return uVar2 + (~uVar3 + 0xb & 0xfffffffc) + 4;
}



int FUN_0804ad50(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 4;
  for (; param_1 != (undefined4 *)0x0; param_1 = (undefined4 *)*param_1) {
    iVar1 = FUN_0804ad14((int)param_1);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2 + 4;
}



uint FUN_0804ad7c(int param_1)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0xffffffff;
  pcVar3 = *(char **)(param_1 + 4);
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  return ~uVar2 + 0x23 & 0xfffffffc;
}



int FUN_0804ada0(int param_1)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_0804ad7c(param_1);
  iVar2 = FUN_0804ad50(*(undefined4 **)(param_1 + 0x14));
  return iVar2 + uVar1;
}



int FUN_0804adc4(void)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  for (puVar1 = DAT_0807b28c; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
    iVar2 = FUN_0804ada0((int)puVar1);
    iVar3 = iVar3 + iVar2;
  }
  return iVar3;
}



uint FUN_0804adf0(FILE *param_1,uint param_2)

{
  for (; (param_2 & 3) != 0; param_2 = param_2 + 1) {
    fputc(0,param_1);
  }
  return param_2;
}



int FUN_0804ae1c(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 local_14;
  
  local_14 = *(int *)(param_1 + 8);
  iVar5 = *(int *)(param_1 + 0x10);
  iVar4 = 0;
  uVar2 = 0;
  if (*(uint *)(param_1 + 4) != 0) {
    do {
      uVar3 = *(int *)(uVar2 * 8 + param_1 + 0x1c) - local_14;
      uVar1 = *(int *)(uVar2 * 8 + param_1 + 0x20) - iVar5;
      if ((uVar3 != 0) || (uVar1 != 0)) {
        if ((uVar3 < 0x40) && (uVar1 < 0x100)) {
          iVar4 = iVar4 + 2;
        }
        else {
          iVar4 = iVar4 + 6;
        }
        local_14 = local_14 + uVar3;
        iVar5 = iVar5 + uVar1;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < *(uint *)(param_1 + 4));
  }
  uVar1 = *(int *)(param_1 + 0xc) - local_14;
  uVar2 = *(int *)(param_1 + 0x14) - iVar5;
  if ((((*(int *)(param_1 + 0xc) != local_14) || (*(int *)(param_1 + 0x14) != iVar5)) &&
      (uVar1 < 0x10001)) && (uVar2 < 0x10001)) {
    if ((uVar1 < 0x40) && (uVar2 < 0x100)) {
      iVar4 = iVar4 + 2;
    }
    else {
      iVar4 = iVar4 + 6;
    }
  }
  return iVar4;
}



int FUN_0804aee0(FILE *param_1,undefined1 param_2,undefined1 param_3,int param_4)

{
  undefined1 local_6;
  undefined1 local_5;
  
  local_6 = param_2;
  local_5 = param_3;
  fwrite(&local_6,1,2,param_1);
  return param_4 + 2;
}



int FUN_0804af10(FILE *param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  undefined1 uVar1;
  undefined1 uVar2;
  undefined1 local_c;
  undefined1 local_b;
  undefined1 local_a;
  undefined1 local_9;
  undefined1 local_8;
  undefined1 local_7;
  
  local_b = 0;
  local_c = 0;
  uVar1 = (undefined1)((uint)param_3 >> 8);
  local_a = (undefined1)param_3;
  local_8 = (undefined1)param_2;
  uVar2 = (undefined1)((uint)param_2 >> 8);
  local_7 = uVar2;
  local_9 = uVar1;
  if (DAT_0808269c != 0) {
    local_7 = local_8;
    local_8 = uVar2;
    local_9 = local_a;
    local_a = uVar1;
  }
  fwrite(&local_c,1,6,param_1);
  return param_4 + 6;
}



uint FUN_0804af94(FILE *param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int local_30;
  int local_2c;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  
  for (; param_2 != (undefined4 *)0x0; param_2 = (undefined4 *)*param_2) {
    iVar1 = FUN_0804ae1c((int)param_2);
    local_1c = FUN_0806d16c(iVar1 + 0x14);
    local_18 = FUN_0806d16c(param_2[2]);
    local_14 = FUN_0806d16c(param_2[3]);
    local_10 = FUN_0806d16c(param_2[4]);
    local_c = FUN_0806d16c(param_2[5] - param_2[4]);
    fwrite(&local_1c,1,0x14,param_1);
    FUN_080514cc(param_3 + 0xc,param_2[6] + 0x81ffffff,0);
    param_3 = param_3 + 0x14;
    uVar3 = param_2[1];
    local_2c = param_2[2];
    local_30 = param_2[4];
    uVar5 = 0;
    if (uVar3 != 0) {
      do {
        uVar4 = param_2[uVar5 * 2 + 7] - local_2c;
        uVar2 = param_2[uVar5 * 2 + 8] - local_30;
        if ((uVar4 != 0) || (uVar2 != 0)) {
          if ((uVar4 < 0x40) && (uVar2 < 0x100)) {
            param_3 = FUN_0804aee0(param_1,(char)uVar2,(char)uVar4,param_3);
          }
          else {
            param_3 = FUN_0804af10(param_1,uVar2,uVar4,param_3);
          }
          local_2c = local_2c + uVar4;
          local_30 = local_30 + uVar2;
        }
        uVar5 = uVar5 + 1;
      } while (uVar5 < uVar3);
    }
    uVar5 = param_2[3] - local_2c;
    uVar3 = param_2[5] - local_30;
    if ((((uVar5 != 0) || (uVar3 != 0)) && (uVar5 < 0x10001)) && (uVar3 < 0x10001)) {
      if ((uVar5 < 0x40) && (uVar3 < 0x100)) {
        param_3 = FUN_0804aee0(param_1,(char)uVar3,(char)uVar5,param_3);
      }
      else {
        param_3 = FUN_0804af10(param_1,uVar3,uVar5,param_3);
      }
    }
    param_3 = FUN_0804adf0(param_1,param_3);
  }
  return param_3;
}



undefined8 __regparm2
FUN_0804b14c(undefined4 param_1,uint param_2,FILE *param_3,int param_4,uint param_5)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  char *pcVar5;
  uint local_14;
  uint local_10;
  uint local_c;
  undefined1 local_8;
  
  if (param_4 != 0) {
    uVar3 = 0xffffffff;
    pcVar5 = *(char **)(param_4 + 4);
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    uVar3 = ~uVar3;
    iVar4 = (uVar3 + 0xb & 0xfffffffc) + 4;
    uVar2 = FUN_0804ab7c(*(uint **)(param_4 + 0xc),(int *)&local_14);
    local_10 = FUN_0806d16c(uVar2 + iVar4);
    local_c = FUN_0806d16c(*(uint *)(param_4 + 8));
    local_8 = (undefined1)(uVar3 - 1);
    fwrite(&local_10,1,9,param_3);
    fwrite(*(void **)(param_4 + 4),1,uVar3 - 1,param_3);
    for (; (uVar3 & 3) != 0; uVar3 = uVar3 + 1) {
      fputc(0,param_3);
    }
    local_14 = FUN_0806d16c(local_14);
    fwrite(&local_14,4,1,param_3);
    param_5 = FUN_0804af94(param_3,*(undefined4 **)(param_4 + 0xc),iVar4 + param_5);
    param_2 = param_5;
  }
  return CONCAT44(param_2,param_5);
}



int FUN_0804b244(FILE *param_1,undefined4 *param_2,int param_3)

{
  uint uVar1;
  size_t sVar2;
  undefined4 extraout_EDX;
  undefined8 uVar3;
  undefined4 local_18;
  uint local_14 [4];
  
  uVar1 = FUN_0804ad50(param_2);
  if (uVar1 < 0x10001) {
    uVar1 = uVar1 << 0x10 | 10;
  }
  else {
    uVar1 = 10;
  }
  local_14[0] = FUN_0806d16c(uVar1);
  sVar2 = fwrite(local_14,4,1,param_1);
  uVar3 = CONCAT44(extraout_EDX,sVar2);
  uVar1 = param_3 + 4;
  for (; param_2 != (undefined4 *)0x0; param_2 = (undefined4 *)*param_2) {
    uVar3 = FUN_0804b14c((int)uVar3,(uint)((ulonglong)uVar3 >> 0x20),param_1,(int)param_2,uVar1);
    uVar1 = (uint)uVar3;
  }
  local_18 = 0;
  fwrite(&local_18,4,1,param_1);
  return uVar1 + 4;
}



int FUN_0804b2cc(FILE *param_1,int param_2,int param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  char *pcVar7;
  uint *puVar8;
  uint local_28;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_21;
  undefined4 local_20;
  uint local_18;
  uint local_10;
  uint local_c;
  undefined1 local_8;
  
  uVar3 = FUN_0804ad7c(param_2);
  uVar5 = 0xffffffff;
  pcVar7 = *(char **)(param_2 + 4);
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar7 + 1;
  } while (cVar1 != '\0');
  uVar5 = ~uVar5;
  iVar2 = *(int *)(param_2 + 0xc);
  puVar8 = &local_28;
  for (iVar6 = 9; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  local_28 = FUN_0806d16c(uVar3 << 0x10 | 1);
  local_24 = 4;
  local_23 = 1;
  local_21 = 3;
  local_20 = 0;
  local_18 = FUN_0806d16c(*(uint *)(param_2 + 0x10));
  local_10 = FUN_0806d16c(uVar3);
  uVar4 = FUN_0804ada0(param_2);
  local_c = FUN_0806d16c(uVar4);
  local_8 = (undefined1)(uVar5 - 1);
  fwrite(&local_28,1,0x21,param_1);
  fwrite(*(void **)(param_2 + 4),1,uVar5 - 1,param_1);
  for (; (uVar5 & 3) != 0; uVar5 = uVar5 + 1) {
    fputc(0,param_1);
  }
  iVar6 = FUN_0804b244(param_1,*(undefined4 **)(param_2 + 0x14),param_3 + uVar3);
  FUN_080514cc(param_3 + 8,iVar2 + 0x81ffffff,0);
  return iVar6;
}



void FUN_0804b3f8(void)

{
  uint *puVar1;
  int iVar2;
  
  puVar1 = FUN_0805eddc(0x2c);
  DAT_0808276c = DAT_0808276c + 1;
  FUN_080588c0((int *)puVar1,"DEBUG_AREA");
  *(byte *)((int)puVar1 + 0xb) = *(byte *)((int)puVar1 + 0xb) | 0x80;
  FUN_0805202c((int *)puVar1,2,0xa000);
  iVar2 = FUN_0804adc4();
  *(int *)(DAT_0808014c + 8) = iVar2;
  return;
}



void FUN_0804b43c(FILE *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = DAT_0807b28c;
  iVar2 = 0;
  FUN_0805202c((int *)0x0,0,0);
  FUN_08051240();
  for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
    iVar2 = FUN_0804b2cc(param_1,(int)puVar1,iVar2);
  }
  FUN_08051454();
  return;
}



char * FUN_0804b484(char *param_1)

{
  sprintf(param_1,"%s%s vsn %s%s%c","ARM AOF"," Macro Assembler","2.50 (ARM Ltd SDT2.51)","",'\0');
  return param_1;
}



undefined4 FUN_0804b4b4(uint param_1)

{
  undefined4 uVar1;
  
  switch(param_1 & 0xf) {
  case 1:
  case 2:
  case 4:
  case 6:
    uVar1 = 6;
    break;
  case 3:
  case 5:
    uVar1 = 4;
    break;
  case 7:
    uVar1 = 10;
    break;
  default:
    uVar1 = 0;
  }
  return uVar1;
}



int FUN_0804b4ec(char *param_1)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = 0xffffffff;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *param_1;
    param_1 = param_1 + 1;
  } while (cVar1 != '\0');
  return ~uVar2 + 2;
}



int FUN_0804b50c(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char local_104 [256];
  
  iVar1 = FUN_0804b4b4(0x12);
  iVar2 = FUN_0804b4ec(*(char **)(param_1 + 4));
  iVar2 = iVar1 + 6 + iVar2;
  if (*(int *)(param_1 + 0xc) != 0) {
    iVar1 = FUN_0804b4b4(0x111);
    iVar3 = FUN_0804b4b4(0x121);
    iVar2 = iVar2 + iVar3 + iVar1;
  }
  iVar1 = FUN_0804b4b4(0x106);
  pcVar4 = FUN_0804b484(local_104);
  iVar3 = FUN_0804b4ec(pcVar4);
  return iVar3 + 4 + iVar2 + iVar1;
}



int FUN_0804b580(FILE *param_1,char *param_2,int param_3)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0xffffffff;
  pcVar3 = param_2;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  fwrite(param_2,1,~uVar2,param_1);
  return ~uVar2 + param_3;
}



int FUN_0804b5b8(FILE *param_1,undefined1 param_2,int param_3)

{
  undefined1 local_5;
  
  local_5 = param_2;
  fwrite(&local_5,1,1,param_1);
  return param_3 + 1;
}



int FUN_0804b5e0(FILE *param_1,void *param_2,size_t param_3,int param_4)

{
  fwrite(param_2,1,param_3,param_1);
  return param_3 + param_4;
}



int FUN_0804b604(FILE *param_1,uint param_2,int param_3)

{
  uint uVar1;
  undefined2 local_6;
  
  uVar1 = FUN_0806d1a4(param_2);
  local_6 = (undefined2)uVar1;
  fwrite(&local_6,1,2,param_1);
  return param_3 + 2;
}



int FUN_0804b638(FILE *param_1,uint param_2,int param_3)

{
  int iVar1;
  
  iVar1 = param_3;
  param_2 = FUN_0806d16c(param_2);
  fwrite(&param_2,1,4,param_1);
  return iVar1 + 4;
}



void FUN_0804b668(FILE *param_1,uint param_2,int param_3,uint param_4)

{
  FUN_080514cc(param_4,param_3 + 0x81ffffff,0);
  FUN_0804b638(param_1,param_2,param_4);
  return;
}



undefined4 FUN_0804b69c(uint param_1)

{
  undefined4 uVar1;
  
  if (param_1 < 0x80) {
    uVar1 = 1;
  }
  else if (param_1 < 0x4000) {
    uVar1 = 2;
  }
  else if (param_1 < 0x200000) {
    uVar1 = 3;
  }
  else if (param_1 < 0x10000000) {
    uVar1 = 4;
  }
  else {
    uVar1 = 5;
  }
  return uVar1;
}



int FUN_0804b6e8(uint param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = 1;
  do {
    uVar1 = (int)param_1 >> 7;
    if ((param_1 & 0x40) == 0) {
      if (uVar1 == 0) {
        return iVar2;
      }
    }
    else if (uVar1 == 0xffffffff) {
      return iVar2;
    }
    iVar2 = iVar2 + 1;
    param_1 = uVar1;
  } while( true );
}



void FUN_0804b718(FILE *param_1,uint param_2,int param_3)

{
  byte *pbVar1;
  int iVar2;
  byte local_c [8];
  
  iVar2 = 0;
  local_c[0] = (byte)param_2 & 0x7f;
  while (param_2 = param_2 >> 7, param_2 != 0) {
    pbVar1 = local_c + iVar2;
    *pbVar1 = *pbVar1 | 0x80;
    iVar2 = iVar2 + 1;
    local_c[iVar2] = (byte)param_2 & 0x7f;
  }
  FUN_0804b5e0(param_1,local_c,iVar2 + 1,param_3);
  return;
}



void FUN_0804b760(FILE *param_1,int param_2,int param_3)

{
  byte *pbVar1;
  int iVar2;
  byte local_c [8];
  
  iVar2 = 0;
  do {
    local_c[iVar2] = (byte)param_2 & 0x7f;
    param_2 = param_2 >> 7;
    if ((local_c[iVar2] & 0x40) == 0) {
      if (param_2 == 0) {
LAB_0804b795:
        FUN_0804b5e0(param_1,local_c,iVar2 + 1,param_3);
        return;
      }
    }
    else if (param_2 == -1) goto LAB_0804b795;
    pbVar1 = local_c + iVar2;
    *pbVar1 = *pbVar1 | 0x80;
    iVar2 = iVar2 + 1;
  } while( true );
}



void FUN_0804b7ac(FILE *param_1,uint param_2,int param_3,char *param_4)

{
  int iVar1;
  
  iVar1 = FUN_0804b604(param_1,param_2,param_3);
  FUN_0804b580(param_1,param_4,iVar1);
  return;
}



void FUN_0804b7d4(FILE *param_1,uint param_2,int param_3,uint param_4,int param_5)

{
  uint uVar1;
  
  uVar1 = FUN_0804b604(param_1,param_2,param_3);
  FUN_0804b668(param_1,param_4,param_5,uVar1);
  return;
}



void FUN_0804b800(FILE *param_1,int param_2)

{
  uint *puVar1;
  uint uVar2;
  int iVar3;
  char *pcVar4;
  int *piVar5;
  uint local_10c;
  undefined4 local_108;
  char local_104 [256];
  
  uVar2 = FUN_0804b50c(param_2);
  if ((uVar2 & 3) == 0) {
    local_10c = 0;
  }
  else {
    local_10c = 8 - (uVar2 & 3);
  }
  iVar3 = FUN_0804b638(param_1,uVar2 - 4,0);
  piVar5 = *(int **)(param_2 + 0xc);
  iVar3 = FUN_0804b604(param_1,0x11,iVar3);
  iVar3 = FUN_0804b7d4(param_1,0x12,iVar3,local_10c + uVar2,DAT_0807b2c0);
  iVar3 = FUN_0804b7ac(param_1,0x38,iVar3,*(char **)(param_2 + 4));
  if (piVar5 != (int *)0x0) {
    puVar1 = (uint *)(piVar5 + 4);
    do {
      uVar2 = piVar5[5];
      piVar5 = (int *)*piVar5;
    } while (piVar5 != (int *)0x0);
    iVar3 = FUN_0804b7d4(param_1,0x111,iVar3,*puVar1,*(int *)(*(int *)(param_2 + 0xc) + 0x18));
    iVar3 = FUN_0804b7d4(param_1,0x121,iVar3,uVar2,*(int *)(*(int *)(param_2 + 0xc) + 0x18));
  }
  iVar3 = FUN_0804b7d4(param_1,0x106,iVar3,0,DAT_0807b2c0 + 1);
  pcVar4 = FUN_0804b484(local_104);
  FUN_0804b7ac(param_1,600,iVar3,pcVar4);
  iVar3 = FUN_0804b638(param_1,4,0);
  if (local_10c != 0) {
    local_108 = 0;
    FUN_0804b638(param_1,local_10c,iVar3);
    fwrite(&local_108,1,local_10c - 4,param_1);
  }
  return;
}



int FUN_0804b978(int param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint local_10;
  int local_8;
  
  local_8 = -1;
  if (*(int **)(param_1 + 0xc) == (int *)0x0) {
    iVar1 = 0;
  }
  else {
    iVar1 = 8;
    piVar3 = *(int **)(param_1 + 0xc);
    iVar5 = -1;
    do {
      piVar2 = piVar3;
      iVar6 = piVar2[2];
      if ((iVar6 != 0) && ((iVar6 != iVar5 || (piVar2[4] != local_8)))) {
        iVar1 = iVar1 + 10;
      }
      local_8 = piVar2[4];
      local_10 = 0;
      if (piVar2[1] != 0) {
        piVar3 = piVar2 + 8;
        piVar4 = piVar2 + 7;
        do {
          if ((*piVar4 != iVar6) || (*piVar3 != local_8)) {
            iVar1 = iVar1 + 10;
          }
          iVar6 = *piVar4;
          local_8 = *piVar3;
          piVar3 = piVar3 + 2;
          piVar4 = piVar4 + 2;
          local_10 = local_10 + 1;
        } while (local_10 < (uint)piVar2[1]);
      }
      piVar3 = (int *)*piVar2;
      iVar5 = iVar6;
    } while ((int *)*piVar2 != (int *)0x0);
    piVar2[3] = 0;
    iVar1 = iVar1 + 10;
  }
  return iVar1;
}



void FUN_0804ba30(FILE *param_1,uint param_2,uint param_3)

{
  FUN_0804b638(param_1,param_2,0);
  FUN_0804b604(param_1,0xffff,0);
  FUN_0804b638(param_1,param_3,0);
  return;
}



void FUN_0804ba64(FILE *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  uint *puVar6;
  int *piVar7;
  uint local_18;
  uint local_10;
  int local_c;
  
  uVar3 = FUN_0804b978(param_2);
  piVar7 = *(int **)(param_2 + 0xc);
  local_c = -1;
  local_10 = 0xffffffff;
  if (piVar7 != (int *)0x0) {
    uVar4 = FUN_0804b638(param_1,uVar3 + (uVar3 & 2),0);
    FUN_0804b668(param_1,piVar7[4],piVar7[6],uVar4);
    iVar1 = piVar7[4];
    do {
      uVar4 = piVar7[1];
      uVar2 = piVar7[2];
      if ((uVar2 != 0) && ((uVar2 != local_10 || (piVar7[4] != local_c)))) {
        FUN_0804ba30(param_1,uVar2,piVar7[4] - iVar1);
      }
      local_18 = 0;
      if (uVar4 != 0) {
        piVar5 = piVar7 + 8;
        puVar6 = (uint *)(piVar7 + 7);
        do {
          if ((*puVar6 != local_10) || (*piVar5 != local_c)) {
            FUN_0804ba30(param_1,*puVar6,*piVar5 - iVar1);
          }
          local_10 = *puVar6;
          local_c = *piVar5;
          piVar5 = piVar5 + 2;
          puVar6 = puVar6 + 2;
          local_18 = local_18 + 1;
        } while (local_18 < uVar4);
      }
      piVar5 = (int *)*piVar7;
      if (piVar5 == (int *)0x0) {
        FUN_0804ba30(param_1,piVar7[3],piVar7[5] - iVar1);
        local_10 = piVar7[3];
        local_c = piVar7[5];
        piVar5 = (int *)*piVar7;
      }
      piVar7 = piVar5;
    } while (piVar5 != (int *)0x0);
    if ((uVar3 & 2) != 0) {
      FUN_0804b604(param_1,0,0);
    }
  }
  return;
}



void FUN_0804bb8c(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  uint *puVar3;
  uint uVar4;
  
  DAT_0807b2c0 = DAT_0808276c + 1;
  for (puVar2 = DAT_0807b28c; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
    for (puVar1 = (undefined4 *)puVar2[5]; puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      puVar3 = FUN_0805eddc(0x2c);
      DAT_0808276c = DAT_0808276c + 1;
      FUN_080588c0((int *)puVar3,".debug");
      *(byte *)((int)puVar3 + 0xb) = *(byte *)((int)puVar3 + 0xb) | 0x80;
      FUN_0805202c((int *)puVar3,2,0xa000);
      uVar4 = FUN_0804b50c((int)puVar1);
      if ((uVar4 & 3) != 0) {
        uVar4 = (uVar4 + 8) - (uVar4 & 3);
      }
      *(uint *)(DAT_0808014c + 8) = uVar4;
      puVar3 = FUN_0805eddc(0x2c);
      DAT_0808276c = DAT_0808276c + 1;
      FUN_080588c0((int *)puVar3,".line");
      *(byte *)((int)puVar3 + 0xb) = *(byte *)((int)puVar3 + 0xb) | 0x80;
      FUN_0805202c((int *)puVar3,2,0xa000);
      uVar4 = FUN_0804b978((int)puVar1);
      if ((uVar4 & 2) != 0) {
        uVar4 = uVar4 + 2;
      }
      *(uint *)(DAT_0808014c + 8) = uVar4;
    }
  }
  return;
}



void FUN_0804bc6c(FILE *param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  for (puVar2 = DAT_0807b28c; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
    for (puVar1 = (undefined4 *)puVar2[5]; puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      FUN_0805202c((int *)0x0,0,0);
      FUN_08051240();
      FUN_0804b800(param_1,(int)puVar1);
      FUN_08051454();
      FUN_0805202c((int *)0x0,0,0);
      FUN_08051240();
      FUN_0804ba64(param_1,(int)puVar1);
      FUN_08051454();
      DAT_0807b2c0 = DAT_0807b2c0 + 2;
    }
  }
  return;
}



void FUN_0804bce0(undefined4 *param_1,int *param_2,int *param_3,int *param_4,int *param_5)

{
  undefined4 *puVar1;
  int *piVar2;
  bool bVar3;
  int iVar4;
  int *piVar5;
  
  *param_2 = 0;
  iVar4 = 0;
  for (; param_1 != (undefined4 *)0x0; param_1 = (undefined4 *)*param_1) {
    bVar3 = false;
    for (puVar1 = (undefined4 *)param_1[5]; puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      piVar2 = (int *)puVar1[3];
      if (piVar2 != (int *)0x0) {
        if (!bVar3) {
          *param_2 = iVar4 + 1;
          bVar3 = true;
          *param_3 = piVar2[6];
          *param_4 = piVar2[4];
          iVar4 = *param_2;
        }
        if (iVar4 == 1) {
          do {
            piVar5 = piVar2;
            piVar2 = (int *)*piVar5;
          } while (piVar2 != (int *)0x0);
          *param_5 = piVar5[5];
          iVar4 = *param_2;
        }
      }
    }
  }
  if (iVar4 != 1) {
    *param_4 = 0;
    *param_5 = 0;
    *param_3 = 0;
  }
  return;
}



uint FUN_0804bd88(char *param_1,int param_2)

{
  char cVar1;
  undefined4 *puVar2;
  int iVar3;
  uint *puVar4;
  uint *puVar5;
  char *pcVar6;
  uint uVar7;
  uint local_10;
  undefined4 *local_c;
  uint *local_8;
  
  local_8 = (uint *)0x0;
  puVar4 = DAT_0807b2bc;
  if (DAT_0807b2bc != (uint *)0x0) {
    do {
      puVar5 = puVar4;
      iVar3 = strcmp(param_1,(char *)puVar5[5]);
      puVar4 = puVar5;
      if (iVar3 == 0) break;
      puVar4 = (uint *)*puVar5;
      local_8 = puVar5;
    } while (puVar4 != (uint *)0x0);
    if (puVar4 != (uint *)0x0) goto LAB_0804beaa;
  }
  if (param_2 == 0) {
    FUN_08052f1c(5,"Filename \"%s\" missing from filename list");
    FUN_080615f0(1);
  }
  else {
    local_c = (undefined4 *)0x0;
    local_10 = 0;
    puVar4 = FUN_0805eddc(0x18);
    *puVar4 = 0;
    puVar5 = FUN_0805ee84(param_1);
    puVar4[5] = (uint)puVar5;
    for (puVar2 = DAT_0807b2b8; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      pcVar6 = strstr(param_1,(char *)puVar2[2]);
      if (pcVar6 == param_1) {
        uVar7 = 0xffffffff;
        pcVar6 = (char *)puVar2[2];
        do {
          if (uVar7 == 0) break;
          uVar7 = uVar7 - 1;
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar1 != '\0');
        if (local_10 < ~uVar7 - 1) {
          uVar7 = 0xffffffff;
          pcVar6 = (char *)puVar2[2];
          do {
            if (uVar7 == 0) break;
            uVar7 = uVar7 - 1;
            cVar1 = *pcVar6;
            pcVar6 = pcVar6 + 1;
          } while (cVar1 != '\0');
          local_10 = ~uVar7 - 1;
          local_c = puVar2;
        }
      }
    }
    puVar4[2] = (uint)local_c;
    puVar4[3] = 0;
    puVar4[4] = 0;
    if (local_8 == (uint *)0x0) {
      DAT_0807b2bc = puVar4;
      puVar4[1] = 1;
    }
    else {
      *local_8 = (uint)puVar4;
      puVar4[1] = local_8[1] + 1;
    }
  }
LAB_0804beaa:
  return puVar4[1];
}



void FUN_0804beb8(void)

{
  char cVar1;
  uint *puVar2;
  uint *puVar3;
  int iVar4;
  int *piVar5;
  uint *puVar6;
  char *pcVar7;
  uint local_8;
  
  local_8 = 1;
  DAT_0807b2b8 = (uint *)0x0;
  if (DAT_0807b2a0 != (int *)0x0) {
    piVar5 = DAT_0807b2a0;
    puVar6 = (uint *)0x0;
    do {
      iVar4 = -1;
      pcVar7 = (char *)piVar5[1];
      do {
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar7 + 1;
      } while (cVar1 != '\0');
      puVar2 = puVar6;
      puVar3 = DAT_0807b2b8;
      if (iVar4 != -2) {
        puVar2 = FUN_0805eddc(0xc);
        *puVar2 = 0;
        puVar2[1] = local_8;
        local_8 = local_8 + 1;
        puVar3 = FUN_0805ee84((char *)piVar5[1]);
        puVar2[2] = (uint)puVar3;
        puVar3 = puVar2;
        if (puVar6 != (uint *)0x0) {
          *puVar6 = (uint)puVar2;
          puVar3 = DAT_0807b2b8;
        }
      }
      DAT_0807b2b8 = puVar3;
      piVar5 = (int *)*piVar5;
      puVar6 = puVar2;
    } while (piVar5 != (int *)0x0);
  }
  return;
}



void FUN_0804bf3c(undefined4 *param_1)

{
  undefined4 *puVar1;
  
  DAT_0807b2bc = 0;
  for (; param_1 != (undefined4 *)0x0; param_1 = (undefined4 *)*param_1) {
    for (puVar1 = (undefined4 *)param_1[5]; puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      FUN_0804bd88((char *)puVar1[1],1);
    }
  }
  return;
}



uint FUN_0804bf80(FILE *param_1,uint param_2)

{
  size_t __n;
  undefined4 local_8;
  
  if ((param_2 & 3) != 0) {
    local_8 = 0;
    __n = 4 - (param_2 & 3);
    fwrite(&local_8,1,__n,param_1);
    param_2 = __n + param_2;
  }
  return param_2;
}



uint FUN_0804bfc0(FILE *param_1,int param_2,int param_3,uint param_4,uint param_5,int param_6,
                 int param_7,int param_8)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  char *pcVar4;
  char local_104 [256];
  
  if (param_8 == 0) {
    iVar3 = FUN_0804b69c(1);
    uVar2 = 0xffffffff;
    pcVar4 = *(char **)(*(int *)(param_2 + 0x14) + 4);
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    iVar3 = iVar3 + 0xb + ~uVar2;
  }
  else {
    uVar2 = FUN_0804bfc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,0);
    iVar3 = FUN_0804b638(param_1,uVar2 - 4,0);
    uVar2 = FUN_0804b604(param_1,2,iVar3);
    iVar3 = FUN_0804b668(param_1,0,param_6,uVar2);
    iVar3 = FUN_0804b5b8(param_1,4,iVar3);
    iVar3 = FUN_0804b718(param_1,1,iVar3);
    iVar3 = FUN_0804b580(param_1,*(char **)(*(int *)(param_2 + 0x14) + 4),iVar3);
  }
  if (param_8 == 0) {
    pcVar4 = FUN_0804b484(local_104);
    uVar2 = 0xffffffff;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    uVar2 = iVar3 + ~uVar2;
  }
  else {
    pcVar4 = FUN_0804b484(local_104);
    uVar2 = FUN_0804b580(param_1,pcVar4,iVar3);
  }
  if (param_5 != 0) {
    if (param_8 == 0) {
      uVar2 = uVar2 + 8;
    }
    else {
      uVar2 = FUN_0804b668(param_1,param_4,param_3,uVar2);
      uVar2 = FUN_0804b668(param_1,param_5,param_3,uVar2);
    }
  }
  if (param_8 == 0) {
    iVar3 = FUN_0804b69c(0);
    uVar2 = uVar2 + iVar3 + 7 & 0xfffffffc;
  }
  else {
    iVar3 = FUN_0804b668(param_1,0,param_7,uVar2);
    uVar2 = FUN_0804b718(param_1,0,iVar3);
    uVar2 = FUN_0804bf80(param_1,uVar2);
  }
  return uVar2;
}



void FUN_0804c1d4(int param_1,int param_2,uint param_3,uint param_4,int param_5,int param_6)

{
  FUN_0804bfc0((FILE *)0x0,param_1,param_2,param_3,param_4,param_5,param_6,0);
  return;
}



void FUN_0804c1f4(FILE *param_1,undefined1 param_2,uint param_3,int param_4)

{
  int iVar1;
  
  iVar1 = FUN_0804b5b8(param_1,param_2,param_4);
  FUN_0804b718(param_1,param_3,iVar1);
  return;
}



void FUN_0804c21c(FILE *param_1,undefined1 param_2,int param_3,int param_4)

{
  int iVar1;
  
  iVar1 = FUN_0804b5b8(param_1,param_2,param_4);
  FUN_0804b760(param_1,param_3,iVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0804c244(FILE *param_1,uint param_2,int param_3,uint param_4,int param_5,uint param_6,
                int param_7,int param_8,int param_9)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  bool bVar9;
  uint local_c;
  
  uVar4 = _DAT_0807b2cc;
  bVar1 = false;
  local_c = param_3 - DAT_0807b2c8;
  uVar6 = param_6 - DAT_0807b2d4 >> 1;
  bVar9 = DAT_0807b2c4 != param_2;
  if (bVar9) {
    if (param_9 == 0) {
      iVar3 = FUN_0804b69c(param_2);
      param_8 = param_8 + 1 + iVar3;
    }
    else {
      param_8 = FUN_0804c1f4(param_1,4,param_2,param_8);
    }
    DAT_0807b2c4 = param_2;
  }
  if (param_4 != uVar4) {
    if (param_9 == 0) {
      iVar3 = FUN_0804b69c(param_4);
      param_8 = param_8 + 1 + iVar3;
    }
    else {
      param_8 = FUN_0804c1f4(param_1,5,param_4,param_8);
    }
    bVar1 = true;
    _DAT_0807b2cc = param_4;
  }
  if (DAT_0807b2d0 != param_5) {
    if (param_9 == 0) {
      iVar3 = FUN_0804b69c(5);
      iVar3 = param_8 + iVar3 + 6;
    }
    else {
      iVar3 = FUN_0804b5b8(param_1,0,param_8);
      iVar3 = FUN_0804b718(param_1,5,iVar3);
      uVar4 = FUN_0804b5b8(param_1,2,iVar3);
      iVar3 = FUN_0804b668(param_1,param_6,param_5,uVar4);
    }
    DAT_0807b2d0 = param_5;
    DAT_0807b2d4 = param_6;
    if (local_c != 0) {
      DAT_0807b2c8 = DAT_0807b2c8 + local_c;
      if (local_c - 1 < 5) {
        if (param_9 == 0) goto LAB_0804c430;
        cVar2 = (char)local_c + '\n';
        goto LAB_0804c3de;
      }
      if (param_9 == 0) {
        iVar5 = FUN_0804b6e8(local_c);
        iVar3 = iVar3 + 1 + iVar5;
      }
      else {
        iVar3 = FUN_0804c21c(param_1,3,local_c,iVar3);
      }
    }
    if (param_9 == 0) {
LAB_0804c430:
      return iVar3 + 1;
    }
    cVar2 = '\x01';
LAB_0804c3de:
    iVar3 = FUN_0804b5b8(param_1,cVar2,iVar3);
    return iVar3;
  }
  if ((local_c == 0) && (!bVar9)) {
    if ((param_7 != 0) && (uVar6 != 0)) {
      if (param_9 == 0) {
        iVar3 = FUN_0804b69c(uVar6);
        param_8 = param_8 + 1 + iVar3;
      }
      else {
        param_8 = FUN_0804c1f4(param_1,2,uVar6,param_8);
      }
      DAT_0807b2d4 = DAT_0807b2d4 + uVar6 * 2;
    }
    goto LAB_0804c5e5;
  }
  if (5 < local_c) {
    if (param_9 == 0) {
      iVar3 = FUN_0804b6e8(local_c);
      param_8 = param_8 + 1 + iVar3;
    }
    else {
      param_8 = FUN_0804c21c(param_1,3,local_c,param_8);
    }
    DAT_0807b2c8 = DAT_0807b2c8 + local_c;
    bVar1 = true;
    local_c = 0;
  }
  if (0x28 < uVar6) {
    uVar4 = uVar6 - 0x28;
    if ((uVar4 < 0x29) || ((uVar4 == 0x29 && (local_c + 0x100 < 0x100)))) {
      if (param_9 == 0) {
        param_8 = param_8 + 1;
      }
      else {
        param_8 = FUN_0804b5b8(param_1,8,param_8);
      }
      DAT_0807b2d4 = DAT_0807b2d4 + 0x50;
      bVar1 = true;
      uVar6 = uVar4;
    }
    if ((0x28 < uVar6) && ((uVar6 != 0x29 || (0xff < local_c + 0x100)))) {
      if (param_9 == 0) {
        iVar3 = FUN_0804b69c(uVar6);
        param_8 = param_8 + 1 + iVar3;
      }
      else {
        param_8 = FUN_0804c1f4(param_1,2,uVar6,param_8);
      }
      DAT_0807b2d4 = DAT_0807b2d4 + uVar6 * 2;
      uVar6 = 0;
      bVar1 = true;
    }
  }
  if ((local_c == 0) && (uVar6 == 0)) {
    if (!bVar1) goto LAB_0804c5e5;
    if (param_9 == 0) goto LAB_0804c5e4;
    cVar2 = '\x01';
  }
  else {
    DAT_0807b2c8 = DAT_0807b2c8 + local_c;
    DAT_0807b2d4 = DAT_0807b2d4 + uVar6 * 2;
    if (param_9 == 0) {
LAB_0804c5e4:
      param_8 = param_8 + 1;
      goto LAB_0804c5e5;
    }
    cVar2 = (char)local_c + '\n' + (char)uVar6 * '\x06';
  }
  param_8 = FUN_0804b5b8(param_1,cVar2,param_8);
LAB_0804c5e5:
  if (param_7 == 0) {
    return param_8;
  }
  if (param_9 == 0) {
    iVar3 = FUN_0804b69c(1);
    iVar3 = param_8 + iVar3 + 2;
  }
  else {
    iVar3 = FUN_0804b5b8(param_1,0,param_8);
    iVar3 = FUN_0804b718(param_1,1,iVar3);
    iVar3 = FUN_0804b5b8(param_1,1,iVar3);
  }
  puVar7 = &DAT_080714d4;
  puVar8 = &DAT_0807b2c4;
  for (iVar5 = 5; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar8 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar8 = puVar8 + 1;
  }
  return iVar3;
}



int FUN_0804c660(FILE *param_1,undefined4 *param_2,int param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 *puVar5;
  uint local_18;
  int local_14;
  
  puVar3 = &DAT_080714d4;
  puVar5 = &DAT_0807b2c4;
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar5 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar5 = puVar5 + 1;
  }
  for (; param_2 != (undefined4 *)0x0; param_2 = (undefined4 *)*param_2) {
    iVar2 = param_2[3];
    local_14 = 0;
    uVar4 = 0;
    local_18 = 0;
    for (puVar3 = (undefined4 *)param_2[5]; puVar3 != (undefined4 *)0x0;
        puVar3 = (undefined4 *)*puVar3) {
      uVar1 = FUN_0804bd88((char *)puVar3[1],0);
      for (puVar5 = (undefined4 *)puVar3[3]; puVar5 != (undefined4 *)0x0;
          puVar5 = (undefined4 *)*puVar5) {
        if (puVar5[2] != 0) {
          param_3 = FUN_0804c244(param_1,uVar1,puVar5[2],0,iVar2,puVar5[4],0,param_3,param_4);
        }
        uVar4 = 0;
        if (puVar5[1] != 0) {
          do {
            param_3 = FUN_0804c244(param_1,uVar1,puVar5[uVar4 * 2 + 7],0,iVar2,puVar5[uVar4 * 2 + 8]
                                   ,0,param_3,param_4);
            uVar4 = uVar4 + 1;
          } while (uVar4 < (uint)puVar5[1]);
        }
        local_14 = puVar5[3];
        uVar4 = puVar5[5];
        local_18 = uVar1;
      }
    }
    param_3 = FUN_0804c244(param_1,local_18,local_14,0,iVar2,uVar4,1,param_3,param_4);
  }
  return param_3;
}



int FUN_0804c7ac(FILE *param_1,undefined4 param_2,int param_3,int param_4)

{
  char cVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  char *pcVar8;
  char *pcVar9;
  uint local_8;
  
  if (param_4 == 0) {
    iVar3 = param_3 + 0xe;
    puVar2 = DAT_0807b2b8;
  }
  else {
    iVar3 = FUN_0804b5b8(param_1,2,param_3);
    iVar3 = FUN_0804b5b8(param_1,1,iVar3);
    iVar3 = FUN_0804b5b8(param_1,0,iVar3);
    iVar3 = FUN_0804b5b8(param_1,6,iVar3);
    iVar3 = FUN_0804b5b8(param_1,10,iVar3);
    iVar3 = FUN_0804b5e0(param_1,&DAT_080714c9,9,iVar3);
    puVar2 = DAT_0807b2b8;
  }
  for (; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
    if (param_4 == 0) {
      uVar7 = 0xffffffff;
      pcVar8 = (char *)puVar2[2];
      do {
        if (uVar7 == 0) break;
        uVar7 = uVar7 - 1;
        cVar1 = *pcVar8;
        pcVar8 = pcVar8 + 1;
      } while (cVar1 != '\0');
      iVar3 = iVar3 + ~uVar7;
    }
    else {
      iVar3 = FUN_0804b580(param_1,(char *)puVar2[2],iVar3);
    }
  }
  if (param_4 == 0) {
    iVar3 = iVar3 + 1;
    puVar2 = DAT_0807b2bc;
  }
  else {
    iVar3 = FUN_0804b5b8(param_1,0,iVar3);
    puVar2 = DAT_0807b2bc;
  }
  do {
    if (puVar2 == (undefined4 *)0x0) {
      if (param_4 == 0) {
        iVar3 = iVar3 + 1;
      }
      else {
        iVar3 = FUN_0804b5b8(param_1,0,iVar3);
      }
      return iVar3;
    }
    pcVar8 = (char *)puVar2[5];
    local_8 = 0;
    iVar4 = puVar2[2];
    if (iVar4 != 0) {
      uVar7 = 0xffffffff;
      pcVar9 = *(char **)(iVar4 + 8);
      do {
        if (uVar7 == 0) break;
        uVar7 = uVar7 - 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar9 + 1;
      } while (cVar1 != '\0');
      pcVar8 = pcVar8 + (~uVar7 - 1);
      local_8 = *(uint *)(iVar4 + 4);
    }
    if (param_4 == 0) {
      uVar7 = 0xffffffff;
      do {
        if (uVar7 == 0) break;
        uVar7 = uVar7 - 1;
        cVar1 = *pcVar8;
        pcVar8 = pcVar8 + 1;
      } while (cVar1 != '\0');
      iVar4 = iVar3 + ~uVar7;
    }
    else {
      iVar4 = FUN_0804b580(param_1,pcVar8,iVar3);
    }
    if (param_4 == 0) {
      iVar5 = FUN_0804b69c(local_8);
      iVar6 = FUN_0804b69c(puVar2[3]);
      iVar3 = FUN_0804b69c(puVar2[4]);
      iVar3 = iVar4 + iVar5 + iVar6 + iVar3;
    }
    else {
      iVar3 = FUN_0804b718(param_1,local_8,iVar4);
      iVar3 = FUN_0804b718(param_1,puVar2[3],iVar3);
      iVar3 = FUN_0804b718(param_1,puVar2[4],iVar3);
    }
    puVar2 = (undefined4 *)*puVar2;
  } while( true );
}



void FUN_0804c9e0(FILE *param_1,undefined4 *param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_0804c7ac(param_1,param_2,0,0);
  if (param_3 == 0) {
    iVar2 = 10;
  }
  else {
    iVar2 = FUN_0804c9e0(param_1,param_2,0);
    iVar2 = FUN_0804b638(param_1,iVar2 - 4,0);
    iVar2 = FUN_0804b604(param_1,2,iVar2);
    iVar2 = FUN_0804b638(param_1,uVar1,iVar2);
  }
  iVar2 = FUN_0804c7ac(param_1,param_2,iVar2,param_3);
  uVar1 = FUN_0804c660(param_1,param_2,iVar2,param_3);
  if (param_3 != 0) {
    FUN_0804bf80(param_1,uVar1);
  }
  return;
}



void FUN_0804ca8c(undefined4 *param_1)

{
  FUN_0804c9e0((FILE *)0x0,param_1,0);
  return;
}



uint FUN_0804caa0(FILE *param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  int iVar6;
  uint local_8;
  
  if (param_2 == 0) {
    puVar5 = (uint *)&DAT_080714e8;
    local_8 = 7;
  }
  else {
    puVar5 = &DAT_08071504;
    local_8 = 0xb;
  }
  if (param_3 == 0) {
    iVar1 = FUN_0804b69c(1);
    iVar6 = FUN_0804b69c(*puVar5);
    iVar1 = iVar1 + iVar6 + 1;
  }
  else {
    iVar1 = FUN_0804b718(param_1,1,0);
    iVar1 = FUN_0804b718(param_1,*puVar5,iVar1);
    iVar1 = FUN_0804b5b8(param_1,1,iVar1);
  }
  iVar6 = 1;
  if (1 < local_8) {
    do {
      puVar5 = puVar5 + 1;
      if (param_3 == 0) {
        iVar2 = FUN_0804b69c(*puVar5);
        iVar1 = iVar1 + iVar2;
      }
      else {
        iVar1 = FUN_0804b718(param_1,*puVar5,iVar1);
      }
      iVar6 = iVar6 + 1;
    } while (iVar6 < (int)local_8);
  }
  if (param_3 == 0) {
    iVar6 = FUN_0804b69c(0);
    iVar2 = FUN_0804b69c(0);
    iVar4 = FUN_0804b69c(0);
    uVar3 = iVar1 + iVar6 + iVar2 + iVar4 + 3U & 0xfffffffc;
  }
  else {
    iVar1 = FUN_0804b718(param_1,0,iVar1);
    iVar1 = FUN_0804b718(param_1,0,iVar1);
    uVar3 = FUN_0804b718(param_1,0,iVar1);
    uVar3 = FUN_0804bf80(param_1,uVar3);
  }
  return uVar3;
}



void FUN_0804cc10(int param_1)

{
  FUN_0804caa0((FILE *)0x0,param_1,0);
  return;
}



void FUN_0804cc24(void)

{
  uint *puVar1;
  int iVar2;
  int local_14;
  int local_10;
  uint local_c;
  uint local_8;
  
  local_c = 0;
  local_8 = 0;
  DAT_0807b2c0 = DAT_0808276c + 1;
  FUN_0804bce0(DAT_0807b28c,&local_14,&local_10,(int *)&local_c,(int *)&local_8);
  FUN_0804beb8();
  FUN_0804bf3c(DAT_0807b28c);
  puVar1 = FUN_0805eddc(0x2c);
  DAT_0808276c = DAT_0808276c + 1;
  FUN_080588c0((int *)puVar1,".debug_info");
  *(byte *)((int)puVar1 + 0xb) = *(byte *)((int)puVar1 + 0xb) | 0x80;
  FUN_0805202c((int *)puVar1,2,0xa000);
  iVar2 = FUN_0804c1d4((int)DAT_0807b28c,local_10,local_c,local_8,DAT_0807b2c0 + 2,DAT_0807b2c0 + 1)
  ;
  *(uint *)(DAT_0808014c + 8) = iVar2 + 3U & 0xfffffffc;
  puVar1 = FUN_0805eddc(0x2c);
  DAT_0808276c = DAT_0808276c + 1;
  FUN_080588c0((int *)puVar1,".debug_line");
  *(byte *)((int)puVar1 + 0xb) = *(byte *)((int)puVar1 + 0xb) | 0x80;
  FUN_0805202c((int *)puVar1,2,0xa000);
  iVar2 = FUN_0804ca8c(DAT_0807b28c);
  *(uint *)(DAT_0808014c + 8) = iVar2 + 3U & 0xfffffffc;
  puVar1 = FUN_0805eddc(0x2c);
  DAT_0808276c = DAT_0808276c + 1;
  FUN_080588c0((int *)puVar1,".debug_abbrev");
  *(byte *)((int)puVar1 + 0xb) = *(byte *)((int)puVar1 + 0xb) | 0x80;
  FUN_0805202c((int *)puVar1,2,0xa000);
  iVar2 = FUN_0804cc10((uint)(local_14 == 1));
  *(uint *)(DAT_0808014c + 8) = iVar2 + 3U & 0xfffffffc;
  return;
}



void FUN_0804cd6c(FILE *param_1)

{
  int local_14;
  int local_10;
  uint local_c;
  uint local_8;
  
  local_c = 0;
  local_8 = 0;
  FUN_0804bce0(DAT_0807b28c,&local_14,&local_10,(int *)&local_c,(int *)&local_8);
  FUN_0805202c((int *)0x0,0,0);
  FUN_08051240();
  FUN_0804bfc0(param_1,(int)DAT_0807b28c,local_10,local_c,local_8,DAT_0807b2c0 + 2,DAT_0807b2c0 + 1,
               1);
  FUN_08051454();
  FUN_0805202c((int *)0x0,0,0);
  FUN_08051240();
  FUN_0804c9e0(param_1,DAT_0807b28c,1);
  FUN_08051454();
  FUN_0805202c((int *)0x0,0,0);
  FUN_08051240();
  FUN_0804caa0(param_1,(uint)(local_14 == 1),1);
  FUN_08051454();
  DAT_0807b2c0 = DAT_0807b2c0 + 3;
  return;
}



void FUN_0804ce3c(FILE *param_1,undefined4 param_2)

{
  if (DAT_0807b28c != 0) {
    if (DAT_080825d0 == 1) {
      FUN_0804ab4c(param_2);
      if (DAT_0807fee0 == 1) {
        FUN_0804b3f8();
      }
      else if (DAT_0807fee0 == 2) {
        FUN_0804bb8c();
      }
      else if (DAT_0807fee0 == 3) {
        FUN_0804cc24();
      }
    }
    else if (DAT_0807fee0 == 1) {
      FUN_0804b43c(param_1);
    }
    else if (DAT_0807fee0 == 2) {
      FUN_0804bc6c(param_1);
    }
    else if (DAT_0807fee0 == 3) {
      FUN_0804cd6c(param_1);
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804cec0(void)

{
  DAT_0807b288 = 0;
  DAT_0807b284 = 0;
  DAT_0807b290 = 0;
  DAT_0807b28c = 0;
  DAT_0807b294 = &DAT_0807b28c;
  DAT_0807b298 = 0;
  _DAT_0807b2a8 = 0;
  _DAT_0807b2a4 = 0;
  DAT_0807b2b0 = 0;
  DAT_0807b2b4 = &DAT_08071556;
  return;
}



void FUN_0804cf2c(void)

{
  DAT_0807b2a0 = 0;
  return;
}



void FUN_0804cf3c(void)

{
  if (DAT_0807b2b0 != 0) {
    FUN_0805ee14(DAT_0807b2b4);
  }
  return;
}



void FUN_0804cf60(char *param_1,int *param_2,byte *param_3)

{
  FUN_0806d7a4(param_1,"a A c C h H o O s S",param_2);
  FUN_0806d81c(param_2,0,param_3,0x100);
  return;
}



void FUN_0804cf90(char *param_1,int *param_2,byte *param_3)

{
  FUN_0806d7a4(param_1,"a A c C h H o O s S",param_2);
  FUN_0806d81c(param_2,0x10,param_3,0x100);
  return;
}



uint * FUN_0804cfc0(uint param_1,char *param_2)

{
  char cVar1;
  uint *puVar2;
  uint uVar3;
  char *pcVar4;
  
  uVar3 = 0xffffffff;
  pcVar4 = param_2;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  puVar2 = FUN_0805eddc(~uVar3 + 7);
  *puVar2 = param_1;
  memcpy(puVar2 + 1,param_2,~uVar3);
  return puVar2;
}



void FUN_0804d004(char *param_1)

{
  uint *puVar1;
  int iVar2;
  uint *puVar3;
  char cVar4;
  char local_21c [256];
  byte local_11c [256];
  int local_1c [6];
  
  cVar4 = *param_1;
  if (cVar4 != '\0') {
    do {
      iVar2 = 0;
      if (cVar4 == ',') {
LAB_0804d06d:
        param_1 = param_1 + 1;
        cVar4 = *param_1;
      }
      else {
        do {
          if (cVar4 == '\0') break;
          if (iVar2 < 0xff) {
            local_21c[iVar2] = cVar4;
            iVar2 = iVar2 + 1;
          }
          param_1 = param_1 + 1;
          cVar4 = *param_1;
        } while (cVar4 != ',');
        if (cVar4 == ',') goto LAB_0804d06d;
      }
      local_21c[iVar2] = '\0';
      FUN_0804cf90(local_21c,local_1c,local_11c);
      FUN_0804aa98((char *)local_11c);
      puVar3 = FUN_0804cfc0(0,(char *)local_11c);
      puVar1 = puVar3;
      if (DAT_0807b404 != (uint *)0x0) {
        *DAT_0807b408 = (uint)puVar3;
        puVar1 = DAT_0807b404;
      }
      DAT_0807b404 = puVar1;
      DAT_0807b408 = puVar3;
    } while (cVar4 != '\0');
  }
  return;
}



void FUN_0804d0d4(undefined4 *param_1)

{
  *param_1 = DAT_0807b404;
  DAT_0807b404 = param_1;
  return;
}



void FUN_0804d0ec(char *param_1)

{
  uint *puVar1;
  byte local_11c [256];
  int local_1c [5];
  byte local_5;
  
  FUN_0804cf60(param_1,local_1c,local_11c);
  local_11c[local_5] = 0;
  FUN_0804aa98((char *)local_11c);
  puVar1 = FUN_0804cfc0(DAT_0807b404,(char *)local_11c);
  FUN_0804d0d4(puVar1);
  return;
}



void FUN_0804d134(void)

{
  uint *puVar1;
  
  if (DAT_0807b404 != (uint *)0x0) {
    puVar1 = (uint *)*DAT_0807b404;
    FUN_0805ee14(DAT_0807b404);
    DAT_0807b404 = puVar1;
  }
  if (DAT_0807b404 == (uint *)0x0) {
    DAT_0807b408 = 0;
  }
  return;
}



void FUN_0804d164(void)

{
  DAT_0807b404 = FUN_0804cfc0(0,"");
  DAT_0807b408 = DAT_0807b404;
  FUN_0804cf2c();
  return;
}



void FUN_0804d184(void)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = DAT_0807b404;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)*puVar2;
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  DAT_0807b408 = 0;
  DAT_0807b404 = (uint *)0x0;
  return;
}



void FUN_0804d1bc(void)

{
  FUN_0804d134();
  if (DAT_0807ff14 != 0) {
    DAT_0807ff0c = 0;
    DAT_0807ff14 = 0;
    fclose(DAT_08080020);
  }
  return;
}



void FUN_0804d1f0(char *param_1)

{
  char cVar1;
  uint *puVar2;
  uint uVar3;
  uint *puVar4;
  char *pcVar5;
  
  uVar3 = 0xffffffff;
  pcVar5 = param_1;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar2 = FUN_0805eddc(uVar3 + 7);
  *puVar2 = 0;
  puVar4 = puVar2 + 1;
  memcpy(puVar4,param_1,uVar3);
  *(undefined1 *)(uVar3 + 3 + (int)puVar2) = 0xd;
  *(undefined1 *)(uVar3 + 4 + (int)puVar2) = 0;
  cVar1 = (char)puVar2[1];
  while (cVar1 != '\r') {
    if ((char)*puVar4 == -2) {
      *(char *)puVar4 = ' ';
    }
    puVar4 = (uint *)((int)puVar4 + 1);
    cVar1 = *(char *)puVar4;
  }
  puVar4 = puVar2;
  if (DAT_0807b40c != (uint *)0x0) {
    *DAT_0807b410 = (uint)puVar2;
    puVar4 = DAT_0807b40c;
  }
  DAT_0807b40c = puVar4;
  DAT_0807b410 = puVar2;
  return;
}



void FUN_0804d288(void)

{
  undefined4 *puVar1;
  int iVar2;
  
  for (puVar1 = DAT_0807b40c; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
    iVar2 = FUN_080590b0((char *)(puVar1 + 1),(undefined4 *)0x0,(undefined4 *)0x0,(int *)0x0);
    if (iVar2 == 0) {
      FUN_08052f1c(1,"bad predefine: %s");
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804d2cc(void)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = DAT_0807b2e4;
  while (puVar2 != (uint *)0x0) {
    FUN_0805ee14((uint *)puVar2[1]);
    FUN_0805ee14((uint *)puVar2[4]);
    puVar1 = (uint *)*puVar2;
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  DAT_0807b2e4 = (uint *)0x0;
  _DAT_0807b400 = 0;
  return;
}



void FUN_0804d31c(int param_1)

{
  int iVar1;
  
  if (DAT_0807ff04 != (FILE *)0x0) {
    FUN_08051748();
    fflush(DAT_0807ff04);
    iVar1 = ferror(DAT_0807ff04);
    if (iVar1 != 0) {
      FUN_08052f1c(4,"Error on code file");
    }
    fclose(DAT_0807ff04);
    DAT_0807ff04 = (FILE *)0x0;
    if (param_1 != 0) {
      remove(&DAT_08080040);
    }
    FUN_0805ee14(DAT_0807ff00);
    FUN_0805ee14(DAT_0807ff10);
    FUN_0805ee14(DAT_0807ff08);
    FUN_0804cf3c();
  }
  FUN_0804d1bc();
  FUN_0804d2cc();
  FUN_0805f414();
  FUN_080516c0();
  FUN_080562d0();
  FUN_08054528();
  return;
}



// WARNING: Removing unreachable block (ram,0x0804d6c4)
// WARNING: Removing unreachable block (ram,0x0804dae4)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0804d3d4(char *param_1)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  undefined2 *puVar4;
  uint uVar5;
  undefined1 *puVar6;
  char *pcVar7;
  char acStack_31e [258];
  byte local_21c [256];
  int local_11c [2];
  void *local_114;
  byte local_10a;
  char local_104 [256];
  
  DAT_0807b2e0 = 0;
  DAT_0807ff14 = 0;
  DAT_0807ff00 = (uint *)0x0;
  DAT_0807ff10 = (uint *)0x0;
  DAT_0807ff04 = (FILE *)0x0;
  DAT_0807b2e4 = 0;
  _DAT_0807b400 = 0;
  DAT_0807b300 = 0;
  DAT_0807ff0c = 0;
  _DAT_0808262c = 0;
  DAT_08082640 = 1;
  FUN_0804cec0();
  FUN_080521e8();
  DAT_08082634 = 4;
  DAT_080826fc = 7;
  DAT_08082690 = 10;
  DAT_08082648 = 0;
  DAT_080825d4 = 0;
  DAT_08082654 = 0;
  DAT_08082688 = 0;
  DAT_080825c4 = 0;
  DAT_0808263c = 0;
  DAT_08082638 = 0;
  DAT_08082680 = 0;
  FUN_0805ec40();
  DAT_0807ff14 = 0;
  acStack_31e[1] = 0;
  pcVar1 = acStack_31e + 1;
  iVar3 = FUN_08050fdc((undefined4 *)local_104);
  if (iVar3 == 0) {
    local_104[0] = '\0';
    DAT_0807b2e0 = 1;
  }
  uVar5 = 0xffffffff;
  pcVar7 = param_1;
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar2 = *pcVar7;
    pcVar7 = pcVar7 + 1;
  } while (cVar2 != '\0');
  uVar5 = ~uVar5;
  pcVar7 = acStack_31e + 2;
  memcpy(pcVar7,param_1,uVar5);
  if ((uVar5 != 1) && (pcVar7[uVar5 - 2] == '\r')) {
    pcVar7[uVar5 - 2] = '\0';
  }
  FUN_0804cf60(pcVar7,local_11c,&DAT_08080040);
  FUN_0804a7c0(local_114,(uint)local_10a);
  FUN_0805f3f4();
  FUN_080562a0();
  FUN_080552b0();
  FUN_08058d5c();
  FUN_080583f0();
  FUN_0805f950();
  FUN_0804a930();
  if (DAT_080826ac != 0) {
    FUN_08054508();
  }
  DAT_080825cc = 0x1e;
  FUN_0805475c(1,(int)pcVar1);
  FUN_08054798(1,(int)pcVar1);
  DAT_08080158 = 0;
  DAT_08080168 = 0;
  if (DAT_08079868 != 0) {
    FUN_08063684();
  }
  FUN_0805633c();
  DAT_0808277c = 1;
  DAT_0808264c = 0;
  DAT_080825d0 = 1;
  DAT_080795ec = DAT_080795f0;
  FUN_08056cc0();
  FUN_08052a3c();
  DAT_080826c8 = 0;
  DAT_080826d0 = 0;
  FUN_0804cf60(local_104,local_11c,local_21c);
  _DAT_080826a4 = 0;
  DAT_0808276c = 0;
  DAT_08082768 = 0;
  DAT_080826a0 = 0;
  FUN_08056234();
  FUN_0804d288();
  do {
    iVar3 = FUN_0804e5e0((char *)local_21c,0,1);
  } while (iVar3 == 0);
  if (DAT_080795f4 != (code *)0x0) {
    (*DAT_080795f4)();
    DAT_080795f4 = (code *)0x0;
  }
  if (DAT_08079804 == 5) {
    DAT_08079804 = 0;
  }
  if (DAT_08080168 != 0) {
    FUN_0804d31c(0);
    puVar6 = &stack0xfffffcb4;
    goto LAB_0804dbdf;
  }
  if ((((DAT_0808276c != 0) && (DAT_080825c4 == 0)) &&
      (*(uint *)(DAT_0808014c + 8) = (DAT_080826a0 + 3 & 0xfffffffc) - *(int *)(DAT_0808014c + 0x10)
      , DAT_08082698 != 0)) && (DAT_08082654 == 0)) {
    FUN_0804ce3c((FILE *)0x0,DAT_08082594);
  }
  DAT_08082688 = 1;
  if (DAT_080825d4 == 0) {
    DAT_080825d4 = 1;
LAB_0804d7c1:
    if (DAT_080825c4 == 1) {
      FUN_0805f848();
    }
  }
  else {
    if (DAT_08082654 != 0) goto LAB_0804d7c1;
    if (DAT_080825c4 == 1) {
      FUN_08052f1c(5,"Incompatible input and output styles");
      goto LAB_0804d7c1;
    }
  }
  FUN_080511fc();
  FUN_08056d34();
  FUN_08052a74();
  FUN_0805475c(1,(int)pcVar1);
  FUN_08054798(1,(int)pcVar1);
  DAT_0807ff0c = 0;
  DAT_080825d0 = 2;
  DAT_080795ec = DAT_080795f0;
  if (DAT_08082654 == 0) {
    DAT_080826c0 = 0xc5e2d080;
    DAT_080826c4 = 0x137;
    DAT_080826c8 = DAT_0808276c;
    _DAT_080826cc = DAT_08082628 + DAT_08082648;
  }
  else {
    if (DAT_080825c4 == 1) {
      if (DAT_080826f8 == 1) {
        DAT_08082618 = DAT_080826a0;
      }
      else if (DAT_080826f8 == 0) {
        DAT_08082704 = DAT_080826a0;
      }
      else if (DAT_080826f8 == 2) {
        DAT_0808268c = DAT_080826a0;
      }
    }
    DAT_08082704 = DAT_08082704 + 3 & 0xfffffffc;
    DAT_08082618 = DAT_08082618 + 3 & 0xfffffffc;
    DAT_0808268c = DAT_0808268c + 3 & 0xfffffffc;
    _DAT_08082660 = 0x107;
    _DAT_0808266c = DAT_0808268c;
    DAT_08082668 = DAT_08082618;
    DAT_08082664 = DAT_08082704;
    if (DAT_080825c4 != 1) {
      DAT_08082664 = 0;
      DAT_08082668 = 0;
      _DAT_0808266c = 0;
    }
    _DAT_08082678 = 0;
    _DAT_0808267c = 0;
    _DAT_08082674 = DAT_080826d4;
    if ((DAT_080825c4 == 0) && (uVar5 = 1, DAT_0808276c != 0)) {
      do {
        iVar3 = FUN_08051d60(uVar5);
        if ((*(uint *)(iVar3 + 4) & 0x200) == 0) {
          if ((*(uint *)(iVar3 + 4) & 0x1000) == 0) {
            DAT_08082668 = *(uint *)(iVar3 + 8);
          }
          else {
            _DAT_0808266c = *(uint *)(iVar3 + 8);
          }
        }
        else {
          DAT_08082664 = *(uint *)(iVar3 + 8);
        }
        uVar5 = uVar5 + 1;
      } while (uVar5 <= DAT_0808276c);
    }
    _DAT_08082670 = DAT_08082648 * 0xc;
    if (DAT_080825c4 == 1) {
      FUN_08051240();
    }
  }
  FUN_08056cc0();
  FUN_08052a3c();
  DAT_080825cc = 0x1f;
  DAT_080826a0 = 0;
  DAT_0808276c = 0;
  FUN_08052268();
  FUN_0804cf60(local_104,local_11c,local_21c);
  DAT_0807ff04 = fopen(&DAT_08080040,"wb");
  if ((DAT_0807ff04 == (FILE *)0x0) || (iVar3 = ferror(DAT_0807ff04), iVar3 != 0)) {
    FUN_08052f1c(4,"Unable to open output file");
  }
  else {
    if (DAT_08082654 == 0) {
      DAT_0807ff00 = FUN_0805eddc((DAT_08082628 + DAT_08082648) * 0x10);
    }
    else {
      DAT_0807ff10 = FUN_0805eddc(DAT_08082648 * 0xc);
    }
    DAT_0807ff08 = FUN_0805eddc(DAT_08082690 + 3 & 0xfffffffc);
    uVar5 = FUN_0806d16c(DAT_08082690);
    *DAT_0807ff08 = uVar5;
    puVar4 = (undefined2 *)(DAT_08082634 + (int)DAT_0807ff08);
    *puVar4 = 0x2424;
    *(undefined1 *)(puVar4 + 1) = 0;
    puVar4 = (undefined2 *)(DAT_080826fc + (int)DAT_0807ff08);
    *puVar4 = 0x5424;
    *(undefined1 *)(puVar4 + 1) = 0;
    FUN_080525c8();
    FUN_08051600();
    do {
      iVar3 = FUN_0804e5e0((char *)local_21c,0,2);
    } while (iVar3 == 0);
    if (DAT_080795f4 != (code *)0x0) {
      (*DAT_080795f4)();
      DAT_080795f4 = (code *)0x0;
    }
    if (DAT_08079804 == 5) {
      DAT_08079804 = 0;
    }
  }
  FUN_08056244();
  FUN_08056d34();
  FUN_08052a74();
  FUN_08058414();
  iVar3 = 0;
  if (DAT_08080168 == 0) {
    FUN_0805f8a4();
    FUN_08051748();
    FUN_08051454();
    if (((DAT_08082698 != 0) && (DAT_0808276c != 0)) && (DAT_08082654 == 0)) {
      FUN_0804ce3c(DAT_0807ff04,0);
    }
    FUN_08052818();
    FUN_080522ac();
    FUN_08052408();
  }
  else {
    iVar3 = 1;
  }
  if ((DAT_08082650 != 0) && (DAT_08080168 == 0)) {
    FUN_0805f2a0();
  }
  FUN_0804d31c(iVar3);
  puVar6 = &stack0xfffffcb8;
  if (DAT_08079868 != 0) {
    FUN_080636a0();
    puVar6 = &stack0xfffffcb8;
  }
LAB_0804dbdf:
  *(undefined4 *)(puVar6 + -4) = 0x804dbe4;
  FUN_08052f7c();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0804dbf0(undefined4 *param_1,int param_2)

{
  uint *puVar1;
  
  if ((uint)(param_2 + _DAT_0807b400) <= DAT_08082630) {
    puVar1 = FUN_0805eddc(param_2);
    *param_1 = puVar1;
    if (puVar1 != (uint *)0x0) {
      _DAT_0807b400 = _DAT_0807b400 + param_2;
      return 1;
    }
  }
  return 0;
}



int * FUN_0804dc2c(char *param_1)

{
  char *pcVar1;
  int *piVar2;
  int local_c;
  
  if (DAT_0807b2e4 != (int *)0x0) {
    piVar2 = DAT_0807b2e4;
    do {
      local_c = 0;
      pcVar1 = param_1;
      if (*param_1 == *(char *)piVar2[1]) {
        do {
          if (*pcVar1 == '\0') {
            return piVar2;
          }
          pcVar1 = pcVar1 + 1;
          local_c = local_c + 1;
        } while (*pcVar1 == ((char *)piVar2[1])[local_c]);
      }
      piVar2 = (int *)*piVar2;
    } while (piVar2 != (int *)0x0);
  }
  return (int *)0x0;
}



FILE * FUN_0804dc90(char *param_1,undefined4 *param_2,char *param_3,byte *param_4,char *param_5)

{
  char *__src;
  byte bVar1;
  char cVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  byte *pbVar7;
  char *pcVar8;
  FILE *local_128;
  undefined4 local_124;
  undefined1 local_120;
  char local_11c [256];
  int local_1c [5];
  byte local_7;
  
  FUN_0804cf60(param_1,local_1c,param_4);
  puVar6 = DAT_0807b404;
  if ((local_7 & 8) != 0) {
    local_124 = 0;
    local_120 = 0;
    puVar6 = &local_124;
  }
  do {
    if (puVar6 == (undefined4 *)0x0) {
      FUN_0804d0ec("");
      *param_2 = 0;
      return (FILE *)0x0;
    }
    local_128 = (FILE *)0x0;
    uVar4 = 0xffffffff;
    pbVar7 = param_4;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      bVar1 = *pbVar7;
      pbVar7 = pbVar7 + 1;
    } while (bVar1 != 0);
    __src = (char *)(puVar6 + 1);
    uVar5 = 0xffffffff;
    pcVar8 = __src;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar2 = *pcVar8;
      pcVar8 = pcVar8 + 1;
    } while (cVar2 != '\0');
    if (0xff < (~uVar4 - 2) + ~uVar5) {
      return (FILE *)0x0;
    }
    strcpy(local_11c,__src);
    strcat(local_11c,(char *)param_4);
    piVar3 = FUN_0804dc2c(local_11c);
    if ((piVar3 != (int *)0x0) || (local_128 = fopen(local_11c,"r"), local_128 != (FILE *)0x0)) {
      if (DAT_080825d0 == 1) {
        FUN_08051160(0x8080040,(int)local_11c);
      }
      FUN_0804d0ec(local_11c);
      strcpy(param_3,__src);
      strcpy(param_5,local_11c);
      *param_2 = piVar3;
      return local_128;
    }
    puVar6 = (undefined4 *)*puVar6;
  } while( true );
}



bool FUN_0804ddec(undefined1 param_1,int *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  uint *puVar3;
  
  piVar1 = (int *)*param_2;
  *(undefined1 *)(*param_3 + 4 + (int)piVar1) = param_1;
  *param_3 = *param_3 + 1;
  iVar2 = *param_3;
  if (iVar2 == 0x400) {
    puVar3 = FUN_0805eddc(0x408);
    *piVar1 = (int)puVar3;
    *(undefined1 *)(piVar1 + 0x101) = 0;
    *param_3 = 0;
    *param_2 = *piVar1;
  }
  return iVar2 == 0x400;
}



undefined4 FUN_0804de3c(int param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int aiStackY_64 [7];
  undefined4 uStackY_48;
  int local_24 [2];
  long local_1c;
  undefined4 local_18;
  size_t local_14;
  uint *local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  if (param_1 != 0) {
    FUN_080529b4(local_24);
    if (local_24[0] != 2) {
      FUN_08052f1c(5,"Structure mismatch");
    }
    DAT_0808259c = local_24[1];
    memcpy(&DAT_0807ff20,local_10,local_14);
    (&DAT_0807ff20)[local_14] = 0;
    FUN_0804e824(&DAT_0807ff20);
    uStackY_48 = 0x804dea4;
    FUN_0805ee14(local_10);
    local_24[0] = 0;
    piVar2 = local_24;
    piVar3 = aiStackY_64;
    for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
      *piVar3 = *piVar2;
      piVar2 = piVar2 + 1;
      piVar3 = piVar3 + 1;
    }
    FUN_08052960();
    FUN_080529b4(local_24);
    if (local_24[1] == 0) {
      DAT_080825a0 = local_1c;
      DAT_08080140 = local_c;
      DAT_08082624 = local_8;
    }
    else if (local_24[1] == 1) {
      DAT_08080020 = fopen(&DAT_0807ff20,"r");
      DAT_0807ff14 = 1;
      if ((DAT_08080020 == (FILE *)0x0) || (iVar1 = ferror(DAT_08080020), iVar1 != 0)) {
        FUN_08052f1c(4,"File \"%s\" could not be reopened");
        DAT_08079804 = 5;
        return 0;
      }
      fseek(DAT_08080020,local_1c,0);
    }
    DAT_08082594 = local_18;
    DAT_0807ff0c = 1;
  }
  return 1;
}



undefined4 FUN_0804df80(char *param_1,int param_2)

{
  size_t __n;
  char cVar1;
  byte bVar2;
  bool bVar3;
  bool bVar4;
  uint *puVar5;
  int iVar6;
  undefined3 extraout_var;
  int iVar7;
  undefined3 extraout_var_00;
  uint *puVar8;
  FILE *__stream;
  size_t sVar9;
  undefined4 uVar10;
  uint uVar11;
  undefined4 *puVar12;
  int *piVar13;
  int iVar14;
  int *piVar15;
  char *pcVar16;
  byte *pbVar17;
  int aiStackY_388 [2];
  char *local_334;
  uint *local_330;
  uint *local_32c;
  int local_328 [3];
  char *local_31c;
  undefined4 local_318;
  int local_314;
  uint *local_310;
  char *local_30c;
  uint local_308;
  char local_304 [256];
  byte local_204 [256];
  char local_104 [256];
  
  if (DAT_0807b2e0 != 0) {
    puVar5 = FUN_0805eddc(0x408);
    local_328[0] = 0;
    iVar14 = 0;
    bVar4 = false;
    local_32c = puVar5;
    iVar6 = _IO_getc(stdin);
    while ((iVar7 = feof(stdin), iVar7 == 0 && (iVar7 = ferror(stdin), iVar7 == 0))) {
      bVar4 = false;
      if ((iVar6 == 10) || (iVar6 == 0xd)) {
        bVar4 = true;
      }
      bVar3 = FUN_0804ddec((char)iVar6,(int *)&local_32c,local_328);
      iVar14 = iVar14 + CONCAT31(extraout_var,bVar3);
      iVar6 = _IO_getc(stdin);
    }
    if (!bVar4) {
      bVar4 = FUN_0804ddec(0xd,(int *)&local_32c,local_328);
      iVar14 = iVar14 + CONCAT31(extraout_var_00,bVar4);
    }
    iVar6 = ferror(stdin);
    if (iVar6 != 0) {
      FUN_08052f1c(1,"Error on stdin: exiting");
      FUN_080615f0(1);
    }
    *(undefined1 *)((int)local_32c + local_328[0] + 4) = 0;
    uVar11 = iVar14 * 0x400 + local_328[0];
    local_330 = FUN_0805eddc(0x14);
    puVar8 = FUN_0805eddc(uVar11);
    local_330[4] = (uint)puVar8;
    local_330[3] = uVar11;
    puVar8 = FUN_0805eddc(1);
    local_330[1] = (uint)puVar8;
    *(undefined1 *)local_330[1] = 0;
    *local_330 = (uint)DAT_0807b2e4;
    DAT_0807b2e4 = local_330;
    local_334 = (char *)local_330[4];
    local_328[0] = 0;
    local_32c = puVar5;
    if (-1 < iVar14) {
      do {
        puVar5 = local_32c;
        strcpy(local_334,(char *)(local_32c + 1));
        local_334 = local_334 + 0x400;
        local_32c = (uint *)*local_32c;
        FUN_0805ee14(puVar5);
        iVar6 = local_328[0] + 1;
        iVar7 = local_328[0] + 1;
        local_328[0] = iVar6;
      } while (iVar7 <= iVar14);
    }
    DAT_0807b2e0 = 0;
  }
  __stream = FUN_0804dc90(param_1,&local_330,local_104,local_204,local_304);
  if ((local_330 == (uint *)0x0) &&
     ((__stream == (FILE *)0x0 || (iVar6 = ferror(__stream), iVar6 != 0)))) {
LAB_0804e2eb:
    if (local_330 == (uint *)0x0) {
      if ((__stream == (FILE *)0x0) || (iVar6 = ferror(__stream), iVar6 != 0)) {
        puVar12 = (undefined4 *)&stack0xfffffc98;
LAB_0804e4ac:
        puVar12[-1] = 4;
        puVar12[-2] = 0x804e4b3;
        FUN_08052f1c(puVar12[-1],(char *)*puVar12);
        goto LAB_0804e4b3;
      }
      DAT_0807ff14 = 1;
      DAT_08080020 = __stream;
      fseek(__stream,0,2);
      sVar9 = ftell(DAT_08080020);
      fseek(DAT_08080020,0,0);
      if ((DAT_08082610 == 0) || (iVar6 = FUN_0804dbf0(&local_334,sVar9 + 1), iVar6 == 0)) {
        DAT_0808259c = 1;
      }
      else {
        uVar11 = 0xffffffff;
        pcVar16 = local_104;
        do {
          if (uVar11 == 0) break;
          uVar11 = uVar11 - 1;
          cVar1 = *pcVar16;
          pcVar16 = pcVar16 + 1;
        } while (cVar1 != '\0');
        __n = ~uVar11 - 1;
        uVar11 = 0xffffffff;
        pbVar17 = local_204;
        do {
          if (uVar11 == 0) break;
          uVar11 = uVar11 - 1;
          bVar2 = *pbVar17;
          pbVar17 = pbVar17 + 1;
        } while (bVar2 != 0);
        DAT_0808259c = 0;
        local_330 = FUN_0805eddc(0x14);
        local_330[4] = (uint)local_334;
        puVar5 = FUN_0805eddc(~uVar11 + __n);
        local_330[1] = (uint)puVar5;
        memcpy((void *)local_330[1],local_104,__n);
        aiStackY_388[1] = 0x804e444;
        memcpy((void *)(__n + local_330[1]),local_204,~uVar11);
        *local_330 = (uint)DAT_0807b2e4;
        local_330[2] = DAT_0807b404;
        sVar9 = fread(local_334,1,sVar9,DAT_08080020);
        iVar6 = ferror(DAT_08080020);
        if (iVar6 != 0) {
          DAT_0807ff14 = 0;
          fclose(DAT_08080020);
          puVar12 = (undefined4 *)&stack0xfffffc94;
          goto LAB_0804e4ac;
        }
        if ((local_334[sVar9 - 1] != '\n') && (local_334[sVar9 - 1] != '\r')) {
          local_334[sVar9] = '\r';
          sVar9 = sVar9 + 1;
        }
        local_330[3] = sVar9;
        DAT_0807b2e4 = local_330;
        DAT_0807ff14 = 0;
        fclose(DAT_08080020);
        DAT_08080140 = local_334;
        DAT_080825a0 = local_334;
        DAT_08082624 = sVar9;
      }
    }
    else {
      DAT_0808259c = 0;
      DAT_08080140 = (char *)local_330[4];
      DAT_080825a0 = DAT_08080140;
      DAT_08082624 = local_330[3];
    }
    DAT_0807ff0c = 1;
    FUN_0804e824((char *)local_204);
    DAT_08082594 = 0;
    uVar10 = 1;
  }
  else {
    if (param_2 == 0) {
LAB_0804e2d7:
      strcpy(&DAT_0807ff20,local_304);
      goto LAB_0804e2eb;
    }
    local_328[1] = 2;
    local_328[2] = DAT_0808259c;
    if (DAT_0808259c == 0) {
      local_31c = DAT_080825a0;
      local_30c = DAT_08080140;
      local_308 = DAT_08082624;
    }
    else if (DAT_0808259c == 1) {
      local_31c = (char *)ftell(DAT_08080020);
      DAT_0807ff14 = 0;
      fclose(DAT_08080020);
    }
    piVar13 = local_328;
    FUN_080588c0(&local_314,&DAT_0807ff20);
    local_318 = DAT_08082594;
    piVar15 = aiStackY_388;
    for (iVar6 = 8; piVar13 = piVar13 + 1, iVar6 != 0; iVar6 = iVar6 + -1) {
      *piVar15 = *piVar13;
      piVar15 = piVar15 + 1;
    }
    iVar6 = FUN_08052960();
    if (iVar6 != 0) goto LAB_0804e2d7;
    FUN_0805ee14(local_310);
LAB_0804e4b3:
    DAT_08079804 = 5;
    uVar10 = 0;
  }
  return uVar10;
}



void FUN_0804e548(char *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  char *pcVar4;
  int local_11c [6];
  char local_104 [256];
  
  iVar3 = 0;
  cVar1 = *param_2;
  while ((1 < (byte)(cVar1 - 0x1fU) && (cVar1 != '\r'))) {
    local_104[iVar3] = cVar1;
    param_2 = param_2 + 1;
    iVar3 = iVar3 + 1;
    cVar1 = *param_2;
  }
  local_104[iVar3] = '\0';
  FUN_0806d7a4(local_104,"a A c C h H o O s S",local_11c);
  *param_1 = '\0';
  uVar2 = 0xffffffff;
  pcVar4 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  FUN_0806d81c(local_11c,0,(byte *)(param_1 + (~uVar2 - 1)),0x100);
  return;
}



undefined4 FUN_0804e5e0(char *param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  char *local_10c;
  int local_108;
  char local_104 [256];
  
  strcpy(local_104,param_1);
  while( true ) {
    local_108 = 0;
    iVar3 = 0;
    iVar2 = FUN_0804df80(local_104,param_2);
    if (iVar2 != 0) {
      if (param_2 == 0) {
        FUN_08056354();
      }
      DAT_08082780 = 0;
      do {
        if (param_3 == 1) {
          iVar3 = FUN_0805c320(&local_10c,&local_108);
          uVar1 = DAT_08082768;
          if ((((DAT_08082768 < DAT_080826a0) && (DAT_08082780 == 0)) &&
              (uVar1 = DAT_080826a0, DAT_0808014c != 0)) &&
             (uVar1 = DAT_080826a0, (*(byte *)(DAT_0808014c + 5) & 2) != 0)) {
            FUN_0804a99c(DAT_080826a0 - DAT_08082768,DAT_08082594);
            uVar1 = DAT_080826a0;
          }
        }
        else {
          iVar3 = FUN_0805e7d0((int *)&local_10c,&local_108);
          uVar1 = DAT_08082768;
        }
        DAT_08082768 = uVar1;
      } while (((DAT_08079804 == 0) && (FUN_08055af8(), iVar3 == 0)) && (local_108 == 0));
      FUN_0804de3c(param_2);
    }
    FUN_0804d1bc();
    if ((DAT_08079804 - 1U < 2) || (DAT_08079804 == 4)) {
      FUN_08052ae0(DAT_08079804 - 1U);
    }
    if (DAT_08079804 != 0) break;
    if (param_2 == 0) {
      FUN_080564e4();
    }
    if (local_108 != 0) {
      FUN_0804e548(local_104,local_10c);
    }
    if (iVar3 != 0) {
      return 1;
    }
  }
  DAT_08079804 = 5;
  return 1;
}



void FUN_0804e77c(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  DAT_08082698 = 0;
  DAT_08082630 = 0x800000;
  DAT_08082684 = 3;
  FUN_0804d164();
  DAT_0807b410 = 0;
  DAT_0807b40c = 0;
  puVar2 = &DAT_08082720;
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  memcpy(&DAT_0807ff20,"<command line>",0xf);
  DAT_08082594 = 0xffffffff;
  return;
}



void FUN_0804e7e8(void)

{
  uint *puVar1;
  uint *puVar2;
  
  FUN_0804d184();
  puVar2 = DAT_0807b40c;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)*puVar2;
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  return;
}



undefined * FUN_0804e818(void)

{
  return &DAT_0807b300;
}



void FUN_0804e824(char *param_1)

{
  strcpy(&DAT_0807b300,param_1);
  if (DAT_080825d0 == 1) {
    FUN_0804aa4c(param_1,DAT_08082594);
  }
  return;
}



char * FUN_0804e860(char *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = tolower(param_2);
  do {
    iVar2 = tolower((int)*param_1);
    if ((char)iVar2 == (char)iVar1) {
      return param_1;
    }
    param_1 = param_1 + 1;
  } while ((char)iVar2 != '\0');
  return (char *)0x0;
}



char * FUN_0804e8a0(char *param_1,int param_2)

{
  char cVar1;
  size_t sVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  uint uVar7;
  char *pcVar8;
  char *local_20;
  int local_1c;
  int local_14;
  char *local_10;
  char *local_c;
  uint local_8;
  
  local_c = strpbrk(param_1,"0123456789");
  local_10 = (char *)0x0;
  local_14 = 0;
  if (local_c == (char *)0x0) {
    local_c = param_1 + param_2;
  }
  else {
    sVar2 = strspn(local_c,"0123456789");
    local_c = local_c + sVar2;
  }
  local_8 = 0;
  local_1c = 0;
  local_20 = "ARM6";
  do {
    pcVar3 = strpbrk(local_20,"0123456789");
    if (pcVar3 == (char *)0x0) {
      uVar7 = 0xffffffff;
      pcVar3 = local_20;
      do {
        if (uVar7 == 0) break;
        uVar7 = uVar7 - 1;
        cVar1 = *pcVar3;
        pcVar3 = pcVar3 + 1;
      } while (cVar1 != '\0');
      pcVar3 = (char *)(~uVar7 - 1);
    }
    else {
      pcVar3 = pcVar3 + (-0x807169f - local_1c);
    }
    iVar4 = FUN_08070ba0(param_1,local_20,(int)pcVar3);
    if (iVar4 == 0) {
      if ((*local_c == '\0') || (*local_c == '/')) {
        return local_20;
      }
      iVar4 = 0;
      for (pcVar8 = local_c; pcVar8 < param_1 + param_2; pcVar8 = pcVar8 + 1) {
        iVar5 = tolower((int)*pcVar8);
        if ((iVar5 != 100) && (iVar5 != 0x69)) {
          pcVar6 = FUN_0804e860(&DAT_080716a0 + (int)(pcVar3 + local_1c),iVar5);
          if (pcVar6 == (char *)0x0) goto LAB_0804e9ed;
          iVar4 = iVar4 + 1;
        }
      }
      if (local_14 < iVar4) {
        local_10 = &DAT_080716a0 + local_1c;
        local_14 = iVar4;
      }
    }
LAB_0804e9ed:
    local_1c = local_1c + 0x30;
    local_20 = local_20 + 0x30;
    local_8 = local_8 + 1;
    if (0xe < local_8) {
      return local_10;
    }
  } while( true );
}



undefined8 FUN_0804ea10(char *param_1)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  uint uVar5;
  
  uVar5 = 0;
  pcVar4 = "ARM6";
  do {
    iVar2 = FUN_08070b40(param_1,pcVar4);
    if (iVar2 == 0) {
      pcVar3 = (char *)0x0;
      goto LAB_0804ea5c;
    }
    pcVar4 = pcVar4 + 0x30;
    uVar5 = uVar5 + 1;
  } while (uVar5 < 0xf);
  uVar5 = 0xffffffff;
  pcVar4 = param_1;
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  pcVar4 = FUN_0804e8a0(param_1,~uVar5 - 1);
  pcVar3 = pcVar4;
LAB_0804ea5c:
  return CONCAT44(pcVar3,pcVar4);
}



undefined4 FUN_0804ea64(int *param_1,char *param_2)

{
  if (*param_2 != '*') {
    if (*param_1 != 0) {
      printf(", ");
    }
    printf("%s",param_2);
    *param_1 = *param_1 + 1;
  }
  return 0;
}



int FUN_0804ea9c(undefined *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined1 *puVar3;
  uint uVar4;
  
  uVar4 = 0;
  iVar2 = 0;
  puVar3 = &DAT_080716a0;
  while ((*(int *)((int)&DAT_080716cc + iVar2) != 0 ||
         (iVar1 = (*(code *)param_1)(param_2,puVar3), iVar1 == 0))) {
    puVar3 = puVar3 + 0x30;
    iVar2 = iVar2 + 0x30;
    uVar4 = uVar4 + 1;
    if (0xe < uVar4) {
      return 0;
    }
  }
  return iVar1;
}



undefined4 FUN_0804eae0(int *param_1,int param_2)

{
  char *__s1;
  int iVar1;
  int iVar2;
  
  __s1 = *(char **)(param_2 + 0x14);
  iVar2 = 0;
  if (0 < *param_1) {
    do {
      iVar1 = strcmp(__s1,(char *)param_1[iVar2 + 1]);
      if (iVar1 == 0) {
        return 0;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < *param_1);
  }
  param_1[*param_1 + 1] = (int)__s1;
  *param_1 = *param_1 + 1;
  return 0;
}



undefined4 FUN_0804eb34(int *param_1)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = 0;
  iVar1 = 0;
  do {
    if (*(int *)((int)&DAT_080719a4 + iVar1) == 0) {
      param_1[*param_1 + 1] = *(int *)((int)&PTR_s__none_0807199c + iVar1);
      *param_1 = *param_1 + 1;
    }
    iVar1 = iVar1 + 0xc;
    uVar2 = uVar2 + 1;
  } while (uVar2 < 3);
  return 0;
}



void FUN_0804eb84(char *param_1,int param_2)

{
  int iVar1;
  undefined4 local_6c;
  int local_68;
  int local_64 [16];
  char local_24 [32];
  
  printf("%s%s vsn %s%s [%s]\n","ARM AOF"," Macro Assembler","2.50 (ARM Ltd SDT2.51)","",
         "Build number 130");
  FUN_0806dd40(param_1,local_24,0x20);
  if (param_2 == 0) {
    printf("\nUsage:      %s [keyword arguments] sourcefile objectfile\n            %s [keyword arguments] -o objectfile sourcefile\n"
           ,local_24,local_24);
    printf(
          "\nKeywords    (Upper case shows allowable abbreviation)\n-list       listingfile   Write a listing file (see manual for options)\n"
          );
    printf(
          "-Depend     dependfile    Save \'make\' source file dependencies\n-Errors     errorsfile    Put stderr diagnostics to errorsfile\n-I          dir[,dir]     Add dirs to source file search path\n-PreDefine  directive     Pre-execute a SET{L,A,S} directive\n-NOCache                  Source caching off    (default on)\n-MaxCache   <n>           Maximum cache size    (default 8MB)\n"
          );
    printf("-NOEsc                    Ignore C-style (\\c) escape sequences\n");
    printf("-NOWarn                   Turn off Warning messages\n");
    printf("-g                        Output debugging tables\n");
    printf(
          "-APCS       <pcs>/<quals> Make pre-definitions to match the\n                          chosen proc-call standard\n"
          );
    printf(
          "-CheckReglist             Warn about out of order LDM/STM register lists\n-Help                     Print this information\n-LIttleend                Little-endian ARM\n-BIgend                   Big-endian ARM\n-VIA        <file>        Read further arguments from <file>\n-ARCH       <target-arch> Set target architecture version\n            one of:       "
          );
    local_68 = 0;
    FUN_0804ea9c(FUN_0804eae0,&local_68);
    iVar1 = 0;
    if (0 < local_68) {
      do {
        if (iVar1 != 0) {
          printf(", ");
        }
        printf("%s",(char *)(local_64[iVar1] + 1));
        iVar1 = iVar1 + 1;
      } while (iVar1 < local_68);
    }
    printf("\n");
    printf("-CPU        <target-cpu>  Set the target ARM core type\n            one of:       ");
    local_6c = 0;
    FUN_0804ea9c(FUN_0804ea64,&local_6c);
    printf("\n");
    printf(
          "-FPu        <target-arch> Set target FP architecture version\n            one of:       NONE, FPA\n"
          );
    printf(
          "-16                       Assemble 16 bit Thumb instructions\n-32                       Assemble 32 bit ARM instructions\n"
          );
  }
  return;
}



void * FUN_0804ecbc(char *param_1)

{
  char cVar1;
  void *__dest;
  uint uVar2;
  char *pcVar3;
  
  if (param_1 == (char *)0x0) {
    __dest = (void *)0x0;
  }
  else {
    uVar2 = 0xffffffff;
    pcVar3 = param_1;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    __dest = malloc(~uVar2);
    memcpy(__dest,param_1,~uVar2);
  }
  return __dest;
}



void FUN_0804ecfc(int *param_1,char *param_2,undefined4 param_3,char *param_4)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  
  if ((void *)param_1[2] != (void *)0x0) {
    iVar1 = param_1[1];
    if (*param_1 <= iVar1) {
      iVar2 = *param_1 + 10;
      *param_1 = iVar2;
      pvVar3 = realloc((void *)param_1[2],iVar2 * 0xc);
      param_1[2] = (int)pvVar3;
    }
    pvVar3 = FUN_0804ecbc(param_2);
    iVar2 = iVar1 * 0xc;
    *(void **)(param_1[2] + iVar2) = pvVar3;
    *(undefined4 *)(param_1[2] + 8 + iVar2) = param_3;
    pvVar3 = FUN_0804ecbc(param_4);
    *(void **)(param_1[2] + 4 + iVar2) = pvVar3;
    param_1[1] = iVar1 + 1;
  }
  return;
}



void FUN_0804ed6c(int *param_1,char *param_2)

{
  char local_104 [256];
  
  DAT_0807b630 = DAT_0807b630 + 1;
  sprintf(local_104,"-I.%x.%s",DAT_0807b630 * 0x100000,param_2);
  FUN_0804ecfc(param_1,local_104,0x3d,param_2);
  if (param_1[3] == 0) {
    FUN_0804d004(param_2);
  }
  return;
}



void FUN_0804edc8(int *param_1,char *param_2)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  char local_104 [256];
  
  pcVar2 = strchr(param_2,0x20);
  if (pcVar2 == (char *)0x0) {
    uVar3 = 0xffffffff;
    pcVar2 = param_2;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    pcVar2 = param_2 + (~uVar3 - 1);
  }
  sprintf(local_104,"-PD.%.*s",(int)pcVar2 - (int)local_104,param_2);
  FUN_0804ecfc(param_1,local_104,0x23,param_2);
  if (param_1[3] == 0) {
    FUN_0804d1f0(param_2);
  }
  return;
}



void FUN_0804ee3c(char *param_1,int *param_2)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  char *pcVar6;
  
  DAT_08082684 = 3;
  do {
    cVar1 = *param_1;
    pcVar2 = param_1;
    do {
      while ((cVar1 != '\0' && (cVar1 != '/'))) {
        cVar1 = pcVar2[1];
        pcVar2 = pcVar2 + 1;
      }
      if (pcVar2 == param_1) {
        return;
      }
      uVar5 = 0;
      do {
        uVar4 = 0xffffffff;
        pcVar6 = (&PTR_s_reentrant_080720ec)[uVar5 * 4];
        do {
          if (uVar4 == 0) break;
          uVar4 = uVar4 - 1;
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar1 != '\0');
        iVar3 = FUN_08070ba0(param_1,(&PTR_s_reentrant_080720ec)[uVar5 * 4],~uVar4 - 1);
        if (iVar3 == 0) {
          FUN_0804ecfc(param_2,(&PTR_s__apcs_reent_080720f0)[uVar5 * 4],
                       (int)(char)*(&PTR_s___reent_080720f4)[uVar5 * 4],
                       (&PTR_s___reent_080720f4)[uVar5 * 4] + 1);
          switch((&DAT_080720f8)[uVar5 * 4]) {
          case 1:
            DAT_080825c0 = 1;
            break;
          case 2:
            DAT_080825c0 = 0;
            break;
          case 3:
            DAT_08082614 = 1;
            break;
          case 4:
            DAT_08082614 = 0;
            break;
          case 5:
            DAT_080826f0 = 0;
            if (param_2[3] == 0) {
              FUN_08052f1c(1,"APCS qualifier /26bit is obsolete");
            }
            break;
          case 6:
            DAT_080826f0 = 1;
            break;
          case 9:
            DAT_08082760 = 0;
            break;
          case 10:
            DAT_08082760 = 1;
            break;
          case 0xd:
            DAT_080825d8 = 1;
            break;
          case 0xe:
            DAT_080825d8 = 0;
          }
          break;
        }
        uVar5 = uVar5 + 1;
      } while (uVar5 < 0x1d);
      if ((uVar5 == 0x1d) && (param_2[3] == 0)) {
        FUN_08052f1c(1,"Unrecognised APCS qualifier \'/%.*s\'");
      }
      cVar1 = *pcVar2;
      param_1 = pcVar2;
    } while (cVar1 != '/');
    param_1 = pcVar2 + 1;
  } while( true );
}



undefined4 FUN_0804eff0(int *param_1,char *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  char *pcVar5;
  
  if (param_2 == (char *)0x0) {
    if (param_1[3] != 0) {
      return 4;
    }
    pcVar5 = "Target cpu missing";
  }
  else {
    uVar4 = FUN_0804ea10(param_2);
    if ((undefined4 *)uVar4 != (undefined4 *)0x0) {
      puVar2 = (undefined4 *)uVar4;
      puVar3 = &DAT_080825e0;
      for (iVar1 = 0xc; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar3 = *puVar2;
        puVar2 = puVar2 + 1;
        puVar3 = puVar3 + 1;
      }
      FUN_0804ecfc(param_1,"-cpu",0x23,param_2);
      return 2;
    }
    if (param_1[3] != 0) {
      return 4;
    }
    pcVar5 = "Target cpu not recognised";
  }
  FUN_08052f1c(1,pcVar5);
  return 4;
}



void FUN_0804f06c(char *param_1,int *param_2)

{
  int iVar1;
  char *pcVar2;
  
  iVar1 = FUN_08070b40(param_1,"none");
  if (iVar1 == 0) {
    DAT_08082684 = 0;
    return;
  }
  if (*param_1 == '/') {
    pcVar2 = param_1 + 1;
LAB_0804f0b0:
    FUN_0804ee3c(pcVar2,param_2);
  }
  else {
    if (*param_1 == '3') {
      if (param_1[1] == '/') {
        pcVar2 = param_1 + 2;
        goto LAB_0804f0b0;
      }
      if (param_1[1] == '\0') {
        DAT_08082684 = 3;
        return;
      }
    }
    if (param_2[3] == 0) {
      FUN_08052f1c(1,"Unrecognised APCS \'%s\' use \'3\' or \'None\'");
    }
  }
  return;
}



// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0804f0e4(char *param_1,byte *param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  char *pcVar7;
  char *pcVar8;
  int local_40;
  undefined4 local_3c;
  uint local_38;
  int local_34 [3];
  char *local_28;
  char local_21;
  int local_1c [3];
  char *local_10;
  char local_9;
  
  iVar1 = toupper((int)param_1[1]);
  switch(iVar1) {
  case 0x31:
    FUN_0804ecfc(param_3,".codesize",0x3d,param_1);
    iVar1 = FUN_08070b40(param_1,"-16");
    if (iVar1 != 0) {
      return 3;
    }
    DAT_080795f0 = 1;
    break;
  default:
    return 3;
  case 0x33:
    FUN_0804ecfc(param_3,".codesize",0x3d,param_1);
    iVar1 = FUN_08070b40(param_1,"-32");
    if (iVar1 != 0) {
      return 3;
    }
    DAT_080795f0 = 0;
    break;
  case 0x41:
    pcVar7 = param_1 + 2;
    iVar1 = FUN_08070b40(pcVar7,"pcs");
    if (iVar1 == 0) {
      if (param_2 != (byte *)0x0) {
        FUN_0804f06c((char *)param_2,param_3);
        return 2;
      }
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Missing argument to \'%s\'";
    }
    else {
      iVar1 = FUN_08070b40(pcVar7,"rch");
      if (iVar1 != 0) {
        iVar1 = FUN_08070b40(pcVar7,"sd");
        if (iVar1 == 0) {
          FUN_0804ecfc(param_3,".debugtable",0x3d,"-asd");
          DAT_0807fee0 = 1;
          return 0;
        }
        return 3;
      }
      if (param_2 != (byte *)0x0) {
        local_38 = 0;
        local_3c = 0;
        local_40 = 0;
        iVar1 = 0;
        uVar5 = 0;
        do {
          iVar6 = *(int *)((int)&PTR_DAT_080716b4 + iVar1);
          iVar2 = FUN_08070b40((char *)param_2,(char *)(iVar6 + 1));
          if (iVar2 == 0) {
            local_38 = *(uint *)((int)&DAT_080716b0 + iVar1);
            local_3c = *(undefined4 *)((int)&DAT_080716b8 + iVar1);
            local_40 = iVar6;
            break;
          }
          iVar1 = iVar1 + 0x30;
          uVar5 = uVar5 + 1;
        } while (uVar5 < 0xf);
        if (local_38 != 0) {
          if (local_38 < 4) {
            DAT_080825fc = 0xc;
            _DAT_08082600 = 0x24;
          }
          else {
            DAT_080825fc = 8;
            _DAT_08082600 = 0x3c;
          }
          DAT_080825f0 = local_38;
          DAT_080825f4 = local_40;
          _DAT_080825f8 = local_3c;
          FUN_0804ecfc(param_3,"-cpu",0x23,"generic");
          memcpy(&DAT_080825e0,"Generic ARM",0xc);
          pcVar7 = "-arch";
          goto LAB_08050593;
        }
        if (param_3[3] != 0) {
          return 4;
        }
        pcVar7 = "Bad architecture specified";
        goto LAB_0805053b;
      }
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Missing argument to \'%s\'";
    }
    goto LAB_08050430;
  case 0x42:
    iVar1 = FUN_08070b40(param_1 + 2,"i");
    if ((iVar1 != 0) && (iVar1 = FUN_08070b40(param_1 + 2,"igend"), iVar1 != 0)) {
      return 3;
    }
    FUN_0804ecfc(param_3,".bytesex",0x3d,"-bi");
    DAT_0808269c = 1;
    break;
  case 0x43:
    pcVar7 = param_1 + 2;
    iVar1 = FUN_08070b40(pcVar7,"pu");
    if (iVar1 == 0) {
LAB_08050086:
      uVar4 = FUN_0804eff0(param_3,(char *)param_2);
      return uVar4;
    }
    iVar1 = FUN_08070b40(pcVar7,"r");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"heckreglist"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,".checkr",0x3d,"-checkreglist");
      DAT_080826f4 = 1;
    }
    else {
      iVar1 = FUN_08070b40(pcVar7,"onfig");
      if (iVar1 != 0) {
        return 3;
      }
      DAT_08080148 = 1;
    }
    break;
  case 0x44:
    if (param_1[2] != '\0') {
      pcVar7 = param_1 + 2;
      iVar1 = FUN_08070b40(pcVar7,"epend");
      if (iVar1 != 0) {
        iVar1 = FUN_08070b40(pcVar7,"warf");
        if (iVar1 == 0) {
          if (param_3[3] == 0) {
            FUN_08052f1c(1,"-dwarf is obsolete. Use -dwarf2 (recommended) or -dwarf1 instead");
          }
        }
        else {
          iVar1 = FUN_08070b40(pcVar7,"warf1");
          if (iVar1 != 0) {
            iVar1 = FUN_08070b40(pcVar7,"warf2");
            if (iVar1 == 0) {
              FUN_0804ecfc(param_3,".debugtable",0x3d,"-dwarf2");
              DAT_0807fee0 = 3;
              return 0;
            }
            return 3;
          }
        }
        FUN_0804ecfc(param_3,".debugtable",0x3d,"-dwarf1");
        DAT_0807fee0 = 2;
        return 0;
      }
    }
    if (DAT_0807b634 == (FILE *)0x0) {
      if (param_2 != (byte *)0x0) {
        uVar5 = *param_2 - 0x2d;
        if (uVar5 == 0) {
          uVar5 = (uint)param_2[1];
        }
        if (uVar5 == 0) {
          DAT_0807b634 = stdout;
        }
        else {
          FUN_0806d7a4((char *)param_2,"s",local_1c);
          if ((local_9 == '\x01') && (iVar1 = FUN_08070b40("s",local_10), iVar1 == 0)) {
            if (param_3[3] != 0) {
              return 4;
            }
            pcVar7 = "The specified depend file \'%s\' must not be a source file";
            goto LAB_08050430;
          }
          DAT_0807b634 = fopen((char *)param_2,"w");
          if (DAT_0807b634 == (FILE *)0x0) {
            DAT_0807b634 = (FILE *)0x0;
            if (param_3[3] != 0) {
              DAT_0807b634 = (FILE *)0x0;
              return 4;
            }
            pcVar7 = "-Depend file \'%s\': cannot open";
            goto LAB_08050430;
          }
        }
        pcVar7 = "-depend";
        goto LAB_08050593;
      }
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "-Depend file missing";
    }
    else {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Dependency file already specified";
    }
    goto LAB_0805053b;
  case 0x45:
    if (param_1[2] != '\0') {
      iVar1 = FUN_08070b40(param_1 + 2,"rrors");
      if (iVar1 != 0) {
        iVar1 = FUN_08070b40(param_1 + 2,"cho");
        if (iVar1 != 0) {
          return 3;
        }
        DAT_08080144 = 1;
        pcVar8 = "-echo";
        pcVar7 = ".echo";
        goto LAB_08050383;
      }
    }
    if (DAT_0807b62c == 0) {
      if (param_2 != (byte *)0x0) {
        FUN_0806d7a4((char *)param_2,"s",local_1c);
        if ((local_9 != '\x01') || (iVar1 = FUN_08070b40("s",local_10), iVar1 != 0)) {
          FUN_0804ecfc(param_3,"-errors",0x23,(char *)param_2);
          DAT_0807b62c = 1;
          return 2;
        }
        if (param_3[3] != 0) {
          return 4;
        }
        pcVar7 = "The specified errors file \'%s\' must not be a source file";
        goto LAB_08050430;
      }
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Errors file missing";
    }
    else {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Errors file already specified";
    }
    goto LAB_0805053b;
  case 0x46:
    if (param_1[2] != '\0') {
      iVar1 = FUN_08070b40(param_1 + 2,"rom");
      if (iVar1 != 0) {
        iVar1 = FUN_08070b40(param_1 + 2,"pu");
        if (iVar1 != 0) {
          return 3;
        }
        if (param_2 != (byte *)0x0) {
          iVar1 = 0;
          uVar5 = 0;
          iVar6 = 0;
          do {
            iVar2 = FUN_08070b40((char *)param_2,
                                 (char *)(*(int *)((int)&PTR_s__none_0807199c + iVar6) + 1));
            if (iVar2 == 0) {
              iVar1 = *(int *)((int)&DAT_080719a0 + iVar6);
              break;
            }
            iVar6 = iVar6 + 0xc;
            uVar5 = uVar5 + 1;
          } while (uVar5 < 3);
          if (uVar5 < 3) {
            FUN_0804ecfc(param_3,"-fpu",0x23,(char *)param_2);
            if (iVar1 != DAT_08082608) {
              DAT_08082608 = iVar1;
              FUN_0804ecfc(param_3,"-cpu",0x23,"generic");
              memcpy(&DAT_080825e0,"Generic ARM",0xc);
              return 2;
            }
            return 2;
          }
          if (param_3[3] != 0) {
            return 4;
          }
          pcVar7 = "Bad architecture specified";
          goto LAB_0805053b;
        }
        if (param_3[3] != 0) {
          return 4;
        }
        pcVar7 = "Missing argument to \'%s\'";
        goto LAB_08050430;
      }
    }
    if (param_2 == (byte *)0x0) {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Input file missing";
      goto LAB_0805053b;
    }
    if (DAT_0807b620 == 0) {
      strcpy(&DAT_0807b420,(char *)param_2);
      DAT_0807b620 = 1;
      return 0;
    }
    if (param_3[3] == 0) {
      FUN_08052f1c(1,"Input file already specified");
    }
  case 0x47:
    DAT_08082698 = 1;
    DAT_080826ec = 1;
    for (pcVar7 = param_1 + 2; *pcVar7 != 0; pcVar7 = pcVar7 + 1) {
      iVar1 = toupper((int)*pcVar7);
      if (((iVar1 == 0x46) || (iVar1 == 0x56)) && (param_3[3] == 0)) {
        FUN_08052f1c(1,"Debug option -g%c not supported");
      }
    }
    pcVar8 = "-g";
    pcVar7 = ".debug";
LAB_08050383:
    FUN_0804ecfc(param_3,pcVar7,0x3d,pcVar8);
    break;
  case 0x48:
    if ((param_1[2] != '\0') && (iVar1 = FUN_08070b40(param_1 + 2,"elp"), iVar1 != 0)) {
      return 3;
    }
    return 1;
  case 0x49:
    if (param_1[2] != '\0') {
      FUN_0804ed6c(param_3,param_1 + 2);
      return 0;
    }
    if ((param_2 != (byte *)0x0) && (*param_2 != 0x2d)) {
      FUN_0804ed6c(param_3,(char *)param_2);
      return 2;
    }
    if (param_3[3] != 0) {
      return 4;
    }
    pcVar7 = "Include path missing";
    goto LAB_0805053b;
  case 0x4b:
    iVar1 = FUN_08070b40(param_1 + 2,"eep");
    if (iVar1 != 0) {
      return 3;
    }
    FUN_0804ecfc(param_3,".keep",0x3d,"-keep");
    DAT_080826ec = 1;
    break;
  case 0x4c:
    if (param_1[2] != '\0') {
      pcVar7 = param_1 + 2;
      iVar1 = FUN_08070b40(pcVar7,"ength");
      if (iVar1 != 0) {
        iVar1 = FUN_08070b40(pcVar7,"i");
        if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"ittleend"), iVar1 == 0)) {
          FUN_0804ecfc(param_3,".bytesex",0x3d,"-li");
          DAT_0808269c = 0;
          return 0;
        }
        iVar1 = FUN_08070b40(pcVar7,"istoff");
        if (iVar1 == 0) {
          FUN_0804ecfc(param_3,"-list",0x3d,"off");
          DAT_080826ac = 0;
          return 0;
        }
        iVar1 = FUN_08070b40(pcVar7,"iston");
        if (iVar1 == 0) {
          FUN_0804ecfc(param_3,"-list",0x3d,"on");
          DAT_080826ac = 1;
          return 0;
        }
        iVar1 = FUN_08070b40(pcVar7,"ist");
        if (iVar1 != 0) {
          return 3;
        }
        FUN_0804ecfc(param_3,"-list",0x3d,"on");
        DAT_080826ac = 1;
        goto LAB_080500b4;
      }
    }
    if (param_2 != (byte *)0x0) {
      uVar5 = __strtol_internal(param_2,0,10,0);
      if ((0xff < uVar5) && (uVar5 = DAT_08082590, param_3[3] == 0)) {
        FUN_08052f1c(1,"Length out of range, ignored");
        uVar5 = DAT_08082590;
      }
      DAT_08082590 = uVar5;
      pcVar7 = ".length";
LAB_08050593:
      FUN_0804ecfc(param_3,pcVar7,0x23,(char *)param_2);
      return 2;
    }
    if (param_3[3] != 0) {
      return 4;
    }
    pcVar7 = "Length specifier missing";
LAB_0805053b:
    FUN_08052f1c(1,pcVar7);
    return 4;
  case 0x4d:
    if (param_1[2] != '\0') {
      pcVar7 = param_1 + 2;
      iVar1 = FUN_08070b40(pcVar7,"odule");
      if (iVar1 != 0) {
        iVar1 = FUN_08070b40(pcVar7,"c");
        if ((iVar1 != 0) && (iVar1 = FUN_08070b40(pcVar7,"axcache"), iVar1 != 0)) {
          iVar1 = FUN_08070b40(pcVar7,"d-");
          if (iVar1 == 0) {
            FUN_0804ecfc(param_3,"-MD",0x3d,"-");
            DAT_0807b634 = stdout;
            return 0;
          }
          return 3;
        }
        if (param_2 != (byte *)0x0) {
          iVar1 = isdigit((int)(char)*param_2);
          if (iVar1 == 0) {
            if (((*param_2 != 0x26) || (iVar1 = isxdigit((int)(char)param_2[1]), iVar1 == 0)) ||
               (param_2[2] == 0x78)) {
              if (param_3[3] != 0) {
                return 4;
              }
              pcVar7 = "Bad value for maxCache";
              goto LAB_0805053b;
            }
            pbVar3 = param_2 + 1;
            uVar4 = 0x10;
          }
          else {
            pbVar3 = param_2;
            if (((*param_2 == 0x30) && (param_2[1] == 0x78)) &&
               (iVar1 = isxdigit((int)(char)param_2[2]), iVar1 != 0)) {
              uVar4 = 0x10;
            }
            else {
              uVar4 = 10;
            }
          }
          iVar1 = __strtol_internal(pbVar3,0,uVar4,0);
          if ((iVar1 < 0) && (iVar1 = DAT_08082630, param_3[3] == 0)) {
            FUN_08052f1c(1,"MaxCache negative, ignored");
            iVar1 = DAT_08082630;
          }
          DAT_08082630 = iVar1;
          pcVar7 = "-maxcache";
          goto LAB_08050593;
        }
        if (param_3[3] != 0) {
          return 4;
        }
        pcVar7 = "Length specifier missing";
        goto LAB_0805053b;
      }
    }
    _DAT_0808261c = 1;
    break;
  case 0x4e:
    pcVar7 = param_1 + 2;
    iVar1 = FUN_08070b40(pcVar7,"ot");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"oterse"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,".terse",0x3d,"-noterse");
      DAT_080825c8 = 0;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"oc");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"ocache"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,".cache",0x3d,"-noache");
      DAT_08082610 = 0;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"oe");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"oesc"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,".esc",0x3d,"-noesc");
      DAT_08082700 = 0;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"ow");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"owarn"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,".warn",0x3d,"-nowarn");
      DAT_08080164 = 1;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"or");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"oregs"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,"-regnames",0x23,"none");
      DAT_080829a0 = 1;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"ocr");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"ocheckreglist"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,".checkr",0x3d,"-nocheckreglist");
      DAT_080826f4 = 0;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"ok");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"okeep"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,".keep",0x3d,"-nokeep");
      DAT_080826ec = 0;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"ox");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"oxref"), iVar1 == 0)) {
      FUN_0804ecfc(param_3,".xref",0x3d,"-noxref");
      DAT_08082650 = 0;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"osplitldms");
    if (iVar1 == 0) {
      FUN_0804ecfc(param_3,"-splitldms",0x3d,"");
      DAT_08079800 = 0;
      return 0;
    }
    iVar1 = FUN_08070b40(pcVar7,"oecho");
    if (iVar1 != 0) {
      return 3;
    }
    DAT_08080144 = 0;
    pcVar8 = "";
    pcVar7 = ".echo";
    goto LAB_08050383;
  case 0x4f:
    if ((param_1[2] != '\0') && (iVar1 = FUN_08070b40(param_1 + 2,"bject"), iVar1 != 0)) {
      return 3;
    }
    if (param_2 == (byte *)0x0) {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Output file missing";
      goto LAB_0805053b;
    }
    if (DAT_0807b624 != 0) {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Output file already specified";
      goto LAB_0805053b;
    }
    strcpy(&DAT_0807b520,(char *)param_2);
    FUN_0806d7a4(&DAT_0807b520,"s",local_1c);
    if ((local_9 != '\x01') || (iVar1 = FUN_08070b40("s",local_10), iVar1 != 0)) {
      DAT_0807b624 = 1;
      return 2;
    }
    iVar1 = param_3[3];
    goto joined_r0x08050421;
  case 0x50:
    pcVar7 = param_1 + 2;
    iVar1 = FUN_08070b40(pcVar7,"d");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"redefine"), iVar1 == 0)) {
      if ((param_1[3] != '\0') &&
         ((iVar1 = toupper((int)param_1[2]), iVar1 == 0x44 || (param_1[10] != '\0')))) {
        iVar1 = toupper((int)param_1[2]);
        if (iVar1 == 0x44) {
          pcVar7 = param_1 + 3;
        }
        else {
          pcVar7 = param_1 + 10;
        }
        FUN_0804edc8(param_3,pcVar7);
        return 0;
      }
      if (param_2 != (byte *)0x0) {
        FUN_0804edc8(param_3,(char *)param_2);
        return 2;
      }
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Predefine missing";
      goto LAB_0805053b;
    }
    iVar1 = FUN_08070b40(pcVar7,"roc");
    if ((iVar1 == 0) || (iVar1 = FUN_08070b40(pcVar7,"rocessor"), iVar1 == 0)) goto LAB_08050086;
    if ((param_1[2] != '\0') && (iVar1 = FUN_08070b40(pcVar7,"rint"), iVar1 != 0)) {
      return 3;
    }
LAB_080500b4:
    if (DAT_0807b628 != 0) {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Listing file already specified";
      goto LAB_0805053b;
    }
    DAT_0807b628 = 1;
    DAT_080826ac = 1;
    if (param_2 == (byte *)0x0) {
      DAT_0807b628 = 1;
      DAT_080826ac = 1;
      return 0;
    }
    FUN_0806d7a4((char *)param_2,"s",local_1c);
    if ((local_9 != '\x01') || (iVar1 = FUN_08070b40("s",local_10), iVar1 != 0)) {
      if ((*param_2 == 0x2d) && (param_2[2] != 0)) {
        return 0;
      }
      pcVar7 = "-print";
      goto LAB_08050593;
    }
    if (param_3[3] != 0) {
      return 4;
    }
    pcVar7 = "The specified listing file \'%s\' must not be a source file";
    goto LAB_08050430;
  case 0x52:
    iVar1 = FUN_08070b40(param_1 + 2,"eg");
    if ((iVar1 != 0) && (iVar1 = FUN_08070b40(param_1 + 2,"egnames"), iVar1 != 0)) {
      return 3;
    }
    if (param_2 != (byte *)0x0) {
      iVar1 = FUN_08070b40((char *)param_2,"all");
      if (iVar1 == 0) {
        FUN_0804ecfc(param_3,"-regnames",0x23,"all");
        DAT_080829a0 = 2;
        return 2;
      }
      iVar1 = FUN_08070b40((char *)param_2,"callstd");
      if (iVar1 == 0) {
        pcVar7 = "callstd";
      }
      else {
        iVar1 = FUN_08070b40((char *)param_2,"none");
        if (iVar1 != 0) {
          return 3;
        }
        pcVar7 = "none";
      }
      FUN_0804ecfc(param_3,"-regnames",0x23,pcVar7);
      DAT_080829a0 = 0;
      return 2;
    }
    if (param_3[3] != 0) {
      return 4;
    }
    pcVar7 = "Missing argument to \'%s\'";
    goto LAB_08050430;
  case 0x53:
    if (param_1[2] != '\0') {
      pcVar7 = param_1 + 2;
      iVar1 = FUN_08070b40(pcVar7,"tamp");
      if (iVar1 != 0) {
        iVar1 = FUN_08070b40(pcVar7,"plitldms");
        if (iVar1 == 0) {
          if (param_2 != (byte *)0x0) {
            iVar1 = FUN_08070b40((char *)param_2,"q");
            if (iVar1 == 0) {
              FUN_0804ecfc(param_3,"-splitldms",0x23,"q");
              DAT_08079800 = 1;
              return 2;
            }
            iVar1 = FUN_08070b40((char *)param_2,"v");
            if (iVar1 == 0) {
              FUN_0804ecfc(param_3,"-splitldms",0x23,"v");
              DAT_08079800 = 2;
              return 2;
            }
            if (param_3[3] != 0) {
              return 4;
            }
            pcVar7 = "Error: -splitldms expects argument q or v";
            goto LAB_0805053b;
          }
          if (param_3[3] != 0) {
            return 4;
          }
          pcVar7 = "Missing argument to \'%s\'";
          goto LAB_08050430;
        }
        iVar1 = FUN_08070b40(pcVar7,"elftest");
        if (iVar1 != 0) {
          return 3;
        }
        DAT_08079868 = 1;
        pcVar8 = "-selftest";
        pcVar7 = ".test";
        goto LAB_08050383;
      }
    }
    FUN_0804ecfc(param_3,"-stamp",0x3f,"");
    _DAT_08082764 = 1;
    break;
  case 0x54:
    if (param_1[2] != '\0') {
      iVar1 = FUN_08070b40(param_1 + 2,"o");
      if (iVar1 != 0) {
        iVar1 = FUN_08070b40(param_1 + 2,"erse");
        if (iVar1 == 0) {
          FUN_0804ecfc(param_3,".terse",0x3d,"-terse");
          DAT_080825c8 = 1;
          return 0;
        }
        return 3;
      }
    }
    if (param_2 == (byte *)0x0) {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Output file missing";
      goto LAB_0805053b;
    }
    if (DAT_0807b624 != 0) {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Output file already specified";
      goto LAB_0805053b;
    }
    strcpy(&DAT_0807b520,(char *)param_2);
    FUN_0806d7a4(&DAT_0807b520,"s",local_34);
    if (local_21 != '\x01') {
      DAT_0807b624 = 1;
      return 2;
    }
    iVar1 = FUN_08070b40("s",local_28);
    if (iVar1 != 0) {
      DAT_0807b624 = 1;
      return 2;
    }
    iVar1 = param_3[3];
joined_r0x08050421:
    if (iVar1 != 0) {
      return 4;
    }
    pcVar7 = "The specified output file \'%s\' must not be a source file";
LAB_08050430:
    FUN_08052f1c(1,pcVar7);
    return 4;
  case 0x55:
    iVar1 = FUN_08070b40(param_1 + 2,"nsafe");
    if (iVar1 != 0) {
      return 3;
    }
    FUN_0804ecfc(param_3,".unsafe",0x3d,"-unsafe");
    DAT_08082620 = 1;
    break;
  case 0x56:
    iVar1 = FUN_08070b40(param_1 + 2,"sn");
    if (iVar1 != 0) {
      return 3;
    }
    return 5;
  case 0x57:
    pcVar7 = param_1 + 2;
    iVar1 = FUN_08070b40(pcVar7,"i");
    if ((iVar1 != 0) && (iVar1 = FUN_08070b40(pcVar7,"idth"), iVar1 != 0)) {
      iVar1 = FUN_08070b40(pcVar7,"arn");
      if (iVar1 != 0) {
        return 3;
      }
      FUN_0804ecfc(param_3,".warn",0x3d,"-warn");
      DAT_08080164 = 0;
      return 0;
    }
    if (param_2 == (byte *)0x0) {
      if (param_3[3] != 0) {
        return 4;
      }
      pcVar7 = "Width specifier missing";
      goto LAB_0805053b;
    }
    uVar5 = __strtol_internal(param_2,0,10,0);
    if ((0xff < uVar5) && (uVar5 = DAT_0808258c, param_3[3] == 0)) {
      FUN_08052f1c(1,"Width out of range, ignored");
      uVar5 = DAT_0808258c;
    }
    DAT_0808258c = uVar5;
    pcVar7 = "-width";
    goto LAB_08050593;
  case 0x58:
    if ((param_1[2] != '\0') && (iVar1 = FUN_08070b40(param_1 + 2,"ref"), iVar1 != 0)) {
      return 3;
    }
    FUN_0804ecfc(param_3,".xref",0x3d,"-xref");
    DAT_08082650 = 1;
  }
  return 0;
}



void FUN_08050624(int param_1)

{
  fgetc(*(FILE **)(param_1 + 8));
  return;
}



void FUN_08050634(int param_1)

{
  fseek(*(FILE **)(param_1 + 8),0,0);
  return;
}



int FUN_08050648(int param_1)

{
  int iVar1;
  
  iVar1 = (int)*(char *)(*(int *)(param_1 + 0xc) + *(int *)(param_1 + 8));
  if (iVar1 == 0) {
    iVar1 = -1;
  }
  else {
    *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + 1;
  }
  return iVar1;
}



void FUN_0805066c(int param_1)

{
  *(undefined4 *)(param_1 + 0xc) = 0;
  return;
}



int FUN_0805067c(undefined4 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  uint uVar4;
  int local_a0;
  char local_9c [152];
  
  local_a0 = 0;
  do {
    uVar4 = 0;
    do {
      iVar1 = (**(code **)*param_1)(param_1);
      if (iVar1 == -1) break;
      iVar2 = isspace(iVar1);
    } while (iVar2 != 0);
    if (iVar1 == -1) {
      return local_a0;
    }
    if ((iVar1 == 0x27) || (iVar2 = iVar1, iVar1 == 0x22)) {
      do {
        iVar2 = (**(code **)*param_1)(param_1);
        if (iVar2 == 0x5c) {
          iVar2 = (**(code **)*param_1)(param_1);
          if (iVar2 != iVar1) {
            if (uVar4 < 0x95) {
              local_9c[uVar4] = '\\';
              uVar4 = uVar4 + 1;
            }
            goto LAB_0805071c;
          }
        }
        else {
LAB_0805071c:
          if ((iVar2 == -1) || (iVar2 == iVar1)) goto LAB_0805075d;
        }
        if (uVar4 < 0x95) {
          local_9c[uVar4] = (char)iVar2;
          uVar4 = uVar4 + 1;
        }
      } while( true );
    }
    do {
      if (uVar4 < 0x95) {
        local_9c[uVar4] = (char)iVar2;
        uVar4 = uVar4 + 1;
      }
      iVar2 = (**(code **)*param_1)(param_1);
    } while ((iVar2 != -1) && (iVar1 = isspace(iVar2), iVar1 == 0));
LAB_0805075d:
    local_9c[uVar4] = '\0';
    if (param_2 != 0) {
      pvVar3 = FUN_0804ecbc(local_9c);
      *(void **)(param_2 + local_a0 * 4) = pvVar3;
    }
    local_a0 = local_a0 + 1;
    if (iVar2 == -1) {
      return local_a0;
    }
  } while( true );
}



int FUN_0805079c(int *param_1,int param_2,int param_3)

{
  void *__ptr;
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  int iVar6;
  
  iVar1 = FUN_0805067c(param_1,0);
  puVar5 = (undefined4 *)param_1[1];
  if (iVar1 == 0) {
    iVar6 = param_3 + 1;
    if (iVar6 <= param_2) {
      puVar3 = puVar5 + param_3 + -1;
      puVar5 = puVar5 + iVar6;
      do {
        *puVar3 = *puVar5;
        puVar3 = puVar3 + 1;
        puVar5 = puVar5 + 1;
        iVar6 = iVar6 + 1;
      } while (iVar6 <= param_2);
    }
  }
  else {
    puVar2 = malloc((param_2 + -1 + iVar1) * 4);
    __ptr = (void *)puVar5[param_3];
    iVar6 = 0;
    puVar3 = puVar2;
    puVar4 = puVar5;
    if (0 < param_3 + -1) {
      do {
        *puVar3 = *puVar4;
        iVar6 = iVar6 + 1;
        puVar3 = puVar3 + 1;
        puVar4 = puVar4 + 1;
      } while (iVar6 < param_3 + -1);
    }
    (**(code **)(*param_1 + 4))(param_1);
    free((void *)puVar5[param_3 + -1]);
    FUN_0805067c(param_1,(int)(puVar2 + iVar6));
    iVar6 = param_3 + 1;
    if (iVar6 <= param_2) {
      puVar3 = puVar5 + iVar6;
      do {
        puVar2[iVar1 + iVar6 + -2] = *puVar3;
        puVar3 = puVar3 + 1;
        iVar6 = iVar6 + 1;
      } while (iVar6 <= param_2);
    }
    free(__ptr);
    free(puVar5);
    param_1[1] = (int)puVar2;
  }
  return iVar1 + -2 + param_2;
}



void FUN_080508b4(void)

{
  DAT_08080148 = 0;
  DAT_0807b630 = 0;
  DAT_0807b62c = 0;
  DAT_0807b628 = 0;
  DAT_0807b624 = 0;
  DAT_0807b620 = 0;
  DAT_0807b634 = 0;
  DAT_080826ec = 0;
  DAT_08080164 = 0;
  DAT_080826ac = 0;
  DAT_08082650 = 0;
  DAT_080825c8 = 1;
  return;
}



uint FUN_08050934(int param_1,undefined4 *param_2,int *param_3)

{
  uint *puVar1;
  undefined4 *puVar2;
  void *pvVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  uint *local_2c;
  uint local_28;
  undefined **local_24;
  uint *local_20;
  uint local_1c;
  char *local_18;
  undefined4 local_14;
  uint *local_10;
  FILE *local_c;
  
  local_28 = 0;
  if (param_1 < 2) {
    FUN_0804eb84((char *)*param_2,0);
    local_28 = 0;
  }
  else {
    local_2c = malloc(param_1 * 4 + 4);
    iVar5 = 1;
    puVar1 = local_2c;
    puVar2 = param_2;
    if (0 < param_1) {
      do {
        pvVar3 = FUN_0804ecbc((char *)puVar2[1]);
        puVar1[1] = (uint)pvVar3;
        iVar5 = iVar5 + 1;
        puVar1 = puVar1 + 1;
        puVar2 = puVar2 + 1;
      } while (iVar5 <= param_1);
    }
    iVar5 = 1;
    if (1 < param_1) {
      do {
        iVar5 = iVar5 + 1;
      } while (iVar5 < param_1);
    }
    iVar5 = 1;
    if (1 < param_1) {
      do {
        pcVar6 = (char *)local_2c[iVar5];
        if (*pcVar6 == '-') {
          iVar4 = FUN_08070b40(pcVar6 + 1,"via");
          if (iVar4 == 0) {
            iVar4 = iVar5 + 1;
            if (iVar4 < param_1) {
              local_c = fopen((char *)local_2c[iVar4],"r");
              if (local_c != (FILE *)0x0) {
                local_14 = &PTR_FUN_08072d60;
                local_10 = local_2c;
                param_1 = FUN_0805079c(&local_14,param_1,iVar4);
                fclose(local_c);
                local_2c = local_10;
                iVar5 = iVar5 + -1;
                goto LAB_08050c52;
              }
              if (param_3[3] == 0) {
                pcVar6 = "Via file would not open";
                goto LAB_08050a54;
              }
            }
            else if (param_3[3] == 0) {
              pcVar6 = "Via file missing";
LAB_08050a54:
              FUN_08052f1c(1,pcVar6);
            }
            goto LAB_08050c49;
          }
          iVar4 = FUN_08070b40(pcVar6 + 1,"vias");
          if (iVar4 == 0) {
            iVar4 = iVar5 + 1;
            if (param_1 <= iVar4) {
              FUN_08052f1c(1,"Via file missing");
              local_28 = 1;
              break;
            }
            local_1c = local_2c[iVar4];
            local_18 = (char *)0x0;
            local_24 = &PTR_FUN_08072d68;
            local_20 = local_2c;
            param_1 = FUN_0805079c((int *)&local_24,param_1,iVar4);
            local_2c = local_20;
            iVar5 = iVar5 + -1;
            iVar4 = 1;
            if (1 < param_1) {
              do {
                iVar4 = iVar4 + 1;
              } while (iVar4 < param_1);
            }
          }
          else {
            iVar4 = FUN_0804f0e4(pcVar6,(byte *)local_2c[iVar5 + 1],param_3);
            if (iVar4 != 2) {
              if (iVar4 == 3) {
                if (param_3[3] == 0) {
                  pcVar6 = "Unrecognised parameter \'%s\'";
                  goto LAB_08050c3f;
                }
              }
              else if (iVar4 != 4) {
                if (((iVar4 == 1) || (iVar4 == 5)) && (param_3[3] == 0)) {
                  FUN_0804eb84((char *)*param_2,(uint)(iVar4 == 5));
                  FUN_0805ee14(local_2c);
                  return 2;
                }
                goto LAB_08050c52;
              }
              goto LAB_08050c49;
            }
            iVar5 = iVar5 + 1;
          }
        }
        else {
          if (DAT_0807b620 != 0) {
            if (DAT_0807b624 == 0) {
              strcpy(&DAT_0807b520,pcVar6);
              FUN_0806d7a4(&DAT_0807b520,"s",(int *)&local_24);
              if ((local_14._3_1_ != '\x01') || (iVar4 = FUN_08070b40("s",local_18), iVar4 != 0)) {
                DAT_0807b624 = 1;
                goto LAB_08050c52;
              }
              if (param_3[3] == 0) {
                pcVar6 = "The specified output file \'%s\' must not be a source file";
                goto LAB_08050c3f;
              }
            }
            else if (param_3[3] == 0) {
              pcVar6 = "Bad command line parameter \'%s\'";
LAB_08050c3f:
              FUN_08052f1c(1,pcVar6);
            }
LAB_08050c49:
            local_28 = 1;
            break;
          }
          strcpy(&DAT_0807b420,pcVar6);
          DAT_0807b620 = 1;
        }
LAB_08050c52:
        iVar5 = iVar5 + 1;
      } while (iVar5 < param_1);
    }
    iVar5 = 1;
    puVar1 = local_2c;
    if (1 < param_1) {
      do {
        free((void *)puVar1[1]);
        iVar5 = iVar5 + 1;
        puVar1 = puVar1 + 1;
      } while (iVar5 < param_1);
    }
    free(local_2c);
    local_28 = local_28 ^ 1;
  }
  return local_28;
}



void FUN_08050c9c(char *param_1,byte *param_2,char *param_3)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  int local_1c [3];
  char *local_10;
  undefined1 local_c;
  undefined1 local_b;
  char local_9;
  byte local_7;
  
  FUN_0806d7a4(param_1,"s",local_1c);
  if (param_3 == (char *)0x0) {
    local_9 = '\0';
  }
  else {
    iVar2 = -1;
    pcVar3 = param_3;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    local_9 = ~(byte)iVar2 - 1;
  }
  local_10 = param_3;
  local_1c[1] = 0;
  local_b = 0;
  local_1c[0] = 0;
  local_c = 0;
  local_7 = local_7 & 0xf7;
  FUN_0806d81c(local_1c,0,param_2,0xff);
  return;
}



undefined4 FUN_08050d10(int *param_1,undefined4 *param_2)

{
  undefined2 uVar1;
  char cVar2;
  int iVar3;
  FILE *pFVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  char *pcVar8;
  byte local_104 [256];
  
  FUN_0806d130((uint)(DAT_0808269c != 0));
  iVar3 = FUN_080702e4(param_1,(byte *)"-errors");
  if (iVar3 != 0) {
    pFVar4 = fopen((char *)(iVar3 + 1),"w");
    if (pFVar4 == (FILE *)0x0) {
      pcVar8 = "Errors file would not open";
      goto LAB_08050fc5;
    }
    FUN_08061600(pFVar4);
  }
  if (DAT_0807b624 == 0) {
    FUN_08050c9c(&DAT_0807b420,&DAT_0807b520,"o");
    DAT_0807b624 = 1;
  }
  if (DAT_080826ac == 0) {
    DAT_08082650 = 0;
  }
  else {
    iVar3 = FUN_080702e4(param_1,(byte *)"-print");
    if (iVar3 == 0) {
      FUN_08050c9c(&DAT_0807b420,local_104,"lst");
      iVar3 = FUN_08054470((char *)local_104);
    }
    else {
      iVar3 = FUN_08054470((char *)(iVar3 + 1));
    }
    if (iVar3 == 0) {
      return 0;
    }
  }
  if (DAT_0807b624 != 0) {
    uVar5 = 0xffffffff;
    pcVar8 = &DAT_0807b520;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar2 = *pcVar8;
      pcVar8 = pcVar8 + 1;
    } while (cVar2 != '\0');
    if (~uVar5 < 9) {
      uVar1 = CONCAT11(DAT_0807b525,DAT_0807b524);
      uVar6 = CONCAT31(CONCAT21(CONCAT11(DAT_0807b523,DAT_0807b522),DAT_0807b521),DAT_0807b520);
      uVar7 = CONCAT31(CONCAT21(CONCAT11(DAT_0807b527,DAT_0807b526),DAT_0807b525),DAT_0807b524);
      uVar5 = 0xffffffff;
      pcVar8 = &DAT_0807b520;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar2 = *pcVar8;
        pcVar8 = pcVar8 + 1;
      } while (cVar2 != '\0');
      switch(~uVar5) {
      case 1:
        *(undefined1 *)param_2 = 0;
        break;
      case 2:
        *(ushort *)param_2 = CONCAT11(DAT_0807b521,DAT_0807b520);
        break;
      case 3:
        *(ushort *)param_2 = CONCAT11(DAT_0807b521,DAT_0807b520);
        *(undefined1 *)((int)param_2 + 2) = 0;
        break;
      case 4:
        *param_2 = uVar6;
        break;
      case 5:
        *param_2 = uVar6;
        *(undefined1 *)(param_2 + 1) = 0;
        break;
      case 6:
        *param_2 = uVar6;
        *(undefined2 *)(param_2 + 1) = uVar1;
        break;
      case 7:
        *param_2 = uVar6;
        *(undefined2 *)(param_2 + 1) = uVar1;
        *(undefined1 *)((int)param_2 + 6) = 0;
        break;
      case 8:
        *param_2 = uVar6;
        param_2[1] = uVar7;
      }
    }
    else {
      uVar5 = 0xffffffff;
      pcVar8 = &DAT_0807b520;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar2 = *pcVar8;
        pcVar8 = pcVar8 + 1;
      } while (cVar2 != '\0');
      memcpy(param_2,&DAT_0807b520,~uVar5);
    }
    return 1;
  }
  pcVar8 = "Output file missing";
LAB_08050fc5:
  FUN_08052f1c(1,pcVar8);
  return 0;
}



int FUN_08050fdc(undefined4 *param_1)

{
  undefined2 uVar1;
  char cVar2;
  ushort uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  char *pcVar7;
  ushort local_c;
  
  if (DAT_0807b620 != 0) {
    uVar4 = 0xffffffff;
    pcVar7 = &DAT_0807b420;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar2 = *pcVar7;
      pcVar7 = pcVar7 + 1;
    } while (cVar2 != '\0');
    if (~uVar4 < 9) {
      uVar1 = CONCAT11(DAT_0807b421,DAT_0807b420);
      local_c = (short)CONCAT21(uVar1,DAT_0807b425) << 8;
      uVar3 = (ushort)DAT_0807b424;
      uVar5 = CONCAT31(CONCAT21(CONCAT11(DAT_0807b423,DAT_0807b422),DAT_0807b421),DAT_0807b420);
      uVar6 = CONCAT31(CONCAT21(CONCAT11(DAT_0807b427,DAT_0807b426),DAT_0807b425),DAT_0807b424);
      uVar4 = 0xffffffff;
      pcVar7 = &DAT_0807b420;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar2 = *pcVar7;
        pcVar7 = pcVar7 + 1;
      } while (cVar2 != '\0');
      switch(~uVar4) {
      case 1:
        *(undefined1 *)param_1 = 0;
        break;
      case 2:
        *(undefined2 *)param_1 = uVar1;
        break;
      case 3:
        *(undefined2 *)param_1 = uVar1;
        *(undefined1 *)((int)param_1 + 2) = 0;
        break;
      case 4:
        *param_1 = uVar5;
        break;
      case 5:
        *param_1 = uVar5;
        *(undefined1 *)(param_1 + 1) = 0;
        break;
      case 6:
        *param_1 = uVar5;
        *(ushort *)(param_1 + 1) = local_c | uVar3;
        break;
      case 7:
        *param_1 = uVar5;
        *(ushort *)(param_1 + 1) = local_c | uVar3;
        *(undefined1 *)((int)param_1 + 6) = 0;
        break;
      case 8:
        *param_1 = uVar5;
        param_1[1] = uVar6;
      }
    }
    else {
      uVar4 = 0xffffffff;
      pcVar7 = &DAT_0807b420;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar2 = *pcVar7;
        pcVar7 = pcVar7 + 1;
      } while (cVar2 != '\0');
      memcpy(param_1,&DAT_0807b420,~uVar4);
    }
  }
  return DAT_0807b620;
}



void FUN_08051160(int param_1,int param_2)

{
  FILE *pFVar1;
  int local_c;
  int local_8;
  
  if (DAT_0807b634 != (FILE *)0x0) {
    if (param_1 != 0) {
      if ((param_2 != 0) && (DAT_0807b634 == stdout)) {
        local_c = param_1;
        local_8 = param_2;
        pFVar1 = DAT_08084dc4;
        if (DAT_08084dc4 == (FILE *)0x0) {
          pFVar1 = DAT_0807b634;
        }
        (*DAT_08084dc0)(pFVar1,2,&local_c);
        return;
      }
      if (param_1 != 0) {
        fprintf(DAT_0807b634,"%s:",(char *)param_1);
      }
    }
    if (param_2 != 0) {
      fprintf(DAT_0807b634,"\t%s",(char *)param_2);
    }
    if ((param_1 != 0) && (param_2 != 0)) {
      fprintf(DAT_0807b634,"\n");
    }
  }
  return;
}



void FUN_080511fc(void)

{
  if ((DAT_0807b634 != (FILE *)0x0) && (DAT_0807b634 != stdout)) {
    fprintf(DAT_0807b634,"\n");
    fclose(DAT_0807b634);
    DAT_0807b634 = (FILE *)0x0;
  }
  return;
}



void FUN_08051240(void)

{
  uint *puVar1;
  uint __n;
  long __off;
  
  DAT_0807c798 = (uint *)0x0;
  DAT_0807c794 = (uint *)0x0;
  DAT_0807c7a0 = (uint *)0x0;
  DAT_0807c79c = (uint *)0x0;
  if (DAT_08082654 == 0) {
    DAT_0807c654 = 0;
    DAT_0807c790 = ftell(DAT_0807ff04);
    if (DAT_08082774 == 0) {
      __n = *(uint *)(DAT_0808014c + 8);
      while (__n != 0) {
        if (__n < 0x100) {
          fwrite(PTR_DAT_080795fc,1,__n,DAT_0807ff04);
          __n = 0;
        }
        else {
          fwrite(PTR_DAT_080795fc,1,0x100,DAT_0807ff04);
          __n = __n - 0x100;
        }
      }
      fseek(DAT_0807ff04,DAT_0807c790,0);
      DAT_0807c790 = DAT_0807c790 + *(int *)(DAT_0808014c + 8);
    }
  }
  else if (DAT_080825c4 == 0) {
    if (DAT_08082774 == 0) {
      if (DAT_08082778 == 0) {
        puVar1 = FUN_0805eddc(0x408);
        DAT_0807c798 = puVar1;
        DAT_0807c7a0 = puVar1;
        puVar1[1] = 0;
        *puVar1 = 0;
        __off = DAT_0807c64c;
      }
      else {
        puVar1 = FUN_0805eddc(0x408);
        DAT_0807c794 = puVar1;
        DAT_0807c79c = puVar1;
        puVar1[1] = 0;
        *puVar1 = 0;
        __off = DAT_0807c658;
      }
      fseek(DAT_0807ff04,__off,0);
    }
  }
  else {
    puVar1 = FUN_0805eddc(0x408);
    DAT_0807c794 = puVar1;
    DAT_0807c79c = puVar1;
    puVar1[1] = 0;
    *puVar1 = 0;
    puVar1 = FUN_0805eddc(0x408);
    DAT_0807c798 = puVar1;
    DAT_0807c7a0 = puVar1;
    puVar1[1] = 0;
    *puVar1 = 0;
  }
  DAT_0807c644 = 0;
  return;
}



void FUN_080513f8(undefined4 *param_1)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = (uint *)*param_1;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)*puVar2;
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  *param_1 = 0;
  return;
}



void FUN_08051424(undefined4 *param_1)

{
  for (; param_1 != (undefined4 *)0x0; param_1 = (undefined4 *)*param_1) {
    fwrite(param_1 + 2,8,param_1[1],DAT_0807ff04);
  }
  return;
}



void FUN_08051454(void)

{
  fseek(DAT_0807ff04,DAT_0807c790,0);
  if (DAT_08082654 == 0) {
    fwrite(PTR_DAT_080795fc,1,DAT_0807c654,DAT_0807ff04);
    DAT_0807c790 = DAT_0807c790 + DAT_0807c654;
  }
  else {
    FUN_08051424(DAT_0807c794);
    FUN_08051424(DAT_0807c798);
    FUN_080513f8(&DAT_0807c794);
    FUN_080513f8(&DAT_0807c798);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_080514cc(uint param_1,uint param_2,uint param_3)

{
  undefined *puVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  long __off;
  uint *puVar5;
  uint uVar6;
  uint *puVar7;
  
  uVar3 = FUN_0806d16c((param_1 | param_3) - *(int *)(DAT_0808014c + 0x10));
  uVar4 = FUN_0806d16c(param_2);
  if (DAT_08082654 == 0) {
    if (DAT_0807c654 == 0x100) {
      __off = ftell(DAT_0807ff04);
      FUN_08051454();
      DAT_0807c654 = 0;
      fseek(DAT_0807ff04,__off,0);
    }
    iVar2 = DAT_0807c654;
    puVar1 = PTR_DAT_080795fc;
    *(uint *)(PTR_DAT_080795fc + DAT_0807c654) = uVar3;
    *(uint *)(puVar1 + iVar2 + 4) = uVar4;
    DAT_0807c654 = DAT_0807c654 + 8;
  }
  else {
    puVar7 = DAT_0807c7a0;
    if (DAT_08082778 != 0) {
      puVar7 = DAT_0807c79c;
    }
    uVar6 = puVar7[1];
    puVar5 = puVar7;
    if (uVar6 == 0x80) {
      puVar5 = FUN_0805eddc(0x408);
      *puVar7 = (uint)puVar5;
      *puVar5 = 0;
      puVar5[1] = 0;
      puVar7 = puVar5;
      if (DAT_08082778 != 0) {
        DAT_0807c79c = puVar5;
        puVar7 = DAT_0807c7a0;
      }
      DAT_0807c7a0 = puVar7;
      uVar6 = puVar5[1];
    }
    puVar5[uVar6 * 2 + 2] = uVar3;
    puVar5[uVar6 * 2 + 3] = uVar4;
    puVar5[1] = puVar5[1] + 1;
  }
  if (DAT_080825c4 == 0) {
    *(int *)(DAT_0808014c + 0xc) = *(int *)(DAT_0808014c + 0xc) + 1;
  }
  else if (DAT_08082778 == 0) {
    _DAT_0808267c = _DAT_0808267c + 8;
  }
  else {
    _DAT_08082678 = _DAT_08082678 + 8;
  }
  return;
}



void FUN_08051600(void)

{
  fseek(DAT_0807ff04,DAT_0807c658,0);
  if (DAT_08082654 == 1) {
    DAT_0807c64c = DAT_0807c658 + DAT_08082664;
  }
  DAT_0807c7a4 = FUN_0805eddc(0x1008);
  DAT_0807c7ac = DAT_0807c7a4;
  DAT_0807c7a8 = FUN_0805eddc(0x1008);
  DAT_0807c7b0 = DAT_0807c7a8;
  DAT_0807c7ac[1] = 0;
  DAT_0807c7b0[1] = 0;
  *DAT_0807c7ac = 0;
  *DAT_0807c7b0 = 0;
  DAT_0807c648 = 0;
  return;
}



void FUN_08051694(undefined4 *param_1)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = (uint *)*param_1;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)*puVar2;
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  *param_1 = 0;
  return;
}



void FUN_080516c0(void)

{
  uint *puVar1;
  
  FUN_08051694(&DAT_0807c7a4);
  FUN_08051694(&DAT_0807c7a8);
  FUN_080513f8(&DAT_0807c794);
  FUN_080513f8(&DAT_0807c798);
  puVar1 = DAT_0807c650;
  while (puVar1 != (uint *)0x0) {
    DAT_0807c650 = (uint *)puVar1[7];
    FUN_0805ee14(puVar1);
    puVar1 = DAT_0807c650;
  }
  DAT_0807c650 = puVar1;
  return;
}



void FUN_08051718(undefined4 *param_1)

{
  for (; param_1 != (undefined4 *)0x0; param_1 = (undefined4 *)*param_1) {
    fwrite(param_1 + 2,1,param_1[1],DAT_0807ff04);
  }
  return;
}



void FUN_08051748(void)

{
  if (DAT_080825c4 == 1) {
    fseek(DAT_0807ff04,DAT_0807c658,0);
    *(uint *)(DAT_0807c7ac + 4) = *(int *)(DAT_0807c7ac + 4) + 3U & 0xfffffffc;
    *(uint *)(DAT_0807c7b0 + 4) = *(int *)(DAT_0807c7b0 + 4) + 3U & 0xfffffffc;
    FUN_08051718(DAT_0807c7a4);
    FUN_08051718(DAT_0807c7a8);
    FUN_08051694(&DAT_0807c7a4);
    FUN_08051694(&DAT_0807c7a8);
  }
  else {
    for (; (DAT_0807c644 & 3) != 0; DAT_0807c644 = DAT_0807c644 + 1) {
      PTR_DAT_080795f8[DAT_0807c644] = 0;
    }
  }
  if (DAT_0807c644 != 0) {
    fwrite(PTR_DAT_080795f8,1,DAT_0807c644,DAT_0807ff04);
  }
  DAT_0807c644 = 0;
  return;
}



void FUN_08051800(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = 0;
  if (0 < param_2) {
    do {
      FUN_0805182c(*(byte *)(iVar1 + param_1));
      iVar1 = iVar1 + 1;
    } while (iVar1 < param_2);
  }
  return;
}



void FUN_0805182c(byte param_1)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  
  DAT_0807c648 = 0;
  if (DAT_08082774 == 0) {
    if (DAT_080825c4 == 0) {
      PTR_DAT_080795f8[DAT_0807c644] = param_1;
      DAT_0807c644 = DAT_0807c644 + 1;
      if (DAT_0807c644 == 0x1000) {
        FUN_08051748();
      }
    }
    else {
      puVar3 = DAT_0807c7b0;
      if (DAT_08082778 != 0) {
        puVar3 = DAT_0807c7ac;
      }
      uVar2 = puVar3[1];
      puVar1 = puVar3;
      if (uVar2 == 0x1000) {
        puVar1 = FUN_0805eddc(0x1008);
        *puVar3 = (uint)puVar1;
        *puVar1 = 0;
        puVar1[1] = 0;
        puVar3 = puVar1;
        if (DAT_08082778 != 0) {
          DAT_0807c7ac = puVar1;
          puVar3 = DAT_0807c7b0;
        }
        DAT_0807c7b0 = puVar3;
        uVar2 = puVar1[1];
      }
      *(byte *)(uVar2 + 8 + (int)puVar1) = param_1;
      puVar1[1] = puVar1[1] + 1;
    }
    DAT_080826a0 = DAT_080826a0 + 1;
    FUN_080560dc(param_1);
  }
  else if (param_1 != 0) {
    FUN_08052f1c(4,"Non-zero data within uninitialised area");
  }
  return;
}



undefined4 FUN_08051910(uint param_1)

{
  int iVar1;
  char *pcVar2;
  
  if (6 < (param_1 & 0xf) - 8) {
    return 0;
  }
  if ((DAT_0807c648 & 0xe500000) == 0x8500000) {
    pcVar2 = "Use of banked R8-R14 after forced user-mode LDM";
    iVar1 = 4;
  }
  else {
    if (DAT_080826f0 != 0) {
      return 1;
    }
    pcVar2 = "Use of banked R8-R14 after in-line mode change";
    iVar1 = 3;
  }
  FUN_08052f1c(iVar1,pcVar2);
  return 1;
}



void FUN_08051964(uint param_1)

{
  int iVar1;
  
  if (DAT_080795ec != 0) {
    DAT_0807c648 = param_1;
    return;
  }
  if (((DAT_0807c648 & 0xd90f000) != 0x110f000) && ((DAT_0807c648 & 0xe508000) != 0x8500000)) {
    DAT_0807c648 = param_1;
    return;
  }
  if ((DAT_0807c648 ^ param_1) >> 0x1c == 1) {
    DAT_0807c648 = param_1;
    return;
  }
  if (((((param_1 & 0xe000010) == 0) || ((param_1 & 0xe000000) == 0x2000000)) &&
      ((param_1 & 0x1900000) != 0x1000000)) || ((param_1 & 0xfc000f0) == 0x90)) {
    iVar1 = FUN_08051910(param_1 >> 0x10);
    if (iVar1 != 0) {
      DAT_0807c648 = param_1;
      return;
    }
    iVar1 = FUN_08051910(param_1 >> 0xc);
    if (iVar1 != 0) {
      DAT_0807c648 = param_1;
      return;
    }
  }
  if (((((param_1 & 0xfb00ff0) == 0x1000090) || ((param_1 & 0xc000000) == 0x4000000)) ||
      ((param_1 & 0xa000000) == 0x8000000)) && (iVar1 = FUN_08051910(param_1 >> 0x10), iVar1 != 0))
  {
    DAT_0807c648 = param_1;
    return;
  }
  if ((((param_1 & 0xe000090) == 0x10) || ((param_1 & 0xfc000f0) == 0x90)) &&
     (iVar1 = FUN_08051910(param_1 >> 0xc), iVar1 != 0)) {
    DAT_0807c648 = param_1;
    return;
  }
  if (((param_1 & 0xe000010) == 0) || ((param_1 & 0xe000000) == 0x6000000)) {
    FUN_08051910(param_1);
  }
  DAT_0807c648 = param_1;
  return;
}



void FUN_08051a9c(uint param_1,int param_2)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  if (param_2 == 0) {
    while ((DAT_080826a0 & 3) != 0) {
      FUN_0805182c(0);
    }
  }
  puVar4 = (uint *)(PTR_DAT_080795f8 + DAT_0807c644);
  if (DAT_08082774 == 0) {
    if (DAT_080825c4 == 0) {
      if (param_2 == 0) {
        uVar2 = FUN_0806d16c(param_1);
        *puVar4 = uVar2;
        DAT_0807c644 = DAT_0807c644 + 4;
      }
      else {
        uVar2 = FUN_0806d1a4(param_1);
        *(short *)puVar4 = (short)uVar2;
        DAT_0807c644 = DAT_0807c644 + 2;
      }
      if (0xfff < DAT_0807c644) {
        fwrite(PTR_DAT_080795f8,1,0x1000,DAT_0807ff04);
        DAT_0807c644 = DAT_0807c644 - 0x1000;
        uVar2 = 0;
        do {
          PTR_DAT_080795f8[uVar2] = PTR_DAT_080795f8[uVar2 + 0x1000];
          uVar2 = uVar2 + 1;
        } while (uVar2 < 4);
      }
    }
    else {
      puVar4 = DAT_0807c7b0;
      if (DAT_08082778 != 0) {
        puVar4 = DAT_0807c7ac;
      }
      puVar3 = puVar4;
      puVar1 = DAT_0807c7b0;
      if (0xfff < puVar4[1]) {
        puVar3 = FUN_0805eddc(0x1008);
        *puVar4 = (uint)puVar3;
        *puVar3 = 0;
        puVar3[1] = 0;
        puVar1 = puVar3;
        if (DAT_08082778 != 0) {
          DAT_0807c7ac = puVar3;
          puVar1 = DAT_0807c7b0;
        }
      }
      DAT_0807c7b0 = puVar1;
      uVar2 = FUN_0806d16c(param_1);
      *(uint *)((int)puVar3 + puVar3[1] + 8) = uVar2;
      puVar3[1] = puVar3[1] + 4;
    }
    if (param_2 == 0) {
      DAT_080826a0 = DAT_080826a0 + 4;
    }
    else {
      DAT_080826a0 = DAT_080826a0 + 2;
    }
    FUN_080560a0(param_1);
  }
  else if (param_1 != 0) {
    FUN_08052f1c(4,"Non-zero data within uninitialised area");
  }
  return;
}



void FUN_08051c18(uint param_1)

{
  if (DAT_08082778 != 0) {
    FUN_08051964(param_1);
  }
  FUN_08051a9c(param_1,0);
  return;
}



void FUN_08051c40(uint param_1)

{
  if (DAT_08082778 != 0) {
    FUN_08051964(param_1);
  }
  FUN_08051a9c(param_1,1);
  return;
}



void FUN_08051c68(uint param_1)

{
  DAT_0807c648 = 0;
  FUN_08051a9c(param_1,0);
  return;
}



void FUN_08051c84(uint param_1,int param_2)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  
  if (param_2 == 0) {
    FUN_08051c68(param_1);
  }
  else {
    bVar1 = (byte)(param_1 >> 8);
    bVar2 = (byte)(param_1 >> 0x10);
    bVar3 = (byte)(param_1 >> 0x18);
    if (DAT_0808269c == 0) {
      FUN_0805182c((byte)param_1);
      FUN_0805182c(bVar1);
      FUN_0805182c(bVar2);
      FUN_0805182c(bVar3);
    }
    else {
      FUN_0805182c(bVar3);
      FUN_0805182c(bVar2);
      FUN_0805182c(bVar1);
      FUN_0805182c((byte)param_1);
    }
  }
  return;
}



undefined4 FUN_08051d0c(void)

{
  return DAT_0807c648;
}



undefined4 FUN_08051d18(int param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = DAT_0807c650;
  while( true ) {
    if (iVar2 == 0) {
      FUN_08052f1c(5,"Area number out of range");
      return 0;
    }
    param_1 = param_1 + -1;
    if (param_1 == 0) break;
    iVar2 = *(int *)(iVar2 + 0x1c);
  }
  uVar1 = (*(undefined4 **)(iVar2 + 0x18))[1];
  *param_2 = **(undefined4 **)(iVar2 + 0x18);
  param_2[1] = uVar1;
  return *(undefined4 *)(iVar2 + 0x10);
}



int FUN_08051d60(uint param_1)

{
  int iVar1;
  
  iVar1 = DAT_0807c650;
  if (DAT_0807c650 != 0) {
    do {
      if (param_1 < 2) break;
      iVar1 = *(int *)(iVar1 + 0x1c);
      param_1 = param_1 - 1;
    } while (iVar1 != 0);
    if (iVar1 != 0) {
      return iVar1;
    }
  }
  FUN_08052f1c(5,"Area number out of range");
  return 0;
}



void FUN_08051d94(int *param_1)

{
  param_1[5] = DAT_08082690;
  param_1[6] = DAT_08082648;
  DAT_08082648 = DAT_08082648 + 1;
  DAT_08082690 = DAT_08082690 + 1 + *param_1;
  return;
}



void FUN_08051dc0(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  if (DAT_08082654 == 0) {
    puVar3 = (undefined4 *)(DAT_08082648 * 0x10 + DAT_0807ff00);
    DAT_08082648 = DAT_08082648 + 1;
    puVar3[2] = param_2;
    *puVar3 = param_1;
    puVar3[1] = 0;
    puVar2 = (undefined4 *)FUN_08051d60(DAT_0808276c);
    puVar3[3] = *puVar2;
    uVar1 = puVar3[1];
    puVar3[1] = uVar1 | 1;
    if (DAT_080795ec == 1) {
      puVar3[1] = uVar1 | 0x1001;
    }
  }
  return;
}



void FUN_08051e28(undefined4 param_1)

{
  FUN_08051dc0(param_1,DAT_080826a0);
  return;
}



void FUN_08051e3c(int param_1,size_t param_2,void *param_3,int param_4,int param_5)

{
  byte bVar1;
  undefined1 uVar2;
  undefined4 *puVar3;
  uint uVar4;
  int iVar5;
  undefined4 *puVar6;
  
  DAT_080825d4 = 1;
  if (DAT_08082654 == 0) {
    puVar6 = (undefined4 *)(*(int *)(param_1 + 0x18) * 0x10 + DAT_0807ff00);
    puVar6[2] = *(undefined4 *)(param_1 + 0xc);
    *puVar6 = *(undefined4 *)(param_1 + 0x14);
    puVar6[1] = 0;
    if (((*(byte *)(param_1 + 8) & 3) == 0) || ((*(uint *)(param_1 + 8) & 0x40000003) == 0x40000001)
       ) {
      puVar3 = (undefined4 *)FUN_08051d60(*(uint *)(param_1 + 0x1c));
      puVar6[3] = *puVar3;
      uVar4 = puVar6[1];
      puVar6[1] = uVar4 | 1;
      if ((*(byte *)(param_1 + 9) >> 4 & 3) == 1) {
        puVar6[1] = uVar4 | 5;
      }
    }
    else {
      puVar6[3] = 0;
    }
    if (param_4 != 0) {
      uVar4 = puVar6[1];
      puVar6[1] = uVar4 | 2;
      if (((uVar4 & 1) == 0) && ((*(byte *)(param_1 + 10) & 0x10) == 0)) {
        puVar6[1] = uVar4 | 0x12;
      }
    }
    if (param_5 != 0) {
      *(byte *)(puVar6 + 1) = *(byte *)(puVar6 + 1) | 0x10;
    }
    if ((puVar6[1] & 0x10) != 0) {
      puVar6[2] = 0;
    }
    uVar4 = (*(ushort *)(param_1 + 8) >> 6 & 0xf) << 8 | puVar6[1];
    puVar6[1] = uVar4;
    bVar1 = *(byte *)(param_1 + 0xb);
    if ((bVar1 & 0x10) != 0) {
      puVar6[1] = uVar4 | 0x1000;
      bVar1 = *(byte *)(param_1 + 0xb);
    }
    if ((bVar1 & 0x20) != 0) {
      *(byte *)((int)puVar6 + 5) = *(byte *)((int)puVar6 + 5) | 1;
      bVar1 = *(byte *)(param_1 + 0xb);
    }
    if ((bVar1 & 0x40) != 0) {
      *(byte *)(puVar6 + 1) = *(byte *)(puVar6 + 1) | 0x20;
    }
    goto LAB_08052000;
  }
  puVar6 = (undefined4 *)(DAT_0807ff10 + *(int *)(param_1 + 0x18) * 0xc);
  puVar6[2] = *(undefined4 *)(param_1 + 0xc);
  *puVar6 = *(undefined4 *)(param_1 + 0x14);
  *(undefined1 *)((int)puVar6 + 5) = 0;
  *(undefined2 *)((int)puVar6 + 6) = 0;
  if ((*(byte *)(param_1 + 8) & 3) == 0) {
    if ((*(byte *)(param_1 + 9) >> 4 & 3) == 1) {
      *(undefined1 *)(puVar6 + 1) = 2;
    }
    else {
      if (DAT_080825c4 == 0) {
        iVar5 = FUN_08051d60(*(uint *)(param_1 + 0x1c));
        if ((*(uint *)(iVar5 + 4) & 0x200) == 0) {
          if ((*(uint *)(iVar5 + 4) & 0x1000) == 0) goto LAB_08051fd3;
LAB_08051fc1:
          uVar2 = 8;
        }
        else {
LAB_08051fd7:
          uVar2 = 4;
        }
      }
      else {
        if (DAT_080826f8 == 0) goto LAB_08051fd7;
        if (DAT_080826f8 != 1) goto LAB_08051fc1;
LAB_08051fd3:
        uVar2 = 6;
      }
      *(undefined1 *)(puVar6 + 1) = uVar2;
    }
  }
  else {
    *(undefined1 *)(puVar6 + 1) = 0;
  }
  if (param_4 != 0) {
    *(byte *)(puVar6 + 1) = *(byte *)(puVar6 + 1) | 1;
  }
  if (param_5 != 0) {
    FUN_08052f1c(4,"Weak symbols not permitted in a.out");
    return;
  }
LAB_08052000:
  iVar5 = *(int *)(param_1 + 0x14);
  memcpy((void *)(iVar5 + DAT_0807ff08),param_3,param_2);
  *(undefined1 *)(iVar5 + param_2 + DAT_0807ff08) = 0;
  return;
}



void FUN_0805202c(int *param_1,int param_2,int param_3)

{
  uint *puVar1;
  uint *puVar2;
  
  if (DAT_080825d0 == 1) {
    puVar2 = (uint *)&DAT_0807c650;
    for (puVar1 = DAT_0807c650; puVar1 != (uint *)0x0; puVar1 = (uint *)puVar1[7]) {
      puVar2 = puVar1 + 7;
    }
    puVar1 = FUN_0805eddc(0x20);
    *puVar2 = (uint)puVar1;
    DAT_08080150 = DAT_08080150 + 1;
    puVar1[7] = 0;
    puVar1[1] = param_3 + param_2;
    puVar1[4] = 0;
    puVar1[6] = (uint)param_1;
    if ((*(byte *)((int)param_1 + 0xb) & 0x80) == 0) {
      if (param_1[6] == -0x80000000) {
        *puVar1 = DAT_08082690;
        FUN_08051d94(param_1);
      }
      else {
        *puVar1 = param_1[5];
      }
    }
    else {
      *puVar1 = DAT_08082690;
      DAT_08082690 = DAT_08082690 + 1 + *param_1;
    }
    puVar1[3] = 0;
    puVar1[5] = DAT_080795ec;
    DAT_0808014c = puVar1;
    if (DAT_08082640 == 0) {
      *(byte *)((int)puVar1 + 5) = *(byte *)((int)puVar1 + 5) | 1;
      puVar1[4] = DAT_080826a0;
    }
    DAT_080826c8 = DAT_080826c8 + 1;
  }
  else if (DAT_080825d0 == 2) {
    puVar2 = DAT_0807c650;
    if ((DAT_0808014c != (uint *)0x0) && ((uint *)DAT_0808014c[7] != (uint *)0x0)) {
      puVar2 = (uint *)DAT_0808014c[7];
    }
    DAT_08082774 = puVar2[1] >> 0xc & 1;
    DAT_080795ec = puVar2[5];
    DAT_0808014c = puVar2;
  }
  DAT_08082778 = DAT_0808014c[1] >> 9 & 1;
  return;
}



undefined4 FUN_08052154(void)

{
  uint *puVar1;
  undefined4 uVar2;
  
  puVar1 = FUN_0805f5ec(7,"$$$$$$$",0);
  if ((puVar1 == (uint *)0x0) || ((*(byte *)((int)puVar1 + 10) & 0xc) != 0)) {
    FUN_08052f1c(4,"Multiply or incompatibly defined symbol");
    uVar2 = 0;
  }
  else {
    FUN_08052f1c(3,"Faking declaration of area AREA |$$$$$$$|");
    FUN_08058c78((int)puVar1);
    DAT_0808276c = 1;
    puVar1[7] = 1;
    *(byte *)((int)puVar1 + 9) = *(byte *)((int)puVar1 + 9) & 0xcf;
    *(byte *)((int)puVar1 + 10) = *(byte *)((int)puVar1 + 10) | 0xc;
    *(byte *)(puVar1 + 2) = (byte)puVar1[2] & 0xfc;
    puVar1[4] = 0;
    puVar1[3] = DAT_080826a0;
    FUN_0805202c((int *)puVar1,2,0x200);
    uVar2 = 1;
  }
  return uVar2;
}



void FUN_080521e8(void)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = DAT_0807c650;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)puVar2[7];
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  DAT_0807c650 = (uint *)0x0;
  DAT_0808014c = 0;
  DAT_080826f8 = 0;
  DAT_08082778 = 1;
  DAT_08082704 = 0;
  DAT_08082618 = 0;
  DAT_0808268c = 0;
  DAT_08080150 = 0;
  DAT_08082628 = 0;
  return;
}



void FUN_08052268(void)

{
  DAT_0808014c = 0;
  DAT_080826f8 = 0;
  DAT_08082778 = 1;
  DAT_08082704 = 0;
  DAT_08082618 = 0;
  DAT_0808268c = 0;
  return;
}



// WARNING: Removing unreachable block (ram,0x080523b0)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_080522ac(void)

{
  int iVar1;
  uint uVar2;
  uint local_8;
  
  DAT_0807c660 = ftell(DAT_0807ff04);
  if (DAT_08082654 == 0) {
    fseek(DAT_0807ff04,0x1c,0);
    DAT_0807c780 = 'O';
    DAT_0807c780_1._0_1_ = 'B';
    DAT_0807c780_1._1_1_ = 'J';
    DAT_0807c780_1._2_1_ = '_';
    DAT_0807c784._0_1_ = 'A';
    DAT_0807c784._1_1_ = 'R';
    DAT_0807c784._2_1_ = 'E';
    DAT_0807c784._3_1_ = 'A';
    _DAT_0807c788 = FUN_0806d16c(DAT_0807c658);
    _DAT_0807c78c = FUN_0806d16c(DAT_0807c660 - DAT_0807c658);
    fwrite(&DAT_0807c780,1,0x10,DAT_0807ff04);
    fseek(DAT_0807ff04,DAT_0807c660,0);
    uVar2 = 0;
    if ((DAT_08082648 & 0x3fffffff) != 0) {
      do {
        iVar1 = uVar2 * 4;
        uVar2 = uVar2 + 1;
        local_8 = FUN_0806d16c(*(uint *)(DAT_0807ff00 + iVar1));
        fwrite(&local_8,1,4,DAT_0807ff04);
      } while (uVar2 < DAT_08082648 * 4);
    }
  }
  else {
    fwrite(DAT_0807ff10,1,DAT_08082648 * 0xc,DAT_0807ff04);
  }
  DAT_0807c664 = ftell(DAT_0807ff04);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08052408(void)

{
  for (; (DAT_08082690 & 3) != 0; DAT_08082690 = DAT_08082690 + 1) {
    *(undefined1 *)(DAT_08082690 + (int)DAT_0807ff08) = 0;
  }
  fwrite(DAT_0807ff08,1,DAT_08082690,DAT_0807ff04);
  DAT_0807c668 = ftell(DAT_0807ff04);
  if (DAT_08082654 == 0) {
    fprintf(DAT_0807ff04,"%s%s vsn %s%s%c","ARM AOF"," Macro Assembler","2.50 (ARM Ltd SDT2.51)","",
            '\0');
    for (DAT_0807c66c = ftell(DAT_0807ff04); (DAT_0807c66c & 3) != 0;
        DAT_0807c66c = DAT_0807c66c + 1) {
      fputc(0,DAT_0807ff04);
    }
    fseek(DAT_0807ff04,0x2c,0);
    _DAT_0807c780 = 0x5f4a424f;
    DAT_0807c784 = 0x544d5953;
    _DAT_0807c788 = FUN_0806d16c(DAT_0807c660);
    _DAT_0807c78c = FUN_0806d16c(DAT_0807c664 - DAT_0807c660);
    fwrite(&DAT_0807c780,1,0x10,DAT_0807ff04);
    DAT_0807c780 = 'O';
    DAT_0807c780_1._0_1_ = 'B';
    DAT_0807c780_1._1_1_ = 'J';
    DAT_0807c780_1._2_1_ = '_';
    DAT_0807c784._0_1_ = 'S';
    DAT_0807c784._1_1_ = 'T';
    DAT_0807c784._2_1_ = 'R';
    DAT_0807c784._3_1_ = 'T';
    _DAT_0807c788 = FUN_0806d16c(DAT_0807c664);
    _DAT_0807c78c = FUN_0806d16c(DAT_0807c668 - DAT_0807c664);
    fwrite(&DAT_0807c780,1,0x10,DAT_0807ff04);
    _DAT_0807c780 = 0x5f4a424f;
    DAT_0807c784 = 0x4e464449;
    _DAT_0807c788 = FUN_0806d16c(DAT_0807c668);
    _DAT_0807c78c = FUN_0806d16c(DAT_0807c66c - DAT_0807c668);
    fwrite(&DAT_0807c780,1,0x10,DAT_0807ff04);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x08052710)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_080525c8(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint local_28 [6];
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_10 = FUN_0806d16c(0xc3cbc6c5);
  local_c = FUN_0806d16c(7);
  local_8 = FUN_0806d16c(5);
  if (DAT_08082654 == 0) {
    fseek(DAT_0807ff04,0,0);
    fwrite(&local_10,1,0xc,DAT_0807ff04);
    DAT_0807c780 = 'O';
    DAT_0807c780_1._0_1_ = 'B';
    DAT_0807c780_1._1_1_ = 'J';
    DAT_0807c780_1._2_1_ = '_';
    DAT_0807c784._0_1_ = 'H';
    DAT_0807c784._1_1_ = 'E';
    DAT_0807c784._2_1_ = 'A';
    DAT_0807c784._3_1_ = 'D';
    _DAT_0807c788 = FUN_0806d16c(0x7c);
    _DAT_0807c78c = FUN_0806d16c(DAT_080826c8 * 0x14 + 0x18);
    uVar2 = 1;
    do {
      fwrite(&DAT_0807c780,1,0x10,DAT_0807ff04);
      uVar2 = uVar2 + 1;
    } while (uVar2 < 6);
    DAT_0807c780 = 'U';
    DAT_0807c780_1._0_1_ = 'n';
    DAT_0807c780_1._1_1_ = 'u';
    DAT_0807c780_1._2_1_ = 's';
    DAT_0807c784._0_1_ = 'e';
    DAT_0807c784._1_1_ = 'd';
    DAT_0807c784._2_1_ = ' ';
    DAT_0807c784._3_1_ = ' ';
    _DAT_0807c788 = 0;
    _DAT_0807c78c = 0;
    uVar2 = 1;
    do {
      fwrite(&DAT_0807c780,1,0x10,DAT_0807ff04);
      uVar2 = uVar2 + 1;
    } while (uVar2 < 3);
    uVar2 = 0;
    iVar3 = 0;
    do {
      uVar1 = FUN_0806d16c(*(uint *)((int)&DAT_080826c0 + iVar3));
      *(uint *)((int)local_28 + iVar3) = uVar1;
      iVar3 = iVar3 + 4;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 6);
    fwrite(local_28,1,0x18,DAT_0807ff04);
    DAT_0807c65c = ftell(DAT_0807ff04);
    for (uVar2 = 1; uVar2 <= (uint)(DAT_080826c8 * 0x14); uVar2 = uVar2 + 1) {
      fputc(0,DAT_0807ff04);
    }
    DAT_0807c658 = DAT_0807c65c + DAT_080826c8 * 0x14;
    DAT_0807c790 = DAT_0807c658;
  }
  else {
    fseek(DAT_0807ff04,0,0);
    fwrite(&DAT_08082660,1,0x20,DAT_0807ff04);
    DAT_0807c65c = ftell(DAT_0807ff04);
    for (uVar2 = 1; uVar2 <= (uint)(DAT_08082668 + DAT_08082664); uVar2 = uVar2 + 1) {
      fputc(0,DAT_0807ff04);
    }
    DAT_0807c790 = ftell(DAT_0807ff04);
    fseek(DAT_0807ff04,DAT_0807c65c,0);
    DAT_0807c658 = DAT_0807c65c;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08052818(void)

{
  size_t __n;
  long __off;
  uint uVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  uint local_18 [5];
  
  __off = ftell(DAT_0807ff04);
  if (DAT_08082654 == 0) {
    fseek(DAT_0807ff04,DAT_0807c65c,0);
    if (DAT_0807c650 != (int *)0x0) {
      piVar4 = DAT_0807c650;
      do {
        uVar3 = 0;
        iVar2 = 0;
        do {
          uVar1 = FUN_0806d16c(*(uint *)((int)piVar4 + iVar2));
          *(uint *)((int)local_18 + iVar2) = uVar1;
          iVar2 = iVar2 + 4;
          uVar3 = uVar3 + 1;
        } while (uVar3 < 5);
        fwrite(local_18,1,0x14,DAT_0807ff04);
        __n = *(size_t *)piVar4[6];
        iVar2 = *piVar4;
        memcpy((void *)(iVar2 + DAT_0807ff08),(void *)((size_t *)piVar4[6])[1],__n);
        *(undefined1 *)(iVar2 + __n + DAT_0807ff08) = 0;
        piVar4 = (int *)piVar4[7];
      } while (piVar4 != (int *)0x0);
    }
  }
  else {
    if ((DAT_080825c4 == 0) && (uVar3 = 1, DAT_0808276c != 0)) {
      do {
        iVar2 = FUN_08051d60(uVar3);
        if ((*(uint *)(iVar2 + 4) & 0x200) == 0) {
          if ((*(uint *)(iVar2 + 4) & 0x1000) == 0) {
            _DAT_0808267c = *(int *)(iVar2 + 0xc) << 3;
          }
        }
        else {
          _DAT_08082678 = *(int *)(iVar2 + 0xc) << 3;
        }
        uVar3 = uVar3 + 1;
      } while (uVar3 <= DAT_0808276c);
    }
    fseek(DAT_0807ff04,0,0);
    fwrite(&DAT_08082660,1,0x20,DAT_0807ff04);
  }
  fseek(DAT_0807ff04,__off,0);
  return;
}



undefined4 FUN_08052960(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if (DAT_0807e7c0 < 0x100) {
    puVar3 = &DAT_0807c7c0 + DAT_0807e7c0 * 8;
    for (iVar2 = 8; register0x00000010 = (BADSPACEBASE *)((int)register0x00000010 + 4), iVar2 != 0;
        iVar2 = iVar2 + -1) {
      *puVar3 = *(undefined4 *)register0x00000010;
      puVar3 = puVar3 + 1;
    }
    DAT_0807e7c0 = DAT_0807e7c0 + 1;
    uVar1 = 1;
  }
  else {
    FUN_08052f1c(4,"Structure stack overflow");
    DAT_08079804 = 2;
    uVar1 = 0;
  }
  return uVar1;
}



undefined4 FUN_080529b4(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if (DAT_0807e7c0 == 0) {
    FUN_08052f1c(4,"Structure stack underflow");
    DAT_08079804 = 3;
    uVar1 = 0;
  }
  else {
    DAT_0807e7c0 = DAT_0807e7c0 + -1;
    puVar3 = &DAT_0807c7c0 + DAT_0807e7c0 * 8;
    for (iVar2 = 8; iVar2 != 0; iVar2 = iVar2 + -1) {
      *param_1 = *puVar3;
      puVar3 = puVar3 + 1;
      param_1 = param_1 + 1;
    }
    uVar1 = 1;
  }
  return uVar1;
}



undefined4 FUN_08052a04(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if (DAT_0807e7c0 == 0) {
    uVar1 = 0;
  }
  else {
    puVar3 = &DAT_0807c7a0 + DAT_0807e7c0 * 8;
    for (iVar2 = 8; iVar2 != 0; iVar2 = iVar2 + -1) {
      *param_1 = *puVar3;
      puVar3 = puVar3 + 1;
      param_1 = param_1 + 1;
    }
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_08052a3c(void)

{
  int iVar1;
  uint uVar2;
  
  DAT_08080154 = 1;
  uVar2 = 0;
  iVar1 = 0;
  do {
    *(undefined4 *)((int)&DAT_0807c7c0 + iVar1) = 0;
    iVar1 = iVar1 + 0x20;
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x100);
  DAT_0807e7c0 = 0;
  return;
}



void FUN_08052a74(void)

{
  FUN_08052a3c();
  return;
}



void FUN_08052a80(void)

{
  DAT_0807e7c4 = DAT_0807e7c0;
  return;
}



undefined4 FUN_08052a90(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  do {
    if (DAT_0807e7c4 == 0) {
      DAT_0807e7c4 = 0;
      return 0;
    }
    DAT_0807e7c4 = DAT_0807e7c4 + -1;
  } while ((&DAT_0807c7c0)[DAT_0807e7c4 * 8] != 3);
  puVar2 = &DAT_0807c7c0 + DAT_0807e7c4 * 8;
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_1 = *puVar2;
    puVar2 = puVar2 + 1;
    param_1 = param_1 + 1;
  }
  return 1;
}



int __regparm3 FUN_08052ae0(int param_1)

{
  while ((DAT_0807e7c0 != 0 && (param_1 = (&DAT_0807c7c0)[(DAT_0807e7c0 + -1) * 8], param_1 != 2)))
  {
    if (param_1 == 3) {
      DAT_08082780 = DAT_08082780 + -1;
      FUN_08057550();
    }
    DAT_0807e7c0 = DAT_0807e7c0 + -1;
    param_1 = 0;
  }
  return param_1;
}



void FUN_08052b24(void)

{
  DAT_0807e7c8 = DAT_0807e7c0;
  return;
}



undefined4 * FUN_08052b34(void)

{
  do {
    if (DAT_0807e7c8 == 0) {
      DAT_0807e7c8 = 0;
      return (undefined4 *)0x0;
    }
    DAT_0807e7c8 = DAT_0807e7c8 + -1;
  } while ((&DAT_0807c7c0)[DAT_0807e7c8 * 8] != 2);
  return &DAT_0807c7c0 + DAT_0807e7c8 * 8;
}



void FUN_08052b80(int param_1)

{
  char *param6;
  char *param2;
  uint param3;
  char *param5;
  
  if (DAT_08084dc8 == (FILE *)0x0) {
    (*DAT_08084dc0)(DAT_08084dc4,1,param_1);
  }
  else {
    param6 = *(char **)(param_1 + 8);
    switch(*(undefined2 *)(param_1 + 0xc)) {
    case 0:
    case 1:
      param5 = "";
      break;
    case 2:
      param5 = "Warning: ";
      break;
    default:
      param5 = "Fatal error: ";
      break;
    case 4:
      param5 = "Error: ";
    }
    param2 = *(char **)(param_1 + 4);
    if ((param2 == (char *)0x0) || (param3 = *(uint *)(param_1 + 0x10), param3 == 0xffffffff)) {
      fprintf(DAT_08084dc8,"%s%s\n",param5,param6);
    }
    else if (*(short *)(param_1 + 0xe) == -1) {
      fprintf(DAT_08084dc8,"\"%s\", line %u: %s%s\n",param2,param3,param5,param6);
    }
    else {
      fprintf(DAT_08084dc8,"\"%s\", line %u (column %u): %s%s\n",param2,param3,
              (uint)*(ushort *)(param_1 + 0xe),param5,param6);
    }
  }
  return;
}



void FUN_08052c2c(int param_1,int param_2,undefined4 param_3,char *param_4,__gnuc_va_list param_5)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  ulong param2;
  char *local_148;
  char *local_13c;
  undefined1 *local_138;
  char *local_134;
  undefined2 local_130;
  undefined2 local_12e;
  ulong local_12c;
  undefined4 local_128;
  undefined4 local_124 [3];
  ulong local_118;
  int local_114;
  char *local_110;
  char local_104 [256];
  
  if ((param_1 != 3) || (DAT_08080158 = DAT_08080158 + 1, DAT_08080164 == 0)) {
    if (param_1 == 0) {
      local_13c = (char *)0x0;
      local_134 = param_4;
      param_1 = 1;
    }
    else {
      vsprintf(local_104,param_4,param_5);
      local_13c = s_armasm_08079858;
      local_134 = local_104;
    }
    local_138 = (undefined1 *)0x0;
    local_12c = 0xffffffff;
    local_12e = 0xffff;
    local_128 = 0xffffffff;
    if (param_1 == 1) {
      local_130 = 1;
      (*DAT_08084dc0)(DAT_08084dc4,1,&local_13c);
    }
    else {
      if (param_1 == 2) {
        local_130 = 1;
      }
      else if (param_1 == 3) {
        local_130 = 2;
      }
      else if (param_1 == 4) {
        local_130 = 4;
      }
      else {
        local_130 = 5;
      }
      FUN_08052a80();
      local_12c = DAT_08082594;
      while (iVar2 = FUN_08052a90(local_124), iVar2 != 0) {
        local_12c = local_118;
      }
      if ((local_12c != 0xffffffff) && (param_2 != 0)) {
        local_12e = (undefined2)param_2;
      }
      local_138 = &DAT_0807ff20;
      FUN_08052b80((int)&local_13c);
      if (param_1 != 2) {
        FUN_08052a80();
        local_138 = (undefined1 *)0x0;
        local_12c = 0xffffffff;
        local_12e = 0xffff;
        local_130 = 0;
        param2 = DAT_08082594;
        while (iVar2 = FUN_08052a90(local_124), iVar2 != 0) {
          sprintf(local_104,"    at line %lu in macro %.*s\n",param2,local_114,local_110);
          FUN_08052b80((int)&local_13c);
          param2 = local_118;
        }
        FUN_08052b24();
        while (puVar3 = FUN_08052b34(), puVar3 != (undefined4 *)0x0) {
          sprintf(local_104,"    included by GET/INCLUDE directive from \"%s\", line %lu\n",
                  (char *)puVar3[5],puVar3[3]);
          FUN_08052b80((int)&local_13c);
        }
        if (DAT_0807ff0c != 0) {
          cVar1 = *DAT_08082584;
          local_148 = DAT_08082584;
          for (iVar2 = 0; (cVar1 != '\r' && (local_148 = local_148 + 1, iVar2 + 0x20U < 0xff));
              iVar2 = iVar2 + 1) {
            cVar1 = *local_148;
          }
          sprintf(local_104,"%5lu %.8lx %.*s",DAT_08082594,DAT_080826a0,iVar2,DAT_08082584);
          if (local_104[0] != '\0') {
            FUN_08052b80((int)&local_13c);
          }
        }
      }
    }
    if (param_1 - 4U < 2) {
      DAT_08080160 = 1;
      DAT_08080168 = DAT_08080168 + 1;
      if ((0x32 < DAT_08080168) || (param_1 == 5)) {
        FUN_08055af8();
        FUN_08052f7c();
        FUN_080615f0(8);
      }
    }
  }
  return;
}



void FUN_08052f1c(int param_1,char *param_2)

{
  FUN_08052c2c(param_1,0,0,param_2,&stack0x0000000c);
  return;
}



void FUN_08052f34(int param_1,int param_2,char *param_3)

{
  FUN_08052c2c(param_1,param_2,0,param_3,&stack0x00000010);
  return;
}



void FUN_08052f50(char *param_1)

{
  FUN_08052c2c(1,0,1,param_1,&stack0x00000008);
  return;
}



void __regparm1 FUN_08052f68(__gnuc_va_list param_1,char *param_2)

{
  FUN_08052c2c(0,0,1,param_2,param_1);
  return;
}



void FUN_08052f7c(void)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  char *pcVar5;
  char local_11c [256];
  char *local_1c;
  undefined4 local_18;
  char *local_14;
  undefined2 local_10;
  undefined2 local_e;
  undefined4 local_c;
  undefined4 local_8;
  
  if ((DAT_08080168 == 0) && (DAT_08080158 == 0)) {
    return;
  }
  local_10 = 1;
  local_1c = s_armasm_08079858;
  local_18 = 0;
  local_c = 0xffffffff;
  local_e = 0xffff;
  local_8 = 0xffffffff;
  local_14 = local_11c;
  sprintf(local_11c,"Assembly terminated:\n");
  uVar2 = 0xffffffff;
  pcVar4 = local_11c;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  pcVar4 = local_11c + (~uVar2 - 1);
  if (DAT_08080168 == 0) {
    pcVar5 = "0 Errors, ";
LAB_0805300c:
    sprintf(pcVar4,pcVar5);
  }
  else {
    if (DAT_08080168 == 1) {
      pcVar5 = "1 Error, ";
      goto LAB_0805300c;
    }
    sprintf(pcVar4,"%ld Errors, ",DAT_08080168);
  }
  uVar3 = 0xffffffff;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  pcVar4 = local_11c + ~uVar3 + ~uVar2 + -2;
  if (DAT_08080158 == 0) {
    pcVar5 = "0 Warnings";
  }
  else {
    if (DAT_08080158 != 1) {
      sprintf(pcVar4,"%ld Warnings",DAT_08080158);
      goto LAB_08053076;
    }
    pcVar5 = "1 Warning";
  }
  sprintf(pcVar4,pcVar5);
LAB_08053076:
  uVar2 = 0xffffffff;
  pcVar5 = pcVar4;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  if ((DAT_08080164 != 0) && (DAT_08080158 != 0)) {
    sprintf(pcVar4 + (~uVar2 - 1)," suppressed by -NOWarn");
  }
  FUN_08052b80((int)&local_1c);
  return;
}



void FUN_080530c0(char *param_1,int *param_2)

{
  uint local_8;
  
  FUN_080534cc(param_1,param_2,0,&local_8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_080530dc(char *param_1,int *param_2,int param_3,uint *param_4,int param_5)

{
  int iVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  undefined3 extraout_var;
  uint uVar5;
  int iVar6;
  char *pcVar7;
  uint local_430;
  int local_42c;
  int local_428;
  uint local_424;
  undefined1 local_404 [1024];
  
  FUN_0805440c(local_404,0x400);
  FUN_08060dd4();
  *param_4 = 1;
  _DAT_08080180 = 0;
  _DAT_08080184 = 0;
  local_430 = 0;
  iVar6 = 0;
  uVar4 = 0;
  do {
    while( true ) {
      uVar5 = uVar4;
      iVar1 = *param_2;
      DAT_0807e9e0 = iVar6 + 1;
      FUN_08060384(param_1,param_2,(undefined4 *)(&DAT_08080180 + (iVar6 * 9 + 9) * 4),&local_42c);
      iVar6 = DAT_0807e9e0;
      if (DAT_08080160 != 0) {
        return;
      }
      iVar3 = DAT_0807e9e0 * 0x24;
      if (*(int *)(&DAT_08080180 + iVar3) != 0) break;
      if (*(int *)(&DAT_08080184 + iVar3) == 0xd) {
        *(undefined4 *)(&DAT_08080184 + iVar3) = 0x1c;
      }
      else if (*(int *)(&DAT_08080184 + iVar3) == 0xe) {
        *(undefined4 *)(&DAT_08080184 + iVar3) = 0x1d;
      }
      uVar4 = *(uint *)(&DAT_08080184 + iVar6 * 0x24);
      local_430 = uVar5;
      if ((uVar4 != 2) && (uVar4 < 0x1c)) {
        pcVar7 = "Unexpected operator";
LAB_080533e0:
        FUN_08052f1c(4,pcVar7);
        return;
      }
    }
    if (((*param_4 == 0) || (local_42c == 0)) && (param_3 == 0)) {
      if ((*(int *)(&DAT_080801a0 + iVar3) == 0) || (param_5 == 0)) {
        FUN_08052f34(4,iVar1,"Bad symbol");
        return;
      }
      local_42c = 1;
    }
    uVar4 = 0;
    if (*param_4 != 0) {
      uVar4 = (uint)(local_42c != 0);
    }
    *param_4 = uVar4;
    while( true ) {
      bVar2 = FUN_0805cad8(param_1,param_2);
      if ((CONCAT31(extraout_var,bVar2) == 0) && (param_1[*param_2] != ']')) {
        FUN_08060384(param_1,param_2,&local_428,&local_42c);
        if (DAT_08080160 != 0) {
          return;
        }
        if (local_428 != 0) {
          pcVar7 = "Unexpected operand";
          goto LAB_080533e0;
        }
        uVar4 = local_424;
        if (0x1b < local_424) {
          pcVar7 = "Unexpected unary operator";
          local_430 = uVar5;
          goto LAB_080533e0;
        }
      }
      else {
        uVar4 = 1;
      }
      if (uVar4 == 1) {
        if (uVar5 == 0) goto LAB_08053319;
        if (DAT_08080160 != 0) {
          return;
        }
        local_430 = uVar5;
        goto LAB_080532f5;
      }
      if (uVar4 != 3) break;
      local_430 = uVar5;
      if ((uVar5 != 2) && (uVar5 != 0)) {
        if (DAT_08080160 != 0) {
          return;
        }
        do {
          FUN_08048fd0(&local_430,&DAT_0807e9e0,param_5);
          if ((local_430 == 2) || (local_430 == 0)) break;
        } while (DAT_08080160 == 0);
      }
      if (DAT_08080160 != 0) {
        return;
      }
      if (local_430 == 0) {
        pcVar7 = "Missing open bracket";
        goto LAB_080533e0;
      }
      FUN_08054004(DAT_0807e9e0 + -1,DAT_0807e9e0,&local_430);
      DAT_0807e9e0 = DAT_0807e9e0 + -1;
      uVar5 = local_430;
    }
    local_430 = uVar5;
    if ((*(uint *)(&DAT_08073280 + uVar4 * 4) <= *(uint *)(&DAT_08073280 + uVar5 * 4)) &&
       (uVar5 != 2)) {
      if (DAT_08080160 != 0) {
        return;
      }
      do {
        FUN_08048fd0(&local_430,&DAT_0807e9e0,param_5);
        if ((*(uint *)(&DAT_08073280 + local_430 * 4) < *(uint *)(&DAT_08073280 + uVar4 * 4)) ||
           (local_430 == 2)) break;
      } while (DAT_08080160 == 0);
    }
    if (DAT_08080160 != 0) {
      return;
    }
    iVar6 = DAT_0807e9e0 + 1;
    *(undefined4 *)(&DAT_08080180 + iVar6 * 0x24) = 0;
    *(uint *)(&DAT_08080184 + iVar6 * 0x24) = uVar4;
  } while( true );
  while (DAT_08080160 == 0) {
LAB_080532f5:
    FUN_08048fd0(&local_430,&DAT_0807e9e0,param_5);
    if (local_430 == 0) break;
  }
LAB_08053319:
  uVar4 = DAT_080801ac;
  if ((DAT_08080160 == 0) && (DAT_080801a8 == 2)) {
    uVar5 = 1;
    if (DAT_080801ac != 0) {
      iVar6 = 0;
      do {
        (&DAT_0807e7e0)[iVar6] = DAT_080801b0[iVar6];
        iVar6 = iVar6 + 1;
        uVar5 = uVar5 + 1;
      } while (uVar5 <= uVar4);
    }
    DAT_080801b0 = &DAT_0807e7e0;
  }
  return;
}



undefined4 FUN_080534cc(char *param_1,int *param_2,int param_3,uint *param_4)

{
  FUN_080530dc(param_1,param_2,param_3,param_4,0);
  FUN_0806215c(&DAT_080801c4);
  if ((DAT_08080160 == 0) && (*param_4 != 0)) {
    if (DAT_080801a8 == 5) {
      return DAT_080801ac;
    }
    FUN_08052f1c(4,"Bad expression type");
  }
  return 0;
}



int FUN_08053524(int param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  
  FUN_0805fa50(param_1,param_2);
  iVar2 = *param_2;
  cVar1 = *(char *)(iVar2 + param_1);
  *param_2 = iVar2 + 1;
  if (cVar1 == '1') {
    if (*(char *)(param_1 + 1 + iVar2) == '0') {
      *param_2 = iVar2 + 2;
      return 7;
    }
    return 1;
  }
  if (cVar1 < '2') {
    if (cVar1 == '0') {
      if (*(char *)(param_1 + 1 + iVar2) != '.') {
        return 0;
      }
      *param_2 = iVar2 + 2;
      if (*(char *)(param_1 + 2 + iVar2) == '5') {
        *param_2 = iVar2 + 3;
        return 6;
      }
      goto LAB_0805359a;
    }
  }
  else if (cVar1 < '6') {
    return cVar1 + -0x30;
  }
  *param_2 = *param_2 + 1;
LAB_0805359a:
  FUN_08052f1c(4,"Bad floating point constant");
  return 0;
}



int FUN_080535b0(char *param_1,int *param_2,int param_3,uint *param_4)

{
  int iVar1;
  
  iVar1 = *param_2;
  FUN_080530dc(param_1,param_2,param_3,param_4,0);
  FUN_0806215c(&DAT_080801c4);
  if ((DAT_08080160 == 0) && (*param_4 != 0)) {
    if (DAT_080801a8 == 1) {
      return DAT_080801ac;
    }
    if ((DAT_080801a8 == 2) && (DAT_080801ac == 1)) {
      return (int)*DAT_080801b0;
    }
    FUN_08052f34(4,iVar1,"Expected constant expression");
  }
  return 0;
}



int FUN_0805362c(char *param_1,int *param_2,int param_3,uint *param_4)

{
  int iVar1;
  bool bVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  uint local_c;
  char *local_8;
  
  iVar1 = *param_2;
  iVar5 = 0;
  bVar2 = true;
  bVar4 = 0;
  iVar3 = FUN_080613f8((int)param_1,param_2,(int *)&local_c);
  if (((iVar3 != 0) && (iVar3 = FUN_0805f618(local_c,local_8,1), iVar3 != 0)) &&
     ((*(ushort *)(iVar3 + 8) & 0x3003) == 0)) {
    if ((*(byte *)(iVar3 + 0xb) & 0x20) == 0) {
      bVar4 = *(byte *)(iVar3 + 0xb) >> 4 & 1;
    }
    else {
      bVar4 = 0;
    }
  }
  *param_2 = iVar1;
  FUN_080530dc(param_1,param_2,param_3,param_4,1);
  iVar3 = iVar5;
  if ((DAT_08080160 == 0) && (*param_4 != 0)) {
    iVar3 = DAT_080801ac;
    if (DAT_080801a8 != 1) {
      if (DAT_080801a8 == 3) {
        if (bVar4 != 0) {
          iVar3 = DAT_080801ac + 1;
        }
      }
      else {
        FUN_08052f34(4,iVar1,"Expected constant or address expression");
        bVar2 = false;
        iVar3 = iVar5;
      }
    }
    if ((bVar2) && (DAT_080825d0 == 2)) {
      FUN_080620a4(&DAT_080801c4,DAT_080826a0);
      return iVar3;
    }
  }
  FUN_0806215c(&DAT_080801c4);
  return iVar3;
}



int FUN_08053738(char *param_1,int *param_2,uint *param_3,int param_4,uint *param_5,uint *param_6)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint local_c;
  char *local_8;
  
  iVar1 = *param_2;
  iVar2 = FUN_080613f8((int)param_1,param_2,(int *)&local_c);
  if ((((iVar2 != 0) && (iVar2 = FUN_0805f618(local_c,local_8,1), iVar2 != 0)) &&
      (param_6 != (uint *)0x0)) && ((*(ushort *)(iVar2 + 8) & 0x3003) == 0)) {
    if ((*(byte *)(iVar2 + 0xb) & 0x20) == 0) {
      uVar3 = *(byte *)(iVar2 + 0xb) >> 4 & 1;
    }
    else {
      uVar3 = 0;
    }
    *param_6 = uVar3;
  }
  *param_2 = iVar1;
  FUN_080530dc(param_1,param_2,param_4,param_5,0);
  uVar4 = FUN_08062050(DAT_080801c4);
  FUN_0806215c(&DAT_080801c4);
  uVar3 = DAT_080801a8;
  if ((DAT_08080160 == 0) && (*param_5 != 0)) {
    *param_3 = DAT_080801a8;
    if (uVar3 == 2) {
      *param_3 = 1;
      if (DAT_080801ac == 1) {
        return (int)*DAT_080801b0;
      }
    }
    else if (uVar3 < 3) {
      if (uVar3 == 1) {
        return DAT_080801ac;
      }
    }
    else if ((uVar3 == 3) && (uVar4 < 2)) {
      return DAT_080801ac;
    }
    FUN_08052f34(4,iVar1,"Expected constant or address expression");
  }
  else {
    *param_3 = 0;
  }
  return 0;
}



int FUN_0805384c(char *param_1,int *param_2,uint *param_3,uint *param_4,int param_5,uint *param_6)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  FUN_080530dc(param_1,param_2,param_5,param_6,0);
  uVar2 = FUN_08062050(DAT_080801c4);
  FUN_0806215c(&DAT_080801c4);
  uVar3 = DAT_080801a8;
  if ((DAT_08080160 != 0) || (*param_6 == 0)) {
    *param_4 = 0;
    return 0;
  }
  *param_4 = DAT_080801a8;
  if (uVar3 == 2) {
    *param_4 = 1;
    if (DAT_080801ac == 1) {
      return (int)*DAT_080801b0;
    }
    goto LAB_08053920;
  }
  iVar1 = DAT_080801ac;
  if (2 < uVar3) {
    if (uVar3 == 3) {
      if (uVar2 < 2) {
        return DAT_080801ac;
      }
      goto LAB_08053920;
    }
    if (uVar3 != 4) goto LAB_08053920;
    uVar3 = 0;
    uVar2 = 0;
    do {
      uVar3 = uVar3 + *(byte *)((int)&DAT_080801ac + uVar2);
      if (*(char *)((int)&DAT_080801ac + uVar2) != '\0') {
        *param_3 = uVar2;
      }
      uVar2 = uVar2 + 1;
      iVar1 = DAT_080801bc;
    } while (uVar2 < 0x10);
  }
  if (uVar3 == 1) {
    return iVar1;
  }
LAB_08053920:
  FUN_08052f1c(4,"Bad expression type");
  return 0;
}



undefined4 FUN_08053938(char *param_1,int *param_2,int param_3,uint *param_4)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = *param_2;
  FUN_080530dc(param_1,param_2,param_3,param_4,0);
  uVar2 = FUN_08062050(DAT_080801c4);
  FUN_0806215c(&DAT_080801c4);
  if ((DAT_08080160 == 0) && (*param_4 != 0)) {
    if (DAT_080801a8 == 1) {
      if (DAT_08082640 == 0) {
        return DAT_080801ac;
      }
    }
    else if ((DAT_080801a8 == 3) && (uVar2 < 2)) {
      return DAT_080801ac;
    }
    FUN_08052f34(4,iVar1,"Expected address expression");
  }
  return 0;
}



void FUN_080539b8(char *param_1,int *param_2,undefined4 *param_3)

{
  int iVar1;
  undefined4 uVar2;
  uint local_8;
  
  iVar1 = *param_2;
  FUN_080530dc(param_1,param_2,0,&local_8,0);
  FUN_0806215c(&DAT_080801c4);
  *param_3 = 0;
  uVar2 = DAT_080801b0;
  if (DAT_08080160 == 0) {
    if (DAT_080801a8 == 2) {
      *param_3 = DAT_080801ac;
      param_3[1] = uVar2;
    }
    else {
      FUN_08052f34(4,iVar1,"Expected string expression");
    }
  }
  return;
}



undefined4 FUN_08053a28(char *param_1,int *param_2,uint *param_3,int param_4,uint *param_5)

{
  int iVar1;
  uint uVar2;
  char cVar3;
  
  iVar1 = *param_2;
  FUN_080530dc(param_1,param_2,param_4,param_5,0);
  uVar2 = FUN_08062050(DAT_080801c4);
  FUN_0806215c(&DAT_080801c4);
  if ((DAT_08080160 == 0) && (*param_5 != 0)) {
    if (DAT_080801a8 == 3) {
      if (uVar2 < 2) {
LAB_08053ae0:
        *param_3 = 0xf;
        return DAT_080801ac;
      }
    }
    else if (DAT_080801a8 < 4) {
      if ((DAT_080801a8 == 1) && (DAT_08082640 == 0)) goto LAB_08053ae0;
    }
    else if (DAT_080801a8 == 4) {
      cVar3 = '\0';
      uVar2 = 0;
      do {
        cVar3 = cVar3 + *(char *)((int)&DAT_080801ac + uVar2);
        if (*(char *)((int)&DAT_080801ac + uVar2) != '\0') {
          if (DAT_080801c0 != 0) {
            uVar2 = uVar2 + 0x100;
          }
          *param_3 = uVar2;
        }
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x10);
      if (cVar3 == '\x01') {
        return DAT_080801bc;
      }
    }
    FUN_08052f34(4,iVar1,"Expected register relative expression");
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08053b0c(char *param_1,int *param_2,int param_3,int *param_4,undefined4 *param_5,
                 undefined4 *param_6)

{
  int iVar1;
  int iVar2;
  uint local_8;
  
  iVar1 = *param_2;
  FUN_080530dc(param_1,param_2,param_3,&local_8,0);
  FUN_0806215c(&DAT_080801c4);
  iVar2 = DAT_080801a8;
  if ((DAT_08080160 == 0) && (local_8 != 0)) {
    *param_4 = DAT_080801a8;
    if (iVar2 == 1) {
      *param_5 = DAT_080801ac;
      return;
    }
    if (iVar2 == 2) {
      _DAT_0807e9e4 = DAT_080801ac;
      _DAT_0807e9ec = DAT_080801b0;
      *param_6 = &DAT_0807e9e4;
      return;
    }
    FUN_08052f34(4,iVar1,"Expected string or constant expression");
  }
  else {
    *param_4 = 1;
  }
  *param_5 = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * FUN_08053bbc(char *param_1,int *param_2,int *param_3,uint *param_4)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined *puVar7;
  uint local_124;
  char *local_120;
  int local_11c;
  uint local_118;
  int local_114;
  uint local_110;
  char *local_10c;
  char local_108 [260];
  
  iVar1 = *param_2;
  FUN_0805cad8(param_1,param_2);
  iVar3 = FUN_080613f8((int)param_1,param_2,(int *)&local_110);
  if (iVar3 == 0) {
    if (DAT_080825c4 == 0) {
      return (undefined *)0x0;
    }
    iVar3 = isdigit((int)param_1[*param_2]);
    if (iVar3 == 0) {
      return (undefined *)0x0;
    }
    FUN_0805fbc8((int)param_1,param_2);
    iVar3 = *param_2;
    local_108[0] = param_1[iVar3];
    if ((local_108[0] != 'b') && (local_108[0] != 'f')) goto LAB_08053ff0;
    *param_2 = iVar3 + 1;
    iVar3 = FUN_0805cb78(param_1[iVar3 + 1]);
    if (iVar3 == 0) goto LAB_08053ff0;
    memcpy(local_108 + 1,param_1 + iVar1,(*param_2 - iVar1) - 1);
    local_108[*param_2 - iVar1] = '\r';
    local_11c = 0;
    iVar3 = FUN_08056ef4((int)local_108,&local_11c,&local_118,&local_114);
    *param_3 = iVar3;
    if ((local_118 == 0) || (local_114 == DAT_0808276c)) {
      *param_2 = iVar1;
      return (undefined *)0x0;
    }
    _DAT_0807ea08 = 0xc0000;
    _DAT_0807ea0c = *param_3;
    _DAT_0807ea1c = local_114;
    puVar7 = &DAT_0807ea00;
  }
  else {
    puVar7 = (undefined *)FUN_0805f618(local_110,local_10c,1);
    if (puVar7 == (undefined *)0x0) goto LAB_08053ff0;
    if ((puVar7[8] & 3) == 0) {
      if (((puVar7[9] & 0x30) == 0) && (param_4 != (uint *)0x0)) {
        if ((puVar7[0xb] & 0x20) == 0) {
          uVar4 = (byte)puVar7[0xb] >> 4 & 1;
        }
        else {
          uVar4 = 0;
        }
        *param_4 = uVar4;
      }
      if (((*(uint *)(puVar7 + 8) & 0xc3000) != 0xc0000) ||
         (*(int *)(puVar7 + 0x1c) == DAT_0808276c)) goto LAB_08053ff0;
      iVar3 = *(int *)(puVar7 + 0xc);
      if (DAT_080825c4 == 0) {
        iVar6 = FUN_08051d18(*(int *)(puVar7 + 0x1c),&local_110);
        iVar3 = iVar3 - iVar6;
      }
      *param_3 = iVar3;
      puVar7 = (undefined *)FUN_0805f618(local_110,local_10c,1);
    }
    else {
      if ((puVar7[8] & 3) != 1) goto LAB_08053ff0;
      *param_3 = 0;
    }
    FUN_08058c28((int)puVar7);
  }
  FUN_0805fa50((int)param_1,param_2);
  iVar3 = *param_2;
  if ((DAT_08082654 == 0) && (param_1[iVar3] == '-')) {
    FUN_0805fa50((int)param_1,param_2);
    iVar6 = *param_2;
    iVar5 = FUN_080613f8((int)param_1,param_2,(int *)&local_124);
    if (iVar5 == 0) {
      *param_2 = iVar3;
    }
    else {
      iVar5 = FUN_0805f618(local_124,local_120,0);
      uVar4 = DAT_080826a0;
      if (iVar5 == 0) {
        *param_2 = iVar3;
      }
      else {
        if ((*(ushort *)(iVar5 + 8) & 0x3003) != 0) {
          FUN_08052f34(4,iVar6,"Bad symbol type");
          return (undefined *)0x0;
        }
        uVar2 = *(uint *)(iVar5 + 0x18);
        iVar3 = *param_3;
        if (DAT_080825c4 == 0) {
          iVar6 = FUN_08051d18(*(int *)(iVar5 + 0x1c),&local_124);
          iVar6 = *(int *)(iVar5 + 0xc) - iVar6;
        }
        else {
          iVar6 = *(int *)(iVar5 + 0xc);
        }
        *param_3 = iVar3 - iVar6;
        FUN_080514cc(uVar4,uVar2 & 0xffffff | 0x86000000,0);
        FUN_08058c28(iVar5);
        FUN_0805fa50((int)param_1,param_2);
        iVar3 = *param_2;
      }
    }
  }
  if ((param_1[iVar3] == '+') || (param_1[iVar3] == '-')) {
    iVar3 = FUN_080535b0(param_1,param_2,(uint)(DAT_080825d0 == 1),&local_118);
    *param_3 = *param_3 + iVar3;
    iVar3 = *param_2;
  }
  iVar3 = FUN_0805cb78(param_1[iVar3]);
  if (iVar3 != 0) {
    return puVar7;
  }
  if (param_1[*param_2] == ',') {
    return puVar7;
  }
LAB_08053ff0:
  *param_2 = iVar1;
  return (undefined *)0x0;
}



void FUN_08054004(int param_1,int param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  *param_3 = (&DAT_08080160)[param_1 * 9];
  puVar1 = (undefined4 *)(&DAT_08080180 + param_1 * 0x24);
  while (puVar4 = puVar1, puVar4 < &DAT_08080180 + param_2 * 0x24) {
    puVar1 = puVar4 + 9;
    if (puVar4[9] == 0) {
      *puVar4 = 0;
      puVar4[1] = puVar4[10];
    }
    else if (puVar4[9] == 1) {
      *puVar4 = 1;
      puVar4[1] = puVar4[10];
      puVar4[8] = puVar4[0x11];
      switch(puVar4[10]) {
      case 0:
      case 1:
      case 3:
      case 5:
        puVar4[2] = puVar4[0xb];
        break;
      case 2:
        puVar4[2] = puVar4[0xb];
        puVar4[3] = puVar4[0xc];
        break;
      case 4:
        puVar3 = puVar4 + 0xb;
        puVar4 = puVar4 + 2;
        for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + 1;
          puVar4 = puVar4 + 1;
        }
      }
    }
  }
  return;
}



// WARNING: Type propagation algorithm not settling

bool FUN_080540c0(uint param_1,int param_2)

{
  int iVar1;
  bool bVar2;
  uint in_stack_00000024;
  int in_stack_00000028;
  undefined4 in_stack_00000044;
  
  switch(in_stack_00000044) {
  default:
    bVar2 = false;
    break;
  case 4:
  case 5:
  case 6:
    bVar2 = false;
    if (param_1 == 5) {
      bVar2 = in_stack_00000024 == 5;
    }
    break;
  case 7:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
switchD_080540cc_caseD_7:
    if (param_1 == 5) {
      return false;
    }
    if (in_stack_00000024 == 5) {
      return false;
    }
    if (((((param_1 != in_stack_00000024) && (param_1 != 0)) && (in_stack_00000024 != 0)) &&
        ((((in_stack_00000024 != 2 || (in_stack_00000028 != 1)) && (in_stack_00000024 != 1)) ||
         ((param_1 != 2 || (param_2 != 1)))))) && (param_1 != 1)) {
      if (in_stack_00000024 != 1) {
        return false;
      }
      if (param_1 != 3) {
        return false;
      }
    }
    return true;
  case 8:
    if ((param_1 != 5) || (in_stack_00000024 != 5)) goto switchD_080540cc_caseD_7;
    goto LAB_0805426f;
  case 0xd:
  case 0xe:
    if (param_1 == 5) {
      return false;
    }
    bVar2 = param_1 == 2;
    param_1 = in_stack_00000024;
    iVar1 = in_stack_00000028;
    if ((bVar2) && (iVar1 = in_stack_00000028, param_2 != 1)) {
      return false;
    }
    goto joined_r0x0805421d;
  case 0xf:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
  case 0x15:
  case 0x19:
  case 0x1a:
  case 0x1b:
    if ((param_1 != 1) && (((param_1 != 2 || (param_2 != 1)) && (param_1 != 0)))) {
      return false;
    }
    if (((in_stack_00000024 != 1) && ((in_stack_00000024 != 2 || (in_stack_00000028 != 1)))) &&
       (in_stack_00000024 != 0)) {
      return false;
    }
    goto LAB_0805426f;
  case 0x16:
  case 0x17:
    bVar2 = false;
    if (param_1 == 2) {
      bVar2 = in_stack_00000024 == 1;
    }
    break;
  case 0x18:
    bVar2 = false;
    if (param_1 == 2) {
      bVar2 = in_stack_00000024 == 2;
    }
    break;
  case 0x1c:
  case 0x1d:
  case 0x28:
    iVar1 = param_2;
joined_r0x0805421d:
    param_2 = iVar1;
    if (param_1 == 5) {
      return false;
    }
    if (param_1 == 2) {
joined_r0x08054243:
      if (param_2 != 1) {
        return false;
      }
    }
    goto LAB_0805426f;
  case 0x1e:
    bVar2 = param_1 == 5;
    break;
  case 0x1f:
    if (param_1 < 2) goto LAB_0805426f;
    if (param_1 != 2) {
      return false;
    }
    goto joined_r0x08054243;
  case 0x20:
    bVar2 = param_1 == 2;
    break;
  case 0x25:
    bVar2 = param_1 == 1;
    break;
  case 0x26:
    if ((param_1 != 1) && (param_1 != 5)) {
      return false;
    }
LAB_0805426f:
    bVar2 = true;
    break;
  case 0x27:
    bVar2 = param_1 - 3 < 2;
  }
  return bVar2;
}



uint FUN_0805428c(int param_1,int *param_2,undefined *param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  char *pcVar5;
  uint local_c;
  char local_5;
  
  local_c = 0;
  FUN_0805fa50(param_1,param_2);
  *param_2 = *param_2 + 1;
  while( true ) {
    uVar1 = (*(code *)param_3)(param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    local_5 = *(char *)(*param_2 + param_1);
    uVar2 = uVar1;
    if (local_5 == '-') {
      *param_2 = *param_2 + 1;
      uVar2 = (*(code *)param_3)(param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (uVar2 < uVar1) {
        pcVar5 = "Bad register range";
        goto LAB_0805439c;
      }
      iVar3 = FUN_0805fa50(param_1,param_2);
      local_5 = (char)iVar3;
    }
    if (((DAT_080826f4 != 0) && (DAT_080825d0 == 1)) &&
       ((local_c & -(1 << ((char)uVar1 + 1U & 0x1f))) != 0)) {
      FUN_08052f1c(3,"Registers should be listed in increasing register number order");
    }
    for (; uVar1 <= uVar2; uVar1 = uVar1 + 1) {
      uVar4 = 1 << ((byte)uVar1 & 0x1f);
      if ((local_c & uVar4) != 0) {
        pcVar5 = "Register occurs multiply in list";
        goto LAB_0805439c;
      }
      local_c = local_c | uVar4;
    }
    if (local_5 != ',') break;
    *param_2 = *param_2 + 1;
  }
  if (local_5 == '}') {
    *param_2 = *param_2 + 1;
    FUN_0805fa50(param_1,param_2);
    return local_c;
  }
  pcVar5 = "Missing close bracket";
LAB_0805439c:
  FUN_08052f1c(4,pcVar5);
  return 0;
}



int FUN_080543b0(uint param_1)

{
  int iVar1;
  
  iVar1 = 0;
  for (; param_1 != 0; param_1 = param_1 & param_1 - 1) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}



uint FUN_080543d0(uint param_1,uint param_2)

{
  uint uVar1;
  
  if (param_2 < 0x1f) {
    uVar1 = (1 << ((byte)param_2 + 1 & 0x1f)) - 1;
    if ((1 << ((byte)param_2 & 0x1f) & param_1) == 0) {
      param_1 = param_1 & uVar1;
    }
    else {
      param_1 = param_1 | ~uVar1;
    }
  }
  return param_1;
}



void FUN_0805440c(undefined4 param_1,undefined4 param_2)

{
  DAT_0807ea2c = param_1;
  DAT_0807ea30 = param_2;
  return;
}



void FUN_08054424(int *param_1,uint param_2)

{
  *param_1 = DAT_0807ea2c;
  if (DAT_0807ea30 < param_2) {
    FUN_08052f1c(5,"Expression storage allocator failed");
    FUN_080615f0(1);
  }
  DAT_0807ea2c = DAT_0807ea2c + param_2;
  DAT_0807ea30 = DAT_0807ea30 - param_2;
  return;
}



undefined4 FUN_08054470(char *param_1)

{
  int iVar1;
  FILE *pFVar2;
  char *pcVar3;
  int local_1c [3];
  byte *local_10;
  char local_9;
  
  FUN_0806d7a4(param_1,"s o",local_1c);
  if (local_9 == '\x01') {
    iVar1 = 0x73 - (uint)*local_10;
    if (iVar1 == 0) {
      iVar1 = -(uint)local_10[1];
    }
    if (iVar1 != 0) {
      iVar1 = 0x6f - (uint)*local_10;
      if (iVar1 == 0) {
        iVar1 = -(uint)local_10[1];
      }
      if (iVar1 != 0) goto LAB_080544d0;
    }
    pcVar3 = "The specified listing file \'%s\' must not be a .s or .o file";
  }
  else {
LAB_080544d0:
    pFVar2 = fopen(param_1,"w");
    if (pFVar2 != (FILE *)0x0) {
      DAT_08082588 = pFVar2;
      return 1;
    }
    pcVar3 = "Can\'t open listing file \'%s\'";
  }
  FUN_08052f1c(1,pcVar3);
  return 0;
}



void FUN_08054508(void)

{
  DAT_0807ea48 = 0;
  FUN_080545cc();
  DAT_0807ea4c = 1;
  return;
}



void FUN_08054528(void)

{
  DAT_0807ea4c = 0;
  return;
}



void FUN_08054538(int param_1)

{
  int iVar1;
  char *local_1c;
  undefined4 local_18;
  undefined *local_14;
  undefined2 local_10;
  undefined2 local_e;
  undefined4 local_c;
  undefined4 local_8;
  
  if (DAT_08082588 == (FILE *)0x0) {
    (&DAT_0807ea60)[DAT_08082580] = (char)param_1;
    DAT_08082580 = DAT_08082580 + 1;
    if (param_1 == 10) {
      local_1c = s_armasm_08079858;
      local_18 = 0;
      local_14 = &DAT_0807ea60;
      local_c = 0xffffffff;
      local_e = 0xffff;
      local_8 = 0xffffffff;
      local_10 = 1;
      iVar1 = DAT_08084dc4;
      if (DAT_08084dc4 == 0) {
        iVar1 = stdout;
      }
      (*DAT_08084dc0)(iVar1,1,&local_1c);
      DAT_08082580 = 0;
    }
  }
  else {
    fputc(param_1,DAT_08082588);
  }
  return;
}



void FUN_080545c0(void)

{
  FUN_08054538(10);
  return;
}



void FUN_080545cc(void)

{
  DAT_0807ea44 = DAT_08082590;
  return;
}



void FUN_080545dc(char param_1)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  
  if ((DAT_0807ea44 == DAT_08082590) && (DAT_0807ea4c != 0)) {
    DAT_0807ea48 = DAT_0807ea48 + 1;
    FUN_08054538(0xc);
    FUN_080545cc();
    fprintf(DAT_08082588,"\n\n\nARM Macro Assembler    Page %lu ",DAT_0807ea48);
    pcVar2 = &DAT_08079600;
    do {
      if (*pcVar2 == '\0') break;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
      FUN_08054538((int)cVar1);
    } while (pcVar2 < &DAT_08079700);
    FUN_080545c0();
    uVar3 = 0;
    pcVar2 = &DAT_08079700;
    do {
      if (*pcVar2 == '\0') break;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
      uVar3 = uVar3 + 1;
      FUN_08054538((int)cVar1);
    } while (uVar3 < 0x100);
    FUN_080545c0();
    FUN_080545c0();
    DAT_0807ea44 = 7;
    DAT_0807ea40 = 0;
  }
  if ((param_1 == '\r') || (param_1 == '\n')) {
    FUN_080545c0();
    if (DAT_0807ea4c != 0) {
      DAT_0807ea44 = DAT_0807ea44 + 1;
      DAT_0807ea40 = 0;
    }
  }
  else if (DAT_0807ea4c == 0) {
    FUN_08054538((int)param_1);
  }
  else if (DAT_0807ea40 < DAT_0808258c) {
    FUN_08054538((int)param_1);
    DAT_0807ea40 = DAT_0807ea40 + 1;
  }
  else {
    FUN_080545dc('\r');
    FUN_080545dc(param_1);
  }
  return;
}



void FUN_08054714(char *param_1)

{
  char *__s;
  char local_104 [256];
  
  __s = local_104;
  vsprintf(__s,param_1,&stack0x00000008);
  while (local_104[0] != '\0') {
    FUN_080545dc(*__s);
    __s = __s + 1;
    local_104[0] = *__s;
  }
  return;
}



void FUN_0805475c(uint param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = 0;
  if (param_1 != 0) {
    do {
      (&DAT_08079600)[uVar1] = *(undefined1 *)(uVar1 + param_2);
      uVar1 = uVar1 + 1;
    } while (uVar1 < param_1);
  }
  if (uVar1 < 0x100) {
    (&DAT_08079600)[uVar1] = 0;
  }
  return;
}



void FUN_08054798(uint param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = 0;
  if (param_1 != 0) {
    do {
      (&DAT_08079700)[uVar1] = *(undefined1 *)(uVar1 + param_2);
      uVar1 = uVar1 + 1;
    } while (uVar1 < param_1);
  }
  if (uVar1 < 0x100) {
    (&DAT_08079700)[uVar1] = 0;
  }
  return;
}



undefined4 FUN_080547e0(int param_1,int *param_2,int param_3,uint *param_4,undefined4 *param_5)

{
  int iVar1;
  undefined4 uVar2;
  uint local_14;
  uint local_10;
  undefined4 local_c;
  char *local_8;
  
  iVar1 = FUN_0806deb8((char *)(param_1 + *param_2),&local_10,&local_8);
  if (iVar1 == 8) {
    FUN_08052f1c(1,"Scanf failed to read floating point number");
    uVar2 = 2;
  }
  else {
    if (param_3 == 0) {
      FUN_0806e418(&local_10,&local_14);
      *param_4 = local_14;
    }
    else {
      *param_4 = local_10;
      *param_5 = local_c;
    }
    for (; (byte)(*local_8 - 0x1fU) < 2; local_8 = local_8 + 1) {
    }
    *param_2 = (int)local_8 - param_1;
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_08054880(int param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  char local_104 [256];
  
  if (DAT_08079804 == 0) {
    FUN_08055af8();
    FUN_0804e548(local_104,(char *)(param_1 + *param_2));
    cVar1 = *(char *)(*param_2 + param_1);
    while (cVar1 != '\r') {
      iVar2 = *param_2;
      *param_2 = iVar2 + 1;
      cVar1 = *(char *)(param_1 + 1 + iVar2);
    }
    do {
      iVar2 = FUN_0804e5e0(local_104,1,DAT_080825d0);
    } while (iVar2 == 0);
    if (DAT_08079804 == 5) {
      DAT_08079804 = 0;
    }
  }
  return;
}



void FUN_08054904(void)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int aiStackY_4c [4];
  undefined4 uStackY_3c;
  int local_24 [2];
  long local_1c;
  int local_18;
  uint local_14;
  
  iVar1 = FUN_080529b4(local_24);
  if (iVar1 != 0) {
    if (local_24[0] == 1) {
      if (DAT_08080154 == 0) {
        DAT_08080154 = local_18;
        DAT_080825cc = local_14;
        if (((local_14 & 1) != 0) && (DAT_08082644 == 0)) {
          DAT_08082644 = 1;
          FUN_08055f9c();
        }
      }
      else {
        DAT_08082594 = local_24[1];
        if ((DAT_0808259c == 0) || (DAT_08082780 != 0)) {
          DAT_080825a0 = local_1c;
        }
        else {
          uStackY_3c = 0x80549a0;
          fseek(DAT_08080020,local_1c,0);
        }
      }
    }
    else {
      if (local_24[0] != 0) {
        piVar2 = local_24;
        piVar3 = aiStackY_4c;
        for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
          *piVar3 = *piVar2;
          piVar2 = piVar2 + 1;
          piVar3 = piVar3 + 1;
        }
        FUN_08052960();
      }
      FUN_08052f1c(4,"Structure mismatch");
      DAT_08079804 = 4;
    }
  }
  return;
}



void FUN_080549d8(void)

{
  int iVar1;
  uint local_24 [8];
  
  iVar1 = FUN_08052a04(local_24);
  if ((iVar1 != 0) && (local_24[0] < 2)) {
    FUN_08052f1c(4,"Unmatched conditional or macro");
  }
  return;
}



undefined4 FUN_08054a04(void)

{
  undefined4 uVar1;
  int iVar2;
  int local_24;
  int local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_c;
  
  if (DAT_08082780 == 0) {
    FUN_08052f1c(4,"No current macro expansion");
LAB_08054a20:
    uVar1 = 1;
  }
  else {
    do {
      iVar2 = FUN_080529b4(&local_24);
      if (iVar2 == 0) goto LAB_08054a20;
      if ((local_24 == 1) || (local_24 == 0)) {
        DAT_08080154 = local_20;
      }
      else if (local_24 == 2) {
        FUN_08052f1c(5,"unexpected GET on structure stack");
      }
    } while (local_24 != 3);
    DAT_08082594 = local_18;
    DAT_080825cc = local_c;
    DAT_08082780 = DAT_08082780 + -1;
    if ((DAT_08082780 != 0) || (local_20 == 0)) {
      DAT_080825a0 = local_1c;
    }
    FUN_08057550();
    if (((byte)DAT_08082644 & 0x20) == 0) {
      FUN_0805627c();
    }
    uVar1 = 0;
  }
  return uVar1;
}



undefined4 FUN_08054ab8(void)

{
  undefined4 uVar1;
  int iVar2;
  int local_24;
  int local_20;
  undefined4 local_1c;
  int local_18;
  undefined4 local_c;
  
  if (DAT_08082780 == 0) {
    FUN_08052f1c(4,"No current macro expansion");
    uVar1 = 1;
  }
  else {
    iVar2 = FUN_080529b4(&local_24);
    if (iVar2 == 0) {
      uVar1 = 1;
    }
    else {
      if (local_24 != 3) {
        FUN_08052f1c(4,"MEND not allowed within conditionals");
        while (local_24 != 3) {
          iVar2 = local_18;
          if ((local_24 == 1) || (iVar2 = local_20, local_24 == 0)) {
            DAT_08080154 = iVar2;
          }
          FUN_080529b4(&local_24);
        }
      }
      DAT_08082594 = local_18;
      DAT_080825cc = local_c;
      DAT_08082780 = DAT_08082780 + -1;
      if ((DAT_08082780 != 0) || (local_20 == 0)) {
        DAT_080825a0 = local_1c;
      }
      FUN_08057550();
      if (((byte)DAT_08082644 & 0x20) == 0) {
        FUN_0805627c();
      }
      uVar1 = 0;
    }
  }
  return uVar1;
}



FILE * FUN_08054b80(char *param_1)

{
  FILE *__stream;
  int iVar1;
  
  __stream = fopen(param_1,"r");
  if ((__stream == (FILE *)0x0) || (iVar1 = ferror(__stream), iVar1 != 0)) {
    FUN_08052f1c(4,"File \"%s\" not found");
    DAT_08079804 = 5;
    __stream = (FILE *)0x0;
  }
  return __stream;
}



void FUN_08054bd0(int param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  for (; (cVar1 = *param_2, 1 < (byte)(cVar1 - 0x1fU) && (cVar1 != '\r')); param_2 = param_2 + 1) {
    *(char *)(iVar2 + param_1) = cVar1;
    iVar2 = iVar2 + 1;
  }
  *(undefined1 *)(iVar2 + param_1) = 0;
  return;
}



void FUN_08054c00(int param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  FILE *__stream;
  long lVar3;
  char local_104 [256];
  
  FUN_08054bd0((int)local_104,(char *)(param_1 + *param_2));
  FUN_08051160(0x8080040,(int)local_104);
  __stream = FUN_08054b80(local_104);
  if (__stream == (FILE *)0x0) {
    if (DAT_08079804 == 5) {
      FUN_08052f1c(4,"Bad GET or INCLUDE");
      DAT_08079804 = 0;
    }
  }
  else {
    cVar1 = *(char *)(*param_2 + param_1);
    while (cVar1 != '\r') {
      iVar2 = *param_2;
      *param_2 = iVar2 + 1;
      cVar1 = *(char *)(param_1 + 1 + iVar2);
    }
    fseek(__stream,0,2);
    lVar3 = ftell(__stream);
    DAT_080826a0 = DAT_080826a0 + lVar3;
    fclose(__stream);
  }
  return;
}



void FUN_08054ca0(int param_1,int *param_2)

{
  char cVar1;
  FILE *__stream;
  long lVar2;
  size_t __n;
  int iVar3;
  char local_1104 [256];
  undefined1 local_1004 [4096];
  
  FUN_08054bd0((int)local_1104,(char *)(param_1 + *param_2));
  __stream = FUN_08054b80(local_1104);
  if (__stream != (FILE *)0x0) {
    cVar1 = *(char *)(*param_2 + param_1);
    while (cVar1 != '\r') {
      iVar3 = *param_2;
      *param_2 = iVar3 + 1;
      cVar1 = *(char *)(param_1 + 1 + iVar3);
    }
    fseek(__stream,0,2);
    lVar2 = ftell(__stream);
    fseek(__stream,0,0);
    iVar3 = 0;
    if (0 < lVar2) {
      do {
        __n = lVar2 - iVar3;
        if (0x1000 < (int)__n) {
          __n = 0x1000;
        }
        fread(local_1004,1,__n,__stream);
        FUN_08051800((int)local_1004,__n);
        iVar3 = iVar3 + 0x1000;
      } while (iVar3 < lVar2);
    }
    fclose(__stream);
  }
  return;
}



undefined4 FUN_08054d90(int *param_1,int param_2)

{
  bool bVar1;
  bool bVar2;
  char *pcVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  char cVar8;
  char *pcVar9;
  uint uVar10;
  char *local_24;
  undefined4 local_c;
  
  pcVar3 = DAT_080825a0;
  local_c = 0;
  DAT_08082644 = DAT_080825cc;
  DAT_0808015c = 0;
  DAT_08082594 = DAT_08082594 + 1;
  if (DAT_08082770 == 0) {
    if (DAT_08082780 != 0) {
      *param_1 = (int)DAT_080825a0;
      DAT_08082584 = pcVar3;
      DAT_08082598 = (char *)*param_1;
      uVar4 = FUN_080572c4(param_1,0x807eb80);
      return uVar4;
    }
    if (DAT_0808259c == 0) {
      pcVar7 = (char *)(DAT_08082624 + DAT_08080140);
      *param_1 = (int)DAT_080825a0;
      DAT_08082584 = pcVar3;
      DAT_08082598 = pcVar3;
      bVar1 = false;
      bVar2 = false;
      local_24 = pcVar3 + -1;
      pcVar9 = pcVar3;
      for (uVar10 = 0; uVar10 < 0xff; uVar10 = uVar10 + 1) {
        if (pcVar7 <= pcVar9) {
          *param_1 = (int)&DAT_0807eb80;
          DAT_0807eb80 = 0xd;
          DAT_08082584 = &DAT_0807eb80;
          if (DAT_08082688 == 0) {
            DAT_08079804 = 1;
            DAT_0807eb80 = 0xd;
            DAT_080825c4 = 1;
            DAT_080825d4 = 1;
            DAT_08082654 = 1;
            DAT_08082688 = 1;
            return 0;
          }
          if (DAT_080825c4 != 0) {
            DAT_08079804 = 1;
            DAT_0807eb80 = 0xd;
            DAT_080825c4 = 1;
            DAT_080825d4 = 1;
            DAT_08082654 = 1;
            DAT_08082688 = 1;
            return 0;
          }
          if (param_2 != 0) {
            DAT_08079804 = 1;
            DAT_0807eb80 = 0xd;
            return 0;
          }
          pcVar3 = "End of input file";
          goto LAB_0805503f;
        }
        cVar8 = *pcVar9;
        if ((!bVar1) && (cVar8 == ';')) {
          bVar2 = true;
        }
        if (cVar8 == '\"') {
          bVar1 = (bool)(bVar1 ^ 1);
        }
        if ((cVar8 == '\r') || (cVar8 == '\n')) {
          if (*local_24 == '\\') {
            if (!bVar1) {
              if (bVar2) {
                *pcVar9 = '\r';
                FUN_08052f1c(3,"\'\\\' at end of comment");
              }
              DAT_08082594 = DAT_08082594 + 1;
              *local_24 = ' ';
              *pcVar9 = '\x1f';
              if (((pcVar3[uVar10 + 1] == '\r') && (cVar8 == '\n')) ||
                 ((pcVar3[uVar10 + 1] == '\n' && (cVar8 == '\r')))) {
                pcVar9 = pcVar9 + 1;
                local_24 = local_24 + 1;
                uVar10 = uVar10 + 1;
                *pcVar9 = ' ';
              }
              goto LAB_08054f4c;
            }
            pcVar3[uVar10] = '\r';
            FUN_08052f1c(4,"\'\\\' should not be used to split strings");
          }
          pcVar3[uVar10] = '\r';
          DAT_080825a0 = pcVar9 + 1;
          if ((DAT_080825a0 < pcVar7) &&
             (((pcVar9[1] == '\r' && (cVar8 == '\n')) || ((pcVar9[1] == '\n' && (cVar8 == '\r'))))))
          {
            DAT_080825a0 = pcVar9 + 2;
          }
          goto LAB_0805524a;
        }
        if (cVar8 == '$') {
          local_c = 1;
        }
        else if (cVar8 == '\t') {
          *pcVar9 = ' ';
        }
        else if (cVar8 == '\x1f') {
          DAT_08082594 = DAT_08082594 + 1;
        }
LAB_08054f4c:
        pcVar9 = pcVar9 + 1;
        local_24 = local_24 + 1;
      }
      pcVar3[0xff] = '\r';
    }
    else {
      if (DAT_0808259c != 1) {
LAB_0805524a:
        DAT_08082584 = (char *)*param_1;
        return local_c;
      }
      DAT_08082598 = (char *)ftell(DAT_08080020);
      *param_1 = (int)&DAT_0807eb80;
      DAT_08082584 = &DAT_0807eb80;
      uVar10 = 0;
      bVar1 = false;
      bVar2 = false;
      do {
        iVar6 = fgetc(DAT_08080020);
        if (iVar6 == -1) {
          *(undefined1 *)*param_1 = 0xd;
          if ((DAT_08082688 == 0) || (DAT_080825c4 != 0)) {
            DAT_08079804 = 1;
            DAT_080825c4 = 1;
            DAT_080825d4 = 1;
            DAT_08082654 = 1;
            DAT_08082688 = 1;
            return 0;
          }
          if (param_2 != 0) {
            DAT_08079804 = 1;
            return 0;
          }
          pcVar3 = "End of input file";
LAB_08055243:
          FUN_08052f1c(4,pcVar3);
          goto LAB_0805524a;
        }
        cVar8 = (char)iVar6;
        (&DAT_0807eb80)[uVar10] = cVar8;
        if ((!bVar1) && (cVar8 == ';')) {
          bVar2 = true;
        }
        if (cVar8 == '\"') {
          bVar1 = (bool)(bVar1 ^ 1);
        }
        if ((cVar8 == '\r') || (cVar8 == '\n')) {
          (&DAT_0807eb80)[uVar10] = 0xd;
          iVar6 = fgetc(DAT_08080020);
          iVar5 = ferror(DAT_08080020);
          if (((iVar5 == 0) && (iVar6 != -1)) &&
             (((cVar8 == '\r' && (iVar6 != 10)) || ((cVar8 == '\n' && (iVar6 != 0xd)))))) {
            fseek(DAT_08080020,-1,1);
          }
          if ((&DAT_0807eb7f)[uVar10] != '\\') goto LAB_0805524a;
          if (bVar1) {
            (&DAT_0807eb80)[uVar10] = 0xd;
            pcVar3 = "\'\\\' should not be used to split strings";
            goto LAB_08055243;
          }
          if (bVar2) {
            (&DAT_0807eb80)[uVar10] = 0xd;
            FUN_08052f1c(3,"\'\\\' at end of comment");
          }
          DAT_08082594 = DAT_08082594 + 1;
          (&DAT_0807eb7f)[uVar10] = 0x20;
          (&DAT_0807eb80)[uVar10] = 0x1f;
        }
        else if (cVar8 == '$') {
          local_c = 1;
        }
        else if (cVar8 == '\t') {
          (&DAT_0807eb80)[uVar10] = 0x20;
        }
        else if (cVar8 == '\x1f') {
          DAT_08082594 = DAT_08082594 + 1;
        }
        uVar10 = uVar10 + 1;
      } while (uVar10 < 0xff);
      DAT_0807ec7f = 0xd;
    }
    pcVar3 = "Line too long";
LAB_0805503f:
    FUN_08052f1c(4,pcVar3);
  }
  else if ((DAT_08082688 == 0) || (DAT_080825c4 != 1)) {
    if (DAT_080826a8 == 0) {
      if (DAT_08082780 == 0) {
        pcVar3 = "   END\r";
      }
      else {
        pcVar3 = " MEXIT\r";
      }
    }
    else {
      pcVar3 = "  MEND\r";
    }
    strcpy(&DAT_0807eb80,pcVar3);
    *param_1 = (int)&DAT_0807eb80;
    return 0;
  }
  DAT_08079804 = 1;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08055260(void)

{
  DAT_08082770 = 0;
  DAT_080826a8 = 0;
  _DAT_08082764 = 0;
  _DAT_0808261c = 0;
  DAT_08082700 = 1;
  DAT_08082610 = 1;
  DAT_08082620 = 0;
  return;
}



void FUN_080552b0(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  if (DAT_08079808 == 0) {
    uVar3 = 0;
    do {
      uVar1 = uVar3 + 1;
      iVar2 = strcmp((&PTR_s_ALIGN_080738e4)[uVar3 * 3],(&PTR_s_ALIGN_080738e4)[uVar1 * 3]);
      if (-1 < iVar2) {
        FUN_08052f1c(1,
                     "Internal error: opcode table not in ascending order\n                Entry %li = %s, Entry %li = %s"
                    );
      }
      uVar3 = uVar1;
    } while (uVar1 < 0x3c);
    DAT_08079808 = 1;
  }
  return;
}



undefined4 FUN_0805531c(int param_1,int *param_2,int *param_3)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  
  cVar1 = *(char *)(*param_2 + param_1);
  if (cVar1 == '.') {
    *param_3 = 0x3f;
    uVar3 = 1;
  }
  else if (((&DAT_080849c0)[*(char *)(param_1 + 1 + *param_2)] == 0) ||
          ((char)(&DAT_0807ec80)[cVar1] < '\0')) {
    uVar3 = 0;
  }
  else {
    *param_3 = (int)(char)(&DAT_0807ec80)[cVar1];
    do {
      iVar2 = *param_2;
      *param_2 = iVar2 + 1;
    } while ((byte)(*(char *)(param_1 + 1 + iVar2) - 0x1fU) < 2);
    uVar3 = 1;
  }
  return uVar3;
}



undefined4 FUN_0805538c(undefined4 *param_1,uint param_2,char *param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint local_c;
  uint local_8;
  
  local_8 = 0;
  local_c = 0x3d;
  do {
    uVar3 = local_8 + local_c >> 1;
    iVar2 = (int)*param_3 - (int)(char)*(&PTR_s_ALIGN_080738e4)[uVar3 * 3];
    if (iVar2 == 0) {
      uVar1 = *(uint *)(&DAT_080738e0 + uVar3 * 0xc);
      if (*(uint *)(&DAT_080738e0 + uVar3 * 0xc) < param_2) {
        uVar1 = param_2;
      }
      iVar2 = strncmp(param_3 + 1,(&PTR_s_ALIGN_080738e4)[uVar3 * 3] + 1,uVar1 - 1);
      if (iVar2 == 0) {
        *param_1 = *(undefined4 *)(&DAT_080738e8 + uVar3 * 0xc);
        return 1;
      }
    }
    if (-1 < iVar2) {
      local_8 = uVar3 + 1;
      uVar3 = local_c;
    }
    local_c = uVar3;
  } while (local_8 != local_c);
  return 0;
}



undefined4 FUN_08055450(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  int local_c;
  char *local_8;
  
  iVar3 = *param_2;
  while ((byte)(*(char *)(iVar3 + param_1) - 0x1fU) < 2) {
    iVar3 = iVar3 + 1;
    *param_2 = iVar3;
  }
  iVar3 = *param_2;
  iVar1 = FUN_080613f8(param_1,param_2,&local_c);
  if (iVar1 != 0) {
    iVar1 = *param_2;
    while ((byte)(*(char *)(iVar1 + param_1) - 0x1fU) < 2) {
      iVar1 = iVar1 + 1;
      *param_2 = iVar1;
    }
    uVar4 = 0;
    iVar1 = 0;
    do {
      iVar2 = *(int *)((int)&DAT_08073cf8 + iVar1);
      if (iVar2 == local_c) {
        bVar7 = true;
        pcVar5 = local_8;
        pcVar6 = *(char **)((int)&PTR_DAT_08073cfc + iVar1);
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar7 = *pcVar5 == *pcVar6;
          pcVar5 = pcVar5 + 1;
          pcVar6 = pcVar6 + 1;
        } while (bVar7);
        if (bVar7) {
          return *(undefined4 *)((int)&DAT_08073d00 + iVar1);
        }
      }
      iVar1 = iVar1 + 0xc;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0xf);
  }
  *param_2 = iVar3;
  return 0;
}



char * FUN_080554f8(int param_1)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = 0;
  iVar1 = 0;
  do {
    if (*(int *)((int)&DAT_08073d00 + iVar1) == param_1) {
      return *(char **)((int)&PTR_DAT_08073cfc + iVar1);
    }
    iVar1 = iVar1 + 0xc;
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0xf);
  return "<unknown attribute>";
}



undefined4 FUN_08055538(int *param_1,int param_2,byte *param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  byte *pbVar5;
  byte *pbVar6;
  bool bVar7;
  bool bVar8;
  uint local_c;
  uint local_8;
  
  local_8 = 0;
  local_c = 0x1f;
  uVar3 = local_c;
  do {
    local_c = uVar3;
    if (local_c <= local_8) {
      return 0;
    }
    uVar3 = local_8 + local_c >> 1;
    iVar1 = uVar3 * 10;
    bVar7 = false;
    uVar4 = 0;
    bVar8 = true;
    iVar2 = param_2;
    pbVar5 = (byte *)("align" + iVar1);
    pbVar6 = param_3;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar7 = *pbVar5 < *pbVar6;
      bVar8 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + 1;
      pbVar6 = pbVar6 + 1;
    } while (bVar8);
    if (!bVar8) {
      uVar4 = -(uint)bVar7 | 1;
    }
    if ((uVar4 == 0) && ("align"[iVar1 + param_2] == '\0')) {
      *param_1 = (int)*(short *)(&DAT_08073e8c + iVar1);
      return 1;
    }
    if ((int)uVar4 < 0) {
      local_8 = uVar3 + 1;
      uVar3 = local_c;
    }
  } while( true );
}



undefined4 FUN_080555e0(int param_1,char param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  char *pcVar3;
  
  uVar1 = *(uint *)(&DAT_0807ed80 + param_1 * 4);
  if (uVar1 == 3) {
LAB_08055615:
    if ((param_2 == ';') || (param_2 == '\r')) goto LAB_08055626;
    pcVar3 = "Syntax error following directive";
    goto LAB_0805564e;
  }
  if (uVar1 < 4) {
    if (uVar1 == 1) goto LAB_08055615;
  }
  else if (uVar1 == 6) goto LAB_08055615;
LAB_08055626:
  uVar1 = *(uint *)(&DAT_0807ed80 + param_1 * 4);
  if (uVar1 == 0) {
LAB_08055660:
    uVar2 = 1;
  }
  else {
    if (uVar1 < 3) {
      if (param_3 == 0) goto LAB_08055660;
      pcVar3 = "Illegal line start should be blank";
    }
    else {
      if ((4 < uVar1) || (param_3 != 0)) goto LAB_08055660;
      pcVar3 = "Label missing from line start";
    }
LAB_0805564e:
    FUN_08052f1c(4,pcVar3);
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 FUN_08055670(int param_1,char param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  char *pcVar3;
  
  uVar1 = *(uint *)(&DAT_08073e10 + param_1 * 4);
  if (uVar1 == 3) {
LAB_080556a5:
    if (((param_2 == '@') || (param_2 == ';')) || (param_2 == '\r')) goto LAB_080556c0;
    pcVar3 = "Syntax error following directive";
    goto LAB_080556e6;
  }
  if (uVar1 < 4) {
    if (uVar1 == 1) goto LAB_080556a5;
  }
  else if (uVar1 == 6) goto LAB_080556a5;
LAB_080556c0:
  uVar1 = *(uint *)(&DAT_08073e10 + param_1 * 4);
  if (uVar1 == 0) {
LAB_080556f1:
    uVar2 = 1;
  }
  else {
    if (uVar1 < 3) {
      if (param_3 == 0) goto LAB_080556f1;
      pcVar3 = "Illegal line start should be blank";
    }
    else {
      if ((4 < uVar1) || (param_3 != 0)) goto LAB_080556f1;
      pcVar3 = "Label missing from line start";
    }
LAB_080556e6:
    FUN_08052f1c(4,pcVar3);
    uVar2 = 0;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08055700(void)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    (&DAT_0807ec80)[uVar1] = 0x3f;
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x100);
  DAT_0807ecdb = 0;
  DAT_0807ecfc = 1;
  DAT_0807ecdd = 2;
  DAT_0807eca1 = 3;
  DAT_0807eca3 = 4;
  DAT_0807ecaa = 5;
  DAT_0807ecbd = 6;
  DAT_0807eca5 = 7;
  DAT_0807eca6 = 8;
  DAT_0807ecde = 9;
  uVar1 = 0;
  do {
    (&DAT_080828a0)[uVar1] = 0;
    (&DAT_080827a0)[uVar1] = 0;
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x3e);
  DAT_080828a0 = 1;
  DAT_080828a4 = 1;
  _DAT_080828a8 = 1;
  _DAT_080828c8 = 1;
  _DAT_080828e8 = 1;
  _DAT_080828ec = 1;
  _DAT_080828f0 = 1;
  _DAT_080828f8 = 1;
  _DAT_0808298c = 1;
  _DAT_080827b8 = 1;
  _DAT_080827bc = 1;
  _DAT_080827c0 = 1;
  _DAT_08082890 = 1;
  _DAT_08082828 = 1;
  _DAT_0808282c = 1;
  _DAT_08082830 = 1;
  _DAT_08082834 = 1;
  _DAT_08082894 = 1;
  _DAT_08082840 = 1;
  _DAT_08082844 = 1;
  _DAT_08082848 = 1;
  _DAT_0808284c = 1;
  _DAT_08082860 = 1;
  _DAT_0808286c = 1;
  _DAT_0807ed80 = 2;
  _DAT_0807ed84 = 1;
  _DAT_0807ed88 = 1;
  _DAT_0807ed8c = 2;
  _DAT_0807ed90 = 5;
  _DAT_0807ed94 = 4;
  _DAT_0807ed98 = 5;
  _DAT_0807ed9c = 5;
  _DAT_0807ee14 = 5;
  _DAT_0807ee74 = 5;
  _DAT_0807eda0 = 5;
  _DAT_0807ee70 = 5;
  _DAT_0807eda4 = 2;
  _DAT_0807eda8 = 0;
  _DAT_0807edac = 0;
  _DAT_0807edb0 = 2;
  _DAT_0807edb4 = 2;
  _DAT_0807edb8 = 2;
  _DAT_0807edbc = 2;
  _DAT_0807edc0 = 2;
  _DAT_0807edc4 = 4;
  _DAT_0807ee1c = 4;
  _DAT_0807ee34 = 4;
  _DAT_0807ee38 = 4;
  _DAT_0807edc8 = 2;
  _DAT_0807edcc = 1;
  _DAT_0807edd0 = 1;
  _DAT_0807edd4 = 1;
  _DAT_0807edd8 = 1;
  _DAT_0807eddc = 2;
  _DAT_0807ede0 = 2;
  _DAT_0807ede4 = 2;
  _DAT_0807ede8 = 2;
  _DAT_0807edec = 2;
  _DAT_0807edf0 = 2;
  _DAT_0807edf4 = 4;
  _DAT_0807edf8 = 4;
  _DAT_0807edfc = 4;
  _DAT_0807ee00 = 2;
  _DAT_0807ee04 = 2;
  _DAT_0807ee08 = 6;
  _DAT_0807ee6c = 3;
  _DAT_0807ee0c = 2;
  _DAT_0807ee10 = 1;
  _DAT_0807ee44 = 2;
  _DAT_0807ee48 = 2;
  _DAT_0807ee50 = 2;
  _DAT_0807ee60 = 2;
  _DAT_0807ee3c = 2;
  _DAT_0807ee40 = 1;
  _DAT_0807ee20 = 5;
  _DAT_0807ee24 = 5;
  _DAT_0807ee28 = 5;
  _DAT_0807ee2c = 5;
  _DAT_0807ee30 = 1;
  _DAT_0807ee5c = 4;
  return;
}



void FUN_08055ab0(char param_1)

{
  if (param_1 != '\0') {
    (&DAT_0807ee80)[DAT_0807f080] = param_1;
    DAT_0807f080 = DAT_0807f080 + 1;
  }
  return;
}



void FUN_08055ad0(uint param_1)

{
  while (DAT_0807f080 < param_1) {
    FUN_08055ab0(' ');
  }
  return;
}



void FUN_08055af8(void)

{
  if ((DAT_080826ac != 0) && (((byte)DAT_08082644 & 1) != 0)) {
    FUN_08055db8();
  }
  return;
}



void FUN_08055b14(int *param_1)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  uint *puVar4;
  uint *puVar5;
  int local_c;
  uint local_8;
  
  iVar2 = *param_1;
  if (((*(char *)(iVar2 + DAT_08082584) != ';') && (DAT_080825c4 == 0)) ||
     ((*(char *)(iVar2 + DAT_08082584) != '@' && (DAT_080825c4 == 1)))) {
    cVar1 = *(char *)(iVar2 + DAT_08082584);
    while (cVar1 != '\r') {
      cVar1 = *(char *)(iVar2 + DAT_08082584);
      *param_1 = *param_1 + 1;
      FUN_08055ab0(cVar1);
      iVar2 = *param_1;
      cVar1 = *(char *)(iVar2 + DAT_08082584);
    }
    FUN_08056244();
    return;
  }
  if (DAT_0807f080 < 0x18) {
    local_8 = 0x17;
  }
  else {
    local_8 = 0x33;
    FUN_08055ab0(' ');
  }
  FUN_08055ad0(local_8);
  puVar5 = (uint *)&stack0xffffffe8;
  if (DAT_0807f080 < 0x34) goto LAB_08055c17;
  local_c = 0;
  if (*(char *)(*param_1 + DAT_08082584) != '\r') {
    pcVar3 = (char *)(*param_1 + DAT_08082584);
    do {
      pcVar3 = pcVar3 + 1;
      local_c = local_c + 1;
    } while (*pcVar3 != '\r');
  }
  puVar5 = (uint *)&stack0xffffffe8;
  if (DAT_0807f080 + local_c <= DAT_0808258c) goto LAB_08055c17;
  puVar5 = (uint *)&stack0xffffffe8;
  if (DAT_0808258c < local_8 + local_c) goto LAB_08055c17;
  FUN_08056244();
  puVar4 = (uint *)&stack0xffffffe4;
  do {
    puVar4[-1] = 0x8055c0e;
    FUN_08055ad0(*puVar4);
    puVar5 = puVar4 + 1;
LAB_08055c17:
    if (DAT_0807f080 < DAT_0808258c) {
      do {
        if (*(char *)(*param_1 + DAT_08082584) == '\r') break;
        *(int *)((int)puVar5 + -4) = (int)*(char *)(*param_1 + DAT_08082584);
        *param_1 = *param_1 + 1;
        *(undefined4 *)((int)puVar5 + -8) = 0x8055c3b;
        FUN_08055ab0(*(char *)((int)puVar5 + -4));
      } while (DAT_0807f080 < DAT_0808258c);
      if (DAT_0807f080 < DAT_0808258c) {
        return;
      }
    }
    *(undefined4 *)((int)puVar5 + -4) = 0x8055c05;
    FUN_08056244();
    puVar4 = (uint *)((int)puVar5 + -4);
    *(uint *)((int)puVar5 + -4) = local_8;
  } while( true );
}



void FUN_08055c5c(uint param_1,int param_2,int *param_3)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  char *pcVar4;
  int local_c;
  
  bVar2 = false;
  FUN_08055ad0(param_1);
  iVar3 = *param_3;
LAB_08055d52:
  do {
    if (bVar2) {
      if (*(char *)(iVar3 + DAT_08082584) == '\r') {
LAB_08055d8f:
        iVar3 = *param_3;
        while ((byte)(*(char *)(iVar3 + DAT_08082584) - 0x1fU) < 2) {
          iVar3 = iVar3 + 1;
          *param_3 = iVar3;
        }
        return;
      }
LAB_08055c91:
      iVar3 = *param_3;
      if (1 < (byte)(*(char *)(iVar3 + DAT_08082584) - 0x1fU)) {
        FUN_08055ab0(*(char *)(iVar3 + DAT_08082584));
        if (*(char *)(*param_3 + DAT_08082584) == '\"') {
          bVar2 = (bool)(bVar2 ^ 1);
        }
        iVar3 = *param_3 + 1;
        *param_3 = iVar3;
        goto LAB_08055d52;
      }
    }
    else {
      iVar3 = FUN_0805cb78(*(char *)(iVar3 + DAT_08082584));
      if (iVar3 == 0) goto LAB_08055c91;
      if ((param_2 == 0) || (iVar3 = *param_3, 1 < (byte)(*(char *)(iVar3 + DAT_08082584) - 0x1fU)))
      goto LAB_08055d8f;
    }
    local_c = 0;
    if ((byte)(*(char *)(iVar3 + DAT_08082584) - 0x1fU) < 2) {
      pcVar4 = (char *)(iVar3 + DAT_08082584);
      do {
        pcVar4 = pcVar4 + 1;
        local_c = local_c + 1;
      } while ((byte)(*pcVar4 - 0x1fU) < 2);
    }
    cVar1 = *(char *)(local_c + iVar3 + DAT_08082584);
    if (cVar1 == '\r') {
      return;
    }
    if (!bVar2) {
      if ((cVar1 == ';') && (DAT_080825c4 == 0)) {
        return;
      }
      if ((cVar1 == '@') && (DAT_080825c4 == 1)) {
        return;
      }
    }
    do {
      cVar1 = *(char *)(iVar3 + DAT_08082584);
      *param_3 = *param_3 + 1;
      FUN_08055ab0(cVar1);
      iVar3 = *param_3;
    } while ((byte)(*(char *)(iVar3 + DAT_08082584) - 0x1fU) < 2);
  } while( true );
}



void FUN_08055db8(void)

{
  char *pcVar1;
  char cVar2;
  int local_8;
  
  local_8 = 0;
  if (DAT_0808015c == 0) {
    if (DAT_0808258c < 0x18) {
      if (DAT_0807f080 < 0x18) {
        FUN_08055ad0(0x17);
      }
      else {
        FUN_08056244();
      }
      cVar2 = DAT_08082584[local_8];
      while (cVar2 != '\r') {
        pcVar1 = DAT_08082584 + local_8;
        local_8 = local_8 + 1;
        FUN_08055ab0(*pcVar1);
        cVar2 = DAT_08082584[local_8];
      }
    }
    else {
      if ((0x17 < DAT_0807f080) && (1 < (byte)(*DAT_08082584 - 0x1fU))) {
        FUN_08056244();
      }
      while ((((DAT_08082584[local_8] != ';' || (DAT_080825c4 != 0)) &&
              ((DAT_08082584[local_8] != '@' || (DAT_080825c4 != 1)))) && (0x1f < DAT_0808258c))) {
        FUN_08055c5c(0x17,0,&local_8);
        cVar2 = DAT_08082584[local_8];
        if ((((cVar2 == '\r') || ((cVar2 == ';' && (DAT_080825c4 == 0)))) ||
            ((cVar2 == '@' && (DAT_080825c4 == 1)))) || (DAT_0808258c < 0x28)) break;
        if (0x1e < DAT_0807f080) {
          FUN_08056244();
        }
        FUN_08055c5c(0x1f,0,&local_8);
        cVar2 = DAT_08082584[local_8];
        if (((cVar2 == '\r') || (cVar2 == ';')) ||
           (((cVar2 == '@' && (DAT_080825c4 == 1)) || (DAT_0808258c < 0x34)))) break;
        if (0x26 < DAT_0807f080) {
          FUN_08056244();
        }
        FUN_08055c5c(0x27,1,&local_8);
      }
      if (DAT_08082584[local_8] != '\r') {
        FUN_08055b14(&local_8);
      }
    }
    FUN_08056244();
  }
  DAT_0808015c = 1;
  DAT_0807f080 = 0;
  return;
}



void FUN_08055f78(char *param_1)

{
  char cVar1;
  
  cVar1 = *param_1;
  while (cVar1 != '\0') {
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    FUN_08055ab0(cVar1);
    cVar1 = *param_1;
  }
  return;
}



void FUN_08055f9c(void)

{
  if ((DAT_080826ac != 0) && (((byte)DAT_08082644 & 1) != 0)) {
    FUN_08055fb8();
  }
  return;
}



void FUN_08055fb8(void)

{
  char local_c [8];
  
  if (DAT_0807f080 != 0) {
    FUN_08056244();
  }
  sprintf(local_c,"%5lu ",DAT_08082594);
  FUN_08055f78(local_c);
  return;
}



void FUN_08055fec(int param_1)

{
  char cVar1;
  
  if (param_1 < 10) {
    cVar1 = (char)param_1 + '0';
  }
  else {
    cVar1 = (char)param_1 + '7';
  }
  FUN_08055ab0(cVar1);
  return;
}



void FUN_08056010(int param_1)

{
  if ((((byte)DAT_08082644 & 1) != 0) && (DAT_080826ac != 0)) {
    FUN_08055f78("       ");
    FUN_08055fec(param_1);
    FUN_08055ab0(' ');
  }
  return;
}



void FUN_08056040(void)

{
  if ((DAT_080826ac != 0) && (((byte)DAT_08082644 & 1) != 0)) {
    FUN_08056080();
  }
  return;
}



void FUN_0805605c(ulong param_1)

{
  char local_10 [12];
  
  sprintf(local_10,"%.8lX",param_1);
  FUN_08055f78(local_10);
  return;
}



void FUN_08056080(void)

{
  FUN_08055ad0(5);
  FUN_0805605c(DAT_080826a0);
  FUN_08055ab0(' ');
  return;
}



void FUN_080560a0(undefined4 param_1)

{
  if ((DAT_080826ac != 0) && (((byte)DAT_08082644 & 1) != 0)) {
    if (0x16 < DAT_0807f080) {
      FUN_08056244();
    }
    FUN_08055ad0(0xe);
    FUN_0805605c(param_1);
    FUN_08055ab0(' ');
  }
  return;
}



void FUN_080560dc(byte param_1)

{
  if ((DAT_080826ac != 0) && (((byte)DAT_08082644 & 1) != 0)) {
    if (0x16 < DAT_0807f080) {
      FUN_08056244();
    }
    FUN_08055ad0(0xe);
    FUN_08055fec((int)(param_1 & 0xf0) >> 4);
    FUN_08055fec(param_1 & 0xf);
    FUN_08055ab0(' ');
  }
  return;
}



void FUN_08056134(int param_1)

{
  char *pcVar1;
  
  if ((DAT_080826ac != 0) && (((byte)DAT_08082644 & 1) != 0)) {
    if (param_1 == 0) {
      pcVar1 = "FALSE";
    }
    else {
      pcVar1 = "TRUE ";
    }
    FUN_08055f78(pcVar1);
    FUN_08055f78("    ");
  }
  return;
}



void FUN_08056170(char param_1)

{
  undefined1 *puVar1;
  char *pcVar2;
  
  puVar1 = &stack0xfffffff8;
  if (0x5e < (byte)(param_1 - 0x20U)) {
    if (param_1 == '\x7f') {
      FUN_08055f78("|?");
      return;
    }
    if (param_1 == '\x1f') {
      pcVar2 = &stack0xfffffff4;
      goto LAB_080561ce;
    }
    if (param_1 < '\0') {
      FUN_08055f78("|!");
      FUN_08056170(param_1 + -0x80);
      return;
    }
    puVar1 = &stack0xfffffff4;
    FUN_08055ab0('|');
    param_1 = param_1 + '@';
  }
  pcVar2 = puVar1 + -4;
  *(int *)(puVar1 + -4) = (int)param_1;
LAB_080561ce:
  pcVar2[-0xffffffff00000004] = -0x2d;
  pcVar2[-0xffffffff00000003] = 'a';
  pcVar2[-0xffffffff00000002] = '\x05';
  pcVar2[-0xffffffff00000001] = '\b';
  FUN_08055ab0(*pcVar2);
  return;
}



void FUN_080561d8(uint param_1,char *param_2)

{
  uint uVar1;
  
  if (((DAT_080826ac != 0) && (((byte)DAT_08082644 & 1) != 0)) && (uVar1 = 1, param_1 != 0)) {
    do {
      if (0xfa < DAT_0807f080) {
        FUN_08056244();
      }
      FUN_08055ad0(0xe);
      FUN_08056170(*param_2);
      param_2 = param_2 + 1;
      uVar1 = uVar1 + 1;
    } while (uVar1 <= param_1);
  }
  return;
}



void FUN_08056234(void)

{
  DAT_0807f080 = 0;
  return;
}



void FUN_08056244(void)

{
  if (DAT_0807f080 != 0) {
    FUN_08055ab0('\r');
    (&DAT_0807ee80)[DAT_0807f080] = 0;
    FUN_08054714("%s");
    DAT_0807f080 = 0;
  }
  return;
}



void FUN_0805627c(void)

{
  DAT_08082644._0_1_ = (byte)DAT_08082644 & 0xfe;
  DAT_0807f080 = 0;
  return;
}



void FUN_080562a0(void)

{
  DAT_0807f0d0 = 0;
  DAT_0807f0c0 = 0;
  DAT_0807f0cc = 0;
  DAT_0807f0c8 = 0;
  return;
}



void FUN_080562d0(void)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = DAT_0807f0c8;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)puVar2[6];
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  DAT_0807f0cc = 0;
  DAT_0807f0c8 = (uint *)0x0;
  puVar2 = DAT_0807f0c0;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)puVar2[4];
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  DAT_0807f0c0 = (uint *)0x0;
  DAT_0807f0c4 = 0;
  return;
}



void FUN_0805633c(void)

{
  if (DAT_080825d0 != 2) {
    DAT_0807f0c4 = 0;
  }
  return;
}



void FUN_08056354(void)

{
  uint *puVar1;
  uint *puVar2;
  
  if (DAT_080825d0 == 1) {
    if (DAT_0807f0c0 == (uint *)0x0) {
      puVar1 = FUN_0805eddc(0x20);
      DAT_0807f0c0 = puVar1;
    }
    else {
      puVar1 = FUN_0805eddc(0x20);
      DAT_0807f0c4[4] = (uint)puVar1;
    }
    DAT_0807f0c4 = puVar1;
    puVar1[4] = 0;
    puVar1[1] = 0;
    puVar1[5] = 0;
    puVar1[6] = 0;
    *puVar1 = 0;
    DAT_0807f0d0 = DAT_0807f0d0 + 1;
    puVar1[7] = DAT_0807f0d0;
    DAT_0807f0cc = 0;
    DAT_0807f0c8 = (uint *)0x0;
  }
  else if (DAT_080825d0 == 2) {
    puVar2 = DAT_0807f0c0;
    puVar1 = DAT_0807f0c8;
    if (DAT_0807f0c4[4] != 0) {
      while (puVar1 != (uint *)0x0) {
        puVar2 = (uint *)puVar1[6];
        FUN_0805ee14(puVar1);
        puVar1 = puVar2;
      }
      puVar2 = (uint *)DAT_0807f0c4[4];
    }
    DAT_0807f0c8 = (uint *)puVar2[5];
    DAT_0807f0c4 = puVar2;
  }
  return;
}



undefined4 FUN_08056444(int param_1)

{
  undefined4 uVar1;
  
  if (param_1 == 3) {
    uVar1 = 8;
  }
  else {
    uVar1 = 4;
  }
  return uVar1;
}



int FUN_0805645c(int param_1,undefined4 param_2,int param_3,undefined4 param_4,int param_5)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  char local_24 [32];
  
  if (param_3 == 0) {
    pcVar3 = "x$litpool_e$%u";
  }
  else {
    pcVar3 = "x$litpool$%u";
  }
  sprintf(local_24,pcVar3,param_2);
  uVar2 = 0xffffffff;
  pcVar3 = local_24;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  if (param_1 == 1) {
    DAT_08082628 = DAT_08082628 + 1;
    param_5 = DAT_08082690;
    DAT_08082690 = ~uVar2 + DAT_08082690;
  }
  else {
    memcpy((void *)(param_5 + DAT_0807ff08),local_24,~uVar2);
    FUN_08051dc0(param_5,param_4);
  }
  return param_5;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

void FUN_080564e4(void)

{
  int *piVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  uint local_28;
  undefined4 local_18;
  uint local_8;
  
  if (DAT_080825d0 == 1) {
    if (DAT_0807f0c4[1] != 0) {
      for (; (DAT_080826a0 & 3) != 0; DAT_080826a0 = DAT_080826a0 + 1) {
      }
      uVar3 = FUN_0805645c(1,DAT_0807f0c4[7],1,DAT_080826a0,0);
      puVar5 = DAT_0807f0c4;
      DAT_0807f0c4[2] = uVar3;
      *puVar5 = DAT_080826a0;
      DAT_080826a0 = DAT_080826a0 + puVar5[1];
      for (piVar1 = (int *)puVar5[5]; piVar1 != (int *)0x0; piVar1 = (int *)piVar1[6]) {
        piVar1[4] = *DAT_0807f0c4;
        *(byte *)(piVar1 + 5) = *(byte *)(piVar1 + 5) | 2;
        iVar4 = FUN_08056444(*piVar1);
        *DAT_0807f0c4 = *DAT_0807f0c4 + iVar4;
      }
      uVar3 = FUN_0805645c(DAT_080825d0,DAT_0807f0c4[7],0,DAT_080826a0 - 1,0);
      DAT_0807f0c4[3] = uVar3;
    }
    puVar5 = FUN_0805eddc(0x20);
    DAT_0807f0c4[4] = (uint)puVar5;
    puVar5[1] = 0;
    puVar5[4] = 0;
    *puVar5 = DAT_080826a0;
    puVar5[5] = 0;
    puVar5[6] = 0;
    DAT_0807f0d0 = DAT_0807f0d0 + 1;
    DAT_0807f0c4 = puVar5;
    puVar5[7] = DAT_0807f0d0;
  }
  else if (DAT_080825d0 == 2) {
    if (DAT_0807f0c4[1] != 0) {
      while ((DAT_080826a0 & 3) != 0) {
        FUN_0805182c(0);
      }
      FUN_0805645c(DAT_080825d0,DAT_0807f0c4[7],1,DAT_080826a0,DAT_0807f0c4[2]);
      local_28 = 0;
      puVar2 = (undefined4 *)DAT_0807f0c4[5];
      puVar5 = DAT_0807f0c4;
      uVar3 = DAT_080826a0;
      while ((DAT_080826a0 = uVar3, puVar2 != (undefined4 *)0x0 && (local_28 < puVar5[1]))) {
        switch(*puVar2) {
        case 0:
        case 2:
          FUN_08051c68(puVar2[1]);
          local_28 = local_28 + 4;
          puVar5 = DAT_0807f0c4;
          break;
        case 1:
          if (DAT_08082654 == 0) {
            local_8 = DAT_0808276c - 1U | 0x82000000;
          }
          else {
            local_8 = 0x4000004;
          }
          FUN_080514cc(uVar3,local_8,0);
          FUN_08051c68(puVar2[1]);
          local_28 = local_28 + 4;
          puVar5 = DAT_0807f0c4;
          break;
        case 3:
          FUN_08051c68(puVar2[1]);
          FUN_08051c68(puVar2[2]);
          local_28 = local_28 + 8;
          puVar5 = DAT_0807f0c4;
          break;
        case 4:
          uVar7 = puVar2[1];
          iVar4 = puVar2[3];
          if (DAT_08082654 == 0) {
            if ((*(byte *)(iVar4 + 8) & 3) == 1) {
              local_18 = puVar2[2] & 0xffffff | 0x8a000000;
            }
            else {
              local_18 = *(int *)(iVar4 + 0x1c) - 1U | 0x82000000;
              if ((*(uint *)(iVar4 + 8) & 0x30003000) == 0x10000000) {
                uVar7 = uVar7 | 1;
              }
            }
          }
          else {
            local_18 = 0;
            if ((*(byte *)(iVar4 + 8) & 3) == 1) {
              local_18 = puVar2[2] & 0xffffff;
                    // WARNING: Ignoring partial resolution of indirect
              local_18._3_1_ = 0xc;
            }
            else {
                    // WARNING: Ignoring partial resolution of indirect
              local_18._3_1_ = 4;
              if (DAT_080825c4 == 0) {
                iVar4 = FUN_08051d60(*(uint *)(iVar4 + 0x1c));
                if ((*(byte *)(iVar4 + 5) & 0x10) == 0) {
                  uVar6 = 6;
                }
                else {
                  uVar6 = 8;
                }
                local_18 = local_18 & 0xff000000 | uVar6;
                uVar7 = uVar7 + DAT_08082664;
                if ((*(byte *)(iVar4 + 5) & 0x10) != 0) {
LAB_080568a4:
                  uVar7 = uVar7 + DAT_08082668;
                }
              }
              else {
                if (*(int *)(iVar4 + 0x1c) == 2) {
                  local_18 = 8;
                }
                else {
                  local_18 = 6;
                }
                local_18 = local_18 | 0x4000000;
                uVar7 = uVar7 + DAT_08082664;
                if (*(int *)(iVar4 + 0x1c) == 2) goto LAB_080568a4;
              }
            }
          }
          FUN_080514cc(uVar3,local_18,0);
          FUN_08051c68(uVar7);
          local_28 = local_28 + 4;
          puVar5 = DAT_0807f0c4;
        }
        puVar2 = (undefined4 *)puVar2[6];
        uVar3 = DAT_080826a0;
      }
      FUN_0805645c(DAT_080825d0,puVar5[7],0,uVar3 - 1,puVar5[3]);
    }
    DAT_0807f0c4 = (uint *)DAT_0807f0c4[4];
    if (DAT_0807f0c8 == 0) {
      DAT_0807f0c8 = DAT_0807f0c4[5];
    }
  }
  return;
}



void FUN_0805693c(void)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = DAT_0807f0c8;
  while (puVar2[4] + 0xff8 <= DAT_080826a0) {
    puVar1 = (uint *)puVar2[6];
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  DAT_0807f0c8 = puVar2;
  return;
}



bool FUN_08056974(int param_1,int param_2,int param_3,int param_4)

{
  if (param_4 == 4) {
    param_2 = *(int *)(param_3 + 0x18);
  }
  else if (param_4 != 3) {
    return true;
  }
  return *(int *)(param_1 + 8) == param_2;
}



uint FUN_080569b0(int param_1,int param_2)

{
  uint uVar1;
  
  if (param_2 == 1) {
    uVar1 = param_1 + 4U & 0xfffffffd;
  }
  else {
    uVar1 = param_1 + 8;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint * FUN_080569c8(uint param_1,uint param_2,int param_3,int param_4,uint param_5,int param_6,
                   int param_7)

{
  uint *puVar1;
  bool bVar2;
  uint uVar3;
  undefined3 extraout_var;
  uint *puVar4;
  int iVar5;
  undefined3 extraout_var_00;
  uint uVar6;
  char *pcVar7;
  
  if (DAT_080825d0 == 1) {
    puVar4 = DAT_0807f0c8;
    if ((param_1 & 1) != 0) {
      for (; puVar4 != (uint *)0x0; puVar4 = (uint *)puVar4[6]) {
        uVar3 = FUN_080569b0(DAT_080826a0,DAT_080795ec);
        uVar6 = puVar4[4];
        if ((((((puVar4[5] & 1) != 0) && (*puVar4 == param_5)) && (puVar4[1] == param_2)) &&
            (puVar4[7] == DAT_0808276c)) &&
           ((param_5 < 3 ||
            (bVar2 = FUN_08056974((int)puVar4,param_3,param_4,param_5),
            CONCAT31(extraout_var,bVar2) != 0)))) {
          if ((puVar4[5] & 2) == 0) {
            return puVar4;
          }
          if ((param_6 <= (int)(uVar6 - uVar3)) && ((int)(uVar6 - uVar3) <= param_7)) {
            return puVar4;
          }
        }
      }
    }
    puVar4 = FUN_0805eddc(0x20);
    puVar1 = puVar4;
    if (DAT_0807f0c8 != (uint *)0x0) {
      DAT_0807f0cc[6] = (uint)puVar4;
      puVar1 = DAT_0807f0c8;
    }
    DAT_0807f0c8 = puVar1;
    iVar5 = DAT_0807f0c4;
    DAT_0807f0cc = puVar4;
    if (*(int *)(DAT_0807f0c4 + 0x14) == 0) {
      *(uint **)(DAT_0807f0c4 + 0x14) = puVar4;
    }
    *(uint **)(iVar5 + 0x18) = puVar4;
    puVar4[5] = param_1;
    *puVar4 = param_5;
    puVar4[1] = param_2;
    puVar4[6] = 0;
    puVar4[4] = 0;
    puVar4[7] = DAT_0808276c;
    iVar5 = FUN_08056444(param_5);
    *(int *)(DAT_0807f0c4 + 4) = *(int *)(DAT_0807f0c4 + 4) + iVar5;
  }
  else {
    FUN_0805693c();
    for (puVar4 = DAT_0807f0c8; puVar4 != (uint *)0x0; puVar4 = (uint *)puVar4[6]) {
      uVar3 = FUN_080569b0(DAT_080826a0,DAT_080795ec);
      uVar6 = puVar4[4];
      if ((((*puVar4 == param_5) && (puVar4[1] == param_2)) &&
          ((param_5 < 3 ||
           (bVar2 = FUN_08056974((int)puVar4,param_3,param_4,param_5),
           CONCAT31(extraout_var_00,bVar2) != 0)))) &&
         (((puVar4[7] == DAT_0808276c && (param_6 <= (int)(uVar6 - uVar3))) &&
          ((int)(uVar6 - uVar3) <= param_7)))) {
        *(byte *)(puVar4 + 5) = (byte)puVar4[5] | 1;
        return puVar4;
      }
    }
    for (puVar4 = *(uint **)(DAT_0807f0c4 + 0x14); puVar4 != (uint *)0x0; puVar4 = (uint *)puVar4[6]
        ) {
      uVar6 = FUN_080569b0(DAT_080826a0,DAT_080795ec);
      if ((((puVar4[5] & 1) == 0) && ((*puVar4 == param_5 || (*puVar4 == 0)))) &&
         ((puVar4[7] == DAT_0808276c &&
          ((param_6 <= (int)(puVar4[4] - uVar6) && ((int)(puVar4[4] - uVar6) <= param_7)))))) {
        puVar4[5] = puVar4[5] | 1;
        *puVar4 = param_5;
        puVar4[1] = param_2;
        return puVar4;
      }
    }
    if (DAT_080795ec == 1) {
      pcVar7 = "Literal pool too distant (>1KB), use LTORG to dump it within range";
    }
    else {
      pcVar7 = "Literal pool too distant (use LTORG to dump it within 4KB)";
    }
    FUN_08052f1c(4,pcVar7);
    _DAT_0807f0b0 = DAT_080826a0 + 8U & 0xfffffffc;
    puVar4 = (uint *)&DAT_0807f0a0;
  }
  return puVar4;
}



uint FUN_08056bec(int param_1,int param_2,uint param_3,int param_4,int param_5)

{
  uint uVar1;
  uint *puVar2;
  
  uVar1 = 0;
  if (param_2 == 0) {
    puVar2 = FUN_080569c8((uint)(param_1 != 0),param_3,0,0,0,param_4,param_5);
    uVar1 = puVar2[4];
  }
  return uVar1;
}



uint FUN_08056c1c(uint param_1,uint param_2,int param_3,int param_4)

{
  uint *puVar1;
  
  puVar1 = FUN_080569c8(1,param_2,0,param_1,4,param_3,param_4);
  puVar1[2] = *(uint *)(param_1 + 0x18);
  puVar1[3] = param_1;
  return puVar1[4];
}



uint FUN_08056c4c(uint param_1,uint param_2,int param_3,int param_4)

{
  uint *puVar1;
  
  puVar1 = FUN_080569c8(param_2,param_1,0,0,1,param_3,param_4);
  return puVar1[4];
}



uint FUN_08056c6c(uint param_1,int param_2,int param_3)

{
  uint *puVar1;
  
  puVar1 = FUN_080569c8(1,param_1,0,0,2,param_2,param_3);
  return puVar1[4];
}



uint FUN_08056c8c(uint param_1,uint param_2,int param_3,int param_4)

{
  uint *puVar1;
  
  puVar1 = FUN_080569c8(1,param_1,param_2,0,3,param_3,param_4);
  puVar1[2] = param_2;
  return puVar1[4];
}



void FUN_08056cb4(void)

{
  FUN_080564e4();
  return;
}



void FUN_08056cc0(void)

{
  uint *puVar1;
  
  if (DAT_080825d0 == 1) {
    puVar1 = FUN_0805eddc(0x18);
    DAT_0807f0d8 = puVar1;
    *puVar1 = 2;
    puVar1[5] = 0;
    puVar1 = FUN_0805eddc(0x18);
    DAT_0807f0d8[4] = (uint)puVar1;
    *puVar1 = 3;
    *(undefined4 *)(DAT_0807f0d8[4] + 0x10) = 0;
    *(uint **)(DAT_0807f0d8[4] + 0x14) = DAT_0807f0d8;
  }
  DAT_0807f0d4 = DAT_0807f0d8[4];
  DAT_0807f0dc = 0;
  return;
}



void FUN_08056d34(void)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = DAT_0807f0d8;
  if (DAT_080825d0 == 2) {
    while (puVar2 != (uint *)0x0) {
      puVar1 = (uint *)puVar2[4];
      FUN_0805ee14(puVar2);
      puVar2 = puVar1;
    }
    DAT_0807f0d8 = (uint *)0x0;
  }
  return;
}



bool FUN_08056d74(uint param_1,int param_2)

{
  bool bVar1;
  
  if (param_2 == 1) {
    bVar1 = param_1 == DAT_08082780;
  }
  else if (param_2 == 0) {
    bVar1 = param_1 <= DAT_08082780;
  }
  else {
    bVar1 = true;
  }
  return bVar1;
}



undefined4 FUN_08056db0(int param_1,undefined4 *param_2,undefined4 *param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  
  puVar2 = *(undefined4 **)(DAT_0807f0d4 + 0x14);
  uVar3 = DAT_08082780;
  do {
    switch(*puVar2) {
    case 0:
      if ((puVar2[2] == param_1) &&
         (bVar1 = FUN_08056d74(uVar3,param_4), CONCAT31(extraout_var,bVar1) != 0)) {
        *param_2 = puVar2[1];
        *param_3 = puVar2[3];
        return 1;
      }
      break;
    case 1:
    case 2:
    case 3:
      return 0;
    case 4:
      uVar3 = uVar3 + 1;
      break;
    case 5:
      uVar3 = uVar3 - 1;
    }
    puVar2 = (undefined4 *)puVar2[5];
  } while( true );
}



undefined4 FUN_08056e28(int param_1,undefined4 *param_2,undefined4 *param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined4 *puVar2;
  uint uVar3;
  
  puVar2 = DAT_0807f0d4;
  uVar3 = DAT_08082780;
  do {
    switch(*puVar2) {
    case 0:
      if ((puVar2[2] == param_1) &&
         (bVar1 = FUN_08056d74(uVar3,param_4), CONCAT31(extraout_var,bVar1) != 0)) {
        *param_2 = puVar2[1];
        *param_3 = puVar2[3];
        return 1;
      }
      break;
    case 1:
    case 2:
    case 3:
      return 0;
    case 4:
      uVar3 = uVar3 - 1;
      break;
    case 5:
      uVar3 = uVar3 + 1;
    }
    puVar2 = (undefined4 *)puVar2[4];
  } while( true );
}



undefined4 FUN_08056e98(int param_1,int *param_2)

{
  int iVar1;
  char *pcVar2;
  bool bVar3;
  int local_c;
  char *local_8;
  
  if ((DAT_0807f0dc == (int *)0x0) || (iVar1 = FUN_080613f8(param_1,param_2,&local_c), iVar1 == 0))
  {
    return 1;
  }
  if (local_c == *DAT_0807f0dc) {
    bVar3 = true;
    pcVar2 = (char *)DAT_0807f0dc[1];
    do {
      if (local_c == 0) break;
      local_c = local_c + -1;
      bVar3 = *local_8 == *pcVar2;
      local_8 = local_8 + 1;
      pcVar2 = pcVar2 + 1;
    } while (bVar3);
    if (bVar3) {
      return 1;
    }
  }
  FUN_08052f1c(4,"Incorrect routine name");
  return 0;
}



undefined4 FUN_08056ef4(int param_1,int *param_2,undefined4 *param_3,undefined4 *param_4)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 local_10;
  int local_c;
  undefined4 local_8;
  
  iVar2 = toupper((int)*(char *)(*param_2 + param_1));
  local_c = 2;
  cVar1 = (char)iVar2;
  if (cVar1 == 'F') {
    local_c = 1;
LAB_08056f31:
    iVar2 = *param_2;
    *param_2 = iVar2 + 1;
    iVar2 = toupper((int)*(char *)(param_1 + 1 + iVar2));
    cVar1 = (char)iVar2;
  }
  else if (cVar1 == 'B') {
    local_c = 0;
    goto LAB_08056f31;
  }
  iVar2 = 0;
  if (cVar1 == 'T') {
    iVar2 = 1;
  }
  else {
    if (cVar1 != 'A') goto LAB_08056f69;
    iVar2 = 2;
  }
  iVar3 = *param_2;
  *param_2 = iVar3 + 1;
  cVar1 = *(char *)(param_1 + 1 + iVar3);
LAB_08056f69:
  iVar3 = isdigit((int)cVar1);
  if (iVar3 == 0) {
    FUN_08052f1c(4,"Bad local label number");
  }
  else {
    iVar3 = FUN_0805fbc8(param_1,param_2);
    if ((DAT_08080160 == 0) && (iVar4 = FUN_08056e98(param_1,param_2), iVar4 != 0)) {
      if (local_c == 1) {
        uVar5 = FUN_08056e28(iVar3,&local_8,param_4,iVar2);
      }
      else {
        if (local_c != 0) {
          if (local_c != 2) {
            return local_8;
          }
          local_10 = 0;
          iVar4 = FUN_08056db0(iVar3,&local_8,param_4,iVar2);
          if ((iVar4 != 0) || (iVar2 = FUN_08056e28(iVar3,&local_8,param_4,iVar2), iVar2 != 0)) {
            local_10 = 1;
          }
          *param_3 = local_10;
          return local_8;
        }
        uVar5 = FUN_08056db0(iVar3,&local_8,param_4,iVar2);
      }
      *param_3 = uVar5;
      return local_8;
    }
  }
  return 0;
}



void FUN_08057038(undefined4 param_1)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  
  uVar1 = *(uint *)(DAT_0807f0d4 + 0x14);
  puVar3 = FUN_0805eddc(0x18);
  *(uint **)(uVar1 + 0x10) = puVar3;
  puVar3[5] = uVar1;
  iVar2 = DAT_0807f0d4;
  *(int *)(*(int *)(uVar1 + 0x10) + 0x10) = DAT_0807f0d4;
  *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(uVar1 + 0x10);
  **(undefined4 **)(uVar1 + 0x10) = param_1;
  return;
}



void FUN_08057074(int param_1,int *param_2)

{
  undefined4 uVar1;
  int iVar2;
  char *pcVar3;
  
  uVar1 = FUN_0805fbc8(param_1,param_2);
  if (DAT_08080160 != 0) {
    return;
  }
  iVar2 = FUN_08056e98(param_1,param_2);
  if (iVar2 == 0) {
    return;
  }
  iVar2 = FUN_0805cb78(*(char *)(*param_2 + param_1));
  if (iVar2 == 0) {
    if (*(char *)(*param_2 + param_1) == ':') {
      if (DAT_08082688 == 0) {
        FUN_0805f950();
      }
      else if (DAT_080825c4 != 1) goto LAB_08057130;
      DAT_08082688 = 1;
      DAT_080825c4 = 1;
      DAT_080825d4 = 1;
      DAT_08082654 = 1;
      iVar2 = *param_2;
      *param_2 = iVar2 + 1;
      iVar2 = FUN_0805cb78(*(char *)(param_1 + 1 + iVar2));
      if (iVar2 != 0) goto LAB_08057177;
      pcVar3 = "Syntax error following local label definition";
    }
    else {
LAB_08057130:
      pcVar3 = "Syntax error following local label definition";
    }
LAB_0805716e:
    FUN_08052f1c(4,pcVar3);
  }
  else {
    if (DAT_08082688 == 0) {
      DAT_08082688 = 1;
      DAT_080825c4 = 0;
      if (*(char *)(*param_2 + param_1) == '@') {
LAB_08057169:
        pcVar3 = "Bad local label number";
        goto LAB_0805716e;
      }
    }
    else if (DAT_080825c4 == 1) goto LAB_08057169;
LAB_08057177:
    iVar2 = *param_2;
    while ((byte)(*(char *)(iVar2 + param_1) - 0x1fU) < 2) {
      iVar2 = iVar2 + 1;
      *param_2 = iVar2;
    }
    if (DAT_080825d0 == 1) {
      FUN_08057038(0);
      iVar2 = *(int *)(DAT_0807f0d4 + 0x14);
      *(undefined4 *)(iVar2 + 4) = DAT_080826a0;
      *(undefined4 *)(iVar2 + 8) = uVar1;
      *(undefined4 *)(iVar2 + 0xc) = DAT_0808276c;
    }
    else {
      DAT_0807f0d4 = *(int *)(DAT_0807f0d4 + 0x10);
    }
  }
  return;
}



void FUN_080571d8(undefined4 param_1)

{
  DAT_0807f0dc = param_1;
  if (DAT_080825d0 == 1) {
    FUN_08057038(1);
  }
  else {
    DAT_0807f0d4 = *(int *)(DAT_0807f0d4 + 0x10);
  }
  return;
}



void FUN_08057204(void)

{
  if (DAT_080825d0 == 1) {
    FUN_08057038(4);
  }
  else {
    DAT_0807f0d4 = *(int *)(DAT_0807f0d4 + 0x10);
  }
  return;
}



void FUN_08057230(void)

{
  if (DAT_080825d0 == 1) {
    FUN_08057038(5);
  }
  else {
    DAT_0807f0d4 = *(int *)(DAT_0807f0d4 + 0x10);
  }
  return;
}



undefined4 FUN_08057260(uint param_1,int param_2,uint param_3,int param_4)

{
  undefined4 uVar1;
  uint uVar2;
  
  uVar2 = 0;
  if (param_3 != 0) {
    do {
      if (param_1 <= uVar2) {
        return 1;
      }
      if (*(char *)(uVar2 + param_2) < *(char *)(uVar2 + param_4)) {
        return 1;
      }
      if (*(char *)(uVar2 + param_4) < *(char *)(uVar2 + param_2)) goto LAB_080572a5;
      uVar2 = uVar2 + 1;
    } while (uVar2 < param_3);
  }
  if (param_1 == param_3) {
    uVar1 = 0;
  }
  else {
LAB_080572a5:
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



undefined4 FUN_080572c4(int *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint local_28;
  int local_24;
  char local_15;
  undefined4 local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
  local_10 = 0;
  local_14 = 0;
  uVar3 = 0;
LAB_080572e0:
  uVar2 = local_10;
  iVar1 = *param_1;
  local_15 = *(char *)(local_10 + iVar1);
  if (local_15 == '$') {
    if (*(char *)(local_10 + 1 + iVar1) == '$') {
      local_14 = 1;
      *(undefined1 *)(uVar3 + param_2) = 0x24;
      local_10 = local_10 + 2;
    }
    else {
      local_10 = local_10 + 1;
      iVar1 = FUN_080613f8(iVar1,(int *)&local_10,(int *)&local_c);
      if (iVar1 != 0) {
        local_24 = 0;
        for (local_28 = 0; local_28 < *DAT_0807f0e4; local_28 = local_28 + 1) {
          iVar1 = FUN_08057260(*(uint *)(DAT_0807f0e4[1] + local_24),
                               *(int *)(DAT_0807f0e4[1] + 4 + local_24),local_c,local_8);
          if (iVar1 == 0) {
            if (local_28 < *DAT_0807f0e4) {
              local_24 = local_24 + DAT_0807f0e4[1];
              if ((*(int *)(local_24 + 8) == 0) || (uVar2 = 0, *(int *)(local_24 + 8) == 0))
              goto LAB_08057404;
              goto LAB_080573d0;
            }
            break;
          }
          local_24 = local_24 + 0x10;
        }
        local_14 = 1;
        for (; uVar2 < local_10; uVar2 = uVar2 + 1) {
          *(undefined1 *)(uVar3 + param_2) = *(undefined1 *)(uVar2 + *param_1);
          uVar3 = uVar3 + 1;
          if (0xfe < uVar3) goto LAB_080574ba;
        }
        goto LAB_080574e0;
      }
      *(undefined1 *)(uVar3 + param_2) = 0x24;
    }
    uVar3 = uVar3 + 1;
    if (0xfe < uVar3) {
LAB_080574ba:
      FUN_08052f1c(4,"Substituted line too long");
      DAT_08079804 = 1;
      return 0;
    }
  }
  else {
    *(char *)(uVar3 + param_2) = local_15;
    uVar3 = uVar3 + 1;
    local_10 = local_10 + 1;
    if (0xfd < uVar3) goto LAB_080574ba;
    if (local_15 == '|') {
      do {
        local_15 = *(char *)(local_10 + *param_1);
        *(char *)(uVar3 + param_2) = local_15;
        uVar3 = uVar3 + 1;
        local_10 = local_10 + 1;
        if (0xfd < uVar3) goto LAB_080574ba;
        if (local_15 == '|') goto LAB_080572e0;
      } while (local_15 != '\r');
    }
  }
  goto LAB_080574e0;
  while (uVar2 = uVar2 + 1, uVar2 < *(uint *)(local_24 + 8)) {
LAB_080573d0:
    *(undefined1 *)(uVar3 + param_2) = *(undefined1 *)(uVar2 + *(int *)(local_24 + 0xc));
    uVar3 = uVar3 + 1;
    if (*(char *)(uVar2 + *(int *)(local_24 + 0xc)) == '$') {
      local_14 = 1;
    }
    if (0xfe < uVar3) goto LAB_080574ba;
  }
LAB_08057404:
  if (*(char *)(local_10 + *param_1) == '.') {
    local_10 = local_10 + 1;
  }
LAB_080574e0:
  if (local_15 == '\r') {
    DAT_080825a0 = local_10 + *param_1;
    *param_1 = param_2;
    DAT_08082584 = param_2;
    return local_14;
  }
  goto LAB_080572e0;
}



void FUN_08057510(uint param_1,uint *param_2)

{
  uint uVar1;
  uint *puVar2;
  
  uVar1 = 0;
  if (param_1 != 0) {
    puVar2 = param_2 + 3;
    do {
      if ((uint *)*puVar2 != (uint *)0x0) {
        FUN_0805ee14((uint *)*puVar2);
      }
      puVar2 = puVar2 + 4;
      uVar1 = uVar1 + 1;
    } while (uVar1 < param_1);
  }
  if (param_2 != (uint *)0x0) {
    FUN_0805ee14(param_2);
  }
  return;
}



void FUN_08057550(void)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  
  FUN_08057204();
  puVar3 = DAT_0807f0e4;
  uVar2 = *DAT_0807f0e4;
  puVar1 = DAT_0807f0e4 + 1;
  DAT_0807f0e4 = (uint *)DAT_0807f0e4[2];
  FUN_08057510(uVar2,(uint *)*puVar1);
  FUN_0805f9d0((uint *)puVar3[4]);
  FUN_0805ee14(puVar3);
  if (DAT_08082780 == 0) {
    DAT_0807f0e8 = 0;
  }
  return;
}



// WARNING: Type propagation algorithm not settling

void FUN_0805759c(char *param_1,uint param_2,int param_3)

{
  uint uVar1;
  undefined4 uVar2;
  char cVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  uint *puVar7;
  uint *puVar8;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  char *pcVar9;
  uint uVar10;
  size_t sVar11;
  size_t *psVar12;
  size_t sVar13;
  size_t *psVar14;
  bool bVar15;
  size_t asStackY_7c [4];
  int local_4c;
  uint local_48;
  int local_44;
  uint local_3c;
  uint *local_2c;
  size_t local_28 [3];
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  
  local_2c = DAT_0807f0e0;
LAB_080575b9:
  if (local_2c == (uint *)0x0) {
LAB_080575dd:
    FUN_08052f1c(4,"Unknown opcode");
    return;
  }
  asStackY_7c[3] = 0x80575d6;
  iVar6 = FUN_08057260(*local_2c,local_2c[1],param_2,param_3);
  if (iVar6 < 0) goto LAB_080575dd;
  if (iVar6 != 0) goto LAB_080575b0;
  puVar7 = FUN_0805eddc(0x14);
  puVar7[2] = (uint)DAT_0807f0e4;
  puVar7[3] = 0;
  puVar7[4] = 0;
  uVar10 = local_2c[2];
  *puVar7 = uVar10;
  puVar8 = FUN_0805eddc(uVar10 << 4);
  puVar7[1] = (uint)puVar8;
  puVar8 = puVar7;
  if (DAT_0807f0e4 != (uint *)0x0) {
    *(uint **)((int)DAT_0807f0e4 + 0xc) = puVar7;
    puVar8 = DAT_0807f0e8;
  }
  DAT_0807f0e8 = puVar8;
  uVar10 = 0;
  if (*puVar7 != 0) {
    iVar6 = 0;
    do {
      uVar1 = puVar7[1];
      uVar2 = *(undefined4 *)(local_2c[3] + 4 + iVar6);
      *(undefined4 *)(uVar1 + iVar6) = *(undefined4 *)(local_2c[3] + iVar6);
      *(undefined4 *)(uVar1 + 4 + iVar6) = uVar2;
      *(undefined4 *)(puVar7[1] + 8 + iVar6) = 0;
      *(undefined4 *)(puVar7[1] + 0xc + iVar6) = 0;
      iVar6 = iVar6 + 0x10;
      uVar10 = uVar10 + 1;
    } while (uVar10 < *puVar7);
  }
  local_28[0] = 0;
  cVar3 = *param_1;
  while (1 < (byte)(cVar3 - 0x1fU)) {
    local_28[0] = local_28[0] + 1;
    cVar3 = param_1[local_28[0]];
  }
  if (local_28[0] != 0) {
    FUN_0805891c((size_t *)(puVar7[1] + 8),local_28[0],param_1);
  }
  cVar3 = param_1[local_28[0]];
  while ((byte)(cVar3 - 0x1fU) < 2) {
    local_28[0] = local_28[0] + 1;
    cVar3 = param_1[local_28[0]];
  }
  FUN_080613f8((int)param_1,(int *)local_28,(int *)&param_2);
  local_3c = 1;
  asStackY_7c[3] = 0x805771c;
  iVar6 = FUN_0805cb78(param_1[local_28[0]]);
  bVar15 = iVar6 == 0;
  if (bVar15) {
    FUN_08052f1c(4,"Error in macro parameters");
  }
  bVar4 = FUN_0805cad8(param_1,(int *)local_28);
  if (CONCAT31(extraout_var,bVar4) != 0) goto LAB_080579ed;
  local_44 = 0x10;
LAB_08057774:
  if (local_2c[2] <= local_3c) {
    FUN_08052f1c(4,"Too many actual parameters");
    bVar15 = true;
  }
  if (bVar15) {
    FUN_08057510(*puVar7,(uint *)puVar7[1]);
    FUN_0805ee14(puVar7);
    if (DAT_0807f0e4 != (uint *)0x0) {
      *(undefined4 *)((int)DAT_0807f0e4 + 0xc) = 0;
      return;
    }
    DAT_0807f0e8 = (uint *)0x0;
    return;
  }
  for (; (byte)(param_1[local_28[0]] - 0x1fU) < 2; local_28[0] = local_28[0] + 1) {
  }
  bVar4 = param_1[local_28[0]] == '\"';
  local_4c = 0;
  if (bVar4) {
    local_28[0] = local_28[0] + 1;
  }
  sVar13 = local_28[0];
  if (param_1[local_28[0]] != '\r') goto LAB_0805782c;
  if (!bVar4) {
    do {
      if (param_1[local_28[0]] == '\r') {
LAB_08057840:
        if (local_28[0] <= sVar13) goto LAB_080578db;
        pcVar9 = param_1 + (local_28[0] - 1);
        sVar11 = local_28[0];
        goto LAB_08057851;
      }
LAB_0805782c:
      do {
        if ((!bVar4) && ((param_1[local_28[0]] == ';' || (param_1[local_28[0]] == ','))))
        goto LAB_08057840;
        if (((param_1[local_28[0]] == '\"') && (bVar4)) &&
           (local_28[0] = local_28[0] + 1, param_1[local_28[0]] != '\"')) {
          bVar5 = FUN_0805cad8(param_1,(int *)local_28);
          if ((CONCAT31(extraout_var_00,bVar5) != 0) || (param_1[local_28[0]] == ','))
          goto LAB_080578db;
          goto LAB_080578a5;
        }
        local_28[0] = local_28[0] + 1;
        local_4c = local_4c + 1;
      } while (param_1[local_28[0]] != '\r');
    } while (!bVar4);
    bVar15 = true;
    goto LAB_080578db;
  }
LAB_080578a5:
  bVar15 = true;
  goto LAB_080578e1;
LAB_080575b0:
  local_2c = (uint *)local_2c[7];
  goto LAB_080575b9;
  while( true ) {
    pcVar9 = pcVar9 + -1;
    sVar11 = sVar11 - 1;
    local_4c = local_4c + -1;
    if (sVar11 <= sVar13) break;
LAB_08057851:
    if (1 < (byte)(*pcVar9 - 0x1fU)) break;
  }
LAB_080578db:
  if (bVar15) {
LAB_080578e1:
    FUN_08052f1c(4,"Error in macro parameters");
  }
  if (((local_4c != 1) || (param_1[sVar13] != '|')) || (bVar4)) {
    *(int *)(puVar7[1] + 8 + local_44) = local_4c;
    iVar6 = *(int *)(puVar7[1] + 8 + local_44);
    if (iVar6 != 0) {
      puVar8 = FUN_0805eddc(iVar6);
      *(uint **)(puVar7[1] + 0xc + local_44) = puVar8;
      local_48 = puVar7[1];
      if (*(int *)(local_48 + 8 + local_44) != 0) {
        uVar10 = 0;
        do {
          cVar3 = param_1[sVar13];
          if ((cVar3 == '\"') && (bVar4)) {
            sVar13 = sVar13 + 1;
            cVar3 = param_1[sVar13];
          }
          *(char *)(uVar10 + *(int *)(local_48 + 0xc + local_44)) = cVar3;
          sVar13 = sVar13 + 1;
          uVar10 = uVar10 + 1;
          local_48 = puVar7[1];
        } while (uVar10 < *(uint *)(local_48 + 8 + local_44));
      }
    }
  }
  else {
    *(undefined4 *)(puVar7[1] + 8 + local_44) = *(undefined4 *)(local_2c[3] + 8 + local_44);
    if (*(int *)(puVar7[1] + 8 + local_44) != 0) {
      FUN_080588f0((size_t *)(local_44 + 8 + puVar7[1]),(size_t *)(local_44 + local_2c[3] + 8));
    }
  }
  local_44 = local_44 + 0x10;
  local_3c = local_3c + 1;
  if (param_1[local_28[0]] != ',') {
LAB_080579ed:
    local_28[1] = 3;
    local_18 = DAT_08082594;
    if ((DAT_0808259c == 0) || (DAT_08082780 != 0)) {
      local_28[2] = 0;
      local_1c = DAT_080825a0;
    }
    else {
      local_28[2] = 1;
    }
    local_c = DAT_08082644;
    if ((DAT_08082644 & 8) == 0) {
      DAT_080825cc._0_1_ = (byte)DAT_080825cc & 0xfe;
    }
    DAT_0807f0e4 = puVar7;
    if ((DAT_08082644 & 0x10) == 0) {
      FUN_0805627c();
    }
    local_14 = *local_2c;
    local_10 = local_2c[1];
    psVar12 = local_28;
    psVar14 = asStackY_7c;
    for (iVar6 = 8; psVar12 = psVar12 + 1, iVar6 != 0; iVar6 = iVar6 + -1) {
      *psVar14 = *psVar12;
      psVar14 = psVar14 + 1;
    }
    iVar6 = FUN_08052960();
    if (iVar6 != 0) {
      DAT_080825a0 = local_2c[5];
      DAT_08082780 = DAT_08082780 + 1;
      DAT_08082594 = local_2c[6];
      FUN_08057230();
    }
    return;
  }
  local_28[0] = local_28[0] + 1;
  goto LAB_08057774;
}



void FUN_08057aa8(int param_1,int *param_2,int param_3,int *param_4)

{
  char cVar1;
  int iVar2;
  bool bVar3;
  
  cVar1 = *(char *)(*param_2 + param_1);
  *param_4 = 0;
  if (cVar1 == '\"') {
    *param_2 = *param_2 + 1;
    bVar3 = true;
  }
  else {
    bVar3 = false;
  }
  while( true ) {
    iVar2 = *param_2;
    cVar1 = *(char *)(iVar2 + param_1);
    if (cVar1 == '\r') break;
    if (bVar3) {
      if ((cVar1 == '\"') && (*param_2 = iVar2 + 1, *(char *)(param_1 + 1 + iVar2) != '\"')) {
        return;
      }
    }
    else {
      if (cVar1 == ';') {
        return;
      }
      if (cVar1 == ',') {
        return;
      }
      if ((cVar1 == '\"') && (*param_2 = iVar2 + 1, *(char *)(param_1 + 1 + iVar2) != '\"'))
      goto LAB_08057b13;
    }
    *(char *)(*param_4 + param_3) = cVar1;
    *param_4 = *param_4 + 1;
    *param_2 = *param_2 + 1;
  }
  if (bVar3) {
LAB_08057b13:
    FUN_08052f1c(4,"Bad macro parameter default value");
    DAT_08079804 = 1;
  }
  return;
}



void FUN_08057b58(void)

{
  char cVar1;
  size_t sVar2;
  size_t sVar3;
  uint *puVar4;
  uint *puVar5;
  bool bVar6;
  int iVar7;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  uint *puVar8;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  uint uVar9;
  char *pcVar10;
  size_t *psStack_10534;
  int *piStack_10530;
  size_t *psStack_10520;
  uint uStack_1051c;
  uint uStack_10518;
  uint uStack_10514;
  int iStack_10510;
  uint uStack_1050c;
  int iStack_10508;
  int iStack_10504;
  size_t sStack_10500;
  char *pcStack_104fc;
  char *pcStack_104f8;
  undefined1 auStack_104f4 [256];
  char acStack_103f4 [65536];
  size_t local_3f4;
  char *local_3f0;
  int local_3ec [250];
  
  uStack_10514 = 0;
  FUN_08055af8();
  FUN_08054d90((int *)&pcStack_104f8,0);
  if (DAT_08079804 == 1) {
    return;
  }
  FUN_08056234();
  FUN_08055f9c();
  FUN_08056040();
  iStack_10504 = 0;
  if (*pcStack_104f8 == '$') {
    bVar6 = true;
    iStack_10504 = 1;
    iVar7 = FUN_080613f8((int)pcStack_104f8,&iStack_10504,(int *)&sStack_10500);
    if (iVar7 == 0) {
      pcVar10 = "Illegal label parameter start in macro prototype";
      goto LAB_08057df5;
    }
  }
  else {
    bVar6 = false;
  }
  if ((byte)(pcStack_104f8[iStack_10504] - 0x1fU) < 2) {
    do {
      iStack_10504 = iStack_10504 + 1;
    } while ((byte)(pcStack_104f8[iStack_10504] - 0x1fU) < 2);
    iVar7 = FUN_080613f8((int)pcStack_104f8,&iStack_10504,(int *)&uStack_1050c);
    puVar8 = DAT_0807f0e0;
    if (iVar7 == 0) {
      pcVar10 = "Bad macro name";
    }
    else {
      if (DAT_0807f0e0 == (uint *)0x0) {
        psStack_10520 = FUN_0805eddc(0x20);
        DAT_0807f0e0 = psStack_10520;
        psStack_10520[7] = 0;
      }
      else {
        iVar7 = FUN_08057260(uStack_1050c,iStack_10508,*DAT_0807f0e0,DAT_0807f0e0[1]);
        if (iVar7 < 0) {
          puVar5 = (uint *)puVar8[7];
          while (puVar4 = puVar5, puVar4 != (uint *)0x0) {
            iVar7 = FUN_08057260(uStack_1050c,iStack_10508,*puVar4,puVar4[1]);
            if (-1 < iVar7) {
              if (iVar7 == 0) {
                pcVar10 = "Macro already exists";
                goto LAB_08057df5;
              }
              break;
            }
            puVar8 = puVar4;
            puVar5 = (uint *)puVar4[7];
          }
          psStack_10520 = FUN_0805eddc(0x20);
          puVar8[7] = (uint)psStack_10520;
          psStack_10520[7] = (size_t)puVar4;
        }
        else {
          if (iVar7 == 0) {
            pcVar10 = "Macro already exists";
            goto LAB_08057df5;
          }
          psStack_10520 = FUN_0805eddc(0x20);
          DAT_0807f0e0 = psStack_10520;
          psStack_10520[7] = (size_t)puVar8;
        }
      }
      psStack_10520[6] = DAT_08082594;
      FUN_080588f0(psStack_10520,&uStack_1050c);
      psStack_10520[5] = 0;
      psStack_10520[3] = 0;
      psStack_10520[2] = 0;
      uStack_10518 = 1;
      local_3ec[0] = 0;
      local_3ec[1] = 0;
      if (bVar6) {
        local_3f4 = sStack_10500;
        local_3f0 = pcStack_104fc;
      }
      else {
        local_3f4 = 0;
        local_3f0 = (char *)0x0;
      }
      bVar6 = FUN_0805cad8(pcStack_104f8,&iStack_10504);
      if (CONCAT31(extraout_var,bVar6) == 0) {
        while (pcStack_104f8[iStack_10504] == '$') {
          iStack_10504 = iStack_10504 + 1;
          iVar7 = FUN_080613f8((int)pcStack_104f8,&iStack_10504,(int *)&sStack_10500);
          if (iVar7 == 0) {
            pcVar10 = "Illegal parameter in macro prototype";
            goto LAB_08057df5;
          }
          (&local_3f4)[uStack_10518 * 4] = sStack_10500;
          (&local_3f0)[uStack_10518 * 4] = pcStack_104fc;
          cVar1 = pcStack_104f8[iStack_10504];
          while ((byte)(cVar1 - 0x1fU) < 2) {
            iStack_10504 = iStack_10504 + 1;
            cVar1 = pcStack_104f8[iStack_10504];
          }
          if (pcStack_104f8[iStack_10504] == '=') {
            iStack_10504 = iStack_10504 + 1;
            local_3ec[uStack_10518 * 4 + 1] = (int)(pcStack_104f8 + iStack_10504);
            FUN_08057aa8((int)pcStack_104f8,&iStack_10504,(int)auStack_104f4,
                         local_3ec + uStack_10518 * 4);
            if (DAT_08079804 != 0) {
              return;
            }
          }
          else {
            local_3ec[uStack_10518 * 4] = 0;
          }
          uStack_10518 = uStack_10518 + 1;
          bVar6 = FUN_0805cad8(pcStack_104f8,&iStack_10504);
          if (CONCAT31(extraout_var_00,bVar6) != 0) goto LAB_08057fda;
          if (pcStack_104f8[iStack_10504] != ',') {
            pcVar10 = "Invalid parameter separator in macro prototype";
            goto LAB_08057df5;
          }
          iStack_10504 = iStack_10504 + 1;
          cVar1 = pcStack_104f8[iStack_10504];
          while ((byte)(cVar1 - 0x1fU) < 2) {
            iStack_10504 = iStack_10504 + 1;
            cVar1 = pcStack_104f8[iStack_10504];
          }
        }
        pcVar10 = "Illegal parameter start in macro prototype";
      }
      else {
LAB_08057fda:
        puVar8 = FUN_0805eddc(uStack_10518 << 4);
        psStack_10520[3] = (size_t)puVar8;
        psStack_10520[2] = uStack_10518;
        uStack_1051c = 0;
        if (uStack_10518 != 0) {
          piStack_10530 = local_3ec;
          psStack_10534 = &local_3f4;
          iVar7 = 0;
          do {
            sVar2 = psStack_10520[3];
            sVar3 = psStack_10534[1];
            *(size_t *)(sVar2 + iVar7) = *psStack_10534;
            *(size_t *)(sVar2 + 4 + iVar7) = sVar3;
            if (*(int *)(psStack_10520[3] + 4 + iVar7) != 0) {
              FUN_080588f0((size_t *)(psStack_10520[3] + iVar7),psStack_10534);
            }
            if (*piStack_10530 == 0) {
              *(undefined4 *)(psStack_10520[3] + 0xc + iVar7) = 0;
              *(undefined4 *)(psStack_10520[3] + 8 + iVar7) = 0;
            }
            else {
              iStack_10504 = 0;
              puVar8 = FUN_0805eddc(*piStack_10530);
              *(uint **)(psStack_10520[3] + 0xc + iVar7) = puVar8;
              FUN_08057aa8(*(int *)((int)local_3ec + iVar7 + 4),&iStack_10504,
                           *(int *)(psStack_10520[3] + 0xc + iVar7),
                           (int *)(iVar7 + psStack_10520[3] + 8));
              if (DAT_08079804 != 0) {
                return;
              }
            }
            piStack_10530 = piStack_10530 + 4;
            psStack_10534 = psStack_10534 + 4;
            iVar7 = iVar7 + 0x10;
            uStack_1051c = uStack_1051c + 1;
          } while (uStack_1051c < uStack_10518);
        }
        DAT_080826a8 = 1;
        psStack_10520[4] = 0;
        psStack_10520[5] = 0;
        do {
          do {
            FUN_08055af8();
            FUN_08054d90((int *)&pcStack_104f8,0);
            if (DAT_08079804 == 1) {
              return;
            }
            FUN_08056234();
            FUN_08055f9c();
            FUN_08056040();
            iStack_10504 = 0;
            cVar1 = *pcStack_104f8;
            uVar9 = uStack_10514;
            while (cVar1 != '\r') {
              acStack_103f4[uVar9] = pcStack_104f8[iStack_10504];
              iStack_10504 = iStack_10504 + 1;
              uVar9 = uVar9 + 1;
              if (0xfffe < uVar9) goto LAB_08057df0;
              cVar1 = pcStack_104f8[iStack_10504];
            }
            acStack_103f4[uVar9] = '\r';
            uStack_10514 = uVar9 + 1;
            if (0xffff < uStack_10514) {
LAB_08057df0:
              pcVar10 = "Macro definition too big";
              goto LAB_08057df5;
            }
            iStack_10504 = 0;
            bVar6 = FUN_0805cad8(pcStack_104f8,&iStack_10504);
          } while ((((CONCAT31(extraout_var_01,bVar6) != 0) || (iStack_10504 == 0)) ||
                   (iVar7 = FUN_0806150c((int)pcStack_104f8,&iStack_10504,(int *)&sStack_10500),
                   iVar7 == 0)) ||
                  ((iVar7 = FUN_0805538c(&iStack_10510,sStack_10500,pcStack_104fc), iVar7 == 0 ||
                   (bVar6 = FUN_0805cad8(pcStack_104f8,&iStack_10504),
                   CONCAT31(extraout_var_02,bVar6) == 0))));
          if (iStack_10510 == 0x16) {
            if (DAT_08080160 == 0) {
              FUN_0805891c(psStack_10520 + 4,uVar9 + 2,acStack_103f4);
              *(undefined1 *)(uStack_10514 + psStack_10520[5]) = 4;
            }
            DAT_080826a8 = 0;
            return;
          }
        } while (iStack_10510 != 0x14);
        pcVar10 = "Macro definitions cannot be nested";
      }
    }
  }
  else {
    pcVar10 = "Illegal label parameter start in macro prototype";
  }
LAB_08057df5:
  FUN_08052f1c(4,pcVar10);
  DAT_08079804 = 1;
  return;
}



void FUN_080582e4(void)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  undefined3 extraout_var_00;
  int local_18;
  uint local_14;
  char *local_10;
  int local_c;
  char *local_8;
  
  FUN_08055af8();
  FUN_08054d90((int *)&local_8,0);
  if (DAT_08079804 != 1) {
    FUN_08056234();
    FUN_08055f9c();
    FUN_08056040();
    DAT_080826a8 = 1;
    do {
      do {
        FUN_08055af8();
        FUN_08054d90((int *)&local_8,0);
        if (DAT_08079804 == 1) {
          return;
        }
        FUN_08056234();
        FUN_08055f9c();
        FUN_08056040();
        local_c = 0;
        bVar1 = FUN_0805cad8(local_8,&local_c);
      } while ((((CONCAT31(extraout_var,bVar1) != 0) || (local_c == 0)) ||
               (iVar2 = FUN_0806150c((int)local_8,&local_c,(int *)&local_14), iVar2 == 0)) ||
              ((iVar2 = FUN_0805538c(&local_18,local_14,local_10), iVar2 == 0 ||
               (bVar1 = FUN_0805cad8(local_8,&local_c), CONCAT31(extraout_var_00,bVar1) == 0))));
      if (local_18 == 0x16) {
        DAT_080826a8 = 0;
        return;
      }
    } while (local_18 != 0x14);
    FUN_08052f1c(4,"Macro definitions cannot be nested");
    DAT_08079804 = 1;
  }
  return;
}



void FUN_080583f0(void)

{
  DAT_0807f0e0 = 0;
  DAT_0807f0e4 = 0;
  DAT_0807f0e8 = 0;
  return;
}



void FUN_08058414(void)

{
  uint *puVar1;
  uint *puVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  uint local_8;
  
  puVar3 = DAT_0807f0e0;
  while (puVar1 = DAT_0807f0e8, puVar3 != (uint *)0x0) {
    if ((uint *)puVar3[1] != (uint *)0x0) {
      FUN_0805ee14((uint *)puVar3[1]);
    }
    if ((uint *)puVar3[5] != (uint *)0x0) {
      FUN_0805ee14((uint *)puVar3[5]);
    }
    uVar5 = 0;
    local_8 = puVar3[2];
    if (local_8 != 0) {
      iVar4 = 0;
      do {
        puVar1 = *(uint **)(puVar3[3] + 4 + iVar4);
        if (puVar1 != (uint *)0x0) {
          FUN_0805ee14(puVar1);
          local_8 = puVar3[2];
        }
        iVar4 = iVar4 + 0x10;
        uVar5 = uVar5 + 1;
      } while (uVar5 < local_8);
    }
    FUN_08057510(puVar3[2],(uint *)puVar3[3]);
    puVar1 = (uint *)puVar3[7];
    FUN_0805ee14(puVar3);
    puVar3 = puVar1;
  }
  while (puVar1 != (uint *)0x0) {
    FUN_08057510(*puVar1,(uint *)puVar1[1]);
    puVar3 = (uint *)puVar1[4];
    while (puVar3 != (uint *)0x0) {
      if (((*(byte *)((int)puVar3 + 9) >> 2 & 3) == 2) && (*(uint **)(puVar3[3] + 8) != (uint *)0x0)
         ) {
        FUN_0805ee14(*(uint **)(puVar3[3] + 8));
        FUN_0805ee14((uint *)puVar3[3]);
      }
      FUN_0805ee14((uint *)puVar3[1]);
      puVar2 = (uint *)puVar3[8];
      FUN_0805ee14(puVar3);
      puVar3 = puVar2;
    }
    puVar3 = (uint *)puVar1[3];
    FUN_0805ee14(puVar1);
    puVar1 = puVar3;
  }
  return;
}



size_t * FUN_08058514(undefined4 param_1,undefined4 param_2,size_t param_3)

{
  int iVar1;
  uint *puVar2;
  int iVar3;
  
  if (DAT_0807f0e4 == 0) {
    FUN_08052f1c(5,"No current macro for insert");
  }
  iVar1 = *(int *)(DAT_0807f0e4 + 0x10);
  if (*(int *)(DAT_0807f0e4 + 0x10) == 0) {
    puVar2 = FUN_0805eddc(0x2c);
    *(uint **)(DAT_0807f0e4 + 0x10) = puVar2;
  }
  else {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x20);
    } while (iVar1 != 0);
    puVar2 = FUN_0805eddc(0x2c);
    *(uint **)(iVar3 + 0x20) = puVar2;
  }
  FUN_080588f0(puVar2,&param_1);
  puVar2[2] = param_3;
  puVar2[4] = 0;
  puVar2[8] = 0;
  puVar2[9] = 0;
  puVar2[10] = 0;
  FUN_08058c78((int)puVar2);
  return puVar2;
}



uint * FUN_080585a4(uint param_1,int param_2)

{
  size_t *psVar1;
  
  psVar1 = FUN_08058710(param_1,param_2);
  if (psVar1 == (uint *)0x0) {
    psVar1 = FUN_08058514(param_1,param_2,0);
    *(byte *)(psVar1 + 2) = (byte)psVar1[2] & 0xfc | 2;
    *(byte *)((int)psVar1 + 9) = *(byte *)((int)psVar1 + 9) & 0xf3;
    *(byte *)((int)psVar1 + 10) = *(byte *)((int)psVar1 + 10) | 0xc;
  }
  else {
    if ((*(byte *)((int)psVar1 + 9) & 0xc) != 0) {
      return (uint *)0x0;
    }
    FUN_08058c28((int)psVar1);
  }
  psVar1[3] = 0;
  return psVar1;
}



uint * FUN_08058608(uint param_1,int param_2)

{
  size_t *psVar1;
  
  psVar1 = FUN_08058710(param_1,param_2);
  if (psVar1 == (uint *)0x0) {
    psVar1 = FUN_08058514(param_1,param_2,0);
    *(byte *)(psVar1 + 2) = (byte)psVar1[2] & 0xfc | 2;
    *(byte *)((int)psVar1 + 9) = *(byte *)((int)psVar1 + 9) & 0xf3 | 4;
    *(byte *)((int)psVar1 + 10) = *(byte *)((int)psVar1 + 10) | 0xc;
  }
  else {
    if ((*(byte *)((int)psVar1 + 9) >> 2 & 3) != 1) {
      return (uint *)0x0;
    }
    FUN_08058c28((int)psVar1);
  }
  psVar1[3] = 0;
  return psVar1;
}



uint * FUN_0805867c(uint param_1,int param_2)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar1 = FUN_08058710(param_1,param_2);
  if (puVar1 == (uint *)0x0) {
    puVar1 = FUN_08058514(param_1,param_2,0);
    *(byte *)(puVar1 + 2) = (byte)puVar1[2] & 0xfc | 2;
    *(byte *)((int)puVar1 + 9) = *(byte *)((int)puVar1 + 9) & 0xf3 | 8;
    *(byte *)((int)puVar1 + 10) = *(byte *)((int)puVar1 + 10) | 0xc;
    puVar2 = FUN_0805eddc(0xc);
    puVar1[3] = (uint)puVar2;
    *puVar2 = 0;
    *(undefined4 *)(puVar1[3] + 8) = 0;
    *(undefined4 *)(puVar1[3] + 4) = 0;
  }
  else if ((*(byte *)((int)puVar1 + 9) >> 2 & 3) == 2) {
    FUN_08058c28((int)puVar1);
    *(undefined4 *)puVar1[3] = 0;
  }
  else {
    puVar1 = (uint *)0x0;
  }
  return puVar1;
}



uint * FUN_08058710(uint param_1,int param_2)

{
  int iVar1;
  uint *puVar2;
  
  if (DAT_0807f0e4 != 0) {
    for (puVar2 = *(uint **)(DAT_0807f0e4 + 0x10); puVar2 != (uint *)0x0; puVar2 = (uint *)puVar2[8]
        ) {
      iVar1 = FUN_08057260(param_1,param_2,*puVar2,puVar2[1]);
      if (iVar1 == 0) {
        FUN_08058c28((int)puVar2);
        return puVar2;
      }
    }
  }
  return (uint *)0x0;
}



uint * FUN_08058760(uint param_1,int param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_08058710(param_1,param_2);
  if ((puVar1 == (uint *)0x0) || ((puVar1[2] & 0xc03) != 2)) {
    puVar1 = (uint *)0x0;
  }
  return puVar1;
}



uint * FUN_08058798(uint param_1,int param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_08058710(param_1,param_2);
  if ((puVar1 == (uint *)0x0) || ((puVar1[2] & 0xc03) != 0x402)) {
    puVar1 = (uint *)0x0;
  }
  return puVar1;
}



uint * FUN_080587cc(uint param_1,int param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_08058710(param_1,param_2);
  if ((puVar1 == (uint *)0x0) || ((puVar1[2] & 0xc03) != 0x802)) {
    puVar1 = (uint *)0x0;
  }
  return puVar1;
}



undefined4 FUN_08058800(int param_1,uint param_2,int param_3,int param_4,uint *param_5,uint param_6)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int *local_c;
  
  uVar5 = 0;
  if (param_6 != 0) {
    local_c = (int *)(param_1 + 4);
    do {
      uVar1 = *(uint *)(param_1 + uVar5 * 8);
      if ((uVar1 == param_2) || ((param_2 <= uVar1 && (param_4 != 0)))) {
        uVar4 = 0;
        if (param_4 == 0) {
          if (uVar1 != 0) {
            do {
              if (*(char *)(uVar4 + *local_c) != *(char *)(uVar4 + param_3)) break;
              uVar4 = uVar4 + 1;
            } while (uVar4 < uVar1);
          }
        }
        else if (param_2 != 0) {
          do {
            iVar2 = toupper((int)*(char *)(uVar4 + *local_c));
            iVar3 = toupper((int)*(char *)(uVar4 + param_3));
            if (iVar2 != iVar3) break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < param_2);
        }
        if (uVar4 == param_2) {
          *param_5 = uVar5;
          return 1;
        }
      }
      local_c = local_c + 2;
      uVar5 = uVar5 + 1;
    } while (uVar5 < param_6);
  }
  return 0;
}



void FUN_080588c0(int *param_1,char *param_2)

{
  char cVar1;
  uint *puVar2;
  uint uVar3;
  char *pcVar4;
  
  uVar3 = 0xffffffff;
  pcVar4 = param_2;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  *param_1 = ~uVar3 - 1;
  puVar2 = FUN_0805ee84(param_2);
  param_1[1] = (int)puVar2;
  return;
}



void FUN_080588f0(size_t *param_1,size_t *param_2)

{
  size_t __n;
  uint *__dest;
  
  __n = *param_2;
  *param_1 = __n;
  __dest = FUN_0805eddc(__n);
  param_1[1] = (size_t)__dest;
  memcpy(__dest,(void *)param_2[1],__n);
  return;
}



void FUN_0805891c(size_t *param_1,size_t param_2,void *param_3)

{
  uint *__dest;
  
  *param_1 = param_2;
  __dest = FUN_0805eddc(param_2);
  param_1[1] = (size_t)__dest;
  memcpy(__dest,param_3,param_2);
  return;
}



void FUN_08058948(int param_1,char *param_2,int param_3)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0xffffffff;
  pcVar3 = param_2;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  FUN_0805891c((size_t *)(param_1 * 8 + param_3),~uVar2 - 1,param_2);
  return;
}



void FUN_08058980(uint param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  if (param_1 != 0) {
    do {
      FUN_08054714("%c");
      uVar1 = uVar1 + 1;
    } while (uVar1 < param_1);
  }
  return;
}



void FUN_080589bc(undefined4 *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)*param_1;
  do {
    FUN_08054714("      %s %i in ");
    if (*piVar1 == 0) {
      FUN_08054714("macro ");
      FUN_08058980(piVar1[1]);
      FUN_08054714("\n");
    }
    else if (*piVar1 == 1) {
      FUN_08054714("file ");
      FUN_08058980(piVar1[1]);
      FUN_08054714("\n");
      return;
    }
    piVar1 = (int *)piVar1[4];
  } while( true );
}



int FUN_08058a58(undefined4 param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = 0;
  FUN_08054714("   %s\n");
  if (param_2 == (undefined4 *)0x0) {
    FUN_08054714("      None\n");
  }
  else {
    do {
      FUN_080589bc(param_2);
      iVar1 = iVar1 + 1;
      param_2 = (undefined4 *)param_2[1];
    } while (param_2 != (undefined4 *)0x0);
  }
  return iVar1;
}



void FUN_08058a9c(uint *param_1)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  
  FUN_08054714("\nSymbol: ");
  FUN_08058980(*param_1);
  FUN_08054714("\n");
  uVar1 = FUN_08058a58("Definitions",(undefined4 *)param_1[9]);
  iVar2 = FUN_08058a58(&DAT_080744fa,(undefined4 *)param_1[10]);
  if (uVar1 == 0) {
    FUN_08054714("Warning: ");
    FUN_08058980(*param_1);
    pcVar3 = " undefined";
  }
  else {
    if (uVar1 < 2) goto LAB_08058b2f;
    FUN_08054714("Warning: ");
    FUN_08058980(*param_1);
    pcVar3 = " multiply defined";
  }
  FUN_08054714(pcVar3);
LAB_08058b2f:
  if (iVar2 == 0) {
    FUN_08054714("Comment: ");
    FUN_08058980(*param_1);
    pcVar3 = " unused";
  }
  else {
    if (iVar2 != 1) {
      return;
    }
    FUN_08054714("Comment: ");
    FUN_08058980(*param_1);
    pcVar3 = " used once";
  }
  FUN_08054714(pcVar3);
  return;
}



void FUN_08058b80(undefined4 *param_1)

{
  char cVar1;
  uint *puVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  size_t sVar6;
  undefined4 local_24 [3];
  uint local_18;
  uint local_14;
  uint local_10;
  
  param_1[1] = 0;
  uVar5 = DAT_08082594;
  puVar2 = FUN_0805eddc(0x14);
  *param_1 = puVar2;
  FUN_08052a80();
  while( true ) {
    iVar4 = FUN_08052a90(local_24);
    if (iVar4 == 0) break;
    *puVar2 = 0;
    puVar2[3] = uVar5;
    puVar2[1] = local_14;
    puVar2[2] = local_10;
    puVar3 = FUN_0805eddc(0x14);
    puVar2[4] = (uint)puVar3;
    puVar2 = puVar3;
    uVar5 = local_18;
  }
  *puVar2 = 1;
  puVar2[3] = uVar5;
  sVar6 = 0;
  cVar1 = DAT_0807ff20;
  while ((byte)(cVar1 - 0x21U) < 0x5e) {
    cVar1 = (&DAT_0807ff21)[sVar6];
    sVar6 = sVar6 + 1;
  }
  FUN_0805891c(puVar2 + 1,sVar6,&DAT_0807ff20);
  puVar2[4] = 0;
  return;
}



void FUN_08058c28(int param_1)

{
  int iVar1;
  uint *puVar2;
  int iVar3;
  
  if ((DAT_08082650 != 0) && (DAT_080825d0 == 1)) {
    iVar1 = *(int *)(param_1 + 0x28);
    if (*(int *)(param_1 + 0x28) == 0) {
      puVar2 = FUN_0805eddc(8);
      *(uint **)(param_1 + 0x28) = puVar2;
    }
    else {
      do {
        iVar3 = iVar1;
        iVar1 = *(int *)(iVar3 + 4);
      } while (iVar1 != 0);
      puVar2 = FUN_0805eddc(8);
      *(uint **)(iVar3 + 4) = puVar2;
    }
    FUN_08058b80(puVar2);
  }
  return;
}



void FUN_08058c78(int param_1)

{
  int iVar1;
  uint *puVar2;
  int iVar3;
  
  if ((DAT_08082650 != 0) && (DAT_080825d0 == 1)) {
    iVar1 = *(int *)(param_1 + 0x24);
    if (*(int *)(param_1 + 0x24) == 0) {
      puVar2 = FUN_0805eddc(8);
      *(uint **)(param_1 + 0x24) = puVar2;
    }
    else {
      do {
        iVar3 = iVar1;
        iVar1 = *(int *)(iVar3 + 4);
      } while (iVar1 != 0);
      puVar2 = FUN_0805eddc(8);
      *(uint **)(iVar3 + 4) = puVar2;
    }
    FUN_08058b80(puVar2);
  }
  return;
}



void FUN_08058cd0(uint param_1,char *param_2,int *param_3,int *param_4)

{
  int iVar1;
  uint uVar2;
  char local_18 [20];
  
  if (param_1 - 1 < 0x10) {
    for (uVar2 = 0; uVar2 < param_1; uVar2 = uVar2 + 1) {
      iVar1 = isupper((int)param_2[uVar2]);
      if (iVar1 != 0) break;
      iVar1 = toupper((int)param_2[uVar2]);
      local_18[uVar2] = (char)iVar1;
    }
    if (uVar2 == param_1) {
      param_2 = local_18;
    }
  }
  if ((DAT_080795ec == 0) || (DAT_080795ec != 1)) {
    FUN_0806727c(param_1,param_2,param_3,param_4);
  }
  else {
    FUN_0806b7e4(param_1,param_2,param_3,param_4);
  }
  return;
}



void FUN_08058d5c(void)

{
  if (DAT_08079848 == 0) {
    FUN_08067328();
    FUN_0806b848();
    DAT_08079848 = 1;
  }
  return;
}



void FUN_08058d80(void)

{
  if (((byte)DAT_08082644 & 2) == 0) {
    FUN_0805627c();
  }
  return;
}



void FUN_08058d94(void)

{
  if (DAT_08082644 == 0) {
    FUN_0805627c();
  }
  return;
}



undefined4 FUN_08058da8(uint param_1,char *param_2,undefined4 *param_3)

{
  byte bVar1;
  uint uVar2;
  uint *puVar3;
  undefined4 uVar4;
  
  puVar3 = FUN_0805f5ec(param_1,param_2,0);
  *param_3 = puVar3;
  if ((puVar3 == (uint *)0x0) || ((*(byte *)((int)puVar3 + 10) & 0xc) != 0)) {
    FUN_08052f1c(4,"Multiply or incompatibly defined symbol");
    uVar4 = 1;
  }
  else {
    FUN_08058c78((int)puVar3);
    bVar1 = *(byte *)((int)puVar3 + 9);
    *(byte *)((int)puVar3 + 9) = bVar1 & 0xcf;
    uVar2 = DAT_0808276c;
    puVar3[7] = DAT_0808276c;
    if (uVar2 != 0) {
      uVar2 = *(uint *)(DAT_0808014c + 4);
      if ((uVar2 & 0x100) != 0) {
        *(byte *)((int)puVar3 + 9) = bVar1 & 0xcf | 0x10;
      }
      if ((uVar2 & 0x100200) == 0x100000) {
        *(byte *)((int)puVar3 + 9) = *(byte *)((int)puVar3 + 9) & 0xcf | 0x20;
        puVar3[2] = puVar3[2] & 0xfffc3fff | uVar2 >> 10 & 0x3c000;
        *(byte *)((int)puVar3 + 0xb) = *(byte *)((int)puVar3 + 0xb) | 8;
      }
    }
    *(byte *)((int)puVar3 + 10) = *(byte *)((int)puVar3 + 10) | 0xc;
    *(byte *)((int)puVar3 + 0xb) = *(byte *)((int)puVar3 + 0xb) & 0xef;
    puVar3[4] = 0;
    puVar3[3] = DAT_080826a0;
    uVar4 = 0;
  }
  return uVar4;
}



undefined4 FUN_08058e70(int param_1,uint param_2,int param_3)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  undefined4 local_14;
  char local_10 [12];
  
  if (param_2 < 0xc) {
    local_10[param_2] = '\0';
    local_14 = local_10;
    while (param_2 != 0) {
      param_2 = param_2 - 1;
      cVar1 = *(char *)(param_2 + param_1);
      iVar2 = isupper((int)cVar1);
      if (iVar2 != 0) {
        iVar2 = tolower((int)cVar1);
        cVar1 = (char)iVar2;
      }
      local_10[param_2] = cVar1;
    }
    iVar2 = 10;
    bVar5 = true;
    pcVar3 = local_14;
    pcVar4 = "fpregargs";
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *pcVar3 == *pcVar4;
      pcVar3 = pcVar3 + 1;
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (bVar5) {
      return 0x200;
    }
    if (param_3 == 0) {
      iVar2 = 5;
      bVar5 = true;
      pcVar3 = local_14;
      pcVar4 = "weak";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (bVar5) {
        return 0x10;
      }
    }
    else {
      iVar2 = 5;
      bVar5 = true;
      pcVar3 = local_14;
      pcVar4 = "data";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (bVar5) {
        return 0x100;
      }
      iVar2 = 5;
      bVar5 = true;
      pcVar3 = local_14;
      pcVar4 = "leaf";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (bVar5) {
        return 0x800;
      }
      iVar2 = 7;
      bVar5 = true;
      pcVar3 = local_14;
      pcVar4 = "usessb";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (bVar5) {
        return 0x400;
      }
      iVar2 = 7;
      bVar5 = true;
      pcVar3 = local_14;
      pcVar4 = "strong";
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (bVar5) {
        return 0x20;
      }
    }
  }
  FUN_08052f1c(3,"AOF symbol attribute not recognised");
  return 0;
}



uint FUN_08058f98(int param_1,int *param_2,int param_3)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint local_8;
  
  local_8 = 0;
  iVar3 = FUN_0805fa50(param_1,param_2);
  cVar2 = (char)iVar3;
  iVar3 = *param_2;
  if ((cVar2 == '[') || ((param_3 == 0 && (cVar2 == ',')))) {
    do {
      do {
        iVar6 = iVar3 + 1;
        iVar3 = iVar6;
      } while ((byte)(*(char *)(iVar6 + param_1) - 0x1fU) < 2);
      while (iVar4 = isalnum((int)*(char *)(iVar3 + param_1)), iVar4 != 0) {
        iVar3 = iVar3 + 1;
      }
      uVar5 = FUN_08058e70(iVar6 + param_1,iVar3 - iVar6,param_3);
      local_8 = local_8 | uVar5;
      for (; cVar1 = *(char *)(iVar3 + param_1), (byte)(cVar1 - 0x1fU) < 2; iVar3 = iVar3 + 1) {
      }
      if (cVar2 == ',') goto LAB_0805905e;
    } while (cVar1 == ',');
    if (cVar1 == ']') {
      iVar3 = iVar3 + 1;
      cVar2 = *(char *)(iVar3 + param_1);
      while ((byte)(cVar2 - 0x1fU) < 2) {
        iVar3 = iVar3 + 1;
        cVar2 = *(char *)(iVar3 + param_1);
      }
    }
    else {
      FUN_08052f1c(4,"Missing close square bracket");
    }
  }
LAB_0805905e:
  if (local_8 != 0) {
    *param_2 = iVar3;
  }
  return local_8;
}



undefined4 FUN_08059074(int param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if ((&DAT_08074620)[uVar1 * 2] == param_1) {
      return (&DAT_08074624)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x10);
  return 0;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

undefined4 FUN_080590b0(char *param_1,undefined4 *param_2,undefined4 *param_3,int *param_4)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  size_t sVar6;
  undefined3 extraout_var_03;
  byte bVar7;
  uint uVar8;
  int *piVar9;
  int iVar10;
  uint unaff_EDI;
  int *piVar11;
  uint uVar12;
  char *pcVar13;
  bool bVar14;
  int aiStackY_1dc [2];
  char *pcVar15;
  uint *local_1b0;
  uint local_1ac;
  uint local_1a8;
  size_t *local_1a0;
  uint local_190;
  uint local_18c;
  int *local_178;
  uint local_174;
  uint local_170;
  uint local_16c;
  size_t *local_168;
  uint local_164;
  uint local_160;
  uint local_15c;
  byte *local_158;
  int local_154;
  size_t local_150;
  uint local_14c;
  char *local_148;
  undefined1 local_144 [256];
  undefined4 local_44 [3];
  int local_38;
  int local_24 [4];
  uint local_14;
  
  local_150 = 0;
  local_168 = (size_t *)0x0;
  uVar8 = 0;
  bVar14 = false;
  bVar2 = false;
  if ((param_2 == (undefined4 *)0x0) || (param_3 == (undefined4 *)0x0)) {
    bVar2 = true;
  }
  iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
  if (1 < (byte)(param_1[local_150] - 0x1fU)) {
    if (iVar3 == 0) {
      iVar4 = isdigit((int)*param_1);
      if (iVar4 == 0) {
        return 0;
      }
      FUN_0805fbc8((int)param_1,(int *)&local_150);
      if (param_1[local_150] != ':') {
        return 0;
      }
      if (1 < (byte)(param_1[local_150 + 1] - 0x1fU)) {
        return 0;
      }
      if ((DAT_08082688 != 0) && (DAT_080825c4 != 1)) {
        return 0;
      }
      local_150 = local_150 + 1;
      bVar14 = true;
      if (DAT_08082688 == 0) {
        FUN_0805f950();
      }
      DAT_08082688 = 1;
      DAT_080825c4 = 1;
      DAT_080825d4 = 1;
      DAT_08082654 = 1;
    }
    else {
      if ((DAT_08082688 != 0) && (DAT_080825c4 == 0)) {
        return 0;
      }
      if (param_1[local_150] != ':') {
        return 0;
      }
      if (1 < (byte)(param_1[local_150 + 1] - 0x1fU)) {
        return 0;
      }
      if (DAT_08082688 == 0) {
        FUN_0805f950();
      }
      DAT_08082688 = 1;
      DAT_080825c4 = 1;
      DAT_080825d4 = 1;
      DAT_08082654 = 1;
      uVar8 = 1;
    }
  }
  do {
    local_150 = local_150 + 1;
  } while ((byte)(param_1[local_150] - 0x1fU) < 2);
  iVar4 = FUN_0805531c((int)param_1,(int *)&local_150,&local_154);
  if (iVar4 == 0) {
    iVar4 = FUN_0806150c((int)param_1,(int *)&local_150,(int *)&local_15c);
    if (iVar4 == 0) {
      return 0;
    }
    iVar4 = FUN_0805538c(&local_154,local_15c,(char *)local_158);
    if (iVar4 == 0) {
      return 0;
    }
  }
  if (local_154 == 0x3f) {
    if (DAT_08082688 == 0) {
      FUN_0805f950();
    }
    else if (DAT_080825c4 == 0) {
      return 0;
    }
    DAT_08082688 = 1;
    DAT_080825c4 = 1;
    DAT_080825d4 = 1;
    DAT_08082654 = 1;
    local_150 = local_150 + 1;
    iVar4 = FUN_0806150c((int)param_1,(int *)&local_150,(int *)&local_15c);
    if (iVar4 == 0) {
      return 1;
    }
    iVar4 = FUN_08055538((int *)&local_160,local_15c,local_158);
    if (iVar4 == 0) {
      return 1;
    }
    cVar1 = (&DAT_08079829)[local_160];
    local_1ac = 0;
    if (iVar3 != 0) {
      local_1ac = uVar8 ^ 1;
    }
    iVar4 = FUN_08055670(local_160,param_1[local_150],local_1ac);
    if (iVar4 == 0) {
      return 1;
    }
    if ((int)cVar1 != 1) {
      for (local_1a8 = DAT_080826a0; DAT_080826a0 = local_1a8, local_1a8 % (uint)(int)cVar1 != 0;
          local_1a8 = local_1a8 + 1) {
      }
    }
    if (bVar14) {
      local_164 = 0;
      FUN_08057074((int)param_1,(int *)&local_164);
    }
    local_154 = (int)(char)(&DAT_0807980c)[local_160];
    if ((char)(&DAT_0807980c)[local_160] != 0x3f) goto LAB_080596aa;
    if ((uVar8 != 0) && (iVar3 = FUN_08058da8(local_14c,local_148,&local_168), iVar3 != 0)) {
      return 1;
    }
    switch(local_160) {
    default:
      FUN_08052f1c(5,"Unexpected as directive not handled");
      break;
    case 1:
      DAT_080825cc = DAT_080825cc & 0xfffffffb;
      break;
    case 2:
      DAT_080825cc = DAT_080825cc | 4;
      break;
    case 3:
    case 8:
    case 9:
    case 0xf:
    case 0x1b:
    case 0x1c:
      break;
    case 4:
      if ((DAT_08082644 & 1) != 0) {
        FUN_08055af8();
        FUN_080545cc();
      }
      break;
    case 5:
    case 6:
    case 7:
      if (DAT_080826f8 == 1) {
        DAT_08082618 = DAT_080826a0;
      }
      else if (DAT_080826f8 == 0) {
        DAT_08082704 = DAT_080826a0;
      }
      else if (DAT_080826f8 == 2) {
        DAT_0808268c = DAT_080826a0;
      }
      if (local_160 == 6) {
        DAT_080826a0 = DAT_08082618;
        DAT_08082778 = 0;
        DAT_08082774 = 0;
        DAT_080826f8 = 1;
        DAT_0808276c = DAT_080826f8;
      }
      else {
        DAT_0808276c = DAT_080826f8;
        if (local_160 < 7) {
          if (local_160 == 5) {
            DAT_080826a0 = DAT_08082704;
            DAT_08082778 = 1;
            DAT_08082774 = 0;
            DAT_080826f8 = 0;
            DAT_0808276c = DAT_080826f8;
          }
        }
        else if (local_160 == 7) {
          DAT_080826a0 = DAT_0808268c;
          DAT_08082778 = 0;
          DAT_08082774 = 1;
          DAT_080826f8 = 2;
          DAT_0808276c = DAT_080826f8;
        }
      }
      break;
    case 0x14:
    case 0x15:
      FUN_080539b8(param_1,(int *)&local_150,&local_15c);
      DAT_080826a0 = local_15c + DAT_080826a0;
      if (local_160 == 0x15) {
        DAT_080826a0 = DAT_080826a0 + 1;
      }
    }
    goto switchD_080594e1_caseD_3;
  }
  if ((DAT_08082688 != 0) && (DAT_080825c4 == 1)) {
    return 0;
  }
  DAT_08082688 = 1;
  DAT_080825c4 = 0;
LAB_080596aa:
  if ((DAT_08080154 == 0) && ((&DAT_080828a0)[local_154] == 0)) {
    return 1;
  }
  if (((DAT_08082688 != 0) && (DAT_080825c4 == 0)) &&
     (iVar4 = FUN_080555e0(local_154,param_1[local_150],iVar3), iVar4 == 0)) {
    return 1;
  }
  if ((((&DAT_080827a0)[local_154] != 0) && (DAT_080825c4 == 0)) &&
     (DAT_080825d4 = 1, DAT_0808276c == 0)) {
    FUN_08052f1c(4,"Area directive missing");
    iVar4 = FUN_08052154();
    if (iVar4 == 0) {
      return 1;
    }
  }
  switch(local_154) {
  case 0:
    local_24[0] = 0;
    local_24[2] = DAT_08082644;
    local_24[1] = DAT_08080154;
    if (DAT_08080154 == 0) {
      cVar1 = param_1[local_150];
      while (cVar1 != '\r') {
        local_150 = local_150 + 1;
        cVar1 = param_1[local_150];
      }
    }
    else {
      iVar3 = FUN_080530c0(param_1,(int *)&local_150);
      if ((iVar3 == 0) && (DAT_08080154 = 0, DAT_080825c8 != 0)) {
        DAT_080825cc = DAT_080825cc & 0xfffffffe;
      }
    }
    piVar9 = local_24;
    piVar11 = aiStackY_1dc;
    for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
      *piVar11 = *piVar9;
      piVar9 = piVar9 + 1;
      piVar11 = piVar11 + 1;
    }
    iVar3 = FUN_08052960();
    if (iVar3 != 0) goto LAB_08059845;
    break;
  case 1:
    iVar3 = FUN_080529b4(local_24);
    if (iVar3 != 0) {
      if (local_24[0] == 0) {
        piVar9 = local_24;
        piVar11 = aiStackY_1dc;
        for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
          *piVar11 = *piVar9;
          piVar9 = piVar9 + 1;
          piVar11 = piVar11 + 1;
        }
        FUN_08052960();
        if (DAT_08080154 == 0) {
          if ((local_24[1] != 0) && (DAT_08080154 = 1, (local_24[2] & 1U) != 0)) {
            DAT_080825cc = DAT_080825cc | 1;
          }
        }
        else {
          DAT_08080154 = 0;
          if (DAT_080825c8 != 0) {
            DAT_080825cc = DAT_080825cc & 0xfffffffe;
          }
        }
        goto LAB_08059845;
      }
LAB_080598df:
      if (local_24[0] != 1) {
        piVar9 = local_24;
        piVar11 = aiStackY_1dc;
        for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
          *piVar11 = *piVar9;
          piVar9 = piVar9 + 1;
          piVar11 = piVar11 + 1;
        }
        FUN_08052960();
      }
      FUN_08052f1c(4,"Structure mismatch");
      DAT_08079804 = 4;
    }
    break;
  case 2:
    iVar3 = FUN_080529b4(local_24);
    if (iVar3 != 0) {
      if (local_24[0] != 0) goto LAB_080598df;
      DAT_080825cc = local_24[2];
      DAT_08080154 = local_24[1];
      if (((local_24[2] & 1U) != 0) && ((DAT_08082644 & 1) == 0)) {
        DAT_08082644 = DAT_08082644 | 1;
        FUN_08055f9c();
      }
      goto LAB_08059845;
    }
    break;
  case 3:
    FUN_08055af8();
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (param_1[local_150] != ',') {
      FUN_08052f1c(4,"Missing comma");
      return 1;
    }
    local_150 = local_150 + 1;
    FUN_080539b8(param_1,(int *)&local_150,&local_14c);
    aiStackY_1dc[1] = 0x80599e5;
    memcpy(&DAT_0807f100,local_148,local_14c);
    (&DAT_0807f100)[local_14c] = 0;
    goto LAB_0805b056;
  case 4:
    if (iVar3 != 0) {
      local_168 = (size_t *)FUN_0805f618(local_14c,local_148,0);
      if (local_168 == (size_t *)0x0) {
        local_168 = FUN_0805f5ec(local_14c,local_148,0);
      }
      else {
        if ((local_168[2] & 3) != 0) {
          FUN_08052f1c(4,"Bad symbol type");
          return 1;
        }
        if ((*(byte *)((int)local_168 + 10) & 0xc) != 0) {
          FUN_08052f1c(4,"Multiply or incompatibly defined symbol");
          return 1;
        }
      }
      FUN_08058c78((int)local_168);
      local_168[7] = DAT_0808276c;
      if (DAT_080826b0 == 0) {
        *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) & 0xcf | 0x10;
LAB_08059af6:
        local_168[3] = DAT_080826b4;
      }
      else if (DAT_080826b0 == 1) {
        if (DAT_080826b8 == 0xf) {
          *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) & 0xcf;
        }
        else {
          *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) & 0xcf | 0x20;
          local_168[2] = local_168[2] & 0xfffc3fff | (DAT_080826b8 & 0xf) << 0xe;
        }
        goto LAB_08059af6;
      }
      *(byte *)((int)local_168 + 10) = *(byte *)((int)local_168 + 10) | 0xc;
    }
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (iVar3 != 0) {
      local_168[4] = local_164;
    }
    if ((DAT_080826b0 == 0) || (DAT_080826b0 == 1)) {
      FUN_080560a0(DAT_080826b4);
      DAT_080826b4 = DAT_080826b4 + local_164;
    }
    break;
  case 5:
    if ((DAT_080825c4 == 1) && (param_1[local_150] == '{')) goto switchD_08059761_caseD_37;
    aiStackY_1dc[1] = 0x8059bc6;
    local_164 = FUN_0805384c(param_1,(int *)&local_150,&local_174,&local_170,1,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    local_168 = (size_t *)FUN_0805f618(local_14c,local_148,0);
    if (local_168 == (size_t *)0x0) {
      local_168 = FUN_0805f5ec(local_14c,local_148,0);
    }
    FUN_08058c78((int)local_168);
    if ((*(byte *)((int)local_168 + 10) & 0xc) != 0) {
      FUN_08052f1c(4,"Multiply or incompatibly defined symbol");
      return 1;
    }
    if (((local_168[2] & 3) != 0) && ((local_168[2] & 0x40000003) != 0x40000001)) {
      FUN_08052f1c(4,"Bad symbol type");
      return 1;
    }
    local_168[7] = DAT_0808276c;
    if (local_16c == 0) {
      *(byte *)((int)local_168 + 10) = *(byte *)((int)local_168 + 10) & 0xf3 | 4;
    }
    else {
      if (local_170 == 3) {
        *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) & 0xcf;
      }
      else if (local_170 < 4) {
        if (local_170 == 1) {
          *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) & 0xcf | 0x10;
        }
      }
      else if (local_170 == 4) {
        *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) & 0xcf | 0x20;
        local_168[2] = local_168[2] & 0xfffc3fff | (local_174 & 0xf) << 0xe;
      }
      *(byte *)((int)local_168 + 10) = *(byte *)((int)local_168 + 10) | 0xc;
      local_168[3] = local_164;
      FUN_080560a0(local_164);
    }
    local_168[4] = 0;
    break;
  case 6:
    if ((iVar3 != 0) && (iVar4 = FUN_08058da8(local_14c,local_148,&local_168), iVar4 != 0)) {
      return 1;
    }
    if ((DAT_080826ec != 0) && ((iVar3 != 0 && (local_168[6] == 0x80000000)))) {
      FUN_08051d94((int *)local_168);
    }
    local_174 = DAT_080826a0;
    while( true ) {
      aiStackY_1dc[1] = 0x8059df3;
      FUN_08053b0c(param_1,(int *)&local_150,1,(int *)&local_170,&local_164,&local_178);
      if (DAT_08080160 != 0) {
        return 1;
      }
      if (local_170 == 1) {
        DAT_080826a0 = DAT_080826a0 + 1;
      }
      else if (local_170 == 2) {
        DAT_080826a0 = DAT_080826a0 + *local_178;
      }
      if (param_1[local_150] != ',') break;
      local_150 = local_150 + 1;
    }
    if (iVar3 != 0) {
      local_168[4] = DAT_080826a0 - local_174;
    }
    break;
  case 7:
    if ((iVar3 != 0) && (iVar4 = FUN_08058da8(local_14c,local_148,&local_168), iVar4 != 0)) {
      return 1;
    }
    if (((DAT_080826ec != 0) && (iVar3 != 0)) && (local_168[6] == 0x80000000)) {
      FUN_08051d94((int *)local_168);
    }
    local_174 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    DAT_080826a0 = DAT_080826a0 + local_174;
    if (iVar3 != 0) {
      local_168[4] = local_174;
    }
    break;
  case 8:
    for (; (DAT_080826a0 & 3) != 0; DAT_080826a0 = DAT_080826a0 + 1) {
    }
  case 0x3c:
    if ((iVar3 != 0) && (iVar4 = FUN_08058da8(local_14c,local_148,&local_168), iVar4 != 0)) {
      return 1;
    }
    if (((DAT_080826ec != 0) && (iVar3 != 0)) && (local_168[6] == 0x80000000)) {
      FUN_08051d94((int *)local_168);
    }
    local_174 = DAT_080826a0;
    while( true ) {
      local_164 = FUN_0805362c(param_1,(int *)&local_150,1,&local_16c);
      DAT_080826a0 = DAT_080826a0 + 4;
      if ((DAT_08080160 != 0) || (param_1[local_150] != ',')) break;
      local_150 = local_150 + 1;
    }
LAB_0805a0ac:
    if (iVar3 != 0) {
      local_168[4] = DAT_080826a0 - local_174;
    }
    break;
  case 9:
    aiStackY_1dc[1] = 0x805a0f2;
    local_164 = FUN_08053738(param_1,(int *)&local_150,&local_170,0,&local_16c,(uint *)0x0);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (local_170 == 1) {
      if (param_1[local_150] == ',') {
        local_150 = local_150 + 1;
        local_174 = FUN_080679f0((int)param_1,(int *)&local_150);
        if (DAT_08080160 != 0) {
          return 1;
        }
        if ((DAT_0808276c == 0) && (local_174 == 0xf)) {
          FUN_08052f1c(4,"Area directive missing");
        }
        DAT_080826b8 = local_174;
        goto LAB_0805a1dc;
      }
      DAT_080826b0 = 0;
      DAT_080826b4 = local_164;
    }
    else if (local_170 == 3) {
      if ((DAT_0808276c == 0) && (local_174 == 0xf)) {
        FUN_08052f1c(4,"Area directive missing");
      }
      DAT_080826b8 = 0xf;
LAB_0805a1dc:
      DAT_080826b0 = 1;
      DAT_080826b4 = local_164;
    }
    break;
  case 10:
    if (bVar2) {
      return 0;
    }
    FUN_080549d8();
    *param_3 = 1;
    break;
  case 0xb:
    if (bVar2) {
      return 0;
    }
    FUN_080549d8();
    *param_2 = 1;
    *param_4 = (int)(param_1 + local_150);
    if (DAT_08079804 != 0) {
      return 1;
    }
    while (iVar3 = FUN_0805cb78(param_1[local_150]), iVar3 == 0) {
      local_150 = local_150 + 1;
    }
    break;
  case 0xc:
    FUN_08054880((int)param_1,(int *)&local_150);
    return 1;
  case 0xd:
    FUN_08054c00((int)param_1,(int *)&local_150);
    return 1;
  case 0xe:
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    local_174 = local_164 >> 2;
    if (((local_174 & 1) != 0) && ((DAT_08082644 & 1) != 0)) {
      FUN_08055af8();
      FUN_080545cc();
    }
    if ((local_174 & 2) != 0) {
      DAT_08082594 = 0;
    }
    uVar8 = local_174 >> 2 & 3;
    if (uVar8 == 1) {
      DAT_080825cc = DAT_080825cc | 4;
    }
    else if (uVar8 == 2) {
      DAT_080825cc = DAT_080825cc & 0xfffffffb;
    }
    uVar8 = local_174 >> 4 & 3;
    if (uVar8 == 1) {
      DAT_080825cc = DAT_080825cc | 8;
    }
    else if (uVar8 == 2) {
      DAT_080825cc = DAT_080825cc & 0xfffffff7;
    }
    uVar8 = local_174 >> 6 & 3;
    if (uVar8 == 1) {
      DAT_080825cc = DAT_080825cc | 0x10;
    }
    else if (uVar8 == 2) {
      DAT_080825cc = DAT_080825cc & 0xffffffef;
    }
    uVar8 = local_174 >> 8 & 3;
    if (uVar8 == 1) {
      DAT_080825cc = DAT_080825cc | 1;
    }
    else if (uVar8 == 2) {
      DAT_080825cc = DAT_080825cc & 0xfffffffe;
    }
    uVar8 = local_174 >> 10 & 3;
    if (uVar8 == 1) {
      DAT_080825cc = DAT_080825cc | 2;
    }
    else if (uVar8 == 2) {
      DAT_080825cc = DAT_080825cc & 0xfffffffd;
    }
    uVar8 = local_174 >> 0xc & 3;
    if (uVar8 == 1) {
      DAT_080825cc = DAT_080825cc | 0x20;
    }
    else if (uVar8 == 2) {
      DAT_080825cc = DAT_080825cc & 0xffffffdf;
    }
    local_174 = local_174 >> 0xe;
    if ((local_174 & 3) == 1) {
      DAT_080825cc = DAT_080825cc | 0x40;
    }
    else if ((local_174 & 3) == 2) {
      DAT_080825cc = DAT_080825cc & 0xffffffbf;
    }
    if ((DAT_08082644 & 0x40) == 0) {
      FUN_0805627c();
    }
    break;
  case 0xf:
    if (((DAT_080825c4 == 1) && (uVar8 != 0)) &&
       (iVar3 = FUN_08058da8(local_14c,local_148,&local_168), iVar3 != 0)) {
      return 1;
    }
    for (; (byte)(param_1[local_150] - 0x1fU) < 2; local_150 = local_150 + 1) {
    }
    cVar1 = param_1[local_150];
    sVar6 = local_150;
    while (cVar1 != '\r') {
      sVar6 = sVar6 + 1;
      cVar1 = param_1[sVar6];
    }
    local_14c = sVar6 - local_150;
    pcVar15 = param_1 + local_150;
    local_164 = local_150;
    local_150 = sVar6;
    FUN_0805475c(local_14c,(int)pcVar15);
    break;
  case 0x10:
    for (; (byte)(param_1[local_150] - 0x1fU) < 2; local_150 = local_150 + 1) {
    }
    cVar1 = param_1[local_150];
    sVar6 = local_150;
    while (cVar1 != '\r') {
      sVar6 = sVar6 + 1;
      cVar1 = param_1[sVar6];
    }
    local_14c = sVar6 - local_150;
    pcVar15 = param_1 + local_150;
    local_164 = local_150;
    local_150 = sVar6;
    FUN_08054798(local_14c,(int)pcVar15);
    break;
  case 0x11:
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (0xf < local_164) {
      FUN_08052f1c(4,"Register value out of range");
      return 1;
    }
    local_168 = FUN_0805f570(local_14c,local_148,0);
    if ((local_168 == (uint *)0x0) || ((local_168[3] != 0xffffffff && (local_168[3] != local_164))))
    {
      FUN_08052f1c(4,"Register symbol already defined");
      return 1;
    }
    goto LAB_0805a810;
  case 0x12:
    local_24[0] = 1;
    local_24[1] = DAT_08082594 + -1;
    local_24[2] = DAT_08082598;
    local_14 = DAT_08082644;
    local_24[3] = DAT_08080154;
    piVar9 = local_24;
    piVar11 = aiStackY_1dc;
    for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
      *piVar11 = *piVar9;
      piVar9 = piVar9 + 1;
      piVar11 = piVar11 + 1;
    }
    iVar3 = FUN_08052960();
    if (iVar3 != 0) {
      if (DAT_08080154 == 0) {
        cVar1 = param_1[local_150];
        while (cVar1 != '\r') {
          local_150 = local_150 + 1;
          cVar1 = param_1[local_150];
        }
      }
      else {
        iVar3 = FUN_080530c0(param_1,(int *)&local_150);
        if ((iVar3 == 0) && (DAT_08080154 = 0, DAT_080825c8 != 0)) {
          DAT_080825cc = DAT_080825cc & 0xfffffffe;
        }
      }
      goto LAB_08059845;
    }
    break;
  case 0x13:
    FUN_08054904();
    if (DAT_08079804 != 0) {
      return 1;
    }
LAB_08059845:
    FUN_08058d80();
    break;
  case 0x14:
    if (DAT_08082780 != 0) {
      FUN_08052f1c(5,"macro definition attempted within expansion");
    }
    if (DAT_08080154 == 0) {
      FUN_080582e4();
      return 1;
    }
    FUN_08057b58();
    return 1;
  case 0x15:
    iVar3 = FUN_08054a04();
    goto joined_r0x0805bec0;
  case 0x16:
    iVar3 = FUN_08054ab8();
    goto joined_r0x0805bec0;
  case 0x17:
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      FUN_08052f1c(4,"Bad global name");
      return 1;
    }
    local_168 = FUN_0805f668(local_14c,local_148);
    if (local_168 == (uint *)0x0) {
      FUN_08052f1c(4,"Global name already exists");
      return 1;
    }
    goto LAB_0805aaa8;
  case 0x18:
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      FUN_08052f1c(4,"Bad global name");
      return 1;
    }
    local_168 = FUN_0805f6ac(local_14c,local_148);
    if (local_168 == (uint *)0x0) {
      FUN_08052f1c(4,"Global name already exists");
      return 1;
    }
    goto LAB_0805aaa8;
  case 0x19:
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      FUN_08052f1c(4,"Bad global name");
      return 1;
    }
    local_168 = FUN_0805f6f8(local_14c,local_148);
    if (local_168 == (uint *)0x0) {
      FUN_08052f1c(4,"Global name already exists");
      return 1;
    }
LAB_0805aaa8:
    *(byte *)(local_168 + 2) = (byte)local_168[2] & 0xfb;
    goto LAB_0805aaac;
  case 0x1a:
    if (DAT_08082780 == 0) {
      FUN_08052f1c(4,"Locals not allowed outside macros");
      return 1;
    }
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      FUN_08052f1c(4,"Bad local name");
      return 1;
    }
    local_168 = FUN_080585a4(local_14c,(int)local_148);
    if (local_168 == (uint *)0x0) {
      FUN_08052f1c(4,"Local name already exists");
      return 1;
    }
    goto LAB_0805aaac;
  case 0x1b:
    if (DAT_08082780 == 0) {
      FUN_08052f1c(4,"Locals not allowed outside macros");
      return 1;
    }
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      FUN_08052f1c(4,"Bad local name");
      return 1;
    }
    local_168 = FUN_08058608(local_14c,(int)local_148);
    if (local_168 == (uint *)0x0) {
      FUN_08052f1c(4,"Local name already exists");
      return 1;
    }
    goto LAB_0805aaac;
  case 0x1c:
    if (DAT_08082780 == 0) {
      FUN_08052f1c(4,"Locals not allowed outside macros");
      return 1;
    }
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      FUN_08052f1c(4,"Bad local name");
      return 1;
    }
    local_168 = FUN_0805867c(local_14c,(int)local_148);
    if (local_168 == (uint *)0x0) {
      FUN_08052f1c(4,"Local name already exists");
      return 1;
    }
    goto LAB_0805aaac;
  case 0x1d:
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (bVar2) {
      local_168 = FUN_0805f668(local_14c,local_148);
      if (local_168 == (uint *)0x0) {
        FUN_08052f1c(4,"Global name already exists");
        return 1;
      }
      *(byte *)(local_168 + 2) = (byte)local_168[2] | 4;
    }
    else {
      local_168 = FUN_08058760(local_14c,(int)local_148);
      if ((local_168 == (uint *)0x0) &&
         (local_168 = FUN_0805f784(local_14c,local_148), local_168 == (uint *)0x0)) {
        FUN_08052f1c(4,"Unknown or wrong type of global/local symbol");
        return 1;
      }
    }
    local_168[3] = local_164;
    FUN_080560a0(local_164);
    goto LAB_0805ae04;
  case 0x1e:
    sVar6 = FUN_080530c0(param_1,(int *)&local_150);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (bVar2) {
      local_168 = FUN_0805f6ac(local_14c,local_148);
      if (local_168 == (uint *)0x0) {
        FUN_08052f1c(4,"Global name already exists");
        return 1;
      }
      *(byte *)(local_168 + 2) = (byte)local_168[2] | 4;
    }
    else {
      local_168 = FUN_08058798(local_14c,(int)local_148);
      if ((local_168 == (uint *)0x0) &&
         (local_168 = FUN_0805f7c8(local_14c,local_148), local_168 == (uint *)0x0)) {
        FUN_08052f1c(4,"Unknown or wrong type of global/local symbol");
        return 1;
      }
    }
    local_168[3] = sVar6;
    FUN_08056134(sVar6);
LAB_0805ae04:
    FUN_08058d94();
    break;
  case 0x1f:
    FUN_080539b8(param_1,(int *)&local_150,&local_15c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (bVar2) {
      local_168 = FUN_0805f6f8(local_14c,local_148);
      if (local_168 == (uint *)0x0) {
        FUN_08052f1c(4,"Global name already exists");
        return 1;
      }
      *(byte *)(local_168 + 2) = (byte)local_168[2] | 4;
    }
    else {
      local_168 = FUN_080587cc(local_14c,(int)local_148);
      if ((local_168 == (uint *)0x0) &&
         (local_168 = FUN_0805f808(local_14c,local_148), local_168 == (uint *)0x0)) {
        FUN_08052f1c(4,"Unknown or wrong type of global/local symbol");
        return 1;
      }
    }
    FUN_080561d8(local_15c,(char *)local_158);
    *(uint *)local_168[3] = local_15c;
    uVar8 = *(uint *)(local_168[3] + 4);
    if (uVar8 < local_15c) {
      if (uVar8 != 0) {
        FUN_0805ee14(*(uint **)(local_168[3] + 8));
      }
      puVar5 = FUN_0805eddc(local_15c);
      *(uint **)(local_168[3] + 8) = puVar5;
      ((undefined4 *)local_168[3])[1] = *(undefined4 *)local_168[3];
    }
    if (local_15c != 0) {
      memcpy(*(void **)(local_168[3] + 8),local_158,local_15c);
    }
LAB_0805aaac:
    FUN_08058d94();
    break;
  case 0x20:
    iVar3 = FUN_080534cc(param_1,(int *)&local_150,1,&local_16c);
    if ((iVar3 != 0) || (local_16c == 0)) break;
    pcVar15 = "Assertion failed";
    goto LAB_0805bede;
  case 0x21:
    FUN_08055af8();
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (param_1[local_150] != ',') {
      FUN_08052f1c(4,"Missing comma");
      return 1;
    }
    local_150 = local_150 + 1;
    FUN_080539b8(param_1,(int *)&local_150,&local_14c);
    aiStackY_1dc[1] = 0x805b04c;
    memcpy(&DAT_0807f100,local_148,local_14c);
    (&DAT_0807f100)[local_14c] = 0;
LAB_0805b056:
    if (local_164 != 0) {
      FUN_08052f1c(4,"%s");
    }
    break;
  case 0x22:
    uVar8 = DAT_080826a0;
    if (DAT_080795ec != 1) goto LAB_0805b130;
    uVar8 = DAT_080826a0 & 1;
    while (uVar8 != 0) {
      while (uVar8 = DAT_080826a0 + 1, DAT_080795ec == 1) {
        uVar12 = DAT_080826a0 & 1;
        DAT_080826a0 = uVar8;
        if (uVar12 != 0) goto LAB_0805b156;
      }
LAB_0805b130:
      DAT_080826a0 = uVar8;
      uVar8 = DAT_080826a0 & 3;
    }
LAB_0805b156:
    if (iVar3 == 0) {
      local_168 = (size_t *)0x0;
    }
    else {
      local_168 = FUN_0805f5ec(local_14c,local_148,0);
      if (local_168 == (uint *)0x0) {
        FUN_08052f1c(4,"Multiply or incompatibly defined symbol");
        return 1;
      }
      iVar3 = FUN_08058da8(local_14c,local_148,&local_168);
      if (iVar3 != 0) {
        return 1;
      }
      *(byte *)((int)local_168 + 0xb) =
           *(byte *)((int)local_168 + 0xb) & 0xef | (DAT_080795ec == 1) << 4;
    }
    FUN_080571d8(local_168);
    break;
  case 0x23:
    if (((DAT_080825c4 == 1) && (uVar8 != 0)) &&
       (iVar3 = FUN_08058da8(local_14c,local_148,&local_168), iVar3 != 0)) {
      return 1;
    }
    if ((DAT_080825c4 == 0) &&
       (bVar2 = FUN_0805cad8(param_1,(int *)&local_150), CONCAT31(extraout_var,bVar2) != 0)) {
      local_164 = 4;
    }
    else {
      local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
      if (DAT_08080160 != 0) {
        return 1;
      }
    }
    if (DAT_080825c4 == 0) {
      if (param_1[local_150] == ',') {
        local_150 = local_150 + 1;
        unaff_EDI = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
        if (DAT_08080160 != 0) {
          return 1;
        }
      }
      else {
        unaff_EDI = 0;
      }
    }
    uVar8 = local_164;
    local_174 = local_164;
    if (DAT_080825c4 == 0) {
      uVar8 = unaff_EDI;
      if (local_164 != 0) {
        for (; (local_164 & 1) == 0; local_164 = local_164 >> 1) {
        }
      }
    }
    else {
      local_174 = 4;
      local_164 = 1;
      if (3 < uVar8) {
        FUN_08052f1c(4,"Bad alignment boundary");
        return 1;
      }
    }
    if (local_164 != 1) {
      FUN_08052f1c(4,"Bad alignment boundary");
      return 1;
    }
    DAT_080826a0 = (uVar8 - DAT_080826a0) % local_174 + DAT_080826a0;
    break;
  case 0x24:
    if (((DAT_080825c4 == 1) && (uVar8 != 0)) &&
       (iVar3 = FUN_08058da8(local_14c,local_148,&local_168), iVar3 != 0)) {
      return 1;
    }
    FUN_08056cb4();
    break;
  case 0x25:
    if ((DAT_080826a0 & 1) != 0) {
      DAT_080826a0 = DAT_080826a0 + 1;
    }
  case 0x3d:
    if ((iVar3 != 0) && (iVar4 = FUN_08058da8(local_14c,local_148,&local_168), iVar4 != 0)) {
      return 1;
    }
    if (((DAT_080826ec != 0) && (iVar3 != 0)) && (local_168[6] == 0x80000000)) {
      FUN_08051d94((int *)local_168);
    }
    local_174 = DAT_080826a0;
    while( true ) {
      local_164 = FUN_080535b0(param_1,(int *)&local_150,1,&local_16c);
      DAT_080826a0 = DAT_080826a0 + 2;
      if ((DAT_08080160 != 0) || (param_1[local_150] != ',')) break;
      local_150 = local_150 + 1;
    }
    goto LAB_0805a0ac;
  case 0x27:
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (0xf < local_164) {
      FUN_08052f1c(4,"Register value out of range");
      return 1;
    }
    local_168 = FUN_0805f570(local_14c,local_148,1);
    if ((local_168 == (uint *)0x0) || ((local_168[3] != 0xffffffff && (local_168[3] != local_164))))
    {
      FUN_08052f1c(4,"Register symbol already defined");
      return 1;
    }
    goto LAB_0805a810;
  case 0x28:
    for (; (DAT_080826a0 & 3) != 0; DAT_080826a0 = DAT_080826a0 + 1) {
    }
  case 0x29:
    if ((iVar3 != 0) && (iVar4 = FUN_08058da8(local_14c,local_148,&local_168), iVar4 != 0)) {
      return 1;
    }
    local_174 = DAT_080826a0;
    do {
      local_1b0 = &local_164;
      iVar4 = FUN_080547e0((int)param_1,(int *)&local_150,0,&local_164,local_1b0);
      if (iVar4 == 1) {
        pcVar15 = "Floating point overflow";
LAB_0805c01c:
        FUN_08052f1c(4,pcVar15);
      }
      else if (iVar4 == 2) {
        pcVar15 = "Floating point number not found";
        goto LAB_0805c01c;
      }
      DAT_080826a0 = DAT_080826a0 + 4;
      for (; (byte)(param_1[local_150] - 0x1fU) < 2; local_150 = local_150 + 1) {
      }
      if ((DAT_08080160 != 0) || (param_1[local_150] != ',')) goto LAB_0805c176;
      local_150 = local_150 + 1;
    } while( true );
  case 0x2a:
    for (; (DAT_080826a0 & 3) != 0; DAT_080826a0 = DAT_080826a0 + 1) {
    }
  case 0x2b:
    if ((iVar3 != 0) && (iVar4 = FUN_08058da8(local_14c,local_148,&local_168), iVar4 != 0)) {
      return 1;
    }
    local_174 = DAT_080826a0;
    do {
      local_1b0 = &local_164;
      iVar4 = FUN_080547e0((int)param_1,(int *)&local_150,1,&local_164,local_1b0);
      if (iVar4 == 1) {
        pcVar15 = "Floating point overflow";
LAB_0805c12c:
        FUN_08052f1c(4,pcVar15);
      }
      else if (iVar4 == 2) {
        pcVar15 = "Floating point number not found";
        goto LAB_0805c12c;
      }
      DAT_080826a0 = DAT_080826a0 + 8;
      for (; (byte)(param_1[local_150] - 0x1fU) < 2; local_150 = local_150 + 1) {
      }
      if ((DAT_08080160 != 0) || (param_1[local_150] != ',')) goto LAB_0805c176;
      local_150 = local_150 + 1;
    } while( true );
  case 0x2c:
    if (DAT_0808264c != 0) {
      FUN_08052f1c(4,"Too late to ban floating point");
      return 1;
    }
    DAT_0808277c = 0;
    break;
  case 0x2d:
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (0xf < local_164) {
      FUN_08052f1c(4,"Register value out of range");
      return 1;
    }
    local_168 = FUN_0805f570(local_14c,local_148,3);
    if ((local_168 == (uint *)0x0) || ((local_168[3] != 0xffffffff && (local_168[3] != local_164))))
    {
      FUN_08052f1c(4,"Register symbol already defined");
      return 1;
    }
    goto LAB_0805a810;
  case 0x2e:
    local_164 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
    if (DAT_08080160 != 0) {
      return 1;
    }
    if (0xf < local_164) {
      FUN_08052f1c(4,"Register value out of range");
      return 1;
    }
    local_168 = FUN_0805f570(local_14c,local_148,2);
    if ((local_168 == (uint *)0x0) || ((local_168[3] != 0xffffffff && (local_168[3] != local_164))))
    {
      FUN_08052f1c(4,"Register symbol already defined");
      return 1;
    }
LAB_0805a810:
    FUN_08058c78((int)local_168);
    local_168[3] = local_164;
    FUN_08056010(local_164);
    break;
  case 0x2f:
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      pcVar15 = "Area name missing";
      goto LAB_0805bede;
    }
    iVar3 = FUN_08058da8(local_14c,local_148,&local_168);
    if (iVar3 != 0) {
      return 1;
    }
    if (DAT_0808014c != 0) {
      if (DAT_080795f4 != (code *)0x0) {
        (*DAT_080795f4)();
        DAT_080795f4 = (code *)0x0;
      }
      FUN_08056cb4();
      *(uint *)(DAT_0808014c + 8) = (DAT_080826a0 + 3 & 0xfffffffc) - *(int *)(DAT_0808014c + 0x10);
    }
    DAT_0808276c = DAT_0808276c + 1;
    local_168[7] = DAT_0808276c;
    local_174 = 2;
    local_18c = 0;
    local_190 = 0;
    do {
      bVar2 = false;
      iVar3 = FUN_0805fa50((int)param_1,(int *)&local_150);
      if ((char)iVar3 != ',') break;
      local_150 = local_150 + 1;
      uVar8 = FUN_08055450((int)param_1,(int *)&local_150);
      local_190 = local_190 | uVar8;
      if (uVar8 == 0) {
        iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
        if ((iVar3 != 0) && (local_14c == 5)) {
          iVar3 = 5;
          bVar14 = true;
          pcVar15 = local_148;
          pcVar13 = "ALIGN";
          do {
            if (iVar3 == 0) break;
            iVar3 = iVar3 + -1;
            bVar14 = *pcVar15 == *pcVar13;
            pcVar15 = pcVar15 + 1;
            pcVar13 = pcVar13 + 1;
          } while (bVar14);
          if (bVar14) {
            iVar3 = FUN_0805fa50((int)param_1,(int *)&local_150);
            if ((char)iVar3 == '=') {
              local_150 = local_150 + 1;
              sVar6 = FUN_080535b0(param_1,(int *)&local_150,0,&local_16c);
              uVar12 = local_174;
              if ((DAT_08080160 != 0) || (uVar12 = sVar6, sVar6 - 2 < 0x1f)) goto LAB_0805bbff;
            }
            bVar2 = true;
            uVar12 = local_174;
            goto LAB_0805bbff;
          }
        }
        pcVar15 = "Bad area attribute or alignment";
LAB_0805bbf5:
        FUN_08052f1c(4,pcVar15);
        uVar12 = local_174;
      }
      else {
        uVar12 = FUN_08059074(uVar8);
        iVar10 = DAT_08082680;
        iVar4 = DAT_0808263c;
        iVar3 = DAT_08082638;
        if ((int)uVar12 < 0) {
          local_18c = local_18c & uVar12;
        }
        else {
          local_18c = local_18c | uVar12;
        }
        if (DAT_08082654 == 1) {
          if (uVar8 == 0x10) {
            DAT_08082638 = DAT_08082638 + 1;
            if (iVar3 != 0) {
              pcVar15 = "Too many data areas for a.out";
              goto LAB_0805bad4;
            }
          }
          else if (uVar8 < 0x11) {
            if ((uVar8 == 8) && (DAT_0808263c = DAT_0808263c + 1, iVar4 != 0)) {
              pcVar15 = "Too many code areas for a.out";
LAB_0805bad4:
              FUN_08052f1c(4,pcVar15);
            }
          }
          else if ((uVar8 == 0x100) && (DAT_08082680 = DAT_08082680 + 1, iVar10 != 0)) {
            pcVar15 = "Too many bss areas for a.out";
            goto LAB_0805bad4;
          }
        }
        uVar12 = local_174;
        if ((uVar8 == 0x800) &&
           (iVar3 = FUN_080679f0((int)param_1,(int *)&local_150), uVar12 = local_174,
           DAT_08080160 == 0)) {
          if ((&DAT_08082720)[iVar3] != 0) {
            pcVar15 = "Register already in use as an AREA base";
            goto LAB_0805bbf5;
          }
          local_18c = local_18c | iVar3 << 0x18;
          (&DAT_08082720)[iVar3] = DAT_0808276c;
        }
      }
LAB_0805bbff:
      local_174 = uVar12;
      if (uVar8 == 1) {
        *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) & 0xcf | 0x10;
      }
      if (bVar2) {
        FUN_08052f1c(4,"Bad area attribute or alignment");
      }
    } while (DAT_08080160 == 0);
    if ((local_190 & 8) == 0) {
      if (((local_190 & 0x10) != 0) && ((local_190 & 0x3600) != 0)) {
        uVar8 = 0x3600;
        do {
          uVar12 = -uVar8 & uVar8;
          if ((local_190 & uVar12) != 0) {
            FUN_080554f8(uVar12);
            FUN_080554f8(0x10);
            FUN_08052f1c(4,"Attribute %s cannot be used with attribute %s");
          }
          uVar8 = uVar8 & ~uVar12;
        } while ((local_190 & uVar8) != 0);
      }
    }
    else {
      uVar12 = 0x910;
      uVar8 = local_190 & 0x910;
      while (uVar8 != 0) {
        uVar8 = -uVar12 & uVar12;
        if ((local_190 & uVar8) != 0) {
          FUN_080554f8(uVar8);
          FUN_080554f8(8);
          FUN_08052f1c(4,"Attribute %s cannot be used with attribute %s");
        }
        uVar12 = uVar12 & ~uVar8;
        uVar8 = local_190 & uVar12;
      }
      if (DAT_080826f0 != 0) {
        local_18c = local_18c | 0x10000;
      }
      if (DAT_08082614 == 0) {
        local_18c = local_18c | 0x80000;
      }
      if (DAT_080795ec == 1) {
        local_18c = local_18c | 0x100000;
      }
      if (DAT_080825d8 != 0) {
        local_18c = local_18c | 0x400000;
      }
      if (DAT_080825c0 != 0) {
        local_18c = local_18c | 0x20000;
      }
    }
    if ((local_190 & 0x4020) == 0x4020) {
      FUN_080554f8(0x4000);
      FUN_080554f8(0x20);
      FUN_08052f1c(4,"Attribute %s cannot be used with attribute %s");
    }
    iVar3 = DAT_08082594;
    if (((DAT_08082698 != 0) && (DAT_0808014c != 0)) && ((*(byte *)(DAT_0808014c + 5) & 2) != 0)) {
      FUN_08052a80();
      do {
        iVar10 = iVar3;
        iVar4 = FUN_08052a90(local_44);
        iVar3 = local_38;
      } while (iVar4 != 0);
      FUN_0804ab4c(iVar10);
    }
    FUN_0805202c((int *)local_168,local_174,local_18c);
    if ((DAT_08082698 != 0) && ((*(byte *)(DAT_0808014c + 5) & 2) != 0)) {
      sVar6 = *local_168;
      memcpy(local_144,(void *)local_168[1],sVar6);
      local_144[sVar6] = 0;
      FUN_0804aafc();
      iVar3 = DAT_08082594;
      pcVar15 = FUN_0804e818();
      aiStackY_1dc[1] = 0x805be3b;
      FUN_0804aa4c(pcVar15,iVar3);
    }
    if (DAT_08082640 == 0) {
      *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) & 0xcf | 0x10;
    }
    else {
      DAT_080826a0 = 0;
    }
    if ((local_18c & 0x200) != 0) {
      *(byte *)((int)local_168 + 0xb) =
           *(byte *)((int)local_168 + 0xb) & 0xef | (DAT_080795ec == 1) << 4;
    }
    DAT_08082768 = DAT_080826a0;
    FUN_080571d8(local_168);
    local_168[3] = DAT_080826a0;
    iVar3 = DAT_08080160;
joined_r0x0805bec0:
    if (iVar3 != 0) {
      return 1;
    }
    break;
  case 0x30:
    if (DAT_080826d0 != 0) {
      pcVar15 = "Entry address already set";
      goto LAB_0805bede;
    }
    DAT_080826d0 = DAT_0808276c;
    DAT_080826d4 = DAT_080826a0;
    break;
  case 0x31:
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      pcVar15 = "Bad imported name";
      goto LAB_0805bede;
    }
    uVar8 = FUN_08058f98((int)param_1,(int *)&local_150,0);
    uVar12 = uVar8 >> 4 & 1;
    bVar2 = FUN_0805cad8(param_1,(int *)&local_150);
    if (CONCAT31(extraout_var_00,bVar2) == 0) {
      FUN_08052f1c(4,"Bad or unknown attribute");
      return 1;
    }
    local_168 = (size_t *)FUN_0805f618(local_14c,local_148,0);
    if (local_168 == (size_t *)0x0) {
      local_168 = (size_t *)FUN_0805f644(local_14c,local_148);
    }
    else if ((*(byte *)((int)local_168 + 10) & 0xc) == 0) {
      local_168[2] = 0;
      *(byte *)(local_168 + 2) = (byte)local_168[2] & 0xfc | 1;
    }
    else if ((local_168[2] & 3) != 1) {
      FUN_08052f1c(4,"Imported name already exists");
      return 1;
    }
    FUN_08058c78((int)local_168);
    *(ushort *)(local_168 + 2) = (ushort)local_168[2] & 0xfc3f | ((ushort)(uVar8 >> 8) & 0xf) << 6;
    if (local_168[6] == 0x80000000) {
      local_168[3] = uVar12;
      FUN_08051d94((int *)local_168);
    }
    else if (uVar12 == 0) {
      local_168[3] = 0;
    }
    break;
  case 0x32:
    if (((DAT_080825c4 == 1) && (uVar8 != 0)) &&
       (iVar3 = FUN_08058da8(local_14c,local_148,&local_168), iVar3 != 0)) {
      return 1;
    }
    while( true ) {
      local_1a0 = &local_150;
      iVar3 = FUN_080613f8((int)param_1,(int *)local_1a0,(int *)&local_14c);
      aiStackY_1dc[1] = 0x805b5d6;
      uVar8 = FUN_08058f98((int)param_1,(int *)&local_150,1);
      if (iVar3 == 0) {
        FUN_08052f1c(4,"Bad exported name");
      }
      else {
        local_168 = (size_t *)FUN_0805f618(local_14c,local_148,0);
        if (local_168 == (size_t *)0x0) {
          if ((uVar8 & 0x20) == 0) {
            local_168 = FUN_0805f5ec(local_14c,local_148,0);
          }
          else {
            local_168 = (size_t *)FUN_0805f644(local_14c,local_148);
          }
        }
        if ((uVar8 & 0x20) != 0) {
          *(byte *)((int)local_168 + 0xb) = *(byte *)((int)local_168 + 0xb) | 0x40;
        }
        FUN_08058c28((int)local_168);
        if (((((local_168[2] & 3) == 0) &&
             (bVar7 = *(byte *)((int)local_168 + 9) >> 4 & 3, bVar7 != 2)) && (bVar7 != 3)) ||
           ((local_168[2] & 0x40000003) == 0x40000001)) {
          if (local_168[6] == 0x80000000) {
            FUN_08051d94((int *)local_168);
          }
          *(byte *)((int)local_168 + 0xb) = *(byte *)((int)local_168 + 0xb) & 0xf9 | 4;
        }
        else {
          FUN_08052f1c(4,"Bad exported symbol type");
        }
        *(ushort *)(local_168 + 2) =
             (ushort)local_168[2] & 0xfc3f | ((ushort)(uVar8 >> 8) & 0xf) << 6;
      }
      bVar2 = FUN_0805cad8(param_1,(int *)&local_150);
      if (CONCAT31(extraout_var_01,bVar2) != 0) break;
      if (param_1[local_150] != ',') {
        FUN_08052f1c(4,"Missing comma");
        return 1;
      }
      local_150 = local_150 + 1;
      cVar1 = param_1[local_150];
      while ((byte)(cVar1 - 0x1fU) < 2) {
        local_150 = local_150 + 1;
        cVar1 = param_1[local_150];
      }
    }
    break;
  case 0x33:
    if (DAT_08082654 == 1) {
      FUN_08052f1c(4,"STRONG directive not suported by a.out");
      return 1;
    }
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      pcVar15 = "Bad imported name";
      goto LAB_0805bede;
    }
    local_168 = (size_t *)FUN_0805f618(local_14c,local_148,0);
    if (local_168 == (size_t *)0x0) {
      local_168 = (size_t *)FUN_0805f644(local_14c,local_148);
    }
    else if ((local_168[2] & 0xc0003) != 1) {
      FUN_08052f1c(4,"Imported name already exists");
      return 1;
    }
    FUN_08058c78((int)local_168);
    *(byte *)((int)local_168 + 10) = *(byte *)((int)local_168 + 10) | 0xc;
    if (local_168[6] == 0x80000000) {
      FUN_08051d94((int *)local_168);
    }
    *(byte *)((int)local_168 + 0xb) = *(byte *)((int)local_168 + 0xb) | 6;
    break;
  case 0x34:
    bVar2 = FUN_0805cad8(param_1,(int *)&local_150);
    if (CONCAT31(extraout_var_02,bVar2) != 0) {
      DAT_080826ec = 1;
      return 1;
    }
  case 0x38:
    iVar3 = FUN_080613f8((int)param_1,(int *)&local_150,(int *)&local_14c);
    if (iVar3 == 0) {
      pcVar15 = "Bad exported name";
LAB_0805bede:
      FUN_08052f1c(4,pcVar15);
    }
    else {
      local_168 = (size_t *)FUN_0805f618(local_14c,local_148,0);
      if (local_168 == (size_t *)0x0) {
        local_168 = FUN_0805f5ec(local_14c,local_148,0);
      }
      FUN_08058c28((int)local_168);
      if ((((local_168[2] & 3) == 0) && (bVar7 = *(byte *)((int)local_168 + 9) >> 4 & 3, bVar7 != 2)
          ) && (bVar7 != 3)) {
        if (local_168[6] == 0x80000000) {
          FUN_08051d94((int *)local_168);
        }
      }
      else {
        FUN_08052f1c(4,"Bad exported symbol type");
      }
      if (local_154 == 0x38) {
        *(ushort *)(local_168 + 2) = (ushort)local_168[2] & 0xfc3f | 0x200;
      }
    }
    break;
  case 0x35:
  case 0x36:
    if (DAT_080825d4 != 0) {
      FUN_08052f1c(4,"Too late to change output format");
      return 1;
    }
    DAT_080825d4 = 1;
    DAT_08082654 = (uint)(local_154 != 0x36);
    break;
  case 0x37:
switchD_08059761_caseD_37:
    local_164 = FUN_08067bdc((int)param_1,(int *)&local_150);
    if (DAT_08080160 != 0) {
      return 1;
    }
    local_168 = (size_t *)FUN_0805f618(local_14c,local_148,0);
    if (local_168 != (size_t *)0x0) {
      FUN_08052f1c(4,"Too late to define symbol as register list");
      return 1;
    }
    local_168 = FUN_0805f5ec(local_14c,local_148,0);
    FUN_08058c78((int)local_168);
    *(byte *)((int)local_168 + 10) = *(byte *)((int)local_168 + 10) | 0xc;
    *(byte *)((int)local_168 + 9) = *(byte *)((int)local_168 + 9) | 0x30;
    *(ushort *)((int)local_168 + 10) = *(ushort *)((int)local_168 + 10) & 0xfe3f;
    local_168[7] = DAT_0808276c;
    local_168[3] = local_164;
    FUN_080560a0(local_164);
    local_168[4] = 0;
    break;
  case 0x39:
    DAT_080826a0 = DAT_080826a0 + 1 & 0xfffffffe;
    DAT_080795ec = 1;
    goto LAB_0805979a;
  case 0x3a:
    DAT_080826a0 = DAT_080826a0 + 3 & 0xfffffffc;
    DAT_080795ec = 0;
LAB_0805979a:
    if (DAT_0808276c != 0) {
      DAT_08082628 = DAT_08082628 + 1;
    }
    break;
  case 0x3b:
    if (iVar3 != 0) {
      if (DAT_08082778 == 0) {
        FUN_08052f1c(4,"DATA directive can only be used in CODE areas");
        return 1;
      }
      local_168 = FUN_0805f5ec(local_14c,local_148,0);
      if (local_168 == (uint *)0x0) {
        FUN_08052f1c(4,"Multiply or incompatibly defined symbol");
        return 1;
      }
      iVar3 = FUN_08058da8(local_14c,local_148,&local_168);
      if (iVar3 != 0) {
        return 1;
      }
      *(byte *)((int)local_168 + 0xb) = *(byte *)((int)local_168 + 0xb) | 0x20;
    }
  }
switchD_08059761_caseD_26:
  if (DAT_08079804 == 0) {
switchD_080594e1_caseD_3:
    local_1a0 = &local_150;
    if (((DAT_08080160 == 0) &&
        (bVar2 = FUN_0805cad8(param_1,(int *)local_1a0), CONCAT31(extraout_var_03,bVar2) == 0)) &&
       (param_1[local_150] != ';')) {
      FUN_08052f1c(4,"Unexpected characters at end of line");
    }
    DAT_08082694 = local_150;
  }
  return 1;
LAB_0805c176:
  if (iVar3 != 0) {
    local_168[4] = DAT_080826a0 - local_174;
  }
  goto switchD_08059761_caseD_26;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0805c320(int *param_1,int *param_2)

{
  uint uVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  undefined3 extraout_var;
  int iVar5;
  undefined3 extraout_var_00;
  undefined4 uVar6;
  undefined3 extraout_var_01;
  char *pcVar7;
  int *local_40;
  int local_3c;
  int local_34;
  uint *local_30;
  int local_2c;
  int local_28;
  uint local_24;
  int local_20;
  uint local_1c;
  char *local_18;
  uint local_14;
  char *local_10;
  int local_c;
  char *local_8;
  
  local_c = 0;
  local_20 = 0;
  bVar3 = false;
  *param_2 = 0;
  DAT_08080160 = 0;
  iVar4 = FUN_08054d90((int *)&local_8,1);
  if (iVar4 != 0) {
    DAT_08082584 = FUN_08061000(local_8);
    local_8 = DAT_08082584;
  }
  if (DAT_08079804 == 1) {
    DAT_08079804 = 0;
    if ((DAT_08082688 != 0) && (DAT_080825c4 == 0)) {
      FUN_08052f1c(3,"Missing END directive at end of file");
    }
LAB_0805c755:
    uVar6 = 1;
  }
  else {
    FUN_08055f9c();
    FUN_08056040();
    while( true ) {
      local_40 = &local_c;
      bVar2 = FUN_0805cad8(local_8,local_40);
      if (CONCAT31(extraout_var,bVar2) != 0) break;
      if (local_8[local_c] == '#') {
        if (DAT_08082688 == 0) {
          if (local_c == 0) {
            DAT_08082688 = 1;
            DAT_080825c4 = 1;
            FUN_0805f950();
            DAT_080825d4 = 1;
            DAT_08082654 = 1;
            break;
          }
        }
        else if (DAT_080825c4 == 1) break;
      }
      if (((DAT_08082688 != 0) && (DAT_080825c4 == 1)) && ((byte)(*local_8 - 0x1fU) < 2)) {
        local_c = 1;
        FUN_0805fa50((int)local_8,local_40);
        local_2c = local_c;
        iVar4 = FUN_080613f8((int)local_8,&local_c,(int *)&local_14);
        if ((iVar4 != 0) && (local_8[local_c] == ':')) {
          local_8 = local_8 + local_2c;
        }
      }
      local_40 = &local_c;
      local_c = 0;
      iVar4 = FUN_080613f8((int)local_8,local_40,(int *)&local_14);
      if (iVar4 == 0) {
        while (iVar5 = FUN_0805cb78(local_8[local_c]), iVar5 == 0) {
          local_c = local_c + 1;
        }
        local_3c = local_c;
      }
      else {
        local_3c = local_c;
        if (local_8[local_c] == ':') {
          if (DAT_08082688 == 0) {
            FUN_0805f950();
          }
          else if (DAT_080825c4 != 1) goto LAB_0805c51e;
          DAT_08082688 = 1;
          DAT_080825c4 = 1;
          DAT_080825d4 = 1;
          DAT_08082654 = 1;
          local_c = local_c + 1;
        }
LAB_0805c51e:
        iVar5 = FUN_0805cb78(local_8[local_c]);
        if (iVar5 == 0) {
          iVar4 = 0;
          while (iVar5 = FUN_0805cb78(local_8[local_c]), iVar5 == 0) {
            local_c = local_c + 1;
          }
        }
      }
      local_34 = 0;
      bVar2 = FUN_0805cad8(local_8,local_40);
      if ((CONCAT31(extraout_var_00,bVar2) == 0) && (local_8[local_c] != ';')) {
        local_2c = local_c;
        FUN_0806150c((int)local_8,local_40,(int *)&local_1c);
        bVar3 = true;
        local_34 = local_c;
        if ((DAT_08080160 == 0) &&
           (iVar5 = FUN_080590b0(local_8,param_2,&local_20,param_1), iVar5 == 0)) goto LAB_0805c640;
        if (((((DAT_080825c4 != 0) && (DAT_08080160 == 0)) && (local_20 == 0)) &&
            ((DAT_08079804 == 0 && (*param_2 == 0)))) && (local_8[DAT_08082694] == ';')) {
          local_c = DAT_08082694;
          goto LAB_0805ca78;
        }
        if ((local_20 == 0) && (DAT_08079804 == 0)) {
          return 0;
        }
        goto LAB_0805c755;
      }
LAB_0805c640:
      if (DAT_08080154 == 0) break;
      if (bVar3) {
        iVar5 = FUN_08058cd0(local_1c,local_18,&local_28,(int *)&local_24);
        if (iVar5 == 0) {
          iVar5 = FUN_080613f8((int)local_8,&local_2c,(int *)&local_1c);
          if (iVar5 != 0) {
            FUN_0805759c(local_8,local_1c,(int)local_18);
            if (DAT_08079804 != 0) goto LAB_0805c755;
            break;
          }
          bVar3 = false;
        }
        else {
          if (iVar5 == 2) {
            FUN_08052f1c(4,"Opcode not supported on selected processor");
          }
          if (DAT_08082688 == 0) {
            FUN_0805f950();
          }
          DAT_08082688 = 1;
          if (DAT_080825c4 == 1) {
            DAT_080825d4 = 1;
            DAT_08082654 = 1;
          }
          if ((DAT_080795ec == 0) || (DAT_080795ec != 1)) {
            DAT_080826a0 = DAT_080826a0 + 3 & 0xfffffffc;
          }
          else {
            DAT_080826a0 = DAT_080826a0 + 1 & 0xfffffffe;
          }
          if ((DAT_0808276c == 0) && (DAT_080825c4 == 0)) {
            FUN_08052f1c(4,"Area directive missing");
            iVar5 = FUN_08052154();
            if (iVar5 == 0) break;
          }
          DAT_080825d4 = 1;
        }
      }
      local_c = local_3c;
      if (1 < (byte)(*local_8 - 0x1fU)) {
        if (iVar4 != 0) {
          if (local_8[local_3c] == ':') {
            if ((DAT_080825c4 == 1) || (DAT_08082688 == 0)) {
              if (DAT_08082688 == 0) {
                FUN_0805f950();
              }
              DAT_08082688 = 1;
              DAT_080825c4 = 1;
              DAT_080825d4 = 1;
              DAT_08082654 = 1;
              local_c = local_c + 1;
            }
LAB_0805c810:
            local_30 = FUN_0805f5ec(local_14,local_10,0);
            if ((local_30 == (uint *)0x0) &&
               (local_30 = (uint *)FUN_0805f644(local_14,local_10),
               (local_30[2] & 0x40000003) != 0x40000001)) {
              pcVar7 = "Multiply or incompatibly defined symbol";
            }
            else {
              FUN_08058c78((int)local_30);
              if (((bVar3) && (1 < (byte)(local_8[local_c] - 0x1fU))) ||
                 ((&DAT_080849c0)[(byte)local_8[local_c]] == 0)) goto LAB_0805c800;
              if ((*(byte *)((int)local_30 + 10) & 0xc) == 0) {
                if (DAT_0808014c == 0) {
                  FUN_08052f1c(5,"A Label was found which was in no AREA");
                }
                *(byte *)((int)local_30 + 10) = *(byte *)((int)local_30 + 10) | 0xc;
                *(byte *)((int)local_30 + 9) =
                     *(byte *)((int)local_30 + 9) & 0xcf |
                     ((byte)((uint)*(undefined4 *)(DAT_0808014c + 4) >> 8) & 1) << 4;
                if (bVar3) {
                  local_30[4] = 4;
                }
                else {
                  local_30[4] = 0;
                }
                local_30[3] = DAT_080826a0;
                if ((*(byte *)(DAT_0808014c + 5) & 2) != 0) {
                  *(byte *)((int)local_30 + 0xb) =
                       *(byte *)((int)local_30 + 0xb) & 0xef | (DAT_080795ec == 1) << 4;
                }
                uVar1 = DAT_0808276c;
                local_30[7] = DAT_0808276c;
                if ((uVar1 != 0) &&
                   (uVar1 = *(uint *)(DAT_0808014c + 4), (uVar1 & 0x100200) == 0x100000)) {
                  *(byte *)((int)local_30 + 9) = *(byte *)((int)local_30 + 9) & 0xcf | 0x20;
                  local_30[2] = local_30[2] & 0xfffc3fff | uVar1 >> 10 & 0x3c000;
                  *(byte *)((int)local_30 + 0xb) = *(byte *)((int)local_30 + 0xb) | 8;
                }
                local_30[7] = DAT_0808276c;
                if ((DAT_080826ec != 0) && (local_30[6] == 0x80000000)) {
                  FUN_08051d94((int *)local_30);
                }
                goto LAB_0805ca00;
              }
              pcVar7 = "Multiply or incompatibly defined symbol";
            }
          }
          else {
            if ((DAT_080825c4 == 0) || (DAT_08082688 == 0)) {
              DAT_08082688 = 1;
              DAT_080825c4 = 0;
              goto LAB_0805c810;
            }
LAB_0805c800:
            pcVar7 = "Syntax error following label";
          }
          goto LAB_0805cac6;
        }
        iVar4 = isdigit((int)*local_8);
        if (iVar4 == 0) {
          pcVar7 = "Invalid line start ";
          goto LAB_0805cac6;
        }
        local_c = 0;
        FUN_08057074((int)local_8,local_40);
        if (DAT_08080160 == 0) {
LAB_0805ca00:
          _DAT_0808262c = 1;
          goto LAB_0805ca0a;
        }
        break;
      }
LAB_0805ca0a:
      if (bVar3) {
        if ((DAT_08082778 == 0) && (DAT_080825c4 == 0)) {
          pcVar7 = "Code generated in data area";
          goto LAB_0805cac6;
        }
        local_c = local_34;
        if ((DAT_080795ec == 0) || (DAT_080795ec != 1)) {
          iVar4 = FUN_080636f4(local_8,local_40,local_28,local_24,(int *)&local_30);
        }
        else {
          iVar4 = FUN_080693e0(local_8,local_40,local_28,local_24,(int *)&local_30);
        }
        if (iVar4 != 0) goto LAB_0805ca78;
        break;
      }
LAB_0805ca78:
      if (DAT_08080160 == 0) {
        bVar3 = FUN_0805cad8(local_8,local_40);
        if (CONCAT31(extraout_var_01,bVar3) != 0) break;
        if (local_8[local_c] != ';') {
          pcVar7 = "Unexpected characters at end of line";
LAB_0805cac6:
          FUN_08052f1c(4,pcVar7);
          break;
        }
        local_8 = local_8 + local_c + 1;
        local_c = 0;
        bVar3 = false;
      }
    }
    uVar6 = 0;
  }
  return uVar6;
}



bool FUN_0805cad8(char *param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  bool bVar3;
  
  if (*param_1 == '*') {
LAB_0805cb61:
    bVar3 = true;
  }
  else {
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    cVar1 = (char)iVar2;
    if (cVar1 == ';') {
      if (DAT_08082688 == 0) {
        DAT_08082688 = 1;
        DAT_080825c4 = 0;
      }
      if (DAT_080825c4 == 0) goto LAB_0805cb61;
    }
    if (cVar1 == '@') {
      if (DAT_08082688 == 0) {
        DAT_08082688 = 1;
        DAT_080825c4 = 1;
        FUN_0805f950();
        DAT_080825d4 = 1;
        DAT_08082654 = 1;
      }
      if (DAT_080825c4 == 1) goto LAB_0805cb61;
    }
    bVar3 = cVar1 == '\r';
  }
  return bVar3;
}



undefined4 FUN_0805cb78(char param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if ((((byte)(param_1 - 0x1fU) < 2) ||
      (((param_1 == '@' && (DAT_080825c4 == 1)) || (param_1 == ';')))) || (param_1 == '\r')) {
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_0805cbb0(void)

{
  if (((byte)DAT_08082644 & 2) == 0) {
    FUN_0805627c();
  }
  return;
}



void FUN_0805cbc4(void)

{
  if (((byte)DAT_08082644 & 4) == 0) {
    FUN_0805627c();
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0805cd61)

undefined4 FUN_0805cbd8(uint *param_1,undefined4 *param_2,undefined4 *param_3,int *param_4)

{
  char cVar1;
  undefined1 uVar2;
  byte bVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined *puVar8;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  uint *puVar9;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined4 *puVar10;
  undefined3 extraout_var_03;
  undefined3 uVar11;
  int *piVar12;
  undefined4 *puVar13;
  int *piVar14;
  uint *local_90;
  uint *local_88;
  undefined3 local_70;
  undefined1 uStack_6d;
  undefined4 local_60;
  uint *local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  undefined4 local_44;
  uint local_40;
  uint local_3c;
  byte *local_38;
  int local_34;
  uint local_30;
  uint local_2c;
  char *local_28;
  int local_24 [4];
  uint local_14;
  
  local_30 = 0;
  iVar5 = FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
  if (1 < (byte)(*(char *)(local_30 + (int)param_1) - 0x1fU)) {
    if ((iVar5 == 0) && (iVar5 = isdigit((int)(char)*param_1), iVar5 != 0)) {
      FUN_0805fbc8((int)param_1,(int *)&local_30);
    }
    return 0;
  }
  do {
    local_30 = local_30 + 1;
  } while ((byte)(*(char *)(local_30 + (int)param_1) - 0x1fU) < 2);
  iVar6 = FUN_0805531c((int)param_1,(int *)&local_30,&local_34);
  if (iVar6 == 0) {
    iVar6 = FUN_0806150c((int)param_1,(int *)&local_30,(int *)&local_3c);
    if (iVar6 == 0) {
      return 0;
    }
    iVar6 = FUN_0805538c(&local_34,local_3c,(char *)local_38);
    if (iVar6 == 0) {
      return 0;
    }
  }
  if (local_34 == 0x3f) {
    if (DAT_080825c4 == 0) {
      return 0;
    }
    local_30 = local_30 + 1;
    iVar6 = FUN_0806150c((int)param_1,(int *)&local_30,(int *)&local_3c);
    if (iVar6 == 0) {
      return 1;
    }
    iVar6 = FUN_08055538((int *)&local_40,local_3c,local_38);
    if (iVar6 == 0) {
      return 1;
    }
    cVar1 = (&DAT_08079829)[local_40];
    if ((int)cVar1 != 1) {
      while (DAT_080826a0 % (uint)(int)cVar1 != 0) {
        FUN_0805182c(0);
      }
    }
    local_34 = (int)(char)(&DAT_0807980c)[local_40];
    if (local_34 != 0x3f) goto LAB_0805cf54;
    switch(local_40) {
    default:
      FUN_08052f1c(5,"Unexpected as directive not handled");
      break;
    case 1:
      DAT_080825cc = DAT_080825cc & 0xfffffffb;
      break;
    case 2:
      DAT_080825cc = DAT_080825cc | 4;
      break;
    case 3:
    case 8:
    case 9:
    case 0xf:
    case 0x1b:
    case 0x1c:
      break;
    case 4:
      if ((DAT_08082644 & 1) != 0) {
        FUN_08055af8();
        FUN_080545cc();
      }
      break;
    case 5:
    case 6:
    case 7:
      if (DAT_080826f8 == 1) {
        DAT_08082618 = DAT_080826a0;
      }
      else if (DAT_080826f8 == 0) {
        DAT_08082704 = DAT_080826a0;
      }
      else if (DAT_080826f8 == 2) {
        DAT_0808268c = DAT_080826a0;
      }
      if (local_40 == 6) {
        DAT_080826a0 = DAT_08082618;
        DAT_08082778 = 0;
        DAT_08082774 = 0;
        DAT_080826f8 = 1;
        DAT_0808276c = DAT_080826f8;
      }
      else {
        DAT_0808276c = DAT_080826f8;
        if (local_40 < 7) {
          if (local_40 == 5) {
            DAT_080826a0 = DAT_08082704;
            DAT_08082778 = 1;
            DAT_08082774 = 0;
            DAT_080826f8 = 0;
            DAT_0808276c = DAT_080826f8;
          }
        }
        else if (local_40 == 7) {
          DAT_080826a0 = DAT_0808268c;
          DAT_08082778 = 0;
          DAT_08082774 = 1;
          DAT_080826f8 = 2;
          DAT_0808276c = DAT_080826f8;
        }
      }
      break;
    case 0x14:
    case 0x15:
      FUN_080539b8((char *)param_1,(int *)&local_30,&local_3c);
      local_50 = 0;
      if (local_3c != 0) {
        do {
          FUN_0805182c(local_38[local_50]);
          local_50 = local_50 + 1;
        } while (local_50 < local_3c);
      }
      if (local_40 == 0x15) {
        FUN_0805182c(0);
      }
    }
    goto switchD_0805cd96_caseD_3;
  }
  if (DAT_080825c4 == 1) {
    return 0;
  }
LAB_0805cf54:
  if ((DAT_08080154 == 0) && ((&DAT_080828a0)[local_34] == 0)) goto switchD_0805cd96_caseD_3;
  switch(local_34) {
  case 0:
    local_24[0] = 0;
    local_24[2] = DAT_08082644;
    local_24[1] = DAT_08080154;
    if (DAT_08080154 == 0) {
      cVar1 = *(char *)(local_30 + (int)param_1);
      while (cVar1 != '\r') {
        local_30 = local_30 + 1;
        cVar1 = *(char *)(local_30 + (int)param_1);
      }
    }
    else {
      iVar5 = FUN_080530c0((char *)param_1,(int *)&local_30);
      if ((iVar5 == 0) && (DAT_08080154 = 0, DAT_080825c8 != 0)) {
        DAT_080825cc = DAT_080825cc & 0xfffffffe;
      }
    }
    piVar12 = local_24;
    piVar14 = (int *)&stack0xffffff44;
    for (iVar5 = 8; iVar5 != 0; iVar5 = iVar5 + -1) {
      *piVar14 = *piVar12;
      piVar12 = piVar12 + 1;
      piVar14 = piVar14 + 1;
    }
    iVar5 = FUN_08052960();
    if (iVar5 != 0) goto LAB_0805d06e;
    break;
  case 1:
    iVar5 = FUN_080529b4(local_24);
    if (iVar5 != 0) {
      if (local_24[0] == 0) {
        piVar12 = local_24;
        piVar14 = (int *)&stack0xffffff44;
        for (iVar5 = 8; iVar5 != 0; iVar5 = iVar5 + -1) {
          *piVar14 = *piVar12;
          piVar12 = piVar12 + 1;
          piVar14 = piVar14 + 1;
        }
        FUN_08052960();
        if (DAT_08080154 == 0) {
          if ((local_24[1] != 0) && (DAT_08080154 = 1, (local_24[2] & 1U) != 0)) {
            DAT_080825cc = DAT_080825cc | 1;
          }
        }
        else {
          DAT_08080154 = 0;
          if (DAT_080825c8 != 0) {
            DAT_080825cc = DAT_080825cc & 0xfffffffe;
          }
        }
        goto LAB_0805d06e;
      }
LAB_0805d10d:
      if (local_24[0] != 1) {
        piVar12 = local_24;
        piVar14 = (int *)&stack0xffffff44;
        for (iVar5 = 8; iVar5 != 0; iVar5 = iVar5 + -1) {
          *piVar14 = *piVar12;
          piVar12 = piVar12 + 1;
          piVar14 = piVar14 + 1;
        }
        FUN_08052960();
      }
      FUN_08052f1c(4,"Structure mismatch");
      DAT_08079804 = 4;
    }
    break;
  case 2:
    iVar5 = FUN_080529b4(local_24);
    if (iVar5 != 0) {
      if (local_24[0] != 0) goto LAB_0805d10d;
      DAT_080825cc = local_24[2];
      DAT_08080154 = local_24[1];
      if (((local_24[2] & 1U) != 0) && ((DAT_08082644 & 1) == 0)) {
        DAT_08082644 = DAT_08082644 | 1;
        FUN_08055f9c();
      }
      goto LAB_0805d06e;
    }
    break;
  case 3:
    FUN_08055af8();
    local_44 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    local_30 = local_30 + 1;
    FUN_080539b8((char *)param_1,(int *)&local_30,&local_2c);
    memcpy(&DAT_0807f200,local_28,local_2c);
    (&DAT_0807f200)[local_2c] = 0;
    FUN_08052f1c(1,"%s");
    FUN_08052f1c(1,"\n");
    break;
  case 4:
    local_44 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    if ((DAT_080826b0 == 0) || (DAT_080826b0 == 1)) {
      FUN_080560a0(DAT_080826b4);
      DAT_080826b4 = DAT_080826b4 + local_44;
    }
    break;
  case 5:
    if ((DAT_080825c4 == 1) && (*(char *)(local_30 + (int)param_1) == '{'))
    goto switchD_0805cf77_caseD_37;
    local_44 = FUN_0805384c((char *)param_1,(int *)&local_30,&local_50,&local_4c,0,&local_48);
    if (DAT_08080160 != 0) {
      return 1;
    }
    FUN_080560a0(local_44);
    iVar5 = FUN_0805f618(local_2c,local_28,0);
    if ((*(byte *)(iVar5 + 10) >> 2 & 3) == 3) {
      return 1;
    }
    if (DAT_08080160 != 0) {
      *(byte *)(iVar5 + 10) = *(byte *)(iVar5 + 10) & 0xf3 | 8;
      return 1;
    }
    *(uint *)(iVar5 + 0xc) = local_44;
    if (local_4c == 3) {
      *(byte *)(iVar5 + 9) = *(byte *)(iVar5 + 9) & 0xcf;
    }
    else if (local_4c < 4) {
      if (local_4c == 1) {
        *(byte *)(iVar5 + 9) = *(byte *)(iVar5 + 9) & 0xcf | 0x10;
      }
    }
    else if (local_4c == 4) {
      *(byte *)(iVar5 + 9) = *(byte *)(iVar5 + 9) & 0xcf | 0x20;
      *(uint *)(iVar5 + 8) = *(uint *)(iVar5 + 8) & 0xfffc3fff | (local_50 & 0xf) << 0xe;
    }
    *(byte *)(iVar5 + 10) = *(byte *)(iVar5 + 10) | 0xc;
    *(undefined4 *)(iVar5 + 0x10) = 0;
    break;
  case 6:
    if (((iVar5 != 0) && (iVar5 = FUN_0805f618(local_2c,local_28,0), iVar5 != 0)) &&
       (((DAT_080826ec != 0 && ((*(byte *)(iVar5 + 0xb) & 6) == 0)) ||
        ((*(byte *)(iVar5 + 0xb) >> 1 & 3) == 1)))) {
      FUN_08051e3c(iVar5,local_2c,local_28,0,0);
      *(byte *)(iVar5 + 0xb) = *(byte *)(iVar5 + 0xb) & 0xf9 | 2;
    }
    while( true ) {
      FUN_08053b0c((char *)param_1,(int *)&local_30,0,(int *)&local_4c,&local_44,&local_54);
      if (DAT_08080160 != 0) {
        return 1;
      }
      if (local_4c == 1) {
        if ((0xff < local_44) && (uVar7 = FUN_080543d0(local_44,7), uVar7 != local_44)) {
          FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
          return 1;
        }
        FUN_0805182c((byte)local_44);
      }
      else if ((local_4c == 2) && (local_50 = 0, *local_54 != 0)) {
        do {
          FUN_0805182c(*(byte *)(local_50 + local_54[2]));
          local_50 = local_50 + 1;
        } while (local_50 < *local_54);
      }
      if (*(char *)(local_30 + (int)param_1) != ',') break;
      local_30 = local_30 + 1;
    }
    break;
  case 7:
    if (((iVar5 != 0) && (iVar5 = FUN_0805f618(local_2c,local_28,0), iVar5 != 0)) &&
       (((DAT_080826ec != 0 && ((*(byte *)(iVar5 + 0xb) & 6) == 0)) ||
        ((*(byte *)(iVar5 + 0xb) >> 1 & 3) == 1)))) {
      FUN_08051e3c(iVar5,local_2c,local_28,0,0);
      *(byte *)(iVar5 + 0xb) = *(byte *)(iVar5 + 0xb) & 0xf9 | 2;
    }
    iVar5 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    local_44 = iVar5 - 1;
    if (iVar5 != 0) {
      do {
        FUN_0805182c(0);
        bVar4 = local_44 != 0;
        local_44 = local_44 - 1;
      } while (bVar4);
      local_44 = 0xffffffff;
    }
    break;
  case 8:
  case 0x3c:
    if (((iVar5 != 0) && (iVar5 = FUN_0805f618(local_2c,local_28,0), iVar5 != 0)) &&
       (((DAT_080826ec != 0 && ((*(byte *)(iVar5 + 0xb) & 6) == 0)) ||
        ((*(byte *)(iVar5 + 0xb) >> 1 & 3) == 1)))) {
      FUN_08051e3c(iVar5,local_2c,local_28,0,0);
      *(byte *)(iVar5 + 0xb) = *(byte *)(iVar5 + 0xb) & 0xf9 | 2;
    }
    if (local_34 == 8) {
      while ((DAT_080826a0 & 3) != 0) {
        FUN_0805182c(0);
      }
    }
    do {
      if (DAT_08082654 == 0) {
        local_44 = FUN_0805362c((char *)param_1,(int *)&local_30,0,&local_48);
      }
      else {
        puVar8 = FUN_08053bbc((char *)param_1,(int *)&local_30,&local_44,(uint *)0x0);
        uVar7 = DAT_080826a0;
        if (puVar8 == (undefined *)0x0) {
          local_44 = FUN_08053738((char *)param_1,(int *)&local_30,&local_4c,0,&local_48,(uint *)0x0
                                 );
          if (local_4c != 3) goto LAB_0805d918;
          if (DAT_08082778 == 0) {
            uVar11 = 6;
          }
          else {
            uVar11 = 4;
          }
          local_60 = CONCAT13(4,uVar11);
          uVar7 = DAT_080826a0;
          if (DAT_08082778 == 0) {
            local_44 = local_44 + DAT_08082664;
          }
        }
        else {
          if ((puVar8[8] & 3) == 1) {
            local_70 = (undefined3)*(undefined4 *)(puVar8 + 0x18);
            uStack_6d = 0xc;
            uVar2 = uStack_6d;
          }
          else if (DAT_080825c4 == 0) {
            iVar5 = FUN_08051d60(*(uint *)(puVar8 + 0x1c));
            if ((*(uint *)(iVar5 + 4) & 0x200) == 0) {
              if ((*(uint *)(iVar5 + 4) & 0x1000) == 0) {
                local_70 = 6;
              }
              else {
                local_70 = 8;
              }
            }
            else {
              local_70 = 4;
            }
            uVar2 = 4;
            if (((*(byte *)(iVar5 + 5) & 2) == 0) &&
               (local_44 = DAT_08082664 + local_44, (*(byte *)(iVar5 + 5) & 0x10) != 0)) {
LAB_0805d8d9:
              uStack_6d = 4;
              local_44 = local_44 + DAT_08082668;
              uVar2 = uStack_6d;
            }
          }
          else {
            if (*(int *)(puVar8 + 0x1c) == 0) {
              local_70 = 4;
            }
            else if (*(int *)(puVar8 + 0x1c) == 1) {
              local_70 = 6;
            }
            else {
              local_70 = 8;
            }
            uStack_6d = 4;
            uVar2 = 4;
            if ((*(int *)(puVar8 + 0x1c) != 0) &&
               (local_44 = DAT_08082664 + local_44, uVar2 = uStack_6d, *(int *)(puVar8 + 0x1c) != 1)
               ) goto LAB_0805d8d9;
          }
          uStack_6d = uVar2;
          local_60 = CONCAT13(uStack_6d,local_70);
        }
        FUN_080514cc(uVar7,local_60,0);
      }
LAB_0805d918:
      if (DAT_08080160 != 0) {
        return 1;
      }
      FUN_08051c84(local_44,(uint)(local_34 == 0x3c));
      if (*(char *)(local_30 + (int)param_1) != ',') break;
      local_30 = local_30 + 1;
    } while( true );
  case 9:
    local_44 = FUN_08053738((char *)param_1,(int *)&local_30,&local_4c,0,&local_48,(uint *)0x0);
    if (local_4c == 1) {
      if (*(char *)(local_30 + (int)param_1) == ',') {
        local_30 = local_30 + 1;
        DAT_080826b8 = FUN_080679f0((int)param_1,(int *)&local_30);
        DAT_080826b0 = 1;
        DAT_080826b4 = local_44;
        local_50 = DAT_080826b8;
      }
      else {
        DAT_080826b0 = 0;
        DAT_080826b4 = local_44;
      }
    }
    else if (local_4c == 3) {
      DAT_080826b0 = 1;
      DAT_080826b8 = 0xf;
      DAT_080826b4 = local_44;
    }
    break;
  case 10:
    *param_3 = 1;
    break;
  case 0xb:
    *param_2 = 1;
    *param_4 = (int)param_1 + local_30;
    break;
  case 0xc:
    FUN_08054880((int)param_1,(int *)&local_30);
    break;
  case 0xd:
    FUN_08054ca0((int)param_1,(int *)&local_30);
    break;
  case 0xe:
    local_44 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    if ((local_44 & 3) == 1) {
      DAT_080825cc = DAT_080825cc | 1;
    }
    else if ((local_44 & 3) == 2) {
      DAT_080825cc = DAT_080825cc & 0xfffffffe;
    }
    local_50 = local_44 >> 2;
    if (((local_50 & 1) != 0) && ((DAT_08082644 & 1) != 0)) {
      FUN_08055af8();
      FUN_080545cc();
    }
    if ((local_50 & 2) != 0) {
      DAT_08082594 = 0;
    }
    uVar7 = local_50 >> 2 & 3;
    if (uVar7 == 1) {
      DAT_080825cc = DAT_080825cc | 4;
    }
    else if (uVar7 == 2) {
      DAT_080825cc = DAT_080825cc & 0xfffffffb;
    }
    uVar7 = local_50 >> 4 & 3;
    if (uVar7 == 1) {
      DAT_080825cc = DAT_080825cc | 8;
    }
    else if (uVar7 == 2) {
      DAT_080825cc = DAT_080825cc & 0xfffffff7;
    }
    uVar7 = local_50 >> 6 & 3;
    if (uVar7 == 1) {
      DAT_080825cc = DAT_080825cc | 0x10;
    }
    else if (uVar7 == 2) {
      DAT_080825cc = DAT_080825cc & 0xffffffef;
    }
    uVar7 = local_50 >> 10 & 3;
    if (uVar7 == 1) {
      DAT_080825cc = DAT_080825cc | 2;
    }
    else if (uVar7 == 2) {
      DAT_080825cc = DAT_080825cc & 0xfffffffd;
    }
    uVar7 = local_50 >> 0xc & 3;
    if (uVar7 == 1) {
      DAT_080825cc = DAT_080825cc | 0x20;
    }
    else if (uVar7 == 2) {
      DAT_080825cc = DAT_080825cc & 0xffffffdf;
    }
    local_50 = local_50 >> 0xe;
    if ((local_50 & 3) == 1) {
      DAT_080825cc = DAT_080825cc | 0x40;
    }
    else if ((local_50 & 3) == 2) {
      DAT_080825cc = DAT_080825cc & 0xffffffbf;
    }
    if ((DAT_08082644 & 0x40) == 0) {
      FUN_0805627c();
    }
    break;
  case 0xf:
    for (; (byte)(*(char *)(local_30 + (int)param_1) - 0x1fU) < 2; local_30 = local_30 + 1) {
    }
    cVar1 = *(char *)(local_30 + (int)param_1);
    uVar7 = local_30;
    while (cVar1 != '\r') {
      uVar7 = uVar7 + 1;
      cVar1 = *(char *)(uVar7 + (int)param_1);
    }
    local_2c = uVar7 - local_30;
    local_28 = (char *)(local_30 + (int)param_1);
    local_44 = local_30;
    local_30 = uVar7;
    FUN_0805475c(local_2c,(int)local_28);
    break;
  case 0x10:
    for (; (byte)(*(char *)(local_30 + (int)param_1) - 0x1fU) < 2; local_30 = local_30 + 1) {
    }
    cVar1 = *(char *)(local_30 + (int)param_1);
    uVar7 = local_30;
    while (cVar1 != '\r') {
      uVar7 = uVar7 + 1;
      cVar1 = *(char *)(uVar7 + (int)param_1);
    }
    local_2c = uVar7 - local_30;
    local_28 = (char *)(local_30 + (int)param_1);
    local_44 = local_30;
    local_30 = uVar7;
    FUN_08054798(local_2c,(int)local_28);
    break;
  case 0x11:
  case 0x27:
  case 0x2d:
  case 0x2e:
    iVar5 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    FUN_08056010(iVar5);
    break;
  case 0x12:
    local_24[0] = 1;
    local_24[1] = DAT_08082594 + -1;
    local_24[2] = DAT_08082598;
    local_14 = DAT_08082644;
    local_24[3] = DAT_08080154;
    piVar12 = local_24;
    piVar14 = (int *)&stack0xffffff44;
    for (iVar5 = 8; iVar5 != 0; iVar5 = iVar5 + -1) {
      *piVar14 = *piVar12;
      piVar12 = piVar12 + 1;
      piVar14 = piVar14 + 1;
    }
    iVar5 = FUN_08052960();
    if (iVar5 != 0) {
      if (DAT_08080154 == 0) {
        cVar1 = *(char *)(local_30 + (int)param_1);
        while (cVar1 != '\r') {
          local_30 = local_30 + 1;
          cVar1 = *(char *)(local_30 + (int)param_1);
        }
      }
      else {
        iVar5 = FUN_080530c0((char *)param_1,(int *)&local_30);
        if ((iVar5 == 0) && (DAT_08080154 = 0, DAT_080825c8 != 0)) {
          DAT_080825cc = DAT_080825cc & 0xfffffffe;
        }
      }
      goto LAB_0805d06e;
    }
    break;
  case 0x13:
    FUN_08054904();
    if (DAT_08079804 != 0) {
      return 1;
    }
LAB_0805d06e:
    FUN_0805cbb0();
    break;
  case 0x14:
    DAT_080826a8 = 1;
    do {
      FUN_08055af8();
      FUN_08054d90((int *)&param_1,0);
      if (DAT_08079804 == 1) break;
      FUN_08056234();
      FUN_08055f9c();
      FUN_08056040();
      local_30 = 0;
      bVar4 = FUN_0805cad8((char *)param_1,(int *)&local_30);
    } while (((((CONCAT31(extraout_var,bVar4) != 0) || (local_30 == 0)) ||
              (iVar5 = FUN_0806150c((int)param_1,(int *)&local_30,(int *)&local_2c), iVar5 == 0)) ||
             ((iVar5 = FUN_0805538c(&local_34,local_2c,local_28), iVar5 == 0 ||
              (bVar4 = FUN_0805cad8((char *)param_1,(int *)&local_30),
              CONCAT31(extraout_var_00,bVar4) == 0)))) || (local_34 != 0x16));
    DAT_080826a8 = 0;
    break;
  case 0x15:
    iVar5 = FUN_08054a04();
    goto joined_r0x0805de49;
  case 0x16:
    iVar5 = FUN_08054ab8();
joined_r0x0805de49:
    if (iVar5 != 0) {
      return 1;
    }
    break;
  case 0x17:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    puVar9 = FUN_0805f784(local_2c,local_28);
    puVar9[3] = 0;
    goto LAB_0805df5f;
  case 0x18:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    puVar9 = FUN_0805f7c8(local_2c,local_28);
    puVar9[3] = 0;
    goto LAB_0805df5f;
  case 0x19:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    puVar9 = FUN_0805f808(local_2c,local_28);
    goto LAB_0805df4a;
  case 0x1a:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    puVar9 = FUN_080585a4(local_2c,(int)local_28);
    puVar9[3] = 0;
    goto LAB_0805df5f;
  case 0x1b:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    puVar9 = FUN_08058608(local_2c,(int)local_28);
    puVar9[3] = 0;
    goto LAB_0805df5f;
  case 0x1c:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    puVar9 = FUN_0805867c(local_2c,(int)local_28);
LAB_0805df4a:
    *(undefined4 *)puVar9[3] = 0;
LAB_0805df5f:
    *(byte *)(puVar9 + 2) = (byte)puVar9[2] | 4;
    FUN_0805cbc4();
    break;
  case 0x1d:
    local_44 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    local_90 = FUN_08058760(local_2c,(int)local_28);
    if (local_90 == (uint *)0x0) {
      local_90 = FUN_0805f784(local_2c,local_28);
    }
    local_90[3] = local_44;
    FUN_080560a0(local_44);
    goto LAB_0805e01d;
  case 0x1e:
    uVar7 = FUN_080530c0((char *)param_1,(int *)&local_30);
    local_90 = FUN_08058798(local_2c,(int)local_28);
    if (local_90 == (uint *)0x0) {
      local_90 = FUN_0805f7c8(local_2c,local_28);
    }
    local_90[3] = uVar7;
    FUN_08056134(uVar7);
LAB_0805e01d:
    FUN_0805cbc4();
    break;
  case 0x1f:
    FUN_080539b8((char *)param_1,(int *)&local_30,&local_3c);
    local_90 = FUN_080587cc(local_2c,(int)local_28);
    if (local_90 == (uint *)0x0) {
      local_90 = FUN_0805f808(local_2c,local_28);
    }
    FUN_080561d8(local_3c,(char *)local_38);
    *(uint *)local_90[3] = local_3c;
    uVar7 = *(uint *)(local_90[3] + 4);
    if (uVar7 < local_3c) {
      if (uVar7 != 0) {
        FUN_0805ee14(*(uint **)(local_90[3] + 8));
      }
      puVar9 = FUN_0805eddc(local_3c);
      *(uint **)(local_90[3] + 8) = puVar9;
      *(uint *)(local_90[3] + 4) = local_3c;
    }
    if (local_3c != 0) {
      memcpy(*(void **)(local_90[3] + 8),local_38,local_3c);
    }
    FUN_0805cbc4();
    break;
  case 0x20:
    iVar5 = FUN_080534cc((char *)param_1,(int *)&local_30,0,&local_48);
    if ((iVar5 == 0) && (DAT_08080160 == 0)) {
      FUN_08052f1c(4,"Assertion failed");
    }
    break;
  case 0x21:
    FUN_08055af8();
    local_44 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    local_30 = local_30 + 1;
    FUN_080539b8((char *)param_1,(int *)&local_30,&local_2c);
    memcpy(&DAT_0807f200,local_28,local_2c);
    (&DAT_0807f200)[local_2c] = 0;
    FUN_08052f1c(2,"%s");
    break;
  case 0x22:
    if ((DAT_080795ec == 0) || (DAT_080795ec != 1)) {
      while ((DAT_080826a0 & 3) != 0) {
        FUN_0805182c(0);
      }
    }
    else {
      while ((DAT_080826a0 & 1) != 0) {
        FUN_0805182c(0);
      }
    }
    if (iVar5 == 0) {
      local_90 = (uint *)0x0;
    }
    else {
      local_90 = FUN_0805f5ec(local_2c,local_28,0);
    }
    goto LAB_0805e62b;
  case 0x23:
    bVar4 = FUN_0805cad8((char *)param_1,(int *)&local_30);
    if (CONCAT31(extraout_var_01,bVar4) == 0) {
      local_44 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    }
    else {
      local_44 = 4;
    }
    if (*(char *)(local_30 + (int)param_1) == ',') {
      local_30 = local_30 + 1;
      local_50 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
    }
    else {
      local_50 = 0;
    }
    if (DAT_080825c4 == 1) {
      local_50 = local_44;
      local_44 = 4;
    }
    uVar7 = (DAT_080826a0 - local_50) % local_44;
    while (uVar7 != 0) {
      FUN_0805182c(0);
      uVar7 = (DAT_080826a0 - local_50) % local_44;
    }
    break;
  case 0x24:
    FUN_08056cb4();
    break;
  case 0x25:
  case 0x3d:
    if (((iVar5 != 0) && (iVar5 = FUN_0805f618(local_2c,local_28,0), iVar5 != 0)) &&
       (((DAT_080826ec != 0 && ((*(byte *)(iVar5 + 0xb) & 6) == 0)) ||
        ((*(byte *)(iVar5 + 0xb) >> 1 & 3) == 1)))) {
      FUN_08051e3c(iVar5,local_2c,local_28,0,0);
      *(byte *)(iVar5 + 0xb) = *(byte *)(iVar5 + 0xb) & 0xf9 | 2;
    }
    if ((local_34 == 0x25) && ((DAT_080826a0 & 1) != 0)) {
      FUN_0805182c(0);
    }
    while( true ) {
      local_44 = FUN_080535b0((char *)param_1,(int *)&local_30,0,&local_48);
      if (DAT_08080160 != 0) {
        return 1;
      }
      if ((0xffff < local_44) && (uVar7 = FUN_080543d0(local_44,0xf), uVar7 != local_44)) {
        FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
        return 1;
      }
      if (DAT_0808269c == 0) {
        FUN_0805182c((byte)local_44);
        bVar3 = local_44._1_1_;
      }
      else {
        FUN_0805182c((byte)(local_44 >> 8));
        bVar3 = (byte)local_44;
      }
      FUN_0805182c(bVar3);
      if (*(char *)(local_30 + (int)param_1) != ',') break;
      local_30 = local_30 + 1;
    }
    break;
  case 0x28:
    while ((DAT_080826a0 & 3) != 0) {
      FUN_0805182c(0);
    }
  case 0x29:
    while( true ) {
      FUN_080547e0((int)param_1,(int *)&local_30,0,&local_44,&local_50);
      FUN_08051c84(local_44,(uint)(local_34 == 0x29));
      cVar1 = *(char *)(local_30 + (int)param_1);
      while ((byte)(cVar1 - 0x1fU) < 2) {
        local_30 = local_30 + 1;
        cVar1 = *(char *)(local_30 + (int)param_1);
      }
      if (*(char *)(local_30 + (int)param_1) != ',') break;
      local_30 = local_30 + 1;
    }
    break;
  case 0x2a:
    while ((DAT_080826a0 & 3) != 0) {
      FUN_0805182c(0);
    }
  case 0x2b:
    while( true ) {
      FUN_080547e0((int)param_1,(int *)&local_30,1,&local_44,&local_50);
      for (; (byte)(*(char *)(local_30 + (int)param_1) - 0x1fU) < 2; local_30 = local_30 + 1) {
      }
      FUN_08051c84(local_44,(uint)(local_34 == 0x2b));
      FUN_08051c84(local_50,(uint)(local_34 == 0x2b));
      if (*(char *)(local_30 + (int)param_1) != ',') break;
      local_30 = local_30 + 1;
    }
    break;
  case 0x2f:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    local_90 = FUN_0805f5ec(local_2c,local_28,0);
    if (DAT_0808276c != 0) {
      if (DAT_080795f4 != (code *)0x0) {
        iVar5 = (*DAT_080795f4)();
        if (iVar5 != 0) {
          return 1;
        }
        DAT_080795f4 = (code *)0x0;
      }
      FUN_08056cb4();
      FUN_08051748();
      if (DAT_08082654 == 0) {
        FUN_08051454();
      }
    }
    FUN_0805202c((int *)local_90,0,0);
    FUN_08051240();
    DAT_0808276c = DAT_0808276c + 1;
    if ((*(byte *)((int)local_90 + 0xb) & 6) == 0) {
      FUN_08051e3c((int)local_90,local_2c,local_28,0,0);
      *(byte *)((int)local_90 + 0xb) = *(byte *)((int)local_90 + 0xb) & 0xf9 | 2;
    }
    if (DAT_08082640 != 0) {
      DAT_080826a0 = 0;
    }
LAB_0805e62b:
    FUN_080571d8(local_90);
    break;
  case 0x31:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    iVar5 = FUN_0805f618(local_2c,local_28,0);
    if ((*(byte *)(iVar5 + 0xb) & 6) == 0) {
      FUN_08051e3c(iVar5,local_2c,local_28,1,*(int *)(iVar5 + 0xc));
      *(byte *)(iVar5 + 0xb) = *(byte *)(iVar5 + 0xb) | 6;
    }
    break;
  case 0x32:
    local_90 = param_1;
    while( true ) {
      param_1 = local_90;
      FUN_080613f8((int)local_90,(int *)&local_30,(int *)&local_2c);
      iVar5 = FUN_0805f618(local_2c,local_28,0);
      if (iVar5 != 0) {
        bVar3 = *(byte *)(iVar5 + 10) >> 2;
        if (((bVar3 & 3) != 3) && ((DAT_080825c4 == 0 || ((bVar3 & 3) != 0)))) {
          FUN_08052f1c(4,"Undefined exported symbol");
          return 1;
        }
        if ((*(byte *)(iVar5 + 0xb) >> 1 & 3) == 2) {
          FUN_08051e3c(iVar5,local_2c,local_28,1,0);
          *(byte *)(iVar5 + 0xb) = *(byte *)(iVar5 + 0xb) | 6;
        }
      }
      bVar4 = FUN_0805cad8((char *)param_1,(int *)&local_30);
      if (CONCAT31(extraout_var_02,bVar4) != 0) break;
      local_30 = local_30 + 1;
      local_90 = param_1;
      cVar1 = *(char *)(local_30 + (int)param_1);
      while (cVar1 == ' ') {
        local_30 = local_30 + 1;
        cVar1 = *(char *)(local_30 + (int)param_1);
      }
    }
    break;
  case 0x33:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    iVar5 = FUN_0805f618(local_2c,local_28,0);
    puVar13 = (undefined4 *)(*(int *)(iVar5 + 0x18) * 0x10 + DAT_0807ff00);
    puVar13[2] = DAT_080826a0;
    *puVar13 = *(undefined4 *)(iVar5 + 0x14);
    puVar13[1] = 0x23;
    if (DAT_08082640 == 0) {
      puVar13[1] = 0x27;
    }
    puVar10 = (undefined4 *)FUN_08051d60(DAT_0808276c);
    puVar13[3] = *puVar10;
    local_50 = *(uint *)(iVar5 + 0x14);
    memcpy((void *)(local_50 + DAT_0807ff08),local_28,local_2c);
    *(undefined1 *)(local_2c + local_50 + DAT_0807ff08) = 0;
    break;
  case 0x34:
    bVar4 = FUN_0805cad8((char *)param_1,(int *)&local_30);
    if (CONCAT31(extraout_var_03,bVar4) != 0) {
      return 1;
    }
  case 0x38:
    FUN_080613f8((int)param_1,(int *)&local_30,(int *)&local_2c);
    iVar5 = FUN_0805f618(local_2c,local_28,0);
    if ((*(byte *)(iVar5 + 10) >> 2 & 3) != 3) {
      FUN_08052f1c(4,"Undefined exported symbol");
      return 1;
    }
    if ((*(byte *)(iVar5 + 0xb) & 6) == 0) {
      FUN_08051e3c(iVar5,local_2c,local_28,0,0);
      *(byte *)(iVar5 + 0xb) = *(byte *)(iVar5 + 0xb) & 0xf9 | 2;
    }
    break;
  case 0x37:
switchD_0805cf77_caseD_37:
    local_44 = FUN_08067bdc((int)param_1,(int *)&local_30);
    FUN_080560a0(local_44);
    break;
  case 0x39:
    if ((DAT_080826a0 & 1) != 0) {
      FUN_0805182c(0);
    }
    DAT_080795ec = 1;
    goto LAB_0805cfbd;
  case 0x3a:
    while ((DAT_080826a0 & 3) != 0) {
      FUN_0805182c(0);
    }
    DAT_080795ec = 0;
LAB_0805cfbd:
    if (DAT_0808276c != 0) {
      FUN_08051e28(DAT_08082634);
    }
  }
  if (DAT_08079804 == 0) {
switchD_0805cd96_caseD_3:
    local_88 = &local_30;
    FUN_0805cad8((char *)param_1,(int *)local_88);
    DAT_08082694 = local_30;
  }
  return 1;
}



undefined4 FUN_0805e7d0(int *param_1,int *param_2)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  undefined3 extraout_var;
  int iVar5;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  int local_3c;
  uint *local_30;
  int local_2c;
  int local_28;
  uint local_24;
  int local_20;
  uint local_1c;
  char *local_18;
  uint local_14;
  char *local_10;
  int local_c;
  uint *local_8;
  
  local_c = 0;
  local_20 = 0;
  *param_2 = 0;
  DAT_08080160 = 0;
  iVar4 = FUN_08054d90((int *)&local_8,1);
  if (iVar4 != 0) {
    DAT_08082584 = (uint *)FUN_08061000((char *)local_8);
    local_8 = DAT_08082584;
  }
  if (DAT_08079804 == 1) {
    DAT_08079804 = 0;
    return 1;
  }
  FUN_08055f9c();
  FUN_08056040();
  do {
    bVar3 = false;
    bVar1 = false;
    bVar2 = FUN_0805cad8((char *)local_8,&local_c);
    if (CONCAT31(extraout_var,bVar2) != 0) {
      return 0;
    }
    if ((*(char *)(local_c + (int)local_8) == '#') && (DAT_080825c4 == 1)) {
      return 0;
    }
    if (((DAT_08082688 != 0) && (DAT_080825c4 == 1)) && ((byte)((char)*local_8 - 0x1fU) < 2)) {
      local_c = 1;
      FUN_0805fa50((int)local_8,&local_c);
      iVar4 = local_c;
      iVar5 = FUN_080613f8((int)local_8,&local_c,(int *)&local_14);
      if ((iVar5 != 0) && (*(char *)(local_c + (int)local_8) == ':')) {
        local_8 = (uint *)((int)local_8 + iVar4);
      }
    }
    local_c = 0;
    local_3c = 0;
    iVar4 = FUN_080613f8((int)local_8,&local_c,(int *)&local_14);
    if (iVar4 == 0) {
      while (iVar4 = FUN_0805cb78(*(char *)(local_c + (int)local_8)), iVar4 == 0) {
        local_c = local_c + 1;
      }
    }
    else {
      bVar1 = true;
      local_3c = local_c;
      if (*(char *)(local_c + (int)local_8) == ':') {
        local_c = local_c + 1;
      }
      iVar4 = FUN_0805cb78(*(char *)(local_c + (int)local_8));
      if (iVar4 == 0) {
        bVar1 = false;
        while (iVar4 = FUN_0805cb78(*(char *)(local_c + (int)local_8)), iVar4 == 0) {
          local_c = local_c + 1;
        }
      }
    }
    iVar4 = 0;
    bVar2 = FUN_0805cad8((char *)local_8,&local_c);
    if ((CONCAT31(extraout_var_00,bVar2) == 0) && (*(char *)(local_c + (int)local_8) != ';')) {
      local_2c = local_c;
      FUN_0806150c((int)local_8,&local_c,(int *)&local_1c);
      iVar4 = local_c;
      bVar3 = true;
      if ((DAT_08080160 == 0) &&
         (iVar5 = FUN_0805cbd8(local_8,param_2,&local_20,param_1), iVar5 == 0)) goto LAB_0805ea40;
      if (((((DAT_080825c4 == 0) || (DAT_08080160 != 0)) || (local_20 != 0)) ||
          ((DAT_08079804 != 0 || (*param_2 != 0)))) ||
         (*(char *)(DAT_08082694 + (int)local_8) != ';')) {
        if (local_20 != 0) {
          return 1;
        }
        if (DAT_08079804 != 0) {
          return 1;
        }
        return 0;
      }
      local_c = DAT_08082694;
    }
    else {
LAB_0805ea40:
      if (DAT_08080154 == 0) {
        return 0;
      }
      if ((bVar3) &&
         (iVar5 = FUN_08058cd0(local_1c,local_18,&local_28,(int *)&local_24), iVar5 == 0)) {
        iVar5 = FUN_080613f8((int)local_8,&local_2c,(int *)&local_1c);
        if (iVar5 != 0) {
          FUN_0805759c((char *)local_8,local_1c,(int)local_18);
          if (DAT_08079804 == 0) {
            return 0;
          }
          return 1;
        }
        bVar3 = false;
      }
      if (1 < (byte)((char)*local_8 - 0x1fU)) {
        if (bVar1) {
          local_c = local_3c;
          if (*(char *)(local_3c + (int)local_8) == ':') {
            local_c = local_3c + 1;
          }
          local_30 = FUN_0805f5ec(local_14,local_10,0);
          if ((DAT_080826ec != 0) && ((*(byte *)((int)local_30 + 0xb) & 6) == 0)) {
            FUN_08051e3c((int)local_30,local_14,local_10,0,0);
            *(byte *)((int)local_30 + 0xb) = *(byte *)((int)local_30 + 0xb) & 0xf9 | 2;
          }
        }
        else {
          iVar5 = isdigit((int)(char)*local_8);
          if (iVar5 != 0) {
            local_c = 0;
            FUN_08057074((int)local_8,&local_c);
          }
        }
      }
      if (bVar3) {
        local_c = iVar4;
        FUN_0805fa50((int)local_8,&local_c);
        if ((DAT_080795ec == 0) || (DAT_080795ec != 1)) {
          iVar4 = FUN_08064c08((char *)local_8,&local_c,local_28,local_24,(int *)&local_30);
        }
        else {
          bVar3 = FUN_080699a8((char *)local_8,&local_c,local_28,local_24,(int *)&local_30);
          iVar4 = CONCAT31(extraout_var_01,bVar3);
        }
        if (iVar4 == 0) {
          return 0;
        }
      }
    }
    if (DAT_08080160 != 0) {
      return 0;
    }
    bVar3 = FUN_0805cad8((char *)local_8,&local_c);
    if (CONCAT31(extraout_var_02,bVar3) != 0) {
      if (DAT_080825c4 != 0) {
        return 0;
      }
      if (*(char *)((int)local_8 + local_c + 1) != '=') {
        return 0;
      }
      if (DAT_08079868 == 0) {
        return 0;
      }
      FUN_080635d0((int)local_8,&local_c);
      return 0;
    }
    if (*(char *)(local_c + (int)local_8) != ';') {
      return 0;
    }
    local_8 = (uint *)((int)local_8 + local_c + 1);
    local_c = 0;
  } while( true );
}



undefined4 FUN_0805ec10(void)

{
  return DAT_0807984c;
}



undefined4 FUN_0805ec1c(void)

{
  return DAT_08079850;
}



void FUN_0805ec28(int param_1)

{
  DAT_0807984c = DAT_0807984c + 1;
  DAT_08079850 = DAT_08079850 + param_1;
  return;
}



void FUN_0805ec40(void)

{
  DAT_0807984c = 0;
  DAT_08079850 = 0;
  return;
}



int FUN_0805ec60(uint param_1)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  
  puVar5 = &DAT_0807f300;
  puVar7 = DAT_0807f300;
  if (DAT_0807f300 != (undefined4 *)0x0) {
    do {
      if (param_1 <= (uint)puVar7[1]) {
        uVar1 = puVar7[1] - param_1;
        puVar7[1] = uVar1;
        puVar3 = puVar7;
        if (uVar1 < 0x7f) {
          *puVar5 = *puVar7;
          *puVar7 = 0;
          do {
            puVar6 = puVar5;
            puVar5 = (undefined4 *)*puVar6;
          } while (puVar5 != (undefined4 *)0x0);
          *puVar6 = puVar7;
        }
        break;
      }
      puVar3 = (undefined4 *)*puVar7;
      puVar5 = puVar7;
      puVar7 = puVar3;
    } while (puVar3 != (undefined4 *)0x0);
    if (puVar3 != (undefined4 *)0x0) goto LAB_0805ed12;
  }
  uVar1 = param_1 + 8;
  uVar2 = uVar1;
  if (uVar1 < 0x1ff0) {
    uVar2 = 0x1ff0;
  }
  puVar3 = FUN_0806fdcc(uVar2,0);
  if (puVar3 == (undefined4 *)0x0) {
    return 0;
  }
  iVar4 = FUN_0806fe40((int)puVar3);
  puVar3[1] = iVar4 - uVar1;
  puVar5 = &DAT_0807f300;
  for (puVar7 = DAT_0807f300; (puVar7 != (undefined4 *)0x0 && (0x7e < (uint)puVar7[1]));
      puVar7 = (undefined4 *)*puVar7) {
    puVar5 = puVar7;
  }
  *puVar3 = puVar7;
  *puVar5 = puVar3;
LAB_0805ed12:
  return puVar3[1] + 8 + (int)puVar3;
}



uint * FUN_0805ed24(int param_1)

{
  uint *puVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_1 == 0) {
    puVar2 = (uint *)0x0;
  }
  else {
    uVar3 = param_1 + 3U & 0xfffffffc;
    uVar4 = uVar3 + 4;
    if ((uVar4 < 0x20) && (puVar2 = *(uint **)((int)&DAT_0807f320 + uVar3), puVar2 != (uint *)0x0))
    {
      *(uint *)((int)&DAT_0807f320 + uVar3) = *puVar2;
LAB_0805ed67:
      *puVar2 = uVar4;
      puVar2 = puVar2 + 1;
    }
    else {
      puVar1 = (uint *)&DAT_0807f33c;
      for (puVar2 = DAT_0807f33c; puVar2 != (uint *)0x0; puVar2 = (uint *)*puVar2) {
        if (uVar4 <= puVar2[1]) {
          uVar3 = puVar2[1] - uVar4;
          puVar2[1] = uVar3;
          if (uVar3 < 8) {
            *puVar1 = *puVar2;
            uVar4 = uVar4 + puVar2[1];
            goto LAB_0805ed67;
          }
          if (uVar3 < 0x20) {
            *puVar1 = *puVar2;
            *puVar2 = *(uint *)(&DAT_0807f31c + (uVar3 & 0xfffffffc));
            *(uint **)(&DAT_0807f31c + (uVar3 & 0xfffffffc)) = puVar2;
          }
          puVar2 = (uint *)((int)puVar2 + puVar2[1]);
          goto LAB_0805edce;
        }
        puVar1 = puVar2;
      }
      puVar2 = (uint *)FUN_0805ec60(uVar4);
LAB_0805edce:
      *puVar2 = uVar4;
      puVar2 = puVar2 + 1;
    }
  }
  return puVar2;
}



uint * FUN_0805eddc(int param_1)

{
  uint *puVar1;
  
  puVar1 = FUN_0805ed24(param_1);
  if ((puVar1 == (uint *)0x0) && (param_1 != 0)) {
    FUN_08052f1c(1,"host error: out of memory");
    FUN_080615f0(2);
  }
  return puVar1;
}



void FUN_0805ee14(uint *param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  uint *puVar3;
  
  if (param_1 != (uint *)0x0) {
    puVar3 = param_1 + -1;
    uVar1 = *puVar3;
    for (puVar2 = DAT_0807f300; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
      if ((uint *)((int)puVar2 + puVar2[1] + 8) == puVar3) {
        puVar2[1] = puVar2[1] + uVar1;
        return;
      }
    }
    *param_1 = uVar1;
    if (uVar1 < 0x20) {
      *puVar3 = *(uint *)(&DAT_0807f31c + (uVar1 & 0xfffffffc));
      *(uint **)(&DAT_0807f31c + (uVar1 & 0xfffffffc)) = puVar3;
    }
    else {
      *puVar3 = (uint)DAT_0807f33c;
      DAT_0807f33c = puVar3;
    }
  }
  return;
}



uint * FUN_0805ee84(char *param_1)

{
  char cVar1;
  uint *__dest;
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
  __dest = FUN_0805eddc(~uVar2);
  memcpy(__dest,param_1,~uVar2);
  return __dest;
}



uint * FUN_0805eeb8(void *param_1,size_t param_2)

{
  uint *__dest;
  
  __dest = FUN_0805eddc(param_2 + 1);
  memcpy(__dest,param_1,param_2);
  *(undefined1 *)(param_2 + (int)__dest) = 0;
  return __dest;
}



void FUN_0805eee8(void)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    (&DAT_0807f320)[uVar1] = 0;
    uVar1 = uVar1 + 1;
  } while (uVar1 < 8);
  DAT_0807f300 = 0;
  FUN_0806fd50();
  return;
}



void FUN_0805ef10(void)

{
  return;
}



int FUN_0805ef20(int *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  piVar1 = param_1 + 0x7ff;
  do {
    for (iVar2 = *param_1; iVar2 != 0; iVar2 = *(int *)(iVar2 + 0x20)) {
      iVar3 = iVar3 + 1;
    }
    param_1 = param_1 + 1;
  } while (param_1 <= piVar1);
  return iVar3;
}



void FUN_0805ef4c(char *param_1)

{
  char cVar1;
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
  FUN_0805475c(~uVar2 - 1,(int)param_1);
  return;
}



int FUN_0805ef80(int param_1,undefined *param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  uint local_8;
  
  iVar4 = 0;
  local_8 = 0;
  do {
    iVar2 = (&DAT_080829c0)[local_8];
    if (iVar2 != 0) {
      piVar3 = (int *)(param_1 + iVar4 * 4);
      do {
        iVar1 = (*(code *)param_2)(*(undefined4 *)(iVar2 + 8));
        if ((iVar1 != 0) && ((param_3 == 0 || (*(int *)(iVar2 + 0x1c) == param_4)))) {
          *piVar3 = iVar2;
          piVar3 = piVar3 + 1;
          iVar4 = iVar4 + 1;
        }
        iVar2 = *(int *)(iVar2 + 0x20);
      } while (iVar2 != 0);
    }
    local_8 = local_8 + 1;
  } while (local_8 < 0x800);
  return iVar4;
}



void FUN_0805efe8(int param_1,uint param_2,undefined *param_3)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint local_8;
  
  uVar5 = param_2;
  if (param_2 != 0) {
    do {
      uVar5 = (uVar5 + 2) / 3;
      local_8 = uVar5 + 1;
      if (local_8 <= param_2) {
        do {
          uVar2 = local_8 - 1;
          while (uVar5 - 1 < uVar2) {
            uVar4 = uVar2 - uVar5;
            iVar3 = (*(code *)param_3)(*(undefined4 *)(param_1 + uVar4 * 4),
                                       *(undefined4 *)(param_1 + uVar2 * 4));
            if (iVar3 != 0) break;
            uVar1 = *(undefined4 *)(param_1 + uVar2 * 4);
            *(undefined4 *)(param_1 + uVar2 * 4) = *(undefined4 *)(param_1 + uVar4 * 4);
            *(undefined4 *)(param_1 + uVar4 * 4) = uVar1;
            uVar2 = uVar4;
          }
          local_8 = local_8 + 1;
        } while (local_8 <= param_2);
      }
    } while (1 < uVar5);
  }
  return;
}



void FUN_0805f088(char *param_1)

{
  char cVar1;
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
  FUN_08054798(~uVar2 - 1,(int)param_1);
  return;
}



void FUN_0805f0bc(undefined4 *param_1,uint param_2,char *param_3)

{
  uint uVar1;
  uint uVar2;
  
  FUN_08054508();
  FUN_0805f088(param_3);
  uVar2 = 0;
  if (param_2 != 0) {
    do {
      for (uVar1 = 0; uVar1 < *(uint *)*param_1; uVar1 = uVar1 + 1) {
        FUN_08054714("%c");
      }
      FUN_08054714(" %08lX\n");
      FUN_08058a9c((uint *)*param_1);
      FUN_08054714("\n");
      param_1 = param_1 + 1;
      uVar2 = uVar2 + 1;
    } while (uVar2 < param_2);
  }
  return;
}



undefined4 FUN_0805f134(uint *param_1,uint *param_2)

{
  uint uVar1;
  
  uVar1 = 0;
  while( true ) {
    if (*param_1 <= uVar1) {
      return 1;
    }
    if (*param_2 <= uVar1) {
      return 0;
    }
    if (*(char *)(uVar1 + param_2[1]) < *(char *)(uVar1 + param_1[1])) {
      return 0;
    }
    if (*(char *)(uVar1 + param_1[1]) < *(char *)(uVar1 + param_2[1])) break;
    uVar1 = uVar1 + 1;
  }
  return 1;
}



void FUN_0805f1a0(undefined4 *param_1,undefined *param_2,char *param_3,int param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = DAT_08080150;
  if (param_4 == 0) {
    uVar3 = 1;
  }
  uVar2 = 1;
  if (uVar3 != 0) {
    do {
      uVar1 = FUN_0805ef80((int)param_1,param_2,param_4,uVar2);
      if (uVar1 != 0) {
        FUN_0805efe8((int)param_1,uVar1,FUN_0805f134);
        FUN_0805f0bc(param_1,uVar1,param_3);
        if (uVar1 == 1) {
          FUN_08054714("1 symbol");
        }
        else {
          FUN_08054714("%lu symbols");
        }
        FUN_08054714("\n");
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 <= uVar3);
  }
  return;
}



bool FUN_0805f23c(uint param_1)

{
  return (param_1 & 0x3003) == 0;
}



bool FUN_0805f250(ushort param_1)

{
  return (param_1 & 0x3003) == 0x1000;
}



bool FUN_0805f26c(ushort param_1)

{
  return (param_1 & 0x3003) == 0x2000;
}



bool FUN_0805f288(uint param_1)

{
  return (param_1 & 3) == 1;
}



void FUN_0805f2a0(void)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = FUN_0805ef20(&DAT_080829c0);
  if (iVar1 == 0) {
    FUN_08054714("%s");
  }
  else {
    puVar2 = FUN_0805eddc(iVar1 * 4);
    FUN_0805ef4c("Alphabetic symbol ordering");
    FUN_0805f1a0(puVar2,FUN_0805f23c,"Relocatable symbols",1);
    FUN_0805f1a0(puVar2,FUN_0805f250,"Absolute symbols",0);
    FUN_0805f1a0(puVar2,FUN_0805f26c,"Register relative symbols",0);
    FUN_0805f1a0(puVar2,FUN_0805f288,"External symbols",0);
    if (iVar1 == 1) {
      FUN_08054714("1 symbol in table");
    }
    else {
      FUN_08054714("%lu symbols in table");
    }
    FUN_08054714("\n");
    FUN_08054528();
    FUN_0805ee14(puVar2);
  }
  return;
}



uint FUN_0805f380(uint param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar2 = 0;
  uVar4 = 5;
  if (param_1 < 5) {
    uVar4 = param_1;
  }
  iVar3 = 0;
  if (0 < (int)uVar4) {
    do {
      iVar2 = (int)*(char *)(iVar3 + param_2) + iVar2 * 2;
      iVar3 = iVar3 + 1;
    } while (iVar3 < (int)uVar4);
  }
  uVar1 = param_1;
  while (uVar1 = uVar1 - 1, (int)(param_1 - uVar4) <= (int)uVar1) {
    iVar2 = (int)*(char *)(uVar1 + param_2) + iVar2 * 2;
  }
  return iVar2 + param_1 & 0x7ff;
}



void FUN_0805f3f4(void)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    (&DAT_080829c0)[uVar1] = 0;
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x800);
  return;
}



void FUN_0805f414(void)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    FUN_0805f9d0((uint *)(&DAT_080829c0)[uVar1]);
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x800);
  return;
}



void FUN_0805f43c(undefined4 *param_1,undefined4 param_2,undefined4 param_3,uint param_4)

{
  uint uVar1;
  uint *puVar2;
  
  uVar1 = param_4;
  puVar2 = FUN_0805eddc(0x2c);
  *param_1 = puVar2;
  puVar2[2] = uVar1;
  puVar2[8] = 0;
  puVar2[9] = 0;
  puVar2[10] = 0;
  FUN_080588f0(puVar2,&param_2);
  puVar2[4] = 0;
  puVar2[5] = 0;
  puVar2[6] = 0x80000000;
  return;
}



uint * FUN_0805f494(uint param_1,char *param_2,int param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  int local_8;
  
  uVar2 = FUN_0805f380(param_1,(int)param_2);
  if (((uint *)(&DAT_080829c0)[uVar2] == (uint *)0x0) && (param_3 != 0)) {
    FUN_0805f43c(&DAT_080829c0 + uVar2,param_1,param_2,param_4);
    FUN_0805ec28(1);
    puVar3 = (uint *)(&DAT_080829c0)[uVar2];
  }
  else {
    local_8 = 0;
    puVar3 = (uint *)(&DAT_080829c0)[uVar2];
    iVar1 = local_8;
    do {
      local_8 = iVar1;
      puVar4 = puVar3;
      if (puVar4 == (uint *)0x0) {
        FUN_0805ec28(local_8);
        return (uint *)0x0;
      }
      if (param_1 == *puVar4) {
        bVar7 = true;
        uVar2 = param_1;
        pcVar5 = param_2;
        pcVar6 = (char *)puVar4[1];
        do {
          if (uVar2 == 0) break;
          uVar2 = uVar2 - 1;
          bVar7 = *pcVar5 == *pcVar6;
          pcVar5 = pcVar5 + 1;
          pcVar6 = pcVar6 + 1;
        } while (bVar7);
        if (bVar7) {
          return puVar4;
        }
      }
      puVar3 = (uint *)puVar4[8];
      iVar1 = local_8 + 1;
    } while ((puVar3 != (uint *)0x0) || (param_3 == 0));
    FUN_0805f43c(puVar4 + 8,param_1,param_2,param_4);
    FUN_0805ec28(local_8 + 2);
    puVar3 = (uint *)puVar4[8];
  }
  return puVar3;
}



uint * FUN_0805f570(uint param_1,char *param_2,uint param_3)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar1 = FUN_0805f494(param_1,param_2,0,0);
  puVar2 = FUN_0805f494(param_1,param_2,1,(param_3 & 7) << 0x16 | 0xc0003);
  if ((puVar2[2] & 3) == 3) {
    puVar2[4] = 0;
    if (puVar1 == (uint *)0x0) {
      puVar2[3] = 0xffffffff;
    }
  }
  else {
    puVar2 = (uint *)0x0;
  }
  return puVar2;
}



uint * FUN_0805f5ec(uint param_1,char *param_2,int param_3)

{
  uint *puVar1;
  
  puVar1 = FUN_0805f494(param_1,param_2,1,0);
  if ((puVar1[2] & 3) == 0) {
    if (param_3 != 0) {
      *(byte *)((int)puVar1 + 10) = *(byte *)((int)puVar1 + 10) | 0x10;
    }
  }
  else {
    puVar1 = (uint *)0x0;
  }
  return puVar1;
}



void FUN_0805f618(uint param_1,char *param_2,int param_3)

{
  uint *puVar1;
  
  puVar1 = FUN_0805f494(param_1,param_2,0,0);
  if ((param_3 != 0) && (puVar1 != (uint *)0x0)) {
    *(byte *)((int)puVar1 + 10) = *(byte *)((int)puVar1 + 10) | 0x10;
  }
  return;
}



void FUN_0805f644(uint param_1,char *param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_0805f494(param_1,param_2,1,1);
  puVar1[4] = 0;
  puVar1[3] = 0;
  return;
}



uint * FUN_0805f668(uint param_1,char *param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_0805f494(param_1,param_2,1,0xc0002);
  if ((puVar1[2] & 0xc03) == 2) {
    puVar1[4] = 0;
    puVar1[3] = 0;
  }
  else {
    puVar1 = (uint *)0x0;
  }
  return puVar1;
}



uint * FUN_0805f6ac(uint param_1,char *param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_0805f494(param_1,param_2,1,0xc0402);
  if ((puVar1[2] & 0xc03) == 0x402) {
    puVar1[4] = 0;
    puVar1[3] = 0;
  }
  else {
    puVar1 = (uint *)0x0;
  }
  return puVar1;
}



uint * FUN_0805f6f8(uint param_1,char *param_2)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar1 = FUN_0805f494(param_1,param_2,0,0);
  if (puVar1 == (uint *)0x0) {
    puVar1 = FUN_0805f494(param_1,param_2,1,0xc0802);
    puVar1[4] = 0;
    puVar2 = FUN_0805eddc(0xc);
    puVar1[3] = (uint)puVar2;
    *puVar2 = 0;
    *(undefined4 *)(puVar1[3] + 8) = 0;
    *(undefined4 *)(puVar1[3] + 4) = 0;
  }
  else if ((puVar1[2] & 0xc03) == 0x802) {
    puVar1[4] = 0;
    *(undefined4 *)puVar1[3] = 0;
  }
  else {
    puVar1 = (uint *)0x0;
  }
  return puVar1;
}



uint * FUN_0805f784(uint param_1,char *param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_0805f494(param_1,param_2,0,0);
  if ((puVar1 == (uint *)0x0) || ((puVar1[2] & 0xc03) != 2)) {
    puVar1 = (uint *)0x0;
  }
  else {
    puVar1[4] = 0;
  }
  return puVar1;
}



uint * FUN_0805f7c8(uint param_1,char *param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_0805f494(param_1,param_2,0,0);
  if ((puVar1 == (uint *)0x0) || ((puVar1[2] & 0xc03) != 0x402)) {
    puVar1 = (uint *)0x0;
  }
  else {
    puVar1[4] = 0;
  }
  return puVar1;
}



uint * FUN_0805f808(uint param_1,char *param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_0805f494(param_1,param_2,0,0);
  if ((puVar1 == (uint *)0x0) || ((puVar1[2] & 0xc03) != 0x802)) {
    puVar1 = (uint *)0x0;
  }
  else {
    puVar1[4] = 0;
  }
  return puVar1;
}



void FUN_0805f848(void)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    for (piVar1 = (int *)(&DAT_080829c0)[iVar2]; piVar1 != (int *)0x0; piVar1 = (int *)piVar1[8]) {
      if ((piVar1[2] & 0xc0003U) == 0) {
        *(byte *)(piVar1 + 2) = *(byte *)(piVar1 + 2) & 0xfc | 1;
        piVar1[3] = 0;
        if (piVar1[6] == -0x80000000) {
          FUN_08051d94(piVar1);
        }
      }
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x800);
  return;
}



void FUN_0805f8a4(void)

{
  size_t *psVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    for (psVar1 = (size_t *)(&DAT_080829c0)[iVar2]; psVar1 != (size_t *)0x0;
        psVar1 = (size_t *)psVar1[8]) {
      if ((psVar1[2] & 0x6000003) == 1) {
        FUN_08051e3c((int)psVar1,*psVar1,(void *)psVar1[1],1,psVar1[3]);
        *(byte *)((int)psVar1 + 0xb) = *(byte *)((int)psVar1 + 0xb) | 6;
      }
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x800);
  return;
}



void FUN_0805f8f8(char *param_1,uint param_2,uint param_3)

{
  char cVar1;
  uint *puVar2;
  uint uVar3;
  char *pcVar4;
  
  uVar3 = 0xffffffff;
  pcVar4 = param_1;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  puVar2 = FUN_0805f570(~uVar3 - 1,param_1,param_2);
  if (puVar2 == (uint *)0x0) {
    FUN_08052f1c(4,"Register symbol already defined");
  }
  else {
    puVar2[3] = param_3;
  }
  return;
}



void FUN_0805f950(void)

{
  if (DAT_080829a0 != 1) {
    FUN_08067c80();
  }
  return;
}



void FUN_0805f964(uint *param_1)

{
  uint *puVar1;
  
  while (param_1 != (uint *)0x0) {
    if ((*param_1 == 1) && (param_1[1] != 0)) {
      FUN_0805ee14((uint *)param_1[2]);
    }
    puVar1 = (uint *)param_1[4];
    FUN_0805ee14(param_1);
    param_1 = puVar1;
  }
  return;
}



void FUN_0805f9a0(uint *param_1)

{
  uint *puVar1;
  
  while (param_1 != (uint *)0x0) {
    FUN_0805f964((uint *)*param_1);
    puVar1 = (uint *)param_1[1];
    FUN_0805ee14(param_1);
    param_1 = puVar1;
  }
  return;
}



void FUN_0805f9d0(uint *param_1)

{
  uint *puVar1;
  uint *puVar2;
  
  while (param_1 != (uint *)0x0) {
    puVar1 = (uint *)param_1[8];
    FUN_0805f9a0((uint *)param_1[9]);
    FUN_0805f9a0((uint *)param_1[10]);
    FUN_0805ee14((uint *)param_1[1]);
    if ((param_1[2] & 0xc03) == 0x802) {
      puVar2 = (uint *)param_1[3];
      if (puVar2[1] != 0) {
        FUN_0805ee14((uint *)puVar2[2]);
        puVar2 = (uint *)param_1[3];
      }
      FUN_0805ee14(puVar2);
    }
    FUN_0805ee14(param_1);
    param_1 = puVar1;
  }
  return;
}



int FUN_0805fa50(int param_1,int *param_2)

{
  char cVar1;
  char *pcVar2;
  
  pcVar2 = (char *)(param_1 + *param_2);
  cVar1 = *pcVar2;
  if ((byte)(cVar1 - 0x1fU) < 2) {
    do {
      pcVar2 = pcVar2 + 1;
      cVar1 = *pcVar2;
    } while ((byte)(cVar1 - 0x1fU) < 2);
    *param_2 = (int)pcVar2 - param_1;
  }
  return (int)cVar1;
}



bool FUN_0805fa8c(int param_1,int *param_2)

{
  int iVar1;
  bool bVar2;
  
  iVar1 = *param_2;
  bVar2 = *(char *)(iVar1 + param_1) != ',';
  if (bVar2) {
    FUN_08052f34(4,iVar1,"Missing comma");
  }
  else {
    *param_2 = iVar1 + 1;
  }
  return !bVar2;
}



uint FUN_0805fabc(int param_1,int *param_2)

{
  int iVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  
  uVar4 = 0;
  cVar2 = *(char *)(*param_2 + param_1);
  while( true ) {
    iVar3 = (int)cVar2;
    iVar1 = isdigit(iVar3);
    if (iVar1 == 0) {
      return uVar4;
    }
    if ((0x2fU - iVar3) / 10 < uVar4) break;
    uVar4 = iVar3 + -0x30 + uVar4 * 10;
    iVar1 = *param_2;
    *param_2 = iVar1 + 1;
    cVar2 = *(char *)(param_1 + 1 + iVar1);
  }
  FUN_08052f1c(4,"Decimal overflow");
  return 0;
}



uint FUN_0805fb34(int param_1,int *param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  uint unaff_ESI;
  uint uVar5;
  
  uVar5 = 0;
  iVar1 = *param_2;
  bVar4 = *(byte *)(iVar1 + param_1);
  while( true ) {
    bVar4 = bVar4 | 0x20;
    iVar3 = isxdigit((int)(char)bVar4);
    if (iVar3 == 0) {
      if (*param_2 == iVar1) {
        FUN_08052f1c(4,"Bad hexadecimal number");
      }
      return unaff_ESI;
    }
    if ((uVar5 & 0xf0000000) != 0) break;
    if ((char)bVar4 < ':') {
      uVar2 = bVar4 & 0xf;
    }
    else {
      uVar2 = (bVar4 & 0xf) + 9;
    }
    uVar5 = uVar5 * 0x10 + uVar2;
    iVar3 = *param_2;
    *param_2 = iVar3 + 1;
    bVar4 = *(byte *)(param_1 + 1 + iVar3);
  }
  FUN_08052f1c(4,"Hexadecimal overflow");
  return unaff_ESI;
}



void FUN_0805fbc8(int param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *param_2;
  if (*(char *)(iVar2 + param_1) == '0') {
    *param_2 = iVar2 + 1;
    cVar1 = *(char *)(param_1 + 1 + iVar2);
    if ((cVar1 == 'x') || (cVar1 == 'X')) {
      *param_2 = iVar2 + 2;
      FUN_0805fb34(param_1,param_2);
      return;
    }
  }
  FUN_0805fabc(param_1,param_2);
  return;
}



undefined4 FUN_0805fc10(int param_1,int *param_2,undefined1 *param_3)

{
  byte bVar1;
  char cVar2;
  bool bVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint local_c;
  
  iVar4 = *param_2;
  uVar5 = (uint)*(char *)(iVar4 + param_1);
  if ((uVar5 != 0x5c) || (DAT_08082700 == 0)) goto LAB_0805fe61;
  *param_2 = iVar4 + 1;
  uVar5 = (uint)*(char *)(param_1 + 1 + iVar4);
  switch(uVar5) {
  case 9:
  case 0x20:
    FUN_08052f1c(4,"Bad string escape sequence");
    do {
      do {
        iVar4 = *param_2;
        *param_2 = iVar4 + 1;
        cVar2 = *(char *)(param_1 + 1 + iVar4);
      } while (cVar2 == ' ');
    } while (cVar2 == '\t');
    if (cVar2 == '\n') {
      *param_2 = iVar4 + 2;
    }
  case 10:
    return 0;
  default:
    FUN_08052f1c(4,"Bad string escape sequence");
    break;
  case 0x22:
    uVar5 = 0x22;
    break;
  case 0x27:
    uVar5 = 0x27;
    break;
  case 0x30:
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
  case 0x35:
  case 0x36:
  case 0x37:
    uVar5 = uVar5 - 0x30;
    iVar4 = *param_2;
    *param_2 = iVar4 + 1;
    iVar6 = (int)*(char *)(param_1 + 1 + iVar4);
    if ((iVar6 - 0x30U & 0xfffffff8) == 0) {
      uVar5 = iVar6 + -0x30 + uVar5 * 8;
      *param_2 = iVar4 + 2;
      iVar6 = (int)*(char *)(param_1 + 2 + iVar4);
      if ((iVar6 - 0x30U & 0xfffffff8) == 0) {
        uVar5 = iVar6 + -0x30 + uVar5 * 8;
        *param_2 = iVar4 + 3;
      }
    }
    if ((uVar5 & 0xffffff00) == 0) goto LAB_0805fe64;
    goto LAB_0805fe0c;
  case 0x3f:
    uVar5 = 0x3f;
    break;
  case 0x5c:
    uVar5 = 0x5c;
    break;
  case 0x61:
    uVar5 = 7;
    break;
  case 0x62:
    uVar5 = 8;
    break;
  case 0x66:
    uVar5 = 0xc;
    break;
  case 0x6e:
    uVar5 = 10;
    break;
  case 0x72:
    uVar5 = 0xd;
    break;
  case 0x74:
    uVar5 = 9;
    break;
  case 0x76:
    uVar5 = 0xb;
    break;
  case 0x78:
    bVar3 = false;
    iVar4 = *param_2;
    *param_2 = iVar4 + 1;
    uVar5 = (uint)*(char *)(param_1 + 1 + iVar4);
    iVar4 = isxdigit(uVar5);
    if (iVar4 == 0) {
      FUN_08052f1c(4,"Bad string escape sequence");
      uVar5 = 0x78;
      goto LAB_0805fe64;
    }
    local_c = uVar5 & 0xf;
    if (0x39 < (int)uVar5) {
      local_c = local_c + 9;
    }
    iVar4 = *param_2;
    while( true ) {
      *param_2 = iVar4 + 1;
      iVar4 = isxdigit((int)*(char *)(param_1 + 1 + iVar4));
      if (iVar4 == 0) break;
      iVar6 = local_c * 0x10;
      if (iVar6 >> 4 != local_c) {
        bVar3 = true;
      }
      iVar4 = *param_2;
      bVar1 = *(byte *)(iVar4 + param_1);
      if ((char)bVar1 < ':') {
        local_c = iVar6 + (bVar1 & 0xf);
      }
      else {
        local_c = iVar6 + 9 + (bVar1 & 0xf);
      }
    }
    uVar5 = local_c & 0xff;
    if ((!bVar3) && (local_c == uVar5)) goto LAB_0805fe64;
LAB_0805fe0c:
    FUN_08052f1c(4,"Bad string escape sequence");
    goto LAB_0805fe64;
  }
  iVar4 = *param_2;
LAB_0805fe61:
  *param_2 = iVar4 + 1;
LAB_0805fe64:
  *param_3 = (char)uVar5;
  return 1;
}



undefined * FUN_0805fe78(int param_1,int *param_2,uint *param_3)

{
  int iVar1;
  undefined *local_8;
  
  *param_3 = 0;
  do {
    iVar1 = *param_2;
    if (*(char *)(iVar1 + param_1) == '\r') {
      FUN_08052f1c(4,"Missing close quote");
      return &DAT_0807f520;
    }
    if (*(char *)(iVar1 + param_1) == '\"') {
      if (*(char *)(param_1 + 1 + iVar1) != '\"') {
        *param_2 = iVar1 + 1;
        FUN_08054424((int *)&local_8,*param_3);
        if (*param_3 == 0) {
          return local_8;
        }
        memcpy(local_8,&DAT_0807f520,*param_3);
        return local_8;
      }
      (&DAT_0807f520)[*param_3] = 0x22;
      *param_2 = *param_2 + 2;
    }
    else {
      iVar1 = FUN_0805fc10(param_1,param_2,&DAT_0807f520 + *param_3);
      if (iVar1 == 0) {
        return &DAT_0807f520;
      }
    }
    *param_3 = *param_3 + 1;
  } while( true );
}



undefined4 FUN_0805ff20(int param_1,int *param_2)

{
  int iVar1;
  uint local_10;
  uint local_c;
  int local_8;
  
  iVar1 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if ((iVar1 != 0) &&
     ((((byte)(*(char *)(*param_2 + param_1) - 0x1fU) < 2 || (*(char *)(*param_2 + param_1) == ':'))
      && (iVar1 = FUN_08058800(0x807f340,local_c,local_8,0,&local_10,0x2a), iVar1 != 0)))) {
    *param_2 = *param_2 + 1;
    return local_10;
  }
  FUN_08052f1c(4,"Bad operator");
  return 0x2a;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0805ff98(undefined4 *param_1)

{
  _DAT_0808262c = 1;
  param_1[8] = 0;
  *param_1 = 1;
  if (DAT_08082640 == 1) {
    param_1[1] = 3;
    param_1[2] = DAT_080826a0;
    FUN_08061fd8(param_1 + 8,0,1,DAT_0808276c);
  }
  else {
    param_1[1] = 1;
    param_1[2] = DAT_080826a0;
  }
  return;
}



void FUN_0805fff4(undefined4 *param_1)

{
  uint uVar1;
  
  *param_1 = 1;
  param_1[8] = 0;
  if (DAT_080826b0 == 0) {
    param_1[1] = 1;
    param_1[2] = DAT_080826b4;
  }
  else if (DAT_080826b0 == 1) {
    param_1[1] = 4;
    param_1[6] = DAT_080826b4;
    uVar1 = 0;
    do {
      *(undefined1 *)((int)param_1 + uVar1 + 8) = 0;
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x10);
    *(undefined1 *)((int)param_1 + DAT_080826b8 + 8) = 1;
  }
  return;
}



void FUN_08060058(int param_1,int *param_2,undefined4 *param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  uint local_10;
  uint local_c;
  int local_8;
  
  iVar2 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if (((iVar2 == 0) || (*(char *)(*param_2 + param_1) != '}')) ||
     (iVar2 = FUN_08058800(0x807f4a0,local_c,local_8,0,&local_10,0x2a), iVar2 == 0)) {
    FUN_08052f1c(4,"Unknown operand");
    return;
  }
  *param_2 = *param_2 + 1;
  switch(local_10) {
  case 0:
    FUN_0805ff98(param_3);
    break;
  case 1:
    FUN_0805fff4(param_3);
    break;
  case 2:
    param_3[8] = 0;
    *param_3 = 1;
    param_3[1] = 1;
    if (((byte)DAT_08082644 & 1) == 0) {
      param_3[2] = DAT_080825d0 * -0x7fe + 0xffe;
    }
    else {
      param_3[2] = DAT_080825d0 * -0x3ff + 0x7ff;
    }
    if (((byte)DAT_08082644 & 2) == 0) {
      param_3[2] = param_3[2] + 0x2000;
    }
    else {
      param_3[2] = param_3[2] + 0x1000;
    }
    if (((byte)DAT_08082644 & 4) == 0) {
      param_3[2] = param_3[2] + 0x20;
    }
    else {
      param_3[2] = param_3[2] + 0x10;
    }
    if (((byte)DAT_08082644 & 8) == 0) {
      param_3[2] = param_3[2] + 0x80;
    }
    else {
      param_3[2] = param_3[2] + 0x40;
    }
    if (((byte)DAT_08082644 & 0x10) == 0) {
      param_3[2] = param_3[2] + 0x200;
    }
    else {
      param_3[2] = param_3[2] + 0x100;
    }
    break;
  case 3:
  case 4:
  case 9:
    param_3[8] = 0;
    *param_3 = 1;
    param_3[1] = 5;
    uVar3 = DAT_080825c0;
    if (local_10 != 9) {
      uVar3 = (uint)(local_10 == 3);
    }
    goto LAB_08060325;
  case 5:
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 1;
    if ((DAT_080795ec != 0) && (DAT_080795ec == 1)) goto LAB_08060353;
    if (DAT_080826f0 == 0) {
      uVar3 = 0x1a;
    }
    else {
      uVar3 = 0x20;
    }
    goto LAB_08060325;
  case 6:
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 2;
    param_3[3] = &DAT_080825e0;
    uVar3 = 0xffffffff;
    pcVar4 = (char *)&DAT_080825e0;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    goto LAB_08060322;
  case 7:
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 2;
    param_3[3] = DAT_080825f4 + 1;
    pcVar4 = (char *)(DAT_080825f4 + 1);
    goto LAB_08060318;
  case 8:
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 1;
    param_3[2] = DAT_080825fc;
    break;
  case 10:
    param_3[8] = 0;
    *param_3 = 1;
    param_3[1] = 2;
    if (DAT_0808269c == 0) {
      pcVar4 = "little";
    }
    else {
      pcVar4 = "big";
    }
    param_3[3] = pcVar4;
    goto LAB_08060318;
  case 0xb:
    param_3[8] = 0;
    *param_3 = 1;
    param_3[1] = 1;
    if ((DAT_080795ec == 0) || (DAT_080795ec != 1)) {
      param_3[2] = 0x20;
      return;
    }
LAB_08060353:
    param_3[2] = 0x10;
    break;
  case 0xc:
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 2;
    if ((DAT_080795ec == 0) || (DAT_080795ec != 1)) {
      param_3[3] = &DAT_080753cf;
    }
    else {
      param_3[3] = "Thumb";
    }
    pcVar4 = (char *)param_3[3];
LAB_08060318:
    uVar3 = 0xffffffff;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
LAB_08060322:
    uVar3 = ~uVar3 - 1;
LAB_08060325:
    param_3[2] = uVar3;
  }
  return;
}



void FUN_08060384(char *param_1,int *param_2,undefined4 *param_3,undefined4 *param_4)

{
  char cVar1;
  bool bVar2;
  byte bVar3;
  undefined3 extraout_var;
  int iVar4;
  undefined4 uVar5;
  uint *puVar6;
  undefined *puVar7;
  uint extraout_EAX;
  int iVar8;
  char cVar9;
  byte bVar10;
  uint uVar11;
  char *pcVar12;
  int local_13c;
  uint local_124;
  char local_11d;
  uint local_11c;
  uint local_118;
  char *local_114;
  int local_110;
  uint local_10c;
  char local_108 [260];
  
  *param_4 = 1;
  *param_3 = 0;
  bVar2 = FUN_0805cad8(param_1,param_2);
  if (CONCAT31(extraout_var,bVar2) != 0) {
    param_3[1] = 1;
    return;
  }
  cVar1 = param_1[*param_2];
  iVar8 = (int)cVar1;
  iVar4 = isdigit(iVar8);
  if (iVar4 != 0) {
    local_110 = *param_2;
    *param_3 = 1;
    param_3[1] = 1;
    param_3[8] = 0;
    if (param_1[*param_2 + 1] != '_') {
      uVar5 = FUN_0805fbc8((int)param_1,param_2);
      param_3[2] = uVar5;
      if (DAT_080825c4 != 1) {
        return;
      }
      iVar4 = *param_2;
      local_108[0] = param_1[iVar4];
      if ((local_108[0] != 'b') && (local_108[0] != 'f')) {
        return;
      }
      *param_2 = iVar4 + 1;
      memcpy(local_108 + 1,param_1 + local_110,iVar4 - local_110);
      local_108[*param_2 - local_110] = '\r';
      local_110 = 0;
      param_3[1] = 3;
      param_3[8] = 0;
      uVar5 = FUN_08056ef4((int)local_108,&local_110,param_4,&local_10c);
      param_3[2] = uVar5;
      FUN_08061fd8(param_3 + 8,0,1,local_10c);
      if (DAT_080825c4 != 1) {
        return;
      }
      if (local_10c == DAT_0808276c) {
        return;
      }
      *param_4 = 0;
      return;
    }
    iVar4 = *param_2 + 2;
    *param_2 = iVar4;
    cVar9 = param_1[iVar4];
    param_3[2] = 0;
    if ((cVar9 < '0') || (cVar1 <= cVar9)) {
      pcVar12 = "Bad based number";
    }
    else {
      local_13c = *param_2;
      while( true ) {
        *param_2 = local_13c + 1;
        if ((0x2fU - (int)cVar9) / (iVar8 - 0x30U) < (uint)param_3[2]) break;
        param_3[2] = cVar9 + -0x30 + param_3[2] * (iVar8 - 0x30U);
        local_13c = *param_2;
        cVar9 = param_1[local_13c];
        if (cVar9 < '0') {
          return;
        }
        if (cVar1 <= cVar9) {
          return;
        }
      }
      pcVar12 = "Numeric overflow";
    }
    goto LAB_08060d45;
  }
  iVar4 = isalpha(iVar8);
  if ((((iVar4 != 0) || (cVar1 == '_')) || ((cVar1 == '|' && (DAT_080825c4 == 0)))) &&
     (iVar4 = FUN_080613f8((int)param_1,param_2,(int *)&local_118), iVar4 != 0)) {
    *param_3 = 1;
    param_3[8] = 0;
    puVar6 = FUN_08058710(local_118,(int)local_114);
    if ((puVar6 == (uint *)0x0) &&
       (puVar6 = (uint *)FUN_0805f618(local_118,local_114,1), puVar6 == (uint *)0x0)) {
      puVar6 = FUN_0805f5ec(local_118,local_114,1);
    }
    FUN_08058c28((int)puVar6);
    if (((*(byte *)((int)puVar6 + 10) >> 2 & 3) != 3) && ((puVar6[2] & 3) != 1)) {
      *param_4 = 0;
      param_3[1] = 0;
      return;
    }
    bVar3 = (byte)puVar6[2];
    bVar10 = bVar3 & 3;
    if (bVar10 == 1) {
      param_3[1] = 1;
      FUN_08061fd8(param_3 + 8,1,1,puVar6[6]);
      param_3[2] = 0;
      *param_4 = 0;
      return;
    }
    if ((bVar3 & 3) == 0) {
      if ((bVar3 & 3) != 0) {
        return;
      }
      bVar3 = *(byte *)((int)puVar6 + 9) >> 4;
      bVar10 = bVar3 & 3;
      if (bVar10 != 1) {
        if ((bVar3 & 3) != 0) {
          if (bVar10 == 2) {
            param_3[1] = 4;
            uVar11 = 0;
            do {
              *(undefined1 *)((int)param_3 + uVar11 + 8) = 0;
              uVar11 = uVar11 + 1;
            } while (uVar11 < 0x10);
            *(undefined1 *)((int)param_3 + (puVar6[2] >> 0xe & 0xf) + 8) = 1;
            param_3[6] = puVar6[3];
            param_3[7] = *(byte *)((int)puVar6 + 0xb) >> 3 & 1;
            return;
          }
          goto LAB_080606f9;
        }
        if ((bVar3 & 3) != 0) {
          return;
        }
        if (puVar6[7] != DAT_0808276c) {
          param_3[1] = 0;
        }
        if (DAT_08082640 == 1) {
          param_3[1] = 3;
          param_3[2] = puVar6[3];
          FUN_08061fd8(param_3 + 8,0,1,puVar6[7]);
          return;
        }
      }
    }
    else if (bVar10 == 2) {
      bVar3 = *(byte *)((int)puVar6 + 9) >> 2;
      if ((bVar3 & 3) == 1) {
        param_3[1] = 5;
        goto LAB_0806088e;
      }
      if ((bVar3 & 3) != 0) {
        if ((bVar3 & 3) != 2) {
          return;
        }
        puVar6 = (uint *)puVar6[3];
        param_3[1] = 2;
        if ((puVar6 != (uint *)0x0) && (*puVar6 != 0)) {
          param_3[2] = *puVar6;
          FUN_08054424(param_3 + 3,*puVar6);
          memcpy((void *)param_3[3],(void *)puVar6[2],*puVar6);
          return;
        }
        param_3[2] = 0;
        param_3[3] = 0;
        return;
      }
      if ((bVar3 & 3) != 0) {
        return;
      }
    }
    else {
LAB_080606f9:
      if (bVar10 != 3) {
        return;
      }
    }
    param_3[1] = 1;
LAB_0806088e:
    param_3[2] = puVar6[3];
    return;
  }
  *param_2 = *param_2 + 1;
  switch(cVar1) {
  case '\"':
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 2;
    puVar7 = FUN_0805fe78((int)param_1,param_2,&local_11c);
    param_3[3] = puVar7;
    param_3[2] = local_11c;
    break;
  case '%':
    if (DAT_080825c4 != 1) {
      *param_3 = 1;
      param_3[8] = 0;
      if (DAT_08082640 == 1) {
        uVar5 = FUN_08056ef4((int)param_1,param_2,param_4,&local_124);
        param_3[2] = uVar5;
        param_3[1] = 3;
        FUN_08061fd8(param_3 + 8,0,1,local_124);
        return;
      }
      uVar5 = FUN_08056ef4((int)param_1,param_2,param_4,&local_124);
      param_3[2] = uVar5;
      param_3[1] = 1;
      return;
    }
  default:
    param_3[1] = 1;
    *param_2 = *param_2 + -1;
    break;
  case '&':
    if ((DAT_080825c4 == 1) && ((byte)(param_1[*param_2 + 1] - 0x1fU) < 2)) {
      param_3[1] = 0x13;
      return;
    }
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 1;
    param_3 = (undefined4 *)FUN_0805fb34((int)param_1,param_2);
    uVar11 = extraout_EAX;
    goto LAB_08060a20;
  case '\'':
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 1;
    iVar4 = FUN_0805fc10((int)param_1,param_2,&local_11d);
    if (iVar4 == 0) {
      return;
    }
    param_3[2] = (int)local_11d;
    cVar1 = param_1[*param_2];
    *param_2 = *param_2 + 1;
    if (cVar1 == '\'') {
      return;
    }
    pcVar12 = "Missing close quote";
    goto LAB_08060d45;
  case '(':
    param_3[1] = 2;
    break;
  case ')':
    param_3[1] = 3;
    break;
  case '*':
    param_3[1] = 0x19;
    break;
  case '+':
    param_3[1] = 0xd;
    break;
  case '-':
    param_3[1] = 0xe;
    break;
  case '.':
    FUN_0805ff98(param_3);
    break;
  case '/':
    if (param_1[*param_2] == '=') {
      *param_2 = *param_2 + 1;
      param_3[1] = 0xb;
    }
    else {
      param_3[1] = 0x1a;
    }
    break;
  case ':':
    iVar4 = FUN_0805ff20((int)param_1,param_2);
    param_3[1] = iVar4;
    if (iVar4 != 0x29) {
      return;
    }
    param_3[8] = 0;
    *param_3 = 1;
    param_3[1] = 5;
    param_3[2] = 0;
    FUN_0805cad8(param_1,param_2);
    iVar4 = FUN_080613f8((int)param_1,param_2,(int *)&local_118);
    if (iVar4 == 0) {
      pcVar12 = "Symbol missing";
      goto LAB_08060d45;
    }
    iVar4 = FUN_0805f618(local_118,local_114,0);
    if (iVar4 == 0) {
      param_3[2] = 0;
      return;
    }
    if ((*(byte *)(iVar4 + 8) & 3) != 2) {
      param_3[2] = 1;
      return;
    }
    if (DAT_080825d0 == 1) {
      uVar11 = 1;
    }
    else {
      uVar11 = *(byte *)(iVar4 + 8) >> 2 & 1;
    }
LAB_08060a20:
    param_3[2] = uVar11;
    break;
  case '<':
    cVar1 = param_1[*param_2];
    if (cVar1 == '=') {
      param_3[1] = 9;
      *param_2 = *param_2 + 1;
    }
    else if (cVar1 == '>') {
      param_3[1] = 0xb;
      *param_2 = *param_2 + 1;
    }
    else if (cVar1 == '<') {
      param_3[1] = 0x12;
      *param_2 = *param_2 + 1;
    }
    else {
      param_3[1] = 7;
    }
    break;
  case '=':
    param_3[1] = 8;
    break;
  case '>':
    iVar4 = *param_2;
    cVar1 = param_1[iVar4];
    if (cVar1 == '<') {
      *param_2 = iVar4 + 1;
      param_3[1] = 0xb;
    }
    else if (cVar1 == '=') {
      *param_2 = iVar4 + 1;
      param_3[1] = 0xc;
    }
    else if (cVar1 == '>') {
      param_3[1] = 0x11;
      *param_2 = *param_2 + 1;
    }
    else {
      param_3[1] = 10;
    }
    break;
  case '?':
    *param_3 = 1;
    param_3[8] = 0;
    param_3[1] = 1;
    param_3[2] = 0;
    FUN_0805cad8(param_1,param_2);
    iVar4 = FUN_080613f8((int)param_1,param_2,(int *)&local_118);
    if (iVar4 != 0) {
      puVar6 = FUN_08058710(local_118,(int)local_114);
      if ((puVar6 == (uint *)0x0) &&
         (puVar6 = (uint *)FUN_0805f618(local_118,local_114,1), puVar6 == (uint *)0x0)) {
        puVar6 = FUN_0805f5ec(local_118,local_114,1);
      }
      FUN_08058c28((int)puVar6);
      if ((*(byte *)((int)puVar6 + 10) >> 2 & 3) != 3) {
        *param_4 = 0;
        return;
      }
      param_3[2] = puVar6[4];
      return;
    }
    pcVar12 = "Symbol missing";
LAB_08060d45:
    FUN_08052f1c(4,pcVar12);
    break;
  case '@':
    FUN_0805fff4(param_3);
    break;
  case '{':
    FUN_08060058((int)param_1,param_2,param_3);
    break;
  case '|':
    param_3[1] = 0x14;
    break;
  case '~':
    param_3[1] = 0x1f;
  }
  return;
}



void FUN_08060d64(int param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0xffffffff;
  pcVar3 = param_2;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  (&DAT_0807f340)[param_1 * 2] = ~uVar2 - 1;
  *(char **)(&DAT_0807f344 + param_1 * 8) = param_2;
  return;
}



void FUN_08060d9c(int param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0xffffffff;
  pcVar3 = param_2;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  (&DAT_0807f4a0)[param_1 * 2] = ~uVar2 - 1;
  *(char **)(&DAT_0807f4a4 + param_1 * 8) = param_2;
  return;
}



void FUN_08060dd4(void)

{
  uint uVar1;
  
  if (DAT_08079854 == 0) {
    uVar1 = 0;
    do {
      (&DAT_0807f340)[uVar1 * 2] = 0;
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x2b);
    FUN_08060d64(4,"LAND");
    FUN_08060d64(5,"LOR");
    FUN_08060d64(6,"LEOR");
    FUN_08060d64(0xf,"ROR");
    FUN_08060d64(0x10,"ROL");
    FUN_08060d64(0x11,"SHR");
    FUN_08060d64(0x12,"SHL");
    FUN_08060d64(0x13,"AND");
    FUN_08060d64(0x15,"EOR");
    FUN_08060d64(0x14,"OR");
    FUN_08060d64(0x16,"LEFT");
    FUN_08060d64(0x17,"RIGHT");
    FUN_08060d64(0x18,"CC");
    FUN_08060d64(0x1b,"MOD");
    FUN_08060d64(0x1e,"LNOT");
    FUN_08060d64(0x1f,"NOT");
    FUN_08060d64(0x20,"LEN");
    FUN_08060d64(0x25,"CHR");
    FUN_08060d64(0x26,"STR");
    FUN_08060d64(0x27,"BASE");
    FUN_08060d64(0x28,"INDEX");
    FUN_08060d64(0x29,"DEF");
    FUN_08060d64(0x2a,"||");
    uVar1 = 0;
    do {
      (&DAT_0807f4a0)[uVar1 * 2] = 0;
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0xe);
    FUN_08060d9c(0,"PC");
    FUN_08060d9c(1,"VAR");
    FUN_08060d9c(2,"OPT");
    FUN_08060d9c(3,"TRUE");
    FUN_08060d9c(4,"FALSE");
    FUN_08060d9c(5,"CONFIG");
    FUN_08060d9c(6,"CPU");
    FUN_08060d9c(7,"ARCHITECTURE");
    FUN_08060d9c(8,"PCSTOREOFFSET");
    FUN_08060d9c(9,"REENTRANT");
    FUN_08060d9c(10,"ENDIAN");
    FUN_08060d9c(0xb,"CODESIZE");
    FUN_08060d9c(0xc,"ISA");
    FUN_08060d9c(0xd,"||");
    DAT_08079854 = 1;
  }
  return;
}



char * FUN_08061000(char *param_1)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  byte bVar4;
  byte bVar5;
  uint *puVar6;
  uint uVar7;
  char *__src;
  byte *pbVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint local_34;
  int local_2c;
  char local_24 [7];
  byte local_1d;
  uint local_1c;
  uint local_18;
  char *local_14;
  uint local_10;
  uint local_c;
  char *local_8;
  
  local_1c = 0;
  local_34 = 0;
  local_2c = 0;
  cVar1 = *param_1;
  uVar7 = local_1c;
  if (cVar1 != '*') {
    while (cVar1 != '\r') {
      if ((cVar1 == '$') && (local_2c != 0x100)) {
        local_1c = uVar7 + 1;
        if (param_1[local_1c] == '$') {
          (&DAT_0807f620)[local_34] = 0x24;
          local_1c = uVar7 + 2;
          uVar10 = local_34 + 1;
          uVar3 = local_1c;
          if (0xfe < local_34 + 1) {
            FUN_08052f1c(4,"Substituted line too long");
            DAT_08079804 = 1;
            goto LAB_080613ae;
          }
        }
        else {
          iVar9 = FUN_080613f8((int)param_1,(int *)&local_1c,(int *)&local_18);
          if (iVar9 == 0) {
            (&DAT_0807f620)[local_34] = 0x24;
            uVar10 = local_34 + 1;
            uVar3 = local_1c;
            if (0xfe < local_34 + 1) {
              FUN_08052f1c(4,"Substituted line too long");
              DAT_08079804 = 1;
              goto LAB_080613ae;
            }
          }
          else {
            puVar6 = FUN_08058710(local_18,(int)local_14);
            if (((puVar6 == (uint *)0x0) &&
                (puVar6 = (uint *)FUN_0805f618(local_18,local_14,1), puVar6 == (uint *)0x0)) ||
               ((puVar6[2] & 3) != 2)) {
              for (; uVar10 = local_34, uVar3 = local_1c, uVar7 < local_1c; uVar7 = uVar7 + 1) {
                (&DAT_0807f620)[local_34] = param_1[uVar7];
                local_34 = local_34 + 1;
                if (0xfe < local_34) {
                  FUN_08052f1c(4,"Substituted line too long");
                  DAT_08079804 = 1;
                  goto LAB_080613ae;
                }
              }
            }
            else {
              if ((DAT_080825d0 == 2) && ((puVar6[2] & 4) == 0)) {
                FUN_08052f1c(4,"No pre-declaration of substituted symbol");
              }
              local_8 = local_24;
              bVar4 = *(byte *)((int)puVar6 + 9) >> 2;
              bVar5 = bVar4 & 3;
              if ((bVar4 & 3) == 0) {
                uVar7 = puVar6[3];
                local_10 = 8;
                iVar9 = 7;
                pbVar8 = &local_1d;
                do {
                  uVar10 = uVar7 & 0xf;
                  uVar7 = uVar7 >> 4;
                  bVar4 = (byte)uVar10;
                  if (uVar10 < 10) {
                    bVar4 = bVar4 | 0x30;
                  }
                  else {
                    bVar4 = bVar4 + 0x37;
                  }
                  *pbVar8 = bVar4;
                  pbVar8 = pbVar8 + -1;
                  iVar9 = iVar9 + -1;
                } while (-1 < iVar9);
              }
              else if (bVar5 == 1) {
                if (puVar6[3] == 0) {
                  __src = "F";
                }
                else {
                  __src = "T";
                }
                strcpy(local_24,__src);
                local_10 = 1;
              }
              else if (bVar5 == 2) {
                puVar6 = (uint *)puVar6[3];
                local_10 = *puVar6;
                local_c = puVar6[1];
                local_8 = (char *)puVar6[2];
              }
              if ((local_10 != 0) && (uVar7 = 0, local_10 != 0)) {
                do {
                  (&DAT_0807f620)[local_34] = local_8[uVar7];
                  local_34 = local_34 + 1;
                  if (0xfe < local_34) {
                    FUN_08052f1c(4,"Substituted line too long");
                    DAT_08079804 = 1;
                    goto LAB_080613ae;
                  }
                  uVar7 = uVar7 + 1;
                } while (uVar7 < local_10);
              }
              uVar10 = local_34;
              uVar3 = local_1c;
              if (param_1[local_1c] == '.') {
                uVar3 = local_1c + 1;
              }
            }
          }
        }
      }
      else {
        iVar9 = (int)cVar1;
        if (iVar9 == local_2c) {
          local_2c = 0;
          iVar2 = local_2c;
        }
        else {
          iVar2 = local_2c;
          if ((((local_2c == 0) && (iVar2 = iVar9, cVar1 != '\'')) && (cVar1 != '\"')) &&
             (iVar2 = local_2c, cVar1 == ';')) {
            local_2c = 0x100;
            iVar2 = local_2c;
          }
        }
        local_2c = iVar2;
        (&DAT_0807f620)[local_34] = cVar1;
        local_34 = local_34 + 1;
        local_1c = uVar7 + 1;
        if (0xfe < local_34) {
          FUN_08052f1c(4,"Substituted line too long");
          DAT_08079804 = 1;
          goto LAB_080613ae;
        }
        uVar10 = local_34;
        uVar3 = local_1c;
        if (cVar1 == '|') {
          do {
            cVar1 = param_1[local_1c];
            uVar7 = local_1c + 1;
            (&DAT_0807f620)[local_34] = cVar1;
            uVar11 = local_34 + 1;
            if (0xfe < uVar11) {
              local_1c = uVar7;
              FUN_08052f1c(4,"Substituted line too long");
              DAT_08079804 = 1;
              goto LAB_080613ae;
            }
            uVar10 = uVar11;
            uVar3 = uVar7;
          } while ((cVar1 != '|') &&
                  (uVar10 = local_34, local_34 = uVar11, uVar3 = local_1c, local_1c = uVar7,
                  cVar1 != '\r'));
        }
      }
      local_1c = uVar3;
      local_34 = uVar10;
      uVar7 = local_1c;
      cVar1 = param_1[local_1c];
    }
    (&DAT_0807f620)[local_34] = 0xd;
LAB_080613ae:
    param_1 = &DAT_0807f620;
  }
  return param_1;
}



undefined4 FUN_080613bc(char *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  for (; (byte)(*param_1 - 0x1fU) < 2; param_1 = param_1 + 1) {
  }
  iVar1 = isalpha((int)*param_1);
  if (((iVar1 == 0) && (*param_1 != '_')) && (*param_1 != '|')) {
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}



undefined4 FUN_080613f8(int param_1,int *param_2,int *param_3)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar3 = (char *)(param_1 + *param_2);
  cVar1 = *pcVar3;
  iVar2 = isalpha((int)cVar1);
  if ((iVar2 == 0) && (cVar1 != '_')) {
    if (((cVar1 != '|') || (pcVar3[1] == '|')) || (pcVar3[1] == '\r')) {
      return 0;
    }
    pcVar3 = pcVar3 + 1;
    cVar1 = *pcVar3;
    if (cVar1 != '|') {
      do {
        if (cVar1 == '\r') break;
        pcVar3 = pcVar3 + 1;
        cVar1 = *pcVar3;
      } while (cVar1 != '|');
      if (cVar1 != '|') {
        return 0;
      }
    }
    *param_3 = (int)(pcVar3 + (1 - param_1)) - (*param_2 + 2);
    param_3[1] = param_1 + *param_2 + 1;
    *param_2 = (int)(pcVar3 + (1 - param_1));
  }
  else {
    do {
      do {
        pcVar3 = pcVar3 + 1;
        iVar2 = isalnum((int)*pcVar3);
      } while (iVar2 != 0);
    } while (*pcVar3 == '_');
    iVar2 = *param_2;
    param_3[1] = param_1 + iVar2;
    *param_3 = (int)pcVar3 - (param_1 + iVar2);
    *param_2 = (int)pcVar3 - param_1;
  }
  return 1;
}



undefined4 FUN_080614c0(int param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *param_2;
  cVar1 = *(char *)(iVar2 + param_1);
  if (cVar1 == '[') {
LAB_080614e4:
    FUN_08052f34(4,iVar2,"Unexpected \'%c\'");
  }
  else {
    if (cVar1 < '\\') {
      if (cVar1 == '#') goto LAB_080614e4;
    }
    else if (cVar1 == '{') goto LAB_080614e4;
    FUN_08052f34(4,iVar2,"Bad symbol");
  }
  return 0;
}



undefined4 FUN_0806150c(int param_1,int *param_2,int *param_3)

{
  undefined4 uVar1;
  char *pcVar2;
  
  pcVar2 = (char *)(*param_2 + param_1);
  param_3[1] = (int)pcVar2;
  if ((&DAT_080849c0)[*pcVar2] == 0) {
    do {
      pcVar2 = pcVar2 + 1;
    } while ((&DAT_080849c0)[*pcVar2] == 0);
    *param_3 = (int)pcVar2 - param_3[1];
    for (; (byte)(*pcVar2 - 0x1fU) < 2; pcVar2 = pcVar2 + 1) {
    }
    *param_2 = (int)(pcVar2 + (*param_2 - param_3[1]));
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_08061560(void)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    (&DAT_080849c0)[uVar1] = 0;
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x100);
  DAT_080849c0 = 1;
  _DAT_080849f4 = 1;
  _DAT_08084a40 = 1;
  _DAT_08084a3c = 1;
  _DAT_08084aac = 1;
  return;
}



void FUN_080615c0(void)

{
  if (DAT_08084dc8 != (FILE *)0x0) {
    fclose(DAT_08084dc8);
  }
  if (DAT_08082588 != (FILE *)0x0) {
    fclose(DAT_08082588);
  }
  FUN_0805ef10();
  return;
}



void FUN_080615f0(int param_1)

{
                    // WARNING: Subroutine does not return
  longjmp((__jmp_buf_tag *)&DAT_0807f820,param_1);
}



void FUN_08061600(undefined4 param_1)

{
  DAT_08084dc8 = param_1;
  return;
}



bool FUN_08061610(undefined4 param_1,char *param_2,char *param_3)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  size_t __n;
  byte *pbVar5;
  uint local_118;
  int local_114 [4];
  char local_104 [256];
  
  pcVar2 = strchr(param_2,0x2e);
  if (pcVar2 == (char *)0x0) {
LAB_08061641:
    uVar4 = 0xffffffff;
    pcVar2 = param_2;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    __n = ~uVar4 - 1;
  }
  else {
    iVar3 = isalnum((int)pcVar2[1]);
    if (iVar3 == 0) goto LAB_08061641;
    __n = (int)pcVar2 - (int)param_2;
  }
  local_118 = 0;
  local_114[0] = 0;
  local_114[2] = 0;
  local_114[1] = 0;
  local_114[3] = 0;
  memcpy(local_104,param_2,__n);
  local_104[__n] = '\0';
  if (*param_3 == '?') {
    if (__n == 0) goto LAB_08061718;
    pbVar5 = (byte *)0x0;
  }
  else if (*param_3 == '#') {
    pbVar5 = (byte *)(param_3 + 1);
  }
  else {
    strcpy(local_104 + __n,param_3 + 1);
    iVar3 = -1;
    pcVar2 = local_104;
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    if (iVar3 == -2) goto LAB_08061718;
    pbVar5 = (byte *)0x0;
  }
  local_118 = FUN_0804f0e4(local_104,pbVar5,local_114);
LAB_08061718:
  return 2 < local_118;
}



bool FUN_08061734(undefined4 *param_1,char *param_2,char *param_3)

{
  int iVar1;
  char *pcVar2;
  char *pcVar3;
  bool bVar4;
  
  iVar1 = 5;
  bVar4 = true;
  pcVar2 = param_2;
  pcVar3 = ".etc";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    bVar4 = *pcVar2 == *pcVar3;
    pcVar2 = pcVar2 + 1;
    pcVar3 = pcVar3 + 1;
  } while (bVar4);
  if (bVar4) {
    *param_1 = param_3;
  }
  else {
    iVar1 = 5;
    bVar4 = true;
    pcVar2 = param_2;
    pcVar3 = "-cpu";
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar4 = *pcVar2 == *pcVar3;
      pcVar2 = pcVar2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar4);
    if (bVar4) {
      param_1[1] = param_3;
    }
    else {
      iVar1 = 6;
      bVar4 = true;
      pcVar2 = param_2;
      pcVar3 = "-arch";
      do {
        if (iVar1 == 0) break;
        iVar1 = iVar1 + -1;
        bVar4 = *pcVar2 == *pcVar3;
        pcVar2 = pcVar2 + 1;
        pcVar3 = pcVar3 + 1;
      } while (bVar4);
      if (bVar4) {
        param_1[2] = param_3;
      }
      else {
        iVar1 = 10;
        bVar4 = true;
        pcVar2 = param_2;
        pcVar3 = ".hasthumb";
        do {
          if (iVar1 == 0) break;
          iVar1 = iVar1 + -1;
          bVar4 = *pcVar2 == *pcVar3;
          pcVar2 = pcVar2 + 1;
          pcVar3 = pcVar3 + 1;
        } while (bVar4);
        if ((!bVar4) && (iVar1 = strncmp(param_2,"-I.",3), iVar1 != 0)) {
          bVar4 = FUN_08061610(param_1,param_2,param_3);
          return bVar4;
        }
      }
    }
  }
  return false;
}



undefined4 FUN_080617e8(int param_1,char *param_2)

{
  int iVar1;
  
  if ((*(size_t *)(param_1 + 0x10) != 0) &&
     (iVar1 = strncmp(param_2,*(char **)(param_1 + 0xc),*(size_t *)(param_1 + 0x10)), iVar1 != 0)) {
    return 0;
  }
  *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + 1;
  return 0;
}



undefined4 FUN_08061810(int param_1,char *param_2,undefined4 param_3)

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



uint FUN_08061854(int *param_1,int *param_2)

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



int FUN_080618a0(int *param_1,char *param_2,undefined *param_3,undefined4 param_4)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int *local_20;
  undefined *local_1c;
  undefined4 local_18;
  char *local_14;
  int local_10;
  size_t local_c;
  void *local_8;
  
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
  local_c = 0;
  FUN_08070794(param_1,FUN_080617e8,&local_20);
  if (local_c == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = 0;
    local_8 = malloc(local_c * 8);
    local_c = 0;
    FUN_08070794(param_1,FUN_08061810,&local_20);
    qsort(local_8,local_c,8,FUN_08061854);
    uVar3 = 0;
    if (local_c != 0) {
      do {
        iVar2 = (*(code *)param_3)(param_4,*(undefined4 *)((int)local_8 + uVar3 * 8),
                                   *(undefined4 *)((int)local_8 + uVar3 * 8 + 4),0);
        if (iVar2 != 0) break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < local_c);
    }
    free(local_8);
  }
  return iVar2;
}



void FUN_0806196c(void)

{
  (*DAT_08084dc0)(DAT_08084dc4,0,0);
  return;
}



bool FUN_08061984(char *param_1)

{
  int iVar1;
  int local_11c [5];
  byte local_105;
  byte local_104 [256];
  
  FUN_0806d7a4(param_1,"",local_11c);
  FUN_0806d81c(local_11c,0,local_104,0xff);
  iVar1 = FUN_08070ba0((char *)(local_104 + local_105),"tasm",4);
  return iVar1 == 0;
}



bool FUN_080619e4(int param_1,undefined4 *param_2,int *param_3)

{
  char cVar1;
  void *pvVar2;
  bool bVar3;
  undefined3 extraout_var;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  undefined4 *puVar7;
  undefined1 *puVar8;
  char *pcVar9;
  undefined1 *local_14c;
  int *local_144;
  undefined1 *local_140;
  int local_13c;
  uint local_134;
  undefined1 local_130 [256];
  undefined4 local_30;
  char *local_2c;
  int local_28;
  undefined4 local_24;
  int local_20;
  char *local_1c;
  char *local_18;
  int local_14;
  int local_10;
  void *local_c;
  undefined4 local_8;
  
  bVar3 = FUN_08061984((char *)*param_2);
  if (CONCAT31(extraout_var,bVar3) == 0) {
    builtin_strncpy(s_armasm_08079858,"armasm",7);
  }
  else {
    builtin_strncpy(s_armasm_08079858,"tasm",4);
    s_armasm_08079858._4_2_ = s_armasm_08079858._4_2_ & 0xff00;
  }
  FUN_08055260();
  FUN_0805eee8();
  FUN_0806341c();
  FUN_0804e77c();
  FUN_08055700();
  FUN_08061560();
  FUN_0805f3f4();
  local_134 = 1;
  local_20 = 0;
  local_1c = (char *)0x0;
  local_18 = (char *)0x0;
  FUN_080508b4();
  iVar4 = FUN_08070794(param_3,FUN_08061734,&local_20);
  if ((iVar4 == 0) && (iVar4 = FUN_080618a0(param_3,"-I.",FUN_08061610,&local_20), iVar4 == 0)) {
    local_14 = 0;
    local_c = (void *)0x0;
    local_10 = 0;
    local_8 = 0;
    if (local_1c == (char *)0x0) {
LAB_08061b00:
      pcVar9 = "-arch";
      pcVar6 = local_18;
    }
    else {
      iVar4 = 9;
      bVar3 = true;
      pcVar6 = local_1c;
      pcVar9 = "#generic";
      do {
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        bVar3 = *pcVar6 == *pcVar9;
        pcVar6 = pcVar6 + 1;
        pcVar9 = pcVar9 + 1;
      } while (bVar3);
      if (bVar3) goto LAB_08061b00;
      pcVar9 = "-cpu";
      pcVar6 = local_1c;
    }
    uVar5 = FUN_0804f0e4(pcVar9,(byte *)(pcVar6 + 1),&local_14);
    if (uVar5 < 3) {
      if (local_20 != 0) {
        local_2c = "-vias";
        local_28 = local_20 + 1;
        local_24 = 0;
        local_134 = FUN_08050934(3,&local_30,&local_14);
      }
      goto LAB_08061b5e;
    }
  }
  local_134 = 0;
LAB_08061b5e:
  local_14 = 10;
  local_c = malloc(0x78);
  local_10 = 0;
  local_8 = 0;
  if (local_134 == 1) {
    local_134 = FUN_08050934(param_1,param_2,&local_14);
  }
  pvVar2 = local_c;
  local_14c = (undefined1 *)0x0;
  if (0 < local_10) {
    local_144 = (int *)((int)local_c + 8);
    puVar7 = (undefined4 *)((int)local_c + 4);
    iVar4 = 0;
    do {
      FUN_08070318(param_3,*(byte **)((int)pvVar2 + iVar4),*local_144,(char *)*puVar7);
      local_144 = local_144 + 3;
      puVar7 = puVar7 + 3;
      iVar4 = iVar4 + 0xc;
      local_14c = (undefined1 *)((int)local_14c + 1);
    } while ((int)local_14c < local_10);
  }
  if (DAT_08080148 == 0) {
    if (DAT_08080144 != 0) {
      local_13c = 1;
      local_140 = (undefined1 *)0x0;
      local_14c = local_130;
      if ((char *)*param_2 != (char *)0x0) {
        uVar5 = 0xffffffff;
        pcVar6 = (char *)*param_2;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar1 != '\0');
        local_13c = ~uVar5 + 1;
      }
      uVar5 = FUN_08063068(param_3,(int)(local_14c + local_13c),0xfeU - local_13c);
      if (0xfeU - local_13c < uVar5) {
        local_14c = malloc(uVar5 + 2 + local_13c);
        uVar5 = FUN_08063068(param_3,(int)(local_14c + local_13c),uVar5 + 2);
        local_140 = local_14c;
      }
      *local_14c = 0x5b;
      if ((char *)*param_2 != (char *)0x0) {
        strcpy(local_14c + 1,(char *)*param_2);
        local_14c[local_13c + -1] = 0x20;
      }
      puVar8 = local_14c + uVar5 + local_13c;
      puVar8[-1] = 0x5d;
      *puVar8 = 10;
      puVar8[1] = 0;
      FUN_08052f68(local_14c,local_14c);
      if (local_140 != (undefined1 *)0x0) {
        free(local_140);
      }
    }
  }
  else {
    FUN_080709f8(param_3);
    local_134 = 2;
  }
  local_14c = (undefined1 *)0x0;
  if (0 < local_10) {
    iVar4 = 0;
    do {
      free(*(void **)((int)local_c + iVar4));
      free(*(void **)((int)local_c + iVar4 + 4));
      iVar4 = iVar4 + 0xc;
      local_14c = (undefined1 *)((int)local_14c + 1);
    } while ((int)local_14c < local_10);
  }
  if ((local_134 == 1) &&
     (local_134 = FUN_08050d10(param_3,(undefined4 *)&DAT_0807f720), local_134 == 1)) {
    FUN_08054528();
    DAT_0807ff0c = 0;
    FUN_0804d3d4(&DAT_0807f720);
    bVar3 = DAT_08080168 != 0;
  }
  else {
    bVar3 = local_134 == 0;
  }
  return bVar3;
}



int FUN_08061e04(int param_1,undefined4 *param_2,int *param_3,undefined4 param_4,undefined4 param_5)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  
  DAT_08084dc0 = param_4;
  DAT_08084dc4 = param_5;
  DAT_08084dc8 = 0;
  DAT_08082588 = 0;
  DAT_08082580 = 0;
  DAT_0807f8bc = 0;
  iVar2 = __sigsetjmp(&DAT_0807f820,0);
  if (iVar2 == 0) {
    bVar1 = FUN_080619e4(param_1,param_2,param_3);
    iVar2 = CONCAT31(extraout_var,bVar1);
  }
  if (DAT_0807f8bc == 0) {
    DAT_0807f8bc = 1;
    if (iVar2 < 0) {
      FUN_0804d31c(1);
    }
    FUN_0804e7e8();
    FUN_080521e8();
    FUN_080615c0();
  }
  return iVar2;
}



undefined4 FUN_08061ea4(void)

{
  if (DAT_08079864 != (undefined4 *)0x0) {
    FUN_080700f8(DAT_08079864);
    DAT_08079864 = (undefined4 *)0x0;
  }
  return 0;
}



char * FUN_08061ec4(void)

{
  return "armasm";
}



int FUN_08061ed0(int *param_1,char *param_2)

{
  int iVar1;
  
  iVar1 = FUN_080708e8(param_1,param_2);
  if (iVar1 == 0) {
    FUN_080633d4(param_1);
  }
  return iVar1;
}



undefined ** FUN_08061efc(void)

{
  if (DAT_08079864 != (undefined4 *)0x0) {
    FUN_080700f8(DAT_08079864);
    DAT_08079864 = (undefined4 *)0x0;
  }
  return &PTR_FUN_08075760;
}



int FUN_08061f20(int *param_1)

{
  int iVar1;
  undefined **ppuVar2;
  
  ppuVar2 = &PTR_s__hasthumb_08075788;
  do {
    iVar1 = FUN_08070394(param_1,*ppuVar2,ppuVar2[1]);
    if (iVar1 != 0) {
      return iVar1;
    }
    ppuVar2 = ppuVar2 + 2;
  } while (*ppuVar2 != (undefined *)0x0);
  FUN_080633d4(param_1);
  if (DAT_08079864 != (undefined4 *)0x0) {
    FUN_080700f8(DAT_08079864);
  }
  DAT_08079864 = FUN_08070528(param_1);
  return 0;
}



void FUN_08061f80(uint *param_1,uint *param_2)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  
  puVar3 = param_2;
  uVar2 = *param_2;
  while( true ) {
    if (uVar2 == 0) {
      *param_1 = *param_2;
      *param_2 = (uint)param_1;
      return;
    }
    puVar1 = (uint *)*puVar3;
    if (((puVar1[1] == param_1[1]) && (puVar1[3] == param_1[3])) && (puVar1[2] != param_1[2]))
    break;
    uVar2 = *puVar1;
    puVar3 = puVar1;
  }
  FUN_0805ee14(param_1);
  uVar2 = *(uint *)*puVar3;
  FUN_0805ee14((uint *)*puVar3);
  *puVar3 = uVar2;
  return;
}



void FUN_08061fd8(uint *param_1,uint param_2,uint param_3,uint param_4)

{
  uint *puVar1;
  
  puVar1 = FUN_0805eddc(0x10);
  *puVar1 = 0;
  puVar1[1] = param_2;
  puVar1[2] = param_3;
  puVar1[3] = param_4;
  FUN_08061f80(puVar1,param_1);
  return;
}



void FUN_08062010(undefined4 *param_1)

{
  for (; param_1 != (undefined4 *)0x0; param_1 = (undefined4 *)*param_1) {
    *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) ^ 1;
  }
  return;
}



undefined4 FUN_0806202c(undefined4 *param_1)

{
  while( true ) {
    if (param_1 == (undefined4 *)0x0) {
      return 0;
    }
    if (param_1[1] == 1) break;
    param_1 = (undefined4 *)*param_1;
  }
  return 1;
}



int FUN_08062050(undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = 0;
  for (; param_1 != (undefined4 *)0x0; param_1 = (undefined4 *)*param_1) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}



void FUN_0806206c(uint *param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = *param_2;
  while (iVar1 != 0) {
    iVar1 = *(int *)*param_2;
    *(int *)*param_2 = 0;
    FUN_08061f80((uint *)*param_2,param_1);
    *param_2 = iVar1;
  }
  return;
}



void FUN_080620a4(undefined4 *param_1,uint param_2)

{
  uint *puVar1;
  uint *puVar2;
  uint uVar3;
  
  puVar2 = (uint *)*param_1;
  do {
    if (puVar2 == (uint *)0x0) {
      *param_1 = 0;
      return;
    }
    puVar1 = (uint *)*puVar2;
    if (DAT_08082654 != 0) {
      FUN_08052f1c(5,"Internal Error : a.out format not fully supported");
      return;
    }
    if (puVar2[1] == 1) {
      if (puVar2[2] != 1) goto LAB_08062115;
      uVar3 = puVar2[3] & 0xffffff | 0x8a000000;
LAB_08062107:
      FUN_080514cc(param_2,uVar3,0);
    }
    else {
      if (puVar2[2] == 1) {
        uVar3 = puVar2[3] - 1 & 0xffffff | 0x82000000;
        goto LAB_08062107;
      }
LAB_08062115:
      FUN_08052f1c(4,"AOF does not support subtractive relocations");
    }
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  } while( true );
}



void FUN_0806215c(undefined4 *param_1)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar2 = (uint *)*param_1;
  while (puVar2 != (uint *)0x0) {
    puVar1 = (uint *)*puVar2;
    FUN_0805ee14(puVar2);
    puVar2 = puVar1;
  }
  *param_1 = 0;
  return;
}



void FUN_08062190(char *param_1)

{
  vfprintf(DAT_0807f8c0,param_1,&stack0x00000008);
  return;
}



void FUN_080621a8(int param_1)

{
  switch(*(undefined2 *)(param_1 + 0xc)) {
  case 0:
  case 1:
    break;
  case 2:
    break;
  default:
    break;
  case 4:
  }
  if ((*(int *)(param_1 + 4) == 0) || (*(int *)(param_1 + 0x10) == -1)) {
    FUN_08062190("%s%s\n");
  }
  else if (*(short *)(param_1 + 0xe) == -1) {
    FUN_08062190("\"%s\", line %u: %s%s\n");
  }
  else {
    FUN_08062190("\"%s\", line %u (column %u): %s%s\n");
  }
  return;
}



undefined4 FUN_0806223c(FILE *param_1,int param_2,undefined4 *param_3)

{
  if (param_2 == 1) {
    if (param_1 != (FILE *)0x0) {
      DAT_0807f8c0 = param_1;
    }
    FUN_080621a8((int)param_3);
  }
  else if ((param_2 != 0) && (param_2 == 2)) {
    fprintf(param_1,"%s:\t%s\n",(char *)*param_3,(char *)param_3[1]);
  }
  return 0;
}



undefined4 FUN_0806227c(void)

{
  return 0;
}



undefined4 FUN_08062284(void)

{
  return 1;
}



int FUN_08062290(undefined4 param_1,undefined4 *param_2)

{
  bool bVar1;
  undefined **ppuVar2;
  int *piVar3;
  undefined3 extraout_var;
  int iVar4;
  
  DAT_0807f8c0 = stderr;
  ppuVar2 = FUN_08061efc();
  piVar3 = (int *)(*(code *)ppuVar2[2])();
  bVar1 = FUN_08061984((char *)*param_2);
  if ((CONCAT31(extraout_var,bVar1) != 0) &&
     (iVar4 = FUN_08070394(piVar3,(byte *)".codesize","=-16"), iVar4 != 0)) {
    return iVar4;
  }
  (*(code *)ppuVar2[5])(piVar3);
  (*(code *)ppuVar2[4])(piVar3,&DAT_08075af3);
  iVar4 = (*(code *)ppuVar2[1])(param_1,param_2,piVar3,FUN_0806223c,0);
  (*(code *)ppuVar2[3])(piVar3);
  (*(code *)*ppuVar2)(ppuVar2);
  return iVar4;
}



bool FUN_08062320(int *param_1,byte *param_2,int param_3,char *param_4)

{
  char *pcVar1;
  int iVar2;
  bool bVar3;
  
  pcVar1 = (char *)FUN_080702e4(param_1,param_2);
  bVar3 = false;
  if ((pcVar1 != (char *)0x0) && (param_3 == *pcVar1)) {
    iVar2 = strcmp(param_4,pcVar1 + 1);
    bVar3 = iVar2 == 0;
  }
  return bVar3;
}



bool FUN_0806235c(int *param_1,byte *param_2,char *param_3)

{
  char *__s2;
  int iVar1;
  bool bVar2;
  
  __s2 = (char *)FUN_080702e4(param_1,param_2);
  bVar2 = false;
  if (__s2 != (char *)0x0) {
    iVar1 = strcmp(param_3,__s2);
    bVar2 = iVar1 == 0;
  }
  return bVar2;
}



undefined4 FUN_0806238c(int *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  
  bVar1 = FUN_0806235c(param_1,(byte *)"-arch","#4T");
  if (((CONCAT31(extraout_var,bVar1) == 0) &&
      (bVar1 = FUN_0806235c(param_1,(byte *)"-arch","#4TxM"), CONCAT31(extraout_var_00,bVar1) == 0))
     && (bVar1 = FUN_0806235c(param_1,(byte *)"-arch","#5T"), CONCAT31(extraout_var_01,bVar1) == 0))
  {
    return 0;
  }
  return 1;
}



bool FUN_080623e8(int *param_1,char *param_2)

{
  undefined3 extraout_var;
  int iVar1;
  char *pcVar2;
  bool bVar3;
  byte *pbVar4;
  char *pcVar5;
  
  iVar1 = 10;
  bVar3 = true;
  pcVar5 = param_2;
  pcVar2 = ".hasthumb";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    bVar3 = *pcVar5 == *pcVar2;
    pcVar5 = pcVar5 + 1;
    pcVar2 = pcVar2 + 1;
  } while (bVar3);
  if (bVar3) {
    return true;
  }
  iVar1 = 10;
  bVar3 = true;
  pcVar5 = param_2;
  pcVar2 = ".codesize";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    bVar3 = *pcVar5 == *pcVar2;
    pcVar5 = pcVar5 + 1;
    pcVar2 = pcVar2 + 1;
  } while (bVar3);
  if (!bVar3) {
    iVar1 = 6;
    bVar3 = true;
    pcVar5 = param_2;
    pcVar2 = "-arch";
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar3 = *pcVar5 == *pcVar2;
      pcVar5 = pcVar5 + 1;
      pcVar2 = pcVar2 + 1;
    } while (bVar3);
    if (bVar3) {
      bVar3 = FUN_0806235c(param_1,&DAT_08075b7a,"#generic");
      iVar1 = CONCAT31(extraout_var,bVar3);
      goto LAB_08062461;
    }
    iVar1 = 0xc;
    bVar3 = true;
    pcVar5 = param_2;
    pcVar2 = "-apcs.32bit";
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar3 = *pcVar5 == *pcVar2;
      pcVar5 = pcVar5 + 1;
      pcVar2 = pcVar2 + 1;
    } while (bVar3);
    if (!bVar3) {
      iVar1 = 6;
      bVar3 = true;
      pcVar5 = param_2;
      pcVar2 = ".keep";
      do {
        if (iVar1 == 0) break;
        iVar1 = iVar1 + -1;
        bVar3 = *pcVar5 == *pcVar2;
        pcVar5 = pcVar5 + 1;
        pcVar2 = pcVar2 + 1;
      } while (bVar3);
      if (bVar3) {
        pcVar5 = "-g";
        pbVar4 = &DAT_08075b94;
      }
      else {
        iVar1 = 9;
        bVar3 = true;
        pcVar5 = param_2;
        pcVar2 = "-apcs.fp";
        do {
          if (iVar1 == 0) break;
          iVar1 = iVar1 + -1;
          bVar3 = *pcVar5 == *pcVar2;
          pcVar5 = pcVar5 + 1;
          pcVar2 = pcVar2 + 1;
        } while (bVar3);
        if (!bVar3) {
          iVar1 = 0xb;
          bVar3 = true;
          pcVar5 = param_2;
          pcVar2 = "-apcs.swst";
          do {
            if (iVar1 == 0) break;
            iVar1 = iVar1 + -1;
            bVar3 = *pcVar5 == *pcVar2;
            pcVar5 = pcVar5 + 1;
            pcVar2 = pcVar2 + 1;
          } while (bVar3);
          if (!bVar3) {
            iVar1 = 10;
            bVar3 = true;
            pcVar5 = param_2;
            pcVar2 = "-apcs.fpr";
            do {
              if (iVar1 == 0) break;
              iVar1 = iVar1 + -1;
              bVar3 = *pcVar5 == *pcVar2;
              pcVar5 = pcVar5 + 1;
              pcVar2 = pcVar2 + 1;
            } while (bVar3);
            if (!bVar3) {
              iVar1 = 0xc;
              bVar3 = true;
              pcVar5 = "-apcs.inter";
              do {
                if (iVar1 == 0) break;
                iVar1 = iVar1 + -1;
                bVar3 = *param_2 == *pcVar5;
                param_2 = param_2 + 1;
                pcVar5 = pcVar5 + 1;
              } while (bVar3);
              if (!bVar3) {
                return false;
              }
            }
          }
        }
        pcVar5 = "#none";
        pbVar4 = &DAT_08075bcb;
      }
      bVar3 = FUN_0806235c(param_1,pbVar4,pcVar5);
      return bVar3;
    }
  }
  iVar1 = FUN_0806238c(param_1);
LAB_08062461:
  return iVar1 == 0;
}



undefined4 FUN_080624fc(int param_1)

{
  return *(undefined4 *)(param_1 + 0x14);
}



undefined4 FUN_08062508(int *param_1,char *param_2)

{
  if (*param_2 != '*') {
    *param_1 = *param_1 + 1;
  }
  return 0;
}



int FUN_0806251c(int *param_1,char *param_2)

{
  undefined3 extraout_var;
  int iVar1;
  char *pcVar2;
  char *pcVar3;
  bool bVar4;
  int local_90;
  int local_8c [17];
  int local_48 [17];
  
  iVar1 = 10;
  bVar4 = true;
  pcVar2 = param_2;
  pcVar3 = "-regnames";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    bVar4 = *pcVar2 == *pcVar3;
    pcVar2 = pcVar2 + 1;
    pcVar3 = pcVar3 + 1;
  } while (bVar4);
  if (bVar4) {
    bVar4 = FUN_0806235c(param_1,&DAT_08075bcb,"#none");
    if (CONCAT31(extraout_var,bVar4) == 0) {
      local_90 = 3;
    }
    else {
      local_90 = 2;
    }
  }
  else {
    iVar1 = 5;
    bVar4 = true;
    pcVar2 = param_2;
    pcVar3 = "-cpu";
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar4 = *pcVar2 == *pcVar3;
      pcVar2 = pcVar2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar4);
    if (bVar4) {
      local_90 = 1;
      FUN_0804ea9c(FUN_08062508,&local_90);
    }
    else {
      iVar1 = 6;
      bVar4 = true;
      pcVar2 = param_2;
      pcVar3 = "-arch";
      do {
        if (iVar1 == 0) break;
        iVar1 = iVar1 + -1;
        bVar4 = *pcVar2 == *pcVar3;
        pcVar2 = pcVar2 + 1;
        pcVar3 = pcVar3 + 1;
      } while (bVar4);
      if (bVar4) {
        local_48[0] = 0;
        FUN_0804ea9c(FUN_0804eae0,local_48);
        local_90 = local_48[0];
      }
      else {
        iVar1 = 5;
        bVar4 = true;
        pcVar2 = "-fpu";
        do {
          if (iVar1 == 0) break;
          iVar1 = iVar1 + -1;
          bVar4 = *param_2 == *pcVar2;
          param_2 = param_2 + 1;
          pcVar2 = pcVar2 + 1;
        } while (bVar4);
        if (bVar4) {
          local_8c[0] = 0;
          FUN_0804eb34(local_8c);
          local_90 = local_8c[0];
        }
        else {
          local_90 = -1;
        }
      }
    }
  }
  return local_90;
}



undefined4 FUN_0806262c(undefined4 *param_1,char *param_2)

{
  undefined4 uVar1;
  undefined1 local_24;
  char local_23 [31];
  
  if (*param_2 == '*') {
    uVar1 = 0;
  }
  else {
    local_24 = 0x23;
    strcpy(local_23,param_2);
    uVar1 = (*(code *)*param_1)(param_1[1],&DAT_08075b7a,&local_24);
  }
  return uVar1;
}



int FUN_08062668(int *param_1,char *param_2,undefined *param_3,undefined4 param_4)

{
  undefined *puVar1;
  undefined3 extraout_var;
  int iVar2;
  int iVar3;
  uint uVar4;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  int local_98;
  undefined *local_94;
  undefined4 local_90;
  int local_8c;
  undefined4 local_88 [16];
  int local_48;
  undefined4 local_44 [16];
  
  local_98 = 0;
  iVar3 = 10;
  bVar7 = true;
  pcVar5 = param_2;
  pcVar6 = "-regnames";
  do {
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    bVar7 = *pcVar5 == *pcVar6;
    pcVar5 = pcVar5 + 1;
    pcVar6 = pcVar6 + 1;
  } while (bVar7);
  if (bVar7) {
    bVar7 = FUN_0806235c(param_1,&DAT_08075bcb,"#none");
    uVar4 = (uint)(CONCAT31(extraout_var,bVar7) != 0);
    puVar1 = (&PTR_s__callstd_08075be0)[uVar4];
    while ((puVar1 != (undefined *)0x0 &&
           (local_98 = (*(code *)param_3)(param_4,param_2,(&PTR_s__callstd_08075be0)[uVar4]),
           local_98 == 0))) {
      uVar4 = uVar4 + 1;
      puVar1 = (&PTR_s__callstd_08075be0)[uVar4];
    }
  }
  else {
    iVar3 = 5;
    bVar7 = true;
    pcVar5 = param_2;
    pcVar6 = "-cpu";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar7 = *pcVar5 == *pcVar6;
      pcVar5 = pcVar5 + 1;
      pcVar6 = pcVar6 + 1;
    } while (bVar7);
    if (bVar7) {
      local_90 = param_4;
      local_94 = param_3;
      (*(code *)param_3)(param_4,param_2,"#generic");
      local_98 = FUN_0804ea9c(FUN_0806262c,&local_94);
    }
  }
  iVar3 = 6;
  bVar7 = true;
  pcVar5 = param_2;
  pcVar6 = "-arch";
  do {
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    bVar7 = *pcVar5 == *pcVar6;
    pcVar5 = pcVar5 + 1;
    pcVar6 = pcVar6 + 1;
  } while (bVar7);
  if (bVar7) {
    local_48 = 0;
    FUN_0804ea9c(FUN_0804eae0,&local_48);
    iVar3 = 0;
    if (0 < local_48) {
      do {
        iVar2 = (*(code *)param_3)(param_4,param_2,local_44[iVar3]);
        if (iVar2 != 0) {
          return iVar2;
        }
        iVar3 = iVar3 + 1;
        local_98 = 0;
      } while (iVar3 < local_48);
    }
  }
  else {
    iVar3 = 5;
    bVar7 = true;
    pcVar5 = param_2;
    pcVar6 = "-fpu";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar7 = *pcVar5 == *pcVar6;
      pcVar5 = pcVar5 + 1;
      pcVar6 = pcVar6 + 1;
    } while (bVar7);
    if (bVar7) {
      local_8c = 0;
      FUN_0804eb34(&local_8c);
      iVar3 = 0;
      if (0 < local_8c) {
        do {
          iVar2 = (*(code *)param_3)(param_4,param_2,local_88[iVar3]);
          if (iVar2 != 0) {
            return iVar2;
          }
          iVar3 = iVar3 + 1;
          local_98 = 0;
        } while (iVar3 < local_8c);
      }
    }
    else {
      local_98 = -1;
    }
  }
  return local_98;
}



undefined4 FUN_0806282c(int *param_1,byte *param_2,char *param_3)

{
  char *__s1;
  int iVar1;
  
  __s1 = (char *)FUN_080702e4(param_1,param_2);
  if ((__s1 != (char *)0x0) && (iVar1 = strcmp(__s1,param_3), iVar1 == 0)) {
    return 0;
  }
  FUN_08070394(param_1,param_2,param_3);
  return 1;
}



uint FUN_08062878(int *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar1 = FUN_0806282c(param_1,(byte *)"-apcs.32bit","#/32");
  uVar2 = FUN_0806282c(param_1,&DAT_08075b9b,"#/nofp");
  uVar3 = FUN_0806282c(param_1,(byte *)".codesize","=-16");
  return uVar1 | uVar2 | uVar3;
}



undefined4 FUN_080628c0(int *param_1,byte *param_2,int param_3,byte *param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  int iVar2;
  char *pcVar3;
  uint uVar4;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  int iVar5;
  byte *pbVar6;
  byte *pbVar7;
  bool bVar8;
  undefined8 uVar9;
  
  bVar1 = FUN_080623e8(param_1,(char *)param_2);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    return 0;
  }
  if ((((param_3 != 0x3d) && (param_3 != 0x23)) && (param_3 != 0x3f)) && (*param_4 != 0)) {
    return 0;
  }
  iVar5 = 5;
  bVar1 = true;
  pbVar6 = param_2;
  pbVar7 = &DAT_08075b7a;
  do {
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    bVar1 = *pbVar6 == *pbVar7;
    pbVar6 = pbVar6 + 1;
    pbVar7 = pbVar7 + 1;
  } while (bVar1);
  if (bVar1) {
    bVar1 = FUN_0806235c(param_1,param_2,"#generic");
    if (param_3 == 0x23) {
      iVar5 = 8;
      bVar8 = true;
      pbVar6 = param_4;
      pbVar7 = (byte *)"generic";
      do {
        if (iVar5 == 0) break;
        iVar5 = iVar5 + -1;
        bVar8 = *pbVar6 == *pbVar7;
        pbVar6 = pbVar6 + 1;
        pbVar7 = pbVar7 + 1;
      } while (bVar8);
      if (bVar8) {
        iVar5 = FUN_0806282c(param_1,param_2,"#generic");
        if (iVar5 != 0) {
          return 2;
        }
        return 1;
      }
    }
    uVar9 = FUN_0804ea10((char *)param_4);
    iVar5 = (int)uVar9;
    if (iVar5 == 0) {
      return 0;
    }
    bVar8 = FUN_08062320(param_1,param_2,param_3,(char *)param_4);
    if (CONCAT31(extraout_var_01,bVar8) != 0) {
      return 1;
    }
    iVar2 = FUN_08070318(param_1,param_2,param_3,(char *)param_4);
    if (iVar2 != 0) {
      return 0;
    }
    pcVar3 = (char *)FUN_080624fc(iVar5);
    iVar2 = FUN_0806282c(param_1,(byte *)"-arch",pcVar3);
    if ((*(byte *)(iVar5 + 0x10) & 8) == 0) {
      uVar4 = FUN_0806282c(param_1,(byte *)".codesize","=-32");
    }
    else {
      uVar4 = FUN_08062878(param_1);
    }
    if ((CONCAT31(extraout_var_00,bVar1) != 0 || iVar2 != 0) || uVar4 != 0) {
      return 2;
    }
    return 1;
  }
  iVar5 = 6;
  bVar1 = true;
  pbVar6 = param_2;
  pbVar7 = (byte *)"-arch";
  do {
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    bVar1 = *pbVar6 == *pbVar7;
    pbVar6 = pbVar6 + 1;
    pbVar7 = pbVar7 + 1;
  } while (bVar1);
  if (bVar1) {
    FUN_0806235c(param_1,param_2,"#4T");
    bVar1 = FUN_0806235c(param_1,&DAT_08075b7a,"#generic");
    if (CONCAT31(extraout_var_02,bVar1) == 0) {
      return 0;
    }
    bVar1 = FUN_08062320(param_1,param_2,param_3,(char *)param_4);
    if (CONCAT31(extraout_var_03,bVar1) != 0) {
      return 1;
    }
    iVar5 = FUN_08070318(param_1,param_2,param_3,(char *)param_4);
    if (iVar5 != 0) {
      return 0;
    }
    if ((param_3 == 0x23) && (iVar5 = FUN_0806238c(param_1), iVar5 != 0)) {
      FUN_08062878(param_1);
      return 2;
    }
    FUN_08070394(param_1,(byte *)".codesize","=-32");
    return 2;
  }
  iVar5 = 5;
  bVar1 = true;
  pbVar6 = param_2;
  pbVar7 = &DAT_08075bdb;
  do {
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    bVar1 = *pbVar6 == *pbVar7;
    pbVar6 = pbVar6 + 1;
    pbVar7 = pbVar7 + 1;
  } while (bVar1);
  if (bVar1) {
    bVar1 = FUN_08062320(param_1,param_2,param_3,(char *)param_4);
    if (CONCAT31(extraout_var_04,bVar1) != 0) {
      return 1;
    }
    iVar5 = FUN_08070318(param_1,param_2,param_3,(char *)param_4);
joined_r0x08062b9e:
    if (iVar5 != 0) {
      return 0;
    }
  }
  else {
    iVar5 = 7;
    bVar1 = true;
    pbVar6 = param_2;
    pbVar7 = &DAT_08075b94;
    do {
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      bVar1 = *pbVar6 == *pbVar7;
      pbVar6 = pbVar6 + 1;
      pbVar7 = pbVar7 + 1;
    } while (bVar1);
    if ((bVar1) && (param_3 == 0x3d)) {
      uVar4 = *param_4 - 0x2d;
      if ((uVar4 == 0) && (uVar4 = param_4[1] - 0x67, uVar4 == 0)) {
        uVar4 = (uint)param_4[2];
      }
      if (uVar4 != 0) goto LAB_08062b77;
      iVar5 = FUN_0806282c(param_1,param_2,"=-g");
      if ((iVar5 != 0) && (iVar5 = FUN_0806282c(param_1,&DAT_08075b8b,"=-keep"), iVar5 != 0)) {
        return 2;
      }
    }
    else {
LAB_08062b77:
      iVar5 = 6;
      bVar1 = true;
      pbVar6 = param_2;
      pbVar7 = &DAT_08075bcb;
      do {
        if (iVar5 == 0) break;
        iVar5 = iVar5 + -1;
        bVar1 = *pbVar6 == *pbVar7;
        pbVar6 = pbVar6 + 1;
        pbVar7 = pbVar7 + 1;
      } while (bVar1);
      if (bVar1) {
        iVar5 = FUN_08070318(param_1,param_2,param_3,(char *)param_4);
        goto joined_r0x08062b9e;
      }
      iVar5 = FUN_08070318(param_1,param_2,param_3,(char *)param_4);
      if (iVar5 != 0) {
        return 0;
      }
    }
    iVar5 = 5;
    bVar1 = true;
    pbVar6 = &DAT_08075c27;
    do {
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      bVar1 = *param_2 == *pbVar6;
      param_2 = param_2 + 1;
      pbVar6 = pbVar6 + 1;
    } while (bVar1);
    if (!bVar1) {
      return 1;
    }
    FUN_08063328(param_1,param_4);
    FUN_080631f4(param_1);
  }
  return 2;
}



void FUN_08062c04(int *param_1,byte *param_2,char *param_3)

{
  FUN_080628c0(param_1,param_2,(int)*param_3,(byte *)(param_3 + 1));
  return;
}



int FUN_08062c20(int *param_1,byte *param_2,undefined4 *param_3)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  
  iVar2 = FUN_080702e4(param_1,param_2);
  if (iVar2 != 0) {
    bVar1 = FUN_080623e8(param_1,(char *)param_2);
    *param_3 = CONCAT31(extraout_var,bVar1);
  }
  return iVar2;
}



undefined4 FUN_08062c54(undefined4 *param_1,char *param_2,undefined4 param_3)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  
  if ((param_1[4] != 0) && (iVar2 = strncmp(param_2,(char *)param_1[3],param_1[4]), iVar2 != 0)) {
    return 0;
  }
  bVar1 = FUN_080623e8((int *)*param_1,param_2);
  uVar3 = (*(code *)param_1[1])(param_1[2],param_2,param_3,bVar1);
  return uVar3;
}



void FUN_08062c9c(int *param_1,byte *param_2,undefined *param_3,undefined4 param_4)

{
  byte bVar1;
  uint uVar2;
  int *local_18;
  undefined *local_14;
  undefined4 local_10;
  byte *local_c;
  int local_8;
  
  uVar2 = *param_2 - 0x2d;
  if (((uVar2 == 0) && (uVar2 = param_2[1] - 0x49, uVar2 == 0)) &&
     (uVar2 = param_2[2] - 0x2e, uVar2 == 0)) {
    uVar2 = (uint)param_2[3];
  }
  if (uVar2 == 0) {
    FUN_080618a0(param_1,(char *)param_2,param_3,param_4);
  }
  else {
    local_18 = param_1;
    local_14 = param_3;
    local_10 = param_4;
    local_c = param_2;
    uVar2 = 0xffffffff;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      bVar1 = *param_2;
      param_2 = param_2 + 1;
    } while (bVar1 != 0);
    local_8 = ~uVar2 - 1;
    FUN_08070794(param_1,FUN_08062c54,&local_18);
  }
  return;
}



void FUN_08062d1c(int *param_1,char *param_2,char *param_3,int param_4)

{
  char cVar1;
  char cVar2;
  int iVar3;
  bool bVar4;
  char *pcVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  char *pcVar9;
  int iVar10;
  int local_28;
  int local_18;
  int local_10;
  size_t local_c;
  
  pcVar5 = strchr(param_2,0x2e);
  if ((pcVar5 == (char *)0x0) ||
     ((iVar6 = isalnum((int)pcVar5[1]), iVar6 == 0 && (pcVar5[1] != '-')))) {
    uVar7 = 0xffffffff;
    pcVar9 = param_2;
    do {
      if (uVar7 == 0) break;
      uVar7 = uVar7 - 1;
      cVar1 = *pcVar9;
      pcVar9 = pcVar9 + 1;
    } while (cVar1 != '\0');
    local_c = ~uVar7 - 1;
  }
  else {
    local_c = (int)pcVar5 - (int)param_2;
  }
  local_10 = param_1[1];
  cVar1 = *param_3;
  local_28 = 0;
  local_18 = 0;
  bVar4 = false;
  uVar7 = 0xffffffff;
  pcVar9 = param_3;
  do {
    if (uVar7 == 0) break;
    uVar7 = uVar7 - 1;
    cVar2 = *pcVar9;
    pcVar9 = pcVar9 + 1;
  } while (cVar2 != '\0');
  uVar7 = ~uVar7;
  uVar8 = uVar7 - 1;
  if (local_10 != 0) {
    local_10 = local_10 + 1;
  }
  local_10 = local_10 + local_c;
  if (cVar1 != '?') {
    if (param_4 != 0) {
      pcVar9 = param_3 + 1;
      cVar2 = param_3[1];
      while (cVar2 != '\0') {
        iVar6 = isspace((int)*pcVar9);
        if (iVar6 == 0) {
          if (*pcVar9 == '\"') {
            local_18 = local_18 + 1;
          }
        }
        else {
          local_28 = local_28 + 1;
        }
        pcVar9 = pcVar9 + 1;
        cVar2 = *pcVar9;
      }
      if ((pcVar5 == param_2) && (local_28 == 1)) {
        local_28 = 0;
      }
    }
    local_10 = local_10 + uVar8;
    if (cVar1 == '=') {
      local_10 = local_10 + -1;
    }
    if ((0 < local_28) || (0 < local_18)) {
      bVar4 = true;
      local_10 = local_18 + 2 + local_10;
    }
  }
  if (local_10 + 1 <= param_1[2]) {
    iVar6 = param_1[1];
    iVar3 = *param_1;
    if (iVar6 != 0) {
      *(undefined1 *)(iVar6 + iVar3) = 0x20;
      iVar6 = iVar6 + 1;
    }
    if ((cVar1 == '=') && (bVar4)) {
      *(undefined1 *)(iVar6 + iVar3) = 0x22;
      iVar6 = iVar6 + 1;
    }
    memcpy((void *)(iVar6 + iVar3),param_2,local_c);
    iVar6 = iVar6 + local_c;
    iVar10 = iVar6;
    if (cVar1 == '#') {
      *(undefined1 *)(iVar6 + iVar3) = 0x20;
      iVar10 = iVar6 + 1;
      if (bVar4) {
        *(undefined1 *)(iVar10 + iVar3) = 0x22;
        iVar10 = iVar6 + 2;
      }
    }
    if (cVar1 != '?') {
      if ((bVar4) && (0 < local_18)) {
        uVar7 = 1;
        if (1 < uVar8) {
          do {
            param_3 = param_3 + 1;
            cVar1 = *param_3;
            if (cVar1 == '\"') {
              *(undefined1 *)(iVar10 + iVar3) = 0x5c;
              iVar10 = iVar10 + 1;
              cVar1 = *param_3;
            }
            *(char *)(iVar10 + iVar3) = cVar1;
            iVar10 = iVar10 + 1;
            uVar7 = uVar7 + 1;
          } while (uVar7 < uVar8);
        }
      }
      else {
        memcpy((void *)(iVar10 + iVar3),param_3 + 1,uVar7 - 2);
        iVar10 = (uVar7 - 2) + iVar10;
      }
      if (bVar4) {
        *(undefined1 *)(iVar10 + iVar3) = 0x22;
      }
    }
  }
  param_1[1] = local_10;
  return;
}



undefined4 FUN_08062f28(int *param_1,byte *param_2,char *param_3)

{
  char *__s2;
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  bool bVar4;
  
  __s2 = (char *)FUN_080702e4(DAT_08079864,param_2);
  if ((__s2 != (char *)0x0) && (iVar1 = strcmp(param_3,__s2), iVar1 == 0)) {
    return 0;
  }
  iVar1 = 10;
  bVar4 = true;
  pbVar2 = param_2;
  pbVar3 = (byte *)".hasthumb";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    bVar4 = *pbVar2 == *pbVar3;
    pbVar2 = pbVar2 + 1;
    pbVar3 = pbVar3 + 1;
  } while (bVar4);
  if (!bVar4) {
    iVar1 = 5;
    bVar4 = true;
    pbVar2 = param_2;
    pbVar3 = &DAT_08075c27;
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar4 = *pbVar2 == *pbVar3;
      pbVar2 = pbVar2 + 1;
      pbVar3 = pbVar3 + 1;
    } while (bVar4);
    if (bVar4) {
      param_1[3] = (int)param_3;
    }
    else {
      iVar1 = 5;
      bVar4 = true;
      pbVar2 = param_2;
      pbVar3 = &DAT_08075b7a;
      do {
        if (iVar1 == 0) break;
        iVar1 = iVar1 + -1;
        bVar4 = *pbVar2 == *pbVar3;
        pbVar2 = pbVar2 + 1;
        pbVar3 = pbVar3 + 1;
      } while (bVar4);
      if (bVar4) {
        param_1[4] = (int)param_3;
      }
      else {
        iVar1 = 6;
        bVar4 = true;
        pbVar2 = param_2;
        pbVar3 = (byte *)"-arch";
        do {
          if (iVar1 == 0) break;
          iVar1 = iVar1 + -1;
          bVar4 = *pbVar2 == *pbVar3;
          pbVar2 = pbVar2 + 1;
          pbVar3 = pbVar3 + 1;
        } while (bVar4);
        if (bVar4) {
          param_1[5] = (int)param_3;
        }
        else {
          iVar1 = 5;
          bVar4 = true;
          pbVar2 = param_2;
          pbVar3 = &DAT_08075bdb;
          do {
            if (iVar1 == 0) break;
            iVar1 = iVar1 + -1;
            bVar4 = *pbVar2 == *pbVar3;
            pbVar2 = pbVar2 + 1;
            pbVar3 = pbVar3 + 1;
          } while (bVar4);
          if (bVar4) {
            param_1[6] = (int)param_3;
          }
          else {
            iVar1 = strncmp((char *)param_2,"-I.",3);
            if (iVar1 != 0) {
              FUN_08062d1c(param_1,(char *)param_2,param_3,1);
            }
          }
        }
      }
    }
  }
  return 0;
}



undefined4 FUN_08063024(int *param_1,byte *param_2,char *param_3)

{
  char *__s2;
  int iVar1;
  
  __s2 = (char *)FUN_080702e4(DAT_08079864,param_2);
  if ((__s2 != (char *)0x0) && (iVar1 = strcmp(param_3,__s2), iVar1 == 0)) {
    return 0;
  }
  FUN_08062d1c(param_1,(char *)param_2,param_3,1);
  return 0;
}



int FUN_08063068(int *param_1,int param_2,int param_3)

{
  int local_20;
  int local_1c;
  int local_18;
  char *local_14;
  char *local_10;
  char *local_c;
  char *local_8;
  
  local_10 = (char *)0x0;
  local_14 = (char *)0x0;
  local_c = (char *)0x0;
  local_8 = (char *)0x0;
  local_20 = param_2;
  local_1c = 0;
  local_18 = param_3;
  FUN_08070794(param_1,FUN_08062f28,&local_20);
  FUN_08062c9c(param_1,&DAT_08075c2c,FUN_08063024,&local_20);
  if (local_10 != (char *)0x0) {
    FUN_08062d1c(&local_20,"-cpu",local_10,1);
  }
  if (local_c != (char *)0x0) {
    FUN_08062d1c(&local_20,"-arch",local_c,1);
  }
  if (local_8 != (char *)0x0) {
    FUN_08062d1c(&local_20,"-fpu",local_8,1);
  }
  if (local_14 != (char *)0x0) {
    FUN_08062d1c(&local_20,"",local_14,0);
  }
  if (local_1c < param_3) {
    *(undefined1 *)(local_1c + param_2) = 0;
  }
  return local_1c + 1;
}



undefined4 FUN_0806313c(int param_1,byte *param_2,char *param_3)

{
  char *__s2;
  int iVar1;
  void *pvVar2;
  byte *pbVar3;
  byte *pbVar4;
  bool bVar5;
  
  if (DAT_08079864 != (int *)0x0) {
    __s2 = (char *)FUN_080702e4(DAT_08079864,param_2);
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
      pbVar4 = &DAT_08075c27;
      do {
        if (iVar1 == 0) break;
        iVar1 = iVar1 + -1;
        bVar5 = *pbVar3 == *pbVar4;
        pbVar3 = pbVar3 + 1;
        pbVar4 = pbVar4 + 1;
      } while (bVar5);
      if ((!bVar5) && (iVar1 = FUN_08062284(), iVar1 == 0)) {
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



void FUN_080631f4(int *param_1)

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
  FUN_08070794(param_1,FUN_0806313c,&local_14);
  if (local_10 == 0) {
    FUN_08070394(param_1,&DAT_08075c27,"=");
  }
  else {
    local_20 = (char *)0x0;
    local_1c = 0;
    local_18 = 0;
    uVar1 = 0;
    if (local_10 != 0) {
      do {
        FUN_08062d1c((int *)&local_20,*(char **)((int)local_8 + uVar1 * 8),
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
        FUN_08062d1c((int *)&local_20,*(char **)((int)local_8 + uVar1 * 8),
                     *(char **)((int)local_8 + uVar1 * 8 + 4),1);
        uVar1 = uVar1 + 1;
      } while (uVar1 < local_10);
    }
    local_20[local_1c] = '\0';
    FUN_08070318(param_1,&DAT_08075c27,0x3d,local_20);
    uVar1 = 0;
    if (local_10 != 0) {
      do {
        FUN_08070394(param_1,*(byte **)((int)local_8 + uVar1 * 8),"=");
        uVar1 = uVar1 + 1;
      } while (uVar1 < local_10);
    }
    free(local_20);
  }
  free(local_8);
  return;
}



void FUN_08063328(int *param_1,undefined4 param_2)

{
  undefined4 *__ptr;
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int *local_2c;
  undefined4 local_24;
  char *local_20;
  undefined4 local_1c;
  undefined4 local_18;
  int local_14;
  int local_10;
  undefined4 *local_c;
  undefined4 local_8;
  
  local_20 = "-vias";
  local_1c = param_2;
  local_18 = 0;
  local_14 = 10;
  local_c = malloc(0x78);
  local_10 = 0;
  local_8 = 1;
  FUN_08050934(3,&local_24,&local_14);
  __ptr = local_c;
  iVar3 = 0;
  if (0 < local_10) {
    puVar2 = local_c + 1;
    local_2c = local_c + 2;
    puVar1 = local_c;
    do {
      FUN_08070318(param_1,(byte *)*puVar1,*local_2c,(char *)*puVar2);
      free((void *)*puVar1);
      free((void *)*puVar2);
      puVar2 = puVar2 + 3;
      puVar1 = puVar1 + 3;
      local_2c = local_2c + 3;
      iVar3 = iVar3 + 1;
    } while (iVar3 < local_10);
  }
  free(__ptr);
  return;
}



void FUN_080633d4(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_080702e4(param_1,&DAT_08075c27);
  if (iVar1 != 0) {
    FUN_08063328(param_1,iVar1 + 1);
  }
  FUN_080631f4(param_1);
  return;
}



void FUN_08063404(void)

{
  __sysv_signal(2,(__sighandler_t)0x0);
  FUN_080615f0(-1);
  return;
}



void FUN_0806341c(void)

{
  __sysv_signal(2,FUN_08063404);
  return;
}



int FUN_08063430(undefined4 *param_1,int *param_2,int *param_3,int *param_4,int param_5)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  
LAB_0806343c:
  pcVar3 = (char *)*param_1;
  local_8 = 0;
  iVar4 = 0;
  local_c = 0;
  local_10 = 0;
  iVar2 = param_5;
  if (param_5 == 0) {
    cVar1 = *pcVar3;
    if (cVar1 == '0') {
      if (pcVar3[1] == 'b') {
        iVar2 = 2;
        pcVar3 = pcVar3 + 2;
      }
      else if (pcVar3[1] == 'x') {
        iVar2 = 0x10;
        pcVar3 = pcVar3 + 2;
      }
      else {
        iVar2 = 8;
        pcVar3 = pcVar3 + 1;
      }
    }
    else {
      if ('0' < cVar1) {
        if (cVar1 == 'x') goto LAB_0806347a;
        goto LAB_080634b8;
      }
      if (cVar1 == '%') {
        iVar2 = 2;
        pcVar3 = pcVar3 + 1;
      }
      else {
        if (cVar1 < '&') {
          if (cVar1 == '$') {
LAB_0806347a:
            iVar2 = 0x10;
            pcVar3 = pcVar3 + 1;
            goto LAB_080634bd;
          }
        }
        else if (cVar1 == '&') goto LAB_0806347a;
LAB_080634b8:
        iVar2 = 10;
      }
    }
  }
LAB_080634bd:
  cVar1 = *pcVar3;
  param_5 = local_8;
joined_r0x080634c1:
  if (cVar1 == '\0') goto switchD_080634d9_caseD_21;
  local_8 = param_5;
  switch(cVar1) {
  case ' ':
  case '|':
    goto switchD_080634d9_caseD_20;
  default:
    goto switchD_080634d9_caseD_21;
  case '.':
  case 'O':
  case 'Z':
    local_14 = 0;
    break;
  case '0':
  case '1':
    goto switchD_080634d9_caseD_30;
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
    goto switchD_080634d9_caseD_32;
  case '8':
  case '9':
    if (iVar2 == 8) goto switchD_080634d9_caseD_21;
    goto switchD_080634d9_caseD_32;
  case 'A':
  case 'B':
  case 'C':
  case 'D':
  case 'E':
  case 'F':
    if (iVar2 != 0x10) goto switchD_080634d9_caseD_21;
    local_14 = *pcVar3 + -0x37;
    break;
  case '_':
    goto switchD_080634d9_caseD_5f;
  case 'a':
  case 'b':
  case 'c':
  case 'd':
  case 'e':
  case 'f':
    if (iVar2 != 0x10) goto switchD_080634d9_caseD_21;
    local_14 = *pcVar3 + -0x57;
  }
  goto LAB_0806353b;
switchD_080634d9_caseD_5f:
  *param_1 = pcVar3 + 1;
  goto LAB_0806343c;
switchD_080634d9_caseD_32:
  if (iVar2 == 2) {
switchD_080634d9_caseD_21:
    *param_3 = local_c;
    *param_2 = iVar4;
    *param_4 = local_10 + iVar4 + local_c;
    *param_1 = pcVar3;
    return param_5;
  }
switchD_080634d9_caseD_30:
  local_14 = *pcVar3 + -0x30;
LAB_0806353b:
  local_8 = iVar2 * param_5 + local_14;
  local_c = local_c * iVar2;
  iVar4 = iVar4 * iVar2;
  local_10 = local_10 * iVar2;
  if (cVar1 == 'O') {
    local_c = iVar2 + -1 + local_c;
  }
  else if (cVar1 < 'P') {
    if (cVar1 == '.') {
      local_10 = iVar2 + -1 + local_10;
    }
  }
  else if (cVar1 == 'Z') {
    iVar4 = iVar2 + -1 + iVar4;
  }
switchD_080634d9_caseD_20:
  pcVar3 = pcVar3 + 1;
  cVar1 = *pcVar3;
  param_5 = local_8;
  goto joined_r0x080634c1;
}



bool FUN_080635d0(int param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  int local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_14 = *param_2 + 2 + param_1;
  uVar1 = FUN_08051d0c();
  uVar2 = FUN_08063430(&local_14,(int *)&local_10,(int *)&local_c,(int *)&local_8,0);
  cVar3 = (uVar1 & ~local_8) != uVar2;
  if ((bool)cVar3) {
    FUN_08052f1c(4,"Test: value=%08lx expected=%08lx/%08lx");
  }
  if ((uVar1 & local_c) != local_c) {
    FUN_08052f1c(4,"Test: value=%08lx expected %08lx SBO");
    cVar3 = cVar3 + '\x01';
  }
  if ((local_10 & uVar1) != 0) {
    FUN_08052f1c(4,"Test: value=%08lx expected %08lx SBZ");
    cVar3 = cVar3 + '\x01';
  }
  DAT_0807f8c4 = DAT_0807f8c4 + 1;
  if (cVar3 != '\0') {
    DAT_0807f8c8 = DAT_0807f8c8 + 1;
  }
  return cVar3 != '\0';
}



void FUN_08063684(void)

{
  DAT_0807f8c8 = 0;
  DAT_0807f8c4 = 0;
  return;
}



void FUN_080636a0(void)

{
  FUN_08052f1c(1,"Tests: %ld test(s), %ld failure(s)");
  return;
}



undefined4 FUN_080636c0(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 0;
  do {
    uVar1 = 0;
    while( true ) {
      if (param_1 < 0x100) {
        return 1;
      }
      if (0xf < uVar1) break;
      param_1 = param_1 << 0x1e | param_1 >> 2;
      uVar1 = uVar1 + 1;
    }
    param_1 = ~param_1;
    uVar2 = uVar2 + 1;
  } while (uVar2 < 2);
  return 0;
}



undefined4 FUN_080636f4(char *param_1,int *param_2,int param_3,uint param_4,int *param_5)

{
  uint *puVar1;
  undefined *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  uint local_24;
  int local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  if (((param_4 & 0xf0000000) == 0xf0000000) &&
     (((param_4 & 0xfe000000) != 0xfa000000 || ((DAT_080825f9 & 2) == 0)))) {
    FUN_08052f1c(3,"Reserved instruction (using NV condition)");
  }
  iVar5 = DAT_0807986c;
  switch(param_3) {
  case 0:
    local_18 = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      local_c = param_4 >> 0x15 & 0xf;
      if (local_c == 0xd) {
LAB_08063920:
        local_18 = 0xffffffff;
      }
      else if ((local_c == 0xf) || (local_c - 8 < 4)) {
        if ((local_c == 0xd) || (local_c == 0xf)) goto LAB_08063920;
        if ((DAT_080826f0 != 0) && (local_18 == 0xf)) {
          FUN_08052f1c(3,"TSTP/TEQP/CMNP/CMPP inadvisable in 32-bit PC configurations");
        }
      }
      else {
        local_18 = FUN_080679f0((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        if (param_1[*param_2] != ',') break;
        *param_2 = *param_2 + 1;
      }
      iVar5 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar5 != '#') {
        local_c = FUN_080676d0(param_1,param_2,1);
        param_4 = param_4 & 0xfffffff;
        iVar5 = DAT_0807986c;
        if (param_4 == 0x1200000) {
          if ((local_c & 0xfffffff0) == 0) goto switchD_08063748_caseD_7;
          pcVar6 = "Shifted register operand to MSR is undefined in architecture 4 and later";
          if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
            iVar5 = 3;
          }
          else {
            iVar5 = 4;
          }
        }
        else {
          if ((local_c & 0x10) == 0) goto switchD_08063748_caseD_7;
          if ((local_c & 0xf00) == 0xf00) {
            if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
              iVar5 = 3;
            }
            else {
              iVar5 = 4;
            }
            FUN_08052f1c(iVar5,"Reserved instruction (using PC as Rs)");
          }
          if (((local_c & 0xf) != 0xf) && (iVar5 = DAT_0807986c, local_18 != 0xf))
          goto switchD_08063748_caseD_7;
          pcVar6 = "Undefined effect (using PC as Rn or Rm in register specified shift)";
          if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
            iVar5 = 3;
          }
          else {
            iVar5 = 4;
          }
        }
        goto LAB_080649a1;
      }
      *param_2 = *param_2 + 1;
      local_c = FUN_080535b0(param_1,param_2,1,&local_8);
      if (DAT_08080160 != 0) {
        return 0;
      }
      iVar5 = DAT_0807986c;
      if (param_1[*param_2] != ',') goto switchD_08063748_caseD_7;
      *param_2 = *param_2 + 1;
      iVar5 = 0;
      goto LAB_08063f23;
    }
    break;
  case 1:
    iVar4 = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      iVar5 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar5 == '[') {
        *param_2 = *param_2 + 1;
        local_18 = FUN_080679f0((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        iVar5 = *param_2;
        if (param_1[iVar5] == ']') {
          *param_2 = iVar5 + 1;
          iVar5 = FUN_0805fa50((int)param_1,param_2);
          if ((char)iVar5 == ',') {
            *param_2 = *param_2 + 1;
            local_18 = local_18 + 0x20;
            iVar5 = FUN_0805fa50((int)param_1,param_2);
            if ((char)iVar5 == '#') {
              *param_2 = *param_2 + 1;
              local_c = FUN_080535b0(param_1,param_2,1,&local_8);
            }
            else {
              if ((param_1[*param_2] == '+') || (param_1[*param_2] == '-')) {
                *param_2 = *param_2 + 1;
              }
              if ((param_4 & 0xc000000) == 0x4000000) {
                local_c = FUN_080676d0(param_1,param_2,0);
              }
              else {
                local_c = FUN_080679f0((int)param_1,param_2);
              }
              if (local_c == 0xf) {
                if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
                  iVar5 = 3;
                }
                else {
                  iVar5 = 4;
                }
                FUN_08052f1c(iVar5,"Undefined effect (using PC as offset register)");
              }
              if ((local_18 & 0xf) == (local_c & 0xf)) {
                if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
                  iVar5 = 3;
                }
                else {
                  iVar5 = 4;
                }
                FUN_08052f1c(iVar5,"Reserved instruction (Rm = Rn with post-indexing)");
              }
            }
          }
          else {
            iVar5 = *param_2;
            if (param_1[iVar5] == '!') {
LAB_08063e30:
              *param_2 = iVar5 + 1;
            }
            else if ((param_4 & 0x200000) == 0) goto LAB_08063e37;
LAB_08063e33:
            local_18 = local_18 + 0x20;
          }
        }
        else {
          if (param_1[iVar5] != ',') break;
          if ((param_4 & 0x200000) != 0) {
            pcVar6 = "Translate not allowed in pre-indexed form";
            goto LAB_08064939;
          }
          *param_2 = iVar5 + 1;
          iVar5 = FUN_0805fa50((int)param_1,param_2);
          if ((char)iVar5 == '#') {
            *param_2 = *param_2 + 1;
            local_c = FUN_080535b0(param_1,param_2,1,&local_8);
            if ((iVar4 == 0xf) && ((local_18 == 0xf && ((local_c & 3) != 0)))) {
              pcVar6 = "Unaligned transfer of PC";
              if (DAT_08082620 != 0) goto LAB_08063c82;
LAB_08063c7b:
              iVar5 = 4;
LAB_08063c87:
              FUN_08052f1c(iVar5,pcVar6);
            }
          }
          else {
            if ((param_1[*param_2] == '+') || (param_1[*param_2] == '-')) {
              *param_2 = *param_2 + 1;
            }
            if ((param_4 & 0xc000000) == 0x4000000) {
              local_c = FUN_080676d0(param_1,param_2,0);
            }
            else {
              local_c = FUN_080679f0((int)param_1,param_2);
            }
            if (local_c == 0xf) {
              pcVar6 = "Undefined effect (using PC as offset register)";
              if ((3 < DAT_080825f0) && (DAT_08082620 == 0)) goto LAB_08063c7b;
LAB_08063c82:
              iVar5 = 3;
              goto LAB_08063c87;
            }
          }
          if (DAT_08080160 != 0) {
            return 0;
          }
          if (param_1[*param_2] != ']') {
            pcVar6 = "Missing close square bracket";
            goto LAB_08064939;
          }
          *param_2 = *param_2 + 1;
          iVar5 = FUN_0805fa50((int)param_1,param_2);
          if ((char)iVar5 == '!') {
            *param_2 = *param_2 + 1;
            goto LAB_08063e33;
          }
        }
      }
      else {
        if ((param_4 & 0x200000) != 0) {
          pcVar6 = "Translate not allowed in pre-indexed form";
          goto LAB_08064939;
        }
        local_18 = 0;
        if ((((param_1[*param_2] == '=') && (DAT_080825c4 == 0)) ||
            ((param_1[*param_2] == '#' && (DAT_080825c4 == 1)))) && ((param_4 & 0x100000) != 0)) {
          *param_2 = *param_2 + 1;
          puVar2 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
          *param_5 = (int)puVar2;
          if (puVar2 == (undefined *)0x0) {
            local_10 = 0;
            local_c = FUN_08053738(param_1,param_2,&local_14,1,&local_8,&local_10);
            if (DAT_08080160 != 0) {
              return 0;
            }
            if (local_14 == 3) {
              if (local_10 != 0) {
                local_c = local_c | 1;
              }
              local_c = FUN_08056c4c(local_c,local_8,-0xfff,0xfff);
            }
            else if ((local_8 == 0) || (iVar5 = FUN_080636c0(local_c), iVar5 == 0)) {
              local_c = FUN_08056bec(local_8,0,local_c,-0xfff,0xfff);
            }
          }
          else {
            local_c = FUN_08056c1c((uint)puVar2,local_c,-0xfff,0xfff);
          }
        }
        else {
          puVar2 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
          *param_5 = (int)puVar2;
          if (puVar2 == (undefined *)0x0) {
            local_c = FUN_08053a28(param_1,param_2,&local_18,1,&local_8);
            local_18 = 0xf;
          }
          iVar5 = *param_2;
          if (param_1[iVar5] == '!') goto LAB_08063e30;
        }
      }
LAB_08063e37:
      if (local_18 == 0x2f) {
        if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
          iVar5 = 3;
        }
        else {
          iVar5 = 4;
        }
        FUN_08052f1c(iVar5,"Undefined effect (PC + writeback)");
      }
      if ((local_18 == iVar4 + 0x20U) && ((param_4 & 0x100000) != 0)) {
        if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
          iVar5 = 3;
        }
        else {
          iVar5 = 4;
        }
        FUN_08052f1c(iVar5,"Undefined effect (destination same as written-back base)");
      }
      iVar5 = DAT_0807986c;
      if ((iVar4 != 0xf) || ((param_4 & 0x4400000) == 0x4000000)) goto switchD_08063748_caseD_7;
      pcVar6 = "Undefined effect (PC used in a non-word context)";
      if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
        iVar5 = 3;
      }
      else {
        iVar5 = 4;
      }
LAB_080649a1:
      FUN_08052f1c(iVar5,pcVar6);
      iVar5 = DAT_0807986c;
      goto switchD_08063748_caseD_7;
    }
    break;
  case 2:
    puVar2 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
    *param_5 = (int)puVar2;
    iVar5 = DAT_0807986c;
    if (puVar2 != (undefined *)0x0) goto switchD_08063748_caseD_7;
    iVar5 = 1;
LAB_08063f23:
    FUN_080535b0(param_1,param_2,iVar5,&local_8);
    iVar5 = DAT_0807986c;
    goto switchD_08063748_caseD_7;
  case 3:
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    iVar5 = *param_2;
    if (param_1[iVar5] == '!') {
      *param_2 = iVar5 + 1;
      local_c = local_c + 0x20;
      FUN_0805fa50((int)param_1,param_2);
      iVar5 = *param_2;
    }
    if (param_1[iVar5] == ',') {
      *param_2 = iVar5 + 1;
      local_18 = FUN_08067bdc((int)param_1,param_2);
      if ((local_c & 0x20) != 0) {
        if ((param_4 & 0x100000) == 0) {
          uVar3 = 1 << ((byte)local_c & 0xf);
          if (((uVar3 & local_18) != 0) && ((uVar3 - 1 & local_18) != 0)) {
            pcVar6 = "Non portable instruction (STM with writeback and base not first in reg. list)"
            ;
            goto LAB_08063fca;
          }
        }
        else if ((local_18 >> (local_c & 0xf) & 1) != 0) {
          pcVar6 = "Non portable instruction (LDM with writeback and base in reg. list)";
LAB_08063fca:
          FUN_08052f1c(3,pcVar6);
        }
      }
      if (param_1[*param_2] == '^') {
        *param_2 = *param_2 + 1;
        if ((-1 < (short)local_18) && ((local_c & 0x20) != 0)) {
          FUN_08052f1c(3,"Unsafe instruction (forced user mode xfer with write-back to base)");
        }
      }
      if ((local_c & 0xf) == 0xf) {
        FUN_08052f1c(3,"Unsafe instruction (PSR bits may pollute PC value)");
      }
      iVar5 = DAT_0807986c;
      if (((DAT_08079800 != 0) && ((param_4 & 0x100000) != 0)) &&
         (iVar5 = DAT_080826a0, DAT_080826a0 == DAT_0807986c + 4)) {
        if (DAT_08079800 == 2) {
          FUN_08052f1c(3,"Inserting NOP between two LDM instructions");
        }
        DAT_080826a0 = DAT_080826a0 + 4;
        iVar5 = DAT_080826a0;
      }
      goto switchD_08063748_caseD_7;
    }
    break;
  case 4:
switchD_08063748_caseD_4:
    puVar2 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
    *param_5 = (int)puVar2;
    iVar5 = DAT_0807986c;
    if (puVar2 != (undefined *)0x0) goto switchD_08063748_caseD_7;
    puVar1 = &local_1c;
    goto LAB_0806414d;
  case 5:
    local_c = FUN_080535b0(param_1,param_2,1,&local_8);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      goto switchD_08063748_caseD_4;
    }
    break;
  case 6:
  case 0x21:
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      if ((local_c == 0xf) && (param_3 == 0x21)) {
        pcVar6 = "ADRL can\'t be used with PC";
        goto LAB_08064939;
      }
      puVar2 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
      *param_5 = (int)puVar2;
      if (puVar2 == (undefined *)0x0) {
        FUN_0805384c(param_1,param_2,&local_c,&local_14,1,&local_8);
      }
      iVar5 = DAT_0807986c;
      if (param_3 == 0x21) {
        DAT_080826a0 = DAT_080826a0 + 4;
      }
      goto switchD_08063748_caseD_7;
    }
    break;
  default:
    goto switchD_08063748_caseD_7;
  case 8:
    if ((DAT_080825f8 & 0x40) == 0) {
      FUN_08052f1c(3,"Instruction not supported on targeted CPU");
    }
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      FUN_080679f0((int)param_1,param_2);
      goto LAB_08064110;
    }
    break;
  case 9:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x19:
  case 0x1a:
  case 0x1b:
    uVar3 = FUN_08067d00(param_1,param_2,param_3,param_4);
    goto LAB_080642db;
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x18:
    uVar3 = FUN_0806b850(param_1,param_2,param_3,param_4);
LAB_080642db:
    iVar5 = DAT_0807986c;
    if (uVar3 == 0) {
      return 0;
    }
    goto switchD_08063748_caseD_7;
  case 0x1c:
    local_c = FUN_08067b48((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      local_c = FUN_08067ab4((int)param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        iVar5 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar5 == '[') {
          *param_2 = *param_2 + 1;
          local_18 = FUN_080679f0((int)param_1,param_2);
          if (DAT_08080160 != 0) {
            return 0;
          }
          iVar5 = *param_2;
          if (param_1[iVar5] != ']') {
            if (param_1[iVar5] != ',') break;
            *param_2 = iVar5 + 1;
            iVar5 = FUN_0805fa50((int)param_1,param_2);
            if ((char)iVar5 == '#') {
              *param_2 = *param_2 + 1;
              local_c = FUN_080535b0(param_1,param_2,1,&local_8);
            }
            else {
              FUN_08052f1c(4,"Missing \'#\'");
            }
            if (DAT_08080160 != 0) {
              return 0;
            }
            if (param_1[*param_2] != ']') {
              pcVar6 = "Missing close square bracket";
              goto LAB_08064939;
            }
            *param_2 = *param_2 + 1;
            iVar5 = FUN_0805fa50((int)param_1,param_2);
            if ((char)iVar5 != '!') goto LAB_0806449b;
            *param_2 = *param_2 + 1;
            goto LAB_08064497;
          }
          *param_2 = iVar5 + 1;
          iVar5 = FUN_0805fa50((int)param_1,param_2);
          if ((char)iVar5 != ',') {
            iVar5 = *param_2;
            goto LAB_0806448e;
          }
          *param_2 = *param_2 + 1;
          iVar5 = FUN_0805fa50((int)param_1,param_2);
          if ((char)iVar5 == '#') {
            *param_2 = *param_2 + 1;
            local_18 = local_18 + 0x20;
            local_c = FUN_080535b0(param_1,param_2,1,&local_8);
          }
          else {
            if ((char)iVar5 != '{') {
              pcVar6 = "Missing \'#\'";
              goto LAB_08064939;
            }
            *param_2 = *param_2 + 1;
            local_c = FUN_080535b0(param_1,param_2,1,&local_8);
            iVar5 = FUN_0805fa50((int)param_1,param_2);
            if ((char)iVar5 != '}') {
              pcVar6 = "Missing close bracket";
              goto LAB_08064939;
            }
            *param_2 = *param_2 + 1;
          }
        }
        else {
          local_c = FUN_08053a28(param_1,param_2,&local_18,1,&local_8);
          iVar5 = *param_2;
LAB_0806448e:
          if (param_1[iVar5] == '!') {
            *param_2 = iVar5 + 1;
LAB_08064497:
            local_18 = local_18 + 0x20;
          }
        }
LAB_0806449b:
        iVar5 = DAT_0807986c;
        if (local_18 != 0x2f) goto switchD_08063748_caseD_7;
        pcVar6 = "Useless instruction (PC can\'t be written back)";
        iVar5 = 3;
        goto LAB_080649a1;
      }
    }
    break;
  case 0x1d:
    local_c = FUN_08067b48((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      local_c = FUN_080535b0(param_1,param_2,0,&local_8);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (0xf < local_c) {
        pcVar6 = "Coprocessor operation out of range";
        goto LAB_08064939;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        local_c = FUN_08067ab4((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        if (param_1[*param_2] == ',') {
          *param_2 = *param_2 + 1;
          local_c = FUN_08067ab4((int)param_1,param_2);
          if (DAT_08080160 != 0) {
            return 0;
          }
          if (param_1[*param_2] == ',') {
            *param_2 = *param_2 + 1;
            local_c = FUN_08067ab4((int)param_1,param_2);
            if (DAT_08080160 != 0) {
              return 0;
            }
            iVar5 = DAT_0807986c;
            if (param_1[*param_2] != ',') goto switchD_08063748_caseD_7;
            *param_2 = *param_2 + 1;
            local_c = FUN_080535b0(param_1,param_2,0,&local_8);
            iVar5 = DAT_0807986c;
            if (local_c < 8) goto switchD_08063748_caseD_7;
            pcVar6 = "Coprocessor operation out of range";
            goto LAB_0806499f;
          }
        }
      }
    }
    break;
  case 0x1e:
    local_c = FUN_08067b48((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      local_c = FUN_080535b0(param_1,param_2,0,&local_8);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (7 < local_c) {
        pcVar6 = "Coprocessor operation out of range";
        goto LAB_08064939;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        local_c = FUN_080679f0((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        if (param_1[*param_2] == ',') {
          *param_2 = *param_2 + 1;
          if ((local_c == 0xf) && (param_4 = param_4 & 0xfffffff, param_4 == 0xe000010)) {
            if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
              iVar5 = 3;
            }
            else {
              iVar5 = 4;
            }
            FUN_08052f1c(iVar5,"Undefined effect (use of PC/PSR)");
          }
          local_c = FUN_08067ab4((int)param_1,param_2);
          if (DAT_08080160 != 0) {
            return 0;
          }
          if (param_1[*param_2] == ',') {
            *param_2 = *param_2 + 1;
            local_c = FUN_08067ab4((int)param_1,param_2);
            if (DAT_08080160 != 0) {
              return 0;
            }
            iVar5 = DAT_0807986c;
            if (param_1[*param_2] != ',') goto switchD_08063748_caseD_7;
            *param_2 = *param_2 + 1;
            local_c = FUN_080535b0(param_1,param_2,0,&local_8);
            iVar5 = DAT_0807986c;
            if (local_c < 8) goto switchD_08063748_caseD_7;
            pcVar6 = "Coprocessor operation out of range";
            goto LAB_0806499f;
          }
        }
      }
    }
    break;
  case 0x1f:
  case 0x20:
  case 0x28:
  case 0x29:
    if ((-1 < (char)DAT_080825f8) && (param_3 - 0x28U < 2)) {
      FUN_08052f1c(3,"Instruction not supported on targeted CPU");
    }
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      local_18 = FUN_080679f0((int)param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (local_18 == local_c) {
        if (DAT_08082620 == 0) {
          iVar5 = 4;
        }
        else {
          iVar5 = 3;
        }
        FUN_08052f1c(iVar5,"Undefined effect (Rd = Rm in MUL/MLA instruction)");
      }
      if (local_c == 0xf) {
        FUN_08052f1c(3,"Useless instruction (PC is destination)");
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        local_c = FUN_080679f0((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        iVar4 = 0;
        if ((param_3 == 0x20) || (param_3 == 0x29)) {
          if (param_1[*param_2] != ',') break;
          *param_2 = *param_2 + 1;
          iVar4 = FUN_080679f0((int)param_1,param_2);
        }
        if (((local_c != 0xf) && (local_18 != 0xf)) && (iVar5 = DAT_0807986c, iVar4 != 0xf))
        goto switchD_08063748_caseD_7;
        pcVar6 = "Dubious instruction (PC used as an operand)";
        iVar5 = 3;
        goto LAB_080649a1;
      }
    }
    break;
  case 0x22:
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      local_18 = FUN_080679f0((int)param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        iVar5 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar5 != '[') {
          pcVar6 = "Missing open square bracket";
          goto LAB_08064939;
        }
        *param_2 = *param_2 + 1;
        iVar4 = FUN_080679f0((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        if (param_1[*param_2] != ']') {
          pcVar6 = "Missing close square bracket";
          goto LAB_08064939;
        }
        *param_2 = *param_2 + 1;
        if ((local_c == 0xf) || (local_18 == 0xf)) {
          FUN_08052f1c(3,"Unsafe instruction (PC as source or destination)");
        }
        iVar5 = DAT_0807986c;
        if (iVar4 != 0xf) goto switchD_08063748_caseD_7;
        pcVar6 = "Undefined effect (PC-relative SWP)";
        iVar5 = 3;
        goto LAB_080649a1;
      }
    }
    break;
  case 0x23:
    if (DAT_080826f0 == 0) {
      FUN_08052f1c(3,"MRS/MSR invalid in 26-bit PC configurations");
    }
    if ((param_4 & 0xfffffff) == 0x1000000) {
      local_c = FUN_080679f0((int)param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        uVar3 = FUN_08067460((int)param_1,param_2,0x1000000);
        goto LAB_080642db;
      }
    }
    else {
      local_c = FUN_08067460((int)param_1,param_2,0x1200000);
      if (local_c == 0) {
        return 0;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        FUN_0805fa50((int)param_1,param_2);
        if ((param_1[*param_2] == '#') && (((local_c & 0x3c) == 0 || ((local_c & 0x3c) == 0x24)))) {
          FUN_08052f1c(3,
                       "Writing an 8-bit immediate value to the whole C/SPSR is not guaranteed on future processors"
                      );
        }
        goto LAB_08063920;
      }
    }
    break;
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x27:
  case 0x2a:
    if (param_3 == 0x2a) {
      if (-1 < (char)DAT_080825f8) {
LAB_080648ba:
        FUN_08052f1c(3,"Instruction not supported on targeted CPU");
      }
    }
    else if ((DAT_080825f8 & 1) == 0) goto LAB_080648ba;
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      local_18 = FUN_080679f0((int)param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        uVar3 = FUN_080679f0((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        if (param_1[*param_2] == ',') {
          *param_2 = *param_2 + 1;
          iVar4 = FUN_080679f0((int)param_1,param_2);
          if (DAT_08080160 != 0) {
            return 0;
          }
          if (((local_c == local_18) || (local_18 == uVar3)) || (uVar3 == local_c)) {
            FUN_08052f1c(3,"Undefined if any of RdLo, RdHi, Rm are the same register");
          }
          if (((local_c != 0xf) && (local_18 != 0xf)) &&
             ((uVar3 != 0xf && (iVar5 = DAT_0807986c, iVar4 != 0xf))))
          goto switchD_08063748_caseD_7;
          pcVar6 = "Long multiply instructions do not take R15 as an operand";
LAB_0806499f:
          iVar5 = 4;
          goto LAB_080649a1;
        }
      }
    }
    break;
  case 0x2b:
  case 0x2c:
    if ((DAT_080825f9 & 1) == 0) {
      FUN_08052f1c(3,"Instruction not supported on targeted CPU");
    }
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      local_18 = FUN_080679f0((int)param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        FUN_080679f0((int)param_1,param_2);
        goto LAB_08064110;
      }
    }
    break;
  case 0x2d:
    FUN_080679f0((int)param_1,param_2);
LAB_08064110:
    iVar5 = DAT_0807986c;
    if (DAT_08080160 != 0) {
      return 0;
    }
    goto switchD_08063748_caseD_7;
  case 0x30:
    local_20 = 0;
    if ((DAT_080825f9 & 2) == 0) {
      FUN_08052f1c(3,"Instruction not supported on targeted CPU");
    }
    local_c = FUN_08067968(param_1,param_2,(int *)&local_c,(uint *)0x0,&local_20,param_5);
    if (local_20 != 0) goto LAB_08064110;
    if ((param_4 & 0xf0000000) != 0xe0000000) {
      pcVar6 = "BLX <address> must be unconditional";
      goto LAB_08064939;
    }
    iVar5 = DAT_0807986c;
    if (*param_5 != 0) goto switchD_08063748_caseD_7;
    puVar1 = &local_24;
LAB_0806414d:
    FUN_08053738(param_1,param_2,puVar1,1,&local_8,(uint *)0x0);
    iVar5 = DAT_0807986c;
switchD_08063748_caseD_7:
    DAT_0807986c = iVar5;
    DAT_080826a0 = DAT_080826a0 + 4;
    return 1;
  }
  pcVar6 = "Missing comma";
LAB_08064939:
  FUN_08052f1c(4,pcVar6);
  return 0;
}



undefined4 FUN_080649c0(uint param_1,uint *param_2,int param_3,uint *param_4)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 0;
  while( true ) {
    uVar1 = 0;
    while( true ) {
      if (param_1 < 0x100) {
        *param_4 = param_1;
        *param_2 = uVar1;
        return 1;
      }
      if (0xf < uVar1) break;
      param_1 = param_1 << 2 | param_1 >> 0x1e;
      uVar1 = uVar1 + 1;
    }
    if (param_3 == 0) break;
    param_1 = ~param_1;
    uVar2 = uVar2 + 1;
    if (1 < uVar2) {
      return 0;
    }
  }
  return 0;
}



undefined4 FUN_08064a0c(int *param_1,uint *param_2,undefined4 param_3,uint *param_4)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = *param_2;
  iVar3 = 0;
  uVar1 = *param_4;
  while (0xff < uVar2) {
    iVar3 = iVar3 + 1;
    uVar2 = uVar2 << 2 | uVar2 >> 0x1e;
    if (iVar3 == 0x10) {
      iVar3 = 0;
      switch(param_3) {
      case 0:
      case 0xe:
        uVar1 = uVar1 ^ 0x1c00000;
        uVar2 = ~uVar2;
        break;
      default:
switchD_08064a3f_caseD_1:
        FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
        return 1;
      case 2:
      case 4:
        uVar1 = uVar1 ^ 0xc00000;
        goto LAB_08064a7e;
      case 5:
      case 6:
        uVar1 = uVar1 ^ 0x600000;
        uVar2 = ~uVar2;
        break;
      case 10:
      case 0xb:
        uVar1 = uVar1 ^ 0x200000;
LAB_08064a7e:
        uVar2 = -uVar2;
        break;
      case 0xd:
      case 0xf:
        uVar1 = uVar1 ^ 0x400000;
        uVar2 = ~uVar2;
      }
      if (uVar2 < 0x100) break;
      do {
        iVar3 = iVar3 + 1;
        uVar2 = uVar2 << 2 | uVar2 >> 0x1e;
        if (iVar3 == 0x10) goto switchD_08064a3f_caseD_1;
      } while (0xff < uVar2);
    }
  }
  *param_1 = iVar3;
  *param_4 = uVar1;
  *param_2 = uVar2;
  return 0;
}



undefined4
FUN_08064acc(uint *param_1,uint *param_2,uint *param_3,uint *param_4,int *param_5,int *param_6,
            int param_7,uint param_8)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 0;
  for (uVar3 = param_8; uVar3 != 0; uVar3 = uVar3 & uVar3 - 1) {
    uVar2 = uVar2 + 1;
  }
  if (uVar2 < 0x11) {
    uVar2 = 0;
    do {
      if ((((param_8 & 3) != 0) || (param_8 == 0)) &&
         (iVar1 = FUN_080649c0(param_8 & 0xffffff00,param_2,0,param_4), iVar1 != 0)) {
        *param_6 = *param_6 + 0x800000;
        *param_2 = uVar2 + *param_2 & 0xf;
        *param_3 = param_8 & 0xff;
        *param_1 = uVar2;
        if (param_7 == 0) {
          iVar1 = *param_5 + 0x800000;
        }
        else {
          iVar1 = *param_5 + 0x1a00000;
        }
        goto LAB_08064bd8;
      }
      param_8 = param_8 << 2 | param_8 >> 0x1e;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x10);
  }
  else {
    if (param_7 == 0) {
      param_8 = param_8 - 1;
    }
    uVar2 = 0;
    do {
      if ((param_8 & 3) != 3) {
        iVar1 = FUN_080649c0(~param_8 & 0xffffff00,param_2,0,param_4);
        if (iVar1 != 0) {
          *param_6 = *param_6 + 0x400000;
          *param_2 = uVar2 + *param_2 & 0xf;
          *param_3 = ~param_8 & 0xff;
          *param_1 = uVar2;
          if (param_7 == 0) {
            iVar1 = *param_5 + 0x400000;
          }
          else {
            iVar1 = *param_5 + 0x1e00000;
          }
LAB_08064bd8:
          *param_5 = iVar1;
          return 0;
        }
      }
      param_8 = param_8 << 2 | param_8 >> 0x1e;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x10);
  }
  FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
  return 1;
}



undefined4 FUN_08064c08(char *param_1,int *param_2,int param_3,uint param_4,int *param_5)

{
  bool bVar1;
  uint uVar2;
  undefined *puVar3;
  uint *puVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined1 *puVar10;
  uint *puVar11;
  char *pcVar12;
  uint *local_8c;
  uint local_88;
  uint local_48;
  uint local_44;
  undefined4 local_40;
  undefined4 local_3c;
  uint local_38;
  undefined4 local_34;
  uint local_30;
  int local_2c;
  uint local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  puVar10 = &stack0xffffff68;
  bVar1 = false;
  while ((DAT_080826a0 & 3) != 0) {
    FUN_0805182c(0);
  }
  switch(param_3) {
  case 0:
    local_24 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_14 = param_4 >> 0x15 & 0xf;
    uVar6 = local_24;
    if (local_14 == 0xd) {
LAB_08064d7e:
      local_24 = 0;
    }
    else if ((local_14 == 0xf) || (local_14 - 8 < 4)) {
      if ((local_14 == 0xd) || (local_14 == 0xf)) goto LAB_08064d7e;
      uVar6 = 0;
    }
    else {
      local_24 = FUN_080679f0((int)param_1,param_2);
      *param_2 = *param_2 + 1;
    }
LAB_08064d8c:
    iVar5 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar5 == '#') {
      *param_2 = *param_2 + 1;
      local_c = FUN_080535b0(param_1,param_2,0,&local_8);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
        uVar2 = FUN_080535b0(param_1,param_2,0,&local_8);
        local_10 = uVar2;
        if (0xff < local_c) {
LAB_08066097:
          FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
          return 0;
        }
        if (((uVar2 & 1) != 0) || (local_10 = uVar2 >> 1, 0xf < local_10)) {
          pcVar12 = "Bad rotator";
          local_10 = uVar2;
          goto LAB_080661e8;
        }
      }
      else if (local_c < 0x100) {
        local_10 = 0;
      }
      else {
        iVar5 = FUN_08064a0c((int *)&local_10,&local_c,local_14,&param_4);
        if (iVar5 != 0) {
          return 0;
        }
      }
      param_4 = param_4 + 0x2000000 + local_10 * 0x100 + local_c;
    }
    else {
      iVar5 = FUN_080676d0(param_1,param_2,1);
      param_4 = param_4 + iVar5;
    }
    if (DAT_08080160 != 0) {
      return 0;
    }
    uVar6 = local_24 * 0x10000 + uVar6 * 0x1000 + param_4;
    puVar10 = &stack0xffffff68;
    break;
  case 1:
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar8 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar8 != '[') {
      if (((param_1[*param_2] == '=') && (DAT_080825c4 == 0)) ||
         ((param_1[*param_2] == '#' && (DAT_080825c4 == 1)))) {
        if ((param_4 & 0xc000000) != 0x4000000) {
          pcVar12 = "Halfword literal values not supported";
          goto LAB_080661e8;
        }
        *param_2 = *param_2 + 1;
        puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_14,(uint *)0x0);
        *param_5 = (int)puVar3;
        local_24 = 0xf;
        if (puVar3 == (undefined *)0x0) {
          local_18 = 0;
          local_14 = FUN_08053738(param_1,param_2,&local_1c,0,&local_8,&local_18);
          if (DAT_08080160 != 0) {
            return 0;
          }
          if (((param_4 & 0x400000) != 0) && ((local_1c != 1 || (0xff < local_14)))) {
            pcVar12 = "Operand to LDRB does not fit in 8 bits";
            goto LAB_080661e8;
          }
          if (local_1c == 3) {
            if (local_18 != 0) {
              local_14 = local_14 | 1;
            }
            local_c = FUN_08056c4c(local_14,1,-0xfff,0xfff);
          }
          else {
            iVar8 = FUN_080649c0(local_14,&local_c,1,&local_20);
            if (iVar8 != 0) {
              param_4 = iVar5 * 0x1000 + 0x3a00000 + (param_4 & 0xf0000000);
              local_c = local_14;
              local_14 = 0xd;
              puVar10 = &stack0xffffff58;
              local_8 = FUN_08064a0c((int *)&local_10,&local_c,0xd,&param_4);
              uVar6 = local_10 << 8 | param_4 | local_c;
              break;
            }
            local_c = FUN_08056bec(1,0,local_14,-0xfff,0xfff);
          }
        }
        else {
          local_c = FUN_08056c1c((uint)puVar3,local_14,-0xfff,0xfff);
        }
      }
      else {
        if ((param_4 & 0xc000000) != 0x4000000) {
          param_4 = param_4 | 0x400000;
        }
        puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
        *param_5 = (int)puVar3;
        if (puVar3 == (undefined *)0x0) {
          local_c = FUN_08053a28(param_1,param_2,&local_24,0,&local_8);
          if (0xff < local_24) goto LAB_080653f7;
        }
        else {
          local_24 = 0xf;
LAB_080653f7:
          if (DAT_08082654 != 0) {
            pcVar12 = "a.out can\'t handle external adresses except for branches";
            goto LAB_080661e8;
          }
          if (local_24 == 0xf) {
            iVar8 = *param_5;
            if ((*(byte *)(iVar8 + 8) & 3) == 1) {
              uVar6 = *(uint *)(iVar8 + 0x18) & 0xffffff | 0x8f000000;
            }
            else {
              uVar6 = *(int *)(iVar8 + 0x1c) - 1U | 0x87000000;
            }
          }
          else {
            local_24 = local_24 & 0xf;
            uVar6 = (&DAT_08082720)[local_24] - 1 | 0x93000000;
          }
          FUN_080514cc(DAT_080826a0,uVar6,0);
        }
        if (DAT_08080160 != 0) {
          return 0;
        }
      }
      uVar6 = param_4 | 0x1000000;
      if (local_24 == 0xf) {
        local_c = (local_c - 8) - DAT_080826a0;
      }
      local_88 = local_c;
      if ((int)local_c < 0) {
        local_88 = -local_c;
      }
      if ((param_4 & 0xc000000) == 0x4000000) {
        if ((int)local_88 < 0x1000) {
LAB_080654f1:
          if (local_c < 0x1000) {
            uVar6 = param_4 | 0x1800000;
          }
          param_4 = uVar6;
          if ((int)local_c < 0) {
            local_c = -local_c;
          }
          if (param_1[*param_2] == '!') {
            *param_2 = *param_2 + 1;
            goto LAB_08065524;
          }
          goto LAB_08065528;
        }
      }
      else if ((int)local_88 < 0x100) goto LAB_080654f1;
LAB_080661e3:
      param_4 = uVar6;
      pcVar12 = "Data transfer offset out of range";
LAB_080661e8:
      FUN_08052f1c(4,pcVar12);
      return 0;
    }
    *param_2 = *param_2 + 1;
    local_24 = FUN_080679f0((int)param_1,param_2);
    iVar8 = *param_2;
    if (param_1[iVar8] == ']') {
      *param_2 = iVar8 + 1;
      iVar8 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar8 == ',') {
        *param_2 = *param_2 + 1;
        iVar8 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar8 == '#') {
          if ((param_4 & 0xc000000) != 0x4000000) {
            param_4 = param_4 | 0x400000;
          }
          *param_2 = *param_2 + 1;
          local_c = FUN_080535b0(param_1,param_2,0,&local_8);
          if (DAT_08080160 != 0) {
            return 0;
          }
          uVar2 = local_c;
          if ((int)local_c < 0) {
            uVar2 = -local_c;
          }
          uVar6 = param_4;
          if ((param_4 & 0xc000000) == 0x4000000) {
            if (0xfff < (int)uVar2) goto LAB_080661e3;
          }
          else if (0xff < (int)uVar2) goto LAB_080661e3;
          if (local_c < 0x1000) {
            param_4 = param_4 | 0x800000;
          }
          if ((int)local_c < 0) {
            local_c = -local_c;
          }
        }
        else {
          if ((param_4 & 0xc000000) == 0x4000000) {
            param_4 = param_4 | 0x2000000;
          }
          iVar8 = *param_2;
          if (param_1[iVar8] == '+') {
            *param_2 = iVar8 + 1;
LAB_08065039:
            param_4 = param_4 | 0x800000;
          }
          else {
            if (param_1[iVar8] != '-') goto LAB_08065039;
            *param_2 = iVar8 + 1;
          }
          if ((param_4 & 0xc000000) == 0x4000000) {
            local_c = FUN_080676d0(param_1,param_2,0);
          }
          else {
            local_c = FUN_080679f0((int)param_1,param_2);
          }
        }
      }
      else {
        uVar6 = param_4 | 0x800000;
        if (param_1[*param_2] == '!') {
          *param_2 = *param_2 + 1;
        }
        else if ((param_4 & 0x200000) == 0) {
          if ((param_4 & 0xc000000) == 0x4000000) {
            uVar6 = param_4 | 0x1800000;
          }
          else {
            uVar6 = param_4 | 0x1c00000;
          }
        }
        param_4 = uVar6;
        local_c = 0;
      }
    }
    else {
      param_4 = param_4 | 0x1000000;
      *param_2 = iVar8 + 1;
      iVar8 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar8 == '#') {
        if ((param_4 & 0xc000000) != 0x4000000) {
          param_4 = param_4 | 0x400000;
        }
        *param_2 = *param_2 + 1;
        local_c = FUN_080535b0(param_1,param_2,0,&local_8);
        if (DAT_08080160 != 0) {
          return 0;
        }
        local_88 = local_c;
        if ((int)local_c < 0) {
          local_88 = -local_c;
        }
        uVar6 = param_4;
        if ((param_4 & 0xc000000) == 0x4000000) {
          if ((int)local_88 < 0x1000) {
LAB_08065120:
            if (local_c < 0x1000) {
              param_4 = param_4 | 0x800000;
            }
            if ((int)local_c < 0) {
              local_c = -local_c;
            }
            goto LAB_080651ad;
          }
        }
        else if ((int)local_88 < 0x100) goto LAB_08065120;
        goto LAB_080661e3;
      }
      if ((param_4 & 0xc000000) == 0x4000000) {
        param_4 = param_4 | 0x2000000;
      }
      iVar8 = *param_2;
      if (param_1[iVar8] == '+') {
        *param_2 = iVar8 + 1;
LAB_08065178:
        param_4 = param_4 | 0x800000;
      }
      else {
        if (param_1[iVar8] != '-') goto LAB_08065178;
        *param_2 = iVar8 + 1;
      }
      if ((param_4 & 0xc000000) == 0x4000000) {
        local_c = FUN_080676d0(param_1,param_2,0);
      }
      else {
        local_c = FUN_080679f0((int)param_1,param_2);
      }
LAB_080651ad:
      *param_2 = *param_2 + 1;
      iVar8 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar8 != '!') goto LAB_08065528;
      *param_2 = *param_2 + 1;
LAB_08065524:
      param_4 = param_4 | 0x200000;
    }
LAB_08065528:
    uVar6 = local_24 << 0x10 | iVar5 << 0xc | param_4;
    if ((uVar6 & 0xc000000) == 0x4000000) {
      param_4 = uVar6 | local_c;
    }
    else if ((uVar6 & 0x400000) == 0) {
      param_4 = uVar6 | local_c;
    }
    else {
      param_4 = uVar6 | local_c & 0xf | (local_c & 0xf0) << 4;
    }
    puVar11 = (uint *)&stack0xffffff64;
    goto LAB_080664d7;
  case 2:
    puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_14,(uint *)0x0);
    *param_5 = (int)puVar3;
    if (puVar3 == (undefined *)0x0) {
      local_14 = FUN_080535b0(param_1,param_2,0,&local_8);
    }
    else {
      if (DAT_08082654 != 0) {
        pcVar12 = "a.out can\'t handle external adresses except for branches";
        goto LAB_080661e8;
      }
      FUN_080514cc(DAT_080826a0,*(uint *)(puVar3 + 0x18) & 0xffffff | 0x8a000000,0);
    }
    if (0xffffff < local_14) goto LAB_08066097;
    uVar6 = local_14 + param_4;
    break;
  case 3:
    local_24 = FUN_080679f0((int)param_1,param_2);
    iVar5 = *param_2;
    if (param_1[iVar5] == '!') {
      *param_2 = iVar5 + 1;
      FUN_0805fa50((int)param_1,param_2);
      param_4 = param_4 | 0x200000;
      iVar5 = *param_2;
    }
    *param_2 = iVar5 + 1;
    FUN_0805fa50((int)param_1,param_2);
    local_14 = FUN_08067bdc((int)param_1,param_2);
    if (param_1[*param_2] == '^') {
      *param_2 = *param_2 + 1;
      param_4 = param_4 | 0x400000;
    }
    if ((DAT_08079800 != 0) && ((param_4 & 0x100000) != 0)) {
      if (DAT_080826a0 == DAT_08079870 + 4) {
        FUN_08051c18(0xe1a00000);
      }
      DAT_08079870 = DAT_080826a0;
    }
    uVar6 = local_24 * 0x10000 + param_4 + local_14;
    puVar10 = &stack0xffffff68;
    break;
  case 4:
  case 0x30:
    local_2c = 0;
    local_30 = (uint)(param_3 == 0x30);
    local_1c = 0;
    if (param_3 == 0x30) {
      FUN_08067968(param_1,param_2,(int *)&local_14,&local_30,&local_2c,param_5);
      if (local_2c != 0) {
        puVar11 = (uint *)&stack0xffffff64;
        goto LAB_080664d7;
      }
      param_4 = 0xfa000000;
    }
    else {
      puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_14,&local_30);
      *param_5 = (int)puVar3;
    }
    local_8c = &local_30;
    if (*param_5 == 0) {
      local_14 = FUN_08053738(param_1,param_2,&local_1c,0,&local_8,local_8c);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (local_1c == 1) {
        puVar4 = FUN_0805f5ec(**(uint **)(DAT_0808014c + 0x18),
                              (char *)(*(uint **)(DAT_0808014c + 0x18))[1],0);
        *param_5 = (int)puVar4;
      }
    }
    if ((((*(byte *)(DAT_0808014c + 5) & 1) == 0) || (local_1c != 1)) &&
       (iVar5 = *param_5, iVar5 != 0)) {
      if (DAT_08082654 == 0) {
        local_38 = DAT_080826a0;
        if ((*(byte *)(iVar5 + 8) & 3) == 1) {
          local_34 = *(uint *)(iVar5 + 0x18) & 0xffffff | 0x8f000000;
        }
        else {
          local_34 = *(int *)(iVar5 + 0x1c) - 1U | 0x87000000;
        }
        local_14 = (local_14 - 8) + (*(int *)(DAT_0808014c + 0x10) - DAT_080826a0);
      }
      else {
        local_40 = 0;
        local_3c = 0;
        local_38 = DAT_080826a0;
        local_14 = local_14 - 8;
        if ((*(byte *)(iVar5 + 8) & 3) == 1) {
          local_34._0_3_ = (undefined3)*(undefined4 *)(iVar5 + 0x18);
          local_34._3_1_ = 0xe;
        }
        else {
          local_34._0_3_ = 0;
          local_34._3_1_ = 7;
          local_14 = local_14 + (DAT_08082664 - DAT_080826a0);
          if (DAT_080825c4 == 0) {
            iVar5 = FUN_08051d60(*(uint *)(iVar5 + 0x1c));
            if ((*(byte *)(iVar5 + 5) & 0x10) == 0) {
              local_34._0_3_ = 6;
            }
            else {
              local_34._0_3_ = 8;
            }
            if ((*(byte *)(iVar5 + 5) & 0x10) != 0) {
LAB_08065a8d:
              local_14 = local_14 + DAT_08082668;
            }
          }
          else {
            if (*(int *)(iVar5 + 0x1c) == 2) {
              local_34._0_3_ = 8;
            }
            else {
              local_34._0_3_ = 6;
            }
            local_34._3_1_ = 7;
            if (*(int *)(*param_5 + 0x1c) == 2) goto LAB_08065a8d;
          }
        }
        local_34 = CONCAT13(local_34._3_1_,(undefined3)local_34) & 0xefffffff;
      }
      FUN_080514cc(local_38,local_34,0);
    }
    else {
      local_14 = (local_14 - 8) - DAT_080826a0;
    }
    if (param_4 == 0xfa000000) {
      if (local_30 == 0) {
        pcVar12 = "BLX from 32 bit code to 32 bit code, use BL";
        goto LAB_080661e8;
      }
    }
    else if (local_30 != 0) {
      pcVar12 = "B or BL from 32 bit code to 16 bit code";
      goto LAB_080661e8;
    }
    uVar6 = local_14;
    if ((int)local_14 < 0) {
      uVar6 = -local_14;
    }
    if (0x4000000 < uVar6) {
      pcVar12 = "Branch offset out of range";
      goto LAB_080661e8;
    }
    if ((param_4 & 0xfe000000) != 0xfa000000) {
      if ((local_14 & 3) != 0) {
        FUN_08052f1c(4,"Branch to unaligned destination");
      }
      uVar6 = local_14 + 3 >> 2 & 0xffffff;
      local_8c = (uint *)param_4;
      goto LAB_080664d0;
    }
    if ((local_14 & 1) != 0) {
      FUN_08052f1c(4,"Branch to unaligned destination");
    }
    uVar6 = (local_14 + 1 >> 2 & 0xffffff) + param_4 + (local_14 + 1 & 2) * 0x800000;
    puVar10 = &stack0xffffff68;
    break;
  case 5:
    local_28 = 0;
    param_4 = FUN_080535b0(param_1,param_2,0,&local_8);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
    }
    local_1c = 0;
    puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_14,&local_28);
    *param_5 = (int)puVar3;
    if (puVar3 == (undefined *)0x0) {
      local_14 = FUN_08053738(param_1,param_2,&local_1c,0,&local_8,&local_28);
      if (DAT_08080160 != 0) {
        return 0;
      }
      if (local_1c == 1) {
        puVar4 = FUN_0805f5ec(**(uint **)(DAT_0808014c + 0x18),
                              (char *)(*(uint **)(DAT_0808014c + 0x18))[1],0);
        *param_5 = (int)puVar4;
      }
    }
    if ((((*(byte *)(DAT_0808014c + 5) & 1) == 0) || (local_1c != 1)) &&
       (iVar5 = *param_5, iVar5 != 0)) {
      if ((*(byte *)(iVar5 + 8) & 3) == 1) {
        uVar6 = *(ushort *)(iVar5 + 0x18) | 0xf0000;
      }
      else {
        uVar6 = *(int *)(iVar5 + 0x1c) - 1U | 0x70000;
      }
      local_14 = local_14 + 8;
      FUN_080514cc(DAT_080826a0,uVar6,0);
    }
    else {
      local_14 = local_14 - DAT_080826a0;
    }
    uVar6 = local_14;
    if ((int)local_14 < 0) {
      uVar6 = -local_14;
    }
    if (0x4000000 < uVar6) {
      pcVar12 = "Branch offset out of range";
      goto LAB_080661e8;
    }
    if ((local_14 & 3) != 0) {
      FUN_08052f1c(4,"Branch to unaligned destination");
    }
    puVar11 = (uint *)&stack0xffffff64;
    goto LAB_080664d7;
  case 6:
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
    *param_5 = (int)puVar3;
    if (puVar3 == (undefined *)0x0) {
      local_c = FUN_0805384c(param_1,param_2,&local_24,&local_1c,0,&local_8);
    }
    else {
      bVar1 = true;
      local_1c = 3;
      if (DAT_08082654 != 0) {
        pcVar12 = "a.out can\'t handle external adresses except for branches";
        goto LAB_080661e8;
      }
      if ((puVar3[8] & 3) == 1) {
        pcVar12 = 
        "%s of external symbol will cause link-time failure if symbol is not close enough to this instruction"
        ;
      }
      else {
        pcVar12 = 
        "%s of symbol in another AREA will cause link-time failure if symbol is not close enough to this instruction"
        ;
      }
      FUN_08052f1c(3,pcVar12);
      iVar8 = *param_5;
      if ((*(byte *)(iVar8 + 8) & 3) == 1) {
        uVar6 = *(uint *)(iVar8 + 0x18) & 0xffffff | 0xaf000000;
      }
      else {
        uVar6 = *(int *)(iVar8 + 0x1c) - 1U | 0xa7000000;
      }
      local_c = (local_c - 8) - DAT_080826a0;
      FUN_080514cc(DAT_080826a0,uVar6,0);
    }
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (local_1c == 3) {
LAB_08065cc7:
      param_4 = param_4 | 0x8f0000;
      local_14 = 4;
      if (!bVar1) {
        local_c = (local_c - 8) - DAT_080826a0;
      }
    }
    else if (local_1c < 4) {
      if (local_1c == 1) goto LAB_08065cc7;
    }
    else if (local_1c == 4) {
      param_4 = param_4 | 0x800000 | local_24 << 0x10;
      local_14 = 4;
    }
    iVar8 = FUN_08064a0c((int *)&local_10,&local_c,local_14,&param_4);
    if (iVar8 != 0) {
      return 0;
    }
    uVar6 = local_10 * 0x100 + param_4 + local_c + iVar5 * 0x1000;
    puVar10 = &stack0xffffff68;
    break;
  case 7:
    puVar11 = (uint *)&stack0xffffff64;
    goto LAB_080664d7;
  case 8:
    FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_24 = FUN_080679f0((int)param_1,param_2);
    puVar11 = (uint *)&stack0xffffff54;
    goto LAB_080664d7;
  case 9:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x19:
  case 0x1a:
  case 0x1b:
    iVar5 = FUN_080682a0(param_1,param_2,param_3,param_4);
    goto LAB_08065f95;
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x18:
    iVar5 = FUN_0806bc80(param_1,param_2,param_3,param_4);
LAB_08065f95:
    if (iVar5 != 0) {
      return 1;
    }
    return 0;
  case 0x1c:
    iVar5 = FUN_08067b48((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar8 = FUN_08067ab4((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar9 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar9 == '[') {
      *param_2 = *param_2 + 1;
      local_24 = FUN_080679f0((int)param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      iVar9 = *param_2;
      if (param_1[iVar9] == ']') {
        *param_2 = iVar9 + 1;
        iVar9 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar9 == ',') {
          *param_2 = *param_2 + 1;
          iVar9 = FUN_0805fa50((int)param_1,param_2);
          *param_2 = *param_2 + 1;
          local_c = FUN_080535b0(param_1,param_2,0,&local_8);
          if (DAT_08080160 != 0) {
            return 0;
          }
          if ((char)iVar9 != '{') {
            uVar2 = local_c;
            if ((int)local_c < 0) {
              uVar2 = -local_c;
            }
            uVar6 = param_4;
            if (((int)uVar2 < 0x400) && ((local_c & 3) == 0)) {
              if (local_c < 0x400) {
                param_4 = param_4 | 0x800000;
              }
              if ((int)local_c < 0) {
                local_c = -local_c;
              }
              if ((int)local_c < 0) {
                local_c = local_c + 3;
              }
              local_c = (int)local_c >> 2;
              goto LAB_0806622e;
            }
            goto LAB_080661e3;
          }
          FUN_0805fa50((int)param_1,param_2);
          *param_2 = *param_2 + 1;
          if (0xff < local_c) goto LAB_08066097;
          param_4 = param_4 | 0x800000;
        }
        else {
          uVar6 = param_4 | 0x1800000;
          if (param_1[*param_2] == '!') {
            *param_2 = *param_2 + 1;
            uVar6 = param_4 | 0x1a00000;
          }
          param_4 = uVar6;
          local_c = 0;
        }
      }
      else {
        param_4 = param_4 | 0x1000000;
        *param_2 = iVar9 + 1;
        FUN_0805fa50((int)param_1,param_2);
        *param_2 = *param_2 + 1;
        local_c = FUN_080535b0(param_1,param_2,0,&local_8);
        if (DAT_08080160 != 0) {
          return 0;
        }
        uVar2 = local_c;
        if ((int)local_c < 0) {
          uVar2 = -local_c;
        }
        uVar6 = param_4;
        if ((0x3ff < (int)uVar2) || ((local_c & 3) != 0)) goto LAB_080661e3;
        if (local_c < 0x400) {
          param_4 = param_4 | 0x800000;
        }
        if ((int)local_c < 0) {
          local_c = -local_c;
        }
        if ((int)local_c < 0) {
          local_c = local_c + 3;
        }
        local_c = (int)local_c >> 2;
        *param_2 = *param_2 + 1;
        iVar9 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar9 == '!') {
          *param_2 = *param_2 + 1;
          goto LAB_0806622e;
        }
      }
    }
    else {
      local_c = FUN_08053a28(param_1,param_2,&local_24,0,&local_8);
      if (DAT_08080160 != 0) {
        return 0;
      }
      uVar6 = param_4 | 0x1000000;
      if (local_24 == 0xf) {
        local_c = (local_c - 8) - DAT_080826a0;
      }
      uVar2 = local_c;
      if ((int)local_c < 0) {
        uVar2 = -local_c;
      }
      if ((0x3ff < (int)uVar2) || ((local_c & 3) != 0)) goto LAB_080661e3;
      if (local_c < 0x400) {
        uVar6 = param_4 | 0x1800000;
      }
      param_4 = uVar6;
      if ((int)local_c < 0) {
        local_c = -local_c;
      }
      if ((int)local_c < 0) {
        local_c = local_c + 3;
      }
      local_c = (int)local_c >> 2;
      if (param_1[*param_2] == '!') {
        *param_2 = *param_2 + 1;
LAB_0806622e:
        param_4 = param_4 | 0x200000;
      }
    }
    uVar6 = local_c + param_4 + local_24 * 0x10000 + iVar8 * 0x1000 + iVar5 * 0x100;
    puVar10 = &stack0xffffff68;
    break;
  case 0x1d:
    iVar5 = FUN_08067b48((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar8 = FUN_080535b0(param_1,param_2,0,&local_8);
    param_4 = param_4 | iVar8 << 0x14;
    *param_2 = *param_2 + 1;
    iVar8 = FUN_08067ab4((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_24 = FUN_08067ab4((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar9 = FUN_08067ab4((int)param_1,param_2);
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      iVar7 = FUN_080535b0(param_1,param_2,0,&local_8);
      param_4 = param_4 | iVar7 << 5;
    }
    uVar6 = local_24 * 0x10000 + param_4 + iVar9 + iVar8 * 0x1000 + iVar5 * 0x100;
    puVar10 = &stack0xffffff68;
    break;
  case 0x1e:
    iVar5 = FUN_08067b48((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar8 = FUN_080535b0(param_1,param_2,0,&local_8);
    param_4 = param_4 | iVar8 << 0x15;
    *param_2 = *param_2 + 1;
    iVar8 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_24 = FUN_08067ab4((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar9 = FUN_08067ab4((int)param_1,param_2);
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      iVar7 = FUN_080535b0(param_1,param_2,0,&local_8);
      param_4 = param_4 | iVar7 << 5;
    }
    uVar6 = local_24 * 0x10000 + param_4 + iVar9 + iVar8 * 0x1000 + iVar5 * 0x100;
    puVar10 = &stack0xffffff68;
    break;
  case 0x1f:
  case 0x28:
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_24 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar8 = FUN_080679f0((int)param_1,param_2);
    uVar6 = iVar8 * 0x100 + iVar5 * 0x10000 + param_4 + local_24;
    puVar10 = &stack0xffffff50;
    break;
  case 0x20:
  case 0x29:
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_24 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar8 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_14 = FUN_080679f0((int)param_1,param_2);
    uVar6 = iVar8 * 0x100 + iVar5 * 0x10000 + param_4 + local_24 + local_14 * 0x1000;
    puVar10 = &stack0xffffff68;
    break;
  case 0x21:
    param_4 = param_4 & 0xfff0ffff;
    local_44 = param_4;
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_14,(uint *)0x0);
    *param_5 = (int)puVar3;
    if (puVar3 == (undefined *)0x0) {
      local_14 = FUN_0805384c(param_1,param_2,&local_24,&local_1c,0,&local_8);
    }
    else {
      bVar1 = true;
      local_1c = 3;
      if (DAT_08082654 != 0) {
        pcVar12 = "a.out can\'t handle external adresses except for branches";
        goto LAB_080661e8;
      }
      if ((puVar3[8] & 3) == 1) {
        pcVar12 = 
        "%s of external symbol will cause link-time failure if symbol is not close enough to this instruction"
        ;
      }
      else {
        pcVar12 = 
        "%s of symbol in another AREA will cause link-time failure if symbol is not close enough to this instruction"
        ;
      }
      FUN_08052f1c(3,pcVar12);
      iVar8 = *param_5;
      if ((*(byte *)(iVar8 + 8) & 3) == 1) {
        uVar6 = *(uint *)(iVar8 + 0x18) & 0xffffff | 0xcf000000;
      }
      else {
        uVar6 = *(int *)(iVar8 + 0x1c) - 1U | 0xc7000000;
      }
      local_14 = (local_14 - 8) - DAT_080826a0;
      FUN_080514cc(DAT_080826a0,uVar6,0);
    }
    if (DAT_08080160 != 0) {
      return 0;
    }
    if ((local_1c == 3) || ((local_1c < 4 && (local_1c == 1)))) {
      if (!bVar1) {
        local_14 = (local_14 - 8) - DAT_080826a0;
      }
      local_24 = 0xf;
    }
    iVar8 = FUN_08064acc(&local_10,&local_48,&local_c,&local_20,(int *)&param_4,(int *)&local_44,0,
                         local_14);
    if (iVar8 != 0) {
      return 0;
    }
    FUN_08051c18(local_10 << 8 | param_4 | local_c & 0xff | iVar5 << 0xc | local_24 << 0x10);
    puVar11 = (uint *)&stack0xffffff60;
    goto LAB_080664d7;
  case 0x22:
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    FUN_0805fa50((int)param_1,param_2);
    local_24 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    FUN_0805fa50((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar8 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    uVar6 = local_24 + param_4 + iVar8 * 0x10000 + iVar5 * 0x1000;
    puVar10 = &stack0xffffff60;
    break;
  case 0x23:
    if ((param_4 & 0xfffffff) != 0x1000000) {
      local_14 = FUN_08067460((int)param_1,param_2,0x1200000);
      if ((local_14 & 2) != 0) {
        param_4 = param_4 | 0x400000;
      }
      *param_2 = *param_2 + 1;
      uVar6 = 0xf;
      local_24 = local_14 >> 2;
      goto LAB_08064d8c;
    }
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    uVar6 = FUN_08067460((int)param_1,param_2,0x1000000);
    if ((uVar6 & 2) != 0) {
      param_4 = param_4 | 0x400000;
    }
    uVar6 = iVar5 * 0x1000 + param_4 + 0xf0000;
    puVar10 = &stack0xffffff68;
    break;
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x27:
  case 0x2a:
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar8 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_24 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar9 = FUN_080679f0((int)param_1,param_2);
    uVar6 = iVar5 * 0x1000 + iVar8 * 0x10000 + param_4 + local_24;
    local_8c = (uint *)(iVar9 << 8);
LAB_080664d0:
    uVar6 = uVar6 + (int)local_8c;
    puVar10 = &stack0xffffff68;
    break;
  case 0x2b:
  case 0x2c:
    iVar5 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_24 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_8c = (uint *)FUN_080679f0((int)param_1,param_2);
    if (param_3 != 0x2c) {
      uVar6 = local_24 * 0x10000 + iVar5 * 0x1000 + param_4;
      goto LAB_080664d0;
    }
    uVar6 = (int)local_8c * 0x10000 + iVar5 * 0x1000 + param_4 + local_24;
    puVar10 = &stack0xffffff68;
    break;
  case 0x2d:
    FUN_080679f0((int)param_1,param_2);
    puVar11 = (uint *)&stack0xffffff5c;
    goto LAB_080664d7;
  default:
    goto switchD_08064c50_caseD_2e;
  }
  puVar11 = (uint *)(puVar10 + -4);
  *(uint *)(puVar10 + -4) = uVar6;
LAB_080664d7:
  puVar11[-1] = 0x80664dc;
  FUN_08051c18(*puVar11);
switchD_08064c50_caseD_2e:
  return 1;
}



undefined4 FUN_080664f0(int param_1,undefined1 *param_2)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  undefined4 uVar4;
  
  uVar4 = 0xffffffff;
  pcVar2 = param_2 + 1;
  switch(*param_2) {
  case 0x41:
    if (1 < param_1) {
      if (*pcVar2 == 'D') {
        if (2 < param_1) {
          cVar1 = param_2[2];
          if (cVar1 == 'D') {
            uVar4 = 1;
          }
          else if (cVar1 < 'E') {
            if (cVar1 == 'C') {
              uVar4 = 0;
            }
          }
          else if (cVar1 == 'R') {
            uVar4 = 2;
          }
        }
      }
      else if (((*pcVar2 == 'N') && (2 < param_1)) && (param_2[2] == 'D')) {
        uVar4 = 3;
      }
    }
    break;
  case 0x42:
    uVar4 = 4;
    if (1 < param_1) {
      cVar1 = *pcVar2;
      if (cVar1 == 'L') {
        uVar4 = 6;
        if ((2 < param_1) && (param_2[2] == 'X')) {
          uVar4 = 7;
        }
      }
      else if (cVar1 < 'M') {
        if (((cVar1 == 'I') && (2 < param_1)) && (param_2[2] == 'C')) {
          uVar4 = 5;
        }
      }
      else if (cVar1 == 'X') {
        uVar4 = 8;
      }
    }
    break;
  case 0x43:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'L') {
        if ((2 < param_1) && (*pcVar2 == 'Z')) {
          uVar4 = 10;
        }
      }
      else if (cVar1 < 'M') {
        if (((cVar1 == 'D') && (2 < param_1)) && (*pcVar2 == 'P')) {
          uVar4 = 9;
        }
      }
      else if ((cVar1 == 'M') && (2 < param_1)) {
        if (*pcVar2 == 'N') {
          uVar4 = 0xb;
        }
        else if (*pcVar2 == 'P') {
          uVar4 = 0xc;
        }
      }
    }
    break;
  case 0x45:
    if (((1 < param_1) && (*pcVar2 == 'O')) && ((2 < param_1 && (param_2[2] == 'R')))) {
      uVar4 = 0xd;
    }
    break;
  case 0x4c:
    if (1 < param_1) {
      if (*pcVar2 == 'D') {
        if (2 < param_1) {
          cVar1 = param_2[2];
          if (cVar1 == 'M') {
            uVar4 = 0xf;
          }
          else if (cVar1 < 'N') {
            if (cVar1 == 'C') {
              uVar4 = 0xe;
            }
          }
          else if (cVar1 == 'R') {
            uVar4 = 0x10;
          }
          else if (cVar1 == 'S') {
            uVar4 = 0x11;
          }
        }
      }
      else if (((*pcVar2 == 'E') && (2 < param_1)) && (param_2[2] == 'A')) {
        uVar4 = 0x12;
      }
    }
    break;
  case 0x4d:
    if (1 < param_1) {
      pcVar3 = param_2 + 2;
      switch(*pcVar2) {
      case 'C':
        if ((2 < param_1) && (*pcVar3 == 'R')) {
          uVar4 = 0x13;
        }
        break;
      case 'L':
        if ((2 < param_1) && (*pcVar3 == 'A')) {
          uVar4 = 0x14;
        }
        break;
      case 'O':
        if ((2 < param_1) && (*pcVar3 == 'V')) {
          uVar4 = 0x15;
        }
        break;
      case 'R':
        if (2 < param_1) {
          if (*pcVar3 == 'C') {
            uVar4 = 0x16;
          }
          else if (*pcVar3 == 'S') {
            uVar4 = 0x17;
          }
        }
        break;
      case 'S':
        if ((2 < param_1) && (*pcVar3 == 'R')) {
          uVar4 = 0x18;
        }
        break;
      case 'U':
        if ((2 < param_1) && (*pcVar3 == 'L')) {
          uVar4 = 0x19;
        }
        break;
      case 'V':
        if ((2 < param_1) && (*pcVar3 == 'N')) {
          uVar4 = 0x1a;
        }
      }
    }
    break;
  case 0x4e:
    if (((1 < param_1) && (*pcVar2 == 'O')) && ((2 < param_1 && (param_2[2] == 'P')))) {
      uVar4 = 0x1b;
    }
    break;
  case 0x4f:
    if ((((1 < param_1) && (*pcVar2 == 'R')) && (2 < param_1)) && (param_2[2] == 'R')) {
      uVar4 = 0x1c;
    }
    break;
  case 0x51:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'D') {
        if (2 < param_1) {
          if (*pcVar2 == 'A') {
            if (((3 < param_1) && (param_2[3] == 'D')) && ((4 < param_1 && (param_2[4] == 'D')))) {
              uVar4 = 0x1e;
            }
          }
          else if (((*pcVar2 == 'S') && (3 < param_1)) &&
                  ((param_2[3] == 'U' && ((4 < param_1 && (param_2[4] == 'B')))))) {
            uVar4 = 0x21;
          }
        }
      }
      else if (cVar1 < 'E') {
        if (((cVar1 == 'A') && (2 < param_1)) &&
           ((*pcVar2 == 'D' && ((3 < param_1 && (param_2[3] == 'D')))))) {
          uVar4 = 0x1d;
        }
      }
      else if (cVar1 == 'M') {
        if (2 < param_1) {
          if (*pcVar2 == 'A') {
            uVar4 = 0x1f;
          }
          else if (*pcVar2 == 'L') {
            uVar4 = 0x20;
          }
        }
      }
      else if ((((cVar1 == 'S') && (2 < param_1)) && (*pcVar2 == 'U')) &&
              ((3 < param_1 && (param_2[3] == 'B')))) {
        uVar4 = 0x22;
      }
    }
    break;
  case 0x52:
    if (((1 < param_1) && (*pcVar2 == 'S')) && (2 < param_1)) {
      if (param_2[2] == 'B') {
        uVar4 = 0x23;
      }
      else if (param_2[2] == 'C') {
        uVar4 = 0x24;
      }
    }
    break;
  case 0x53:
    if (1 < param_1) {
      pcVar3 = param_2 + 2;
      switch(*pcVar2) {
      case 'B':
        if ((2 < param_1) && (*pcVar3 == 'C')) {
          uVar4 = 0x25;
        }
        break;
      case 'M':
        if (2 < param_1) {
          if (*pcVar3 == 'L') {
            if (((3 < param_1) && (param_2[3] == 'A')) && (4 < param_1)) {
              cVar1 = param_2[4];
              pcVar2 = param_2 + 5;
              if (cVar1 == 'L') {
                uVar4 = 0x2c;
                if (5 < param_1) {
                  if (*pcVar2 == 'B') {
                    if (6 < param_1) {
                      cVar1 = param_2[6];
                      if (cVar1 == 'B') {
                        uVar4 = 0x2d;
                      }
                      else if (cVar1 == 'T') {
                        uVar4 = 0x2e;
                      }
                    }
                  }
                  else if ((*pcVar2 == 'T') && (6 < param_1)) {
                    cVar1 = param_2[6];
                    if (cVar1 == 'B') {
                      uVar4 = 0x2f;
                    }
                    else if (cVar1 == 'T') {
                      uVar4 = 0x30;
                    }
                  }
                }
              }
              else if (cVar1 < 'M') {
                if ((cVar1 == 'B') && (5 < param_1)) {
                  if (*pcVar2 == 'B') {
                    uVar4 = 0x26;
                  }
                  else if (*pcVar2 == 'T') {
                    uVar4 = 0x27;
                  }
                }
              }
              else if (cVar1 == 'T') {
                if (5 < param_1) {
                  if (*pcVar2 == 'B') {
                    uVar4 = 0x28;
                  }
                  else if (*pcVar2 == 'T') {
                    uVar4 = 0x29;
                  }
                }
              }
              else if ((cVar1 == 'W') && (5 < param_1)) {
                if (*pcVar2 == 'B') {
                  uVar4 = 0x2a;
                }
                else if (*pcVar2 == 'T') {
                  uVar4 = 0x2b;
                }
              }
            }
          }
          else if ((((*pcVar3 == 'U') && (3 < param_1)) && (param_2[3] == 'L')) && (4 < param_1)) {
            cVar1 = param_2[4];
            pcVar2 = param_2 + 5;
            if (cVar1 == 'L') {
              uVar4 = 0x33;
            }
            else if (cVar1 < 'M') {
              if ((cVar1 == 'B') && (5 < param_1)) {
                if (*pcVar2 == 'B') {
                  uVar4 = 0x31;
                }
                else if (*pcVar2 == 'T') {
                  uVar4 = 0x32;
                }
              }
            }
            else if (cVar1 == 'T') {
              if (5 < param_1) {
                if (*pcVar2 == 'B') {
                  uVar4 = 0x34;
                }
                else if (*pcVar2 == 'T') {
                  uVar4 = 0x35;
                }
              }
            }
            else if ((cVar1 == 'W') && (5 < param_1)) {
              if (*pcVar2 == 'B') {
                uVar4 = 0x36;
              }
              else if (*pcVar2 == 'T') {
                uVar4 = 0x37;
              }
            }
          }
        }
        break;
      case 'T':
        if (2 < param_1) {
          cVar1 = *pcVar3;
          if (cVar1 == 'M') {
            uVar4 = 0x39;
          }
          else if (cVar1 < 'N') {
            if (cVar1 == 'C') {
              uVar4 = 0x38;
            }
          }
          else if (cVar1 == 'R') {
            uVar4 = 0x3a;
          }
        }
        break;
      case 'U':
        if ((2 < param_1) && (*pcVar3 == 'B')) {
          uVar4 = 0x3b;
        }
        break;
      case 'W':
        if (2 < param_1) {
          if (*pcVar3 == 'I') {
            uVar4 = 0x3c;
          }
          else if (*pcVar3 == 'P') {
            uVar4 = 0x3d;
          }
        }
      }
    }
    break;
  case 0x54:
    if (1 < param_1) {
      if (*pcVar2 == 'E') {
        if ((2 < param_1) && (param_2[2] == 'Q')) {
          uVar4 = 0x3e;
        }
      }
      else if (((*pcVar2 == 'S') && (2 < param_1)) && (param_2[2] == 'T')) {
        uVar4 = 0x3f;
      }
    }
    break;
  case 0x55:
    if (((1 < param_1) && (*pcVar2 == 'M')) && (2 < param_1)) {
      if (param_2[2] == 'L') {
        if (((3 < param_1) && (param_2[3] == 'A')) && ((4 < param_1 && (param_2[4] == 'L')))) {
          uVar4 = 0x40;
        }
      }
      else if (((param_2[2] == 'U') && (3 < param_1)) &&
              ((param_2[3] == 'L' && ((4 < param_1 && (param_2[4] == 'L')))))) {
        uVar4 = 0x41;
      }
    }
  }
  return uVar4;
}



undefined4 FUN_08066e98(int *param_1,int param_2)

{
  undefined4 uVar1;
  char *pcVar2;
  uint uVar3;
  
  pcVar2 = (char *)(*param_1 + param_2);
  uVar3 = (pcVar2[1] + -0x840 + *pcVar2 * 0x20) * 2 & 0x1f8;
  if ((*(char *)((int)&DAT_0807f8e0 + uVar3) == *pcVar2) &&
     (*(char *)((int)&DAT_0807f8e0 + uVar3 + 1) == pcVar2[1])) {
    *param_1 = *param_1 + 2;
    uVar1 = *(undefined4 *)((int)&DAT_0807f8e4 + uVar3);
  }
  else {
    uVar1 = 0xe0000000;
  }
  return uVar1;
}



undefined4 FUN_08066ef4(uint param_1,undefined1 *param_2,int *param_3,int *param_4)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint local_14;
  uint local_c;
  uint local_8;
  
  iVar3 = FUN_080664f0(param_1,param_2);
  if (iVar3 == -1) {
    return 0;
  }
  if ((iVar3 == 6) && (param_1 == 3)) {
    iVar3 = 4;
  }
  iVar4 = iVar3 * 0xc;
  local_14 = *(uint *)(&DAT_08079874 + iVar4);
  iVar7 = *(int *)(&DAT_0807987c + iVar4);
  uVar6 = *(uint *)(&DAT_08079878 + iVar4);
  local_c = uVar6 & 0xf0000000;
  if (local_c == 0) {
    if (param_1 < local_14 + 2) {
      local_c = 0xe0000000;
    }
    else {
      local_8 = local_14;
      local_c = FUN_08066e98((int *)&local_8,(int)param_2);
      local_14 = local_8;
    }
  }
  else {
    uVar6 = uVar6 & 0xfffffff;
  }
  if (param_1 - local_14 != 1) {
    if (param_1 == local_14) {
      if (iVar3 == 0x11) {
        return 0;
      }
      if (iVar3 < 0x12) {
        if (iVar3 == 0xf) {
          return 0;
        }
      }
      else if (iVar3 == 0x39) {
        return 0;
      }
      goto LAB_08067261;
    }
    if (param_1 - local_14 != 2) {
      return 0;
    }
    cVar1 = param_2[local_14];
    cVar2 = param_2[local_14 + 1];
    if (iVar7 != 1) {
      if (iVar7 != 3) {
        return 0;
      }
      if (cVar1 == 'E') {
        uVar5 = 0x1000000;
        if (cVar2 == 'D') {
          uVar5 = 0x1800000;
        }
        else if (cVar2 != 'A') {
          return 0;
        }
      }
      else {
        if (cVar1 < 'F') {
          if (cVar1 != 'D') {
            return 0;
          }
          if (cVar2 == 'B') {
            uVar6 = uVar6 + 0x1000000;
          }
          else if (cVar2 != 'A') {
            return 0;
          }
          goto LAB_08067261;
        }
        if (cVar1 != 'F') {
          if (cVar1 != 'I') {
            return 0;
          }
          if (cVar2 == 'B') {
            uVar6 = uVar6 + 0x1800000;
          }
          else {
            if (cVar2 != 'A') {
              return 0;
            }
            uVar6 = uVar6 + 0x800000;
          }
          goto LAB_08067261;
        }
        uVar5 = 0;
        if (cVar2 == 'D') {
          uVar5 = 0x800000;
        }
        else if (cVar2 != 'A') {
          return 0;
        }
      }
      if (iVar3 == 0x39) {
        uVar5 = uVar5 ^ 0x1800000;
      }
      uVar6 = uVar6 + uVar5;
      goto LAB_08067261;
    }
    if (((cVar1 == 'B') && (cVar2 == 'T')) && ((iVar3 == 0x10 || (iVar3 == 0x3a)))) {
      uVar6 = uVar6 + 0x600000;
      goto LAB_08067261;
    }
    if (iVar3 != 0x10) {
      return 0;
    }
    if ((DAT_080825f8 & 4) == 0) {
      return 2;
    }
    if (cVar1 != 'S') {
      return 0;
    }
    if (cVar2 == 'B') {
      uVar6 = 0x1000d0;
      goto LAB_08067261;
    }
    if (cVar2 != 'H') {
      return 0;
    }
LAB_080671b1:
    uVar6 = 0x1000f0;
    goto LAB_08067261;
  }
  cVar1 = param_2[local_14];
  switch(iVar7) {
  case 0:
    if (((iVar3 - 0x3eU < 2) || (iVar3 == 0xc)) || (iVar3 == 0xb)) {
      if (cVar1 == 'P') {
        uVar6 = uVar6 + 0xf000;
      }
      else if (cVar1 != 'S') {
        return 0;
      }
      goto LAB_08067261;
    }
    if (cVar1 != 'S') {
      return 0;
    }
    goto LAB_0806710a;
  case 1:
    if (cVar1 != 'H') {
      if (cVar1 == 'B') {
        if (iVar3 == 0x11) {
          if ((DAT_080825f8 & 4) == 0) {
            return 2;
          }
        }
        else if (iVar3 == 0x10) {
          uVar6 = 0x4500000;
        }
        else {
          if (iVar3 != 0x3a) {
            return 0;
          }
          uVar6 = 0x4400000;
        }
      }
      else {
        if (cVar1 != 'T') {
          return 0;
        }
        uVar6 = uVar6 + 0x200000;
      }
      goto LAB_08067261;
    }
    if ((DAT_080825f8 & 4) == 0) {
      return 2;
    }
    if (iVar3 != 0x11) {
      if (iVar3 == 0x10) {
        uVar6 = 0x1000b0;
      }
      else {
        if (iVar3 != 0x3a) {
          return 0;
        }
        uVar6 = 0xb0;
      }
      goto LAB_08067261;
    }
    goto LAB_080671b1;
  case 6:
    if (cVar1 == 'L') {
      uVar6 = 0x20f0000;
      iVar7 = 0x21;
      goto LAB_08067261;
    }
    break;
  case 0x1c:
    if (cVar1 == 'L') {
      uVar6 = uVar6 + 0x400000;
      goto LAB_08067261;
    }
    break;
  case 0x1f:
  case 0x20:
    goto joined_r0x08067104;
  case 0x22:
    if (cVar1 == 'B') {
      uVar6 = 0x1400090;
      goto LAB_08067261;
    }
    break;
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x27:
joined_r0x08067104:
    if (cVar1 == 'S') {
LAB_0806710a:
      uVar6 = uVar6 + 0x100000;
LAB_08067261:
      *param_3 = iVar7;
      *param_4 = uVar6 + local_c;
      return 1;
    }
  }
  return 0;
}



int FUN_0806727c(uint param_1,char *param_2,int *param_3,int *param_4)

{
  int iVar1;
  
  iVar1 = FUN_08066ef4(param_1,param_2,param_3,param_4);
  if (iVar1 == 0) {
    iVar1 = FUN_08068ff4(param_1,param_2,param_3,param_4);
    if (iVar1 == 0) {
      iVar1 = FUN_0806cfd4(param_1,param_2,param_3,param_4);
      if (iVar1 == 0) {
        iVar1 = 0;
      }
    }
  }
  return iVar1;
}



void FUN_080672cc(char *param_1,undefined4 param_2)

{
  uint uVar1;
  
  uVar1 = (param_1[1] + -0x840 + *param_1 * 0x20) * 2 & 0x1f8;
  if (*(char *)((int)&DAT_0807f8e0 + uVar1) != '\0') {
    FUN_08052f1c(1,"internal error: conditional clash at %s");
  }
  *(undefined4 *)((int)&DAT_0807f8e4 + uVar1) = param_2;
  *(char *)((int)&DAT_0807f8e0 + uVar1) = *param_1;
  *(char *)((int)&DAT_0807f8e0 + uVar1 + 1) = param_1[1];
  return;
}



void FUN_08067328(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = &DAT_0807f8e0;
  for (iVar1 = 0x80; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  FUN_080672cc("EQ",0);
  FUN_080672cc("NE",0x10000000);
  FUN_080672cc("CS",0x20000000);
  FUN_080672cc("CC",0x30000000);
  FUN_080672cc("MI",0x40000000);
  FUN_080672cc("PL",0x50000000);
  FUN_080672cc("VS",0x60000000);
  FUN_080672cc("VC",0x70000000);
  FUN_080672cc("HI",0x80000000);
  FUN_080672cc("LS",0x90000000);
  FUN_080672cc("GE",0xa0000000);
  FUN_080672cc("LT",0xb0000000);
  FUN_080672cc("GT",0xc0000000);
  FUN_080672cc("LE",0xd0000000);
  FUN_080672cc("AL",0xe0000000);
  FUN_080672cc("NV",0xf0000000);
  FUN_080672cc("HS",0x20000000);
  FUN_080672cc("LO",0x30000000);
  return;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

uint FUN_08067460(int param_1,int *param_2,int param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint local_c;
  char *local_8;
  
  FUN_0805fa50(param_1,param_2);
  iVar2 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if (iVar2 == 0) {
LAB_0806748b:
    uVar3 = 0;
  }
  else {
    iVar2 = strncmp(local_8,"CPSR",4);
    if ((iVar2 == 0) || (iVar2 = strncmp(local_8,"cpsr",4), iVar2 == 0)) {
      uVar3 = 1;
    }
    else {
      iVar2 = strncmp(local_8,"SPSR",4);
      if ((iVar2 != 0) && (iVar2 = strncmp(local_8,"spsr",4), iVar2 != 0)) {
        FUN_08052f1c(4,"Bad CPSR or SPSR designator");
        goto LAB_0806748b;
      }
      uVar3 = 2;
    }
    if (local_c == 4) {
      if ((DAT_080825d0 == 1) && (param_3 == 0x1200000)) {
        FUN_08052f1c(3,"Deprecated form of PSR field specifier used (use _cxsf)");
      }
      return uVar3 | 0x24;
    }
    iVar2 = strncmp(local_8 + 4,"_all",4);
    if (iVar2 == 0) {
      if (DAT_080825d0 != 1) {
        return uVar3 + 0x24;
      }
      if (param_3 != 0x1200000) {
        FUN_08052f1c(3,"MRS cannot select fields, use %.*s directly");
        return uVar3 + 0x24;
      }
    }
    else {
      if (param_3 == 0x1000000) {
        if (DAT_080825d0 == 1) {
          FUN_08052f1c(4,"MRS cannot select fields, use %.*s directly");
        }
        goto LAB_0806748b;
      }
      iVar2 = strncmp(local_8 + 4,"_ctl",4);
      if (iVar2 == 0) {
        if (DAT_080825d0 == 1) {
          FUN_08052f1c(3,"Deprecated form of PSR field specifier used (use _cxsf)");
        }
        return uVar3 + 4;
      }
      iVar2 = strncmp(local_8 + 4,"_flg",4);
      if (iVar2 == 0) {
        if (DAT_080825d0 == 1) {
          FUN_08052f1c(3,"Deprecated form of PSR field specifier used (use _cxsf)");
        }
        return uVar3 + 0x20;
      }
      iVar2 = strncmp(local_8 + 4,"_all",4);
      if (iVar2 != 0) {
        if (local_8[4] != '_') {
LAB_08067664:
          FUN_08052f1c(4,"Invalid PSR field specifier");
          return uVar3;
        }
        uVar5 = 5;
        if (local_c < 6) {
          return uVar3;
        }
        do {
          cVar1 = local_8[uVar5];
          if (cVar1 == 'f') {
            uVar4 = 0x20;
          }
          else if (cVar1 < 'g') {
            if (cVar1 != 'c') goto LAB_08067664;
            uVar4 = 4;
          }
          else if (cVar1 == 's') {
            uVar4 = 0x10;
          }
          else {
            if (cVar1 != 'x') goto LAB_08067664;
            uVar4 = 8;
          }
          uVar3 = uVar3 | uVar4;
          uVar5 = uVar5 + 1;
          if (local_c <= uVar5) {
            return uVar3;
          }
        } while( true );
      }
      if (DAT_080825d0 != 1) {
        return uVar3 + 0x24;
      }
    }
    uVar3 = uVar3 + 0x24;
    FUN_08052f1c(3,"Deprecated form of PSR field specifier used (use _cxsf)");
  }
  return uVar3;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

int FUN_080676d0(char *param_1,int *param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  uint local_18;
  uint local_14;
  int local_10;
  undefined1 *local_c;
  undefined1 local_8 [4];
  
  iVar1 = FUN_080679f0((int)param_1,param_2);
  if (DAT_08080160 == 0) {
    if (param_1[*param_2] != ',') {
      return iVar1;
    }
    *param_2 = *param_2 + 1;
    FUN_0805fa50((int)param_1,param_2);
    iVar2 = FUN_080613f8((int)param_1,param_2,&local_10);
    if (iVar2 == 0) {
      pcVar4 = "Bad shift name";
    }
    else {
      local_8[2] = 0;
      uVar3 = 0;
      do {
        iVar2 = islower((int)(char)local_c[uVar3]);
        if (iVar2 == 0) break;
        iVar2 = toupper((int)(char)local_c[uVar3]);
        local_8[uVar3] = (char)iVar2;
        uVar3 = uVar3 + 1;
      } while (uVar3 < 3);
      if (uVar3 == 3) {
        local_c = local_8;
      }
      if ((local_10 == 3) &&
         (iVar2 = FUN_08058800(0x8076e40,3,(int)local_c,0,&local_14,6), iVar2 != 0)) {
        if (local_14 == 5) {
          local_14 = 0;
        }
        if (local_14 == 4) {
          return iVar1 + 0x60;
        }
        FUN_0805fa50((int)param_1,param_2);
        if (param_1[*param_2] == '#') {
          *param_2 = *param_2 + 1;
          uVar3 = FUN_080535b0(param_1,param_2,0,&local_18);
          if (DAT_08080160 != 0) {
            return 0;
          }
          if (local_14 == 1) {
            if (uVar3 - 1 < 0x20) {
              return (uVar3 & 0x1f) * 0x80 + 0x20 + iVar1;
            }
          }
          else if (local_14 == 0) {
            if (uVar3 < 0x20) {
              return iVar1 + uVar3 * 0x80;
            }
          }
          else if (local_14 == 2) {
            if (uVar3 - 1 < 0x20) {
              return (uVar3 & 0x1f) * 0x80 + 0x40 + iVar1;
            }
          }
          else if ((local_14 == 3) && (uVar3 - 1 < 0x1f)) {
            return uVar3 * 0x80 + 0x60 + iVar1;
          }
          pcVar4 = "Shift option out of range";
        }
        else {
          if (param_3 != 0) {
            iVar2 = FUN_080679f0((int)param_1,param_2);
            return local_14 * 0x20 + iVar2 * 0x100 + 0x10 + iVar1;
          }
          pcVar4 = "Missing \'#\'";
        }
      }
      else {
        pcVar4 = "Unknown shift name";
      }
    }
    FUN_08052f1c(4,pcVar4);
  }
  return 0;
}



undefined4 FUN_080678c8(int param_1,int *param_2,uint *param_3)

{
  ushort uVar1;
  int iVar2;
  undefined4 uVar3;
  uint local_c;
  char *local_8;
  
  FUN_0805fa50(param_1,param_2);
  iVar2 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if (iVar2 == 0) {
    uVar3 = FUN_080614c0(param_1,param_2);
  }
  else {
    FUN_0805fa50(param_1,param_2);
    iVar2 = FUN_0805f618(local_c,local_8,0);
    if (((iVar2 != 0) && ((*(byte *)(iVar2 + 8) & 3) == 3)) &&
       (uVar1 = *(ushort *)(iVar2 + 10) >> 6, (uVar1 & 7) < 2)) {
      *param_3 = (uint)((uVar1 & 7) == 0);
      FUN_08058c28(iVar2);
      return *(undefined4 *)(iVar2 + 0xc);
    }
    FUN_08052f1c(4,"Bad register name symbol");
    uVar3 = 0;
  }
  return uVar3;
}



undefined4
FUN_08067968(char *param_1,int *param_2,int *param_3,uint *param_4,undefined4 *param_5,
            undefined4 *param_6)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined *puVar4;
  uint local_c;
  char *local_8;
  
  iVar1 = *param_2;
  FUN_0805fa50((int)param_1,param_2);
  iVar2 = FUN_080613f8((int)param_1,param_2,(int *)&local_c);
  if (iVar2 != 0) {
    iVar2 = FUN_0805f618(local_c,local_8,0);
    *param_2 = iVar1;
    if ((iVar2 != 0) && ((*(byte *)(iVar2 + 8) & 3) == 3)) {
      *param_5 = 1;
      uVar3 = FUN_080679f0((int)param_1,param_2);
      return uVar3;
    }
  }
  *param_5 = 0;
  puVar4 = FUN_08053bbc(param_1,param_2,param_3,param_4);
  *param_6 = puVar4;
  return 0;
}



undefined4 FUN_080679f0(int param_1,int *param_2)

{
  byte *pbVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  uint local_c;
  char *local_8;
  
  FUN_0805fa50(param_1,param_2);
  iVar2 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if (iVar2 == 0) {
    uVar3 = FUN_080614c0(param_1,param_2);
  }
  else {
    FUN_0805fa50(param_1,param_2);
    iVar2 = FUN_0805f618(local_c,local_8,0);
    if ((iVar2 == 0) || ((*(uint *)(iVar2 + 8) & 0x1c00003) != 3)) {
      FUN_08052f1c(4,"Bad register name symbol");
      uVar3 = 0;
    }
    else {
      FUN_08058c28(iVar2);
      if ((DAT_080825d0 == 1) && ((DAT_08082760 != 0 && (*(int *)(iVar2 + 0xc) == -1)))) {
        pbVar1 = *(byte **)(iVar2 + 4);
        uVar4 = *pbVar1 - 0x66;
        if ((uVar4 == 0) && (uVar4 = pbVar1[1] - 0x70, uVar4 == 0)) {
          uVar4 = (uint)pbVar1[2];
        }
        if (uVar4 == 0) {
          FUN_08052f1c(3,"Register name fp used in -apcs 3/nofp mode");
        }
      }
      uVar3 = *(undefined4 *)(iVar2 + 0xc);
    }
  }
  return uVar3;
}



undefined4 FUN_08067ab4(int param_1,int *param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint local_c;
  char *local_8;
  
  FUN_0805fa50(param_1,param_2);
  iVar1 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if (iVar1 == 0) {
    uVar2 = FUN_080614c0(param_1,param_2);
  }
  else {
    FUN_0805fa50(param_1,param_2);
    iVar1 = FUN_0805f618(local_c,local_8,0);
    if ((iVar1 == 0) || ((*(uint *)(iVar1 + 8) & 0x1c00003) != 0xc00003)) {
      FUN_08052f1c(4,"Bad register name symbol");
      uVar2 = 0;
    }
    else {
      if (0xf < *(uint *)(iVar1 + 0xc)) {
        FUN_08052f1c(4,"Coprocessor register number out of range");
      }
      FUN_08058c28(iVar1);
      uVar2 = *(undefined4 *)(iVar1 + 0xc);
    }
  }
  return uVar2;
}



undefined4 FUN_08067b48(int param_1,int *param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint local_c;
  char *local_8;
  
  FUN_0805fa50(param_1,param_2);
  iVar1 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if (iVar1 == 0) {
    uVar2 = FUN_080614c0(param_1,param_2);
  }
  else {
    FUN_0805fa50(param_1,param_2);
    iVar1 = FUN_0805f618(local_c,local_8,0);
    if ((iVar1 == 0) || ((*(uint *)(iVar1 + 8) & 0x1c00003) != 0x800003)) {
      FUN_08052f1c(4,"Bad register name symbol");
      uVar2 = 0;
    }
    else {
      if (0xf < *(uint *)(iVar1 + 0xc)) {
        FUN_08052f1c(4,"Coprocessor number out of range");
      }
      FUN_08058c28(iVar1);
      uVar2 = *(undefined4 *)(iVar1 + 0xc);
    }
  }
  return uVar2;
}



uint FUN_08067bdc(int param_1,int *param_2)

{
  int iVar1;
  uint uVar2;
  uint local_c;
  char *local_8;
  
  iVar1 = FUN_0805fa50(param_1,param_2);
  if ((char)iVar1 == '{') {
    uVar2 = FUN_0805428c(param_1,param_2,FUN_080679f0);
  }
  else {
    iVar1 = FUN_080613f8(param_1,param_2,(int *)&local_c);
    if (iVar1 == 0) {
      uVar2 = FUN_080614c0(param_1,param_2);
    }
    else {
      FUN_0805fa50(param_1,param_2);
      iVar1 = FUN_0805f618(local_c,local_8,0);
      if ((iVar1 == 0) || ((*(uint *)(iVar1 + 8) & 0x1c03003) != 0x3000)) {
        FUN_08052f1c(4,"Bad register list symbol");
        uVar2 = 0;
      }
      else {
        FUN_08058c28(iVar1);
        uVar2 = *(uint *)(iVar1 + 0xc);
      }
    }
  }
  return uVar2;
}



void FUN_08067c80(void)

{
  int iVar1;
  uint uVar2;
  
  if (DAT_080829a0 != 1) {
    uVar2 = 0;
    iVar1 = 0;
    do {
      FUN_0805f8f8(*(char **)((int)&PTR_DAT_08079b98 + iVar1),*(uint *)((int)&DAT_08079b9c + iVar1),
                   *(uint *)((int)&DAT_08079ba0 + iVar1));
      iVar1 = iVar1 + 0xc;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0xe6);
    if ((DAT_08082684 != 0) || (DAT_080829a0 == 2)) {
      uVar2 = 0;
      iVar1 = 0;
      do {
        FUN_0805f8f8(*(char **)((int)&PTR_DAT_0807a660 + iVar1),
                     *(uint *)((int)&DAT_0807a664 + iVar1),*(uint *)((int)&DAT_0807a668 + iVar1));
        iVar1 = iVar1 + 0xc;
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x14);
    }
  }
  return;
}



undefined4 FUN_08067d00(char *param_1,int *param_2,int param_3,uint param_4)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  uint local_10;
  uint local_c;
  uint local_8;
  
  switch(param_3) {
  case 9:
    FUN_08069340((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08068257;
    }
    *param_2 = *param_2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 == '[') {
      *param_2 = *param_2 + 1;
      local_10 = FUN_080679f0((int)param_1,param_2);
      if (DAT_08080160 != 0) {
        return 0;
      }
      iVar2 = *param_2;
      if (param_1[iVar2] == ']') {
        *param_2 = iVar2 + 1;
        iVar2 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar2 != ',') {
          iVar2 = *param_2;
          goto LAB_08067f06;
        }
        *param_2 = *param_2 + 1;
        local_10 = local_10 + 0x20;
        iVar2 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar2 != '#') {
LAB_080681e4:
          pcVar4 = "Missing \'#\'";
          goto LAB_080681e9;
        }
        *param_2 = *param_2 + 1;
        FUN_080535b0(param_1,param_2,1,&local_8);
      }
      else if (param_1[iVar2] == ',') {
        *param_2 = iVar2 + 1;
        iVar2 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar2 == '#') {
          *param_2 = *param_2 + 1;
          FUN_080535b0(param_1,param_2,1,&local_8);
        }
        else {
          FUN_08052f1c(4,"Missing \'#\'");
        }
        if (DAT_08080160 != 0) {
          return 0;
        }
        iVar2 = *param_2;
        if (param_1[iVar2] != ']') goto LAB_08068252;
LAB_08068262:
        *param_2 = iVar2 + 1;
        iVar2 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar2 == '!') {
          *param_2 = *param_2 + 1;
          goto LAB_08068275;
        }
      }
      else {
        pcVar4 = "Missing comma";
LAB_080681e9:
        FUN_08052f1c(4,pcVar4);
      }
    }
    else if ((param_1[*param_2] == '=') && ((param_4 & 0x500000) == 0x100000)) {
      *param_2 = *param_2 + 1;
      uVar3 = param_4 >> 0xf & 1;
      iVar2 = FUN_080547e0((int)param_1,param_2,uVar3,&local_10,&local_c);
      if (iVar2 == 1) {
        pcVar4 = "Floating point overflow";
        goto LAB_08068257;
      }
      if (iVar2 == 2) {
        pcVar4 = "Floating point number not found";
        goto LAB_08068257;
      }
      if (uVar3 == 0) {
        FUN_08056c6c(local_10,-0x3fc,0x3fc);
      }
      else if (uVar3 == 1) {
        FUN_08056c8c(local_10,local_c,-0x3fc,0x3fc);
      }
    }
    else {
      FUN_08053a28(param_1,param_2,&local_10,1,&local_8);
      iVar2 = *param_2;
LAB_08067f06:
      if (param_1[iVar2] == '!') {
        *param_2 = iVar2 + 1;
LAB_08068275:
        local_10 = local_10 + 0x20;
      }
    }
    goto LAB_08068279;
  case 10:
    FUN_08069340((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08068257;
    }
    *param_2 = *param_2 + 1;
    FUN_08069340((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08068257;
    }
    *param_2 = *param_2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    cVar1 = (char)iVar2;
    goto joined_r0x08067fbf;
  case 0xb:
  case 0xc:
  case 0x1b:
    FUN_08069340((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08068257;
    }
    *param_2 = *param_2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    cVar1 = (char)iVar2;
joined_r0x08067fbf:
    if (cVar1 == '#') {
      *param_2 = *param_2 + 1;
      FUN_08053524((int)param_1,param_2);
      return 1;
    }
LAB_08068073:
    FUN_08069340((int)param_1,param_2);
    return 1;
  case 0xd:
    FUN_08069340((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08068257;
    }
    *param_2 = *param_2 + 1;
    iVar2 = FUN_080679f0((int)param_1,param_2);
    if (iVar2 != 0xf) {
      return 1;
    }
    pcVar4 = "Undefined effect (use of PC/PSR)";
    if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
      iVar2 = 3;
    }
    else {
      iVar2 = 4;
    }
    break;
  case 0xe:
    FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08068257;
    }
    *param_2 = *param_2 + 1;
    goto LAB_08068073;
  case 0xf:
    iVar2 = FUN_080679f0((int)param_1,param_2);
    if (iVar2 != 0xf) {
      return 1;
    }
    pcVar4 = "Undefined effect (use of PC/PSR)";
    if ((DAT_080825f0 < 4) || (DAT_08082620 != 0)) {
      iVar2 = 3;
    }
    else {
      iVar2 = 4;
    }
    break;
  default:
    goto switchD_08067d21_caseD_10;
  case 0x19:
  case 0x1a:
    FUN_08069340((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08068257;
    }
    *param_2 = *param_2 + 1;
    FUN_0805fa50((int)param_1,param_2);
    FUN_080535b0(param_1,param_2,1,&local_8);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08068257;
    }
    *param_2 = *param_2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 != '[') {
      FUN_08053a28(param_1,param_2,&local_10,1,&local_8);
      if (param_1[*param_2] != '!') {
        return 1;
      }
      *param_2 = *param_2 + 1;
      return 1;
    }
    *param_2 = *param_2 + 1;
    local_10 = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    iVar2 = *param_2;
    if (param_1[iVar2] != ']') {
      if (param_3 != 0x1a) {
        if (param_1[iVar2] != ',') {
          pcVar4 = "Missing comma";
          goto LAB_08068257;
        }
        *param_2 = iVar2 + 1;
        iVar2 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar2 == '#') {
          *param_2 = *param_2 + 1;
          FUN_080535b0(param_1,param_2,1,&local_8);
        }
        else {
          FUN_08052f1c(4,"Missing \'#\'");
        }
        if (DAT_08080160 != 0) {
          return 0;
        }
        iVar2 = *param_2;
        if (param_1[iVar2] == ']') goto LAB_08068262;
      }
LAB_08068252:
      pcVar4 = "Missing close square bracket";
LAB_08068257:
      FUN_08052f1c(4,pcVar4);
      return 0;
    }
    *param_2 = iVar2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 == ',') {
      if (param_3 == 0x1a) {
        return 1;
      }
      *param_2 = *param_2 + 1;
      iVar2 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar2 != '#') goto LAB_080681e4;
      *param_2 = *param_2 + 1;
      FUN_080535b0(param_1,param_2,1,&local_8);
      local_10 = local_10 + 0x20;
    }
    else if (param_1[*param_2] == '!') {
      *param_2 = *param_2 + 1;
      goto LAB_08068275;
    }
LAB_08068279:
    if (local_10 != 0x2f) {
      return 1;
    }
    pcVar4 = "Undefined effect (PC + writeback)";
    iVar2 = 3;
  }
  FUN_08052f1c(iVar2,pcVar4);
switchD_08067d21_caseD_10:
  return 1;
}



undefined4 FUN_080682a0(char *param_1,int *param_2,int param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined1 *puVar7;
  uint *puVar8;
  uint uVar9;
  uint uVar10;
  char *pcVar11;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  switch(param_3) {
  case 9:
    iVar2 = FUN_08069340((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar3 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar3 == '[') {
      *param_2 = *param_2 + 1;
      local_14 = FUN_080679f0((int)param_1,param_2);
      iVar3 = *param_2;
      if (param_1[iVar3] == ']') {
        *param_2 = iVar3 + 1;
        iVar3 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar3 == ',') {
          *param_2 = *param_2 + 1;
          uVar5 = param_4 | 0x200000;
          FUN_0805fa50((int)param_1,param_2);
          *param_2 = *param_2 + 1;
          uVar4 = FUN_080535b0(param_1,param_2,0,&local_8);
          if (DAT_08080160 != 0) {
            return 0;
          }
          uVar9 = uVar4;
          if ((int)uVar4 < 0) {
            uVar9 = -uVar4;
          }
          if ((0x3ff < (int)uVar9) || ((uVar4 & 3) != 0)) goto LAB_080688f0;
          if (uVar4 < 0x400) {
            uVar5 = param_4 | 0xa00000;
          }
          if ((int)uVar4 < 0) {
            uVar4 = -uVar4;
          }
          if ((int)uVar4 < 0) {
            uVar4 = uVar4 + 3;
          }
          iVar3 = (int)uVar4 >> 2;
        }
        else {
          if (param_1[*param_2] == '!') {
            *param_2 = *param_2 + 1;
            uVar5 = param_4 | 0xa00000;
          }
          else {
            uVar5 = param_4 | 0x1800000;
          }
          iVar3 = 0;
        }
      }
      else {
        uVar5 = param_4 | 0x1000000;
        *param_2 = iVar3 + 1;
        FUN_0805fa50((int)param_1,param_2);
        *param_2 = *param_2 + 1;
        uVar4 = FUN_080535b0(param_1,param_2,0,&local_8);
        if (DAT_08080160 != 0) {
          return 0;
        }
        uVar9 = uVar4;
        if ((int)uVar4 < 0) {
          uVar9 = -uVar4;
        }
        if ((0x3ff < (int)uVar9) || ((uVar4 & 3) != 0)) goto LAB_080688f0;
        if (uVar4 < 0x400) {
          uVar5 = param_4 | 0x1800000;
        }
        if ((int)uVar4 < 0) {
          uVar4 = -uVar4;
        }
        if ((int)uVar4 < 0) {
          uVar4 = uVar4 + 3;
        }
        iVar3 = (int)uVar4 >> 2;
        *param_2 = *param_2 + 1;
        iVar1 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar1 == '!') {
          *param_2 = *param_2 + 1;
          goto LAB_0806854f;
        }
      }
    }
    else {
      if (param_1[*param_2] == '=') {
        *param_2 = *param_2 + 1;
        uVar4 = (uint)((short)param_4 < 0);
        FUN_080547e0((int)param_1,param_2,uVar4,&local_10,&local_c);
        if (uVar4 == 0) {
          uVar4 = FUN_08056c6c(local_10,-0x3fc,0x3fc);
        }
        else {
          uVar4 = FUN_08056c8c(local_10,local_c,-0x3fc,0x3fc);
        }
        local_14 = 0xf;
      }
      else {
        uVar4 = FUN_08053a28(param_1,param_2,&local_14,0,&local_8);
        if (DAT_08080160 != 0) {
          return 0;
        }
      }
      uVar5 = param_4 | 0x1000000;
      if (local_14 == 0xf) {
        uVar4 = (uVar4 - 8) - DAT_080826a0;
      }
      uVar9 = uVar4;
      if ((int)uVar4 < 0) {
        uVar9 = -uVar4;
      }
      if ((0x3ff < (int)uVar9) || ((uVar4 & 3) != 0)) {
LAB_080688f0:
        pcVar11 = "Data transfer offset out of range";
LAB_080688f5:
        FUN_08052f1c(4,pcVar11);
        return 0;
      }
      if (uVar4 < 0x400) {
        uVar5 = param_4 | 0x1800000;
      }
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      if ((int)uVar4 < 0) {
        uVar4 = uVar4 + 3;
      }
      iVar3 = (int)uVar4 >> 2;
      if (param_1[*param_2] == '!') {
        *param_2 = *param_2 + 1;
LAB_0806854f:
        uVar5 = uVar5 | 0x200000;
      }
    }
    puVar7 = &stack0xffffffd8;
    iVar2 = iVar3 + uVar5 + local_14 * 0x10000 + iVar2 * 0x1000;
    break;
  case 10:
    iVar2 = FUN_08069340((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_14 = FUN_08069340((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar3 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar3 == '#') {
      *param_2 = *param_2 + 1;
      iVar3 = FUN_08053524((int)param_1,param_2);
      uVar4 = iVar3 + 8;
    }
    else {
      uVar4 = FUN_08069340((int)param_1,param_2);
    }
    iVar2 = iVar2 * 0x1000 + (param_4 | uVar4);
    goto LAB_08068941;
  case 0xb:
  case 0xc:
  case 0x1b:
    iVar2 = FUN_08069340((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    iVar3 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar3 == '#') {
      *param_2 = *param_2 + 1;
      iVar3 = FUN_08053524((int)param_1,param_2);
      uVar4 = iVar3 + 8;
    }
    else {
      uVar4 = FUN_08069340((int)param_1,param_2);
    }
    puVar7 = &stack0xffffffd8;
    if (param_3 == 0xc) {
      iVar2 = iVar2 * 0x10000 + (param_4 | uVar4);
      puVar7 = &stack0xffffffd8;
    }
    else {
      iVar2 = iVar2 * 0x1000 + (param_4 | uVar4);
    }
    break;
  case 0xd:
    FUN_08069340((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    FUN_080679f0((int)param_1,param_2);
    puVar8 = (uint *)&stack0xffffffc4;
    goto LAB_0806894a;
  case 0xe:
    FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    FUN_08069340((int)param_1,param_2);
    puVar8 = (uint *)&stack0xffffffc4;
    goto LAB_0806894a;
  case 0xf:
    puVar7 = &stack0xffffffd0;
    iVar2 = FUN_080679f0((int)param_1,param_2);
    iVar2 = iVar2 * 0x1000 + param_4;
    break;
  default:
    goto switchD_080682be_caseD_10;
  case 0x19:
  case 0x1a:
    uVar4 = FUN_08069340((int)param_1,param_2);
    if (7 < uVar4) {
      pcVar11 = "Floating point register number out of range";
      goto LAB_080688f5;
    }
    *param_2 = *param_2 + 1;
    FUN_0805fa50((int)param_1,param_2);
    uVar5 = FUN_080535b0(param_1,param_2,0,&local_8);
    if (3 < uVar5 - 1) {
      FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
      return 0;
    }
    uVar9 = param_4 | (uVar5 & 1) * 0x8000 + (uVar5 & 2) * 0x200000;
    *param_2 = *param_2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 == '[') {
      *param_2 = *param_2 + 1;
      local_14 = FUN_080679f0((int)param_1,param_2);
      iVar2 = *param_2;
      if (param_1[iVar2] == ']') {
        *param_2 = iVar2 + 1;
        iVar2 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar2 == ',') {
          uVar10 = uVar9 | 0x200000;
          *param_2 = *param_2 + 1;
          FUN_0805fa50((int)param_1,param_2);
          *param_2 = *param_2 + 1;
          uVar5 = FUN_080535b0(param_1,param_2,0,&local_8);
          if (DAT_08080160 != 0) {
            return 0;
          }
          uVar6 = uVar5;
          if ((int)uVar5 < 0) {
            uVar6 = -uVar5;
          }
          if ((0x3ff < (int)uVar6) || ((uVar5 & 3) != 0)) goto LAB_080688f0;
          if (uVar5 < 0x400) {
            uVar10 = uVar9 | 0xa00000;
          }
          if ((int)uVar5 < 0) {
            uVar5 = -uVar5;
          }
          if ((int)uVar5 < 0) {
            uVar5 = uVar5 + 3;
          }
          iVar2 = (int)uVar5 >> 2;
        }
        else {
          uVar10 = uVar9;
          if (param_1[*param_2] == '!') {
            uVar10 = uVar9 | 0x200000;
          }
          if (param_3 == 0x19) {
            iVar2 = 0;
            uVar10 = uVar10 | 0x1800000;
          }
          else if ((uVar10 & 0x1200000) == 0) {
            iVar2 = 0;
            uVar10 = uVar10 | 0x1000000;
          }
          else {
            iVar2 = uVar5 * 3;
          }
        }
      }
      else {
        uVar10 = uVar9 | 0x1000000;
        *param_2 = iVar2 + 1;
        FUN_0805fa50((int)param_1,param_2);
        *param_2 = *param_2 + 1;
        uVar5 = FUN_080535b0(param_1,param_2,0,&local_8);
        if (DAT_08080160 != 0) {
          return 0;
        }
        uVar6 = uVar5;
        if ((int)uVar5 < 0) {
          uVar6 = -uVar5;
        }
        if ((0x3ff < (int)uVar6) || ((uVar5 & 3) != 0)) goto LAB_080688f0;
        if (uVar5 < 0x400) {
          uVar10 = uVar9 | 0x1800000;
        }
        if ((int)uVar5 < 0) {
          uVar5 = -uVar5;
        }
        if ((int)uVar5 < 0) {
          uVar5 = uVar5 + 3;
        }
        iVar2 = (int)uVar5 >> 2;
        *param_2 = *param_2 + 1;
        iVar3 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar3 == '!') goto LAB_08068931;
      }
    }
    else {
      uVar5 = FUN_08053a28(param_1,param_2,&local_14,0,&local_8);
      if (DAT_08080160 != 0) {
        return 0;
      }
      uVar10 = uVar9 | 0x1000000;
      if (local_14 == 0xf) {
        uVar5 = (uVar5 - 8) - DAT_080826a0;
      }
      uVar6 = uVar5;
      if ((int)uVar5 < 0) {
        uVar6 = -uVar5;
      }
      if ((0x3ff < (int)uVar6) || ((uVar5 & 3) != 0)) goto LAB_080688f0;
      if (uVar5 < 0x400) {
        uVar10 = uVar9 | 0x1800000;
      }
      if ((int)uVar5 < 0) {
        uVar5 = -uVar5;
      }
      if ((int)uVar5 < 0) {
        uVar5 = uVar5 + 3;
      }
      iVar2 = (int)uVar5 >> 2;
      if (param_1[*param_2] == '!') {
        *param_2 = *param_2 + 1;
LAB_08068931:
        uVar10 = uVar10 | 0x200000;
      }
    }
    iVar2 = iVar2 + uVar10 + uVar4 * 0x1000;
LAB_08068941:
    puVar7 = &stack0xffffffd8;
    iVar2 = iVar2 + local_14 * 0x10000;
  }
  puVar8 = (uint *)(puVar7 + -4);
  *(int *)(puVar7 + -4) = iVar2;
LAB_0806894a:
  puVar8[-1] = 0x806894f;
  FUN_08051c18(*puVar8);
switchD_080682be_caseD_10:
  return 1;
}



undefined4 FUN_08068960(int param_1,undefined1 *param_2)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  undefined4 uVar4;
  
  uVar4 = 0xffffffff;
  pcVar2 = param_2 + 1;
  switch(*param_2) {
  case 0x41:
    if (1 < param_1) {
      pcVar3 = param_2 + 2;
      switch(*pcVar2) {
      case 'B':
        if ((2 < param_1) && (*pcVar3 == 'S')) {
          uVar4 = 0;
        }
        break;
      case 'C':
        if ((2 < param_1) && (*pcVar3 == 'S')) {
          uVar4 = 1;
        }
        break;
      case 'D':
        if ((2 < param_1) && (*pcVar3 == 'F')) {
          uVar4 = 2;
        }
        break;
      case 'S':
        if ((2 < param_1) && (*pcVar3 == 'N')) {
          uVar4 = 3;
        }
        break;
      case 'T':
        if ((2 < param_1) && (*pcVar3 == 'N')) {
          uVar4 = 4;
        }
      }
    }
    break;
  case 0x43:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'N') {
        if (((2 < param_1) && (*pcVar2 == 'F')) && ((uVar4 = 6, 3 < param_1 && (param_2[3] == 'E')))
           ) {
          uVar4 = 8;
        }
      }
      else if (cVar1 < 'O') {
        if (((cVar1 == 'M') && (2 < param_1)) &&
           ((*pcVar2 == 'F' && ((uVar4 = 5, 3 < param_1 && (param_2[3] == 'E')))))) {
          uVar4 = 7;
        }
      }
      else if (((cVar1 == 'O') && (2 < param_1)) && (*pcVar2 == 'S')) {
        uVar4 = 9;
      }
    }
    break;
  case 0x44:
    if (((1 < param_1) && (*pcVar2 == 'V')) && ((2 < param_1 && (param_2[2] == 'F')))) {
      uVar4 = 10;
    }
    break;
  case 0x45:
    if ((((1 < param_1) && (*pcVar2 == 'X')) && (2 < param_1)) && (param_2[2] == 'P')) {
      uVar4 = 0xb;
    }
    break;
  case 0x46:
    if (1 < param_1) {
      pcVar3 = param_2 + 2;
      switch(*pcVar2) {
      case 'D':
        if ((2 < param_1) && (*pcVar3 == 'V')) {
          uVar4 = 0xc;
        }
        break;
      case 'I':
        if ((2 < param_1) && (*pcVar3 == 'X')) {
          uVar4 = 0xd;
        }
        break;
      case 'L':
        if ((2 < param_1) && (*pcVar3 == 'T')) {
          uVar4 = 0xe;
        }
        break;
      case 'M':
        if ((2 < param_1) && (*pcVar3 == 'L')) {
          uVar4 = 0xf;
        }
        break;
      case 'R':
        if ((2 < param_1) && (*pcVar3 == 'D')) {
          uVar4 = 0x10;
        }
      }
    }
    break;
  case 0x4c:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'F') {
        if ((2 < param_1) && (*pcVar2 == 'M')) {
          uVar4 = 0x12;
        }
      }
      else if (cVar1 < 'G') {
        if (((cVar1 == 'D') && (2 < param_1)) && (*pcVar2 == 'F')) {
          uVar4 = 0x11;
        }
      }
      else if (cVar1 == 'G') {
        if ((2 < param_1) && (*pcVar2 == 'N')) {
          uVar4 = 0x13;
        }
      }
      else if (((cVar1 == 'O') && (2 < param_1)) && (*pcVar2 == 'G')) {
        uVar4 = 0x14;
      }
    }
    break;
  case 0x4d:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'U') {
        if ((2 < param_1) && (*pcVar2 == 'F')) {
          uVar4 = 0x16;
        }
      }
      else if (cVar1 < 'V') {
        if (((cVar1 == 'N') && (2 < param_1)) && (*pcVar2 == 'F')) {
          uVar4 = 0x15;
        }
      }
      else if (((cVar1 == 'V') && (2 < param_1)) && (*pcVar2 == 'F')) {
        uVar4 = 0x17;
      }
    }
    break;
  case 0x4e:
    if (((1 < param_1) && (*pcVar2 == 'R')) && ((2 < param_1 && (param_2[2] == 'M')))) {
      uVar4 = 0x18;
    }
    break;
  case 0x50:
    if (((1 < param_1) && (*pcVar2 == 'O')) && (2 < param_1)) {
      if (param_2[2] == 'L') {
        uVar4 = 0x19;
      }
      else if (param_2[2] == 'W') {
        uVar4 = 0x1a;
      }
    }
    break;
  case 0x52:
    if (1 < param_1) {
      pcVar3 = param_2 + 2;
      switch(*pcVar2) {
      case 'D':
        if ((2 < param_1) && (*pcVar3 == 'F')) {
          uVar4 = 0x1b;
        }
        break;
      case 'F':
        if (2 < param_1) {
          if (*pcVar3 == 'C') {
            uVar4 = 0x1c;
          }
          else if (*pcVar3 == 'S') {
            uVar4 = 0x1d;
          }
        }
        break;
      case 'M':
        if ((2 < param_1) && (*pcVar3 == 'F')) {
          uVar4 = 0x1e;
        }
        break;
      case 'N':
        if ((2 < param_1) && (*pcVar3 == 'D')) {
          uVar4 = 0x1f;
        }
        break;
      case 'P':
        if ((2 < param_1) && (*pcVar3 == 'W')) {
          uVar4 = 0x20;
        }
        break;
      case 'S':
        if ((2 < param_1) && (*pcVar3 == 'F')) {
          uVar4 = 0x21;
        }
      }
    }
    break;
  case 0x53:
    if (1 < param_1) {
      pcVar3 = param_2 + 2;
      switch(*pcVar2) {
      case 'F':
        if ((2 < param_1) && (*pcVar3 == 'M')) {
          uVar4 = 0x22;
        }
        break;
      case 'I':
        if ((2 < param_1) && (*pcVar3 == 'N')) {
          uVar4 = 0x23;
        }
        break;
      case 'Q':
        if ((2 < param_1) && (*pcVar3 == 'T')) {
          uVar4 = 0x24;
        }
        break;
      case 'T':
        if ((2 < param_1) && (*pcVar3 == 'F')) {
          uVar4 = 0x25;
        }
        break;
      case 'U':
        if ((2 < param_1) && (*pcVar3 == 'F')) {
          uVar4 = 0x26;
        }
      }
    }
    break;
  case 0x54:
    if (((1 < param_1) && (*pcVar2 == 'A')) && ((2 < param_1 && (param_2[2] == 'N')))) {
      uVar4 = 0x27;
    }
    break;
  case 0x55:
    if (((1 < param_1) && (*pcVar2 == 'R')) && ((2 < param_1 && (param_2[2] == 'D')))) {
      uVar4 = 0x28;
    }
    break;
  case 0x57:
    if (((1 < param_1) && (*pcVar2 == 'F')) && (2 < param_1)) {
      if (param_2[2] == 'C') {
        uVar4 = 0x29;
      }
      else if (param_2[2] == 'S') {
        uVar4 = 0x2a;
      }
    }
  }
  return uVar4;
}



undefined4 FUN_08068ff4(uint param_1,undefined1 *param_2,int *param_3,int *param_4)

{
  char cVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  int local_14;
  int local_10;
  int local_c;
  uint local_8;
  
  if (1 < DAT_08082608 - 2U) {
    return 0;
  }
  local_10 = FUN_08068960(param_1,param_2);
  if (local_10 == -1) {
    return 0;
  }
  if (param_1 == 5) {
    if (local_10 == 7) {
      local_10 = 5;
    }
    else if (local_10 == 8) {
      local_10 = 6;
    }
  }
  iVar3 = local_10 * 0xc;
  local_8 = *(uint *)(&DAT_0807a750 + iVar3);
  local_14 = *(int *)(&DAT_0807a758 + iVar3);
  uVar4 = *(uint *)(&DAT_0807a754 + iVar3);
  if (DAT_08082608 == 2) {
    if (local_14 == 0x1b) {
      return 0;
    }
    if (local_14 == 0x19) {
      return 0;
    }
  }
  if (param_1 < local_8 + 2) {
    local_c = -0x20000000;
  }
  else {
    local_c = FUN_08066e98((int *)&local_8,(int)param_2);
  }
  if (param_1 - local_8 == 1) {
    cVar1 = param_2[local_8];
    switch(local_14) {
    case 9:
      if (cVar1 == 'E') {
        uVar4 = uVar4 + 0x400000;
      }
      else if (cVar1 < 'F') {
        if (cVar1 != 'D') {
          return 0;
        }
        uVar4 = uVar4 + 0x8000;
      }
      else {
        if (cVar1 != 'P') goto LAB_08069118;
        uVar4 = uVar4 + 0x408000;
      }
      break;
    case 10:
    case 0xb:
    case 0xd:
    case 0x1b:
      if (cVar1 == 'E') {
        uVar4 = uVar4 + 0x80000;
      }
      else if (cVar1 < 'F') {
        if (cVar1 != 'D') {
          return 0;
        }
        uVar4 = uVar4 + 0x80;
      }
      else {
LAB_08069118:
        if (cVar1 != 'S') {
          return 0;
        }
      }
      break;
    default:
      goto switchD_080691c5_caseD_c;
    case 0xe:
      switch(cVar1) {
      case 'D':
      case 'E':
      case 'S':
        if (DAT_080825d0 == 1) {
          FUN_08052f1c(3,"Precision specifier ignored for \'FIX\'");
        }
        break;
      default:
        goto switchD_080691c5_caseD_c;
      case 'M':
switchD_0806917f_caseD_4d:
        uVar4 = uVar4 + 0x40;
        break;
      case 'P':
switchD_0806917f_caseD_50:
        uVar4 = uVar4 + 0x20;
        break;
      case 'Z':
switchD_0806917f_caseD_5a:
        uVar4 = uVar4 + 0x60;
      }
      uVar4 = uVar4 & 0xfff7ff7f;
    }
  }
  else if (param_1 == local_8) {
    switch(local_14) {
    case 9:
    case 10:
    case 0xb:
    case 0xd:
    case 0x1b:
      goto switchD_080691c5_caseD_c;
    }
  }
  else {
    if (param_1 - local_8 != 2) {
      return 0;
    }
    cVar1 = param_2[local_8];
    cVar2 = param_2[local_8 + 1];
    switch(local_14) {
    case 10:
    case 0xb:
    case 0xd:
    case 0x1b:
      if (cVar1 == 'E') {
        uVar4 = uVar4 + 0x80000;
      }
      else if (cVar1 < 'F') {
        if (cVar1 != 'D') {
          return 0;
        }
        uVar4 = uVar4 + 0x80;
      }
      else if (cVar1 != 'S') {
        return 0;
      }
      if (cVar2 == 'P') {
        uVar4 = uVar4 + 0x20;
      }
      else if (cVar2 < 'Q') {
        if (cVar2 != 'M') {
          return 0;
        }
        uVar4 = uVar4 + 0x40;
      }
      else {
        if (cVar2 != 'Z') {
          return 0;
        }
        uVar4 = uVar4 + 0x60;
      }
      break;
    default:
      goto switchD_080691c5_caseD_c;
    case 0xe:
      if (cVar1 < 'D') {
        return 0;
      }
      if (('E' < cVar1) && (cVar1 != 'S')) {
        return 0;
      }
      if (DAT_080825d0 == 1) {
        FUN_08052f1c(3,"Precision specifier ignored for \'FIX\'");
      }
      if (cVar2 == 'P') goto switchD_0806917f_caseD_50;
      if ('P' < cVar2) {
        if (cVar2 != 'Z') {
          return 0;
        }
        goto switchD_0806917f_caseD_5a;
      }
      if (cVar2 != 'M') {
        return 0;
      }
      goto switchD_0806917f_caseD_4d;
    case 0x19:
      local_14 = 0x1a;
      if (cVar1 == 'E') {
        if (cVar2 != 'A') {
          return 0;
        }
        if (local_10 == 0x22) {
LAB_080692dc:
          uVar4 = uVar4 + 0x800000;
          break;
        }
      }
      else if (cVar1 < 'F') {
        if (cVar1 != 'D') {
          return 0;
        }
        if (cVar2 != 'B') {
          return 0;
        }
      }
      else {
        if (cVar1 != 'F') {
          if (cVar1 != 'I') {
            return 0;
          }
          uVar4 = uVar4 + 0x800000;
          if (cVar2 != 'A') {
            return 0;
          }
          break;
        }
        if (cVar2 != 'D') {
          return 0;
        }
        if (local_10 != 0x22) goto LAB_080692dc;
      }
      uVar4 = uVar4 + 0x1000000;
    }
  }
  *param_3 = local_14;
  *param_4 = uVar4 + local_c;
  if (DAT_0808277c != 0) {
    DAT_0808264c = 1;
    return 1;
  }
switchD_080691c5_caseD_c:
  return 0;
}



undefined4 FUN_08069340(int param_1,int *param_2)

{
  int iVar1;
  char *pcVar2;
  uint local_c;
  char *local_8;
  
  FUN_0805fa50(param_1,param_2);
  iVar1 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if (iVar1 == 0) {
    pcVar2 = "Bad symbol";
  }
  else {
    FUN_0805fa50(param_1,param_2);
    iVar1 = FUN_0805f618(local_c,local_8,0);
    if ((iVar1 != 0) && ((*(uint *)(iVar1 + 8) & 0x1c00003) == 0x400003)) {
      if (7 < *(uint *)(iVar1 + 0xc)) {
        FUN_08052f1c(4,"Floating point register number out of range");
      }
      FUN_08058c28(iVar1);
      return *(undefined4 *)(iVar1 + 0xc);
    }
    pcVar2 = "Bad register name symbol";
  }
  FUN_08052f1c(4,pcVar2);
  return 0;
}



undefined4 FUN_080693e0(char *param_1,int *param_2,int param_3,int param_4,int *param_5)

{
  bool bVar1;
  int iVar2;
  undefined *puVar3;
  char *pcVar4;
  uint local_20;
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  switch(param_3) {
  case 0:
    bVar1 = false;
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_4 == 0x4700) goto switchD_080693fe_caseD_5;
    iVar2 = *param_2;
    if (param_1[iVar2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08069941;
    }
    *param_2 = iVar2 + 1;
    if (((((param_4 != 0x42c0) && (param_4 != 0x4280)) && (param_4 != 0x1c00)) &&
        ((param_4 != 0x43c0 && (param_4 != 0x4240)))) &&
       ((param_4 != 0x4200 && ((param_4 != 0x4600 && (param_4 != 0x4500)))))) {
      iVar2 = FUN_080613bc(param_1 + iVar2 + 1);
      if (iVar2 != 0) {
        local_c = FUN_080679f0((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        bVar1 = true;
      }
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
      }
    }
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 == '#') {
      *param_2 = *param_2 + 1;
      FUN_080535b0(param_1,param_2,1,&local_8);
    }
    else {
      if ((bVar1) && (iVar2 = FUN_080613bc(param_1 + *param_2), iVar2 == 0))
      goto switchD_080693fe_caseD_5;
      FUN_080679f0((int)param_1,param_2);
    }
LAB_08069506:
    if (DAT_08080160 != 0) {
      return 0;
    }
    goto switchD_080693fe_caseD_5;
  case 1:
    FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08069941;
    }
    *param_2 = *param_2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 != '[') {
      if (((param_1[*param_2] == '=') && (DAT_080825c4 == 0)) ||
         ((param_1[*param_2] == '#' && (DAT_080825c4 == 1)))) {
        *param_2 = *param_2 + 1;
        puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
        *param_5 = (int)puVar3;
        if (puVar3 == (undefined *)0x0) {
          local_14 = 0;
          local_c = FUN_08053738(param_1,param_2,&local_18,1,&local_8,&local_14);
          if (DAT_08080160 != 0) {
            return 0;
          }
          if (local_18 == 3) {
            if (local_14 != 0) {
              local_c = local_c | 1;
            }
            FUN_08056c4c(local_c,local_8,0,0x3fc);
          }
          else if ((local_8 == 0) || (0xff < local_c)) {
            FUN_08056bec(local_8,0,local_c,0,0x3fc);
          }
        }
        else {
          FUN_08056c1c((uint)puVar3,local_c,0,0x3fc);
        }
      }
      else {
        puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
        *param_5 = (int)puVar3;
        if (puVar3 == (undefined *)0x0) {
          FUN_08053a28(param_1,param_2,&local_10,1,&local_8);
        }
      }
      goto switchD_080693fe_caseD_5;
    }
    *param_2 = *param_2 + 1;
    local_10 = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    iVar2 = *param_2;
    if (param_1[iVar2] != ']') {
      if (param_1[iVar2] == ',') {
        *param_2 = iVar2 + 1;
        iVar2 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar2 == '#') {
          *param_2 = *param_2 + 1;
          local_c = FUN_080535b0(param_1,param_2,1,&local_8);
        }
        else {
          if ((param_1[*param_2] == '+') || (param_1[*param_2] == '-')) {
            *param_2 = *param_2 + 1;
          }
          local_c = FUN_080679f0((int)param_1,param_2);
        }
        if (DAT_08080160 != 0) {
          return 0;
        }
        if (param_1[*param_2] == ']') {
          *param_2 = *param_2 + 1;
          goto switchD_080693fe_caseD_5;
        }
        pcVar4 = "Missing close square bracket";
      }
      else {
        pcVar4 = "Missing comma";
      }
      goto LAB_08069941;
    }
    *param_2 = iVar2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 != ',') goto switchD_080693fe_caseD_5;
    *param_2 = *param_2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 != '#') {
      pcVar4 = "Must have immediate value with this operation";
      goto LAB_08069941;
    }
    *param_2 = *param_2 + 1;
    break;
  case 2:
    puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
    *param_5 = (int)puVar3;
    if (puVar3 != (undefined *)0x0) goto switchD_080693fe_caseD_5;
    break;
  case 3:
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != '!') {
      pcVar4 = "Missing \'!\'";
      goto LAB_08069941;
    }
    *param_2 = *param_2 + 1;
    iVar2 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar2 != ',') {
      pcVar4 = "Missing comma";
      goto LAB_08069941;
    }
    *param_2 = *param_2 + 1;
  case 0x2e:
    FUN_08067bdc((int)param_1,param_2);
    goto switchD_080693fe_caseD_5;
  case 4:
  case 0x30:
    if (param_3 == 0x30) {
      local_1c = 0;
      local_c = FUN_08067968(param_1,param_2,(int *)&local_c,(uint *)0x0,&local_1c,param_5);
      if (local_1c != 0) goto LAB_08069506;
    }
    else {
      puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
      *param_5 = (int)puVar3;
    }
    if (*param_5 == 0) {
      FUN_08053738(param_1,param_2,&local_20,1,&local_8,(uint *)0x0);
    }
    if ((param_4 == 0xf800) || (param_4 == 0xe800)) {
      DAT_080826a0 = DAT_080826a0 + 2;
      DAT_08082628 = DAT_08082628 + 1;
    }
  default:
    goto switchD_080693fe_caseD_5;
  case 6:
    local_c = FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
      *param_5 = (int)puVar3;
      if (puVar3 == (undefined *)0x0) {
        FUN_0805384c(param_1,param_2,&local_c,&local_18,1,&local_8);
        if (local_18 == 4) {
          DAT_080826a0 = DAT_080826a0 + 2;
        }
        goto switchD_080693fe_caseD_5;
      }
      pcVar4 = "ADR/L cannot be used on external symbols";
    }
    else {
      pcVar4 = "Missing comma";
    }
    goto LAB_08069941;
  case 0x2f:
    FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      FUN_0805fa50((int)param_1,param_2);
      puVar3 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
      *param_5 = (int)puVar3;
      if (puVar3 == (undefined *)0x0) {
        FUN_08053a28(param_1,param_2,&local_10,1,&local_8);
      }
      DAT_080826a0 = DAT_080826a0 + 6;
      goto switchD_080693fe_caseD_5;
    }
    pcVar4 = "Missing comma";
LAB_08069941:
    FUN_08052f1c(4,pcVar4);
    return 0;
  }
  FUN_080535b0(param_1,param_2,1,&local_8);
switchD_080693fe_caseD_5:
  DAT_080826a0 = DAT_080826a0 + 2;
  return 1;
}



undefined4 FUN_08069990(void)

{
  FUN_08052f1c(4,"Invalid register or register combination for this operation");
  return 1;
}



bool FUN_080699a8(char *param_1,int *param_2,int param_3,uint param_4,int *param_5)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  uint uVar6;
  uint uVar7;
  undefined *puVar8;
  uint *puVar9;
  int iVar10;
  undefined1 uVar11;
  uint unaff_EDI;
  bool bVar12;
  char *pcVar13;
  uint local_7c;
  uint local_50;
  int local_4c;
  int local_48;
  int local_44;
  uint local_40;
  uint local_3c;
  uint local_2c;
  undefined4 local_28;
  uint local_24;
  int local_20;
  uint local_1c;
  uint local_18;
  undefined4 local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  bVar12 = false;
  local_3c = 0;
  if ((DAT_080826a0 & 1) != 0) {
    FUN_0805182c(0);
  }
  switch(param_3) {
  case 0:
    uVar6 = FUN_080679f0((int)param_1,param_2);
    if (param_4 != 0x4700) {
      if (param_1[*param_2] == ',') {
        *param_2 = *param_2 + 1;
      }
      local_44 = 0;
      local_48 = 0;
      local_4c = 0;
      local_10 = uVar6;
      if ((((((param_4 != 0x42c0) && (param_4 != 0x4280)) && (param_4 != 0x1c00)) &&
           ((param_4 != 0x43c0 && (param_4 != 0x4240)))) &&
          ((param_4 != 0x4200 && ((param_4 != 0x4600 && (param_4 != 0x4500)))))) &&
         (iVar10 = FUN_080613bc(param_1 + *param_2), iVar10 != 0)) {
        local_44 = 1;
        local_10 = FUN_080679f0((int)param_1,param_2);
        if (param_1[*param_2] == ',') {
          *param_2 = *param_2 + 1;
        }
      }
      iVar10 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar10 == '#') {
        local_4c = 1;
        *param_2 = *param_2 + 1;
        local_c = FUN_080535b0(param_1,param_2,0,&local_8);
        if (DAT_08080160 != 0) {
          return false;
        }
      }
      else if ((local_44 == 0) || (iVar10 = FUN_080613bc(param_1 + *param_2), iVar10 != 0)) {
        local_48 = 1;
        unaff_EDI = FUN_080679f0((int)param_1,param_2);
      }
    }
    if (param_4 != 0x4080) {
      if (0x4080 < param_4) {
        if (param_4 == 0x4100) goto LAB_08069ee0;
        if (param_4 < 0x4101) {
          if (param_4 == 0x40c0) goto LAB_08069ee0;
        }
        else {
          if (param_4 == 0x4280) goto LAB_08069e10;
          if (param_4 == 0x4700) {
            param_4 = uVar6 * 8 | 0x4700;
            break;
          }
        }
LAB_08069fa0:
        if (local_4c != 0) {
          FUN_08052f1c(4,"Immediate value cannot be used with this operation");
          local_3c = 1;
        }
        goto LAB_08069fbc;
      }
      if (param_4 == 0x1a00) {
LAB_08069ba0:
        if (local_4c == 0) {
          if (local_48 == 0) {
            unaff_EDI = local_10;
            local_10 = uVar6;
          }
          if (((7 < uVar6) || (7 < local_10)) || (7 < unaff_EDI)) {
            if ((uVar6 != local_10) || (param_4 == 0x1a00)) {
              local_3c = FUN_08069990();
            }
            uVar7 = uVar6 & 7 | (uVar6 & 8) << 4 | 0x4400 | (unaff_EDI & 7) << 3;
            uVar6 = (unaff_EDI & 8) * 8;
            goto LAB_0806adf2;
          }
          param_4 = param_4 | uVar6 | local_10 << 3 | unaff_EDI << 6;
        }
        else {
          if (7 < uVar6) {
            if (uVar6 != 0xd) {
              local_3c = FUN_08069990();
            }
            if ((local_c & 3) != 0) {
              FUN_08052f1c(4,"Immediate value must be word aligned for this operation");
              local_3c = 1;
            }
            if (param_4 == 0x1a00) {
              local_c = -local_c;
            }
            if (((int)local_c < -0x1ff) || (0x1ff < (int)local_c)) {
              FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
              local_3c = 1;
            }
            uVar7 = 0xb000;
            if ((int)local_c < 0) {
              uVar7 = 0xb080;
              local_c = -local_c;
            }
            uVar6 = local_c >> 2;
            goto LAB_0806adf2;
          }
          if ((local_10 == 0xd) || (local_10 == 0xf)) {
            bVar12 = (local_c & 3) != 0;
            if (bVar12) {
              FUN_08052f1c(4,"Immediate value must be word aligned for this operation");
            }
            local_3c = (uint)bVar12;
            if (param_4 == 0x1a00) {
              local_c = -local_c;
            }
            if (0x3ff < local_c) {
              FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
              local_3c = 1;
            }
            uVar11 = (undefined1)(local_c >> 2);
            if (local_10 == 0xd) {
              param_4 = (uint)CONCAT11(0xa8,uVar11) | uVar6 << 8;
            }
            else {
              param_4 = (uint)CONCAT11(0xa0,uVar11) | uVar6 << 8;
            }
          }
          else if (local_10 < 8) {
            if (((int)local_c < 8) && (-8 < (int)local_c)) {
              if ((int)local_c < 0) {
                if (param_4 == 0x1800) {
                  param_4 = 0x1a00;
                }
                else {
                  param_4 = 0x1800;
                }
                local_c = -local_c;
              }
              uVar7 = param_4 ^ 0x400 | local_c << 6 | uVar6;
              uVar6 = local_10 * 8;
              goto LAB_0806adf2;
            }
            if ((local_44 != 0) && (uVar6 != local_10)) {
              FUN_08052f1c(4,
                           "Source and destination registers must be identical for this instruction"
                          );
              local_3c = 1;
            }
            if ((local_c & 0xffffff00) == 0) {
              if (param_4 == 0x1800) {
                uVar7 = local_c | 0x3000;
              }
              else {
                uVar7 = local_c | 0x3800;
              }
              param_4 = uVar7 | uVar6 << 8;
            }
            else {
              FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
              local_3c = 1;
            }
          }
          else {
            local_3c = FUN_08069990();
          }
        }
        goto switchD_080699e5_caseD_7;
      }
      if (param_4 < 0x1a01) {
        if (param_4 != 0x1800) goto LAB_08069fa0;
        goto LAB_08069ba0;
      }
      if (param_4 != 0x1c00) goto LAB_08069fa0;
LAB_08069e10:
      if (local_4c != 0) {
        if (7 < uVar6) {
          local_3c = FUN_08069990();
        }
        if (0xff < local_c) {
          FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
          local_3c = 1;
        }
        if (param_4 == 0x1c00) {
          uVar7 = local_c | 0x2000;
        }
        else {
          uVar7 = local_c | 0x2800;
        }
        param_4 = uVar7 | uVar6 << 8;
        break;
      }
      if ((uVar6 < 8) && (unaff_EDI < 8)) {
        if (param_4 != 0x1c00) goto LAB_08069ee0;
        param_4 = unaff_EDI * 8 | uVar6 | 0x1c00;
        break;
      }
      if (param_4 == 0x1c00) {
        uVar7 = 0x4600;
      }
      else {
        uVar7 = 0x4500;
      }
      uVar6 = (unaff_EDI & 8) * 8 | (unaff_EDI & 7) << 3 | (uVar6 & 8) << 4 | uVar6 & 7;
      goto LAB_0806adf2;
    }
LAB_08069ee0:
    if (local_4c == 0) {
LAB_08069fbc:
      uVar7 = local_10;
      if ((local_48 != 0) && (uVar7 = unaff_EDI, uVar6 != local_10)) {
        local_3c = FUN_08069990();
      }
      if ((7 < uVar6) || (7 < uVar7)) {
        local_3c = FUN_08069990();
      }
      param_4 = uVar7 * 8 | uVar6 | param_4;
    }
    else {
      if ((param_4 == 0x40c0) || (param_4 == 0x4100)) {
        if (local_c == 0) {
          FUN_08052f1c(4,"Shift count out of range");
          local_3c = 1;
        }
        else if (local_c == 0x20) {
          local_c = 0;
        }
      }
      if (0x1f < local_c) {
        FUN_08052f1c(4,"Shift count out of range");
        local_3c = 1;
      }
      if ((7 < uVar6) || (7 < local_10)) {
        local_3c = FUN_08069990();
      }
      uVar7 = local_10 * 8;
      if (param_4 != 0x4080) {
        if (param_4 == 0x40c0) {
          uVar7 = uVar7 | 0x800;
        }
        else {
          uVar7 = uVar7 | 0x1000;
        }
      }
      param_4 = uVar7 | uVar6 | local_c << 6;
    }
    break;
  case 1:
    bVar3 = false;
    if (((param_4 == 0x5c00) || (param_4 == 0x5400)) || (param_4 == 0x5600)) {
      bVar3 = true;
    }
    bVar2 = false;
    if ((param_4 == 0x5600) || (param_4 == 0x5e00)) {
      bVar2 = true;
    }
    bVar1 = false;
    if (((param_4 == 0x5a00) || (param_4 == 0x5e00)) || (param_4 == 0x5200)) {
      bVar1 = true;
    }
    if (bVar1) {
      if (param_4 == 0x5a00) {
        uVar6 = 0x800;
      }
      else {
        uVar6 = 0;
      }
    }
    else {
      uVar6 = param_4 & 0x800;
    }
    bVar4 = false;
    bVar5 = false;
    local_40 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_c = 0;
    iVar10 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar10 == '[') {
      *param_2 = *param_2 + 1;
      local_10 = FUN_080679f0((int)param_1,param_2);
      iVar10 = *param_2;
      if (param_1[iVar10] == ']') {
        *param_2 = iVar10 + 1;
        iVar10 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar10 != ',') goto LAB_0806a59f;
        *param_2 = *param_2 + 1;
        iVar10 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar10 == '#') {
          *param_2 = *param_2 + 1;
        }
        if ((bVar2) || (bVar1)) {
          FUN_08052f1c(4,"Immediate value cannot be used with this operation");
          local_3c = 1;
        }
      }
      else {
        bVar4 = true;
        *param_2 = iVar10 + 1;
        iVar10 = FUN_0805fa50((int)param_1,param_2);
        if ((char)iVar10 != '#') {
          if (param_1[*param_2] == '+') {
            *param_2 = *param_2 + 1;
          }
          local_c = FUN_080679f0((int)param_1,param_2);
          bVar5 = true;
          if (7 < local_c) {
            local_3c = FUN_08069990();
          }
          goto LAB_0806a5a6;
        }
        *param_2 = *param_2 + 1;
      }
      local_c = FUN_080535b0(param_1,param_2,0,&local_8);
      if (DAT_08080160 != 0) {
        return false;
      }
    }
    else {
      if (((param_1[*param_2] == '=') && (DAT_080825c4 == 0)) ||
         ((param_1[*param_2] == '#' && (DAT_080825c4 == 1)))) {
        *param_2 = *param_2 + 1;
        puVar8 = FUN_08053bbc(param_1,param_2,&local_14,(uint *)0x0);
        *param_5 = (int)puVar8;
        local_10 = 0xf;
        if (puVar8 == (undefined *)0x0) {
          local_18 = 0;
          local_14 = FUN_08053738(param_1,param_2,&local_1c,0,&local_8,&local_18);
          if (DAT_08080160 != 0) {
            return false;
          }
          if (((bVar3) || (bVar1)) && ((local_1c != 1 || (0xff < local_14)))) {
            if (bVar1) {
              pcVar13 = "Halfword literal values not supported";
            }
            else {
              pcVar13 = "Operand to LDRB does not fit in 8 bits";
            }
            goto LAB_0806ad2e;
          }
          if (local_1c == 3) {
            if (local_18 != 0) {
              local_14 = local_14 | 1;
            }
            local_c = FUN_08056c4c(local_14,1,0,0x3fc);
          }
          else {
            if (local_14 < 0x100) {
              param_4 = local_14 | 0x2000 | local_40 << 8;
              break;
            }
            local_c = FUN_08056bec(1,0,local_14,0,0x3fc);
          }
        }
        else {
          local_c = FUN_08056c1c((uint)puVar8,local_14,0,0x3fc);
        }
        local_c = local_c - (DAT_080826a0 + 4 & 0xfffffffd);
      }
      else {
        puVar8 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
        *param_5 = (int)puVar8;
        if (puVar8 == (undefined *)0x0) {
          local_c = FUN_08053a28(param_1,param_2,&local_10,0,&local_8);
          if (local_10 == 0xf) {
            local_c = local_c - (DAT_080826a0 + 4 & 0xfffffffd);
          }
        }
        else {
          local_10 = 0xf;
          bVar12 = true;
        }
        if ((bVar12) || (0xff < local_10)) {
          if (DAT_08082654 != 0) {
            pcVar13 = "a.out can\'t handle external adresses except for branches";
LAB_0806ad2e:
            FUN_08052f1c(4,pcVar13);
            return false;
          }
          if (local_10 != 0xf) {
            pcVar13 = "BASED areas must be accessed using LDA, not LDR";
            goto LAB_0806ad2e;
          }
          iVar10 = *param_5;
          if ((*(byte *)(iVar10 + 8) & 3) == 1) {
            uVar7 = *(uint *)(iVar10 + 0x18) & 0xffffff | 0x8f000000;
          }
          else {
            uVar7 = *(int *)(iVar10 + 0x1c) - 1U | 0x87000000;
          }
          FUN_080514cc(DAT_080826a0,uVar7,1);
        }
        if (DAT_08080160 != 0) {
          return false;
        }
      }
LAB_0806a59f:
      bVar4 = true;
    }
LAB_0806a5a6:
    if ((((local_10 == 0xd) || ((local_10 == 0xf && (uVar6 != 0)))) && (bVar4)) &&
       (((!bVar3 && (!bVar1)) && (!bVar5)))) {
      if (7 < local_40) {
        local_3c = FUN_08069990();
      }
      if (local_10 == 0xd) {
        param_4 = uVar6 | 0x9000;
      }
      else {
        param_4 = 0x4800;
      }
      if ((local_c & 3) != 0) {
        FUN_08052f1c(4,"Offset must be word aligned with this operation");
        local_3c = 1;
      }
      local_c = local_c >> 2;
      if (0xff < local_c) {
        FUN_08052f1c(4,"Data transfer offset out of range");
        goto LAB_0806ade8;
      }
      goto LAB_0806adeb;
    }
    if ((7 < local_40) || (7 < local_10)) {
      local_3c = FUN_08069990();
    }
    if (!bVar4) {
      pcVar13 = "Post indexed addressing mode not available";
      goto LAB_0806a735;
    }
    if ((bVar1) || (bVar2)) {
      if (!bVar5) {
        if (bVar2) {
          pcVar13 = "Pre indexed addressing mode not available for this instruction, use [Rn, Rm]";
        }
        else {
          param_4 = uVar6 | 0x8000;
          if ((local_c & 1) != 0) {
            FUN_08052f1c(4,"Offset must be halfword aligned with this operation");
            local_3c = 1;
          }
          local_c = local_c >> 1;
          if (local_c < 0x20) goto LAB_0806a746;
          pcVar13 = "Data transfer offset out of range";
        }
LAB_0806a735:
        FUN_08052f1c(4,pcVar13);
        local_3c = 1;
      }
    }
    else if (bVar5) {
      param_4 = uVar6 | 0x5000;
      if (bVar3) {
        param_4 = uVar6 | 0x5400;
      }
    }
    else {
      param_4 = uVar6 | 0x6000;
      if (bVar3) {
        param_4 = uVar6 | 0x7000;
      }
      else {
        if ((local_c & 3) != 0) {
          FUN_08052f1c(4,"Offset must be word aligned with this operation");
          local_3c = 1;
        }
        local_c = local_c >> 2;
      }
      if (0x1f < local_c) {
        pcVar13 = "Data transfer offset out of range";
        goto LAB_0806a735;
      }
    }
LAB_0806a746:
    param_4 = local_10 * 8 | param_4 | local_c << 6 | local_40;
    break;
  case 2:
    puVar8 = FUN_08053bbc(param_1,param_2,&local_14,(uint *)0x0);
    *param_5 = (int)puVar8;
    if (puVar8 == (undefined *)0x0) {
      local_14 = FUN_080535b0(param_1,param_2,0,&local_8);
    }
    else {
      if (DAT_08082654 != 0) {
        pcVar13 = "a.out can\'t handle external adresses except for branches";
        goto LAB_0806ad2e;
      }
      FUN_080514cc(DAT_080826a0,*(uint *)(puVar8 + 0x18) & 0xffffff | 0x8a000000,0);
    }
    bVar12 = 0xff < local_14;
    if (bVar12) {
      FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
    }
    local_3c = (uint)bVar12;
    param_4 = local_14 + param_4;
    break;
  case 3:
  case 0x2e:
    local_10 = 0;
    uVar6 = 0;
    if (param_3 == 3) {
      local_10 = FUN_080679f0((int)param_1,param_2);
      iVar10 = *param_2;
      if (param_1[iVar10] == '!') {
        *param_2 = iVar10 + 1;
        FUN_0805fa50((int)param_1,param_2);
        iVar10 = *param_2;
      }
      *param_2 = iVar10 + 1;
    }
    local_14 = FUN_08067bdc((int)param_1,param_2);
    if (param_3 == 0x2e) {
      if (param_4 == 0xb400) {
        if ((local_14 & 0x4000) != 0) {
          local_14 = local_14 ^ 0x4000;
LAB_0806a7d1:
          uVar6 = 0x100;
        }
      }
      else if ((short)local_14 < 0) {
        local_14 = local_14 ^ 0x8000;
        goto LAB_0806a7d1;
      }
    }
    if ((7 < local_10) || (local_14._1_1_ != '\0')) {
      local_3c = FUN_08069990();
    }
    param_4 = uVar6 | param_4 | local_10 << 8 | local_14;
    break;
  case 4:
  case 0x30:
    local_24 = (uint)(param_3 != 0x30);
    local_1c = 0;
    if (param_3 == 0x30) {
      local_20 = 0;
      local_14 = FUN_08067968(param_1,param_2,&local_14,&local_24,&local_20,param_5);
      if (local_20 != 0) {
        param_4 = local_14 << 3 | 0x4780;
        break;
      }
    }
    else {
      puVar8 = FUN_08053bbc(param_1,param_2,&local_14,&local_24);
      *param_5 = (int)puVar8;
    }
    if (*param_5 == 0) {
      local_14 = FUN_08053738(param_1,param_2,&local_1c,0,&local_8,&local_24);
      if (DAT_08080160 != 0) {
        return false;
      }
      if (local_1c == 1) {
        puVar9 = FUN_0805f5ec(**(uint **)(DAT_0808014c + 0x18),
                              (char *)(*(uint **)(DAT_0808014c + 0x18))[1],0);
        *param_5 = (int)puVar9;
      }
    }
    if ((param_4 == 0xf800) || (param_4 == 0xe800)) {
      FUN_08051e28(DAT_080826fc);
    }
    if ((((*(byte *)(DAT_0808014c + 5) & 1) == 0) || (local_1c != 1)) &&
       (iVar10 = *param_5, iVar10 != 0)) {
      if (DAT_08082654 == 0) {
        if ((param_4 != 0xf800) && (param_4 != 0xe800)) {
          FUN_08052f1c(4,"Only BL can be used to branch to external symbols or other AREAs");
          local_3c = 1;
        }
        local_2c = DAT_080826a0;
        iVar10 = *param_5;
        if ((*(byte *)(iVar10 + 8) & 3) == 1) {
          local_28 = *(uint *)(iVar10 + 0x18) & 0xffffff | 0x8f000000;
        }
        else {
          local_28 = *(int *)(iVar10 + 0x1c) - 1U | 0x87000000;
        }
        local_14 = (local_14 - 4) + (*(int *)(DAT_0808014c + 0x10) - DAT_080826a0);
      }
      else {
        local_2c = DAT_080826a0;
        local_14 = local_14 - 4;
        if ((*(byte *)(iVar10 + 8) & 3) == 1) {
          local_28 = CONCAT13(0xe,(int3)*(undefined4 *)(iVar10 + 0x18));
        }
        else {
          local_14 = local_14 + (DAT_08082664 - DAT_080826a0);
          if (DAT_080825c4 == 0) {
            iVar10 = FUN_08051d60(*(uint *)(iVar10 + 0x1c));
            if ((*(byte *)(iVar10 + 5) & 0x10) == 0) {
              local_7c = 6;
            }
            else {
              local_7c = 8;
            }
            local_28 = local_7c | 0x7000000;
            if ((*(byte *)(iVar10 + 5) & 0x10) != 0) {
LAB_0806ab4d:
              local_14 = local_14 + DAT_08082668;
            }
          }
          else {
            if (*(int *)(iVar10 + 0x1c) == 2) {
              local_28 = 8;
            }
            else {
              local_28 = 6;
            }
            local_28 = local_28 | 0x7000000;
            if (*(int *)(*param_5 + 0x1c) == 2) goto LAB_0806ab4d;
          }
        }
      }
      FUN_080514cc(local_2c,local_28,1);
    }
    else {
      local_14 = (local_14 - 4) - DAT_080826a0;
    }
    if (param_4 == 0xe800) {
      if ((DAT_080826a0 + local_14 & 3) != 0) goto LAB_0806ab8c;
LAB_0806aba2:
      if (param_4 != 0xe800) goto LAB_0806abaa;
LAB_0806abbf:
      if (local_24 != 0) {
        pcVar13 = "BLX from 16 bit code to 16 bit code, use BL";
LAB_0806abca:
        FUN_08052f1c(4,pcVar13);
        local_3c = 1;
      }
    }
    else {
      if ((local_14 & 1) != 0) {
LAB_0806ab8c:
        FUN_08052f1c(4,"Branch to unaligned destination");
        local_3c = 1;
        goto LAB_0806aba2;
      }
LAB_0806abaa:
      if (local_24 == 0) {
        pcVar13 = "B or BL from 16 bit code to 32 bit code";
        goto LAB_0806abca;
      }
      if (param_4 == 0xe800) goto LAB_0806abbf;
    }
    if ((param_4 == 0xf800) || (param_4 == 0xe800)) {
      if (((int)local_14 < -0x1000000) || (0xffffff < (int)local_14)) {
        FUN_08052f1c(4,"Branch offset out of range");
        local_3c = 1;
      }
      FUN_08051c40((local_14 >> 0xc & 0x7ff) + 0xf000);
      local_14 = local_14 >> 1 & 0x7ff;
    }
    else if (param_4 == 0xe000) {
      if (((int)local_14 < -0x800) || (0x7ff < (int)local_14)) {
        FUN_08052f1c(4,"Branch offset out of range");
        local_3c = 1;
      }
      local_14 = local_14 >> 1 & 0x7ff;
    }
    else {
      if (((int)local_14 < -0x100) || (0xff < (int)local_14)) {
        FUN_08052f1c(4,"Branch offset out of range");
        local_3c = 1;
      }
      local_14 = local_14 >> 1 & 0xff;
    }
    param_4 = param_4 + local_14;
    goto switchD_080699e5_caseD_7;
  default:
    goto switchD_080699e5_caseD_5;
  case 6:
    local_40 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    local_c = FUN_0805384c(param_1,param_2,&local_10,&local_1c,0,&local_8);
    if (DAT_08080160 != 0) {
      return false;
    }
    if (local_1c == 3) {
LAB_0806ad40:
      local_c = (local_c - 4) - (DAT_080826a0 & 0xfffffffd);
      bVar12 = (local_c & 3) != 0;
      if (bVar12) {
        FUN_08052f1c(4,"Immediate value must be word aligned for this operation");
      }
      local_3c = (uint)bVar12;
      if ((int)local_c < 0) {
        local_c = local_c + 3;
      }
      local_c = (int)local_c >> 2;
    }
    else if (local_1c < 4) {
      if (local_1c == 1) {
        if (DAT_08082640 != 0) {
          pcVar13 = "Immediate value cannot be used with this operation";
          goto LAB_0806ad2e;
        }
        goto LAB_0806ad40;
      }
    }
    else if (local_1c == 4) {
      if (7 < local_10) {
        local_3c = FUN_08069990();
      }
      FUN_08051c40(local_10 * 8 | 0x1c00 | local_40);
      param_4 = 0x3000;
    }
    if (7 < local_40) {
      local_3c = FUN_08069990();
    }
    if (0xff < local_c) {
      FUN_08052f1c(4,"Immediate 0x%08X out of range for this operation");
LAB_0806ade8:
      local_3c = 1;
    }
LAB_0806adeb:
    uVar7 = param_4 | local_40 << 8;
    uVar6 = local_c;
LAB_0806adf2:
    param_4 = uVar7 | uVar6;
switchD_080699e5_caseD_7:
    break;
  case 7:
    goto switchD_080699e5_caseD_7;
  case 0x2f:
    uVar6 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    FUN_0805fa50((int)param_1,param_2);
    puVar8 = FUN_08053bbc(param_1,param_2,(int *)&local_c,(uint *)0x0);
    *param_5 = (int)puVar8;
    local_10 = 0xf;
    if (puVar8 == (undefined *)0x0) {
      local_c = FUN_08053a28(param_1,param_2,&local_10,0,&local_8);
    }
    uVar7 = DAT_080826a0;
    local_10 = local_10 & 0xf;
    if (local_10 == 0xf) {
      iVar10 = *param_5;
      if ((*(byte *)(iVar10 + 8) & 3) == 1) {
        local_50 = *(uint *)(iVar10 + 0x18) & 0xffffff | 0x8f000000;
      }
      else {
        local_50 = *(int *)(iVar10 + 0x1c) - 1U | 0x87000000;
      }
      FUN_08052f1c(4,"LDA can only load addresses from BASED AREAs");
      local_3c = 1;
    }
    else {
      local_50 = (&DAT_08082720)[local_10] - 1 | 0x93000000;
    }
    FUN_080514cc(uVar7,local_50,1);
    if (7 < uVar6) {
      local_3c = FUN_08069990();
    }
    if (0x7fff < local_c) {
      FUN_08052f1c(4,"Data transfer offset out of range");
      local_3c = 1;
    }
    if ((local_c & 3) != 0) {
      FUN_08052f1c(4,"Offset must be word aligned with this operation");
      local_3c = 1;
    }
    FUN_08051c40(uVar6 << 8 | CONCAT22((ushort)(local_c >> 0x17),(short)(local_c >> 7)) | 0x2000);
    FUN_08051c40(uVar6 * 8 | uVar6 | 0x1c0);
    if (local_10 < 8) {
      uVar7 = uVar6 << 6 | local_10 << 3 | 0x1800 | uVar6;
    }
    else {
      uVar7 = local_10 * 8 - 0x40 | uVar6 | 0x4440;
    }
    FUN_08051c40(uVar7);
    param_4 = (local_c & 0x7c) << 4 | uVar6 * 8 | 0x6800 | uVar6;
  }
  FUN_08051c40(param_4);
switchD_080699e5_caseD_5:
  return local_3c == 0;
}



undefined4 FUN_0806ae20(int param_1,undefined1 *param_2)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  undefined4 uVar4;
  
  uVar4 = 0xffffffff;
  pcVar2 = param_2 + 1;
  switch(*param_2) {
  case 0x41:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'N') {
        if ((2 < param_1) && (*pcVar2 == 'D')) {
          uVar4 = 3;
        }
      }
      else if (cVar1 < 'O') {
        if ((cVar1 == 'D') && (2 < param_1)) {
          cVar1 = *pcVar2;
          if (cVar1 == 'D') {
            uVar4 = 1;
          }
          else if (cVar1 < 'E') {
            if (cVar1 == 'C') {
              uVar4 = 0;
            }
          }
          else if (cVar1 == 'R') {
            uVar4 = 2;
          }
        }
      }
      else if ((cVar1 == 'S') && (2 < param_1)) {
        if (*pcVar2 == 'L') {
          uVar4 = 4;
        }
        else if (*pcVar2 == 'R') {
          uVar4 = 5;
        }
      }
    }
    break;
  case 0x42:
    uVar4 = 6;
    if (1 < param_1) {
      pcVar3 = param_2 + 2;
      switch(*pcVar2) {
      case 'C':
        if (2 < param_1) {
          if (*pcVar3 == 'C') {
            uVar4 = 7;
          }
          else if (*pcVar3 == 'S') {
            uVar4 = 8;
          }
        }
        break;
      case 'E':
        if ((2 < param_1) && (*pcVar3 == 'Q')) {
          uVar4 = 9;
        }
        break;
      case 'G':
        if (2 < param_1) {
          if (*pcVar3 == 'E') {
            uVar4 = 10;
          }
          else if (*pcVar3 == 'T') {
            uVar4 = 0xb;
          }
        }
        break;
      case 'H':
        if (2 < param_1) {
          if (*pcVar3 == 'I') {
            uVar4 = 0xc;
          }
          else if (*pcVar3 == 'S') {
            uVar4 = 0xd;
          }
        }
        break;
      case 'I':
        if ((2 < param_1) && (*pcVar3 == 'C')) {
          uVar4 = 0xe;
        }
        break;
      case 'L':
        uVar4 = 0xf;
        if (2 < param_1) {
          switch(*pcVar3) {
          case 'E':
            uVar4 = 0x10;
            break;
          case 'O':
            uVar4 = 0x11;
            break;
          case 'S':
            uVar4 = 0x12;
            break;
          case 'T':
            uVar4 = 0x13;
            break;
          case 'X':
            uVar4 = 0x14;
          }
        }
        break;
      case 'M':
        if ((2 < param_1) && (*pcVar3 == 'I')) {
          uVar4 = 0x15;
        }
        break;
      case 'N':
        if (2 < param_1) {
          pcVar2 = param_2 + 3;
          switch(*pcVar3) {
          case 'C':
            if (3 < param_1) {
              if (*pcVar2 == 'C') {
                uVar4 = 0x16;
              }
              else if (*pcVar2 == 'S') {
                uVar4 = 0x17;
              }
            }
            break;
          case 'E':
            uVar4 = 0x18;
            if ((3 < param_1) && (*pcVar2 == 'Q')) {
              uVar4 = 0x19;
            }
            break;
          case 'G':
            if (3 < param_1) {
              if (*pcVar2 == 'E') {
                uVar4 = 0x1a;
              }
              else if (*pcVar2 == 'T') {
                uVar4 = 0x1b;
              }
            }
            break;
          case 'H':
            if (3 < param_1) {
              if (*pcVar2 == 'I') {
                uVar4 = 0x1c;
              }
              else if (*pcVar2 == 'S') {
                uVar4 = 0x1d;
              }
            }
            break;
          case 'L':
            if (3 < param_1) {
              cVar1 = *pcVar2;
              if (cVar1 == 'O') {
                uVar4 = 0x1f;
              }
              else if (cVar1 < 'P') {
                if (cVar1 == 'E') {
                  uVar4 = 0x1e;
                }
              }
              else if (cVar1 == 'S') {
                uVar4 = 0x20;
              }
              else if (cVar1 == 'T') {
                uVar4 = 0x21;
              }
            }
            break;
          case 'M':
            if ((3 < param_1) && (*pcVar2 == 'I')) {
              uVar4 = 0x22;
            }
            break;
          case 'N':
            if ((3 < param_1) && (*pcVar2 == 'E')) {
              uVar4 = 0x23;
            }
            break;
          case 'P':
            if ((3 < param_1) && (*pcVar2 == 'L')) {
              uVar4 = 0x24;
            }
            break;
          case 'V':
            if (3 < param_1) {
              if (*pcVar2 == 'C') {
                uVar4 = 0x25;
              }
              else if (*pcVar2 == 'S') {
                uVar4 = 0x26;
              }
            }
          }
        }
        break;
      case 'P':
        if ((2 < param_1) && (*pcVar3 == 'L')) {
          uVar4 = 0x27;
        }
        break;
      case 'V':
        if (2 < param_1) {
          if (*pcVar3 == 'C') {
            uVar4 = 0x28;
          }
          else if (*pcVar3 == 'S') {
            uVar4 = 0x29;
          }
        }
        break;
      case 'X':
        uVar4 = 0x2a;
      }
    }
    break;
  case 0x43:
    if (((1 < param_1) && (*pcVar2 == 'M')) && (2 < param_1)) {
      if (param_2[2] == 'N') {
        uVar4 = 0x2b;
      }
      else if (param_2[2] == 'P') {
        uVar4 = 0x2c;
      }
    }
    break;
  case 0x45:
    if ((((1 < param_1) && (*pcVar2 == 'O')) && (2 < param_1)) && (param_2[2] == 'R')) {
      uVar4 = 0x2d;
    }
    break;
  case 0x4c:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'E') {
        if ((2 < param_1) && (*pcVar2 == 'A')) {
          uVar4 = 0x38;
        }
      }
      else if (cVar1 < 'F') {
        if ((cVar1 == 'D') && (2 < param_1)) {
          cVar1 = *pcVar2;
          pcVar2 = param_2 + 3;
          if (cVar1 == 'M') {
            uVar4 = 0x2f;
            if ((((3 < param_1) && (*pcVar2 == 'I')) && (4 < param_1)) && (param_2[4] == 'A')) {
              uVar4 = 0x30;
            }
          }
          else if (cVar1 < 'N') {
            if (cVar1 == 'A') {
              uVar4 = 0x2e;
            }
          }
          else if (cVar1 == 'R') {
            uVar4 = 0x31;
            if (3 < param_1) {
              cVar1 = *pcVar2;
              if (cVar1 == 'H') {
                uVar4 = 0x33;
              }
              else if (cVar1 < 'I') {
                if (cVar1 == 'B') {
                  uVar4 = 0x32;
                }
              }
              else if ((cVar1 == 'S') && (4 < param_1)) {
                if (param_2[4] == 'B') {
                  uVar4 = 0x34;
                }
                else if (param_2[4] == 'H') {
                  uVar4 = 0x35;
                }
              }
            }
          }
          else if ((cVar1 == 'S') && (3 < param_1)) {
            if (*pcVar2 == 'B') {
              uVar4 = 0x36;
            }
            else if (*pcVar2 == 'H') {
              uVar4 = 0x37;
            }
          }
        }
      }
      else if ((cVar1 == 'S') && (2 < param_1)) {
        if (*pcVar2 == 'L') {
          uVar4 = 0x39;
        }
        else if (*pcVar2 == 'R') {
          uVar4 = 0x3a;
        }
      }
    }
    break;
  case 0x4d:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'U') {
        if ((2 < param_1) && (*pcVar2 == 'L')) {
          uVar4 = 0x3c;
        }
      }
      else if (cVar1 < 'V') {
        if (((cVar1 == 'O') && (2 < param_1)) && (*pcVar2 == 'V')) {
          uVar4 = 0x3b;
        }
      }
      else if (((cVar1 == 'V') && (2 < param_1)) && (*pcVar2 == 'N')) {
        uVar4 = 0x3d;
      }
    }
    break;
  case 0x4e:
    if (1 < param_1) {
      if (*pcVar2 == 'E') {
        if ((2 < param_1) && (param_2[2] == 'G')) {
          uVar4 = 0x3e;
        }
      }
      else if (((*pcVar2 == 'O') && (2 < param_1)) && (param_2[2] == 'P')) {
        uVar4 = 0x3f;
      }
    }
    break;
  case 0x4f:
    if (((1 < param_1) && (*pcVar2 == 'R')) && ((2 < param_1 && (param_2[2] == 'R')))) {
      uVar4 = 0x40;
    }
    break;
  case 0x50:
    if (1 < param_1) {
      if (*pcVar2 == 'O') {
        if ((2 < param_1) && (param_2[2] == 'P')) {
          uVar4 = 0x41;
        }
      }
      else if ((((*pcVar2 == 'U') && (2 < param_1)) && (param_2[2] == 'S')) &&
              ((3 < param_1 && (param_2[3] == 'H')))) {
        uVar4 = 0x42;
      }
    }
    break;
  case 0x52:
    if (((1 < param_1) && (*pcVar2 == 'O')) && ((2 < param_1 && (param_2[2] == 'R')))) {
      uVar4 = 0x43;
    }
    break;
  case 0x53:
    if (1 < param_1) {
      cVar1 = *pcVar2;
      pcVar2 = param_2 + 2;
      if (cVar1 == 'T') {
        if (2 < param_1) {
          if (*pcVar2 == 'M') {
            uVar4 = 0x45;
            if (((3 < param_1) && (param_2[3] == 'I')) && ((4 < param_1 && (param_2[4] == 'A')))) {
              uVar4 = 0x46;
            }
          }
          else if ((*pcVar2 == 'R') && (uVar4 = 0x47, 3 < param_1)) {
            cVar1 = param_2[3];
            if (cVar1 == 'B') {
              uVar4 = 0x48;
            }
            else if (cVar1 == 'H') {
              uVar4 = 0x49;
            }
          }
        }
      }
      else if (cVar1 < 'U') {
        if (((cVar1 == 'B') && (2 < param_1)) && (*pcVar2 == 'C')) {
          uVar4 = 0x44;
        }
      }
      else if (cVar1 == 'U') {
        if ((2 < param_1) && (*pcVar2 == 'B')) {
          uVar4 = 0x4a;
        }
      }
      else if (((cVar1 == 'W') && (2 < param_1)) && (*pcVar2 == 'I')) {
        uVar4 = 0x4b;
      }
    }
    break;
  case 0x54:
    if ((((1 < param_1) && (*pcVar2 == 'S')) && (2 < param_1)) && (param_2[2] == 'T')) {
      uVar4 = 0x4c;
    }
  }
  return uVar4;
}



undefined4 FUN_0806b7e4(int param_1,undefined1 *param_2,int *param_3,undefined4 *param_4)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = FUN_0806ae20(param_1,param_2);
  if (iVar3 != -1) {
    iVar3 = iVar3 * 0xc;
    iVar1 = *(int *)(&DAT_0807a960 + iVar3);
    uVar2 = *(undefined4 *)(&DAT_0807a964 + iVar3);
    if ((param_1 == iVar1) ||
       (((param_1 - iVar1 == 1 && (*(int *)(&DAT_0807a968 + iVar3) == 0)) && (param_2[iVar1] == 'S')
        ))) {
      *param_3 = *(int *)(&DAT_0807a968 + iVar3);
      *param_4 = uVar2;
      return 1;
    }
  }
  return 0;
}



void FUN_0806b848(void)

{
  return;
}



undefined4 FUN_0806b850(char *param_1,int *param_2,undefined4 param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  char *pcVar5;
  uint local_10;
  uint local_c;
  uint local_8;
  
  switch(param_3) {
  case 0x10:
    FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar5 = "Missing comma";
      break;
    }
    *param_2 = *param_2 + 1;
  case 0x11:
    uVar3 = param_4 & 0xfffffff;
    if (((((uVar3 == 0xeb70ac0) || (uVar3 == 0xeb70bc0)) || (uVar3 == 0xebc0b40)) ||
        ((uVar3 == 0xebd0b40 || (uVar3 == 0xebc0bc0)))) || (uVar3 == 0xebd0bc0)) {
      uVar3 = (byte)((byte)(param_4 >> 8) ^ 1) & 1;
    }
    else {
      uVar3 = param_4 & 0x100;
    }
    FUN_0806d080((int)param_1,param_2,uVar3);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
switchD_0806b871_caseD_12:
      if (((param_4 & 0xfffffff) == 0xeb80b40) || ((param_4 & 0xfffffff) == 0xeb80bc0)) {
        uVar3 = (param_4 >> 8 ^ 1) & 1;
      }
      else {
LAB_0806b9a8:
        uVar3 = param_4 & 0x100;
      }
      FUN_0806d080((int)param_1,param_2,uVar3);
LAB_0806b9b6:
      if (DAT_08080160 != 0) {
        return 0;
      }
switchD_0806b871_default:
      return 1;
    }
    pcVar5 = "Missing comma";
    break;
  case 0x12:
    goto switchD_0806b871_caseD_12;
  case 0x13:
  case 0x14:
    FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar5 = "Missing comma";
      break;
    }
    *param_2 = *param_2 + 1;
    FUN_080679f0((int)param_1,param_2);
    goto LAB_0806b9b6;
  case 0x15:
  case 0x16:
    FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] != ',') {
      pcVar5 = "Missing comma";
      break;
    }
    *param_2 = *param_2 + 1;
    goto LAB_0806b9a8;
  case 0x17:
    FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == ',') {
      *param_2 = *param_2 + 1;
      iVar1 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar1 == '[') {
        *param_2 = *param_2 + 1;
        local_10 = FUN_080679f0((int)param_1,param_2);
        if (DAT_08080160 != 0) {
          return 0;
        }
        iVar1 = *param_2;
        if (param_1[iVar1] == ',') {
          *param_2 = iVar1 + 1;
          iVar1 = FUN_0805fa50((int)param_1,param_2);
          if ((char)iVar1 == '#') {
            *param_2 = *param_2 + 1;
            FUN_080535b0(param_1,param_2,1,&local_8);
          }
          else {
            FUN_08052f1c(4,"Missing \'#\'");
          }
          if (DAT_08080160 != 0) {
            return 0;
          }
          iVar1 = *param_2;
          if (param_1[iVar1] == ']') goto LAB_0806baa0;
          pcVar5 = "Missing close square bracket";
        }
        else {
          if (param_1[iVar1] == ']') {
LAB_0806baa0:
            iVar1 = iVar1 + 1;
LAB_0806bc66:
            *param_2 = iVar1;
            return 1;
          }
          pcVar5 = "Missing comma";
        }
      }
      else {
        if ((param_1[*param_2] != '=') || ((param_4 & 0x500000) != 0x100000)) {
          FUN_08053a28(param_1,param_2,&local_10,1,&local_8);
          return 1;
        }
        *param_2 = *param_2 + 1;
        uVar3 = param_4 >> 8 & 1;
        iVar1 = FUN_080547e0((int)param_1,param_2,uVar3,&local_10,&local_c);
        if (iVar1 == 1) {
          pcVar5 = "Floating point overflow";
        }
        else {
          if (iVar1 != 2) {
            if (uVar3 == 0) {
              FUN_08056c6c(local_10,-0x3fc,0x3fc);
              return 1;
            }
            if (uVar3 != 1) {
              return 1;
            }
            FUN_08056c8c(local_10,local_c,-0x3fc,0x3fc);
            return 1;
          }
          pcVar5 = "Floating point number not found";
        }
      }
    }
    else {
      pcVar5 = "Missing comma";
    }
    break;
  case 0x18:
    FUN_080679f0((int)param_1,param_2);
    if (DAT_08080160 != 0) {
      return 0;
    }
    if (param_1[*param_2] == '!') {
      *param_2 = *param_2 + 1;
    }
    iVar1 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar1 == ',') {
      *param_2 = *param_2 + 1;
      iVar1 = FUN_0805fa50((int)param_1,param_2);
      if ((char)iVar1 == '{') {
        *param_2 = *param_2 + 1;
        uVar3 = param_4 & 0x100;
        while( true ) {
          uVar2 = FUN_0806d080((int)param_1,param_2,uVar3);
          if (DAT_08080160 != 0) {
            return 0;
          }
          while( true ) {
            iVar1 = FUN_0805fa50((int)param_1,param_2);
            if ((char)iVar1 == '}') {
              iVar1 = *param_2;
              *param_2 = iVar1 + 1;
              if (uVar3 == 0) {
                return 1;
              }
              if (param_1[iVar1 + 1] != '^') {
                return 1;
              }
              iVar1 = iVar1 + 2;
              goto LAB_0806bc66;
            }
            iVar1 = *param_2;
            if (param_1[iVar1] != ',') break;
            *param_2 = iVar1 + 1;
            local_10 = FUN_0806d080((int)param_1,param_2,uVar3);
            if (DAT_08080160 != 0) {
              return 0;
            }
            bVar4 = uVar2 != local_10 - 1;
            uVar2 = local_10;
            if (bVar4) {
              pcVar5 = "Bad register range";
              goto LAB_0806bc35;
            }
          }
          if (param_1[iVar1] != '-') break;
          *param_2 = iVar1 + 1;
        }
        pcVar5 = "Bad register list symbol";
      }
      else {
        pcVar5 = "Missing open bracket";
      }
    }
    else {
      pcVar5 = "Missing comma";
    }
    break;
  default:
    goto switchD_0806b871_default;
  }
LAB_0806bc35:
  FUN_08052f1c(4,pcVar5);
  return 0;
}



undefined4 FUN_0806bc80(char *param_1,int *param_2,undefined4 param_3,uint param_4)

{
  undefined1 uVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined1 *puVar7;
  uint *puVar8;
  int unaff_ESI;
  uint uVar9;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  switch(param_3) {
  case 0x10:
    uVar5 = param_4 & 0x100;
    uVar6 = FUN_0806d080((int)param_1,param_2,uVar5);
    if (uVar5 == 0) {
      uVar6 = (uVar6 & 0x1e) << 0xb | (uVar6 & 1) << 0x16;
    }
    else {
      uVar6 = (uVar6 & 0xf) << 0xc;
    }
    *param_2 = *param_2 + 1;
    uVar9 = FUN_0806d080((int)param_1,param_2,uVar5);
    if (uVar5 == 0) {
      local_14 = (uVar9 & 1) << 7 | (uVar9 & 0x1e) << 0xf;
    }
    else {
      local_14 = (uVar9 & 0xf) << 0x10;
    }
    *param_2 = *param_2 + 1;
    uVar9 = FUN_0806d080((int)param_1,param_2,uVar5);
    if (uVar5 == 0) {
      uVar9 = (uVar9 & 0x1e) >> 1 | (uVar9 & 1) << 5;
    }
    else {
      uVar9 = uVar9 & 0xf;
    }
    param_4 = param_4 | uVar6 | local_14;
    goto LAB_0806c344;
  case 0x11:
    uVar9 = param_4 & 0xfffffff;
    if (((((uVar9 == 0xeb70ac0) || (uVar9 == 0xeb70bc0)) || (uVar9 == 0xebc0b40)) ||
        ((uVar9 == 0xebd0b40 || (uVar9 == 0xebc0bc0)))) || (uVar9 == 0xebd0bc0)) {
      uVar2 = param_4._2_2_;
      uVar1 = (undefined1)param_4;
      param_4 = param_4 ^ 0x100;
      uVar6 = FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
      if ((param_4 & 0x100) == 0) {
        uVar6 = (uVar6 & 0x1e) << 0xb | (uVar6 & 1) << 0x16;
      }
      else {
        uVar6 = (uVar6 & 0xf) << 0xc;
      }
      param_4 = CONCAT22(uVar2,CONCAT11(param_4._1_1_,uVar1)) ^ 0x100;
      uVar9 = param_4 & 0xfffffff;
    }
    else {
      uVar6 = FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
      if ((param_4 & 0x100) == 0) {
        uVar6 = (uVar6 & 0x1e) << 0xb | (uVar6 & 1) << 0x16;
      }
      else {
        uVar6 = (uVar6 & 0xf) << 0xc;
      }
    }
    *param_2 = *param_2 + 1;
    if ((uVar9 == 0xeb80b40) || (uVar9 == 0xeb80bc0)) {
      uVar2 = param_4._2_2_;
      uVar1 = (undefined1)param_4;
      param_4 = param_4 ^ 0x100;
      uVar9 = FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
      if ((param_4 & 0x100) == 0) {
        uVar9 = (uVar9 & 0x1e) >> 1 | (uVar9 & 1) << 5;
      }
      else {
        uVar9 = uVar9 & 0xf;
      }
      param_4 = CONCAT22(uVar2,CONCAT11(param_4._1_1_,uVar1)) ^ 0x100;
    }
    else {
      uVar9 = FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
      if ((param_4 & 0x100) == 0) {
        uVar9 = (uVar9 & 0x1e) >> 1 | (uVar9 & 1) << 5;
      }
      else {
        uVar9 = uVar9 & 0xf;
      }
    }
    goto LAB_0806c341;
  case 0x12:
    FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    puVar8 = (uint *)&stack0xffffffd4;
    break;
  case 0x13:
    uVar6 = FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    if ((param_4 & 0x100) == 0) {
      uVar6 = (uVar6 & 0x1e) << 0xf | (uVar6 & 1) << 7;
    }
    else {
      uVar6 = (uVar6 & 0xf) << 0x10;
    }
    *param_2 = *param_2 + 1;
    puVar7 = &stack0xffffffd0;
    local_14 = FUN_080679f0((int)param_1,param_2);
    param_4 = param_4 | uVar6 | local_14 << 0xc;
    goto LAB_0806c347;
  case 0x14:
    FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    *param_2 = *param_2 + 1;
    local_14 = FUN_080679f0((int)param_1,param_2);
    puVar8 = (uint *)&stack0xffffffc0;
    break;
  case 0x15:
    FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    uVar6 = FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    if ((param_4 & 0x100) == 0) {
      local_14 = (uVar6 & 1) << 7 | (uVar6 & 0x1e) << 0xf;
    }
    else {
      local_14 = (uVar6 & 0xf) << 0x10;
    }
    puVar8 = (uint *)&stack0xffffffd4;
    break;
  case 0x16:
    iVar3 = FUN_080679f0((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    puVar7 = &stack0xffffffc4;
    local_14 = FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    param_4 = param_4 | iVar3 << 0xc | local_14 << 0x10;
    goto LAB_0806c347;
  case 0x17:
    FUN_0806d080((int)param_1,param_2,param_4 & 0x100);
    *param_2 = *param_2 + 1;
    iVar3 = FUN_0805fa50((int)param_1,param_2);
    if ((char)iVar3 == '[') {
      *param_2 = *param_2 + 1;
      local_14 = FUN_080679f0((int)param_1,param_2);
      if (param_1[*param_2] != ']') {
        *param_2 = *param_2 + 1;
        FUN_0805fa50((int)param_1,param_2);
        *param_2 = *param_2 + 1;
        uVar6 = FUN_080535b0(param_1,param_2,0,&local_8);
        if (DAT_08080160 != 0) {
          return 0;
        }
        uVar9 = uVar6;
        if ((int)uVar6 < 0) {
          uVar9 = -uVar6;
        }
        if ((0x3ff < (int)uVar9) || ((uVar6 & 3) != 0)) goto LAB_0806c202;
      }
      *param_2 = *param_2 + 1;
    }
    else {
      if (param_1[*param_2] == '=') {
        *param_2 = *param_2 + 1;
        uVar6 = (uint)((param_4 & 0x100) != 0);
        FUN_080547e0((int)param_1,param_2,uVar6,&local_10,&local_c);
        if (uVar6 == 0) {
          uVar6 = FUN_08056c6c(local_10,-0x3fc,0x3fc);
        }
        else {
          uVar6 = FUN_08056c8c(local_10,local_c,-0x3fc,0x3fc);
        }
        local_14 = 0xf;
      }
      else {
        uVar6 = FUN_08053a28(param_1,param_2,&local_14,0,&local_8);
        if (DAT_08080160 != 0) {
          return 0;
        }
      }
      if (local_14 == 0xf) {
        uVar6 = (uVar6 - 8) - DAT_080826a0;
      }
      uVar9 = uVar6;
      if ((int)uVar6 < 0) {
        uVar9 = -uVar6;
      }
      if ((0x3ff < (int)uVar9) || ((uVar6 & 3) != 0)) {
LAB_0806c202:
        FUN_08052f1c(4,"Data transfer offset out of range");
        return 0;
      }
    }
    puVar8 = (uint *)&stack0xffffffd4;
    break;
  case 0x18:
    iVar3 = FUN_080679f0((int)param_1,param_2);
    if (param_1[*param_2] == '!') {
      param_4 = param_4 | 0x200000;
      *param_2 = *param_2 + 1;
    }
    FUN_0805fa50((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    FUN_0805fa50((int)param_1,param_2);
    *param_2 = *param_2 + 1;
    uVar6 = param_4 & 0x100;
    local_14 = FUN_0806d080((int)param_1,param_2,uVar6);
    while (iVar4 = FUN_0805fa50((int)param_1,param_2), (char)iVar4 != '}') {
      *param_2 = *param_2 + 1;
      unaff_ESI = FUN_0806d080((int)param_1,param_2,uVar6);
    }
    iVar4 = *param_2;
    *param_2 = iVar4 + 1;
    uVar9 = (unaff_ESI - local_14) + 1;
    if (uVar6 == 0) {
      local_14 = (local_14 & 1) << 0x16 | (local_14 & 0x1e) << 0xb;
    }
    else {
      uVar9 = uVar9 * 2;
      if (param_1[iVar4 + 1] == '^') {
        *param_2 = iVar4 + 2;
        uVar9 = uVar9 + 1;
      }
      local_14 = (local_14 & 0xf) << 0xc;
    }
    param_4 = param_4 | local_14;
    uVar6 = iVar3 << 0x10;
LAB_0806c341:
    param_4 = param_4 | uVar6;
LAB_0806c344:
    puVar7 = &stack0xffffffd8;
    param_4 = param_4 | uVar9;
LAB_0806c347:
    puVar8 = (uint *)(puVar7 + -4);
    *(uint *)(puVar7 + -4) = param_4;
    break;
  default:
    goto switchD_0806bc98_default;
  }
  puVar8[-1] = 0x806c350;
  FUN_08051c18(*puVar8);
switchD_0806bc98_default:
  return 1;
}



undefined4 FUN_0806c360(int param_1,char *param_2)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  undefined4 uVar4;
  
  uVar4 = 0xffffffff;
  if ((*param_2 == 'F') && (1 < param_1)) {
    pcVar2 = param_2 + 2;
    switch(param_2[1]) {
    case 'A':
      if (2 < param_1) {
        if (*pcVar2 == 'B') {
          if (((3 < param_1) && (param_2[3] == 'S')) && (4 < param_1)) {
            if (param_2[4] == 'D') {
              uVar4 = 0;
            }
            else if (param_2[4] == 'S') {
              uVar4 = 1;
            }
          }
        }
        else if (((*pcVar2 == 'D') && (3 < param_1)) && ((param_2[3] == 'D' && (4 < param_1)))) {
          if (param_2[4] == 'D') {
            uVar4 = 2;
          }
          else if (param_2[4] == 'S') {
            uVar4 = 3;
          }
        }
      }
      break;
    case 'C':
      if (2 < param_1) {
        cVar1 = *pcVar2;
        pcVar2 = param_2 + 3;
        if (cVar1 == 'P') {
          if (((3 < param_1) && (*pcVar2 == 'Y')) && (4 < param_1)) {
            if (param_2[4] == 'D') {
              uVar4 = 0xc;
            }
            else if (param_2[4] == 'S') {
              uVar4 = 0xd;
            }
          }
        }
        else if (cVar1 < 'Q') {
          if (((cVar1 == 'M') && (3 < param_1)) && ((*pcVar2 == 'P' && (4 < param_1)))) {
            cVar1 = param_2[4];
            if (cVar1 == 'E') {
              if (5 < param_1) {
                cVar1 = param_2[5];
                if (cVar1 == 'S') {
                  uVar4 = 6;
                }
                else if (cVar1 < 'T') {
                  if (cVar1 == 'D') {
                    uVar4 = 5;
                  }
                }
                else if ((cVar1 == 'Z') && (6 < param_1)) {
                  if (param_2[6] == 'D') {
                    uVar4 = 7;
                  }
                  else if (param_2[6] == 'S') {
                    uVar4 = 8;
                  }
                }
              }
            }
            else if (cVar1 < 'F') {
              if (cVar1 == 'D') {
                uVar4 = 4;
              }
            }
            else if (cVar1 == 'S') {
              uVar4 = 9;
            }
            else if ((cVar1 == 'Z') && (5 < param_1)) {
              cVar1 = param_2[5];
              if (cVar1 == 'D') {
                uVar4 = 10;
              }
              else if (cVar1 == 'S') {
                uVar4 = 0xb;
              }
            }
          }
        }
        else if (((cVar1 == 'V') && (3 < param_1)) && ((*pcVar2 == 'T' && (4 < param_1)))) {
          if (param_2[4] == 'D') {
            if ((5 < param_1) && (param_2[5] == 'S')) {
              uVar4 = 0xe;
            }
          }
          else if (((param_2[4] == 'S') && (5 < param_1)) && (param_2[5] == 'D')) {
            uVar4 = 0xf;
          }
        }
      }
      break;
    case 'D':
      if (((2 < param_1) && (*pcVar2 == 'I')) &&
         ((3 < param_1 && ((param_2[3] == 'V' && (4 < param_1)))))) {
        if (param_2[4] == 'D') {
          uVar4 = 0x10;
        }
        else if (param_2[4] == 'S') {
          uVar4 = 0x11;
        }
      }
      break;
    case 'L':
      if (((2 < param_1) && (*pcVar2 == 'D')) && (3 < param_1)) {
        cVar1 = param_2[3];
        if (cVar1 == 'M') {
          if (4 < param_1) {
            cVar1 = param_2[4];
            if (cVar1 == 'I') {
              if (((5 < param_1) && (param_2[5] == 'A')) && (6 < param_1)) {
                if (param_2[6] == 'D') {
                  uVar4 = 0x16;
                }
                else if (param_2[6] == 'S') {
                  uVar4 = 0x17;
                }
              }
            }
            else if (cVar1 < 'J') {
              if (((cVar1 == 'D') && (uVar4 = 0x13, 5 < param_1)) &&
                 ((param_2[5] == 'B' && (6 < param_1)))) {
                if (param_2[6] == 'D') {
                  uVar4 = 0x14;
                }
                else if (param_2[6] == 'S') {
                  uVar4 = 0x15;
                }
              }
            }
            else if (cVar1 == 'S') {
              uVar4 = 0x18;
            }
          }
        }
        else if (cVar1 < 'N') {
          if (cVar1 == 'D') {
            uVar4 = 0x12;
          }
        }
        else if (cVar1 == 'S') {
          uVar4 = 0x19;
        }
      }
      break;
    case 'M':
      if (2 < param_1) {
        pcVar3 = param_2 + 3;
        switch(*pcVar2) {
        case 'A':
          if (((3 < param_1) && (*pcVar3 == 'C')) && (4 < param_1)) {
            if (param_2[4] == 'D') {
              uVar4 = 0x1a;
            }
            else if (param_2[4] == 'S') {
              uVar4 = 0x1b;
            }
          }
          break;
        case 'D':
          if (3 < param_1) {
            if (*pcVar3 == 'H') {
              if ((4 < param_1) && (param_2[4] == 'R')) {
                uVar4 = 0x20;
              }
            }
            else if (((*pcVar3 == 'L') && (4 < param_1)) && (param_2[4] == 'R')) {
              uVar4 = 0x21;
            }
          }
          break;
        case 'O':
          if (((3 < param_1) && (*pcVar3 == 'V')) && (4 < param_1)) {
            if (param_2[4] == 'D') {
              uVar4 = 0x1c;
            }
            else if (param_2[4] == 'S') {
              uVar4 = 0x1d;
            }
          }
          break;
        case 'R':
          if (3 < param_1) {
            cVar1 = *pcVar3;
            if (cVar1 == 'S') {
              uVar4 = 0x22;
            }
            else if (cVar1 < 'T') {
              if ((cVar1 == 'D') && (4 < param_1)) {
                if (param_2[4] == 'H') {
                  uVar4 = 0x1e;
                }
                else if (param_2[4] == 'L') {
                  uVar4 = 0x1f;
                }
              }
            }
            else if (cVar1 == 'X') {
              uVar4 = 0x23;
            }
          }
          break;
        case 'S':
          if (3 < param_1) {
            if (*pcVar3 == 'C') {
              if (4 < param_1) {
                if (param_2[4] == 'D') {
                  uVar4 = 0x24;
                }
                else if (param_2[4] == 'S') {
                  uVar4 = 0x25;
                }
              }
            }
            else if (*pcVar3 == 'R') {
              uVar4 = 0x26;
            }
          }
          break;
        case 'U':
          if (((3 < param_1) && (*pcVar3 == 'L')) && (4 < param_1)) {
            if (param_2[4] == 'D') {
              uVar4 = 0x27;
            }
            else if (param_2[4] == 'S') {
              uVar4 = 0x28;
            }
          }
          break;
        case 'X':
          if ((3 < param_1) && (*pcVar3 == 'R')) {
            uVar4 = 0x29;
          }
        }
      }
      break;
    case 'N':
      if (2 < param_1) {
        if (*pcVar2 == 'E') {
          if (((3 < param_1) && (param_2[3] == 'G')) && (4 < param_1)) {
            if (param_2[4] == 'D') {
              uVar4 = 0x2a;
            }
            else if (param_2[4] == 'S') {
              uVar4 = 0x2b;
            }
          }
        }
        else if ((*pcVar2 == 'M') && (3 < param_1)) {
          cVar1 = param_2[3];
          pcVar2 = param_2 + 4;
          if (cVar1 == 'S') {
            if (((4 < param_1) && (*pcVar2 == 'C')) && (5 < param_1)) {
              if (param_2[5] == 'D') {
                uVar4 = 0x2e;
              }
              else if (param_2[5] == 'S') {
                uVar4 = 0x2f;
              }
            }
          }
          else if (cVar1 < 'T') {
            if (((cVar1 == 'A') && (4 < param_1)) && ((*pcVar2 == 'C' && (5 < param_1)))) {
              if (param_2[5] == 'D') {
                uVar4 = 0x2c;
              }
              else if (param_2[5] == 'S') {
                uVar4 = 0x2d;
              }
            }
          }
          else if (((cVar1 == 'U') && (4 < param_1)) && ((*pcVar2 == 'L' && (5 < param_1)))) {
            if (param_2[5] == 'D') {
              uVar4 = 0x30;
            }
            else if (param_2[5] == 'S') {
              uVar4 = 0x31;
            }
          }
        }
      }
      break;
    case 'S':
      if (2 < param_1) {
        cVar1 = *pcVar2;
        pcVar2 = param_2 + 3;
        if (cVar1 == 'Q') {
          if ((((3 < param_1) && (*pcVar2 == 'R')) && (4 < param_1)) &&
             ((param_2[4] == 'T' && (5 < param_1)))) {
            if (param_2[5] == 'D') {
              uVar4 = 0x34;
            }
            else if (param_2[5] == 'S') {
              uVar4 = 0x35;
            }
          }
        }
        else if (cVar1 < 'R') {
          if (((cVar1 == 'I') && (3 < param_1)) &&
             ((*pcVar2 == 'T' && (((4 < param_1 && (param_2[4] == 'O')) && (5 < param_1)))))) {
            if (param_2[5] == 'D') {
              uVar4 = 0x32;
            }
            else if (param_2[5] == 'S') {
              uVar4 = 0x33;
            }
          }
        }
        else if (cVar1 == 'T') {
          if (3 < param_1) {
            cVar1 = *pcVar2;
            if (cVar1 == 'M') {
              if (4 < param_1) {
                cVar1 = param_2[4];
                if (cVar1 == 'I') {
                  if (((5 < param_1) && (param_2[5] == 'A')) && (6 < param_1)) {
                    if (param_2[6] == 'D') {
                      uVar4 = 0x3a;
                    }
                    else if (param_2[6] == 'S') {
                      uVar4 = 0x3b;
                    }
                  }
                }
                else if (cVar1 < 'J') {
                  if ((((cVar1 == 'D') && (uVar4 = 0x37, 5 < param_1)) && (param_2[5] == 'B')) &&
                     (6 < param_1)) {
                    if (param_2[6] == 'D') {
                      uVar4 = 0x38;
                    }
                    else if (param_2[6] == 'S') {
                      uVar4 = 0x39;
                    }
                  }
                }
                else if (cVar1 == 'S') {
                  uVar4 = 0x3c;
                }
              }
            }
            else if (cVar1 < 'N') {
              if (cVar1 == 'D') {
                uVar4 = 0x36;
              }
            }
            else if (cVar1 == 'S') {
              uVar4 = 0x3d;
            }
          }
        }
        else if (((cVar1 == 'U') && (3 < param_1)) && ((*pcVar2 == 'B' && (4 < param_1)))) {
          if (param_2[4] == 'D') {
            uVar4 = 0x3e;
          }
          else if (param_2[4] == 'S') {
            uVar4 = 0x3f;
          }
        }
      }
      break;
    case 'T':
      if (((2 < param_1) && (*pcVar2 == 'O')) && (3 < param_1)) {
        if (param_2[3] == 'S') {
          if (((4 < param_1) && (param_2[4] == 'I')) && (5 < param_1)) {
            cVar1 = param_2[5];
            if (cVar1 == 'S') {
              uVar4 = 0x41;
            }
            else if (cVar1 < 'T') {
              if (cVar1 == 'D') {
                uVar4 = 0x40;
              }
            }
            else if ((cVar1 == 'Z') && (6 < param_1)) {
              if (param_2[6] == 'D') {
                uVar4 = 0x42;
              }
              else if (param_2[6] == 'S') {
                uVar4 = 0x43;
              }
            }
          }
        }
        else if (((param_2[3] == 'U') && (4 < param_1)) && ((param_2[4] == 'I' && (5 < param_1)))) {
          cVar1 = param_2[5];
          if (cVar1 == 'S') {
            uVar4 = 0x45;
          }
          else if (cVar1 < 'T') {
            if (cVar1 == 'D') {
              uVar4 = 0x44;
            }
          }
          else if ((cVar1 == 'Z') && (6 < param_1)) {
            if (param_2[6] == 'D') {
              uVar4 = 0x46;
            }
            else if (param_2[6] == 'S') {
              uVar4 = 0x47;
            }
          }
        }
      }
      break;
    case 'U':
      if ((((2 < param_1) && (*pcVar2 == 'I')) && (3 < param_1)) &&
         (((param_2[3] == 'T' && (4 < param_1)) && ((param_2[4] == 'O' && (5 < param_1)))))) {
        if (param_2[5] == 'D') {
          uVar4 = 0x48;
        }
        else if (param_2[5] == 'S') {
          uVar4 = 0x49;
        }
      }
    }
  }
  return uVar4;
}



undefined4 FUN_0806cfd4(int param_1,char *param_2,undefined4 *param_3,int *param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int local_8;
  
  if ((DAT_08082608 == 0x10) && (iVar2 = FUN_0806c360(param_1,param_2), iVar2 != -1)) {
    iVar2 = iVar2 * 0xc;
    local_8 = *(int *)(&DAT_0807ad08 + iVar2);
    uVar1 = *(undefined4 *)(&DAT_0807ad10 + iVar2);
    iVar2 = *(int *)(&DAT_0807ad0c + iVar2);
    if (param_1 == local_8 + 2) {
      iVar3 = FUN_08066e98(&local_8,(int)param_2);
    }
    else {
      iVar3 = -0x20000000;
    }
    if (param_1 == local_8) {
      *param_3 = uVar1;
      *param_4 = iVar3 + iVar2;
      if (DAT_0808277c != 0) {
        DAT_0808264c = 1;
        return 1;
      }
    }
  }
  return 0;
}



undefined4 FUN_0806d080(int param_1,int *param_2,int param_3)

{
  int iVar1;
  char *pcVar2;
  uint local_c;
  char *local_8;
  
  FUN_0805fa50(param_1,param_2);
  iVar1 = FUN_080613f8(param_1,param_2,(int *)&local_c);
  if (iVar1 == 0) {
    pcVar2 = "Bad symbol";
LAB_0806d0e3:
    FUN_08052f1c(4,pcVar2);
    return 0;
  }
  FUN_0805fa50(param_1,param_2);
  iVar1 = FUN_0805f618(local_c,local_8,0);
  if ((iVar1 == 0) || ((*(uint *)(iVar1 + 8) & 0x1c00003) != 0x400003)) {
    pcVar2 = "Bad register name symbol";
    goto LAB_0806d0e3;
  }
  if (param_3 == 0) {
    if (*(uint *)(iVar1 + 0xc) < 0x20) goto LAB_0806d114;
  }
  else if (*(uint *)(iVar1 + 0xc) < 0x10) goto LAB_0806d114;
  FUN_08052f1c(4,"Floating point register number out of range");
LAB_0806d114:
  FUN_08058c28(iVar1);
  return *(undefined4 *)(iVar1 + 0xc);
}



void FUN_0806d130(undefined4 param_1)

{
  DAT_0807b08c = param_1;
  return;
}



undefined4 FUN_0806d150(void)

{
  return DAT_0807b08c;
}



uint FUN_0806d16c(uint param_1)

{
  if (DAT_0807b08c != 0) {
    param_1 = (param_1 << 0x18 | param_1 >> 8) ^
              (((param_1 << 0x10 | param_1 >> 0x10) ^ param_1) & 0xff00ffff) >> 8;
  }
  return param_1;
}



uint FUN_0806d1a4(uint param_1)

{
  if (DAT_0807b08c != 0) {
    param_1 = (param_1 & 0xff) << 8 | (int)param_1 >> 8 & 0xffU;
  }
  return param_1;
}



void FUN_0806d1d8(uint *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = param_3 >> 2;
  if (uVar2 != 0) {
    do {
      uVar1 = *param_2;
      param_2 = param_2 + 1;
      uVar1 = FUN_0806d16c(uVar1);
      *param_1 = uVar1;
      param_1 = param_1 + 1;
      uVar2 = uVar2 - 1;
    } while (0 < (int)uVar2);
  }
  return;
}



void FUN_0806d220(char *param_1,int *param_2,int param_3)

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
    if (pcVar1 == param_1) goto LAB_0806d3b3;
    pcVar3 = pcVar1 + -1;
  } while (*pcVar3 != '.');
  param_2[3] = (int)pcVar1;
  cVar4 = (char)pcVar3 - (char)param_1;
  *(char *)((int)param_2 + 0x13) = (*(char *)((int)param_2 + 0x12) - cVar4) + -1;
  *(char *)((int)param_2 + 0x12) = cVar4;
LAB_0806d3b3:
  *(char *)((int)param_2 + 0x16) = (char)param_3;
  return;
}



undefined4 FUN_0806d3c0(int param_1,int param_2,char *param_3)

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
LAB_0806d3fc:
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
      if (param_2 <= iVar2) goto LAB_0806d3fc;
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



void FUN_0806d42c(char *param_1,char *param_2,char *param_3)

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
LAB_0806d494:
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
LAB_0806d4db:
    if ((*pcVar6 == '&') || (*pcVar6 == '$')) {
      pcVar6 = pcVar6 + 2;
    }
    param_2[0x14] = param_2[0x14] | 8;
  }
  else {
    if ((cVar2 == '&') || (cVar2 == '$')) {
      if (cVar2 == ':') goto LAB_0806d494;
      param_2[0x14] = bVar1 & 0x20;
      goto LAB_0806d4db;
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
LAB_0806d582:
    param_2[0xc] = '\0';
    param_2[0xd] = '\0';
    param_2[0xe] = '\0';
    param_2[0xf] = '\0';
    param_2[0x13] = '\0';
    *(char **)(param_2 + 8) = param_1;
    cVar2 = cVar2 - cVar4;
  }
  else {
    iVar3 = FUN_0806d3c0((int)pcVar7,(int)(param_1 + (-1 - (int)pcVar7)),param_3);
    if (iVar3 != 0) {
      *(char **)(param_2 + 0xc) = pcVar7;
      param_2[0x13] = (cVar4 - (char)pcVar7) + -1;
      *(char **)(param_2 + 8) = param_1;
      param_2[0x12] = cVar2 - cVar4;
      param_1 = pcVar7;
      goto LAB_0806d59f;
    }
    iVar3 = FUN_0806d3c0((int)param_1,(int)pcVar6 - (int)param_1,param_3);
    if (iVar3 == 0) goto LAB_0806d582;
    *(char **)(param_2 + 0xc) = param_1;
    param_2[0x13] = cVar2 - cVar4;
    *(char **)(param_2 + 8) = pcVar7;
    cVar2 = (cVar4 - (char)pcVar7) + -1;
    param_1 = pcVar7;
  }
  param_2[0x12] = cVar2;
LAB_0806d59f:
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



void FUN_0806d5d4(char *param_1,int *param_2)

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



void FUN_0806d6ac(char *param_1,char *param_2,int *param_3)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  byte bVar4;
  
  bVar2 = *(byte *)((int)param_3 + 0x15) & 7;
  if ((*param_1 == '\\') ||
     (((iVar3 = isalpha((int)*param_1), iVar3 != 0 && (param_1[1] == ':')) && (param_1[2] == '\\')))
     ) {
    FUN_0806d220(param_1,param_3,0x5c);
    *(byte *)((int)param_3 + 0x15) = *(byte *)(param_3 + 5) & 8 | 2;
    return;
  }
  FUN_0806d220(param_1,param_3,0x2f);
  if (((bVar2 == 3) || (bVar4 = *(byte *)(param_3 + 5), (bVar4 & 0x40) != 0)) ||
     (((*param_3 == 0 && ((bVar4 & 0x10) != 0)) &&
      ((bVar2 != 1 ||
       (((cVar1 = *param_1, cVar1 != ':' && (cVar1 != '$')) &&
        ((cVar1 != '&' && ((cVar1 != '^' && (cVar1 != '@')))))))))))) {
    *(byte *)((int)param_3 + 0x15) = *(byte *)(param_3 + 5) & 8 | 3;
    return;
  }
  if (bVar2 == 1) {
    FUN_0806d42c(param_1,(char *)param_3,param_2);
  }
  else if (bVar2 == 4) {
    FUN_0806d5d4(param_1,param_3);
  }
  else {
    if (bVar2 != 2) goto LAB_0806d793;
    FUN_0806d220(param_1,param_3,0x5c);
  }
  bVar4 = *(byte *)(param_3 + 5);
LAB_0806d793:
  *(byte *)((int)param_3 + 0x15) = bVar4 & 8 | bVar2;
  return;
}



void FUN_0806d7a4(char *param_1,char *param_2,int *param_3)

{
  *(undefined1 *)((int)param_3 + 0x15) = 3;
  FUN_0806d6ac(param_1,param_2,param_3);
  return;
}



byte * FUN_0806d7cc(byte *param_1,byte *param_2,int param_3,byte *param_4,uint param_5)

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



int FUN_0806d81c(undefined4 *param_1,uint param_2,byte *param_3,int param_4)

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
    if (param_2 == 1) goto LAB_0806d890;
    local_14 = 0x2e2f;
  }
  else if (param_2 == 1) {
    local_14 = 0x2f2e;
  }
  else {
LAB_0806d890:
    local_14 = 0;
  }
  if ((byte *)*param_1 == (byte *)0x0) {
    pbVar5 = param_3;
    if ((*(byte *)((int)param_1 + 0x15) & 8) == 0) {
      if ((param_2 != 4) || (param_3 == pbVar2)) goto LAB_0806d9b8;
      *param_3 = 0x3a;
    }
    else {
      if ((param_2 == 1) && (param_3 != pbVar2)) {
        *param_3 = 0x24;
        pbVar5 = param_3 + 1;
      }
      if ((param_2 == 4) || (pbVar5 == pbVar2)) goto LAB_0806d9b8;
      *pbVar5 = (&DAT_080784ec)[param_2];
    }
  }
  else {
    pbVar5 = FUN_0806d7cc(param_3,(byte *)*param_1,(uint)*(byte *)(param_1 + 4),pbVar2,0);
    if ((((param_2 != 3) && (param_2 != uVar9)) && (pbVar5[-1] != 0x3a)) && (pbVar5 != pbVar2)) {
      *pbVar5 = 0x3a;
      pbVar5 = pbVar5 + 1;
    }
    bVar4 = *(byte *)(param_1 + 5);
    if ((bVar4 & 0x40) == 0) {
      if (((bVar4 & 8) == 0) && (param_2 != 3)) goto LAB_0806d9b8;
      if (((param_2 == 1) && ((uVar9 != 1 || ((bVar4 & 0x20) != 0)))) && (pbVar5 != pbVar2)) {
        *pbVar5 = 0x24;
        pbVar5 = pbVar5 + 1;
      }
      if ((param_2 == 4) || (pbVar5 == pbVar2)) goto LAB_0806d9b8;
      *pbVar5 = (&DAT_080784ec)[param_2];
    }
    else if (param_2 == 1) {
      if (pbVar5 == pbVar2) goto LAB_0806d9b8;
      *pbVar5 = 0x3a;
    }
    else {
      if ((param_2 == 4) || (pbVar5 == pbVar2)) goto LAB_0806d9b8;
      *pbVar5 = (&DAT_080784ec)[param_2];
    }
  }
  pbVar5 = pbVar5 + 1;
LAB_0806d9b8:
  pbVar10 = (byte *)param_1[1];
  if (pbVar10 != (byte *)0x0) {
    pbVar6 = pbVar10 + *(byte *)((int)param_1 + 0x11);
    bVar4 = (&DAT_080784ec)[uVar9];
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
LAB_0806da9e:
            pbVar5 = pbVar7;
            if (((param_2 != 4) && (pbVar6 <= pbVar10)) &&
               ((uint)*(byte *)((int)param_1 + 0x12) + (uint)*(byte *)((int)param_1 + 0x13) == 0))
            goto LAB_0806dacc;
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
            goto LAB_0806da9e;
          }
          if (pbVar5 != pbVar2) {
            *pbVar5 = (&DAT_080784ec)[param_2];
            pbVar5 = pbVar5 + 1;
          }
        }
        else if ((iVar8 != 1) || (*local_20 != (&DAT_080784f2)[uVar9])) {
          pbVar7 = FUN_0806d7cc(pbVar5,local_20,iVar8,pbVar2,local_14);
          goto LAB_0806da9e;
        }
LAB_0806dacc:
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
      ((pbVar5 = FUN_0806d7cc(pbVar5,(byte *)param_1[3],(uint)*(byte *)((int)param_1 + 0x13),pbVar2,
                              0), *(char *)((int)param_1 + 0x12) != '\0' && (pbVar5 != pbVar2))))))
  {
    *pbVar5 = 0x2e;
    pbVar5 = pbVar5 + 1;
  }
  pbVar5 = FUN_0806d7cc(pbVar5,(byte *)param_1[2],(uint)*(byte *)((int)param_1 + 0x12),pbVar2,
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
    pbVar5 = FUN_0806d7cc(pbVar10,(byte *)param_1[3],(uint)*(byte *)((int)param_1 + 0x13),pbVar2,0);
  }
  if (uVar1 != 0) {
    if (param_2 == 4) {
      if ((param_3 < pbVar5) && (pbVar5[-1] == 0x3a)) {
        pbVar5 = pbVar5 + -1;
      }
    }
    else if ((pbVar5 != param_3) && (pbVar5 != pbVar2)) {
      *pbVar5 = (&DAT_080784ec)[param_2];
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



void FUN_0806dbf8(char param_1,char *param_2,char *param_3)

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



void FUN_0806dc94(int param_1,byte *param_2,int *param_3)

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



byte FUN_0806dd1c(int param_1)

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



char * FUN_0806dd40(char *param_1,char *param_2,int param_3)

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
      if (!bVar7) goto LAB_0806ddce;
    }
    local_10 = ~uVar2 - 5;
    local_8 = pcVar4;
  }
LAB_0806ddce:
  iVar3 = local_10 + -2;
  do {
    if (iVar3 < 0) {
LAB_0806de03:
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
      goto LAB_0806de03;
    }
    iVar3 = iVar3 + -1;
  } while( true );
}



undefined4 FUN_0806de50(uint *param_1,uint param_2)

{
  *param_1 = param_2 | 0x7ff00000;
  param_1[1] = 0;
  return 2;
}



void FUN_0806de70(uint *param_1,uint *param_2,uint param_3)

{
  *param_1 = *param_2 & 0x7fffffff | param_3;
  param_1[1] = param_2[1];
  return;
}



undefined4 FUN_0806de90(uint *param_1,int param_2,uint param_3)

{
  *param_1 = param_2 >> 3 | 0x7ff80000U | param_3;
  param_1[1] = param_2 << 0x1d;
  return 7;
}



undefined4 FUN_0806deb8(char *param_1,uint *param_2,undefined4 *param_3)

{
  char *pcVar1;
  char cVar2;
  bool bVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int local_30;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  uint local_c;
  uint local_8;
  
  pcVar1 = param_1;
  do {
    param_1 = pcVar1;
    local_24 = (int)*param_1;
    pcVar1 = param_1 + 1;
    iVar4 = isspace(local_24);
  } while (iVar4 != 0);
  local_8 = 0;
  if (local_24 == 0x2b) {
LAB_0806df05:
    local_24 = (int)*pcVar1;
    pcVar1 = param_1 + 2;
  }
  else if (local_24 == 0x2d) {
    local_8 = 0x80000000;
    goto LAB_0806df05;
  }
  param_1 = pcVar1;
  if ((local_24 != 0x2e) && (iVar4 = isdigit(local_24), iVar4 == 0)) {
    if (param_3 != (undefined4 *)0x0) {
      *param_3 = param_1 + -1;
    }
    return 8;
  }
  local_10 = 0;
  uVar8 = 0;
  local_c = 0;
  local_14 = 0x100000;
  bVar3 = false;
  local_20 = 0;
  local_1c = 0;
  local_18 = 0;
  while (local_24 == 0x30) {
    cVar2 = *param_1;
    param_1 = param_1 + 1;
    local_24 = (int)cVar2;
  }
  uVar7 = 0;
  if (local_24 == 0x2e) {
    bVar3 = true;
    cVar2 = *param_1;
    while( true ) {
      local_24 = (int)cVar2;
      param_1 = param_1 + 1;
      if (local_24 != 0x30) break;
      local_20 = local_20 + -1;
      cVar2 = *param_1;
    }
  }
  while( true ) {
    if ((!bVar3) && (local_24 == 0x2e)) {
      local_24 = (int)*param_1;
      param_1 = param_1 + 1;
      bVar3 = true;
    }
    iVar4 = isdigit(local_24);
    if (iVar4 == 0) break;
    iVar4 = (local_14 % 10) * 0x1000000 + local_18;
    local_18 = iVar4 / 10;
    local_1c = ((iVar4 % 10) * 0x1000000 + local_1c) / 10;
    local_24 = local_24 + -0x30;
    uVar8 = uVar8 + local_24 * local_1c;
    uVar7 = uVar7 + (uVar8 >> 0x18) + local_24 * local_18;
    local_c = local_c + (uVar7 >> 0x18) + local_24 * (local_14 / 10);
    uVar8 = uVar8 & 0xffffff;
    uVar7 = uVar7 & 0xffffff;
    if (!bVar3) {
      local_20 = local_20 + 1;
    }
    local_24 = (int)*param_1;
    param_1 = param_1 + 1;
    local_14 = local_14 / 10;
  }
  if ((local_24 != 0x65) && (local_24 != 0x45)) goto LAB_0806e146;
  bVar3 = false;
  local_24 = (int)*param_1;
  if (local_24 == 0x2b) {
LAB_0806e0ee:
    local_24 = (int)param_1[1];
    pcVar1 = param_1 + 2;
  }
  else {
    pcVar1 = param_1 + 1;
    if (local_24 == 0x2d) {
      bVar3 = true;
      goto LAB_0806e0ee;
    }
  }
  param_1 = pcVar1;
  local_30 = 0;
  while (iVar4 = isdigit(local_24), iVar4 != 0) {
    local_30 = local_24 + -0x30 + local_30 * 10;
    local_24 = (int)*param_1;
    param_1 = param_1 + 1;
  }
  if (bVar3) {
    local_20 = local_20 - local_30;
  }
  else {
    local_20 = local_20 + local_30;
  }
LAB_0806e146:
  if (param_3 != (undefined4 *)0x0) {
    *param_3 = param_1 + -1;
  }
  if (local_c == 0) {
    *param_2 = 0;
    param_2[1] = 0;
    uVar5 = 0;
  }
  else {
    for (; 0 < local_20; local_20 = local_20 + -1) {
      uVar6 = (uVar8 * 10 >> 0x18) + uVar7 * 10;
      uVar8 = uVar8 * 10 & 0xffffff;
      uVar7 = uVar6 & 0xffffff;
      for (local_c = (uVar6 >> 0x18) + local_c * 10; (local_c & 0xffe00000) != 0;
          local_c = (int)local_c >> 1) {
        uVar8 = (int)uVar8 >> 1 | (uVar7 & 1) << 0x17;
        uVar7 = (int)uVar7 >> 1 | (local_c & 1) << 0x17;
        local_10 = local_10 + 1;
      }
    }
    for (; local_20 < 0; local_20 = local_20 + 1) {
      iVar4 = uVar7 + ((int)local_c % 10) * 0x1000000;
      uVar8 = (int)(uVar8 + (iVar4 % 10) * 0x1000000) / 10;
      uVar7 = iVar4 / 10 + (uVar8 >> 0x18);
      local_c = (int)local_c / 10 + (uVar7 >> 0x18);
      uVar7 = uVar7 & 0xffffff;
      uVar6 = local_c;
      while (uVar8 = uVar8 & 0xffffff, (uVar6 & 0xfff00000) == 0) {
        uVar6 = local_c << 1;
        local_c = uVar6 | (int)uVar7 >> 0x17;
        uVar7 = uVar7 * 2 & 0xffffff | (int)uVar8 >> 0x17;
        uVar8 = uVar8 * 2;
        local_10 = local_10 + -1;
      }
    }
    while( true ) {
      for (; (local_c & 0xfff00000) == 0; local_c = local_c << 1 | uVar6) {
        uVar6 = (int)uVar7 >> 0x17;
        uVar7 = uVar7 * 2 & 0xffffff | (int)uVar8 >> 0x17;
        uVar8 = uVar8 * 2 & 0xffffff;
        local_10 = local_10 + -1;
      }
      for (; (local_c & 0xffe00000) != 0; local_c = (int)local_c >> 1) {
        uVar8 = (int)uVar8 >> 1 | (uVar7 & 1) << 0x17;
        uVar7 = (int)uVar7 >> 1 | (local_c & 1) << 0x17;
        local_10 = local_10 + 1;
      }
      if ((uVar8 & 0xff00) < 0x8001) break;
      uVar7 = uVar7 + (uVar8 + 0x10000 >> 0x18);
      local_c = local_c + (uVar7 >> 0x18);
      uVar8 = uVar8 + 0x10000 & 0xff0000;
      uVar7 = uVar7 & 0xffffff;
    }
    if ((uVar8 & 0xff00) == 0x8000) {
      uVar8 = uVar8 & 0xfe0000;
    }
    local_10 = local_10 + 0x3ff;
    uVar5 = 0;
    local_c = local_c & 0xfffff;
    uVar8 = uVar7 << 8 | (int)uVar8 >> 0x10;
    if (local_10 < 1) {
      if (local_10 < -0x34) {
        local_10 = 0;
        uVar8 = 0;
        local_c = 0;
        uVar5 = 1;
      }
      else {
        local_c = local_c | 0x100000;
        do {
          if ((uVar8 & 1) != 0) {
            uVar5 = 0xffffffff;
          }
          uVar8 = uVar8 >> 1 | local_c << 0x1f;
          local_c = (int)local_c >> 1;
          local_10 = local_10 + 1;
        } while (local_10 < 1);
        local_10 = 0;
      }
    }
    else if (0x7ff < local_10) {
      uVar5 = FUN_0806de50(param_2,local_8);
      return uVar5;
    }
    *param_2 = local_8 | local_10 << 0x14 | local_c;
    param_2[1] = uVar8;
  }
  return uVar5;
}



undefined4 FUN_0806e418(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  
  uVar1 = *param_1;
  uVar2 = param_1[1];
  uVar7 = uVar1 & 0x80000000;
  uVar5 = uVar1 >> 0x14 & 0x7ff;
  if (uVar5 == 0) {
    *param_2 = uVar7;
    if (((uVar1 & 0xfffff) != 0) || (uVar2 != 0)) {
      return 4;
    }
  }
  else {
    uVar4 = (uVar1 & 0xfffff) << 3 | uVar2 >> 0x1d;
    uVar1 = uVar2 << 3;
    if (uVar5 != 0x7ff) {
      if (((0x80000000 < uVar1) || ((uVar1 == 0x80000000 && ((uVar2 >> 0x1d & 1) != 0)))) &&
         (uVar4 = uVar4 + 1, uVar4 == 0x800000)) {
        uVar4 = 0;
        uVar5 = uVar5 + 1;
      }
      iVar6 = uVar5 - 0x380;
      uVar3 = 0;
      if (iVar6 < 0xff) {
        if (iVar6 < 1) {
          if (iVar6 < -0x17) {
            uVar4 = 0;
            uVar3 = 4;
          }
          else {
            uVar4 = uVar4 | 0x800000;
            do {
              uVar4 = uVar4 >> 1;
              iVar6 = iVar6 + 1;
            } while (iVar6 < 1);
          }
          iVar6 = 0;
        }
      }
      else {
        iVar6 = 0xff;
        uVar4 = 0;
        uVar3 = 3;
      }
      *param_2 = uVar7 | iVar6 << 0x17 | uVar4;
      return uVar3;
    }
    if ((uVar4 == 0) && (uVar1 != 0)) {
      uVar4 = 1;
    }
    *param_2 = uVar7 | uVar4 | 0x7f800000;
  }
  return 0;
}



void FUN_0806e510(uint *param_1,uint *param_2)

{
  FUN_0806e418(param_1,param_2);
  return;
}



void FUN_0806e530(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = *param_1;
  uVar1 = uVar3 >> 0x17 & 0xff;
  uVar2 = uVar3 & 0x80000000;
  uVar3 = uVar3 & 0x7fffff;
  if (uVar1 == 0) {
    if (uVar3 == 0) {
      *param_2 = uVar2;
      param_2[1] = 0;
      return;
    }
    while (uVar3 = uVar3 * 2, (uVar3 & 0x800000) == 0) {
      uVar1 = uVar1 - 1;
    }
    uVar3 = uVar3 & 0x7fffff;
  }
  else if (uVar1 == 0xff) {
    uVar1 = uVar3 >> 3 | 0x7ff00000;
    goto LAB_0806e5a2;
  }
  uVar2 = uVar2 | (uVar1 + 0x380) * 0x100000;
  uVar1 = uVar3 >> 3;
LAB_0806e5a2:
  *param_2 = uVar2 | uVar1;
  param_2[1] = uVar3 << 0x1d;
  return;
}



undefined4 FUN_0806e5b4(uint *param_1,uint *param_2,uint *param_3)

{
  byte bVar1;
  undefined4 uVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint local_20;
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_8 = 0;
  local_c = (int)*param_2 >> 0x14 & 0x7ff;
  uVar5 = *param_2 & 0xfffff;
  local_14 = param_2[1];
  if (local_c == 0) {
    if ((uVar5 != 0) || (uVar6 = 0, local_14 != 0)) {
      uVar5 = uVar5 * 2;
      uVar6 = uVar5 | local_14 >> 0x1f;
      uVar4 = 0;
      while (local_14 = local_14 << 1, (uVar5 & 0x100000) == 0) {
        local_c = uVar4 - 1;
        uVar5 = uVar6 * 2;
        uVar6 = uVar5 | local_14 >> 0x1f;
        uVar4 = local_c;
      }
    }
  }
  else {
    uVar6 = uVar5 | 0x100000;
  }
  local_10 = (int)*param_3 >> 0x14 & 0x7ff;
  uVar5 = *param_3 & 0xfffff;
  local_18 = param_3[1];
  if (local_10 == 0) {
    if ((uVar5 != 0) || (local_20 = 0, local_18 != 0)) {
      uVar5 = uVar5 << 1;
      local_20 = uVar5 | local_18 >> 0x1f;
      uVar4 = 0;
      while (local_18 = local_18 << 1, (uVar5 & 0x100000) == 0) {
        local_10 = uVar4 - 1;
        uVar5 = local_20 << 1;
        local_20 = uVar5 | local_18 >> 0x1f;
        uVar4 = local_10;
      }
    }
  }
  else {
    local_20 = uVar5 | 0x100000;
  }
  if (local_c == 0x7ff) {
    if ((uVar6 != 0) || (local_14 != 0)) {
      FUN_0806de70(param_1,param_3,0x80000000);
    }
    if (((local_10 == 0x7ff) && (local_20 != 0)) || (local_18 != 0)) {
      FUN_0806de70(param_1,param_3,0x80000000);
    }
LAB_0806e72e:
    FUN_0806de50(param_1,0);
    return 0;
  }
  if (local_10 == 0x7ff) {
    if ((local_20 != 0) || (local_18 != 0)) {
      FUN_0806de70(param_1,param_3,0);
    }
    goto LAB_0806e72e;
  }
  local_1c = local_c - local_10;
  if ((uVar6 == 0) && (local_14 == 0)) {
    uVar5 = param_3[1];
    *param_1 = *param_3;
    param_1[1] = uVar5;
    return 0;
  }
  if ((local_20 == 0) && (local_18 == 0)) {
    uVar5 = param_2[1];
    *param_1 = *param_2;
    param_1[1] = uVar5;
    return 0;
  }
  if (local_1c < -0x36) {
    uVar5 = param_3[1];
    *param_1 = *param_3;
    param_1[1] = uVar5;
    return 0xffffffff;
  }
  if (0x36 < local_1c) {
    uVar5 = param_2[1];
    *param_1 = *param_2;
    param_1[1] = uVar5;
    return 0xffffffff;
  }
  uVar5 = uVar6;
  if (local_1c == 0x20) {
    local_8 = local_18;
    local_18 = local_20;
    local_20 = 0;
  }
  else if (local_1c == -0x20) {
    local_8 = local_14;
    local_c = local_10;
    uVar5 = 0;
    local_14 = uVar6;
  }
  else if (local_1c < 1) {
    if (local_1c < 0) {
      if (local_1c < -0x20) {
        local_8 = local_14;
        uVar5 = 0;
        local_1c = local_1c + 0x20;
        local_14 = uVar6;
      }
      bVar1 = -(char)local_1c;
      bVar3 = (char)local_1c + 0x20;
      uVar6 = local_14 << (bVar3 & 0x1f);
      if (local_8 != 0) {
        uVar6 = uVar6 | 1;
      }
      local_14 = local_14 >> (bVar1 & 0x1f) | uVar5 << (bVar3 & 0x1f);
      uVar5 = uVar5 >> (bVar1 & 0x1f);
      local_c = local_10;
      local_8 = uVar6;
    }
  }
  else {
    if (0x20 < local_1c) {
      local_8 = local_18;
      local_18 = local_20;
      local_20 = 0;
      local_1c = local_1c + -0x20;
    }
    bVar1 = (byte)local_1c;
    uVar6 = local_18 << (0x20 - bVar1 & 0x1f);
    if (local_8 != 0) {
      uVar6 = uVar6 | 1;
    }
    local_18 = local_18 >> (bVar1 & 0x1f) | local_20 << (0x20 - bVar1 & 0x1f);
    local_20 = local_20 >> (bVar1 & 0x1f);
    local_8 = uVar6;
  }
  uVar4 = (local_14 & 0xff) + (local_18 & 0xff);
  uVar6 = (local_14 >> 8) + (local_18 >> 8) + (uVar4 >> 8);
  uVar5 = uVar5 + (uVar6 >> 0x18) + local_20;
  uVar4 = uVar4 & 0xff;
  local_14 = uVar4 + uVar6 * 0x100;
  if ((uVar5 & 0x200000) != 0) {
    local_8 = local_8 & 1 | uVar4 * -0x80000000 | local_8 >> 1;
    local_14 = local_14 >> 1 | uVar5 * -0x80000000;
    uVar5 = uVar5 >> 1;
    local_c = local_c + 1;
    if (0x7fe < (int)local_c) goto LAB_0806e968;
  }
  if (((int)local_8 < 0) && (((local_14 & 1) != 0 || (local_8 != 0x80000000)))) {
    if (local_14 == 0xffffffff) {
      local_14 = 0;
      uVar5 = uVar5 + 1;
      if ((uVar5 & 0x200000) != 0) {
        uVar5 = 0;
        local_c = local_c + 1;
        if (0x7fe < (int)local_c) {
LAB_0806e968:
          uVar2 = FUN_0806de50(param_1,0);
          return uVar2;
        }
      }
    }
    else {
      local_14 = local_14 + 1;
    }
  }
  if (local_8 == 0) {
    local_20 = 0;
  }
  else {
    local_20 = 0xffffffff;
  }
  uVar5 = uVar5 & 0xffefffff;
  if ((int)local_c < 1) {
    if ((int)local_c < -0x34) {
      local_c = 0;
      local_14 = 0;
      uVar5 = 0;
      local_20 = 1;
    }
    else {
      uVar5 = uVar5 | 0x100000;
      do {
        if ((local_14 & 1) != 0) {
          local_20 = 0xffffffff;
        }
        local_14 = local_14 >> 1 | uVar5 << 0x1f;
        uVar5 = uVar5 >> 1;
        local_c = local_c + 1;
      } while ((int)local_c < 1);
      local_c = 0;
    }
  }
  *param_1 = uVar5 | local_c << 0x14;
  param_1[1] = local_14;
  return local_20;
}



undefined4 FUN_0806ea1c(uint *param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  byte bVar5;
  byte bVar6;
  int iVar7;
  uint uVar8;
  uint local_30;
  uint local_2c;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_8 = 0;
  local_c = 0;
  local_14 = (int)*param_2 >> 0x14 & 0x7ff;
  uVar2 = *param_2 & 0xfffff;
  uVar8 = param_2[1];
  if (local_14 == 0) {
    if ((uVar2 != 0) || (local_2c = 0, uVar8 != 0)) {
      local_2c = uVar2 << 1 | uVar8 >> 0x1f;
      uVar8 = uVar8 * 2;
      if ((uVar2 << 1 & 0x100000) == 0) {
        local_14 = 0;
        do {
          local_14 = local_14 - 1;
          uVar2 = local_2c << 1;
          local_2c = uVar2 | uVar8 >> 0x1f;
          uVar8 = uVar8 * 2;
        } while ((uVar2 & 0x100000) == 0);
      }
    }
  }
  else {
    local_2c = uVar2 | 0x100000;
  }
  uVar4 = local_2c;
  local_18 = (int)*param_3 >> 0x14 & 0x7ff;
  uVar2 = *param_3 & 0xfffff;
  local_1c = param_3[1];
  if (local_18 == 0) {
    if ((uVar2 != 0) || (local_30 = 0, local_1c != 0)) {
      uVar2 = uVar2 << 1;
      local_30 = uVar2 | local_1c >> 0x1f;
      uVar1 = 0;
      while (local_1c = local_1c << 1, (uVar2 & 0x100000) == 0) {
        local_18 = uVar1 - 1;
        uVar2 = local_30 << 1;
        local_30 = uVar2 | local_1c >> 0x1f;
        uVar1 = local_18;
      }
    }
  }
  else {
    local_30 = uVar2 | 0x100000;
  }
  if (local_14 == 0x7ff) {
    if ((local_2c != 0) || (uVar8 != 0)) {
      FUN_0806de70(param_1,param_3,0x80000000);
    }
    if (local_18 == 0x7ff) {
      if ((local_30 != 0) || (local_1c != 0)) {
        FUN_0806de70(param_1,param_3,0x80000000);
      }
      uVar3 = FUN_0806de90(param_1,4,0);
      return uVar3;
    }
    uVar8 = 0;
LAB_0806ebcb:
    FUN_0806de50(param_1,uVar8);
    return 0;
  }
  if (local_18 == 0x7ff) {
    if ((local_30 != 0) || (local_1c != 0)) {
      FUN_0806de70(param_1,param_3,0x80000000);
    }
    uVar8 = 0x80000000;
    goto LAB_0806ebcb;
  }
  iVar7 = local_14 - local_18;
  if ((local_30 == 0) && (local_1c == 0)) {
    uVar8 = param_2[1];
    *param_1 = *param_2;
    param_1[1] = uVar8;
    return 0;
  }
  if ((local_2c == 0) && (uVar8 == 0)) {
    uVar8 = param_3[1];
    *param_1 = *param_3;
    param_1[1] = uVar8;
    *(byte *)((int)param_1 + 3) = *(byte *)((int)param_1 + 3) ^ 0x80;
    return 0;
  }
  if (iVar7 < -0x36) {
    uVar8 = param_3[1];
    *param_1 = *param_3;
    param_1[1] = uVar8;
    *(byte *)((int)param_1 + 3) = *(byte *)((int)param_1 + 3) ^ 0x80;
    return 0xffffffff;
  }
  uVar2 = uVar8;
  if (iVar7 == 0x20) {
    local_c = local_1c;
    local_1c = local_30;
    local_30 = 0;
  }
  else if (iVar7 == -0x20) {
    local_2c = 0;
    local_14 = local_18;
    uVar2 = uVar4;
    local_8 = uVar8;
  }
  else if (iVar7 < 1) {
    if (iVar7 < 0) {
      if (iVar7 < -0x20) {
        local_2c = 0;
        iVar7 = iVar7 + 0x20;
        uVar2 = uVar4;
        local_8 = uVar8;
      }
      bVar5 = -(char)iVar7;
      bVar6 = (char)iVar7 + 0x20;
      uVar8 = uVar2 << (bVar6 & 0x1f);
      if (local_8 != 0) {
        uVar8 = uVar8 | 1;
      }
      uVar2 = uVar2 >> (bVar5 & 0x1f) | local_2c << (bVar6 & 0x1f);
      local_2c = local_2c >> (bVar5 & 0x1f);
      local_14 = local_18;
      local_8 = uVar8;
    }
  }
  else {
    if (0x20 < iVar7) {
      local_c = local_1c;
      local_1c = local_30;
      local_30 = 0;
      iVar7 = iVar7 + -0x20;
    }
    bVar5 = (byte)iVar7;
    uVar8 = local_1c << (0x20 - bVar5 & 0x1f);
    if (local_c != 0) {
      uVar8 = uVar8 | 1;
    }
    local_1c = local_1c >> (bVar5 & 0x1f) | local_30 << (0x20 - bVar5 & 0x1f);
    local_30 = local_30 >> (bVar5 & 0x1f);
    local_c = uVar8;
  }
  uVar8 = (local_8 & 0xff) - (local_c & 0xff);
  if ((int)uVar8 < 0) {
    uVar4 = uVar8 >> 8 ^ 0xff000000;
  }
  else {
    uVar4 = uVar8 >> 8;
  }
  uVar4 = uVar4 + ((local_8 >> 8) - (local_c >> 8));
  if ((int)uVar4 < 0) {
    local_c = uVar4 >> 0x18 ^ 0xffffff00;
  }
  else {
    local_c = uVar4 >> 0x18;
  }
  local_8 = uVar4 * 0x100 | uVar8 & 0xff;
  uVar8 = ((uVar2 & 0xff) - (local_1c & 0xff)) + local_c;
  if ((int)uVar8 < 0) {
    uVar4 = uVar8 >> 8 ^ 0xff000000;
  }
  else {
    uVar4 = uVar8 >> 8;
  }
  uVar4 = ((uVar2 >> 8) - (local_1c >> 8)) + uVar4;
  if ((int)uVar4 < 0) {
    local_c = uVar4 >> 0x18 ^ 0xffffff00;
  }
  else {
    local_c = uVar4 >> 0x18;
  }
  uVar8 = uVar4 * 0x100 | uVar8 & 0xff;
  local_2c = (local_2c - local_30) + local_c;
  if (-1 < (int)local_2c) {
    local_10 = 0;
    goto LAB_0806ee1f;
  }
  if (local_8 == 0) {
    if (uVar8 != 0) {
      uVar8 = -uVar8;
      goto LAB_0806ee0c;
    }
    local_2c = -local_2c;
  }
  else {
    local_8 = -local_8;
    uVar8 = ~uVar8;
LAB_0806ee0c:
    local_2c = ~local_2c;
  }
  local_10 = 0x80000000;
LAB_0806ee1f:
  if (((local_2c == 0) && (uVar8 == 0)) && (local_8 == 0)) {
    param_1[1] = 0;
    *param_1 = 0;
    return 0;
  }
  if ((local_2c & 0x300000) == 0) {
    while (local_2c == 0) {
      uVar2 = local_8 >> 0xb;
      local_8 = local_8 << 0x15;
      local_14 = local_14 - 0x15;
      local_2c = uVar8 >> 0xb;
      uVar8 = uVar8 << 0x15 | uVar2;
    }
    for (; uVar2 = local_2c, (local_2c & 0x1fe000) == 0; local_2c = local_2c << 8 | uVar2) {
      uVar2 = uVar8 >> 0x18;
      uVar8 = uVar8 << 8 | local_8 >> 0x18;
      local_8 = local_8 << 8;
      local_14 = local_14 - 8;
    }
    while (uVar4 = local_2c, (uVar2 & 0x1c0000) == 0) {
      uVar2 = local_2c << 3;
      local_2c = uVar2 | uVar8 >> 0x1d;
      uVar8 = uVar8 << 3 | local_8 >> 0x1d;
      local_8 = local_8 << 3;
      local_14 = local_14 - 3;
    }
    while ((uVar4 & 0x100000) == 0) {
      uVar4 = local_2c << 1;
      local_2c = uVar4 | uVar8 >> 0x1f;
      uVar8 = uVar8 * 2 | local_8 >> 0x1f;
      local_8 = local_8 << 1;
      local_14 = local_14 - 1;
    }
  }
  else if ((local_2c & 0x200000) != 0) {
    local_8 = local_8 >> 1 | uVar8 << 0x1f;
    uVar8 = uVar8 >> 1 | local_2c << 0x1f;
    local_2c = local_2c >> 1;
    local_14 = local_14 + 1;
    if (0x7fe < (int)local_14) {
      uVar3 = FUN_0806de50(param_1,local_10);
      return uVar3;
    }
  }
  if (((int)local_8 < 0) && (((uVar8 & 1) != 0 || (local_8 != 0x80000000)))) {
    if (uVar8 == 0xffffffff) {
      uVar8 = 0;
      local_2c = local_2c + 1;
      if ((local_2c & 0x200000) != 0) {
        local_2c = 0;
        local_14 = local_14 + 1;
        if (0x7fe < (int)local_14) {
          uVar3 = FUN_0806de50(param_1,local_10);
          return uVar3;
        }
      }
    }
    else {
      uVar8 = uVar8 + 1;
    }
  }
  if (local_8 == 0) {
    local_30 = 0xffffffff;
  }
  else {
    local_30 = 0;
  }
  local_2c = local_2c & 0xffefffff;
  if ((int)local_14 < 1) {
    if ((int)local_14 < -0x34) {
      local_14 = 0;
      uVar8 = 0;
      local_2c = 0;
      local_30 = 1;
    }
    else {
      local_2c = local_2c | 0x100000;
      do {
        if ((uVar8 & 1) != 0) {
          local_30 = 0xffffffff;
        }
        uVar8 = uVar8 >> 1 | local_2c << 0x1f;
        local_2c = local_2c >> 1;
        local_14 = local_14 + 1;
      } while ((int)local_14 < 1);
      local_14 = 0;
    }
  }
  *param_1 = local_2c | local_14 << 0x14 | local_10;
  param_1[1] = uVar8;
  return local_30;
}



void FUN_0806f030(uint *param_1,uint *param_2,uint *param_3)

{
  uint *puVar1;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_14 = *param_3;
  if ((int)*param_2 < 0) {
    local_c = *param_2 & 0x7fffffff;
    local_8 = param_2[1];
    puVar1 = &local_c;
    param_2 = param_3;
    if ((int)local_14 < 0) {
      local_14 = local_14 & 0x7fffffff;
      local_10 = param_3[1];
      FUN_0806e5b4(param_1,puVar1,&local_14);
      *(byte *)((int)param_1 + 3) = *(byte *)((int)param_1 + 3) ^ 0x80;
      return;
    }
  }
  else {
    if (-1 < (int)local_14) {
      FUN_0806e5b4(param_1,param_2,param_3);
      return;
    }
    local_1c = local_14 & 0x7fffffff;
    local_18 = param_3[1];
    puVar1 = &local_1c;
  }
  FUN_0806ea1c(param_1,param_2,puVar1);
  return;
}



void FUN_0806f0c4(uint *param_1,uint *param_2,uint *param_3)

{
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_1c = *param_3;
  if ((int)*param_2 < 0) {
    local_c = *param_2 & 0x7fffffff;
    local_8 = param_2[1];
    if (-1 < (int)local_1c) {
      FUN_0806e5b4(param_1,&local_c,param_3);
      *(byte *)((int)param_1 + 3) = *(byte *)((int)param_1 + 3) ^ 0x80;
      return;
    }
    local_14 = local_1c & 0x7fffffff;
    local_10 = param_3[1];
    param_2 = &local_14;
    param_3 = &local_c;
  }
  else if ((int)local_1c < 0) {
    local_1c = local_1c & 0x7fffffff;
    local_18 = param_3[1];
    FUN_0806e5b4(param_1,param_2,&local_1c);
    return;
  }
  FUN_0806ea1c(param_1,param_2,param_3);
  return;
}



// WARNING: Removing unreachable block (ram,0x0806f560)
// WARNING: Removing unreachable block (ram,0x0806f536)
// WARNING: Removing unreachable block (ram,0x0806f541)
// WARNING: Removing unreachable block (ram,0x0806f54a)
// WARNING: Removing unreachable block (ram,0x0806f570)
// WARNING: Removing unreachable block (ram,0x0806f550)
// WARNING: Removing unreachable block (ram,0x0806f579)

undefined4 FUN_0806f154(uint *param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  uint *puVar8;
  uint local_6c;
  uint local_68;
  uint local_4c;
  uint local_48;
  uint local_44;
  uint local_40 [4];
  uint local_30 [4];
  int local_20 [7];
  
  uVar4 = *param_2;
  uVar7 = *param_3;
  uVar1 = (uVar4 ^ uVar7) & 0x80000000;
  local_44 = (int)uVar4 >> 0x14 & 0x7ff;
  uVar4 = uVar4 & 0xfffff;
  local_6c = param_2[1];
  if (local_44 == 0) {
    if ((uVar4 != 0) || (uVar5 = 0, local_6c != 0)) {
      uVar4 = uVar4 * 2;
      uVar5 = uVar4 | local_6c >> 0x1f;
      uVar2 = 0;
      while (local_6c = local_6c << 1, (uVar4 & 0x100000) == 0) {
        local_44 = uVar2 - 1;
        uVar4 = uVar5 * 2;
        uVar5 = uVar4 | local_6c >> 0x1f;
        uVar2 = local_44;
      }
    }
  }
  else {
    uVar5 = uVar4 | 0x100000;
  }
  local_48 = (int)uVar7 >> 0x14 & 0x7ff;
  uVar7 = uVar7 & 0xfffff;
  local_68 = param_3[1];
  if (local_48 == 0) {
    if ((uVar7 != 0) || (uVar4 = 0, local_68 != 0)) {
      uVar7 = uVar7 * 2;
      uVar4 = uVar7 | local_68 >> 0x1f;
      uVar2 = 0;
      while (local_68 = local_68 << 1, (uVar7 & 0x100000) == 0) {
        local_48 = uVar2 - 1;
        uVar7 = uVar4 * 2;
        uVar4 = uVar7 | local_68 >> 0x1f;
        uVar2 = local_48;
      }
    }
  }
  else {
    uVar4 = uVar7 | 0x100000;
  }
  if (local_44 == 0x7ff) {
    if ((uVar5 == 0) && (local_6c == 0)) {
      if (((local_48 == 0x7ff) && (uVar4 != 0)) || (local_68 != 0)) {
        FUN_0806de70(param_1,param_3,uVar1);
      }
      else {
        if ((local_48 != 0x7ff) && (uVar4 == 0)) {
          uVar3 = FUN_0806de90(param_1,5,uVar1);
          return uVar3;
        }
        FUN_0806de50(param_1,uVar1);
      }
    }
    else {
      FUN_0806de70(param_1,param_2,uVar1);
    }
  }
  else if (local_48 == 0x7ff) {
    if ((uVar4 == 0) && (local_68 == 0)) {
      if ((uVar5 == 0) && (local_6c == 0)) {
        uVar3 = FUN_0806de90(param_1,5,uVar1);
        return uVar3;
      }
      FUN_0806de50(param_1,uVar1);
    }
    else {
      FUN_0806de70(param_1,param_3,uVar1);
    }
  }
  else {
    if (((uVar5 != 0) || (local_6c != 0)) && ((uVar4 != 0 || (local_68 != 0)))) {
      local_30[0] = uVar5 >> 7;
      local_30[1] = (uVar5 & 0x7f) << 7 | local_6c >> 0x19;
      local_30[2] = local_6c >> 0xb & 0x3fff;
      local_30[3] = local_6c * 8 & 0x3ff8;
      local_40[0] = uVar4 >> 7;
      local_40[1] = (uVar4 & 0x7f) << 7 | local_68 >> 0x19;
      local_40[2] = local_68 >> 0xb & 0x3fff;
      local_40[3] = local_68 * 8 & 0x3ff8;
      local_20[6] = 0;
      local_20[5] = 0;
      local_20[4] = 0;
      local_20[3] = 0;
      local_20[0] = 0;
      local_68 = 0;
      do {
        iVar6 = 0;
        do {
          local_20[local_68 + iVar6] =
               local_20[local_68 + iVar6] + local_30[local_68] * local_40[iVar6];
          iVar6 = iVar6 + 1;
        } while (iVar6 < 4);
        local_68 = local_68 + 1;
      } while ((int)local_68 < 4);
      local_6c = 0;
      local_68 = 6;
      puVar8 = (uint *)(local_20 + 6);
      do {
        uVar4 = *puVar8;
        *puVar8 = local_6c + uVar4 & 0x3fff;
        local_6c = local_6c + uVar4 >> 0xe;
        puVar8 = puVar8 + -1;
        local_68 = local_68 + -1;
      } while (local_68 != 0);
      local_68 = local_44 + local_48 + -0x3ff;
      local_20[2] = 0;
      local_20[1] = 0;
      uVar4 = local_6c * 2 >> 7;
      local_4c = local_6c << 0x1a;
      local_6c = 0;
      if (0x7fe < (int)local_68) {
        uVar3 = FUN_0806de50(param_1,uVar1);
        return uVar3;
      }
      if ((int)local_68 < 1) {
        if ((int)local_68 < -0x34) {
          local_68 = 0;
          local_4c = 0;
          uVar4 = 0;
          local_6c = 1;
        }
        else {
          uVar4 = uVar4 | 0x100000;
          do {
            if ((local_4c & 1) != 0) {
              local_6c = 0xffffffff;
            }
            local_4c = local_4c >> 1 | uVar4 << 0x1f;
            uVar4 = uVar4 >> 1;
            local_68 = local_68 + 1;
          } while ((int)local_68 < 1);
          local_68 = 0;
        }
      }
      *param_1 = uVar4 | local_68 << 0x14 | uVar1;
      param_1[1] = local_4c;
      return local_6c;
    }
    *param_1 = uVar1;
    param_1[1] = 0;
  }
  return 0;
}



undefined4 FUN_0806f624(uint *param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint local_28;
  uint local_24;
  int local_20;
  int local_1c;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  uVar6 = *param_2;
  uVar5 = *param_3;
  uVar1 = (uVar6 ^ uVar5) & 0x80000000;
  local_8 = (int)uVar6 >> 0x14 & 0x7ff;
  uVar6 = uVar6 & 0xfffff;
  uVar4 = param_2[1];
  if (local_8 == 0) {
    if ((uVar6 != 0) || (uVar7 = 0, uVar4 != 0)) {
      uVar6 = uVar6 * 2;
      uVar7 = uVar6 | uVar4 >> 0x1f;
      uVar2 = 0;
      while (uVar4 = uVar4 * 2, (uVar6 & 0x100000) == 0) {
        local_8 = uVar2 - 1;
        uVar6 = uVar7 * 2;
        uVar7 = uVar6 | uVar4 >> 0x1f;
        uVar2 = local_8;
      }
    }
  }
  else {
    uVar7 = uVar6 | 0x100000;
  }
  local_28 = (int)uVar5 >> 0x14 & 0x7ff;
  uVar5 = uVar5 & 0xfffff;
  local_c = param_3[1];
  if (local_28 == 0) {
    if ((uVar5 != 0) || (local_24 = 0, local_c != 0)) {
      uVar5 = uVar5 << 1;
      local_24 = uVar5 | local_c >> 0x1f;
      uVar6 = 0;
      while (local_c = local_c << 1, (uVar5 & 0x100000) == 0) {
        local_28 = uVar6 - 1;
        uVar5 = local_24 << 1;
        local_24 = uVar5 | local_c >> 0x1f;
        uVar6 = local_28;
      }
    }
  }
  else {
    local_24 = uVar5 | 0x100000;
  }
  if (local_8 == 0x7ff) {
    if ((uVar7 == 0) && (uVar4 == 0)) {
      if (local_28 == 0x7ff) {
        if ((local_24 == 0) && (local_c == 0)) {
          uVar3 = FUN_0806de90(param_1,8,uVar1);
          return uVar3;
        }
        FUN_0806de70(param_1,param_3,uVar1);
      }
      else {
        FUN_0806de50(param_1,uVar1);
      }
    }
    else {
      FUN_0806de70(param_1,param_2,uVar1);
    }
  }
  else {
    if (local_28 == 0x7ff) {
      if ((local_24 != 0) || (local_c != 0)) {
        FUN_0806de70(param_1,param_3,uVar1);
        return 0;
      }
    }
    else {
      if ((local_24 == 0) && (local_c == 0)) {
        if ((uVar7 == 0) && (uVar4 == 0)) {
          uVar3 = FUN_0806de90(param_1,7,uVar1);
          return uVar3;
        }
        FUN_0806de50(param_1,uVar1);
        return 6;
      }
      if ((uVar7 != 0) || (uVar4 != 0)) {
        local_1c = (local_8 - local_28) + 0x3fe;
        local_14 = 0;
        local_10 = 0;
        local_20 = 0x36;
        do {
          if ((local_24 < uVar7) || ((uVar7 == local_24 && (local_c <= uVar4)))) {
            uVar6 = (uVar4 & 0xff) - (local_c & 0xff);
            if ((int)uVar6 < 0) {
              uVar5 = uVar6 >> 8 ^ 0xff000000;
            }
            else {
              uVar5 = uVar6 >> 8;
            }
            uVar5 = ((uVar4 >> 8) - (local_c >> 8)) + uVar5;
            if ((int)uVar5 < 0) {
              uVar4 = uVar5 >> 0x18 ^ 0xffffff00;
            }
            else {
              uVar4 = uVar5 >> 0x18;
            }
            uVar7 = (uVar7 - local_24) + uVar4;
            uVar4 = uVar5 * 0x100 | uVar6 & 0xff;
            local_10 = local_10 << 1 | local_14 >> 0x1f;
            local_14 = local_14 << 1 | 1;
          }
          else {
            local_10 = local_10 << 1 | local_14 >> 0x1f;
            local_14 = local_14 << 1;
          }
          uVar7 = uVar7 * 2 | uVar4 >> 0x1f;
          uVar4 = uVar4 * 2;
          local_20 = local_20 + -1;
        } while (-1 < local_20);
        uVar6 = (uVar7 | uVar4) >> 8 | (uVar7 | uVar4) & 0xff;
        if ((local_10 & 0x400000) != 0) {
          uVar6 = uVar6 | local_14 & 1;
          local_14 = local_14 >> 1 | local_10 << 0x1f;
          local_10 = local_10 >> 1;
          local_1c = (local_8 - local_28) + 0x3ff;
        }
        uVar5 = local_14 << 0x1f;
        uVar6 = uVar6 | uVar5;
        uVar4 = local_14 >> 1;
        local_14 = uVar4 | local_10 << 0x1f;
        local_10 = local_10 >> 1;
        if ((uVar5 != 0) && (((uVar4 & 1) != 0 || (uVar6 != 0x80000000)))) {
          if (local_14 == 0xffffffff) {
            local_14 = 0;
            local_10 = local_10 + 1;
            if ((local_10 & 0x200000) != 0) {
              local_10 = 0;
              local_1c = local_1c + 1;
            }
          }
          else {
            local_14 = local_14 + 1;
          }
        }
        if (uVar6 == 0) {
          uVar3 = 0;
        }
        else {
          uVar3 = 0xffffffff;
        }
        local_10 = local_10 & 0xffefffff;
        if (local_1c < 0x7ff) {
          if (local_1c < 1) {
            if (local_1c < -0x34) {
              local_1c = 0;
              local_14 = 0;
              local_10 = 0;
              uVar3 = 1;
            }
            else {
              local_10 = local_10 | 0x100000;
              do {
                if ((local_14 & 1) != 0) {
                  uVar3 = 0xffffffff;
                }
                local_14 = local_14 >> 1 | local_10 << 0x1f;
                local_10 = local_10 >> 1;
                local_1c = local_1c + 1;
              } while (local_1c < 1);
              local_1c = 0;
            }
          }
          *param_1 = local_10 | local_1c << 0x14 | uVar1;
          param_1[1] = local_14;
          return uVar3;
        }
        uVar3 = FUN_0806de50(param_1,uVar1);
        return uVar3;
      }
    }
    *param_1 = uVar1;
    param_1[1] = 0;
  }
  return 0;
}



undefined4 FUN_0806fa48(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  uVar5 = *param_1;
  uVar6 = param_1[1];
  uVar2 = *param_2;
  uVar1 = param_2[1];
  if (((((uVar5 & 0x7fffffff) == 0) && ((uVar2 & 0x7fffffff) == 0)) && (uVar6 == 0)) && (uVar1 == 0)
     ) {
    return 0;
  }
  if ((int)uVar5 < 0) {
    if (-1 < (int)uVar2) {
      return 0xffffffff;
    }
    uVar4 = uVar2 & 0x7fffffff;
    uVar2 = uVar5 & 0x7fffffff;
    uVar3 = uVar6;
    uVar5 = uVar4;
    uVar6 = uVar1;
  }
  else {
    uVar3 = uVar1;
    if ((int)uVar2 < 0) {
      return 1;
    }
  }
  if ((int)uVar2 <= (int)uVar5) {
    if ((int)uVar5 <= (int)uVar2) {
      if (uVar6 < uVar3) {
        return 0xffffffff;
      }
      if (uVar6 <= uVar3) {
        return 0;
      }
    }
    return 1;
  }
  return 0xffffffff;
}



undefined4 FUN_0806fac4(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  uVar1 = param_2[1];
  *param_1 = *param_2;
  param_1[1] = uVar1;
  return 0;
}



undefined4 FUN_0806fadc(uint *param_1,uint *param_2)

{
  *param_1 = *param_2 ^ 0x80000000;
  param_1[1] = param_2[1];
  return 0;
}



undefined4 FUN_0806fafc(uint *param_1,uint param_2,uint param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_2 == 0) {
    param_1[1] = 0;
    *param_1 = 0;
  }
  else {
    uVar3 = param_2 >> 0xb;
    uVar4 = param_2 << 0x15;
    iVar2 = 0x41e;
    uVar1 = uVar3;
    while ((uVar1 & 0x100000) == 0) {
      uVar1 = uVar3 * 2;
      uVar3 = uVar1 | uVar4 >> 0x1f;
      uVar4 = uVar4 * 2;
      iVar2 = iVar2 + -1;
    }
    *param_1 = uVar3 & 0xffefffff | iVar2 << 0x14 | param_3;
    param_1[1] = uVar4;
  }
  return 0;
}



void FUN_0806fb68(uint *param_1,uint param_2)

{
  uint uVar1;
  
  if ((int)param_2 < 0) {
    uVar1 = 0x80000000;
    param_2 = -param_2;
  }
  else {
    uVar1 = 0;
  }
  FUN_0806fafc(param_1,param_2,uVar1);
  return;
}



void FUN_0806fba0(uint *param_1,uint param_2)

{
  FUN_0806fafc(param_1,param_2,0);
  return;
}



undefined4 FUN_0806fbc4(uint *param_1,uint *param_2)

{
  *param_1 = *param_2 & 0x7fffffff;
  param_1[1] = param_2[1];
  return 0;
}



undefined4 FUN_0806fbe4(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  uVar1 = *param_2;
  uVar2 = uVar1 >> 0x14 & 0xfffff7ff;
  uVar4 = uVar1 & 0xfffff | 0x100000;
  iVar3 = uVar2 - 0x3ff;
  if (iVar3 < 0) {
    uVar4 = 0;
  }
  else if (iVar3 < 0x14) {
    uVar4 = uVar4 >> (0x14U - (char)iVar3 & 0x1f);
  }
  else if (iVar3 != 0x14) {
    if (0x1f < iVar3) {
      if (iVar3 == 0x400) {
        *param_1 = 0;
        return 2;
      }
      if ((uVar1 & 0x80000000) == 0) {
        *param_1 = 0x7fffffff;
        return 2;
      }
      goto LAB_0806fc7d;
    }
    uVar4 = uVar4 << ((char)uVar2 - 0x13U & 0x1f) | param_2[1] >> (0x34U - (char)iVar3 & 0x1f);
  }
  if ((uVar1 & 0x80000000) == 0) {
    if ((int)uVar4 < 0) {
      *param_1 = 0x7fffffff;
      return 2;
    }
  }
  else {
    if (0x80000000 < uVar4) {
LAB_0806fc7d:
      *param_1 = 0x80000000;
      return 2;
    }
    uVar4 = -uVar4;
  }
  *param_1 = uVar4;
  return 0;
}



undefined4 FUN_0806fcb4(uint *param_1,uint *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  
  uVar4 = *param_2;
  uVar1 = uVar4 >> 0x14 & 0xfffff7ff;
  if (((int)uVar4 < 0) && (uVar1 != 0)) {
    *param_1 = 0;
    uVar2 = 5;
  }
  else {
    uVar4 = uVar4 & 0xfffff | 0x100000;
    iVar3 = uVar1 - 0x3ff;
    if (iVar3 < 0) {
      uVar4 = 0;
    }
    else if (iVar3 < 0x14) {
      uVar4 = uVar4 >> (0x14U - (char)iVar3 & 0x1f);
    }
    else if (iVar3 != 0x14) {
      if (0x1f < iVar3) {
        if (iVar3 == 0x400) {
          *param_1 = 0;
        }
        else {
          *param_1 = 0xffffffff;
        }
        return 2;
      }
      uVar4 = uVar4 << ((char)uVar1 - 0x13U & 0x1f) | param_2[1] >> (0x34U - (char)iVar3 & 0x1f);
    }
    *param_1 = uVar4;
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_0806fd50(void)

{
  undefined4 *puVar1;
  
  DAT_0807b094 = DAT_0807b090;
  puVar1 = DAT_0807b090;
  while (puVar1 != (undefined4 *)0x0) {
    puVar1[2] = (undefined4 *)*puVar1;
    puVar1 = (undefined4 *)*puVar1;
  }
  DAT_0807b098 = FUN_0806feec();
  return;
}



int FUN_0806fd8c(uint param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = &DAT_0807b094;
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



undefined4 * FUN_0806fdcc(int param_1,uint param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  
  uVar2 = param_1 + 3U & 0xfffffffc;
  puVar1 = (undefined4 *)FUN_0806fd8c(uVar2);
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
    *puVar1 = DAT_0807b090;
    DAT_0807b090 = puVar1;
  }
  return puVar1 + 2;
}



undefined4 FUN_0806fe40(int param_1)

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



void FUN_0806fe54(int *param_1)

{
  if (param_1 != (int *)0x0) {
    *param_1 = (int)DAT_0807b094;
    DAT_0807b094 = param_1 + -2;
  }
  return;
}



void FUN_0806fe84(void)

{
  undefined4 *puVar1;
  undefined4 *__ptr;
  
  __ptr = DAT_0807b090;
  while (__ptr != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*__ptr;
    free(__ptr);
    __ptr = puVar1;
  }
  DAT_0807b094 = 0;
  DAT_0807b090 = (undefined4 *)0x0;
  FUN_0806ff34(DAT_0807b098);
  DAT_0807b098 = 0;
  return;
}



undefined4 FUN_0806fee4(undefined4 param_1)

{
  return param_1;
}



undefined4 FUN_0806feec(void)

{
  return 0;
}



void FUN_0806fef4(undefined4 param_1)

{
  FUN_0806fee4(param_1);
  return;
}



void FUN_0806ff14(undefined4 param_1)

{
  FUN_0806fee4(param_1);
  return;
}



void FUN_0806ff34(undefined4 param_1)

{
  FUN_0806fee4(param_1);
  return;
}



int FUN_0806ff60(byte *param_1)

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



void FUN_0806ff88(uint param_1)

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



char * FUN_0806ffa0(char *param_1)

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



void FUN_0806ffec(char *param_1,size_t param_2)

{
  char *pcVar1;
  size_t __n;
  
  __n = param_2;
  pcVar1 = malloc(param_2 + 1);
  pcVar1 = strncpy(pcVar1,param_1,__n);
  pcVar1[param_2] = '\0';
  return;
}



void FUN_08070024(void *param_1)

{
  if (param_1 != (void *)0x0) {
    free(param_1);
  }
  return;
}



void FUN_08070048(void *param_1)

{
  void *pvVar1;
  
  FUN_08070024(*(void **)((int)param_1 + 4));
  pvVar1 = *(void **)((int)param_1 + 8);
  if (*(void **)((int)param_1 + 0xc) != pvVar1) {
    FUN_08070024(*(void **)((int)param_1 + 0xc));
    pvVar1 = *(void **)((int)param_1 + 8);
  }
  FUN_08070024(pvVar1);
  free(param_1);
  return;
}



int * FUN_08070090(uint param_1)

{
  int *piVar1;
  int iVar2;
  void *pvVar3;
  
  piVar1 = malloc(0xc);
  if (param_1 < 8) {
    param_1 = 8;
  }
  iVar2 = FUN_0806ff88(param_1);
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



void FUN_080700f8(undefined4 *param_1)

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
      FUN_08070048(puVar2);
      puVar2 = puVar1;
    }
  }
  free((void *)*param_1);
  free(param_1);
  return;
}



undefined4 * FUN_08070154(int *param_1,byte *param_2,char *param_3,uint param_4)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  char *pcVar5;
  
  uVar2 = FUN_0806ff60(param_2);
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
        FUN_08070024(param_2);
      }
      if ((void *)puVar4[3] != (void *)0x0) {
        if ((void *)puVar4[3] != (void *)puVar4[2]) {
          FUN_08070024((void *)puVar4[2]);
        }
        puVar4[2] = 0;
        return puVar4;
      }
      *puVar1 = *puVar4;
      FUN_08070048(puVar4);
      return (undefined4 *)0x0;
    }
    if (puVar4 == (undefined4 *)0x0) {
      puVar4 = malloc(0x10);
      *puVar4 = 0;
      *puVar1 = puVar4;
      if ((param_4 & 2) == 0) {
        pcVar5 = FUN_0806ffa0((char *)param_2);
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
      FUN_08070024(param_2);
    }
    if ((puVar4[2] == 0) || (iVar3 = strcmp((char *)(puVar4[2] + 1),param_3 + 1), iVar3 != 0)) {
      if ((void *)puVar4[2] != (void *)puVar4[3]) {
        FUN_08070024((void *)puVar4[2]);
      }
      if ((param_4 & 2) == 0) {
        pcVar5 = FUN_0806ffa0(param_3);
        puVar4[2] = pcVar5;
      }
      else {
        puVar4[2] = param_3;
      }
      *(char *)puVar4[2] = *param_3;
    }
    else if ((param_4 & 2) != 0) {
      *(char *)puVar4[2] = *param_3;
      FUN_08070024(param_3);
    }
  }
  return puVar4;
}



undefined4 FUN_080702e4(int *param_1,byte *param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = FUN_08070154(param_1,param_2,(char *)0x0,1);
  if (puVar1 == (undefined4 *)0x0) {
    uVar2 = 0;
  }
  else {
    uVar2 = puVar1[2];
  }
  return uVar2;
}



undefined4 FUN_08070318(int *param_1,byte *param_2,int param_3,char *param_4)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  
  if ((*param_4 == '\0') && (param_3 != 0x3f)) {
    uVar3 = 0;
    pcVar2 = (char *)0x0;
  }
  else {
    param_2 = (byte *)FUN_0806ffa0((char *)param_2);
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
  FUN_08070154(param_1,param_2,pcVar2,uVar3);
  return 0;
}



undefined4 FUN_08070394(int *param_1,byte *param_2,char *param_3)

{
  char cVar1;
  
  cVar1 = *param_3;
  if ((((cVar1 == '=') || (cVar1 == '#')) || (cVar1 == '^')) && (param_3[1] == '\0')) {
    param_3 = (char *)0x0;
  }
  FUN_08070154(param_1,param_2,param_3,0);
  return 0;
}



undefined4 FUN_080703d4(int *param_1,char *param_2)

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
    pbVar2 = (byte *)FUN_0806ffec(param_2,(int)pcVar3 - (int)param_2);
    for (param_2 = pcVar3; (cVar4 = *param_2, cVar4 != '\0' && (cVar4 != '\n'));
        param_2 = param_2 + 1) {
    }
    if ((param_2 == pcVar3 + 1) &&
       (((cVar1 = *pcVar3, cVar1 == '=' || (cVar1 == '#')) || (cVar1 == '^')))) {
      pcVar3 = (char *)0x0;
    }
    else {
      pcVar3 = (char *)FUN_0806ffec(pcVar3,(int)param_2 - (int)pcVar3);
      cVar4 = *param_2;
    }
    if (cVar4 == '\n') {
      param_2 = param_2 + 1;
    }
    FUN_08070154(param_1,pbVar2,pcVar3,2);
    cVar4 = *param_2;
  } while( true );
}



void FUN_080704b4(int *param_1)

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
        FUN_08070024((void *)piVar2[3]);
        pvVar3 = (void *)piVar2[2];
      }
      piVar2[3] = (int)pvVar3;
      if (pvVar3 == (void *)0x0) {
        *piVar4 = *piVar2;
        FUN_08070048(piVar2);
      }
      else {
        piVar4 = (int *)*piVar4;
      }
    }
  }
  return;
}



int * FUN_08070528(int *param_1)

{
  undefined4 *puVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = FUN_08070090(param_1[2]);
  iVar3 = param_1[1];
  while (0 < iVar3) {
    iVar3 = iVar3 + -1;
    for (puVar1 = *(undefined4 **)(*param_1 + iVar3 * 4); puVar1 != (undefined4 *)0x0;
        puVar1 = (undefined4 *)*puVar1) {
      FUN_08070154(piVar2,(byte *)puVar1[1],(char *)puVar1[2],0);
    }
  }
  return piVar2;
}



int FUN_0807058c(int *param_1,char *param_2,uint param_3)

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
        goto LAB_0807076d;
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
LAB_0807076d:
    }
  } while( true );
}



int FUN_08070794(int *param_1,undefined *param_2,undefined4 param_3)

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



char * FUN_080707f0(char *param_1)

{
  char cVar1;
  char *__s2;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  uint uVar5;
  
  __s2 = FUN_08061ec4();
  pcVar2 = FUN_08070eec((char *)0x0,(char *)0x0,(int)__s2,0);
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



int * FUN_080708a8(void)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = FUN_08070090(0x40);
  if (piVar1 != (int *)0x0) {
    iVar2 = FUN_08061f20(piVar1);
    if (iVar2 != 0) {
      FUN_080700f8(piVar1);
      piVar1 = (int *)0x0;
    }
  }
  return piVar1;
}



int FUN_080708e8(int *param_1,char *param_2)

{
  int iVar1;
  char *pcVar2;
  FILE *__stream;
  size_t sVar3;
  int local_1008;
  char local_1004 [4096];
  
  if ((*param_2 == '$') && (param_2[1] == '\0')) {
    iVar1 = FUN_08061f20(param_1);
  }
  else if (*param_2 == '*') {
    if (param_2[1] == '\0') {
      pcVar2 = FUN_080707f0(local_1004);
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
        local_1008 = FUN_080703d4(param_1,pcVar2);
        free(pcVar2);
      }
      fclose(__stream);
      return local_1008;
    }
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_080703d4(param_1,param_2);
  }
  return iVar1;
}



bool FUN_080709f8(int *param_1)

{
  uint param2;
  size_t __size;
  char *pcVar1;
  FILE *pFVar2;
  size_t sVar3;
  char *__filename;
  bool bVar4;
  char local_1004 [4096];
  
  param2 = FUN_08070ddc();
  sprintf(local_1004,"?%#.8x",param2);
  FUN_08070394(param_1,(byte *)".defaulttime",local_1004);
  __size = FUN_0807058c(param_1,(char *)0x0,0);
  if (__size == 0) {
    pcVar1 = FUN_080707f0(local_1004);
    if ((pcVar1 != (char *)0x0) && (pFVar2 = fopen(pcVar1,"w"), pFVar2 != (FILE *)0x0)) {
      fclose(pFVar2);
      return false;
    }
  }
  else {
    pcVar1 = malloc(__size);
    if (pcVar1 != (char *)0x0) {
      sVar3 = FUN_0807058c(param_1,pcVar1,__size);
      if (((sVar3 == __size) && (__filename = FUN_080707f0(local_1004), __filename != (char *)0x0))
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



int FUN_08070b40(char *param_1,char *param_2)

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



int FUN_08070ba0(char *param_1,char *param_2,int param_3)

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



bool FUN_08070c0c(char *param_1,char *param_2)

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
        bVar1 = FUN_08070c0c(param_1,param_2);
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



undefined1 * FUN_08070ca4(undefined1 *param_1,undefined1 *param_2,char *param_3)

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



__time_t FUN_08070d10(char *param_1)

{
  int iVar1;
  stat local_5c;
  
  iVar1 = __xstat(3,param_1,&local_5c);
  if (iVar1 != 0) {
    local_5c.st_mtim.tv_sec = -1;
  }
  return local_5c.st_mtim.tv_sec;
}



undefined4 FUN_08070d48(char *param_1,__time_t param_2)

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



undefined4 FUN_08070d8c(char *param_1)

{
  int iVar1;
  stat local_5c;
  
  iVar1 = __xstat(3,param_1,&local_5c);
  if ((iVar1 == 0) && (iVar1 = chmod(param_1,local_5c.st_mode | 0x40), iVar1 == 0)) {
    return 0;
  }
  return 0xffffffff;
}



time_t FUN_08070ddc(void)

{
  time_t local_8;
  
  time(&local_8);
  return local_8;
}



void FUN_08070e00(void)

{
  return;
}



bool FUN_08070e10(char *param_1)

{
  int iVar1;
  stat local_5c;
  
  iVar1 = __xstat(3,param_1,&local_5c);
  return iVar1 == 0 && (local_5c.st_mode & 0xf000) != 0x4000;
}



char * FUN_08070e54(char *param_1,char *param_2,int param_3,char *param_4)

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
    bVar1 = FUN_08070e10(param_4);
    if (CONCAT31(extraout_var,bVar1) != 0) break;
    param2 = strtok((char *)0x0,":");
    if (param2 == (char *)0x0) {
      return (char *)0x0;
    }
  }
  return param_4;
}



char * FUN_08070eec(char *param_1,char *param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  char *pcVar2;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  char local_808 [2048];
  undefined1 local_8;
  
  if (param_1 != (char *)0x0) {
    DAT_0807b09c = param_1;
  }
  if (param_3 == 0) {
    return (char *)0x0;
  }
  local_8 = 0;
  if (param_4 == 0) {
    sprintf(&DAT_0807fae0,"%s",(char *)param_3);
  }
  else {
    sprintf(&DAT_0807fae0,"%s.%s",(char *)param_3,(char *)param_4);
  }
  bVar1 = FUN_08070e10(&DAT_0807fae0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    pcVar2 = (char *)0x0;
    if (DAT_0807b09c != (char *)0x0) {
      pcVar2 = strrchr(DAT_0807b09c,0x2f);
    }
    if (pcVar2 != (char *)0x0) {
      if (param_4 == 0) {
        sprintf(&DAT_0807fae0,"%.*s%s",(int)(pcVar2 + (1 - (int)DAT_0807b09c)),DAT_0807b09c,
                (char *)param_3);
      }
      else {
        sprintf(&DAT_0807fae0,"%.*s%s.%s",(int)(pcVar2 + (1 - (int)DAT_0807b09c)),DAT_0807b09c,
                (char *)param_3,(char *)param_4);
      }
      bVar1 = FUN_08070e10(&DAT_0807fae0);
      if (CONCAT31(extraout_var_00,bVar1) != 0) goto LAB_080710db;
    }
    if ((param_2 != (char *)0x0) && (pcVar2 = getenv(param_2), pcVar2 != (char *)0x0)) {
      strncpy(local_808,pcVar2,0x800);
      pcVar2 = FUN_08070e54(local_808,param_3,param_4,&DAT_0807fae0);
      if (pcVar2 != (char *)0x0) {
        return pcVar2;
      }
    }
    pcVar2 = getenv("ARMLIB");
    if (pcVar2 != (char *)0x0) {
      strncpy(local_808,pcVar2,0x800);
      pcVar2 = FUN_08070e54(local_808,param_3,param_4,&DAT_0807fae0);
      if (pcVar2 != (char *)0x0) {
        return pcVar2;
      }
    }
    pcVar2 = getenv("HOME");
    if (pcVar2 != (char *)0x0) {
      if (param_4 == 0) {
        sprintf(&DAT_0807fae0,"%s/%s",pcVar2,(char *)param_3);
      }
      else {
        sprintf(&DAT_0807fae0,"%s/%s.%s",pcVar2,(char *)param_3,(char *)param_4);
      }
      bVar1 = FUN_08070e10(&DAT_0807fae0);
      if (CONCAT31(extraout_var_01,bVar1) != 0) goto LAB_080710db;
    }
    pcVar2 = getenv("PATH");
    if ((pcVar2 != (char *)0x0) && (*pcVar2 != '\0')) {
      strncpy(local_808,pcVar2,0x800);
      pcVar2 = FUN_08070e54(local_808,param_3,param_4,&DAT_0807fae0);
      if (pcVar2 != (char *)0x0) {
        return pcVar2;
      }
    }
    memcpy(local_808,"/usr/local/lib/arm:/usr/local/lib:/usr/local/arm:/usr/lib/arm:/usr/lib",0x47);
    pcVar2 = FUN_08070e54(local_808,param_3,param_4,&DAT_0807fae0);
  }
  else {
LAB_080710db:
    pcVar2 = &DAT_0807fae0;
  }
  return pcVar2;
}



void FUN_08071160(void)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = &DAT_0807b0a4;
  iVar1 = DAT_0807b0a4;
  while (iVar1 != -1) {
    (*(code *)*piVar2)();
    piVar2 = piVar2 + -1;
    iVar1 = *piVar2;
  }
  return;
}



void FUN_08071184(void)

{
  return;
}



void _DT_FINI(void)

{
  FUN_08048f50();
  return;
}


