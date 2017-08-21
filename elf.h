#ifndef ELF_H
#define ELF_H

#include <stdint.h>
#include <elf.h>

#if __WORDSIZE == 64
#define ElfW(x) Elf64_ ## x
#else
#define ElfW(x) Elf32_ ## x
#endif

#endif
