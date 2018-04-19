#ifndef ELF_H
#define ELF_H

#include <stdint.h>
#include <elf.h>

#if __WORDSIZE == 64

#define ElfW(x) Elf64_ ## x
#define ELFW(x) ELF64_ ## x
#define ELFW_CLASS ELFCLASS64

#else

#define ElfW(x) Elf32_ ## x
#define ELFW(x) ELF32_ ## x
#define ELFW_CLASS ELFCLASS32

#endif

#include "modules.h"

extern struct module *load_soname(char const *);
extern void process_dynamic(struct module *);
extern void load_tls(struct module *);

#endif
