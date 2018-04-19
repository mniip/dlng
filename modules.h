#ifndef MODULES_H
#define MODULES_H

#include <stddef.h>
#include <stdint.h>

struct mod_ns;
struct module;

#include "elf.h"

typedef struct module
{
	struct module *next;

	struct mod_ns *parent_ns;

	char *name;
	char *filename;

	ElfW(Addr) entry;

	ElfW(Addr) base_addr;
	ElfW(Phdr) *program_headers;
	size_t num_ph;
	size_t size_ph;
	int ph_mapped;

	ElfW(Dyn) *dynamic;
	ElfW(Sym) *symtab;
	size_t num_st;
	size_t size_st;
	char *strtab;

	ElfW(Half) *ver_sym;
	size_t num_ver_defs;
	ElfW(Verdef) *ver_defs;

	size_t tls_offset;
	ElfW(Addr) tls_tdata;
	size_t tls_tdata_size;

	void (*init)(int, char **, char **);
	void (*fini)(void);

	size_t num_rev_deps;
	struct module **rev_deps;
}
module;

typedef struct mod_ns
{
	struct mod_ns *next;
	struct mod_ns *parent;

	module *first_mod;
}
mod_ns;

extern mod_ns *first_ns;

extern mod_ns *dynamic_ns;

extern mod_ns *create_namespace(void);
extern module *create_module(char const *);
extern void ns_add_parent(mod_ns *, mod_ns *);
extern void ns_add_module(mod_ns *, module *);
extern void dump_mods(void);

#endif
