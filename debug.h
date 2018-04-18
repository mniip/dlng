#ifndef DEBUG_H
#define DEBUG_H

#include "elf.h"

struct r_debug
{
	int r_version;
	struct link_map *r_map;
	ElfW(Addr) r_brk;
	enum { RT_CONSISTENT, RT_ADD, RT_DELETE } r_state;
	ElfW(Addr) r_ldbase;
};

extern volatile struct r_debug local_debug;
extern volatile struct r_debug r_debug;

struct link_map
{
	ElfW(Addr) l_addr;
	char *l_name;
	ElfW(Dyn) *l_ld;
	struct link_map *l_next, *l_prev;
	module *mod;
};

extern void debug_notify(void) __attribute__((noinline));
extern void debug_init(module *);
extern void debug_add(module *);
extern void debug_remove(module *);
extern void debug_update(module *);

#endif
