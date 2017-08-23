#include "elf.h"
#include "debug.h"
#include "alloc.h"

volatile struct r_debug r_debug;

void debug_notify()
{
}

void debug_init(module *dlng)
{
	r_debug.r_version = 1;
	r_debug.r_map = NULL;
	r_debug.r_brk = (intptr_t)debug_notify;
	r_debug.r_state = RT_CONSISTENT;
	r_debug.r_ldbase = dlng->base_addr;
}

void debug_add(module *mod)
{
	r_debug.r_state = RT_ADD;
	debug_notify();
	
	struct link_map *link = mmap_malloc(sizeof(struct link_map));
	link->l_addr = mod->base_addr;
	link->l_name = mod->filename;
	link->l_ld = mod->dynamic;
	link->mod = mod;

	link->l_next = r_debug.r_map;
	link->l_prev = NULL;
	if(r_debug.r_map)
		r_debug.r_map->l_prev = link;
	r_debug.r_map = link;

	r_debug.r_state = RT_CONSISTENT;
	debug_notify();
}

void debug_remove(module *mod)
{
	r_debug.r_state = RT_DELETE;
	debug_notify();
	
	struct link_map *link;
	for(link = r_debug.r_map; link; link = link->l_next)
		if(link->mod == mod)
		{
			if(link->l_prev)
				link->l_prev->l_next = link->l_next;
			else
				r_debug.r_map = link->l_next;

			if(link->l_next)
				link->l_next->l_prev = link->l_prev;

			mmap_free(link);
			break;
		}

	r_debug.r_state = RT_CONSISTENT;
	debug_notify();
}
