#include "elf.h"
#include "debug.h"
#include "alloc.h"

volatile struct r_debug local_debug =
{
	.r_version = 1,
	.r_map = NULL,
	.r_brk = 0,
	.r_state = RT_CONSISTENT,
};

extern volatile struct r_debug _r_debug __attribute__ ((alias ("local_debug")));

__attribute__((noinline)) void debug_notify(void)
{
	asm volatile ("");
}

void debug_init(module *dlng)
{
	local_debug.r_brk = (intptr_t)debug_notify;
	local_debug.r_ldbase = dlng->base_addr;
	debug_notify();
}

void debug_add(module *mod)
{
	local_debug.r_state = RT_ADD;
	debug_notify();
	
	struct link_map *link = mmap_malloc(sizeof(struct link_map));
	link->l_addr = mod->base_addr;
	link->l_name = mod->filename;
	link->l_ld = mod->dynamic;
	link->mod = mod;

	link->l_next = local_debug.r_map;
	link->l_prev = NULL;
	if(local_debug.r_map)
		local_debug.r_map->l_prev = link;
	local_debug.r_map = link;

	local_debug.r_state = RT_CONSISTENT;
	debug_notify();
}

void debug_remove(module *mod)
{
	local_debug.r_state = RT_DELETE;
	debug_notify();
	
	struct link_map *link;
	for(link = local_debug.r_map; link; link = link->l_next)
		if(link->mod == mod)
		{
			if(link->l_prev)
				link->l_prev->l_next = link->l_next;
			else
				local_debug.r_map = link->l_next;

			if(link->l_next)
				link->l_next->l_prev = link->l_prev;

			mmap_free(link);
			break;
		}

	local_debug.r_state = RT_CONSISTENT;
	debug_notify();
}
