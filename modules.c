#include "modules.h"
#include "dump.h"
#include "alloc.h"

mod_ns *first_ns = NULL;
mod_ns *dynamic_ns = NULL;

mod_ns *create_namespace(void)
{
	mod_ns *ns = mmap_malloc(sizeof(mod_ns));
	ns->next = first_ns;
	ns->first_mod = NULL;
	ns->parent = NULL;
	first_ns = ns;
	return ns;
}

module *create_module(char const *name)
{
	module *mod = mmap_malloc(sizeof(module));
	
	mod->next = NULL;
	mod->parent_ns  = NULL;

	mod->name = name ? strdup(name) : NULL;
	mod->filename = NULL;

	mod->num_rev_deps = 0;
	mod->rev_deps = NULL;

	return mod;
}

void ns_add_parent(mod_ns *ns, mod_ns *parent)
{
	ns->parent = parent;
}

void ns_add_module(mod_ns *ns, module *mod)
{
	mod->next = ns->first_mod;
	ns->first_mod = mod;
}

void dump_mod_tree(mod_ns *root, mod_ns ***seen, size_t *num_seen, size_t spc)
{
	(*num_seen)++;
	*seen = mmap_realloc(*seen, *num_seen * sizeof(mod_ns *));
	(*seen)[*num_seen - 1] = root;

	size_t i;
	for(i = 0; i < spc; i++) dumpf("  ");
	dumpf("NS %p%s:\n", root, root == dynamic_ns ? " (dynamic linker)" : "");
	
	module *mod;
	for(mod = root->first_mod; mod; mod = mod->next)
	{
		for(i = 0; i < spc; i++) dumpf("  ");
		dumpf("  MOD %s @ 0x%x (%s)\n", mod->name ? mod->name : "???", mod->base_addr, mod->filename ? mod->filename : "???");
	}

	mod_ns *ns;
	for(ns = first_ns; ns; ns = ns->next)
		if(ns->parent == root)
			dump_mod_tree(ns, seen, num_seen, spc + 1);
}

void dump_mods(void)
{
	size_t num_seen = 0;
	mod_ns **seen = mmap_malloc(num_seen * sizeof(mod_ns *));

	mod_ns *ns;
	for(ns = first_ns; ns; ns = ns->next)
	{
		int found = 0;
		size_t i;
		for(i = 0; i < num_seen; i++)
			if(seen[i] == ns)
			{
				found = 1;
				break;
			}

		if(found)
			continue;

		dump_mod_tree(ns, &seen, &num_seen, 0);
	}

	mmap_free(seen);
}
