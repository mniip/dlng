#include "modules.h"
#include "dump.h"
#include "alloc.h"

mod_ns *first_ns = NULL;
mod_ns *dynamic_ns = NULL;

mod_ns *create_namespace()
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
