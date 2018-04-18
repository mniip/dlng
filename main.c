#include <stdint.h>
#include <asm/prctl.h>
#include <linux/fcntl.h>
#include <linux/auxvec.h>

#include "modules.h"
#include "elf.h"
#include "alloc.h"
#include "syscalls.h"
#include "util.h"
#include "dump.h"
#include "debug.h"

extern char _start[];
extern char _DYNAMIC[];
extern void start_program(void *, void (*)());

void dlng_main_finish(void);

struct rtld_hook
{
	void *(*dlopen_mode)(char const *, int);
	void *(*dlsym)(void *, char const *);
	int (*dlclose)(void *);
};

void *dlopen_mode(char const *mod, int f)
{
	if(mod)
		panic("dlmopen(\"%s\", %x)\n", mod, f);
	else
		panic("dlmopen(NULL, %x)\n", f);
}

void *dlsym(void *l, char const *s)
{
	if(s)
		panic("dlsym(%p, \"%s\")\n", l, s);
	else
		panic("dlsym(%p, NULL)\n", l);
}

int dlclose(void *l)
{
	panic("dlclose(%p)\n", l);
}

struct rtld_hook dlng_rtld = {};

void dlng_main(void *stack)
{
	void *stk = stack;

	intptr_t argc = *(intptr_t *)stk;
	stk = PTR_ADVANCE(stk, intptr_t);

	char **argv = stk;
	stk = PTR_ADVANCE_N(stk, char const *, argc + 1);
	
	char **envp = stk;
	while(*(char const **)stk)
		stk = PTR_ADVANCE(stk, char const *);
	stk = PTR_ADVANCE(stk, char const *);

	ElfW(Addr) entry = 0;
	ElfW(auxv_t) *auxvec = stk;
	ElfW(auxv_t) *av;
	
	dynamic_ns = create_namespace();

	module *dlng = create_module(NULL);
	dlng->base_addr = -1;
	dlng->program_headers = NULL;
	dlng->ph_mapped = 0;
	
	ns_add_module(dynamic_ns, dlng);
	
	int seen_entry;

	av = auxvec;
	while(av->a_type != AT_NULL)
	{
		switch(av->a_type)
		{
			case AT_EXECFD:
				panic("AT_EXECFD not supported\n");

			case AT_NOTELF:
				if(av->a_un.a_val)
					panic("AT_NOTELF not supported\n");
				break;
			
			case AT_ENTRY:
				entry = av->a_un.a_val;
				seen_entry = 1;
				break;

			case AT_BASE:
				dlng->base_addr = av->a_un.a_val;

			default:
				break;
		}
		av++;
	}

	if(!seen_entry)
		panic("Cannot find program: AT_ENTRY not specified\n");

	void **tls = mmap_malloc(sizeof(void *));
	tls[0] = tls;
	arch_prctl(ARCH_SET_FS, tls);
	
	debug_init(dlng);
	debug_add(dlng);

	dlng_rtld.dlopen_mode = dlopen_mode;
	dlng_rtld.dlsym = dlsym;
	dlng_rtld.dlclose = dlclose;
	
	module *program;

	if((void *)entry == (void *)&_start)
	{
		dlng->filename = strdup(argv[0]);
		dlng->name = strdup(argv[0]);

		program = load_soname(argv[1]);

		intptr_t *istk = (intptr_t *)stack;
		istk[1] = istk[0] - 1;
		stack = &istk[1];
		argc--;
		argv++;

		entry = program->entry;

		ElfW(Dyn) *de;
		for(de = (void *)&_DYNAMIC; de->d_tag != DT_NULL; de++)
			if(de->d_tag == DT_DEBUG)
				de->d_un.d_ptr = (intptr_t)&local_debug;
	}
	else
	{
		program = create_module(argv[0]);
		program->filename = strdup(argv[0]);
		program->base_addr = 0;
		ns_add_module(dynamic_ns, program);
		
		int seen_phdr = 0, seen_phnum = 0, seen_phent = 0;

		av = auxvec;
		while(av->a_type != AT_NULL)
		{
			switch(av->a_type)
			{
				case AT_PHDR:
					program->program_headers = (void *)av->a_un.a_val;
					program->ph_mapped = 1;
					seen_phdr = 1;
					break;

				case AT_PHENT:
					program->size_ph = av->a_un.a_val;
					seen_phent = 1;

				case AT_PHNUM:
					program->num_ph = av->a_un.a_val;
					seen_phnum = 1;

				default:
					break;
			}
			av++;
		}
		
		if(!seen_phdr)
			panic("Cannot find program: AT_PHDR not specified\n");
		if(!seen_phent)
			panic("Cannot find program: AT_PHENT not specified\n");
		if(!seen_phnum)
			panic("Cannot find program: AT_PHNUM not specified\n");

		ElfW(Phdr) *phdr;
		size_t phidx;

		for(phidx = 0, phdr = program->program_headers; phidx < program->num_ph; phidx++, phdr = PTR_ADVANCE_I(phdr, program->size_ph))
			if(phdr->p_type == PT_PHDR)
			{
				program->base_addr = (ElfW(Addr))program->program_headers - phdr->p_vaddr;
				break;
			}

		for(phidx = 0, phdr = program->program_headers; phidx < program->num_ph; phidx++, phdr = PTR_ADVANCE_I(phdr, program->size_ph))
			switch(phdr->p_type)
			{
				case PT_DYNAMIC:
					program->dynamic = (ElfW(Dyn) *)(phdr->p_vaddr + program->base_addr);
					break;

				case PT_INTERP:
					dlng->filename = strdup((char const *)(phdr->p_vaddr + program->base_addr));
					dlng->name = strdup((char const *)(phdr->p_vaddr + program->base_addr));
					debug_update(dlng);

				default:
					break;
			}

		ElfW(Dyn) *de;
		for(de = program->dynamic; de->d_tag != DT_NULL; de++)
			if(de->d_tag == DT_DEBUG)
				de->d_un.d_ptr = (intptr_t)&local_debug;

		process_dynamic(program);
	}


	module *mod;
	for(mod = dynamic_ns->first_mod; mod; mod = mod->next)
		if(mod->init)
		{
			dumpf("Calling init for %s\n", mod->name);
			mod->init(argc, argv, envp);
		}

	dump_mods();

	size_t symidx;
	ElfW(Sym) *sym;
	for(mod = dynamic_ns->first_mod; mod; mod = mod->next)
		for(symidx = 0, sym = mod->symtab; symidx < mod->num_st; symidx++, sym = PTR_ADVANCE_I(sym, mod->size_st))
			if(!strcmp("_dl_open_hook", &mod->strtab[sym->st_name]))
			{
				struct rtld_hook **hook_ptr = (struct rtld_hook **)(sym->st_value + mod->base_addr);
				*hook_ptr = &dlng_rtld;
				break;
			}

	dumpf("Transferring control to the program\n");
	start_program(stack, (void(*)())entry);
	exit(0);
}
