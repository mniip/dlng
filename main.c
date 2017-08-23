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
extern void start_program(void *, void (*)());

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

	ElfW(auxv_t) *auxvec = stk;
	
	dynamic_ns = create_namespace();

	module *dlng = create_module(NULL);
	dlng->base_addr = -1;
	dlng->program_headers = NULL;
	dlng->ph_mapped = 0;
	
	ns_add_module(dynamic_ns, dlng);

	module *program = create_module(argv[0]);
	program->filename = strdup(argv[0]);
	program->base_addr = 0;
	ns_add_module(dynamic_ns, program);
	
	ElfW(Addr) entry;
	int seen_entry = 0, seen_phdr = 0, seen_phnum = 0, seen_phent = 0;

	while(auxvec->a_type != AT_NULL)
	{
		switch(auxvec->a_type)
		{
			case AT_EXECFD:
				panic("AT_EXECFD not supported\n");

			case AT_NOTELF:
				if(auxvec->a_un.a_val)
					panic("AT_NOTELF not supported\n");
				break;
			
			case AT_PHDR:
				program->program_headers = (void *)auxvec->a_un.a_val;
				program->ph_mapped = 1;
				seen_phdr = 1;
				break;

			case AT_ENTRY:
				entry = auxvec->a_un.a_val;
				seen_entry = 1;
				break;

			case AT_PHENT:
				program->size_ph = auxvec->a_un.a_val;
				seen_phent = 1;

			case AT_PHNUM:
				program->num_ph = auxvec->a_un.a_val;
				seen_phnum = 1;

			case AT_BASE:
				dlng->base_addr = auxvec->a_un.a_val;

			default:
				break;
		}
		auxvec++;
	}

	if(!seen_entry)
		panic("Cannot find program: AT_ENTRY not specified\n");
	
	if((void *)entry == (void *)&_start)
		panic("Direct invocation not supported\n");
	
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

			default:
				break;
		}

	debug_init(dlng);
	ElfW(Dyn) *de;
	for(de = program->dynamic; de->d_tag != DT_NULL; de++)
		if(de->d_tag == DT_DEBUG)
			de->d_un.d_ptr = (intptr_t)&r_debug;
	debug_add(dlng);

	void **tls = mmap_malloc(sizeof(void *));
	tls[0] = tls;
	arch_prctl(ARCH_SET_FS, tls);

	process_dynamic(program);

	module *mod;
	for(mod = dynamic_ns->first_mod; mod; mod = mod->next)
		if(mod->init)
		{
			dumpf("Calling init for %s\n", mod->name);
			mod->init(argc, argv, envp);
		}

	dump_mods();

	dumpf("Transferring control to the program\n");
	start_program(stack, (void(*)())entry);
	
	exit(0);
}
