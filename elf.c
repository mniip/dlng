#include <linux/fcntl.h>
#include <linux/mman.h>
#include <linux/fs.h>

#include "syscalls.h"
#include "debug.h"
#include "elf.h"
#include "alloc.h"
#include "util.h"
#include "modules.h"
#include "dump.h"

void *base_addr_random(ElfW(Phdr) *phdrs, size_t num_ph, size_t size_ph)
{
	ElfW(Addr) min = -1;
	ElfW(Addr) max = 0;

	ElfW(Phdr) *phdr;
	size_t phidx;
	int seen = 0;
	for(phidx = 0, phdr = phdrs; phidx < num_ph; phidx++, phdr = PTR_ADVANCE_I(phdr, size_ph))
		if(phdr->p_type == PT_LOAD && phdr->p_memsz)
		{
			seen = 1;
			if(phdr->p_vaddr < min)
				min = PAGE_START(phdr->p_vaddr);
			if(phdr->p_vaddr + phdr->p_memsz > max)
				max = PAGE_PAD(phdr->p_vaddr + phdr->p_memsz);
		}

	if(!seen)
		panic("No load headers\n");

	void *base = mmap(NULL, max - min, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if(MAP_BAD(base))
		panic("Could not find region\n");
	munmap(base, max - min);

	return base;
}

void load_segments(int fd, module *mod)
{
	ElfW(Phdr) *phdr;
	size_t phidx;
	for(phidx = 0, phdr = mod->program_headers; phidx < mod->num_ph; phidx++, phdr = PTR_ADVANCE_I(phdr, mod->size_ph))
		if(phdr->p_type == PT_LOAD && phdr->p_memsz)
		{
			void *start = (void *)PAGE_START(mod->base_addr + phdr->p_vaddr);
			void *fend = (void *)PAGE_PAD(mod->base_addr + phdr->p_vaddr + phdr->p_filesz);
			void *mend = (void *)PAGE_PAD(mod->base_addr + phdr->p_vaddr + phdr->p_memsz);
			size_t offt = PAGE_START(phdr->p_offset);

			int prot = PROT_NONE;
			if(phdr->p_flags & PF_R)
				prot |= PROT_READ;
			if(phdr->p_flags & PF_W)
				prot |= PROT_WRITE;
			if(phdr->p_flags & PF_X)
				prot |= PROT_EXEC;

			void *mapping = mmap(start, fend - start, prot, MAP_PRIVATE, fd, offt);
			if(MAP_BAD(mapping))
				panic("Could not map header\n");
			if(fend != mend)
			{
				void *bss = mmap(fend, mend - fend, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				if(MAP_BAD(bss))
					panic("Could not map header's bss\n");
			}
		}
}

module *load_fd(int fd, char const *name)
{
	dumpf("Loading file %s\n", name);

	ElfW(Ehdr) header;
	if(lseek(fd, 0, SEEK_SET) < 0)
		panic("Could not seek\n");
	read_all(fd, &header, sizeof header);

	if(header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 || header.e_ident[EI_MAG2] != ELFMAG2 || header.e_ident[EI_MAG3] != ELFMAG3)
		panic("Invalid ELF signature\n");
	if(header.e_ident[EI_CLASS] != ELFW_CLASS)
		panic("Invalid ELFCLASS\n");
	if(header.e_ident[EI_DATA] != ELFDATA2LSB)
		panic("Invalid ELF data encoding\n");
	if(header.e_ident[EI_VERSION] != EV_CURRENT)
		panic("Invalid ELF version\n");

	if(lseek(fd, header.e_phoff, SEEK_SET) < 0)
		panic("Could not seek\n");
	ElfW(Phdr) *phdrs = mmap_malloc(header.e_phnum * header.e_phentsize);
	read_all(fd, phdrs, header.e_phnum * header.e_phentsize);

	void *base_addr = base_addr_random(phdrs, header.e_phnum, header.e_phentsize);

	module *mod = create_module(name);
	mod->filename = strdup(name);
	mod->base_addr = (ElfW(Addr))base_addr;
	mod->program_headers = phdrs;
	mod->ph_mapped = 0;
	mod->num_ph = header.e_phnum;
	mod->size_ph = header.e_phentsize;

	load_segments(fd, mod);

	ns_add_module(dynamic_ns, mod);
	
	ElfW(Phdr) *phdr;
	size_t phidx;
	for(phidx = 0, phdr = phdrs; phidx < header.e_phnum; phidx++, phdr = PTR_ADVANCE_I(phdr, header.e_phentsize))
		if(phdr->p_type == PT_DYNAMIC)
			mod->dynamic = (ElfW(Dyn) *)(phdr->p_vaddr + mod->base_addr);

	process_dynamic(mod);

	return mod;
}

void load_soname(char const *name)
{
	if(strchr(name, '/'))
	{
		int fd = open(name, O_RDONLY, 0);
		if(fd >= 0)
		{
			load_fd(fd, name);
			return;
		}
	}

	char const *usrlib = "/usr/lib/";
	char *newname = mmap_malloc(strlen(usrlib) + strlen(name) + 1);
	memcpy(newname, usrlib, strlen(usrlib));
	memcpy(newname + strlen(usrlib), name, strlen(name) + 1);

	int fd = open(newname, O_RDONLY, 0);
	if(fd >= 0)
		load_fd(fd, newname);
	mmap_free(newname);
}

intptr_t symbol_value(module *mod, size_t symbol)
{
	char const *name = &mod->strtab[mod->symtab[symbol].st_name];
	dumpf("Resolving %s\n", name);

	int found_weak = 0;
	intptr_t weak;

	mod_ns *ns;
	module *other;
	ElfW(Sym) *sym;
	size_t symidx;
	for(ns = mod->parent_ns; ns; ns = ns->parent)
		for(other = ns->first_mod; other; other = other->next)
			for(symidx = 0, sym = other->symtab; symidx < other->num_st; symidx++, sym = PTR_ADVANCE_I(sym, other->size_st))
				if(sym->st_shndx != STN_UNDEF)
				{
					unsigned bind = ELFW(ST_BIND(sym->st_info)); 
					if(bind == STB_GLOBAL || (bind == STB_LOCAL && other == mod))
					{
						if(!strcmp(name, &other->strtab[sym->st_name]))
						{
							dumpf("Found in %s\n", other->name);
							return sym->st_value + other->base_addr;
						}
					}
					else if(bind == STB_WEAK)
					{
						if(!strcmp(name, &other->strtab[sym->st_name]))
						{
							dumpf("Found (weak) in %s\n", other->name);
							weak = sym->st_value + other->base_addr;
							found_weak = 1;
						}
					}
				}

	if(found_weak)
		return weak;
	if(ELFW(ST_BIND(mod->symtab[symbol].st_info)) == STB_WEAK)
		return 0;
	panic("Could not find %s (%s)\n", name, mod->name);
}

void *get_tls()
{
	void *val;
	asm ("movq %%fs:0, %0" : "=r"(val));
	return val;
}

void relocate(module *mod, int type, size_t symbol, void *offset, intptr_t addend)
{
	void *loc = mod->base_addr + offset;
	switch(type)
	{
		case R_X86_64_64:
			*(uint64_t *)loc = symbol_value(mod, symbol) + addend;
			break;

		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT:
			*(intptr_t *)loc = symbol_value(mod, symbol);
			break;

		case R_X86_64_RELATIVE:
			*(intptr_t *)loc = mod->base_addr + addend;
			break;

		case R_X86_64_TPOFF64:
			*(intptr_t *)loc = (symbol ? symbol_value(mod, symbol) : 0) + addend - (intptr_t)get_tls();
			break;

		case R_X86_64_IRELATIVE:
			*(intptr_t *)loc = ((intptr_t(*)())(mod->base_addr + addend))();
			break;

		default:
			panic("Unknown reloc 0x%x\n", type);
			break;
	}
}

void process_rela(module *mod, ElfW(Rela) *rela, size_t rela_size, size_t rela_length)
{
	ElfW(Rela) *r;
	for(r = rela; r < PTR_ADVANCE_I(rela, rela_length); r = PTR_ADVANCE_I(r, rela_size))
		relocate(mod, ELFW(R_TYPE(r->r_info)), ELFW(R_SYM(r->r_info)), (void *)r->r_offset, r->r_addend);
}

void process_rel(module *mod, ElfW(Rel) *rel, size_t rel_size, size_t rel_length)
{
	ElfW(Rel) *r;
	for(r = rel; r < PTR_ADVANCE_I(rel, rel_length); r = PTR_ADVANCE_I(r, rel_size))
		relocate(mod, ELFW(R_TYPE(r->r_info)), ELFW(R_SYM(r->r_info)), (void *)r->r_offset, 0);
}

void guess_symtab_size(module *mod)
{
	ElfW(Addr) max = -1;
	uintptr_t symtab_off = (uintptr_t)mod->symtab - mod->base_addr;

	ElfW(Dyn) *de;
	for(de = mod->dynamic; de->d_tag != DT_NULL; de++)
		switch(de->d_tag)
		{
			case DT_PLTGOT: case DT_HASH: case DT_STRTAB: case DT_RELA: case DT_INIT: case DT_FINI: case DT_REL: case DT_JMPREL:
				if(de->d_un.d_ptr < max)
					if(de->d_un.d_ptr > symtab_off)
						max = de->d_un.d_ptr;
				break;

			default:
				break;
		}

	size_t phidx;
	ElfW(Phdr) *phdr;
	for(phidx = 0, phdr = mod->program_headers; phidx < mod->num_ph; phidx++, phdr = PTR_ADVANCE_I(phdr, mod->size_ph))
		if(phdr->p_type == PT_LOAD)
			if(phdr->p_vaddr <= symtab_off && phdr->p_vaddr + phdr->p_memsz >= symtab_off)
				if(phdr->p_vaddr + phdr->p_memsz < max)
					max = phdr->p_vaddr + phdr->p_memsz;

	mod->num_st = (max - symtab_off) / mod->size_st;

	dumpf("Guessed symtab size for %s: %d\n", mod->name, mod->num_st);
}

void process_dynamic(module *mod)
{
	if(!mod->dynamic)
		return;

	ElfW(Rela) *rela = NULL;
	size_t rela_size = sizeof(ElfW(Rela));
	size_t rela_length = 0;
	int seen_rela = 0;
	
	ElfW(Rel) *rel = NULL;
	size_t rel_size = sizeof(ElfW(Rel));
	size_t rel_length = 0;
	int seen_rel = 0;
	
	void *pltrel = NULL;
	ElfW(Sword) pltrel_type = DT_NULL;
	size_t pltrel_length = 0;
	int seen_pltrel = 0;

	int seen_hash = 0;

	ElfW(Dyn) *de;
	for(de = mod->dynamic; de->d_tag != DT_NULL; de++)
		switch(de->d_tag)
		{
			case DT_STRTAB: mod->strtab = (void *)(de->d_un.d_ptr + mod->base_addr); break;
			case DT_SYMTAB: mod->symtab = (void *)(de->d_un.d_ptr + mod->base_addr); break;
			case DT_SYMENT: mod->size_st = de->d_un.d_val; break;
			case DT_HASH: mod->num_st = ((ElfW(Word) *)(de->d_un.d_ptr + mod->base_addr))[1]; seen_hash = 1; break;
			case DT_RELA: rela = (void *)(de->d_un.d_ptr + mod->base_addr); seen_rela = 1; break;
			case DT_RELAENT: rela_size = de->d_un.d_val; break;
			case DT_RELASZ: rela_length = de->d_un.d_val; break;
			case DT_REL: rel = (void *)(de->d_un.d_ptr + mod->base_addr); seen_rel = 1; break;
			case DT_RELENT: rel_size = de->d_un.d_val; break;
			case DT_RELSZ: rel_length = de->d_un.d_val; break;
			case DT_JMPREL: pltrel = (void *)(de->d_un.d_ptr + mod->base_addr); seen_pltrel = 1; break;
			case DT_PLTREL: pltrel_type = de->d_un.d_val; break;
			case DT_PLTRELSZ: pltrel_length = de->d_un.d_val; break;
			case DT_INIT: mod->init = (void(*)())(de->d_un.d_ptr + mod->base_addr); break;
			case DT_FINI: mod->fini = (void(*)())(de->d_un.d_ptr + mod->base_addr); break;

			default:
				break;
		}

	if(!seen_hash)
		guess_symtab_size(mod);

	for(de = mod->dynamic; de->d_tag != DT_NULL; de++)
		switch(de->d_tag)
		{
			case DT_NEEDED:
				load_soname(&mod->strtab[de->d_un.d_val]);
				break;

			default:
				break;
		}

	if(seen_rela)
		process_rela(mod, rela, rela_size, rela_length);
	if(seen_rel)
		process_rel(mod, rel, rel_size, rel_length);
	if(seen_pltrel)
	{
		if(pltrel_type == DT_RELA)
			process_rela(mod, (ElfW(Rela) *)pltrel, rela_size, pltrel_length);
		else if(pltrel_type == DT_REL)
			process_rel(mod, (ElfW(Rel) *)pltrel, rel_size, pltrel_length);
	}

	debug_add(mod);
}
