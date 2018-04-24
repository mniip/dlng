#include <linux/fcntl.h>
#include <linux/mman.h>
#include <linux/fs.h>

#include "syscalls.h"
#include "debug.h"
#include "elf.h"
#include "alloc.h"
#include "util.h"
#include "modules.h"
#include "tls.h"
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

	return base - min;
}

void load_segments(int fd, module *mod)
{
	ElfW(Phdr) *phdr;
	size_t phidx;
	for(phidx = 0, phdr = mod->program_headers; phidx < mod->num_ph; phidx++, phdr = PTR_ADVANCE_I(phdr, mod->size_ph))
		if(phdr->p_type == PT_LOAD && phdr->p_memsz)
		{
			void *start = (void *)PAGE_START(mod->base_addr + phdr->p_vaddr);
			void *bss = (void *)(mod->base_addr + phdr->p_vaddr + phdr->p_filesz);
			void *fend = (void *)PAGE_PAD(bss);
			void *mend = (void *)PAGE_PAD(mod->base_addr + phdr->p_vaddr + phdr->p_memsz);
			size_t offt = PAGE_START(phdr->p_offset);

			int prot = PROT_NONE;
			if(phdr->p_flags & PF_R)
				prot |= PROT_READ;
			if(phdr->p_flags & PF_W)
				prot |= PROT_WRITE;
			if(phdr->p_flags & PF_X)
				prot |= PROT_EXEC;

			void *mapping = mmap(start, fend - start, prot, MAP_FIXED | MAP_PRIVATE, fd, offt);
			if(MAP_BAD(mapping))
				panic("Could not map header\n");
			if(fend != bss)
			{
				if(!(prot & PROT_WRITE))
					mprotect((void *)PAGE_START(bss), PAGE_SIZE, prot | PROT_WRITE);
				memset(bss, 0, fend - bss);
				if(!(prot & PROT_WRITE))
					mprotect((void *)PAGE_START(bss), PAGE_SIZE, prot);
			}
			if(fend != mend)
			{
				void *bss_rest = mmap(fend, mend - fend, prot, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				if(MAP_BAD(bss_rest))
					panic("Could not map header's bss\n");
			}
		}
		else if(phdr->p_type == PT_TLS && phdr->p_memsz)
		{
			mod->tls_offset = static_tls_allocate(phdr->p_memsz);
			mod->tls_tdata = phdr->p_vaddr;
			mod->tls_tdata_size = phdr->p_filesz;
		}
}

void load_tls(module *mod)
{
	if(mod->tls_tdata_size)
		memcpy(get_tls() + mod->tls_offset, (void *)(mod->base_addr + mod->tls_tdata), mod->tls_tdata_size);
}

module *load_fd(int fd, char const *filename, char const *name)
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

	module *mod = create_module(name);
	mod->filename = strdup(filename);

	void *base_addr = header.e_type == ET_EXEC ? 0 : base_addr_random(phdrs, header.e_phnum, header.e_phentsize);

	mod->entry = (ElfW(Addr))base_addr + header.e_entry;
	mod->base_addr = (ElfW(Addr))base_addr;
	mod->program_headers = phdrs;
	mod->ph_mapped = 0;
	mod->num_ph = header.e_phnum;
	mod->size_ph = header.e_phentsize;
	mod->ver_sym = NULL;
	mod->num_ver_defs = 0;
	mod->ver_defs = 0;
	mod->tls_offset = 0;
	mod->tls_tdata = 0;
	mod->tls_tdata_size = 0;

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

module *load_soname(char const *name)
{
	if(strchr(name, '/'))
	{
		int fd = open(name, O_RDONLY, 0);
		if(fd >= 0)
			return load_fd(fd, name, name);
	}

	char const *usrlib = "/usr/lib/";
	char *newname = mmap_malloc(strlen(usrlib) + strlen(name) + 1);
	memcpy(newname, usrlib, strlen(usrlib));
	memcpy(newname + strlen(usrlib), name, strlen(name) + 1);

	int fd = open(newname, O_RDONLY, 0);
	module *mod = NULL;
	if(fd >= 0)
		mod = load_fd(fd, newname, name);
	mmap_free(newname);
	return mod;
}

intptr_t symbol_value_extra(module *mod, size_t symbol, size_t ver_hash, size_t *size, module **contains)
{
	char const *name = &mod->strtab[mod->symtab[symbol].st_name];
	dumpf("Resolving %s (%p)\n", name, ver_hash);

	if(!strcmp(name, "__tls_get_addr"))
		return (intptr_t)&__tls_get_addr;

	int found_weak = 0;
	size_t size_weak;
	module *contains_weak;
	int ifunc_weak;
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
							if(ver_hash != (size_t)-1 && other->ver_sym && other->num_ver_defs && (!(other->ver_sym[symidx] & 0x8000) || other == mod))
							{
								size_t found_ver = -1;
								ElfW(Verdef) *def;
								size_t defidx;
								for(def = other->ver_defs, defidx = 0; defidx < other->num_ver_defs; def = PTR_ADVANCE_I(def, def->vd_next), defidx++)
									if(def->vd_ndx == (other->ver_sym[symidx] & ~0x8000))
									{
										found_ver = def->vd_hash;
										break;
									}
								if(found_ver != -1 && found_ver != ver_hash)
									continue;
							}

							dumpf("Found in %s\n", other->name);
							if(size)
								*size = sym->st_size;
							if(contains)
								*contains = other;
							if(ELFW(ST_TYPE(sym->st_info)) == STT_LOOS)
								return ((intptr_t (*)(void))sym->st_value + other->base_addr)();
							return sym->st_value + (ELFW(ST_TYPE(sym->st_info)) == STT_TLS ? 0 : other->base_addr);
						}
					}
					else if(bind == STB_WEAK)
					{
						if(!strcmp(name, &other->strtab[sym->st_name]))
						{
							if(ver_hash != (size_t)-1 && other->ver_sym && other->num_ver_defs && (!(other->ver_sym[symidx] & 0x8000) || other == mod))
							{
								size_t found_ver = -1;
								ElfW(Verdef) *def;
								size_t defidx;
								for(def = other->ver_defs, defidx = 0; defidx < other->num_ver_defs; def = PTR_ADVANCE_I(def, def->vd_next), defidx++)
									if(def->vd_ndx == (other->ver_sym[symidx] & ~0x8000))
									{
										found_ver = def->vd_hash;
										break;
									}
								if(found_ver != -1 && found_ver != ver_hash)
									continue;
							}

							dumpf("Found (weak) in %s\n", other->name);
							size_weak = sym->st_size;
							contains_weak = other;
							weak = sym->st_value + (ELFW(ST_TYPE(sym->st_info)) == STT_TLS ? 0 : other->base_addr);
							ifunc_weak = ELFW(ST_TYPE(sym->st_info)) == STT_LOOS;
							found_weak = 1;
						}
					}
				}

	if(found_weak)
	{
		if(size)
			*size = size_weak;
		if(contains)
			*contains = contains_weak;
		if(ifunc_weak)
			return ((intptr_t (*)(void))weak)();
		return weak;
	}
	if(ELFW(ST_BIND(mod->symtab[symbol].st_info)) == STB_WEAK)
	{
		if(size)
			*size = 0;
		if(contains)
			*contains = NULL;
		dumpf("Zeroing weak symbol %s (%s)\n", name, mod->name);
		return 0;
	}
	panic("Could not find %s (%s)\n", name, mod->name);
}

intptr_t symbol_value(module *mod, size_t symbol, size_t ver_hash)
{
	return symbol_value_extra(mod, symbol, ver_hash, NULL, NULL);
}

void relocate(module *mod, int type, size_t symbol, void *offset, intptr_t addend, size_t ver_hash)
{
	void *loc = mod->base_addr + offset;
	switch(type)
	{
		case R_X86_64_64:
			*(uint64_t *)loc = symbol_value(mod, symbol, ver_hash) + addend;
			break;

		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT:
			*(intptr_t *)loc = symbol_value(mod, symbol, ver_hash);
			break;

		case R_X86_64_RELATIVE:
			*(intptr_t *)loc = mod->base_addr + addend;
			break;

		case R_X86_64_TPOFF64:
			if(symbol)
			{
				module *other;
				intptr_t value = symbol_value_extra(mod, symbol, ver_hash, NULL, &other);
				if(!other)
					other = mod;
				*(size_t *)loc = other->tls_offset + value + addend;
			}
			else
				*(size_t *)loc = mod->tls_offset + addend;
			break;

		case R_X86_64_IRELATIVE:
			*(intptr_t *)loc = ((intptr_t(*)())(mod->base_addr + addend))();
			break;

		case R_X86_64_COPY:
			{
				size_t size;
				intptr_t value = symbol_value_extra(mod, symbol, ver_hash, &size, NULL);
				memcpy(loc, (void *)value, size);
				dumpf("COPY %s %p <- %p + %x\n", &mod->strtab[mod->symtab[symbol].st_name], loc, value, size);
				break;
			}

		default:
			panic("Unknown reloc 0x%x\n", type);
			break;
	}
}

size_t lookup_versym_hash(module *mod, size_t symbol, size_t num_ver_needs, ElfW(Verneed) *ver_needs)
{
	ElfW(Verneed) *need;
	size_t needidx;
	for(need = ver_needs, needidx = 0; needidx < num_ver_needs; need = PTR_ADVANCE_I(need, need->vn_next), needidx++)
	{
		ElfW(Vernaux) *aux = (ElfW(Vernaux) *)PTR_ADVANCE_I(need, need->vn_aux);
		if(aux->vna_other == mod->ver_sym[symbol])
			return aux->vna_hash;
	}
	return (size_t)-1;
}

void process_rela(module *mod, ElfW(Rela) *rela, size_t rela_size, size_t rela_length, size_t num_ver_needs, ElfW(Verneed) *ver_needs)
{
	ElfW(Rela) *r;
	for(r = rela; r < PTR_ADVANCE_I(rela, rela_length); r = PTR_ADVANCE_I(r, rela_size))
	{
		size_t ver_hash = -1;
		if(ELFW(R_SYM(r->r_info)))
			ver_hash = lookup_versym_hash(mod, ELFW(R_SYM(r->r_info)), num_ver_needs, ver_needs);

		relocate(mod, ELFW(R_TYPE(r->r_info)), ELFW(R_SYM(r->r_info)), (void *)r->r_offset, r->r_addend, ver_hash);
	}
}

void process_rel(module *mod, ElfW(Rel) *rel, size_t rel_size, size_t rel_length, size_t num_ver_needs, ElfW(Verneed) *ver_needs)
{
	ElfW(Rel) *r;
	for(r = rel; r < PTR_ADVANCE_I(rel, rel_length); r = PTR_ADVANCE_I(r, rel_size))
	{
		size_t ver_hash = -1;
		if(ELFW(R_SYM(r->r_info)))
			ver_hash = lookup_versym_hash(mod, ELFW(R_SYM(r->r_info)), num_ver_needs, ver_needs);

		relocate(mod, ELFW(R_TYPE(r->r_info)), ELFW(R_SYM(r->r_info)), (void *)r->r_offset, 0, ver_hash);
	}
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

	size_t num_ver_needs = 0;
	ElfW(Verneed) *ver_needs = NULL;

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
			case DT_VERDEFNUM: mod->num_ver_defs = de->d_un.d_val; break;
			case DT_VERDEF: mod->ver_defs = (void *)(de->d_un.d_ptr + mod->base_addr); break;
			case DT_VERSYM: mod->ver_sym = (void *)(de->d_un.d_ptr + mod->base_addr); break;
			case DT_VERNEEDNUM: num_ver_needs = de->d_un.d_val; break;
			case DT_VERNEED: ver_needs = (void *)(de->d_un.d_ptr + mod->base_addr); break;
			default:
				break;
		}

	if(!seen_hash)
		guess_symtab_size(mod);

	for(de = mod->dynamic; de->d_tag != DT_NULL; de++)
		switch(de->d_tag)
		{
			case DT_NEEDED:
			{
				char const *needed = &mod->strtab[de->d_un.d_val];
				int found = 0;
				mod_ns *ns;
				module *other;
				for(ns = mod->parent_ns; ns; ns = ns->parent)
				{
					for(other = ns->first_mod; other; other = other->next)
						if(!strcmp(needed, other->name))
						{
							found = 1;
							break;
						}
					if(found)
						break;
				}
				if(!found)
					load_soname(needed);
				break;
			}

			default:
				break;
		}

	if(seen_rela)
		process_rela(mod, rela, rela_size, rela_length, num_ver_needs, ver_needs);
	if(seen_rel)
		process_rel(mod, rel, rel_size, rel_length, num_ver_needs, ver_needs);
	if(seen_pltrel)
	{
		if(pltrel_type == DT_RELA)
			process_rela(mod, (ElfW(Rela) *)pltrel, rela_size, pltrel_length, num_ver_needs, ver_needs);
		else if(pltrel_type == DT_REL)
			process_rel(mod, (ElfW(Rel) *)pltrel, rel_size, pltrel_length, num_ver_needs, ver_needs);
	}

	debug_add(mod);
	load_tls(mod);
	if(mod->init)
	{
		dumpf("Calling init for %s\n", mod->name);
		mod->init(global_argc, global_argv, global_envp);
	}
}
