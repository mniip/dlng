#include <linux/mman.h>
#include <sys/user.h>

#include "dump.h"
#include "syscalls.h"

#define PAGE_PAD(x) (((x)|~PAGE_MASK)+1)

typedef struct alloc_header
{
	struct alloc_header *next, *prev;
	size_t size;
}
alloc_header;

alloc_header *first = NULL;

void *mmap_malloc(size_t size)
{
	size_t mapping_size = PAGE_PAD(size + sizeof(alloc_header));
	void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	
	if(mapping > (void*)-4096)
		return NULL;

	alloc_header *header = mapping;
	header->next = first;
	first = header;
	header->prev = NULL;
	header->size = mapping_size;
	return &header[1];
}

void mmap_free(void *mapping)
{
	alloc_header *header = mapping;
	header--;
	if(header->prev)
		header->prev->next = header->next;
	else
		first = header->next;
	if(header->next)
		header->next->prev = header->prev;

	munmap(header, header->size);
}

void *mmap_realloc(void *data, size_t size)
{
	alloc_header *header = data;
	header--;
	
	size_t mapping_size = PAGE_PAD(size + sizeof(alloc_header));
	if(mapping_size == header->size)
		return data;

	void *new = mremap(header, header->size + sizeof(alloc_header), size + sizeof(alloc_header), MREMAP_MAYMOVE, NULL);
	if(new < (void *)0 && new > (void*)-4096)
	{
		new = mmap_malloc(size);
		if(!new)
			return NULL;
		memcpy(new, data, header->size);
		mmap_free(data);
		return new;
	}
	
	if(header != new)
	{
		header = new;
		if(header->prev)
			header->prev->next = header;
		else
			first = header;
		if(header->next)
			header->next->prev = header;
	}

	header->size = size;
	return &header[1];
}
