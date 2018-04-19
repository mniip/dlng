#include <asm/prctl.h>

#include "alloc.h"
#include "syscalls.h"
#include "dump.h"

size_t tls_area_size;
size_t tls_offset;

void init_tls(void)
{
	void *tls_area = mmap_malloc(sizeof(void *));
	tls_area_size = mmap_usable_size(tls_area);
	tls_offset = tls_area_size - sizeof(void *);
	void **tls_self = (void **)(tls_area + tls_offset);
	*tls_self = tls_self;

	arch_prctl(ARCH_SET_FS, tls_self);
}

size_t static_tls_allocate(size_t size)
{
	if(tls_offset < size)
		panic("Could not allocate 0x%x bytes in TLS (off=0x%x, size=0x%x)\n", size, tls_offset, tls_area_size);

	tls_offset -= size;
	return tls_offset - tls_area_size + sizeof(void *);
}

void *__tls_get_addr(size_t *v)
{
	panic("__tls_get_addr(%p)\n", v);
}
