#ifndef TLS_H
#define ALLOC_H

#include <stddef.h>

extern void init_tls(void);
extern size_t static_tls_allocate(size_t);
extern void *__tls_get_addr(size_t *);

inline void *get_tls(void)
{
	void *ptr;
	asm volatile("mov %%fs:0, %0" : "=r"(ptr));
	return ptr;
}

#endif
