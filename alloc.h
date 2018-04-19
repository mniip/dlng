#ifndef ALLOC_H
#define ALLOC_H

#include <stdint.h>
#include <stddef.h>

extern void *mmap_malloc(size_t);
extern void mmap_free(void *);
extern void *mmap_realloc(void *, size_t);
extern size_t mmap_usable_size(void *);

#endif
