#ifndef UTIL_H
#define UTIL_H

#include <sys/user.h>

#define PAGE_START(x) (((intptr_t)x)&PAGE_MASK)
#define PAGE_PAD(x) ((((intptr_t)x)|~PAGE_MASK)+1)

#define MAP_BAD(x) (((void *)x) > (void *)-4096)

#define PTR_ADVANCE_N(p, t, n) ((typeof(p))((t *)(p) + (n)))
#define PTR_ADVANCE_I(p, n) PTR_ADVANCE_N(p, void, n)
#define PTR_ADVANCE(p, t) PTR_ADVANCE_N(p, t, 1)

#endif
