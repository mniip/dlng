#ifndef UTIL_H
#define UTIL_H

#define PTR_ADVANCE_N(p, t, n) ((typeof(p))((t *)(p) + (n)))
#define PTR_ADVANCE_I(p, n) PTR_ADVANCE_N(p, void, n)
#define PTR_ADVANCE(p, t) PTR_ADVANCE_N(p, t, 1)

#endif
