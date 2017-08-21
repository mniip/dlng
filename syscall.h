#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>

#define syscall_JOIN(x, y) x ## y
#define syscall_ISTRUE_TRUE TRUE
#define syscall_ISTRUE_ FALSE
#define syscall_ISTRUE(x, ...) syscall_JOIN(syscall_ISTRUE_, x)
#define syscall_ISEMPTY_(...) syscall_ISTRUE(, ## __VA_ARGS__ TRUE)
#define syscall_ISEMPTY(...) syscall_ISEMPTY_(__VA_ARGS__)
#define syscall_IF(c) syscall_JOIN(syscall_IF_, c)
#define syscall_IF_TRUE(x, y) x
#define syscall_IF_FALSE(x, y) y

#define syscall(sysnum, ...) syscall_IF(syscall_ISEMPTY(__VA_ARGS__)) (syscall0r(sysnum), syscall_(sysnum, __VA_ARGS__))
#define syscall_(sysnum, arg1, ...) syscall_IF(syscall_ISEMPTY(__VA_ARGS__)) (syscall1r((intptr_t)arg1, sysnum), syscall__(sysnum, arg1, __VA_ARGS__))
#define syscall__(sysnum, arg1, arg2, ...) syscall_IF(syscall_ISEMPTY(__VA_ARGS__)) (syscall2r((intptr_t)arg1, (intptr_t)arg2, sysnum), syscall___(sysnum, arg1, arg2, __VA_ARGS__))
#define syscall___(sysnum, arg1, arg2, arg3, ...) syscall_IF(syscall_ISEMPTY(__VA_ARGS__)) (syscall3r((intptr_t)arg1, (intptr_t)arg2, (intptr_t)arg3, sysnum), syscall____(sysnum, arg1, arg2, arg3, __VA_ARGS__))
#define syscall____(sysnum, arg1, arg2, arg3, arg4, ...) syscall_IF(syscall_ISEMPTY(__VA_ARGS__)) (syscall4r((intptr_t)arg1, (intptr_t)arg2, (intptr_t)arg3, (intptr_t)arg4, sysnum), syscall_____(sysnum, arg1, arg2, arg3, arg4, __VA_ARGS__))
#define syscall_____(sysnum, arg1, arg2, arg3, arg4, arg5, ...) syscall_IF(syscall_ISEMPTY(__VA_ARGS__)) (syscall5r((intptr_t)arg1, (intptr_t)arg2, (intptr_t)arg3, (intptr_t)arg4, (intptr_t)arg5, sysnum), syscall6r((intptr_t)arg1, (intptr_t)arg2, (intptr_t)arg3, (intptr_t)arg4, (intptr_t)arg5, (intptr_t)__VA_ARGS__, sysnum))

extern intptr_t syscall6r(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
extern intptr_t syscall5r(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
extern intptr_t syscall4r(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
extern intptr_t syscall3r(intptr_t, intptr_t, intptr_t, intptr_t);
extern intptr_t syscall2r(intptr_t, intptr_t, intptr_t);
extern intptr_t syscall1r(intptr_t, intptr_t);
extern intptr_t syscall0r(intptr_t);

#endif
