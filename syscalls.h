#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <stdint.h>
#include <stddef.h>

extern intptr_t read(int, void *, size_t);
extern intptr_t write(int, void const *, size_t);
extern int open(char const *, int, int);
extern size_t lseek(int, intptr_t, int);
extern void *mmap(void *, size_t, int, int, int, size_t);
extern int mprotect(void *, size_t, int);
extern int munmap(void *, size_t);
extern void *mremap(void *, size_t, size_t, int, void *);
extern intptr_t getpid(void);
extern void exit(int) __attribute__((noreturn));
extern int kill(intptr_t, int);
extern int arch_prctl(int, void *);

extern int read_all(int, void *, size_t);
extern int write_all(int, void const *, size_t);

#endif
