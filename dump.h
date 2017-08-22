#ifndef DUMP_H
#define DUMP_H

#include <stddef.h>
#include <stdarg.h>

extern void *memcpy(void *, void const *, size_t);
extern size_t strlen(char const *);
extern char *strdup(char const *);
extern char *strchr(char const *, int);
extern int strcmp(char const *, char const *);
extern void vdumpf(char const *, va_list);
extern void dumpf(char const *, ...);
extern void panic(char const *, ...) __attribute__((noreturn));

#endif
