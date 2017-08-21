#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <linux/signal.h>

#include "syscalls.h"
#include "alloc.h"

size_t strlen(char const *str)
{
	size_t sz = 0;
	while(str[sz])
		sz++;
	return sz;
}

void *memcpy(void *dest, void const *src, size_t len)
{
	size_t i;
	for(i = 0; i < len; i++)
		((char *)dest)[i] = ((char const *)src)[i];
	return dest;
}

char *strdup(char const *str)
{
	size_t size = strlen(str) + 1;
	char *new = mmap_malloc(size);
	memcpy(new, str, size);
	return new;
}

static void dump_s(char const *str, size_t len)
{
	size_t wrote = 0;
	while(wrote < len)
	{
		intptr_t w = write(1, str + wrote, len - wrote);
		if(w > 0)
			wrote += w;
		else
			break;
	}
}

static void dump_sz(char const *str)
{
	dump_s(str, strlen(str));
}

static void dump_u(uintptr_t n)
{
	char str[40];
	int i;
	for(i = sizeof str - 1; i >= 0; i--)
	{
		str[i] = n % 10 + '0';
		n = n / 10;
	}
	char const *s = str;
	while(*s == '0' && s < &str[sizeof str - 1])
		s++;
	dump_s(s, &str[sizeof str] - s);
}

static void dump_d(intptr_t n)
{
	char str[40];
	int i;
	int negative = n < 0;
	for(i = sizeof str - 1; i >= 0; i--)
	{
		str[i] = negative ? '0' - n % 10 : n % 10 + '0';
		n = n / 10;
	}
	char const *s = str;
	while(*s == '0' && s < &str[sizeof str - 1])
		s++;
	if(negative)
		dump_sz("-");
	dump_s(s, &str[sizeof str] - s);
}

static void dump_h(uintptr_t n)
{
	static char hex[16] = "0123456789abcdef";
	char str[32];
	int i;
	for(i = sizeof str - 1; i >= 0; i--)
	{
		str[i] = hex[n % 16];
		n = n / 16;
	}
	char const *s = str;
	while(*s == '0' && s < &str[sizeof str - 1])
		s++;
	dump_s(s, &str[sizeof str] - s);
}

static void dump_p(void const *p)
{
	if(p)
		dump_sz("0x"), dump_h((uintptr_t)p);
	else
		dump_sz("(null)");
}

void vdumpf(char const *fmt, va_list list)
{
	char const *start = fmt;
	while(*fmt)
	{
		start = fmt;
		while(*fmt && *fmt != '%')
			fmt++;
		if(start != fmt)
			dump_s(start, fmt - start);
		if(*fmt == '%')
		{
			fmt++;
			switch(*(fmt++))
			{
				case 'd':
					dump_d(va_arg(list, intptr_t));
					break;
				case 'p':
					dump_p(va_arg(list, void const *));
					break;
				case 's':
					dump_sz(va_arg(list, char const *));
					break;
				case 'u':
					dump_u(va_arg(list, uintptr_t));
					break;
				case 'x':
					dump_h(va_arg(list, uintptr_t));
					break;
				default:
					break;
			}
		}
	}
}

void dumpf(char const *fmt, ...)
{
	va_list list;
	va_start(list, fmt);
	vdumpf(fmt, list);
	va_end(list);
}

void panic(char const *fmt, ...)
{
	va_list list;
	va_start(list, fmt);
	vdumpf(fmt, list);
	va_end(list);
	kill(getpid(), SIGABRT);
}
