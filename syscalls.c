#include <stdint.h>
#include <stddef.h>
#include <sys/syscall.h>

#include "syscall.h"
#include "syscalls.h"

intptr_t read(int fd, void *buf, size_t size)
{
	return syscall(__NR_read, fd, buf, size);
}

intptr_t write(int fd, void const *buf, size_t size)
{
	return syscall(__NR_write, fd, buf, size);
}

int open(char const *file, int flags, int mode)
{
	return syscall(__NR_open, file, flags, mode);
}

void *mmap(void *addr, size_t size, int prot, int flags, int fd, size_t offset)
{
	return (void *)syscall(__NR_mmap, addr, size, prot, flags, fd, offset);
}

int munmap(void *addr, size_t size)
{
	return syscall(__NR_munmap, addr, size);
}

void *mremap(void *addr, size_t size, size_t new_size, int flags, void *new_addr)
{
	return (void *)syscall(__NR_munmap, addr, size, new_size, flags, new_addr);
}

intptr_t getpid(void)
{
	return syscall(__NR_getpid);
}

void exit(int code)
{
	syscall(__NR_exit, code);
	__builtin_unreachable();
}

int kill(intptr_t pid, int signal)
{
	return syscall(__NR_kill, pid, signal); 
}

int arch_prctl(int code, void *addr)
{
	return syscall(__NR_arch_prctl, code, addr);
}

int read_all(int fd, void *buf, size_t size)
{
	size_t done = 0;
	while(done < size)
	{
		size_t ret = read(fd, buf + done, size);
		if(ret < 0)
			return ret;
		if(ret == 0)
			break;
		done += ret;
	}
	return done;
}

int write_all(int fd, void const *buf, size_t size)
{
	size_t done = 0;
	while(done < size)
	{
		size_t ret = write(fd, buf + done, size);
		if(ret < 0)
			return ret;
		if(ret == 0)
			break;
		done += ret;
	}
	return done;
}
