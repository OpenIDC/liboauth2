/* mmap() replacement for Windows
 *
 * Author: Mike Frysinger <vapier@gentoo.org>
 * Placed into the public domain
 */

/* References:
 * CreateFileMapping:
 * http://msdn.microsoft.com/en-us/library/aa366537(VS.85).aspx CloseHandle:
 * http://msdn.microsoft.com/en-us/library/ms724211(VS.85).aspx MapViewOfFile:
 * http://msdn.microsoft.com/en-us/library/aa366761(VS.85).aspx UnmapViewOfFile:
 * http://msdn.microsoft.com/en-us/library/aa366882(VS.85).aspx
 */

#include "mmap-windows.h"

typedef struct temp_handle
{
	HANDLE h;
	void* mem_handle;
} temp_handle;

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
 		   off_t offset)
{

	temp_handle *x = malloc(sizeof(temp_handle));

	if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC))
		return MAP_FAILED;
	if (fd == -1) {
		if (!(flags & MAP_ANON) || offset)
			return MAP_FAILED;
	} else if (flags & MAP_ANON)
		return MAP_FAILED;

	DWORD flProtect;
	if (prot & PROT_WRITE) {
		if (prot & PROT_EXEC)
			flProtect = PAGE_EXECUTE_READWRITE;
		else
			flProtect = PAGE_READWRITE;
	} else if (prot & PROT_EXEC) {
		if (prot & PROT_READ)
			flProtect = PAGE_EXECUTE_READ;
		else if (prot & PROT_EXEC)
			flProtect = PAGE_EXECUTE;
	} else
		flProtect = PAGE_READONLY;

	off_t end = length + offset;
	HANDLE mmap_fd;
	if (fd == -1)
		mmap_fd = INVALID_HANDLE_VALUE;
	else
		mmap_fd = (HANDLE)_get_osfhandle(fd);

	x->h = CreateFileMapping(mmap_fd, NULL, flProtect, DWORD_HI(end),
							 DWORD_LO(end), NULL);
	if (x->h == NULL)
		return MAP_FAILED;

	DWORD dwDesiredAccess;
	if (prot & PROT_WRITE)
		dwDesiredAccess = FILE_MAP_WRITE;
	else
		dwDesiredAccess = FILE_MAP_READ;
	if (prot & PROT_EXEC)
		dwDesiredAccess |= FILE_MAP_EXECUTE;
	if (flags & MAP_PRIVATE)
		dwDesiredAccess |= FILE_MAP_COPY;
	x->mem_handle = MapViewOfFile(x->h, dwDesiredAccess, DWORD_HI(offset),
				                  DWORD_LO(offset), length);
	if (x->mem_handle == NULL) {
		CloseHandle(x->h);
		free(x);
		return MAP_FAILED;
	}
	return x;
}

int munmap(void *addr, size_t length)
{
	temp_handle* x = (temp_handle*)addr;
	UnmapViewOfFile(x->mem_handle);
	CloseHandle(x->h);
	free(x);
	
	return 0;
}
