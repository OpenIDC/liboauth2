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

#pragma once
#include <io.h>
#include <sys/types.h>
#include <windows.h>

#define PROT_READ 0x1
#define PROT_WRITE 0x2
/* This flag is only available in WinXP+ */
#ifdef FILE_MAP_EXECUTE
#define PROT_EXEC 0x4
#else
#define PROT_EXEC 0x0
#define FILE_MAP_EXECUTE 0
#endif

#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FAILED ((void *)-1)

#ifdef __USE_FILE_OFFSET64
#define DWORD_HI(x) (x >> 32)
#define DWORD_LO(x) ((x)&0xffffffff)
#else
#define DWORD_HI(x) (0)
#define DWORD_LO(x) (x)
#endif

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
 		   off_t offset);

int munmap(void *addr, size_t length);
