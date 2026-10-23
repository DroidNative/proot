/*
 * mprotect(PROT_EXEC) of written pages of a private file mapping, as Wine
 * does with relocated PE files. Android refuses it (SELinux execmod), a
 * noexec mount on the PC too; PRoot redoes it on an anonymous copy
 * (extension/dn_storage/exec.c). Writes a function into the first page and
 * a marker into the second, then runs the function.
 *
 * Usage: mprotect-exec <file of at least two pages>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(__i386__)
static const unsigned char code[] = { 0xb8, 0x2a, 0, 0, 0, 0xc3 };	// mov eax, 42; ret
#elif defined(__aarch64__)
static const unsigned char code[] = { 0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6 };	// mov w0, #42; ret
#else
#error "no test code for this architecture"
#endif

int main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	int fd = open(argv[1], O_RDONLY);
	char *p;

	if (argc != 2 || fd < 0) {
		perror("open");
		return 2;
	}
	p = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		perror("mmap");
		return 2;
	}
	memcpy(p, code, sizeof(code));
	strcpy(p + page, "marker");
	if (mprotect(p, 2 * page, PROT_READ | PROT_EXEC) != 0) {
		printf("mprotect: %s\n", strerror(errno));
		return 1;
	}
	__builtin___clear_cache(p, p + sizeof(code));
	printf("result %d %s\n", ((int (*)(void)) p)(), p + page);
	return 0;
}
