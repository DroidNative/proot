/* Installs its own seccomp filter that traps getppid with SECCOMP_RET_TRAP
 * and handler data 7 (as Chromium style sandboxes do) and answers it in its
 * SIGSYS handler. Prints "result 4242 data 7" when the signal reached the
 * handler.
 *
 * "nested": the filter also traps getpid with data 0, like Android's app
 * filter, and the handler calls getpid. That trap hits with SIGSYS blocked,
 * so the kernel resets the handler; PRoot answers it and must reinstall
 * the handler, else the second getppid kills the program. Only meaningful
 * under PRoot (natively nobody answers the getpid trap). */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static volatile int seen_data = -1;
static int nested;

static void on_sigsys(int sig, siginfo_t *info, void *ctx)
{
	ucontext_t *uc = ctx;
	(void) sig;
	seen_data = info->si_errno;
	if (nested)
		syscall(__NR_getpid);
#if defined(__x86_64__)
	uc->uc_mcontext.gregs[REG_RAX] = 4242;
#elif defined(__aarch64__)
	uc->uc_mcontext.regs[0] = 4242;
#elif defined(__arm__)
	uc->uc_mcontext.arm_r0 = 4242;
#elif defined(__i386__)
	uc->uc_mcontext.gregs[REG_EAX] = 4242;
#endif
}

int main(int argc, char **argv)
{
	struct sock_filter code[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | 7),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { sizeof(code) / sizeof(code[0]), code };
	struct sigaction sa;

	nested = argc > 1 && strcmp(argv[1], "nested") == 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = on_sigsys;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSYS, &sa, NULL);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
	    || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
		printf("filter: %s\n", strerror(errno));
		return 1;
	}
	long r = syscall(__NR_getppid);
	if (nested) {
		seen_data = -1;
		r = syscall(__NR_getppid);   // killed here if the handler is gone
	}
	printf("result %ld data %d\n", r, seen_data);
	return 0;
}
