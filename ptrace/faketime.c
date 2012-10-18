// original: http://blog.youxu.info/2007/12/01/how-to-give-a-program-fake-system-time-so-that-you-can-use-it-forever-linux/
//
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

int main(int argc, char *argv[]) {
	int pid;
	int status;
	int insyscall = 0;
	struct user_regs_struct regs;

	pid = fork();
	if (pid == -1) {
		perror("fork");
		exit(1);
	}
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execv(argv[1], argv+2);
	} else {
		while(1) {
			wait(&status);
			if (WIFEXITED(status))
				break;
			ptrace(PTRACE_GETREGS, pid, 0, &regs);
			int orig_eax = regs.orig_eax;
			// hook clock_gettime
			struct timespec *tp;
			if (orig_eax == SYS_time) {
				if (insyscall == 0)
					insyscall = 1;
				else {
					ptrace(PTRACE_GETREGS, pid, 0, &regs);
					regs.eax = 0x12345678;
					ptrace(PTRACE_SETREGS, pid, 0, &regs);
					insyscall = 0;
				}
			}
			if (orig_eax == SYS_clock_gettime) {
//				printf("clock_gettime\n");
				if (insyscall == 0) {
					insyscall = 1;
					tp = regs.ecx; // second argument of clock_gettime
				//	printf("%x\n", tp);
				//	printf("%x\n", &tp->tv_sec);
				} else {
					insyscall = 0;
					ptrace(PTRACE_POKEDATA, pid, &tp->tv_sec, 0x12345678);
				}
			}
			ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		}
	}
}

