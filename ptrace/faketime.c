#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>

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
			//TODO: hook clock_gettime
			if (orig_eax == SYS_time || orig_eax == SYS_clock_gettime) {
				if (insyscall == 0)
					insyscall = 1;
				else {
					ptrace(PTRACE_GETREGS, pid, 0, &regs);
					regs.eax = 0x12345678;
					ptrace(PTRACE_SETREGS, pid, 0, &regs);
					insyscall = 0;
				}
			}
			ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		}
	}
}

