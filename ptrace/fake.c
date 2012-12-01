// x86 32-bit linux 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

char *proc_readstr(int pid, char *addr) {
	char buf[1024];
	int n = 0;
	while (n < 1023) {
		long data = ptrace(PTRACE_PEEKDATA, pid, addr+n, NULL);
		char *t = (char *)&data;
		int i = 0;
		for (; i < 4; i++) 
			if (t[i] == '\0')
				break;
		strncpy(buf+n, t, 4);
		n += i;
		if (i < 4) {
			break;
		}
	}
	buf[n] = '\0';
	return strdup(buf);
}

void *proc_readptr(int pid, void *addr) {
	long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
	return (void *)data;
}

struct process {
	int pid;
	char *file;
	char **argv;
	char **envp;
	int insyscall;
};

struct process *proc_maps[0x10000] = {NULL};

int all_exit(struct process *procs[], int n) {
	int i = 0;
	for (; i < n; i++) {
		if (procs[i] != NULL)
			return 0;
	}
	return 1;
}

int main() {
	int pid;
	int status;
	struct user_regs_struct regs;

	pid = fork();
	if (pid == -1) {
		perror("fork");
		exit(1);
	}
	char *args[] = {"make", NULL};
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		int err = execvp("make", args);
		if (err == -1) {
			perror("execv");
			exit(1);
		}
	} else {
		wait(&status);
		if (WIFEXITED(status))
			return;
		ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEVFORK|PTRACE_O_TRACESYSGOOD);//|PTRACE_O_TRACEEXEC);
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		while(1) {
			int c = waitpid(-1, &status, __WALL);
			if (c == -1) {
				perror("waitpid");
			}
			if (proc_maps[c] == NULL) {
				proc_maps[c] = calloc(1, sizeof(struct process));
				proc_maps[c]->pid = c;
			}
			if (WIFEXITED(status)) {
				if (proc_maps[c] != NULL) {
					free(proc_maps[c]);
					proc_maps[c] = NULL;
				}
				if (all_exit(proc_maps, 0x10000)) {
					break;
				}
			}
			if (WSTOPSIG(status) == SIGCHLD) {
				fprintf(stderr, "pid %d get SIGCHLD\n", c);
				ptrace(PTRACE_SYSCALL, c, NULL, SIGCHLD);
				continue;
			}
			if (WSTOPSIG(status) != (SIGTRAP|0x80))
				goto cont;
			ptrace(PTRACE_GETREGS, c, 0, &regs);
			if (regs.orig_eax == SYS_execve) {
//				siginfo_t siginfo;
//				printf("%x\n", WSTOPSIG(status)); 
//				fprintf(stderr, "pid %d %p\n", c, regs.eip);
				fprintf(stderr, "%d %d\n", regs.orig_eax, regs.eax);
				fprintf(stderr, "status %p\n", status);
//				ptrace(PTRACE_GETSIGINFO, c, NULL, &siginfo);
//				printf("si_code: %p\n", siginfo.si_code);
				if (proc_maps[c]->insyscall == 0) {
					proc_maps[c]->insyscall = 1;
					// arg: BX, CX, DX
					char *file = (char *)regs.ebx;
                    char **argv = (char **)regs.ecx;
                    char **envp = (char **)regs.edx;
					char *arg;
					char *str = proc_readstr(c, file);
					fprintf(stderr, "%p %s\n", file, str);
					free(str);
					while ((arg = proc_readptr(c, argv)) != NULL) {
						str = proc_readstr(c, arg);
						fprintf(stderr, "%s ", str);
						free(str);
						argv++;
					}
					fprintf(stderr, "\n");
				} else {
					proc_maps[c]->insyscall = 0;
					if (regs.eax == 0) {
//						char *file = proc_maps[c]->file;
//						char **argv = proc_maps[c]->argv;
//						fprintf(stderr, "%p %p\n", file, argv);
//						char *arg;
//						char *str = proc_readstr(c, file);
//						fprintf(stderr, "%p %s\n", file, str);
//						free(str);
//						while ((arg = proc_readptr(c, argv)) != null) {
//							str = proc_readstr(c, arg);
//							fprintf(stderr, "%s ", str);
//							free(str);
//							argv++;
//						}
//						fprintf(stderr, "\n");
					}
				}
			}
cont:
			ptrace(PTRACE_SYSCALL, c, NULL, NULL);
		}
	}
}

