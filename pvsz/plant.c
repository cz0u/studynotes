#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>

//4 ptrace-stops: syscall-stop, signal-delivery-stop, group-stop, ptrace_event-stop;
//group-stop: caused by receiving a stopping signal, that is , SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU; 
//			  And a following ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) will set errno to EINVAL;
//
//syscall-stop: set PTRACE_O_TRACESYSGOOD option(by calling ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD)).
//				WIFSTOPPED(status) true, WSTOPSIG(status) == (SIGTRAP|0x80)
//
//signal-delivery-stop: WIFSTOPPED(status) == true; sig = WSTOPSIG(status);
//
//ptrace_event-stop: 
//
struct proc {
	int pid;
	int status;
	struct user_regs_struct oregs, regs;
	enum {
		TRACED = 0,
		RUNNING = 1,
		SIGNAL_DELIVER_STOP = 2,
		GROUP_STOP = 3,
		EVENT_STOP = 4,
		SYSCALL_STOP = 5,
		UNTRACED = 6,
		DEAD = 7,
	} stat;
	int insys;
};

struct proc* attach(int pid) {
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	struct proc *p = calloc(1, sizeof *p);
	p->pid = pid;
	p->status = 0;
	int c = waitpid(pid, &p->status, __WALL);
	if (c == -1) {
		perror("waitpid");
		exit(1);
	}
	if (WIFEXITED(p->status)||WIFSIGNALED(p->status)) {
		free(p);
		return NULL;
	}
	assert(WSTOPSIG(p->status)==SIGSTOP);
	p->stat = SIGNAL_DELIVER_STOP;
	if(ptrace(PTRACE_SETOPTIONS, p->pid, NULL, PTRACE_O_TRACESYSGOOD)) {
		perror("ptrace[SETOPTIONS]");
		exit(1);
	}
	return p;
}

void proc_regs(struct proc *p, int set) {
	if (set)
		ptrace(PTRACE_SETREGS, p->pid, NULL, &p->regs);
	else
		ptrace(PTRACE_GETREGS, p->pid, NULL, &p->regs);
}

void proc_save(struct proc *p) {
	assert(p->stat < UNTRACED);
	if (ptrace(PTRACE_GETREGS, p->pid, NULL, &p->oregs) == -1) {
		perror("ptrace[GETREGS]");
		exit(1);
	}
}

void proc_restore(struct proc *p) {
	assert(p->stat < UNTRACED);
	if (ptrace(PTRACE_SETREGS, p->pid, NULL, &p->oregs) == -1) {
		perror("ptrace[SETREGS]");
		exit(1);
	}
}

void proc_cont(struct proc *p, int flags) {
	if (flags) {
		ptrace(PTRACE_SYSCALL, p->pid, NULL, NULL);
	} else {
		ptrace(PTRACE_CONT, p->pid, NULL, NULL);
	}
}

void proc_detach(struct proc *p) {
	if (p->stat == UNTRACED) {
		fprintf(stderr, "process %d not traced\n", p->pid);
		return;
	}
	ptrace(PTRACE_DETACH, p->pid, NULL, NULL);
	p->stat = UNTRACED;
}

void proc_wait(struct proc *p) {
	int status = 0;
	int child = waitpid(p->pid, &status, __WALL);
	printf("wait child %d status %p\n", child, status);
	if (child == -1) {
		perror("wait");
		exit(1);
	}
	if (WIFEXITED(status)||WIFSIGNALED(status)) {
		p->stat = DEAD;
	} else if (WIFSTOPPED(status)) {
		int sig = WSTOPSIG(status);
		if (sig == (SIGTRAP|0x80)) {
			p->stat = SYSCALL_STOP;
		} else if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTOU || sig == SIGTTIN) {
			siginfo_t siginfo;
			errno = 0;
			ptrace(PTRACE_GETSIGINFO, p->pid, NULL, &siginfo);
			if (errno == EINVAL) {
				p->stat = GROUP_STOP;
			} else {
				p->stat = SIGNAL_DELIVER_STOP;
			}
		}
	}
	p->status = status;
}

//proc_write, proc_read
//return the num of bytes that've been read or writen;
int proc_write(struct proc *p, void *addr, char *buf, int len) {
	int pid = p->pid;
	int i = 0;
	while (len > 0) {
		void *word;
		int l = len < sizeof(word) ? len : sizeof(word);
		memcpy(&word, buf+i, l);
		if (ptrace(PTRACE_POKEDATA, pid, addr+i, word) == -1) {
			if (i)
				break;
			perror("ptrace");
			exit(1);
		}
		len -= sizeof(word);
		i += sizeof(word);
	}
	return i;
}

int proc_read(struct proc *p, void *addr, char *buf, int len) {
	int pid = p->pid;
	int i = 0;
	while (len > 0) {
		errno = 0;
		long word = ptrace(PTRACE_PEEKDATA, pid, addr+i, NULL);
		if (errno != 0) {
			if (i)
				break;
			perror("ptrace");
			exit(1);
		}
		int l = len < sizeof(long) ? len : sizeof(long);
		memcpy(buf+i, &word, l);
		len -= sizeof(long);
		i += sizeof(long);
	}
	return i;
}

void proc_push(struct proc *p, long data) {
	p->regs.esp -= 4;	
	proc_write(p, (void *)p->regs.esp, (char *)&data, sizeof(long));
}

//BX, CX, DX, SI, DI, BP
#define EBASE 0x8048000
void *proc_mmap(struct proc *p, int prot, int flags) {
	void *addr = NULL;
	char *code = "\xcd\x80\x00\x00";
	proc_save(p);
	p->regs = p->oregs;
	//if use SYS_mmap, the call will fail; 
	//WHY? Because SYS_mmap only has one argument;
	p->regs.eax = SYS_mmap2; 
	p->regs.ebx = 0;
	p->regs.ecx = 4;
	p->regs.edx = prot;
	p->regs.esi = flags;
	p->regs.edi = -1;
	p->regs.ebp = 0;
	p->regs.eip = EBASE;
	char savebuf[4] = {0};
	int n = proc_read(p, (void*)EBASE, savebuf, 4);
	if (n != 4) {
		perror("read");
		exit(1);
	}
	n = proc_write(p, (void*)EBASE, code, 4);
	if (n != 4) {
		perror("write");
		exit(1);
	}
	proc_regs(p, 1);
	printf("syscall mmap begin...\n");
	ptrace(PTRACE_SYSCALL, p->pid, NULL, NULL);
	while (1) {
		proc_wait(p);
		if (p->stat != SYSCALL_STOP) {
			goto cont;
		}
		proc_regs(p, 0);
		if (p->regs.orig_eax == SYS_mmap2) {
			if (p->insys == 0) {
				p->insys = 1;
			} else if (p->insys == 1) {
				addr = (void *)p->regs.eax;
				p->insys = 0;
				break;
			}
		}
cont:
		ptrace(PTRACE_SYSCALL, p->pid, NULL, NULL);
	}
	proc_write(p, (void *)EBASE, savebuf, 4);
	proc_restore(p);
	return addr;
}

void proc_exit(struct proc *p, int no) {
	char *code = "\xcd\x80\x00\x00";
	proc_save(p);
	p->regs = p->oregs;
	p->regs.eax = SYS_exit;
	p->regs.ebx = no;
	p->regs.eip = EBASE;
	char savebuf[4] = {0};
	int n = proc_read(p, (void*)EBASE, savebuf, 4);
	if (n != 4) {
		perror("read");
		exit(1);
	}
	proc_write(p, (void*)EBASE, code, 4);
	proc_regs(p, 1);
	printf("syscall exit begin...\n");
	ptrace(PTRACE_SYSCALL, p->pid, NULL, NULL);
	while (1) {
		proc_wait(p);
		if (p->stat == DEAD) {
			printf("%p: ", p->status);
			if (WIFEXITED(p->status)) {
				printf("exit code %d\n", WEXITSTATUS(p->status));
			} else if (WIFSIGNALED(p->status)) {
				printf("signal %d\n", WTERMSIG(p->status));
			}
			break;
		}
		if (p->stat != SYSCALL_STOP) {
			goto cont;
		}
		proc_regs(p, 0);
		if (p->regs.orig_eax == SYS_exit) {
			if (p->insys == 0) {
				p->insys = 1;
			} else if (p->insys == 1) {
				p->insys = 0;
				break;
			}
		}
cont:
		ptrace(PTRACE_SYSCALL, p->pid, NULL, NULL);
	}
}

long call_waitpid(struct proc *p, int pid) {
	long child;
	char *code = "\xcd\x80\x00\x00";
	proc_save(p);
	p->regs = p->oregs;
	p->regs.eax = SYS_waitpid; 
	p->regs.ebx = pid;
	p->regs.ecx = 0;
	p->regs.edx = 0;
	p->regs.eip = EBASE;
	char savebuf[4] = {0};
	int n = proc_read(p, (void*)EBASE, savebuf, 4);
	if (n != 4) {
		perror("read");
		exit(1);
	}
	n = proc_write(p, (void*)EBASE, code, 4);
	if (n != 4) {
		perror("write");
		exit(1);
	}
	proc_regs(p, 1);
	ptrace(PTRACE_SYSCALL, p->pid, NULL, NULL);
	while (1) {
		proc_wait(p);
		if (p->stat != SYSCALL_STOP) {
			goto cont;
		}
		proc_regs(p, 0);
		if (p->regs.orig_eax == SYS_waitpid) {
			if (p->insys == 0) {
				p->insys = 1;
			} else if (p->insys == 1) {
				child = p->regs.eax;
				p->insys = 0;
				break;
			}
		}
cont:
		ptrace(PTRACE_SYSCALL, p->pid, NULL, NULL);
	}
	proc_write(p, (void *)EBASE, savebuf, 4);
	proc_restore(p);
	return child;
}

int main(int argc, char *argv[]) {
	int parent, child;
	if (argc != 3) {
		fprintf(stderr, "usage: %s <parent_pid> <child_pid>\n", argv[0]);
		return 1;
	}
	parent = atoi(argv[1]);
	child = atoi(argv[2]);
	struct proc *p = attach(parent);
	printf("attach %d\n", p->pid);
	long pid = call_waitpid(p, child);
	if ((unsigned long)pid > (unsigned long)-4095) {
		errno = pid;
		perror("waitpid");
	}
	//proc_exit(p, 42);
	proc_detach(p);
}

