#include <stdio.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
	int pid = fork();
	if (pid == -1) {
		perror("fork");
		return 1;
	}
	if (pid == 0) {
		printf("pid is %d\n", getpid());
		return 0;
	} else {
		while (1) {
			sleep(3);
		}
	}
}

