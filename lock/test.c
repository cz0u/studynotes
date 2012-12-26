#include <stdio.h>
#include <unistd.h>

int test;
int testb;

int main() {
	printf("address of test: %p\n", &test);
	printf("address of testb: %p\n", &testb);
	while (1) {
		sleep(3);
		test++;
		testb++;
		printf("test %d\n", test);
		printf("testb %d\n", testb);
	}
}
