/*
 * test_ioctl.c
 *
 *  Created on: Dec 9, 2014
 *      Author: francis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <signal.h>

#include "../perfuser-abi.h"

FILE *perfuser = NULL;

#define PAGE_SIZE 4096

static int count = 0;

void handle_sample(int signum) {
	count++;
}

void do_work(int nb) {
	int i;
	size_t sz = PAGE_SIZE * nb;
	char *buf = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(buf, 0, sz);
	munmap(buf, sz);
}

static int enable() {
	perfuser = fopen(PERFUSER_PATH, "rw");
	if (!perfuser) {
		printf("fopen() error for file %s\n", PERFUSER_PATH);
		return -1;
	}
	signal(SIGUSR1, handle_sample);
	ioctl(perfuser->_fileno, PERFUSER_REGISTER, SIGUSR1);
	return 0;
}

static void disable() {
	if (!perfuser)
		return;
	ioctl(perfuser->_fileno, PERFUSER_UNREGISTER);
	fclose(perfuser);
}

int main(int argc, char **argv)
{
	int i;

	printf("test_ioctl begin\n");
	if (argc > 1)
		enable();

	do_work(1000);

	if (argc > 1)
		disable();
	printf("test_ioctl done count=%d\n", count);
error:
	return 0;
}
