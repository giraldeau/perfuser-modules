/*
 * test_ioctl.c
 *
 *  Created on: Dec 9, 2014
 *      Author: francis
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <signal.h>

#include "../perfuser-abi.h"

#define PAGE_SIZE 4096

void handle_sample(int signum) {
	printf("sample!\n");
}

int main(int argc, char **argv)
{
	int i;
	printf("hello!\n");
	FILE *f = fopen(PERFUSER_PATH, "rw");
	if (!f) {
		printf("fopen() error for file %s\n", PERFUSER_PATH);
		goto error;
	}
	signal(SIGUSR1, handle_sample);
	ioctl(f->_fileno, PERFUSER_REGISTER, SIGUSR1);
	size_t x = PAGE_SIZE * 10000;
	char *buf = malloc(x);
	buf[x] = 0xcafecafe;
	ioctl(f->_fileno, PERFUSER_UNREGISTER);
error:
	return 0;
}
