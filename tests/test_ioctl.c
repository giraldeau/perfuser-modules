/*
 * test_ioctl.c
 *
 *  Created on: Dec 9, 2014
 *      Author: francis
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <syscall.h>

#include "../perfuser-abi.h"

int main(int argc, char **argv)
{
	FILE *f = fopen("/proc/perf_event_user", "rw");
	if (!f) {
		printf("fopen() error\n");
		goto error;
	}
	ioctl(f->_fileno, PERFUSER_CREATE);
error:
	return 0;
}
