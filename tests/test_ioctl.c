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
#include <pthread.h>

#include "../perfuser-abi.h"

#define PAGE_SIZE 4096
static int th = 4;
static int count[4];
static __thread int id;
static int rank;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void handle_sample(int signum, siginfo_t *info, void *arg);

static struct sigaction action = {
	.sa_sigaction = handle_sample,
	.sa_flags = SA_SIGINFO,
};

static struct sigaction save_act;

static int enable(FILE **handle) {
	int ret;
	struct perfuser_info info;
	*handle = fopen(PERFUSER_PATH, "rw");
	if (!*handle) {
		printf("fopen() error for file %s\n", PERFUSER_PATH);
		return -1;
	}
	info.cmd = PERFUSER_REGISTER;
	info.sig = SIGUSR1;
	if (ioctl((*handle)->_fileno, PERFUSER_IOCTL, &info) < 0) {
		printf("ioctl error register\n");
		fclose(*handle);
		*handle = NULL;
		return -1;
	}
	return 0;
}

static void disable(FILE **handle) {
	struct perfuser_info info = { .cmd = PERFUSER_UNREGISTER };
	if (!*handle)
		return;
	if (ioctl((*handle)->_fileno, PERFUSER_IOCTL, &info) < 0) {
		printf("ioctl error unregister\n");
	}
	fclose(*handle);
	*handle = NULL;
}

void handle_sample(int signum, siginfo_t *info, void *arg) {
	count[id]++;
}

void *do_work(void *args) {
	int nb = *((int *) args);
	int i;
	size_t sz = PAGE_SIZE * nb;
	FILE *handle;

	pthread_mutex_lock(&mutex);
	id = rank++;
	pthread_mutex_unlock(&mutex);

	enable(&handle);
	printf("%20s %ld\n", "self", pthread_self());
	char *buf = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(buf, 0, sz);
	munmap(buf, sz);
	disable(&handle);
	return NULL;
}

int main(int argc, char **argv)
{
	int i;
	int nb = 1000;
	pthread_t pth[th];

	printf("test_ioctl begin\n");
	sigaction(SIGUSR1, &action, &save_act);

	for (i = 0; i < th; i++) {
		pthread_create(&pth[i], NULL, do_work, &nb);
	}

	for (i = 0; i < th; i++) {
		pthread_join(pth[i], NULL);
		printf("count=%d\n", count[i]);
	}

	sigaction(SIGUSR1, &save_act, NULL);
	printf("test_ioctl done\n");
error:
	return 0;
}
