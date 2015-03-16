/*
 * perfuser-abi.h
 *
 *  Created on: Dec 9, 2014
 *      Author: francis
 */

#ifndef PERFUSER_ABI_H_
#define PERFUSER_ABI_H_

#include <linux/types.h>
#include <linux/signal.h>

#define PERFUSER_PROC "perfuser"
#define PERFUSER_PATH "/proc/" PERFUSER_PROC

enum perfuser_cmd {
	PERFUSER_REGISTER = 0,
	PERFUSER_UNREGISTER = 1,
	PERFUSER_STATUS = 2,
	PERFUSER_DEBUG = 3,
	PERFUSER_SENDSIG = 4, /* benchmark purpose */
	PERFUSER_NONE = 5,
};

/*
 * Structure to exchange data from and to kernel module.
 */
struct perfuser_info {
	int cmd;
	int signo;
} __attribute__((packed));

struct perfuser_state {
	int delayed;
	int count;
	unsigned long ts;
} __attribute__((packed));

/* Borrow some unused range of LTTng ioctl ;-) */
#define PERFUSER_IOCTL 		_IO(0xF6, 0x90)

#endif /* PERFUSER_ABI_H_ */
