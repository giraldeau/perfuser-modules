/*
 * perfuser-abi.h
 *
 *  Created on: Dec 9, 2014
 *      Author: francis
 */

#ifndef PERFUSER_ABI_H_
#define PERFUSER_ABI_H_

#define PERFUSER_PROC "perfuser"
#define PERFUSER_PATH "/proc/" PERFUSER_PROC

enum perfuser_cmd {
	PERFUSER_REGISTER = 0,
	PERFUSER_UNREGISTER = 1,
	PERFUSER_STATUS = 2,
	PERFUSER_DEBUG = 3,
};

enum perfuser_feature {
	SAMPLE_PERF = 0,
	SAMPLE_BLOCKING = 1,
};

/*
 * Structure to exchange data from and to kernel module.
 */
struct perfuser_info {
	int cmd;
	int sig;
	int feature;
} __attribute__((packed));

/* Borrow some unused range of LTTng ioctl ;-) */
#define PERFUSER_IOCTL 		_IO(0xF6, 0x90)

#endif /* PERFUSER_ABI_H_ */
