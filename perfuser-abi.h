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
	PERFUSER_SENDSIG = 4, /* benchmark purpose */
	PERFUSER_NONE = 5,
};

/*
 * Structure to exchange data from and to kernel module.
 */
struct perfuser_info {
	int cmd;
	int sig;
} __attribute__((packed));

/*
 * Extends siginfo_t to forward context.
 */
struct perfuser_siginfo {
	union {
		siginfo_t _info;
		struct {
			int _pad[4]; // preserve first fields of siginfo_t
			int bidon;
		} _perf;
	};
};

/* Borrow some unused range of LTTng ioctl ;-) */
#define PERFUSER_IOCTL 		_IO(0xF6, 0x90)

#endif /* PERFUSER_ABI_H_ */
