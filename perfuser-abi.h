/*
 * perfuser-abi.h
 *
 *  Created on: Dec 9, 2014
 *      Author: francis
 */

#ifndef PERFUSER_ABI_H_
#define PERFUSER_ABI_H_

#define PERFUSER_PROC "perf_event_user"

/* Borrow some unused range of LTTng ioctl ;-) */
#define PERFUSER_CREATE _IO(0xF6, 0x90)

#endif /* PERFUSER_ABI_H_ */
