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

/* Borrow some unused range of LTTng ioctl ;-) */
#define PERFUSER_REGISTER 		_IO(0xF6, 0x90)
#define PERFUSER_UNREGISTER 		_IO(0xF6, 0x91)
#define PERFUSER_DEBUG	 		_IO(0xF6, 0x99)

#endif /* PERFUSER_ABI_H_ */
