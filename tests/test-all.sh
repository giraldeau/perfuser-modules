#!/bin/sh

BIN=/home/ubuntu/perfuser/tests/test_ioctl

sudo dmesg -c > /dev/null
sudo perf record -c 1 -e faults -- $BIN

sudo insmod ../perfuser.ko
sudo perf record -c 1 -e faults -- $BIN go
sudo rmmod perfuser
sudo dmesg -c
