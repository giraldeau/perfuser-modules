#!/bin/sh

BIN=/home/ubuntu/perfuser/tests/test_ioctl

sudo dmesg -c > /dev/null
sudo $BIN
sudo perf record -e faults -- $BIN

sudo insmod ../perfuser.ko
sudo perf record -e faults -- $BIN
sudo rmmod perfuser
sudo dmesg -c
