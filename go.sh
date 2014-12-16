#!/bin/sh


rsync -av ../perfuser/ ubuntu@kernel-dev.phd.vm:~/perfuser/

fab build
