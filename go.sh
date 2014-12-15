#!/bin/sh


rsync -av ../perfuser/ ubuntu@trusty-dev.vm:~/perfuser/

fab build
