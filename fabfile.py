from fabric.api import local, env, run, cd, sudo, prefix, execute, lcd, task, hosts
from fabric.operations import put, get
from fabric.contrib.project import rsync_project

import os
from fabric.context_managers import settings

@task
def reload_modules():
    with settings(warn_only=True):
        sudo("rmmod perfuser")
    sudo("dmesg -c > /dev/null")
    sudo("modprobe perfuser")
    sudo("dmesg -c")

def do_rsync(name):
    ex = [ "*.o", "*.so", "*.so.0.0.0", "*.la", "*.lai",
          "*.lo", "*.ko", ".libs", "*.deps", "*perf.data*",
          "autom4te.cache", "config/missing", "Makefile",
          "*Makefile.in", "aclocal.m4", "config.log", "config.status",
          "configure", "libtool", "test_ioctl" ]
    local_dir = os.path.abspath(os.curdir) + "/../" + name + "/"
    dest = "~/%s/" % (name)
    rsync_project(dest, local_dir, exclude=ex)

@task
def build_modules():
    name = "perfuser-modules"
    do_rsync(name)
    with cd("~/%s" % (name)):
        run("echo $(pwd)")
        run("make")
        sudo("make modules_install")
        sudo("depmod -a")
    reload_modules()

@task
def build_lib():
    name = "perfuser"
    do_rsync(name)
    with cd("~/%s" % (name)):
        run("make clean")
        run("make")
        run("make check")

@task
def configure():
    name = "perfuser"
    do_rsync(name)
    with cd("~/%s" % (name)):
        run("./bootstrap")
        run("./configure")

@task
def build():
    build_modules()
    build_lib()
