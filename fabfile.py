from fabric.api import local, env, run, cd, sudo, prefix, execute, lcd, task, hosts
from fabric.operations import put, get
from fabric.contrib.project import rsync_project

import os

@task
def build():
    local_dir = os.path.abspath(os.curdir) + "/"
    rsync_project("~/perfuser/", local_dir)
    with cd("~/perfuser"):
        run("echo $(pwd)")
        run("make clean")
        run("make")
    with cd("~/perfuser/tests"):
        run("make clean")
        run("make")
        run("./test-all.sh")
