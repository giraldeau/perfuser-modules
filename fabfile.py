from fabric.api import local, env, run, cd, sudo, prefix, execute, lcd, task, hosts
from fabric.operations import put, get

env.user = "ubuntu"

@task
@hosts("trusty-dev.vm")
def build():
    with cd("~/perfuser"):
        run("echo $(pwd)")
        run("make clean")
        run("make")
    with cd("~/perfuser/tests"):
        run("make clean")
        run("make")
        run("./test-all.sh")
