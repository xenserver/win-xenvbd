#!python -u

import os, sys
import datetime
import re
import glob
import tarfile
import subprocess

def shell(command):
    print(command)
    sys.stdout.flush()

    pipe = os.popen(command, 'r', 1)

    for line in pipe:
        print(line.rstrip())

    return pipe.close()


class msbuild_failure(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

def msbuild(name, target, args):
    cwd = os.getcwd()

    os.environ['PLATFORM'] = 'x64'
    os.environ['CONFIGURATION'] = 'Windows 8 Release'
    os.environ['TARGET'] = target
    os.environ['BUILD_FILE'] = name + '.vcxproj'
    os.environ['BUILD_ARGS'] = args

    os.chdir('proj')
    os.chdir(name)
    status = shell('..\\msbuild.bat')
    os.chdir(cwd)

#    if (status != None):
#        raise msbuild_failure(sdv_arg)


if __name__ == '__main__':
    msbuild('xencrsh', 'sdv', '/p:Inputs="/clean"')
    msbuild('xenvbd',  'sdv', '/p:Inputs="/clean"')
    msbuild('xencrsh', 'sdv', '/p:Inputs="/check:default.sdv"')
    msbuild('xenvbd',  'sdv', '/p:Inputs="/check:default.sdv"')
    msbuild('xencrsh', 'dvl', '')
    msbuild('xenvbd',  'dvl', '')
#archive the dvl.xmls
