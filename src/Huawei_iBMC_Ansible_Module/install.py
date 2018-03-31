#! /usr/bin/python
# _*_ coding:utf-8 _*_

import os
import sys
import time

copyFileCounts = 0

try:
    import ansible
except ImportError:
    print "Error:make sure ansible has be installed before install huawei ansible_ibmc"
    sys.exit(1)

ansible_path = ''.join("/etc/ansible")
huawei_ibmc_path = ansible_path + '/ansible_ibmc'

def touch(fname,times=None):
    with open(fname, 'a'):
        os.utime(fname,times)

def copyFiles(sourceDir, targetDir, overWrite):   
    global copyFileCounts
    print sourceDir
    for f in os.listdir(sourceDir):
        sourceF = os.path.join(sourceDir, f)
        targetF = os.path.join(targetDir, f)

        if os.path.isfile(sourceF):   
            #创建目录   
            if not os.path.exists(targetDir):
                os.makedirs(targetDir)
            copyFileCounts += 1
               
            #文件不存在，或者存在但是大小不同，覆盖
            if not os.path.exists(targetF) or (os.path.exists(targetF) and overWrite == 'Y'):
                #2进制文件
                open(targetF, "wb").write(open(sourceF, "rb").read()) 
                print u"%s %s copy successfully " %(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())), targetF)   
            else: 
                print u"%s %s exist,not copy again" %(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())), targetF)
           
        if os.path.isdir(sourceF):   
            copyFiles(sourceF, targetF, overWrite)   


if __name__ == "__main__":
    try:
        import psyco
        psyco.profile()
    except ImportError:
        pass

    if os.path.exists(huawei_ibmc_path + '/module') or os.path.exists(huawei_ibmc_path + '/scripts'):
        print "Please remove Huawei-iBMC-Ansible_Modules first!"
        exit(1)

    overWrite = raw_input("Do you want to over write ansible configuration(Y/N):")
    if overWrite.upper() != 'Y' and overWrite.upper() != 'N':
        print "Please input Y or N !"
        exit(1)

    copyFiles(os.getcwd(), huawei_ibmc_path, overWrite.upper())

    if not os.path.exists(huawei_ibmc_path + '/log'):
        os.makedirs(huawei_ibmc_path + '/log')
    
    if not os.path.exists(huawei_ibmc_path + '/report'):
        os.makedirs(huawei_ibmc_path + '/report')

    if not os.path.isdir(huawei_ibmc_path):
        os.makedirs(huawei_ibmc_path)

    touch(huawei_ibmc_path + '/__init__.py')
