#! /usr/bin/python
# _*_ coding:utf-8 _*_

import os
import sys
import time
import shutil

copyFileCounts = 0

ansible_path = ''.join("/etc/ansible")
huawei_ibmc_path = ansible_path + '/ansible_ibmc'

folderList = [] 
fileList = ''

def removePartFiles(removeDir):
    fileList = os.listdir(removeDir)
    
    for fileName in fileList:
        if os.path.isfile(removeDir + os.path.sep + fileName):
            os.remove(removeDir + os.path.sep + fileName)
            continue
        
        if fileName != "configFile" and fileName != "playbooks":
            shutil.rmtree(removeDir + os.path.sep + fileName)

def removeAllFiles(removeDir):
    if os.path.exists(removeDir):
        shutil.rmtree(removeDir)

if __name__ == "__main__":
    try:
        import psyco
        psyco.profile()
    except ImportError:
        pass

    removeAll = raw_input("Do you want to keep configure file and playbooks(Y/N):")
    if removeAll.upper() != 'Y' and removeAll.upper() != 'N':
        print "Please input Y or N !"
        exit(1)
    if removeAll.upper() == 'Y':
        removePartFiles(huawei_ibmc_path)
    else:
        removeAllFiles(huawei_ibmc_path)

