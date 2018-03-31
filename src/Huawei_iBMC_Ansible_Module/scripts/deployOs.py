#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2017, Huawei.
#
# This file is part of Ansible
#

import os
import json
import re
import sys
import time
import commands
import base64
import platform
import subprocess
import string
import logging
import ConfigParser
from datetime import datetime

sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
sys.path.append("/etc/ansible/ansible_ibmc/scripts")
from powerManage import *
from cfgBmc import *

LOG_FILE = "/etc/ansible/ansible_ibmc/log/deployOsLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/deployOsReport.log"

log_hander = logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes = 1024*1024,backupCount = 5)
report_hander = logging.handlers.RotatingFileHandler(REPORT_FILE,maxBytes = 1024*1024,backupCount = 5)
fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
log_hander.setFormatter(fmt)
report_hander.setFormatter(fmt)

log = logging.getLogger('deployOsLog')
log.addHandler(log_hander)
log.setLevel(logging.INFO)

report = logging.getLogger('deployOsReport')
report.addHandler(report_hander)
report.setLevel(logging.INFO)



global token


'''
#==========================================================================
# @Method:sCmd 
# @command: 
# @Param:  strCmd
# @date: 2017.10.18
#==========================================================================
'''
def sCmd(strCmd):
    ret = []
    if not strCmd:
        ret.append(55)
        ret.append("Input cmd is null")
        return ret
    if "Windows" != platform.system():
        strCmd = ['/bin/sh', '-c', strCmd]

    retCmd = subprocess.Popen(strCmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    rettup = retCmd.communicate(input='y\n')
    returnCode = retCmd.wait()

    ret.append(returnCode)
    ret.append(rettup[0])
    ret.append(rettup[1])

    return ret

'''
#==========================================================================
# @Method:hex2str 
# @command: 
# @Param:  hex
# @date: 2017.10.18
#==========================================================================
'''
def hex2str(hexStr):
    hexList = hexStr.split()
    ret = ""
    for index in hexList:
        if (index != "00") and (index != ""):
            ret = ret + chr(int(index,16))
    return ret

'''
#==========================================================================
# @Method: string to hex 
# @command: 
# @Param:  str
# @date: 2017.10.18
#==========================================================================
'''
def str2hex(str):
    ret = ""
    ascList = map(ord, str)
    for index in ascList:
        ret = ret + " " + hex(index)
    return ret

'''
#==========================================================================
# @Method: readFlag 
# @command: 
# @Param:  row
# @date: 2017.10.18
#==========================================================================
'''
def readFlag(ibmc,row=0):

    ret = os.popen("ipmitool -H " + ibmc['ip'] + " -I lanplus -U "+ ibmc['user'] + " -P " + ibmc['pswd'] + " raw 0x06 0x59 0x00 0xc2 " + hex(row) + " 0x00")

    info = ret.readlines()
    newStr = ""
    for line in info:
        newStr = newStr + line.replace("\n", "")

    newStr = newStr[3:]
    if (row == 0):
        newStr = newStr[3:]
        return [0, hex2str(newStr)]
    else:
        return [0, hex2str(newStr)]

'''
#==========================================================================
# @Method:read255 
# @command: read all form bmc info
# @Param:  ibmc
# @date: 2017.10.18
#==========================================================================
'''
def read255(ibmc):
    ret = []
    flag = True
    allStr = ""
    index = 0
    while index < 16:
        retRow = readFlag(ibmc,index)
        if (retRow[0] == 0):
            allStr = allStr + retRow[1]
            index = index + 1
        else:
            ret = retRow
            flag = False
            break

    if (flag == True):
        ret.append(0)
        ret.append(allStr)
    return ret


'''
#==========================================================================
# @Method:write info to bmc
# @command: 
# @Param:  ibmc
# @date: 2017.10.18
#==========================================================================
'''
def writeRow(ibmc, row, string, sLen=-1):

    if (len(string) > 16):
        return -1
    if (sLen != -1):
        hexStr = " " + hex(sLen) + "" + str2hex(string)
    else:
        hexStr = str2hex(string)
    cmd = "ipmitool -H " + ibmc['ip'] + " -I lanplus -U " + ibmc['user'] + " -P " + ibmc['pswd'] + " raw 0x06 0x58 0xc2 " + hex(row) + hexStr
    ret = sCmd(cmd)

'''
#==========================================================================
# @Method:write255
# @command: 
# @Param:  ibmc
# @date: 2017.10.18
#==========================================================================
'''
def write255(ibmc,string):
    sLen = len(string)
    if sLen > 255:
        return -1
    row = 0
    index = 0
    while index < sLen:
        if index == 0:
            writeRow(ibmc,0, string[0:15], sLen)
            index = index + 15
            row = row + 1
        else:
            writeRow(ibmc,row, string[index:(index + 16)])
            index = index + 16
            row = row + 1


'''
#==========================================================================
# @Method: clear bmc info
# @command: 
# @Param:  ibmc
# @date: 2017.10.18
#==========================================================================
'''
def clearBmcInfo(ibmc):
    index = 0
    for index in range(16):
        cmd = "ipmitool -H " + ibmc['ip'] + " -I lanplus -U " + ibmc['user'] + " -P " + ibmc['pswd'] + " raw 0x06 0x58 0xc2 " + hex(index) + (" 0x00"*16 )
        os.popen(cmd)

'''
#==========================================================================
# @Method: read bmc info by redfish
# @command: 
# @Param:  ibmc
# @date: 2017.11.28
#==========================================================================
'''
def readBmcInfoByRedfish(ibmc, root_uri, manager_uri):
    rets = ''
    uri = root_uri + manager_uri
    try:
        response = sendGetRequest(ibmc, uri, 30)
    except Exception ,e:
        log.error(ibmc['ip'] + " -- read bmc info failed!" + str(e))
        raise

    if response is None:
        ret = 'HTTP request exception!'
    else:
        try:
            ret = response.json()
        except:
            log.error(ibmc['ip'] + " -- response reslove json failed!" + str(e))
            raise

    info = ret['Oem']['Huawei']['RemoteOEMInfo']
    for i in range(0,len(info)):
        rets = rets + unichr(info[i])

    return rets.strip() 


'''
#==========================================================================
# @Method: write bmc info by redfish
# @command: 
# @Param:  ibmc
# @date: 2017.11.28
#==========================================================================
'''
def writeBmcInfoByRedfish(ibmc,root_uri,manager_uri,infostr):
    
    info = [0]
    for i in range(0,len(infostr)):
        info.append(ord(infostr[i]))
    for i in range(len(infostr),255):
        info.append(0)

    uri = root_uri + manager_uri
    token = getToken()
    try:
        eTag = getEtag(ibmc,uri)
    except Exception,e:
        log.error(ibmc['ip'] + " -- get eTag failed!" + str(e))
        raise

    headers = {'content-type': 'application/json','X-Auth-Token':token, 'If-Match': eTag}
    payload = {"Oem":{"Huawei":{"RemoteOEMInfo":info}}}

    try:
        r = request('PATCH',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            result = True
        elif r.status_code == 412:
            log.error(ibmc['ip'] + " -- " +"write bmc info failed! auth failed! ")
            result = "write bmc info failed! auth failed! "
        else:
            log.error(ibmc['ip'] + " -- " +"write bmc info failed!")
            result = "write bmc info failed!" + str(r.status_code)
    except Exception,e:
        log.exception(ibmc['ip'] + " -- " +"write bmc info failed! " + str(e))
        result = str(e)
        raise

    return result


'''
#==========================================================================
# @Method: clear bmc info by redfish
# @command: 
# @Param:  ibmc
# @date: 2017.11.28
#==========================================================================
'''
def clearBmcInfoByRedfish(ibmc,root_uri,manager_uri):
    info = [0]
    
    for i in range(0,255):
        info.append(0)
    
    uri = root_uri + manager_uri 
    token = getToken()
    try:
        eTag = getEtag(ibmc,uri)
    except Exception,e:
        log.error(ibmc['ip'] + " -- get eTag failed!" + str(e))
        raise

    headers = {'content-type': 'application/json','X-Auth-Token':token, 'If-Match': eTag}
    payload = {"Oem":{"Huawei":{"RemoteOEMInfo":info}}}

    try:
        r = request('PATCH',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            result = True
        elif r.status_code == 412:
            log.error(ibmc['ip'] + " -- " +"clear bmc info failed! auth failed! ")
            result = "clear bmc info failed! auth failed! " 
        else:
            log.error(ibmc['ip'] + " -- " +"clear bmc info failed!error code:" + str(r.status_code) + " "  + str(r.json()))
            result = "clear bmc info failed!error code:" + str(r.status_code) + " "  + str(r.json())

    except Exception,e:
        log.exception(ibmc['ip'] + " -- " +"clear bmc info failed! " + str(e))
        result = "clear bmc info failed! " + str(e)
        raise

    return result

    

'''
#==========================================================================
# @Method: query vmm info
# @command: 
# @Param:  ibmc
# @date: 2017.10.19
#==========================================================================
'''
def getVmmInfo(ibmc, root_uri,manager_uri):
    ret = ''
    result = ''
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + manager_uri + "/VirtualMedia/CD"
    payload = {}
    try:
        ret = request('GET',resource=uri,headers=headers,data=payload, tmout=30,ip=ibmc['ip'])
        data = ret.json()
        if ret.status_code == 200:
            result = data
        else:
            result = 'unknown'
    except Exception, e:
        log.exception(str(e))
        result = 'unknown'
        return result
        
    return result

'''
#==========================================================================
# @Method: query vmm info
# @command: 
# @Param:  ibmc
# @date: 2017.10.19
#==========================================================================
'''
def vmmIsConnected(ibmc, root_uri,manager_uri):
    ret = ''
    result = ''
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + manager_uri +"/VirtualMedia/CD"
    payload = {}
    try:
        ret = request('GET',resource=uri,headers=headers,data=payload, tmout=30,ip=ibmc['ip'])
        data = ret.json()
        if ret.status_code == 200:
            result = data[u'Inserted']
        else:
            log.error(ibmc['ip'] + " -- get vmm info failed!")
            result = 'unknown'
    except Exception,e:
        log.exception(str(e))
      
    return result
    

'''
#==========================================================================
# @Method: 挂载镜像
# @command: mountFile
# @Param: filepath ibmc url
# @date: 2017.9.18
#==========================================================================
'''
def mountFile(filepath,ibmc, root_uri, manager_uri):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + manager_uri + "/VirtualMedia/CD/Oem/Huawei/Actions/VirtualMedia.VmmControl"
    playload = {'VmmControlType':'Connect','Image':filepath}
    try:
        r = request('POST',resource=uri,headers=headers,data=playload,tmout=30,ip=ibmc['ip'])
        result = r.status_code

        if result == 202:
            log.info(ibmc['ip'] + " -- " +'mount ' + filepath.split("/")[-1] + ' successful')
            time.sleep(10)
        elif result == 404:
            log.error(ibmc['ip'] + " -- mount Failure:resource was not found")
        elif result == 400:
            log.error(ibmc['ip'] + " -- mount Failure:operation failed")
        elif result == 401:
            log.error(ibmc['ip'] + " -- mount Failure:session id is timeout or username and password is not correct!")
        else:
            log.error(ibmc['ip'] + " -- mount Failure:unknown error")
    except Exception, e:
        log.exception(str(e))

    return result 


'''
#==========================================================================
# @Method: unmount镜像
# @command: unmountFile
# @Param: filepath ibmc url
# @date: 2017.10.11
#==========================================================================
'''
def unMountFile(ibmc,root_uri,manager_uri):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + manager_uri + "/VirtualMedia/CD/Oem/Huawei/Actions/VirtualMedia.VmmControl"
    playload = {'VmmControlType':'Disconnect'}
    try:
        r = request('POST',resource=uri,headers=headers,data=playload,tmout=30,ip=ibmc['ip'])
    
        result = r.status_code
        if result == 202:
            log.info(ibmc['ip']+' -- unmount successful')
            time.sleep(10)
        elif result == 404:
            log.info(ibmc['ip']+' -- unmount Failure:resource was not found')
        elif result == 400:
            log.info(ibmc['ip']+" -- unmount Failure:operation failed")
        elif result == 401:
            log.info(ibmc['ip']+" -- unmount Failure:session id is timeout or username and password is not correct!")
        else:
            log.info(ibmc['ip']+' -- unmount Failure:unknown error')
        
    except Exception, e:
        log.exception(str(e))

    return result


'''
#==========================================================================
# @Method: get config file 
# @command: 
# @Param: osName
# @date: 2017.10.24
#==========================================================================
'''
def getConfigFile(osName):
    path = ""
    if osName.find("CentOS") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/CentOS.xml"
    elif osName.find("RHEL") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/RedHat.xml"
    elif osName.find("SUSE") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/SLES11SP1_64.xml"
    elif osName.find("Win2008_R2") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/win2008r2.xml"
    elif osName.find("Win2012_R2") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/win2012r2.xml"
    elif osName.find("Win2012") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/win2012.xml"
    elif osName.find("Win2016") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/win2016.xml"
    elif osName.find("ESXi5.0") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/VM5.0.xml"
    elif osName.find("ESXi5.1") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/VM5.1.xml"
    elif osName.find("ESXi5.5") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/VM5.5.xml"
    elif osName.find("ESXi6.0") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/VM6.0.xml"
    elif osName.find("ESXi6.5") >= 0:
        path = "/etc/ansible/ansible_ibmc/configFile/deployCfg/VM6.5.xml"
    else:
        path = "Unsupport!"
    return path

'''
#==========================================================================
# @Method: deploy os process 
# @command: 
# @Param: filepath ibmc url
# @date: 2017.10.18
#==========================================================================
'''
def deployOsProcess(filepath, ibmc, root_uri, system_uri, manager_uri):
    rets = {'result':True,'msg': ''}

    #parse ini file and get image config file
    config = ConfigParser.ConfigParser()
    config.read(filepath)
    serviceImg = config.get("config","serviceImg")
    osType = config.get("config","osType")
    osImg = config.get("config","osImg")
    configFile = getConfigFile(osType)
    log.info(ibmc['ip'] + " -- " + serviceImg.split("/")[-1] + ";" + osImg.split("/")[-1] + ";" + configFile)
    if configFile.find("Unsupport") >= 0:
        log.error(ibmc['ip'] + " -- Unsupport OS type,please check the config file!  \n")
        report.error(ibmc['ip'] + " -- Unsupport deploy OS,please check the config file! \n")
        rets['result'] = False
        rets['msg'] = "Unsupport deploy OS,please check the config file!"
        return rets
   
    #clear bmc info
    ret = clearBmcInfoByRedfish(ibmc,root_uri,manager_uri)
    if ret != True:
        rets['result'] = False
        rets['msg'] = ret
        return rets
    
    #write operator and ostype to ibmc
    ret = writeBmcInfoByRedfish(ibmc,root_uri,manager_uri, "operator:eSight;osType:"+osType)
    if ret != True:
        rets['result'] = False
        rets['msg'] = ret
        return rets
    ret = readBmcInfoByRedfish(ibmc,root_uri,manager_uri)
    log.info(ibmc['ip'] + " -- read for bmc info:" + str(ret))
    
    #get vmm is connected
    ret = vmmIsConnected(ibmc, root_uri, manager_uri)
    log.info(ibmc['ip'] + " -- is connect:"+str(ret))

    #if is connected,disconnect first
    if ret == True:
        log.info(ibmc['ip'] + " -- vmm is connect before,unmount ! ")
        unMountFile(ibmc, root_uri,manager_uri)
        time.sleep(5)

    #set CD as boot device
    log.info(ibmc['ip'] + " -- set boot device to CD! ")
    setBootDevice("Cd",ibmc,root_uri,system_uri) 

    #make sure boot device is Cd
    ret = getBootDevice(ibmc, root_uri,system_uri)
    if ret != "Cd":
        setBootDevice("Cd",ibmc,root_uri,system_uri)
    log.info(ibmc['ip'] + " -- bootdevice is:" + str(ret))

    #mount service iso
    ret = mountFile(serviceImg, ibmc, root_uri, manager_uri)
    if ret != 202:
        unMountFile(ibmc, root_uri, manager_uri)
        log.error(ibmc['ip'] + " -- install OS(" + osType + ")  failed! please check the service iamge is exist or not!")
        report.error(ibmc['ip'] + " -- install OS(" + osType + ")  failed! please check the service iamge is exist or not!")
        rets['result'] = False
        rets['msg'] = "install OS(" + osType + ")  failed! please check the service iamge is exist or not!"
        return rets    

    ret = managePower("ForceRestart", ibmc, root_uri, system_uri)
    if ret['result'] == True:
        log.info(ibmc['ip'] + " -- reboot system successfully!")
    else:
        log.error(ibmc['ip'] + " -- install os failed! reboot system failed!")
        report.error(ibmc['ip'] + " -- install os failed! reboot system failed!")
        rets['result'] = False
        rets['msg'] = "reboot system failed!"
        return rets

    loop = 0
    loopCount = 0 
    #make sure serviceCD is recived operator and osType, write successful info to BMC
    while 1:
        loop += 1
        time.sleep(20)
        ret = readBmcInfoByRedfish(ibmc,root_uri,manager_uri)
        log.info(ibmc['ip'] + " -- loop:" + str(loop) +  " ret: " + ret)

        if ret.find("progress:step1;result:successful") >= 0:
            log.info(ibmc['ip'] + " -- progress:step1;result:successful")
            break

        if loop >= 30:
            loopCount += 1
            if loopCount > 3:
                log.error(ibmc['ip'] + " -- wait for service systen start too long,step1 failed!  \n")
                report.error(ibmc['ip'] + " -- wait for service systen start too long,step1 failed!")
                rets['result'] = False
                rets['msg'] = "wait for service systen start too long,step1 failed!"
                return rets
            log.error(ibmc['ip'] + " -- wait for service systen start too long,step1 failed! reboot and try again")
            #clear bmc info
            ret = clearBmcInfoByRedfish(ibmc,root_uri,manager_uri)
            if ret != True:
                rets['result'] = False
                rets['msg'] = ret
                return rets
            #write operator and ostype to ibmc
            ret = writeBmcInfoByRedfish(ibmc,root_uri,manager_uri,"operator:eSight;osType:"+osType)
            if ret != True:
                rets['result'] = False
                rets['msg'] = ret
                return rets
            setBootDevice("Cd",ibmc,root_uri,system_uri)
            ret = managePower("ForceRestart", ibmc, root_uri, system_uri)
            log.info(ibmc['ip'] + " -- reboot system again " + str(ret))
            loop = 0

    #start cp config file info to BMC        
    log.info(ibmc['ip'] + " -- start cp config file")
    ret = clearBmcInfoByRedfish(ibmc,root_uri,manager_uri)
    if ret != True:
        rets['result'] = False
        rets['msg'] = ret
        return rets
    ret = writeBmcInfoByRedfish(ibmc,root_uri,manager_uri, "oscfg:start")
    if ret != True:
        rets['result'] = False
        rets['msg'] = ret
        return rets
    fp_de = open(configFile, 'r')
    fp_en = open("cfgEnc", 'w')
    base64.encode(fp_de, fp_en)
    fp_de.close()
    fp_en.close()

    try:
        fp = open("cfgEnc", 'r')
        loopWriteFile = 0
        while 1:
            loopWriteFile += 1
            log.info(ibmc['ip'] + " -- loopWriteFile:" + str(loopWriteFile))
            loopNext = 0
            while 1:
                loopNext += 1
                log.info(ibmc['ip'] + " -- loopNext:" + str(loopNext))
                ret = readBmcInfoByRedfish(ibmc,root_uri,manager_uri)
                if ret.find("oscfg:next") >= 0:
                    log.info(ibmc['ip'] + " -- find oscfg:next!!!" )
                    break
                if loopNext >= 20:
                    log.error(ibmc['ip'] + " -- write os config too long,failed!  \n")
                    report.error(ibmc['ip'] + " -- write os config too long,failed!")
                    rets['result'] = False
                    rets['msg'] = "write os config too long,failed!"
                    return rets
                time.sleep(10)

            newStr = fp.read(200)
            if len(newStr) == 200:
                log.info(ibmc['ip'] + " -- equal 200")
                ret = clearBmcInfoByRedfish(ibmc, root_uri,manager_uri)
                if ret != True:
                    rets['result'] = False
                    rets['msg'] = ret
                    return rets
                ret = writeBmcInfoByRedfish(ibmc,root_uri,manager_uri, "oscfg:" + newStr)
                if ret != True:
                    rets['result'] = False
                    rets['msg'] = ret
                    return rets
            else:
                log.info(ibmc['ip'] + " -- not equal 200")
                ret = clearBmcInfoByRedfish(ibmc,root_uri,manager_uri)
                if ret != True:
                    rets['result'] = False
                    rets['msg'] = ret
                    return rets
                ret = writeBmcInfoByRedfish(ibmc,root_uri,manager_uri, "oscfg:" + newStr + ":end")
                if ret != True:
                    rets['result'] = False
                    rets['msg'] = ret
                    return rets
                break
            if loopWriteFile >= 50:
                log.error(ibmc['ip'] + " -- write config too long,failed!  \n")
                report.error(ibmc['ip'] + " -- write config too long,failed!")
                rets['result'] = False
                rets['msg'] = "write config too long,failed!"
                return rets
            log.info(ibmc['ip'] + " -- write end") 
    except Exception, e:
        rets['result'] = False
        rets['msg'] = "write config failed! error info:" + str(e)
        log.error(ibmc['ip'] + " -- write config failed! error info:") + str(e)
        report.error(ibmc['ip'] + " -- write config failed! error info:") + str(e)
        return rets
    finally:
        fp.close()

    try:
        loopStep2 = 0
        while 1:
            loopStep2 += 1
            time.sleep(5)
            ret = readBmcInfoByRedfish(ibmc,root_uri,manager_uri)
            if ret.find("progress:step2;result:successful;errorCode:0") >= 0:
                log.info(ibmc['ip'] + " -- progress:step2;result:successful;")
                break
            else:
                log.info(ibmc['ip'] + " -- loopStep2:" + str(loopStep2) + " ret:" + ret)
            if loopStep2 > 50:
                log.error(ibmc['ip'] + " -- progress:setp2 failed! \n")
                report.error(ibmc['ip'] + " -- deployg os " + osType + " failed!")
                rets['result'] = False
                rets['msg'] = "progress:setp2 failed!"
                return rets
    except Exception, e:
        rets['result'] = False
        rets['msg'] = "progress:setp2 failed! error info:" + str(e)
        return rets
    finally:
        unMountFile(ibmc, root_uri, manager_uri)

    #make sure the service ISO is disconnect!
    time.sleep(15)
    ret = vmmIsConnected(ibmc, root_uri, manager_uri)
    log.info(ibmc['ip'] + " -- os is connected:" + str(ret))
    if ret == True:
        unMountFile(ibmc, root_uri, manager_uri)

    #make sure OS image is mounted!!!!
    ret = mountFile(osImg, ibmc, root_uri, manager_uri)
    if ret != 202:
        unMountFile(ibmc, root_uri, manager_uri)
        log.error(ibmc['ip'] + " -- install OS(" + osType + ")  failed! please check the OS iamge is exist or not!")
        report.error(ibmc['ip'] + " -- install OS(" + osType + ")  failed! please check the OS iamge is exist or not!")
        rets['result'] = False
        rets['msg'] = "install OS(" + osType + ")  failed! please check the OS iamge is exist or not!"
        return rets

    log.info(ibmc['ip'] + " -- mount os image result:" + str(ret))
    time.sleep(20)

    getVmmInfo(ibmc, root_uri, manager_uri)
    log.info(ibmc['ip'] + " -- os vmm is: " + str(ret) + " config iso file is:"+osImg.split("/")[-1])

    ret = clearBmcInfoByRedfish(ibmc,root_uri,manager_uri)
    if ret != True:
        rets['result'] = False
        rets['msg'] = ret
        return rets
    ret = writeBmcInfoByRedfish(ibmc,root_uri,manager_uri, "osinstall:start")
    if ret != True:
        rets['result'] = False
        rets['msg'] = ret
        return rets
    log.info(ibmc['ip'] + " -- start install os")

    try:
        loopInstall = 0
        while 1:
            loopInstall += 1
            time.sleep(100)
            ret = readBmcInfoByRedfish(ibmc,root_uri,manager_uri)
            log.info(ibmc['ip'] + " -- loopInstall:" + str(loopInstall) + " install os:" + str(ret))
            if loopInstall >= 25:
                log.error(ibmc['ip'] + " -- install OS(" + osType + ")  failed!")
                report.error(ibmc['ip'] + " -- install OS(" + osType + ")  failed!")
                rets['result'] = False
                rets['msg'] = "install OS(" + osType + ")  failed!"
                return rets

            if ret.find("result:5") != -1:
                log.info(ibmc['ip'] + " -- install OS(" + osType + ")  successfully!")
                report.info(ibmc['ip'] + " -- install OS(" + osType + ")  successfully!")
                rets['result'] = True
                rets['msg'] = "install OS(" + osType + ")  successfully!"
                return rets
            elif ret.find("result:failed") != -1:
                log.info(ibmc['ip'] + " -- install OS(" + osType + ")  failed!" + ret)
                report.info(ibmc['ip'] + " -- install OS(" + osType + ")  failed!" + ret)
                rets['result'] = False
                rets['msg'] = "install OS(" + osType + ") failed!" + ret
                return rets
    except Exception, e:
        rets['result'] = False
        rets['msg'] = "install OS(" + osType + ") failed! error info：" + str(e)
        log.info(ibmc['ip'] + " -- install OS(" + osType + ")  failed! error info：" + str(e))
        report.info(ibmc['ip'] + " -- install OS(" + osType + ")  failed! error info：" + str(e))
        return rets
    finally:
        unMountFile(ibmc, root_uri, manager_uri)

if __name__ == '__main__':
    main()

