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
import ConfigParser
import logging, logging.handlers
from datetime import datetime


sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
sys.path.append("/etc/ansible/ansible_ibmc/scripts")
from cfgBmc import *
from powerManage import *

global token

LOG_FILE = "/etc/ansible/ansible_ibmc/log/cfgRaidLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/cfgRaidReport.log"

log_hander = logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes = 1024*1024,backupCount = 5)  
report_hander = logging.handlers.RotatingFileHandler(REPORT_FILE,maxBytes = 1024*1024,backupCount = 5)  
fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
log_hander.setFormatter(fmt)
report_hander.setFormatter(fmt)

log = logging.getLogger('cfgRaidLog')
log.addHandler(log_hander)
log.setLevel(logging.INFO)  

report = logging.getLogger('cfgRaidReport')
report.addHandler(report_hander)  
report.setLevel(logging.INFO)


'''
#==========================================================================
# @Method: get Task Status 
# @command: 
# @Param: 
# @date: 2017.11.01
#==========================================================================
'''
def getTaskStatus(ibmc, taskId, root_uri):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = "https://" + ibmc['ip'] + taskId
    result = []

    try:
        r = request('GET',resource=uri,headers=headers,data=None,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            r = r.json()
            taskStatus = r[u'TaskState']
            if taskStatus == "Running":
                result.append("Running")
            elif taskStatus == "Completed" and r['Messages']['Message'].find("successfully") != -1 :
                result.append("Successful")
                result.append(r['Messages']['MessageArgs'][0])
                log.info(ibmc['ip'] + " -- taskStatus:%s" %taskStatus)
            else:
                result.append(taskStatus)
                result.append(r['Messages']['Message'])
        else:
            result.append("failed")
            result.append("Unknown error!")
            
    except Exception,e:
        log.exception(ibmc['ip'] + " -- get task status failed! error info:%s" %str(e))
        result = "Exception!"
        result.append(str(e))
        raise

    log.info(ibmc['ip'] + " -- get Task status:%s" %str(result))
    return result

'''
#==========================================================================
# @Method: create logic device 
# @command: 
# @Param: 
# @date: 2017.10.31
#==========================================================================
'''
def creatLD(ibmc, playload, root_uri, system_uri):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + system_uri + "/Storages/RAIDStorage0/Volumes"
    payload = playload 
    try:
        r = request('POST',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])

    except Exception, e:
        log.exception(ibmc['ip'] + " -- error info:%s" %str(e))
        raise

    return r
  
  
'''
#==========================================================================
# @Method: config raid
# @command: 
# @Param: filepath ibmc url
# @date: 2017.11.01
#==========================================================================
'''
def deleteLD(ibmc,root_uri, vol_uri):
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = "https://" + ibmc['ip'] + vol_uri
    playload = None
    try:
        r = request('DELETE',resource=uri,headers=headers,data=playload,tmout=30,ip=ibmc['ip'])

    except Exception, e:
        log.exception(ibmc['ip'] + " -- error info:%s" %str(e))
        raise

    return r


'''
#==========================================================================
# @Method: delete all raid
# @command: 
# @Param:  ibmc url
# @date: 2017.11.01
#==========================================================================
'''
def deletAllLd(ibmc, root_uri, system_uri):

    members = getRaidInfo(ibmc, root_uri, system_uri)
    log.info(ibmc['ip'] + " -- delete Ld:%s" %str(members))
    if len(members) > 0: 
        try:
            for member in members:
                 ret = deleteLD(ibmc, root_uri, member[u'@odata.id'])
                 log.info(ibmc['ip'] + " -- delete ld:%s" %member[u'@odata.id'])
                 ret = ret.json()
                 if ret is not None:
                     taskId = ret[u'@odata.id']
                     status = ret[u'TaskState']
                     while 1:
                         taskResult = getTaskStatus(ibmc, taskId, root_uri)
                         if taskResult[0].find("Running") != -1:
                             continue
                         elif taskResult[0].find("Successful") != -1:
                             log.info(ibmc['ip'] + " -- the %s delete successful!" %str(member[u'@odata.id']))
                             time.sleep(20)
                             break 
                         else:
                             log.error(ibmc['ip'] + " -- delete %s failed:%s" %(str(member[u'@odata.id']),taskResult[1]))
                             return False
                 else:
                     logg.error("delete all logic disk failed:%s" %taskResult[1])
                     return False
            log.info(ibmc['ip'] + " -- all of logic device has be delete! \n")
        except Exception,e:
            log.exception(ibmc['ip'] + " -- error info:%s" %str(e))
            raise
    else:
        log.info(ibmc['ip'] + " -- there are no logic device create before!")
        return True

    return True

'''
#==========================================================================
# @Method: get raid info 
# @command: 
# @Param: ibmc url
# @date: 2017.11.01
#==========================================================================
'''
def getRaidInfo(ibmc, root_uri, system_uri):
    raidInfo_uri = system_uri + "/Storages/RAIDStorage0/Volumes"
    token = getToken()
    result = [] 
 
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + raidInfo_uri
    try:
        r = request('GET',resource=uri,headers=headers,data=None,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            r = r.json()
            result = r['Members']

    except Exception,e:
        log.error(ibmc['ip'] + " -- get raid info failed!error info:%s " %str(e))
        raise

    return result    

'''
#==========================================================================
# @Method: config raid
# @command: 
# @Param: filepath ibmc url
# @date: 2017.10.31
#==========================================================================
'''
def setBootEnable(ibmc, ld):
    uri = "https://" + ibmc['ip'] + str(ld)
    token = getToken()
    eTag = getEtag(ibmc,uri)
    result = True

    headers = {'content-type': 'application/json','X-Auth-Token':token, 'If-Match': eTag}
    payload = {"Oem":{"Huawei":{"BootEnable":True}}}

    try:
        r = request('PATCH',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])
        if r.status_code == 200:
            r = r.json()
            log.info(ibmc['ip'] + " -- set boot enable successful!")
            result = r[u'Oem'][u'Huawei'][u'BootEnable']
            
        elif r.status_code == 412:
            log.error(ibmc['ip'] + " -- set boot enable failed, percondition is fault,maybe th etag is error!")
            result = False
        else:
            log.error(ibmc['ip'] + " -- set boot enable failed,unknown reason,error info:" + str(r.status_code))
            result = False

    except Exception,e:
        log.exception(ibmc['ip'] + " -- set boot enable failed! " + str(e))
        result = False 
        raise

    return result



'''
#==========================================================================
# @Method: config raid
# @command: 
# @Param: filepath ibmc url
# @date: 2017.10.31
#==========================================================================
'''
def cfgRaid(filepath, ibmc, root_uri, system_uri):
    ret = {'result':True,'msg': ''}
    #before config raid, make sure x86 is power on state!
    powerState = managePower('PowerState', ibmc, root_uri, system_uri)
    log.info(ibmc['ip'] + " -- power state:%s" %str(powerState))
    if powerState.find("On") == -1:
        log.error(ibmc['ip'] + " -- the system is poweroff, make sure the system is power on , wait 5 mins and try it again! \n")
        report.error(ibmc['ip'] + " -- the system is poweroff, make sure the system is power on , wait 5 mins and try it again! \n")
        ret['result'] = False
        ret['msg'] = "the system is poweroff, make sure the system is power on , wait 5 mins and try it again!"
        return ret

    #parse ini file and get image config file
    config = ConfigParser.ConfigParser()
    config.read(filepath)

    ForceCreate = config.get("config","ForceCreate")
    CapacityBytes = config.get("config","CapacityBytes")
    OptimumIOSizeBytes = config.get("config","OptimumIOSizeBytes")
    CreateCacheCadeFlag = config.get("config","CreateCacheCadeFlag")
    Drives = config.get("config","Drives")
    VolumeRaidLevel = config.get("config","VolumeRaidLevel")
    VolumeName = config.get("config","VolumeName")
    DefaultReadPolicy = config.get("config","DefaultReadPolicy")
    DefaultWritePolicy = config.get("config","DefaultWritePolicy")
    DefaultCachePolicy = config.get("config","DefaultCachePolicy")
    SpanNumber = config.get("config","SpanNumber")
    AccessPolicy = config.get("config","AccessPolicy")
    DriveCachePolicy = config.get("config","DriveCachePolicy")
    InitializationMode = config.get("config","InitializationMode")
    BootEnable = config.get("config","BootEnable")

    #delete all ld,else sleep 20s to avoid constinous config raid problem
    if ForceCreate.find('Y') != -1:
        result = deletAllLd(ibmc, root_uri, system_uri)
        if result == False:
            ret['result'] = False
            ret['msg'] = "may be the raid card does not support this option!"
            return ret
    else:
        time.sleep(20)
    
    HuaweiDict = {} 
    if CreateCacheCadeFlag != "":
        HuaweiDict['CreateCacheCadeFlag'] = bool(string.atoi(CreateCacheCadeFlag))
    if Drives != "":
        Drives = Drives.split(',')
        diskArr = []
        for Drive in Drives:
             diskArr.append(string.atoi(Drive))
        HuaweiDict['Drives'] = diskArr 
    if VolumeRaidLevel != "":
        HuaweiDict['VolumeRaidLevel'] = VolumeRaidLevel
    if VolumeName != "":
        HuaweiDict['VolumeName'] = VolumeName
    if DefaultReadPolicy != "":
        HuaweiDict['DefaultReadPolicy'] = DefaultReadPolicy
    if DefaultWritePolicy != "":
        HuaweiDict['DefaultWritePolicy'] = DefaultWritePolicy
    if DefaultCachePolicy != "":
        HuaweiDict['DefaultCachePolicy'] = DefaultCachePolicy
    if SpanNumber != "":
        SpanNumber = string.atoi(SpanNumber)
        HuaweiDict['SpanNumber'] = SpanNumber
    if AccessPolicy != "":
        HuaweiDict['AccessPolicy'] = AccessPolicy
    if DriveCachePolicy != "":
        HuaweiDict['DriveCachePolicy'] = DriveCachePolicy
    if InitializationMode != "":
        HuaweiDict['InitializationMode'] = InitializationMode

    oemDict = {}
    oemDict['Huawei'] = HuaweiDict

    playloadDict = {}
   # if CapacityBytes != "":
   #     playloadDict['CapacityBytes'] = CapacityBytes
    if OptimumIOSizeBytes != "":
        OptimumIOSizeBytes = string.atoi(OptimumIOSizeBytes)
        playloadDict['OptimumIOSizeBytes'] = OptimumIOSizeBytes
    if HuaweiDict is not None:
        playloadDict['Oem'] = oemDict
 
    taskId = ''
    status = ''
    try:
        #sleep 20s
        loopCreate1 = 0
        loopCreate2 = 0
        loopBootEnable = 0
        time.sleep(20)
        log.info("playload:%s , uri:%s" %(str(playloadDict),root_uri + system_uri))
        r = creatLD(ibmc, playloadDict, root_uri, system_uri)

        if r.status_code == 202:
            result = r.json()
            taskId = result[u'@odata.id']
            status = result[u'TaskState']
            while 1:
                 log.info("taskId:%s" %(str(taskId)))
                 taskResult = getTaskStatus(ibmc, taskId, root_uri)
                 if taskResult[0].find("Running") != -1:
                     time.sleep(1)
                     continue
                 elif taskResult[0].find("Successful") != -1:
                     if BootEnable == 'Y':
                         log.info(ibmc['ip'] + " -- create %s successful! \n" %VolumeRaidLevel)
                         report.info(ibmc['ip'] + " -- create %s successful!" %VolumeRaidLevel )
                         time.sleep(20)
                         result = setBootEnable(ibmc, taskResult[1])
                         # to fix windows create ld failed that after remove ld and then system reboot
                         while loopBootEnable <= 20 and result != True:
                             time.sleep(20)
                             result = setBootEnable(ibmc, taskResult[1])
                             loopBootEnable += 1
                             log.info(ibmc['ip'] + " -- loopBootEnable:%s" %str(loopBootEnable))
                         if result == True:
                             log.info(ibmc['ip'] + " -- set %s as boot enable successful!\n" %VolumeRaidLevel)
                             report.info(ibmc['ip'] + " -- set %s as boot enable successful!" %VolumeRaidLevel)
                             ret['result'] = True
                             ret['msg'] = "Successful"
                             return ret

                         else:
                             log.info(ibmc['ip'] + " -- set %s as boot enable failed! %s" %(VolumeRaidLevel ,taskResult[1]) )
                             report.info(ibmc['ip'] + " -- set %s as boot enable failed! %s" %(VolumeRaidLevel ,taskResult[1]) )
                             ret['result'] = False
                             ret['msg'] = "set " + VolumeRaidLevel + " as boot enable failed!" + taskResult[1]
                             return ret
                     else:
                         log.info(ibmc['ip'] + " -- create %s successful! \n" %VolumeRaidLevel)
                         report.info(ibmc['ip'] + " -- create %s successful! " %VolumeRaidLevel)
                         ret['result'] = True
                         ret['msg'] = "Successful"
                         return ret

                 else:
                     if loopCreate2 <= 20:
                         time.sleep(20)
                         log.info("playload:%s , uri:%s" %(str(playloadDict),root_uri + system_uri))
                         result = creatLD(ibmc, playloadDict, root_uri, system_uri)
                         result = result.json()
                         taskId = result[u'@odata.id']
                         loopCreate2 += 1
                         log.info(ibmc['ip'] + " -- loopCreate2:%d" %loopCreate2)
                     else: 
                         log.info(ibmc['ip'] + " -- create %s failed! %s" %(VolumeRaidLevel,taskResult[1]))
                         report.info(ibmc['ip'] + " -- create %s failed! %s" %(VolumeRaidLevel,taskResult[1]))
                         ret['result'] = False
                         ret['msg'] = "create " + VolumeRaidLevel + " failed!" + taskResult[1]
                         return ret
                 
        else:
            log.error(ibmc['ip'] + " -- create  %s failed! error info:%s" %(VolumeRaidLevel, str(result.json())))
            report.error(ibmc['ip'] + " -- create  %s failed! error info:%s" %(VolumeRaidLevel, str(result.json())))
            ret['result'] = False
            ret['msg'] = "Create logic device failed!"
            return ret

    except Exception,e:
        log.error(ibmc['ip'] + " -- create logic device failed! error info:%s" %str(e))
        report.info(ibmc['ip'] + " -- create logicv device failed! error info:%s" %str(e))
        raise


if __name__ == '__main__':
    main()
 
