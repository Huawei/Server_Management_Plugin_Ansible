#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2017, Huawei.
# Author: Ray
# Date: 20180411
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
from commonLoger import *

LOG_FILE = "/etc/ansible/ansible_ibmc/log/deploySPOsLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/deploySPOsReport.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"deploySPOsReport")

global token


'''
#==========================================================================
# @Method: check iBMC version
# @command: 
# @Param:  ibmc
# @date: 2018.4.24
#==========================================================================
'''
def checkBMCVersion(ibmc, root_uri,manager_uri):
    ret = {'result':True,'msg': ''}
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + manager_uri
    payload = {}
    try:
        r = request('GET',resource=uri,headers=headers,data=payload, tmout=10,ip=ibmc['ip'])
        rjson = r.json()
        version = rjson[u'FirmwareVersion']
        if r.status_code == 200:
            if version >= '3.00':
                log.info(ibmc['ip'] + " -- the iBMC version is greater than 3.00, match the redfish interface requirement, continue! \n")
                ret['result'] = True
                ret['msg'] = 'the iBMC version is greater than 3.00, match the redfish interface requirement,continue!'                
            else:
                log.info(ibmc['ip'] + " -- the iBMC version is lower than 3.00, please upgrade the iBMC to 3.00 or later! \n")
                ret['result'] = False
                ret['msg'] = 'the iBMC version is lower than 3.00, please upgrade the iBMC to 3.00 or later'                         
        else:
            log.info(ibmc['ip'] + " -- get iBMC version failed! error code:%s \n" %str(r.status_code))
            ret['result'] = False
            ret['msg'] = "%s, %s" %(rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Message'], rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Resolution'])
    except Exception, e:
        log.info(ibmc['ip'] + " -- exception had occured when getting iBMC version ! %s \n" %str(e) )
        ret['result'] = False
        ret['msg'] = 'exception had occured when getting iBMC version !' + str(e)
    finally:
        return ret


'''
#==========================================================================
# @Method: check SP version
# @command: 
# @Param:  ibmc
# @date: 2018.4.24
#==========================================================================
'''
def checkSPVersion(ibmc, root_uri,manager_uri):
    ret = {'result':True,'msg': ''}
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    uri = root_uri + manager_uri + "/SPService"
    payload = {}
    try:
        r = request('GET',resource=uri,headers=headers,data=payload, tmout=10,ip=ibmc['ip'])
        rjson = r.json()
        APPVersion = rjson[u'Version'][u'APPVersion']
        OSVersion = rjson[u'Version'][u'OSVersion']
        DataVersion = rjson[u'Version'][u'DataVersion']
        if r.status_code == 200:
            if min(APPVersion,OSVersion,DataVersion) >= '1.09':
                log.info(ibmc['ip'] + " -- the SP version is greater than 1.09, match the redfish interface requirement! \n")
                ret['result'] = True
                ret['msg'] = 'the SP version is greater than 1.09, match the redfish interface requirement!'                
            else:
                log.info(ibmc['ip'] + " -- the SP version is lower than 1.09, please upgrade the SP to 1.09 or later! \n")
                ret['result'] = False
                ret['msg'] = 'the SP version is lower than 1.09, please upgrade the SP to 1.09 or later!'                         
        else:
            log.info(ibmc['ip'] + " -- get SP version failed! error code:%s \n" %str(r.status_code))
            ret['result'] = False
            ret['msg'] = "%s %s" %(rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Message'], rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Resolution'])
    except Exception, e:
        log.info(ibmc['ip'] + " -- exception had occured when getting SP version ! %s \n" %str(e))
        ret['result'] = False
        ret['msg'] = 'exception had occured when getting SP version !' + str(e)
    finally:
        return ret
        

'''
#==========================================================================
# @Method: query VMM status
# @command: 
# @Param:  ibmc
# @date: 2018.4.8
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
# @Method: mount image file
# @command: mountFile
# @Param: filepath ibmc url
# @date: 2018.4.8
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
# @Method: unmount image file
# @command: unmountFile
# @Param: filepath ibmc url
# @date: 2018.4.8
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
# @Method: config OS
# @command: 
# @Param: ini file path, ibmc, root_uri, manager_uri
# @date: 2018.4.11
#==========================================================================
'''

def configOS(info,ibmc,root_uri,manager_uri):

    ret = {'result':True,'msg': ''}
    #parse ini file
    config = open(info, 'r')
    content = json.load(config)
    config.close()
    
    #send restful request 
    token = getToken()
    #get interface id
    uri = root_uri + manager_uri + "/SPService/SPOSInstallPara"

    #get etag for headers
    Etag = getEtag(ibmc,uri)
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}

    try:
        r = request('POST',resource=uri,headers=headers,data=content,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        rjson = r.json()
        if result == 201:
            report.info(ibmc['ip'] + " -- post os config parament successfully!")
            log.info(ibmc['ip'] + " -- post os config parament successfully! \n")
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            report.info(ibmc['ip'] + " -- post os config parament failed! error code:%s" %str(result))
            log.info(ibmc['ip'] + " -- post os config parament failed! error code:%s\n" %str(result))
            ret['result'] = False
            ret['msg'] = "%s, %s" %(rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Message'], rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Resolution'])
    except Exception, e:
        report.info(ibmc['ip'] + " -- post os config parament failed! %s" %str(e))
        log.info(ibmc['ip'] + " -- post os config parament failed! %s \n" %str(e) )
        ret['result'] = False
        ret['msg'] = 'post os config parament failed! ' + str(e)
    finally:
        return ret
    

'''
#==========================================================================
# @Method: set SP Result Finished
# @command: 
# @Param: filepath ibmc url
# @date: 2018.4.8
#==========================================================================
'''    
def setSPFinished(ibmc,root_uri,manager_uri):
    uri = root_uri + manager_uri + "/SPService"
    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
    playload = {"SPFinished": True}
    
    ret = {'result':True,'msg': ''}

    try:
        r = request('PATCH',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        rjson = r.json()
        if result == 200:
            log.info(ibmc['ip'] + " -- set SP result finished successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            log.info(ibmc['ip'] + " -- set SP result finished failed! error code is: %s \n" %result)
            ret['result'] = False
            ret['msg'] = "%s, %s" %(rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Message'], rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Resolution'])

    except Exception, e:
        report.info(ibmc['ip'] + " -- " + "set SP result finished failed!" + str(e))
        log.info(ibmc['ip'] + " -- " + "set SP result finished failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'set SP result finished failed! ' + str(e)
    finally:
        return ret     
    
    
'''
#==========================================================================
# @Method: set BootDevice as SP
# @command: 
# @Param: filepath ibmc url
# @date: 2018.4.8
#==========================================================================
'''    
def setSPStartEnabled(ibmc,root_uri,manager_uri):
    uri = root_uri + manager_uri + "/SPService"
    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
    playload = {"SPStartEnabled": True,"SysRestartDelaySeconds": "30","SPTimeout": "1800","SPFinished": True}
    # The SPTimeout 1800s is the time for SP Init status to Deploying status, after the status change to Deploying, the timeout valut is controlled by SP itsself.
    
    ret = {'result':True,'msg': ''}

    try:
        r = request('PATCH',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        rjson = r.json()
        if result == 200:
            log.info(ibmc['ip'] + " -- set boot device as SP successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            log.info(ibmc['ip'] + " -- set boot device as SP failed! error code is: %s \n" %result)
            ret['result'] = False
            ret['msg'] = "%s, %s" %(rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Message'], rjson[u'error'][u'@Message.ExtendedInfo'][0][u'Resolution'])

    except Exception, e:
        report.info(ibmc['ip'] + " -- " + "set boot device as SP failed!" + str(e))
        log.info(ibmc['ip'] + " -- " + "set boot device as SP failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'set boot device as SP failed! ' + str(e)
    finally:
        return ret 
      
    
def checkOSResult(ibmc,root_uri,manager_uri):
    uri = root_uri + manager_uri + "/SPService/SPResult/1"
    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
    playload = {}
    rets = {'SPStatus':'','OSProgress':'','OSStatus':'','OSStep':'','OSErrorInfo':''}

    try:
        r = request('GET',resource=uri,headers=headers,data=playload,tmout=100,ip=ibmc['ip'])
        code = r.status_code
        r = r.json()
        if code == 200:
            SPStatus = r[u'Status']
            rets['SPStatus'] = SPStatus
            log.info(ibmc['ip'] + ": SP Status is %s\n"%SPStatus)
            if SPStatus == "Deploying" or SPStatus == "Running" or SPStatus == "Finished":
                rets['OSProgress'] = r[u'OSInstall'][u'Progress']
                rets['OSStatus'] = r[u'OSInstall'][u'Results'][0][u'Status']
                rets['OSStep'] = r[u'OSInstall'][u'Results'][0][u'Step']            
                rets['OSErrorInfo'] = r[u'OSInstall'][u'Results'][0][u'ErrorInfo']
        else:
            log.info(ibmc['ip'] + " -- get the sp result failed! error code is %s\n" %code)
    except Exception, e:
        log.info(ibmc['ip'] + " -- " + "exception is thrown, get the sp result failed!" + str(e) + " \n" )
        raise
    finally:
        return rets
    
    
'''
#==========================================================================
# @Method: deploy os process 
# @command: 
# @Param: filepath ibmc url
# @date: 2018.4.8
#==========================================================================
'''
def deploySPOSProcess(filepath, ibmc, root_uri, system_uri, manager_uri):
    rets = {'result':True,'msg': ''}

    #Check the BMC version
    rets = checkBMCVersion(ibmc, root_uri, manager_uri)
    if rets['result'] == False:
        return rets    
    
    #Check the SP version
    rets = checkSPVersion(ibmc, root_uri, manager_uri)
    if rets['result'] == False:
        return rets  
    
    #get vmm is connected
    rets = vmmIsConnected(ibmc, root_uri, manager_uri)
    log.info(ibmc['ip'] + " --vmm is connected:"+str(rets))
    #if is connected,disconnect first
    if rets == True:
        log.info(ibmc['ip'] + " -- vmm is connected before,unmount ! ")
        unMountFile(ibmc, root_uri,manager_uri)
        time.sleep(5)

    # Power off the X86 system to make sure the SP is not running
    rets = managePower("PowerOff", ibmc, root_uri, system_uri)
    if rets['result'] == True:
        log.info(ibmc['ip'] + " -- Power off x86 System successfully!")
    else:
        log.error(ibmc['ip'] + " -- Power off x86 System failed!")
        report.error(ibmc['ip'] + " -- Power off Operation System failed!")
        rets['result'] = False
        rets['msg'] = "Power off Operation System failed!"
        return rets
    time.sleep(10)

    #parse ini file and get image config file
    config = ConfigParser.ConfigParser()
    config.read(filepath)
    osImg = config.get("ConfigOS","osImg")
    osConfig = config.get("ConfigOS","osConfig")
    rets = configOS(osConfig, ibmc, root_uri, manager_uri)
    if rets['result'] == False:
        managePower("PowerOff", ibmc, root_uri, system_uri)
        time.sleep(15)
        configOS(osConfig, ibmc, root_uri, manager_uri)
        return rets  

    #Set SP Finished, in order to avoid the impact of last result 
    rets = setSPFinished(ibmc, root_uri, manager_uri)
    if rets['result'] == False:
        log.info(ibmc['ip'] + " -- set sp result finished failed, please try it again! ")
        report.error(ibmc['ip'] + " -- set sp result finished failed, please try it again!")
        return rets
        
    #Set SP enabled
    rets = setSPStartEnabled(ibmc, root_uri, manager_uri)
    if rets['result'] == False:
        log.info(ibmc['ip'] + " -- sp start enable failed, please try it again! ")
        report.error(ibmc['ip'] + " -- sp start enable failed, please try it again!")
        return rets

    #mount OS iso image
    rets = mountFile(osImg, ibmc, root_uri, manager_uri)
    if rets != 202:
        unMountFile(ibmc, root_uri, manager_uri)
        log.error(ibmc['ip'] + " -- install OS failed! please check the OS image is exist or not!")
        report.error(ibmc['ip'] + " -- install OS failed! please check the OS image is exist or not!")
        rets['result'] = False
        rets['msg'] = "install OS failed! please check the OS image is exist or not!"
        return rets

    # Start the X86 system to make the os config task avaliable and install the OS.
    rets = managePower("PowerOn", ibmc, root_uri, system_uri)
    if rets['result'] == True:
        log.info(ibmc['ip'] + " -- power on the X86 system successfully!")
    else:
        log.error(ibmc['ip'] + " -- install os failed! power on x86 System failed!")
        report.error(ibmc['ip'] + " -- install os failed! power on x86 System failed!")
        rets['result'] = False
        rets['msg'] = "reboot system failed!"
        return rets
    time.sleep(5)

    # check the OS install result
    try:
        loopInstall = 0
        while 1:
            loopInstall += 1
            status = checkOSResult(ibmc, root_uri, manager_uri)
            SPStatus = status[u'SPStatus']
            OSStatus = status[u'OSStatus']
            OSProgress = status[u'OSProgress']
            OSStep = status[u'OSStep']
            OSErrorInfo = status[u'OSErrorInfo']
            log.info(ibmc['ip'] + " -- loopInstall:" + str(loopInstall) + " SPStatus:%s, OSProgress:%s, OSStatus:%s, OSStep:%s, OSErrorInfo:%s \n"%(SPStatus,OSProgress,OSStatus,OSStep,OSErrorInfo))         
            if SPStatus == "Init":
                log.info(ibmc['ip'] + " -- SP is initial, please wait!")
                time.sleep(60)
            elif SPStatus == "Deploying" or SPStatus == "Running":
                log.info(ibmc['ip'] + " -- SP is %s" %SPStatus)
                time.sleep(60)
                # the sleep time 60s is waiting for iBMA starting up otherwise we could not get the info like OSProgress and OSErrorInfo from SP
                  
                if OSStatus == "Successful" or OSStatus == "successful":
                    log.info(ibmc['ip'] + " -- os install successfully")
                    report.info(ibmc['ip'] + " -- os install successfully")
                elif OSStatus == "Progressing":
                    log.info(ibmc['ip'] + " -- os install progress is %s, in step: %s"%(OSProgress, OSStep))
                else:
                    time.sleep(30)
                    log.error(ibmc['ip'] + " -- os install has unknown error! ErrorInfo: %s" % OSErrorInfo)
                    report.error(ibmc['ip'] + " -- os install has unknown error! ErrorInfo: %s" %OSErrorInfo)
            elif SPStatus == "Finished" and OSStatus == "Successful" and OSProgress == "100":
                log.info(ibmc['ip'] + " -- os install successfully")
                report.info(ibmc['ip'] + " -- os install successfully")
                rets['result'] = True
                rets['msg'] = "os install successfully!"            
                return rets
            elif SPStatus == "Timeout" or SPStatus == "Idle":
                log.error(ibmc['ip'] + " -- SP status is %s, please check it again!" %SPStatus)
                report.error(ibmc['ip'] + " -- SP status is %s,please check it again!" %SPStatus)
                rets['result'] = False
                rets['msg'] = "please check it again, SP status is " + SPStatus
                return rets
            else:
                time.sleep(60)
                # the sleep time 60s is waiting for getting the info like OSProgress and OSErrorInfo from SP when sp stutas changes to finished
                # get the OS deploy Error Information
                status = checkOSResult(ibmc, root_uri, manager_uri)
                OSErrorInfo = status[u'OSErrorInfo']
                log.error(ibmc['ip'] + " -- install OS has unknown error! ErrorInfo: %s" % OSErrorInfo)
                report.error(ibmc['ip'] + " -- install OS has unknown error! ErrorInfo: %s" % OSErrorInfo)
                rets['result'] = False
                rets['msg'] = "install OS has unknown error!" + OSErrorInfo
                return rets
            if loopInstall >= 60:
                log.error(ibmc['ip'] + " -- too many times loop, install OS has time out,please try it again!")
                report.error(ibmc['ip'] + " -- too many times loop, install OS has time out,please try it again!")
                rets['result'] = False
                rets['msg'] = "too many times loop, install OS has time out,please try it again!"
                return rets
    except Exception, e:
        rets['result'] = False
        rets['msg'] = "install OS failed! exception error info：" + str(e)
        log.info(ibmc['ip'] + " -- install OS failed! exception error info：" + str(e))
        report.info(ibmc['ip'] + " -- install OS failed! exception error info：" + str(e))
        return rets
    finally:
        unMountFile(ibmc, root_uri, manager_uri)

if __name__ == '__main__':
    main()

