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
sys.path.append("/etc/ansible/ansible_ibmc/scripts/")
from cfgBmc import *
from powerManage import *
from commonLoger import *
global token


LOG_FILE = "/etc/ansible/ansible_ibmc/log/cfgSnmpLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/cfgSnmpReport.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"cfgSnmpReport")



'''
#==========================================================================
# @Method: config snmp trap
# @command: 
# @Param: filepath ibmc url
# @date: 2017.12.25
#==========================================================================
'''
def cfgSnmpTrap(ibmc, payload, root_uri, manager_uri):
    uri = root_uri + manager_uri + "/SnmpService"

    token = getToken()
    eTag = getEtag(ibmc,uri)
    headers = {'content-type': 'application/json','X-Auth-Token':token, 'If-Match': eTag}

    try:
        r = request('PATCH',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])

    except Exception,e:
        log.exception(ibmc['ip'] + " -- " +"config snmp trap failed! " + str(e))
        raise

    return r



'''
#==========================================================================
# @Method: config snmp Trap
# @command: 
# @Param: filepath ibmc url
# @date: 2017.12.25
#==========================================================================
'''
def cfgTrap(filepath, community, ibmc, root_uri, manager_uri):

    ret = {'result':True,'msg': ''}
    #parse ini file
    if filepath.lower() == "getinfo":
        ret = getTrapcfg(ibmc, root_uri, manager_uri)
        return ret
        
    config = ConfigParser.ConfigParser()
    config.read(filepath)
    try:
        ServiceEnabled = config.get("snmpTrapNotification","ServiceEnabled")
    except Exception , e:
        ServiceEnabled=''
        log.info(" get MaxPollingInterval param exception"+ str(e))  
    
    try:
        TrapVersion = config.get("snmpTrapNotification","TrapVersion")
    except Exception , e:
        TrapVersion=''
        log.info(" get MaxPollingInterval param exception"+ str(e))  
    
    try:
        TrapV3User = config.get("snmpTrapNotification","TrapV3User")
    except Exception , e:
        TrapV3User=''
        log.info(" get MaxPollingInterval param exception"+ str(e))      
    
    try:    
        TrapMode = config.get("snmpTrapNotification","TrapMode")
    except Exception , e:
        TrapMode=''
        log.info(" get MaxPollingInterval param exception"+ str(e))  
    
    try:    
        TrapServerIdentity = config.get("snmpTrapNotification","TrapServerIdentity")
    except Exception , e:
        TrapServerIdentity=''
        log.info(" get MaxPollingInterval param exception"+ str(e))      
    
    try:    
        AlarmSeverity = config.get("snmpTrapNotification","AlarmSeverity")
    except Exception , e:
        AlarmSeverity=''
        log.info(" get MaxPollingInterval param exception"+ str(e))  
    
    try:        
        TrapDestNum = config.get("snmpTrapNotification","TrapDestNum")
    except Exception , e:
        TrapDestNum=''
        log.info(" get MaxPollingInterval param exception"+ str(e))      
    
    CommunityName = community
    
    HuaweiDict = {} 
    if ServiceEnabled != "":
        if ServiceEnabled == "Y":
            ServiceEnabled = True
        else:
            ServiceEnabled = False
        HuaweiDict['ServiceEnabled'] = ServiceEnabled
    if TrapVersion != "":
        HuaweiDict['TrapVersion'] = TrapVersion
    if TrapVersion != "":
        if TrapVersion == "V3" and TrapV3User != "":
            HuaweiDict['TrapVersion'] = TrapVersion
            HuaweiDict['TrapV3User'] = TrapV3User
        else:
            HuaweiDict['TrapVersion'] = TrapVersion
            HuaweiDict['CommunityName'] = CommunityName
    if TrapMode != "":
        HuaweiDict['TrapMode'] = TrapMode
    if TrapServerIdentity != "":
        HuaweiDict['TrapServerIdentity'] = TrapServerIdentity
    if TrapDestNum != "":
        TrapDestNum = string.atoi(TrapDestNum)
    if AlarmSeverity != "":
        HuaweiDict['AlarmSeverity'] = AlarmSeverity   
   
    if  TrapDestNum != '' and TrapDestNum > 0:
        trapServerDicts = []
        for i in range(0,TrapDestNum):
            trapServerDict = {}
            trapDest = "trapDest" + str(i+1)
            if config.has_section(trapDest) is False:
                log.error(ibmc['ip'] + " -- the snmpTrap.ini file of section:" + trapDest + " does not exist!")
                continue
            TrapEnabled = config.get(trapDest,"TrapEnabled")
            TrapServerAddress = config.get(trapDest,"TrapServerAddress")
            TrapServerPort = config.get(trapDest,"TrapServerPort")

            if TrapEnabled != "":
                if TrapEnabled == "Y":
                    TrapEnabled = True
                else:
                    TrapEnabled = False
                trapServerDict['Enabled'] = TrapEnabled
            if TrapServerAddress != "":
                trapServerDict['TrapServerAddress'] = TrapServerAddress
            if TrapServerPort != "":
                TrapServerPort = string.atoi(TrapServerPort)
                trapServerDict['TrapServerPort'] = TrapServerPort
            trapServerDicts.append(trapServerDict)
    else :
        trapServerDicts={}
    HuaweiDict['TrapServer'] = trapServerDicts

    playloadDict = {}
    if HuaweiDict is not None:
        playloadDict['SnmpTrapNotification'] = HuaweiDict
 
    try:
        result = cfgSnmpTrap(ibmc, playloadDict, root_uri, manager_uri)
        if result.status_code == 200:
            log.info(ibmc['ip'] + " -- " + "config snmp trap successful! "+"==== respon:"+str(result.json()))
            report.info(ibmc['ip'] + " -- " + "config snmp trap successful! "+"==== respon:"+str(result.json()))
            ret['result'] = True
            ret['msg'] = "config snmp trap successful!"+"==== respon:"+str(result.json())
            return ret
        else:
            log.info(ibmc['ip'] + " -- " +"config snmp trap failed!" + str(result.json()))
            report.info(ibmc['ip'] + " -- " +"config snmp trap failed!" + str(result.json()))
            ret['result'] = False
            ret['msg'] = "config snmp trap failed!"
            return ret

    except Exception,e:
        log.info(ibmc['ip'] + " -- " + "config snmp trap failed!" + str(e))
        report.info(ibmc['ip'] + " -- " + "config snmp trap failed!" + str(e))
        raise
        
def getTrapcfg(ibmc, root_uri, manager_uri):
    uri = root_uri + manager_uri + "/SnmpService"
    ret = {'result':True,'msg': ''}
    token = getToken()
    headers = {'content-type':'application/json','X-Auth-Token':token}
    payload = {}

    try:
        r = request('GET',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])
    except Exception,e:
        log.exception(ibmc['ip'] + " -- " +"config snmp trap failed! " + str(e))
        raise
    if r.status_code == 200:
        if 'SnmpTrapNotification' in  r.json().keys():
            fileName= str(ibmc['ip'])+"_trapInfo.json" 
            ret['msg']='get snmp trap successful! please refer to /etc/ansible/ansible_ibmc/report/%s for detail'%fileName
            log.info(ibmc['ip'] + " -- " + "get snmp trap successful! snmpInfo json is:" +str(r.json()['SnmpTrapNotification']) )
            report.info(ibmc['ip'] + " -- " + "get snmp trap successful! snmpInfo json is:"+str(r.json()['SnmpTrapNotification']))
            jsonfile=None
            try:
                jsonfile = open ( '/etc/ansible/ansible_ibmc/report/'+fileName,"w")
                if jsonfile is not None :
                    json.dump(r.json(),jsonfile,indent=4) 
            except Exception ,e:
                log.error( str(ibmc["ip"])+"write json exception :"+str(e) )
            finally:
                if jsonfile is not None:
                    jsonfile.close()
        else:
            log.info(ibmc['ip'] + " -- " + "parse snmp trap info  failed! return json is:" + str(r.json()))

    else:
        ret['result'] =False
        ret['msg']='get snmp trap failed!'
        log.info(ibmc['ip'] + " -- " + "get snmp trap failed!" )
        report.info(ibmc['ip'] + " -- " + "get snmp trap failed!" )    
    return ret
    
    
if __name__ == '__main__':
    main()
 
