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

global token

# snmp config ini file
snmpConfigPath = "/etc/ansible/ansible_ibmc/configFile/snmpCfg/snmpTrap.ini"

LOG_FILE = "/etc/ansible/ansible_ibmc/log/cfgSnmpLog.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/cfgSnmpReport.log"

log_hander = logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes = 1024*1024,backupCount = 5)  
report_hander = logging.handlers.RotatingFileHandler(REPORT_FILE,maxBytes = 1024*1024,backupCount = 5)  
fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
log_hander.setFormatter(fmt)
report_hander.setFormatter(fmt)

log = logging.getLogger('cfgSnmpLog')
log.addHandler(log_hander)
log.setLevel(logging.INFO)  

report = logging.getLogger('cfgSnmpReport')
report.addHandler(report_hander)  
report.setLevel(logging.INFO)



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
def cfgTrap(ibmc, root_uri, manage_uri):

    ret = {'result':True,'msg': ''}
    #parse ini file
    config = ConfigParser.ConfigParser()
    config.read(snmpConfigPath)

    ServiceEnabled = config.get("snmpTrapNotification","ServiceEnabled")
    TrapVersion = config.get("snmpTrapNotification","TrapVersion")
    TrapV3User = config.get("snmpTrapNotification","TrapV3User")
    TrapMode = config.get("snmpTrapNotification","TrapMode")
    TrapServerIdentity = config.get("snmpTrapNotification","TrapServerIdentity")
    AlarmServerity = config.get("snmpTrapNotification","AlarmServerity")
    TrapDestNum = config.get("snmpTrapNotification","TrapDestNum")
    
    HuaweiDict = {} 
    if ServiceEnabled != "":
        if ServiceEnabled == "Y":
            ServiceEnabled = True
        else:
            ServiceEnabled = False
        HuaweiDict['ServiceEnabled'] = ServiceEnabled
    if TrapVersion != "":
        HuaweiDict['TrapVersion'] = TrapVersion
    if TrapV3User != "":
        HuaweiDict['TrapV3User'] = TrapV3User
    if TrapMode != "":
        HuaweiDict['TrapMode'] = TrapMode
    if TrapServerIdentity != "":
        HuaweiDict['TrapServerIdentity'] = TrapServerIdentity
    if TrapDestNum != "":
        TrapDestNum = string.atoi(TrapDestNum)
    #if community != "":
    #    HuaweiDict['CommunityName'] = community
   
    if TrapDestNum > 0:
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

    HuaweiDict['TrapServer'] = trapServerDicts

    playloadDict = {}
    if HuaweiDict is not None:
        playloadDict['SnmpTrapNotification'] = HuaweiDict
 
    try:
        result = cfgSnmpTrap(ibmc, playloadDict, root_uri, manage_uri)
        if result.status_code == 200:
            result = result.json()
            log.info(ibmc['ip'] + " -- " + "config snmp trap successful! ")
            report.info(ibmc['ip'] + " -- " + "config snmp trap successful! ")
            ret['result'] = True
            ret['msg'] = "config snmp trap successful!"
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


if __name__ == '__main__':
    main()
 
