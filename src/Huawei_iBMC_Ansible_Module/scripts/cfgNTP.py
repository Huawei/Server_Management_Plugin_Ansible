#!/usr/bin/env python
# -*- coding: utf-8 -*-

# (c) 2018, Huawei.
#
# This file is part of Ansible, for bmc ntp config
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

global token

# ntp config ini file


LOG_FILE = "/etc/ansible/ansible_ibmc/log/cfgNTP.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/cfgNTP.log"

log_hander = logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes = 1024*1024,backupCount = 5)  
report_hander = logging.handlers.RotatingFileHandler(REPORT_FILE,maxBytes = 1024*1024,backupCount = 5)  
fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
log_hander.setFormatter(fmt)
report_hander.setFormatter(fmt)

log = logging.getLogger('cfgNTPLog')
log.addHandler(log_hander)
log.setLevel(logging.INFO)  

report = logging.getLogger('cfgNTPReport')
report.addHandler(report_hander)  
report.setLevel(logging.INFO)

# check ip validation
def checkip(ip):
    if ip == '':
        return True

    ips = ip.split('.')

    if len(ips) != 4:
        return False
    for index in range(4):
       ipsVal = string.atoi(ips[index])
       if ipsVal > 255 or ipsVal < 0:
           return False
    return True



'''
#==========================================================================
# @Method: config bmc ntp
# @command: 
# @Param: inifile path, ibmc, root_uri, manager_uri
# @date: 2018.3.21
#==========================================================================
'''

def configNTP(info,ibmc,root_uri,manager_uri):

    ret = {'result':True,'msg': ''}
    #parse ini file
    config = ConfigParser.ConfigParser()
    config.read(info)

    ServiceEnabled = config.get("NTP","ServiceEnabled").upper()
    AlternateNtpServer = config.get("NTP","AlternateNtpServer")
    PreferredNtpServer = config.get("NTP","PreferredNtpServer")
    ServerAuthenticationEnabled = config.get("NTP","ServerAuthenticationEnabled").upper()
    NtpAddressOrigin = config.get("NTP","NtpAddressOrigin")
    MinPollingInterval = string.atoi(config.get("NTP","MinPollingInterval"))
    MaxPollingInterval = string.atoi(config.get("NTP","MaxPollingInterval"))

    HuaweiDict = {} 
    if ServiceEnabled != "":
        if ServiceEnabled == "TRUE":
            ServiceEnabled = True
        elif ServiceEnabled == "FALSE":
            ServiceEnabled = False
        else:
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is not valid, please config it again!' %ServiceEnabled}
            return ret
        HuaweiDict['ServiceEnabled'] = ServiceEnabled

    if checkip(AlternateNtpServer) == True:
        HuaweiDict['AlternateNtpServer'] = AlternateNtpServer
    else:
        ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is not valid, please config it again!' %AlternateNtpServer} 
        return ret

    if checkip(PreferredNtpServer) == True:
        HuaweiDict['PreferredNtpServer'] = PreferredNtpServer
    else:
        ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is not valid, please config it again!' %PreferredNtpServer}
        return ret

    if ServerAuthenticationEnabled != "":
        if ServerAuthenticationEnabled == "TRUE":
            ServerAuthenticationEnabled = True
        elif ServerAuthenticationEnabled == "FALSE":
            ServerAuthenticationEnabled = False
        else:
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is not valid, please config it again!' %ServerAuthenticationEnabled}
            return ret
        HuaweiDict['ServerAuthenticationEnabled'] = ServerAuthenticationEnabled

    if NtpAddressOrigin != "":
        if NtpAddressOrigin != "IPv4" and NtpAddressOrigin != "IPv6" and NtpAddressOrigin != "Static":
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is not valid, please config it again!' %NtpAddressOrigin}
            return ret
        else:
            HuaweiDict['NtpAddressOrigin'] = NtpAddressOrigin

    if MinPollingInterval != "":
        if MinPollingInterval >= 3 and MinPollingInterval <= 17 and MinPollingInterval <= MaxPollingInterval:
            HuaweiDict['MinPollingInterval'] = MinPollingInterval
        else:
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is not valid, please config it again!' %MinPollingInterval}
            return ret
        
    if MaxPollingInterval != "":
        if MaxPollingInterval >= 3 and MaxPollingInterval <= 17 and MaxPollingInterval >= MinPollingInterval:
            HuaweiDict['MaxPollingInterval'] = MaxPollingInterval
        else:
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is not valid, please config it again!' %MaxPollingInterval}
            return ret

    #send restful request 
    token = getToken()
    #get interface id
    uri = root_uri + manager_uri + "/NtpService"

    #get etag for headers
    Etag = getEtag(ibmc,uri)
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
    log.info(str(headers))

    try:
        r = request('PATCH',resource=uri,headers=headers,data=HuaweiDict,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            report.info(ibmc['ip'] + " -- config bmc ntp successfully!")
            log.info(ibmc['ip'] + " -- config bmc ntp successfully! \n")
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            report.info(ibmc['ip'] + " -- config bmc ntp failed! error code:%s" %str(result))
            log.info(ibmc['ip'] + " -- config bmc ntp failed! error code:%s\n" %str(result))
            ret['result'] = False
            ret['msg'] = 'config bmc ntp failed! the error code is ' + str(result)

    except Exception, e:
        report.info(ibmc['ip'] + " -- config bmc ntp failed! %s" %str(e))
        log.info(ibmc['ip'] + " -- config bmc ntp failed! %s \n" %str(e) )
        ret['result'] = False
        ret['msg'] = 'config bmc ntp failed! ' + str(e)
        raise


    return ret

if __name__ == '__main__':
    main()
 
