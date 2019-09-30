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
from commonLoger import *
global token

# ntp config ini file
LOG_FILE = "/etc/ansible/ansible_ibmc/log/cfgNTP.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/cfgNTP.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"cfgNTP")



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
    if info.lower() == "getinfo":
        ret = getNtp(ibmc,root_uri,manager_uri)
        return ret
    config = ConfigParser.ConfigParser()
    config.read(info)
   
    ServiceEnabled = config.get("NTP","ServiceEnabled").upper()
    try:
        AlternateNtpServer = config.get("NTP","AlternateNtpServer")
    except Exception , e:
        AlternateNtpServer=''
        log.info(" get AlternateNtpServer param exception"+ str(e))
    
    PreferredNtpServer = config.get("NTP","PreferredNtpServer")
    try:
        ServerAuthenticationEnabled = config.get("NTP","ServerAuthenticationEnabled").upper()
    except Exception , e:
        ServerAuthenticationEnabled=''
        log.info(" get ServerAuthenticationEnabled param exception"+ str(e))    
    try:
        NtpAddressOrigin = config.get("NTP","NtpAddressOrigin")
    except Exception , e:
        NtpAddressOrigin=''
        log.info(" get NtpAddressOrigin param exception"+ str(e))     

    try:
        MinPollingInterval = string.atoi(config.get("NTP","MinPollingInterval"))
    except Exception , e:
        MinPollingInterval=''
        log.info(" get MinPollingInterval param exception"+ str(e)) 

    try:    
        MaxPollingInterval = string.atoi(config.get("NTP","MaxPollingInterval"))
    except Exception , e:
        MaxPollingInterval=''
        log.info(" get MaxPollingInterval param exception"+ str(e))

    HuaweiDict = {} 
    if ServiceEnabled != "":
        if ServiceEnabled == "TRUE":
            ServiceEnabled = True
        elif ServiceEnabled == "FALSE":
            ServiceEnabled = False
        else:
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %ServiceEnabled}
            log.error("The value of parameter %s in ntp.ini file is invalid, please config it again!"%ServiceEnabled)
            report.info("The value of parameter %s in ntp.ini file is invalid, please config it again!"%ServiceEnabled)
            return ret
        HuaweiDict['ServiceEnabled'] = ServiceEnabled

    if PreferredNtpServer != '':
        HuaweiDict['AlternateNtpServer'] = AlternateNtpServer
    
    if PreferredNtpServer != '':
        HuaweiDict['PreferredNtpServer'] = PreferredNtpServer

    if ServerAuthenticationEnabled != "":
        if ServerAuthenticationEnabled.upper() == "TRUE":
            ServerAuthenticationEnabled = True
        elif ServerAuthenticationEnabled.upper() == "FALSE":
            ServerAuthenticationEnabled = False
        else:
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %ServerAuthenticationEnabled}
            log.error("The value of parameter %s in ntp.ini file is invalid, please config it again!" %ServerAuthenticationEnabled)
            report.info("The value of parameter %s in ntp.ini file is invalid, please config it again!" %ServerAuthenticationEnabled)
            return ret
        HuaweiDict['ServerAuthenticationEnabled'] = ServerAuthenticationEnabled

    if NtpAddressOrigin != "":
        if NtpAddressOrigin != "IPv4" and NtpAddressOrigin != "IPv6" and NtpAddressOrigin != "Static":
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %NtpAddressOrigin}
            log.error('The value of parameter %s in ntp.ini file is invalid, please config it again!' %NtpAddressOrigin)
            report.info('The value of parameter %s in ntp.ini file is invalid, please config it again!' %NtpAddressOrigin)
            return ret
        else:
            HuaweiDict['NtpAddressOrigin'] = NtpAddressOrigin

    if MinPollingInterval != "":
        if MinPollingInterval >= 3 and MinPollingInterval <= 17 and MinPollingInterval <= MaxPollingInterval:
            HuaweiDict['MinPollingInterval'] = MinPollingInterval
        else:
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %MinPollingInterval}
            log.error( 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %MinPollingInterval)
            report.info( 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %MinPollingInterval)
            return ret
        
    if MaxPollingInterval != "":
        if MaxPollingInterval >= 3 and MaxPollingInterval <= 17 and MaxPollingInterval >= MinPollingInterval:
            HuaweiDict['MaxPollingInterval'] = MaxPollingInterval
        else:
            ret = {'result':False,'msg': 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %MaxPollingInterval}
            log.error( 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %MaxPollingInterval)
            report.info( 'The value of parameter %s in ntp.ini file is invalid, please config it again!' %MaxPollingInterval)
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
            report.info(ibmc['ip'] + " -- config bmc ntp successfully!"+"==== respon:"+str(r.json()))
            log.info(ibmc['ip'] + " -- config bmc ntp successfully! \n"+"==== respon:"+str(r.json()))
            ret['result'] = True
            ret['msg'] = 'successful!'+"==== respon:"+str(r.json())
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

def getNtp(ibmc,root_uri,manager_uri):
    token = getToken()
    ret = {'result':True,'msg': ''}
    uri = root_uri + manager_uri + "/NtpService"
    headers = {'content-type': 'application/json','X-Auth-Token':token} 
    payload ={}   
    try:
        r = request('GET',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])
    except Exception,e:
        log.exception(ibmc['ip'] + " -- " +"send  getNtp comand exception! " + str(e))
        raise
    if r.status_code == 200:
        ret['result']=True  
        ntpinfo = "ServiceEnabled: " +str(r.json()["ServiceEnabled"]) \
                  + "  PreferredNtpServer:" + str( r.json()["PreferredNtpServer"])\
                  + "  AlternateNtpServer:" +  str(r.json()["AlternateNtpServer"])\
                  + "  NtpAddressOrigin:" +  str(r.json()["NtpAddressOrigin"])\
                  + "  MinPollingInterval:" +  str(r.json()["MinPollingInterval"])\
                  + "  MaxPollingInterval:" +  str(r.json()["MaxPollingInterval"])\
                  + "  ServerAuthenticationEnabled:" + str(r.json()["ServerAuthenticationEnabled"])\
                  + "  NTPKeyStatus:" + str(r.json()["NTPKeyStatus"])           

        ret['msg']='get NTP successful! NTPInfo is:'+ ntpinfo 
        log.info(ibmc['ip'] + " -- " + "get NTP successful! NTPInfo is:" +ntpinfo )
        report.info(ibmc['ip'] + " -- " + "get NTP successful! NTPInfo is:"+ntpinfo )
    else:
        ret['result'] =False
        ret['msg']='get NTP failed!'
        log.info(ibmc['ip'] + " -- " + "get NTP  failed!" )
        report.info(ibmc['ip'] + " -- " + "get NTP failed!" )    
    return ret

if __name__ == '__main__':
    main()
 
