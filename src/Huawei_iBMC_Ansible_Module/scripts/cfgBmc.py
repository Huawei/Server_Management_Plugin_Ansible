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
import string
import logging, logging.handlers
from datetime import datetime
sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *

LOG_FILE = "/etc/ansible/ansible_ibmc/log/cfgBmc.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/cfgBmc.log"

log_hander = logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes = 1024*1024,backupCount = 5)
report_hander = logging.handlers.RotatingFileHandler(REPORT_FILE,maxBytes = 1024*1024,backupCount = 5)
fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
log_hander.setFormatter(fmt)
report_hander.setFormatter(fmt)

log = logging.getLogger('cfgBmcLog')
log.addHandler(log_hander)
log.setLevel(logging.INFO)

report = logging.getLogger('cfgBmcReport')
report.addHandler(report_hander)
report.setLevel(logging.INFO)


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
# @Method: 设置启动设备
# @command: get bootdevice info
# @Param: device ibmc url
# @date: 2017.10.23
#==========================================================================
'''
def getBootDevice(ibmc,root_uri,system_uri):
    uri = root_uri + system_uri
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    payload = {}
    try:
        ret = request('GET',resource=uri,headers=headers,data=payload, tmout=30,ip=ibmc['ip'])
        data = ret.json()
        if ret.status_code == 200:
            result = data[u'Boot'][u'BootSourceOverrideTarget']
        else:
            result = 'unknown'
    except Exception, e:
        result = 'unknown'

    return result
    

'''
#==========================================================================
# @Method: 设置启动设备
# @command: set_bootdevice
# @Param: device ibmc url
# @date: 2017.9.18
#==========================================================================
'''
def setBootDevice(device,ibmc,root_uri,system_uri):
    uri = root_uri + system_uri

    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
    playload = {"Boot":{"BootSourceOverrideTarget":device,"BootSourceOverrideEnabled":"Once"}}
    
    ret = {'result':True,'msg': ''}

    try:
        r = request('PATCH',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            report.info(ibmc['ip'] + " -- set boot device as:%s successful!" %device )
            log.info(ibmc['ip'] + " -- set boot device as:%s successful!\n" %device )
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            report.info(ibmc['ip'] + " -- set boot device as:" + device + " failed!")
            log.info(ibmc['ip'] + " -- set boot device as:" + device + " failed! \n")
            ret['result'] = False
            ret['msg'] = 'set boot device failed! the error code is ' + result

    except Exception, e:
        report.info(ibmc['ip'] + " -- " + "set boot device as:" + device + " failed!" + str(e))
        log.info(ibmc['ip'] + " -- " + "set boot device as:" + device + " failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'set boot device failed! ' + str(e)
        raise
    finally:
        return ret

'''
#==========================================================================
# @Method: 配置BMC
# @command: config_bmc
# @Param: info ibmc url
# @date: 2017.9.18
#==========================================================================
'''
def configBmc(info,ibmc,root_uri,manager_uri):
    ret = {'result':True,'msg': ''}

    token = getToken()
    try:
        #get interface id
        uri = root_uri + manager_uri + "/EthernetInterfaces"
        r = sendGetRequest(ibmc,uri,10)
        if r.status_code == 200:
            data = r.json()
        else:
            ret['result'] = False
            ret['msg'] = 'get system info failed!'
            return ret 
    
        Member = data[u'Members'][0][u'@odata.id']
        interfaceid = Member.split('/')[6]

        #get etag for headers
        Etag = getEtag(ibmc,uri+"/"+interfaceid)
        headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
        #get bmc ip info
        ip = info.split(';')[0]
        mask = info.split(';')[1]
        gateway = info.split(';')[2]
    except Exception, e:
        report.info(ibmc['ip'] + " -- config bmc ip failed, please check the paraments and separator again! %s" %str(e))
        log.info(ibmc['ip'] + " -- config bmc ip failed, please check the paraments and separator again! %s \n" %str(e) )
        ret['result'] = False
        ret['msg'] = 'config bmc ip failed, please check the paraments and separator again!  ' + str(e)
        return ret

    #playload = {"IPv4Addresses":[{'AddressOrigin':'Static','Address':ip,'SubnetMask':mask,'Gateway':gateway}]}
    playload = {}
    ipinfo = {}
    Array = []
    ipinfo['AddressOrigin'] = 'Static'
    if checkip(ip) == True:
        ipinfo['Address'] = ip
    else:
        ret['result'] = False
        ret['msg'] = 'The ip address is error!'
        return ret

    if checkip(mask) == True:
        ipinfo['SubnetMask'] = mask
    else:
        ret['result'] = False
        ret['msg'] = 'The mask is error!'
        return ret
    if checkip(gateway) == True:
        ipinfo['Gateway'] = gateway
    else:
        ret['result'] = False
        ret['msg'] = 'The Gateway is error!'
        return ret

    Array.append(ipinfo)
    playload['IPv4Addresses'] = Array
    log.info(str(playload))

    try:
        r = request('PATCH',resource=uri + "/" +interfaceid,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            report.info(ibmc['ip'] + " -- config bmc successful!")
            log.info(ibmc['ip'] + " -- config bmc successful! \n")
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            report.info(ibmc['ip'] + " -- config bmc failed! error code:%s" %str(result))
            log.info(ibmc['ip'] + " -- config bmc failed! error code:%s\n" %str(result))
            ret['result'] = False
            ret['msg'] = 'config bmc failed! the error code is ' + str(result)

    except Exception, e:
        report.info(ibmc['ip'] + " -- config bmc failed! %s" %str(e))
        log.info(ibmc['ip'] + " -- config bmc failed! %s \n" %str(e) )
        ret['result'] = False
        ret['msg'] = 'config bmc failed! ' + str(e)
        raise


    return ret

   
if __name__ == '__main__':
    main()
 
