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
from commonLoger import *
LOG_FILE = "/etc/ansible/ansible_ibmc/log/cfgBmc.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/cfgBmc.log"
log, report = ansibleGetLoger(LOG_FILE,REPORT_FILE,"cfgBmc")


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
    r = request('GET',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
    result = r.status_code
    if result == 200:
        try: 
            if not device in r.json()["Boot"]["BootSourceOverrideTarget@Redfish.AllowableValues"]:
                log.error(ibmc['ip'] + " -- device not allow ")
                ret['result'] = False
                ret['msg'] = 'device not valid ' 
                return ret
        except Exception ,e:           
            raise  Exception (ibmc['ip']+" parse get all boot device  exception\n "+str(e)+str(r.json()))        
    else :    
        report.info(ibmc['ip'] + " -- get valid device failed")
        log.info(ibmc['ip'] + " -- get valid device failed")
        ret['result'] = False
        ret['msg'] = 'get valid device failed ' + result
        return ret 

    try:
        r = request('PATCH',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            report.info(ibmc['ip'] + " -- set boot device as:%s successful!" %device + "=====respon:" +str (r.json())  )
            log.info(ibmc['ip'] + " -- set boot device as:%s successful!\n" %device + "=====respon:" +str (r.json()))
            ret['result'] = True
            ret['msg'] = 'successful!'+ "=====respon:" +str (r.json())
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

def testIPInGateway(ip,gateway,netmask):
    if gateway is None or ip is None or netmask is None or gateway == "" or ip == "" or netmask == "": 
        return True  
    
    ipSplit=ip.split(".")
    gatewaySplit=gateway.split(".")
    netmaskSplit=netmask.split(".")
    for i in range(4):
        if int(ipSplit[i])&int(netmaskSplit[i]) !=  int(gatewaySplit[i])& int(netmaskSplit[i]):
            return False        
    return True    
        
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

      
        
        #get bmc ip info
        if info.lower() == "getinfo":
            return getBmcIPInfo(ibmc,uri + "/" +interfaceid)
        config=None
        try:
            config = open(info, 'r')
            configDic = json.load(config)
        except Exception ,e:    
            log.error(ibmc['ip'] + " -- configBmc: read config file failed! error info:%s" %str(e))
            raise Exception (ibmc['ip']+"handler configBmc configfile exception \n"+str(e)) 
        finally:
            if config is not None :
                config.close() 
                
        
        log.info(ibmc['ip'] + " -- " + "bmc  config param json is:" +str(configDic) )

    except Exception, e:
        report.info(ibmc['ip'] + " -- config bmc ip failed, please check the paraments and separator again! %s" %str(e))
        log.info(ibmc['ip'] + " -- config bmc ip failed, please check the paraments and separator again! %s \n" %str(e) )
        ret['result'] = False
        ret['msg'] = 'config bmc ip failed, please check the paraments and separator again!  ' + str(e)
        return ret

    #playload = {"IPv4Addresses":[{'AddressOrigin':'Static','Address':ip,'SubnetMask':mask,'Gateway':gateway}]}
    playload = {}
    oemDic= {
         'Huawei':{}
    }
    
    if configDic.has_key('IPVersion'):
        oemDic['Huawei']['IPVersion'] = configDic['IPVersion']
        playload["Oem"]=oemDic
          #get etag for headers
        Etag = getEtag(ibmc,uri+"/"+interfaceid)
        headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
        try:
            r = request('PATCH',resource=uri + "/" +interfaceid,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
            result = r.status_code
            if result == 200:
                report.info(ibmc['ip'] + " -- config bmc IPVersion successful! =====respon=====:"+str(r.json()) )
                log.info(ibmc['ip'] + " -- config bmc IPVersion successful! \n=====respon=====:"+str(r.json()) )
                ret['result'] = True
                ret['msg'] = 'successful!'+"=====respon=====:"+str(r.json())    
            else:
                report.info(ibmc['ip'] + " -- config bmc  IPVersion failed! error code:%s" %str(result))
                log.info(ibmc['ip'] + " -- config bmc  IPVersion failed! error code:%s\n" %str(result))
                ret['result'] = False
                ret['msg'] = 'config bmc IPVersion failed! the error code is ' + str(result)
        except Exception, e:
            report.info(ibmc['ip'] + " -- config bmc IPVersion Exception! %s" %str(e))
            log.info(ibmc['ip'] + " -- config bmc  IPVersion Exception! %s \n" %str(e) )
            ret['result'] = False
            ret['msg'] = 'config bmc failed! ' + str(e)
            raise    
    playload = {}    

    if configDic.has_key('IPv6DefaultGateway') :
        playload['IPv6DefaultGateway'] = configDic['IPv6DefaultGateway']
    if  configDic.has_key('IPv6Addresses')  :
        playload['IPv6Addresses']=configDic['IPv6Addresses']
    
    ipv4info = []
    if  configDic.has_key('IPv4Addresses'):
        ipv4info= configDic['IPv4Addresses']
    
    if len(ipv4info) >0 and ipv4info[0] is not None:
        if  ipv4info[0].has_key('Address'):
             if checkip( ipv4info[0]['Address']) == False: 
                log.info(ibmc['ip'] + " -- config bmc ip failed,ip is invalid \n" )
                ret['result'] = False
                ret['msg'] = 'config bmc ip failed,ip is invalid'
                return  ret
        if  ipv4info[0].has_key('SubnetMask'):
             if checkip( ipv4info[0]['SubnetMask']) == False: 
                log.info(ibmc['ip'] + " -- config bmc ip failed,SubnetMask is invalid \n" )
                ret['result'] = False
                ret['msg'] = 'config bmc ip failed,SubnetMask is invalid'
                return  ret
        if  ipv4info[0].has_key('Gateway'):
             if checkip( ipv4info[0]['Gateway']) == False: 
                log.info(ibmc['ip'] + " -- config bmc ip failed,Gateway is invalid \n" )
                ret['result'] = False
                ret['msg'] = 'config bmc ip failed,Gateway is invalid'
                return  ret            
        if  ipv4info[0].has_key('Address') and ipv4info[0].has_key('SubnetMask') and ipv4info[0].has_key('Gateway'): 
            if testIPInGateway(ipv4info[0]['Address'],ipv4info[0]['Gateway'],ipv4info[0]['SubnetMask']) ==False:
                log.error(ibmc['ip'] + " -- " + 'config bmc failed! The Gateway and ip are not in the same network' )
                ret['result'] = False
                ret['msg'] = 'config bmc failed! The Gateway and ip are not in the same network '
                return ret
        playload['IPv4Addresses'] = ipv4info
    log.info(str(playload))
    #there is not anyother param ,return 
    if  playload ==  {}:
        return ret
    #get etag for headers
    Etag = getEtag(ibmc,uri+"/"+interfaceid)
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}    
    try:
        r = request('PATCH',resource=uri + "/" +interfaceid,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            report.info(ibmc['ip'] + " -- config bmc successful! =====respon=====:"+str(r.json()) )
            log.info(ibmc['ip'] + " -- config bmc successful! \n=====respon=====:"+str(r.json()) )
            ret['result'] = True
            ret['msg'] = 'successful!'+"=====respon=====:"+str(r.json())
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
def getBmcIPInfo(ibmc,uri):
    ret = {'result':True,'msg': ''}
    token = getToken()
    headers = {'content-type':'application/json','X-Auth-Token':token}
    payload = {}
    try:
        r = request('GET',resource=uri,headers=headers,data=payload,tmout=30,ip=ibmc['ip'])
    except Exception,e:
        log.exception(ibmc['ip'] + " -- " +"get bmc failed! " + str(e))
        raise
    if r.status_code == 200: 
        BMCinfo = "IPv4Addresses:" + str(r.json()["IPv4Addresses"]) \
                  +  " IPv6Addresses:" +str(r.json()["IPv6Addresses"])\
                  + " PermanentMACAddress:" +str(r.json()["PermanentMACAddress"])\
                  + " IPv6DefaultGateway:" +str(r.json()["IPv6DefaultGateway"])\
                  + " IpVersion:" + str(r.json()["Oem"]["Huawei"]["IPVersion"])
        ret['msg']='get bmc successful! bmc IP Info is:'+ BMCinfo
        log.info(ibmc['ip'] + " -- " + "get bmc successful! bmc json is:" +str(r.json()) )
        report.info(ibmc['ip'] + " -- " + "get bmc successful! bmc json is:"+str(r.json()))
    else:
        ret['result'] =False
        ret['msg']='get bmc failed!'
        log.info(ibmc['ip'] + " -- " + "get bmc failed!" )
        report.info(ibmc['ip'] + " -- " + "get bmc failed!" )    
    return ret
if __name__ == '__main__':
    main()
 
