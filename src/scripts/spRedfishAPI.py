#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2018, Huawei.
# Author: xueweihong
# Date: 20180417
# This file is 
# part of Ansible
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
from datetime import datetime
sys.path.append("/etc/ansible/ansible_ibmc/module")
from redfishApi import *
sys.path.append("/etc/ansible/ansible_ibmc/scripts")
from powerManage import *
from cfgBmc import *
from commonLoger import ansibleGetLoger
LOG_FILE = "/etc/ansible/ansible_ibmc/log/spRedfishAPI.log"
REPORT_FILE = "/etc/ansible/ansible_ibmc/report/spRedfishAPI.log"
log,report=ansibleGetLoger(LOG_FILE,REPORT_FILE,"spRedfishAPI")

def spAPISetSpService(ibmc,root_uri,manager_uri,spEnable,restarTimeout = 30,deployTimeout=7200,deployStatus=True):
    uri = root_uri + manager_uri + "/SPService"
    Etag = getEtag(ibmc,uri)
    token = getToken() 
    headers = {'content-type': 'application/json','X-Auth-Token':token,'If-Match':Etag}
    playload = {"SPStartEnabled": spEnable ,\
                 "SysRestartDelaySeconds": restarTimeout,\
                 "SPTimeout": deployTimeout,\
                 "SPFinished":deployStatus }    
    ret = {'result':True,'msg': ''}
    try:
        r = request('PATCH',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        print "rrrr",r
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- setSpService successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            log.error(ibmc['ip'] + " -- set setSpService error info is: %s \n" %str(r.json()))
            ret['result'] = False
            ret['msg'] = 'set setSpService failed! the error code is ' + result
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "set setSpService failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'set setSpService failed! ' + str(e)
    finally:
        return ret 

def spApiSetFwUpgrade(ibmc,root_uri,manager_uri,ImageeUrl,SignalUrl,imageType="Firmware",Parameter="all",UpgradeMode="Auto",ActiveMethod="Restart",updateId="1"):
    uri = root_uri + manager_uri + "/SPService/SPFWUpdate/%s/Actions/SPFWUpdate.SimpleUpdate"% ( updateId )
    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'content-type': 'application/json','X-Auth-Token':token}
    playload = {"ImageURI": ImageeUrl ,\
                 "SignalURI": SignalUrl,\
                 "ImageType": imageType,\
                 "Parameter":Parameter,\
                 "UpgradeMode":UpgradeMode,\
                 "ActiveMethod":ActiveMethod
                  }  
    ret = {'result':True,'msg': ''}
    try:
        r = request('POST',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- spApiSetFwUpgrade successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
        else:
            log.error(ibmc['ip'] + " -- set spApiSetFwUpgradeerror info is: %s \n" %str(r.json()) )
            ret['result'] = False
            ret['msg'] = 'set sespApiSetFwUpgradefailed error '
    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "setSpOrFwUpgrade failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'setSpOrFwUpgrade failed! ' + str(e)
    finally:
        return ret 
def spApiGetFwInfo (ibmc,root_uri,manager_uri ):
    ret = {'result':False,'msg': '' ,"fwInfo":[] }
    uri = root_uri + manager_uri + "/SPService/DeviceInfo" 
    token = getToken()
    headers = {'X-Auth-Token':token}
    playload = {}    
    try:
        r = request('GET',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- get FwInfo successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
            ret["fwInfo"]=r.json()["PCIeCards"]
        else:
            log.error(ibmc['ip'] + " -- get FwInfo error info is: %s \n" %str(r.json()) )
            ret['result'] = False
            ret['msg'] = 'get fwInfo error '

    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "get FWInfo failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'sp getFWInfo  failed! ' + str(e)
    finally:
        return ret 


def spApiGetFwUpdateId (ibmc,root_uri,manager_uri ):
    ret = {'result':False,'msg': '' ,"updateidlist": [] }
    uri = root_uri + manager_uri + "/SPService/SPFWUpdate" 
    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'X-Auth-Token':token}
    playload = {}    
    try:
        r = request('GET',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- spApiGetFwUpdateId successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
            tmpdic=r.json()
            ret["updateidlist"]=range( len(tmpdic["Members"]) )

        else:
            log.error(ibmc['ip'] + " -- set spApiGetFwUpdateId error info is: %s \n" %str(r.json()) )
            ret['result'] = False
            ret['msg'] = 'set spApiGetFwUpdateId error '

    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "spApiGetFwUpdateId failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'spApiGetFwUpdateId failed! ' + str(e)
    finally:
        return ret 



def spApiGetFWSource(ibmc,root_uri,manager_uri,updateId="1"):
    ret ={'result':False,'msg': '',"SourceInfo":{} }
    uri = root_uri + manager_uri + "/SPService/SPFWUpdate/%s"%(updateId) 
    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'X-Auth-Token':token}
    playload = {}    
    try:
        r = request('GET',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- spApiGetFWSource successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
            ret["SourceInfo"].update(r.json())
        else:
            log.error(ibmc['ip'] + " -- set spApiGetFWSource error info is: %s \n" %str(r.json()) )
            ret['result'] = False
            ret['msg'] = 'set spApiGetFWSource error '

    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "spApiGetFWSource failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'spApiGetFWSource failed! ' + str(e)
    finally:
        return ret 

def spApiGetResultId(ibmc,root_uri,manager_uri, ) : 
    ret = {'result':False,'msg': '',"resultIdlist":[] }
    uri = root_uri + manager_uri + "/SPService/SPResult"
    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'X-Auth-Token':token}
    playload = {}    
    try:
        r = request('GET',resource=uri,headers=headers,data=playload,tmout=10,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- spApiGetFWSource successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
            ret["resultIdlist"]=range( len(tmpdic["Members"]) )
        else:
            log.error(ibmc['ip'] + " -- set spApiGetResultId error info is: %s \n" %str(r.json()) )
            ret['result'] = False
            ret['msg'] = 'set spApiGetResultId error '

    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "spApiGetResultId failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'spApiGetResultId failed! ' + str(e)
    finally:
        return ret 


def spApiGetResultInfo(ibmc,root_uri,manager_uri,resultId="1"):
    ret ={'result':False,'msg': '',"resultInfo":{} }
    uri = root_uri + manager_uri + "/SPService/SPResult/%s"%(resultId)
    Etag = getEtag(ibmc,uri)
    token = getToken()
    headers = {'X-Auth-Token':token}
    playload = {}    
    try:
        r = request('GET',resource=uri,headers=headers,data=playload,tmout=30,ip=ibmc['ip'])
        result = r.status_code
        if result == 200:
            log.info(ibmc['ip'] + " -- spApiGetResultInfo successful!\n" )
            ret['result'] = True
            ret['msg'] = 'successful!'
            ret["resultInfo"].update(r.json())
        else:
            log.error(ibmc['ip'] + " -- set spApiGetResultInfo error info is: %s \n" %str(r.json()) )
            ret['result'] = False
            ret['msg'] = 'set spApiGetResultId error '

    except Exception, e:
        log.error(ibmc['ip'] + " -- " + "spApiGetResultInfo failed!" + str(e) + " \n" )
        ret['result'] = False
        ret['msg'] = 'spApiGetResultInfo failed! ' + str(e)
    finally:
        return ret 
    return ret
if __name__=='__main__':
   pass

